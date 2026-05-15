// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Core types and traits for the amla-vm VMM.
//!
//! This crate provides foundational abstractions shared across VMM crates:
//! - `VmState` self-describing view over mapped VM state + guest memory
//! - `IrqLine` trait for interrupt delivery
//! - `MmioDevice` trait for MMIO-mapped devices
//! - Error types that never panic on guest input

#![allow(unexpected_cfgs)] // `cfg(kani)` is set by the Kani verifier
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-core requires a 64-bit target");

// =============================================================================
// vCPU Abstraction (hypervisor-agnostic)
// =============================================================================

pub mod vcpu;
pub use vcpu::{ExitSource, VcpuError, VcpuExit, VcpuId, VcpuResponse};

// Re-export the shared `num` helpers (`lo32`, `hi32`) from amla-vm-constants
// so downstream crates can write `amla_core::num::lo32(x)` without adding a
// direct dep on amla-vm-constants.
pub use amla_constants::num;

// =============================================================================
// Factory Traits (backend-agnostic vCPU and IRQ creation)
// =============================================================================

mod vcpu_factory;
pub use vcpu_factory::{
    BasicDeviceWaker, DeviceWakeIndex, DeviceWakeIndexError, DeviceWakeResult, DeviceWaker,
    IrqFactory,
};

// =============================================================================
// ARM64 Architecture Support
// =============================================================================

pub mod arm64;

// =============================================================================
// x86_64 Architecture Support
// =============================================================================

pub mod x86_64;

// =============================================================================
// Architecture Constants
// =============================================================================

/// Guest physical address where RAM begins.
///
/// ARM64 places RAM at `0x4000_0000` (1 GiB), matching the standard `virt`
/// machine memory map. `x86_64` maps RAM at GPA 0 (identity-mapped).
#[cfg(target_arch = "aarch64")]
pub const GUEST_PHYS_ADDR: u64 = 0x4000_0000;

/// Guest physical address where RAM begins (`x86_64`: identity-mapped at GPA 0).
#[cfg(not(target_arch = "aarch64"))]
pub const GUEST_PHYS_ADDR: u64 = 0;

/// Memory block size for virtio-mem and hotplug bitmap granularity.
///
/// Single source of truth for:
/// - Virtio-mem plug/unplug block size (guest-visible config)
/// - Hotplug node RAM descriptor bitmap granularity
/// - Alignment for `add_hotplug_memory()` sizing
pub const BLOCK_SIZE: u64 = 2 * 1024 * 1024; // 2 MiB

/// Minimum base RAM in megabytes.
///
/// The kernel and guest agent need at least this much RAM to boot. All memory
/// beyond this can be provided via virtio-mem.
pub const MIN_MEMORY_MB: usize = 128;

/// Block alignment in megabytes (derived from `BLOCK_SIZE`).
///
/// Both `memory_mb` and `max_memory_mb` must be multiples of this.
pub const BLOCK_SIZE_MB: usize = (BLOCK_SIZE / (1024 * 1024)) as usize; // 2

// =============================================================================
// Memory Holes — architecture-specific GPA reservations
// =============================================================================

pub mod memory;
pub use memory::{
    MEMORY_HOLES, MapSource, MappingHandleInfo, MemoryHole, MemoryHoles, MemoryMapping,
    ValidatedMapSource, ValidatedMemoryMapping, ValidatedMemoryMappings,
};

mod worker_process;
pub use worker_process::{WorkerBinary, WorkerProcessConfig};

// =============================================================================
// VM State
// =============================================================================

// VmState is exported via vm_state module (pub use view::*).

// =============================================================================
// Backend Traits (console, net)
// =============================================================================

pub mod backends;

// =============================================================================
// Network Constants
// =============================================================================

pub mod net;

// =============================================================================
// VM State Layout (moved from amla-vm-state)
// =============================================================================

pub mod vm_state;

// Re-export bytemuck for memory operations
pub use bytemuck;

// =============================================================================
// Error Types
// =============================================================================

/// Error types for VMM operations.
///
/// All errors are structured and implement Display.
/// Guest-controlled inputs NEVER cause panics - they return these errors.
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    #[error("Guest memory out of bounds: addr={addr:#x}, size={size}, memory_size={memory_size}")]
    MemoryOutOfBounds {
        addr: u64,
        size: usize,
        memory_size: usize,
    },

    #[error("Address overflow: {addr:#x} + {size} overflows")]
    AddressOverflow { addr: u64, size: usize },

    #[error("Unaligned guest memory access: addr={addr:#x}, size={size}, align={align}")]
    UnalignedGuestMemoryAccess {
        addr: u64,
        size: usize,
        align: usize,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Device not activated")]
    DeviceNotActivated,

    #[error("Memory access denied: {0}")]
    MemoryAccessDenied(String),

    #[error("{0}")]
    DeviceActivation(String),

    #[error("{0}")]
    DeviceConfig(String),

    #[error("Virtqueue error: {0}")]
    Virtqueue(Box<VirtqueueError>),
}

/// Error type for virtqueue operations.
#[derive(Debug, thiserror::Error)]
pub enum VirtqueueError {
    #[error("Guest memory access failed at {addr:#x}: {source}")]
    GuestMemoryAccess {
        addr: u64,
        #[source]
        source: VmmError,
    },

    #[error("Descriptor address overflow: addr={addr:#x} + len={len}")]
    AddressOverflow { addr: u64, len: u64 },

    #[error("Descriptor out of bounds: addr={addr:#x}, len={len}, memory={memory_size}")]
    OutOfBounds {
        addr: u64,
        len: u32,
        memory_size: usize,
    },

    #[error("Descriptor chain too long (>{max}) - possible cycle")]
    ChainTooLong { max: u16 },

    #[error("Invalid descriptor index: {index} >= queue_size {queue_size}")]
    InvalidIndex { index: u16, queue_size: u16 },
}

impl From<VirtqueueError> for VmmError {
    fn from(e: VirtqueueError) -> Self {
        Self::Virtqueue(Box::new(e))
    }
}

// =============================================================================
// IRQ Line Trait
// =============================================================================

/// Trait for asserting/deasserting IRQ lines.
///
/// This abstracts the IRQ delivery mechanism, allowing devices to raise
/// interrupts without knowing the underlying implementation.
///
/// # Thread Safety
/// Implementations must be thread-safe.
pub trait IrqLine: Send + Sync {
    /// Assert an IRQ line (set level HIGH).
    fn assert(&self);

    /// De-assert an IRQ line (set level LOW).
    fn deassert(&self);

    /// Drain any pending resample (EOI) token and retrigger if needed.
    ///
    /// Default: no-op (non-resampled IRQ lines don't need this).
    fn check_resample(&self) {}
}

/// A no-op IRQ line that does nothing.
#[derive(Clone, Copy, Default)]
pub struct NullIrqLine;

impl IrqLine for NullIrqLine {
    fn assert(&self) {}
    fn deassert(&self) {}
}

// =============================================================================
// MMIO Device Trait
// =============================================================================

/// Trait for MMIO-mapped devices.
///
/// Devices implement this to handle MMIO reads/writes from the guest.
///
/// # Phase Separation
///
/// Operational methods (`read`, `write`) take `&self`. Devices are fully
/// configured at construction time (IRQ line, guest memory), then placed
/// behind `Arc` for shared access.
///
/// Guest memory and IRQ line are provided at construction time.
pub trait MmioDevice: Send + Sync {
    /// Handle an MMIO read. Returns the value to return to the guest.
    fn read(&self, offset: u64, size: u8) -> u64;

    /// Handle an MMIO write from the guest.
    fn write(&self, offset: u64, data: u64, size: u8);
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmm_error_display() {
        let err = VmmError::MemoryOutOfBounds {
            addr: 0x1000,
            size: 100,
            memory_size: 0x800,
        };
        assert!(err.to_string().contains("0x1000"));
    }

    #[test]
    fn test_virtqueue_error_display() {
        let err = VirtqueueError::ChainTooLong { max: 256 };
        assert!(err.to_string().contains("256"));
    }

    #[test]
    fn test_null_irq_line() {
        let irq = NullIrqLine;
        irq.assert();
        irq.deassert();
    }

    // Error variant display format tests
    #[test]
    fn test_vmm_error_address_overflow_display() {
        let err = VmmError::AddressOverflow {
            addr: 0xFFFF_FFFF_FFFF_FFF0,
            size: 32,
        };
        let s = err.to_string();
        assert!(s.contains("overflow"), "should mention overflow: {s}");
        assert!(s.contains("0xffff"), "should contain hex addr: {s}");
    }

    #[test]
    fn test_vmm_error_device_not_activated_display() {
        let err = VmmError::DeviceNotActivated;
        assert!(err.to_string().contains("not activated"));
    }

    #[test]
    fn test_vmm_error_memory_access_denied_display() {
        let err = VmmError::MemoryAccessDenied("test region".into());
        assert!(err.to_string().contains("test region"));
    }

    #[test]
    fn test_virtqueue_error_address_overflow_display() {
        let err = VirtqueueError::AddressOverflow {
            addr: 0xDEAD,
            len: 0x1000,
        };
        let s = err.to_string();
        assert!(s.contains("0xdead"), "should contain hex addr: {s}");
    }

    #[test]
    fn test_virtqueue_error_out_of_bounds_display() {
        let err = VirtqueueError::OutOfBounds {
            addr: 0x1000,
            len: 0x100,
            memory_size: 0x800,
        };
        let s = err.to_string();
        assert!(s.contains("0x1000"), "should contain addr: {s}");
        assert!(
            s.contains("out of bounds") || s.contains("Out of bounds"),
            "should mention bounds: {s}"
        );
    }

    #[test]
    fn test_virtqueue_error_invalid_index_display() {
        let err = VirtqueueError::InvalidIndex {
            index: 300,
            queue_size: 256,
        };
        let s = err.to_string();
        assert!(s.contains("300"));
        assert!(s.contains("256"));
    }

    #[test]
    fn test_virtqueue_error_guest_memory_access_display() {
        let inner = VmmError::MemoryOutOfBounds {
            addr: 0x5000,
            size: 16,
            memory_size: 0x4000,
        };
        let err = VirtqueueError::GuestMemoryAccess {
            addr: 0x5000,
            source: inner,
        };
        let s = err.to_string();
        assert!(s.contains("0x5000"), "should contain addr: {s}");
    }

    // VirtqueueError -> VmmError conversion test
    #[test]
    fn test_virtqueue_error_to_vmm_error_conversion() {
        let vq_err = VirtqueueError::ChainTooLong { max: 256 };

        let vmm_err: VmmError = vq_err.into();
        assert!(matches!(vmm_err, VmmError::Virtqueue(_)));

        // The error message should contain the original error text
        let msg = vmm_err.to_string();
        assert!(
            msg.contains("256"),
            "converted error should preserve original text: {msg}"
        );
    }
}
