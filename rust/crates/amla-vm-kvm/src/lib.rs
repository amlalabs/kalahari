// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

// =============================================================================
// Crate-level lint configuration for low-level KVM/VMM code
// =============================================================================
// Require documentation for all public items
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! KVM backend: shell-only VM management.
//!
//! This crate provides KVM shell management:
//!
//! - **Shell pooling**: Pre-warmed KVM shells with registered hardware
//! - **State capture/restore**: vCPU and irqchip snapshot support
//!
//! Memory management is handled by the VMM layer (amla-vmm) via `MemoryNode`.
//! This crate only manages the KVM VM fd, vCPU fds, and pre-registered hardware.
//!
//! On non-Linux targets this crate is empty — KVM is Linux-only.

#[cfg(target_os = "linux")]
mod arch;
/// Boot protocol support (kernel loading, vCPU boot state).
/// Arch-specific implementation selected at compile time.
#[cfg(target_os = "linux")]
pub use arch::boot;
#[cfg(target_os = "linux")]
pub mod builder;
#[cfg(target_os = "linux")]
pub(crate) mod device_waker;
#[cfg(target_os = "linux")]
pub mod error;
#[cfg(target_os = "linux")]
pub mod irq;
#[cfg(target_os = "linux")]
pub(crate) mod shell;
#[cfg(all(target_os = "linux", feature = "subprocess"))]
pub mod subprocess;
#[cfg(target_os = "linux")]
pub mod vcpu;

// Re-export primary interface types

#[cfg(target_os = "linux")]
pub use arch::{VcpuSnapshot, VmStateSnapshot};
#[cfg(target_os = "linux")]
pub use builder::{Vm, VmBuilder, VmPools};

#[cfg(target_os = "linux")]
pub use amla_core::GUEST_PHYS_ADDR;
#[cfg(target_os = "linux")]
pub use error::{Result, VmmError};
#[cfg(target_os = "linux")]
pub use irq::{IrqLine, irqs};
#[cfg(target_os = "linux")]
pub use shell::HardwareLayout;

// Re-export kvm types used in public API (x86_64-specific register types)
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub use kvm_bindings::{kvm_fpu, kvm_lapic_state, kvm_regs, kvm_sregs, kvm_xcrs};

/// Get the system page size (cached after first call).
///
/// Re-exported from amla-mem.
#[cfg(target_os = "linux")]
pub use amla_mem::page_size;

/// Subprocess worker entry point. Never returns.
#[cfg(all(target_os = "linux", feature = "subprocess"))]
pub async fn worker_main() -> ! {
    subprocess::worker::worker_main().await
}

/// Subprocess worker entry point (stub).
#[cfg(not(all(target_os = "linux", feature = "subprocess")))]
pub async fn worker_main() -> ! {
    unimplemented!("KVM subprocess worker not available in this build")
}
