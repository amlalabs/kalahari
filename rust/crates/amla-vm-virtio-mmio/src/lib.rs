// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Virtio MMIO v2 transport layer.
//!
//! Provides [`MmioTransport`] for dispatching MMIO register reads/writes per
//! the virtio-mmio spec. Works for all device types with zero per-device
//! transport code.
//!
//! # MMIO Address Routing
//!
//! Each device gets a 0x200-byte MMIO region. Dispatch is a simple range check:
//! `(addr - MMIO_BASE) / 0x200` → device index.
//!
//! The address space is over-provisioned to 64 slots (32 KiB total). Active
//! devices occupy the first N slots chosen by platform code; the remaining
//! slots are reserved and return `device_id = 0` (not present).

#[cfg(test)]
mod tests;
mod transport;

pub use transport::{
    CONFIG_GENERATION, DEVICE_ID, INTERRUPT_STATUS, MAGIC_VALUE, MmioTransport, QUEUE_NOTIFY,
    STATUS, VENDOR_ID_REG, VERSION, VIRTIO_MMIO_MAGIC, VIRTIO_MMIO_VERSION,
};

// =============================================================================
// MMIO Address Constants
// =============================================================================

/// Base MMIO address for virtio devices.
pub const MMIO_BASE: u64 = 0x0A00_0000;

/// Size of each device's MMIO region.
pub const MMIO_DEVICE_SIZE: u64 = 0x200;

/// Total device slots in the MMIO address space.
///
/// Over-provisioned to 64 so the mmap layout is fixed regardless of how many
/// devices are actually active. Reserved slots return `device_id = 0`.
pub const NUM_DEVICES: usize = 64;

/// Total MMIO region size (64 devices × 0x200 = 32 KiB).
pub const MMIO_TOTAL_SIZE: u64 = MMIO_DEVICE_SIZE * NUM_DEVICES as u64;

/// Maximum active devices supported by the x86 IOAPIC interrupt layout.
///
/// IOAPIC has 24 pins; GSI starts at 5, so 19 are usable (5..23).
/// ARM64 IRQ capacity is owned by `amla_boot::arm64::irq`.
#[cfg(not(target_arch = "aarch64"))]
pub const MAX_ACTIVE_DEVICES: usize = 19;

// =============================================================================
// GSI Assignment
// =============================================================================

/// `x86_64` GSI offset for virtio devices — avoids legacy ISA IRQs 0-4.
/// See also: `amla-vm-kvm` `arch::consts::VIRTIO_IRQ_BASE`.
#[cfg(not(target_arch = "aarch64"))]
const VIRTIO_GSI_OFFSET: u32 = 5;

/// Compute the `x86_64` GSI (interrupt number) for a device index.
///
/// ARM64 IRQ assignment is owned by `amla_boot::arm64::irq`.
#[inline]
#[must_use]
#[cfg(not(target_arch = "aarch64"))]
#[allow(clippy::cast_possible_truncation)] // device_idx bounded by MAX_ACTIVE_DEVICES
pub fn device_gsi(device_idx: usize) -> u32 {
    debug_assert!(
        device_idx < MAX_ACTIVE_DEVICES,
        "device_gsi: index {device_idx} exceeds MAX_ACTIVE_DEVICES ({MAX_ACTIVE_DEVICES})"
    );
    VIRTIO_GSI_OFFSET + device_idx as u32
}

/// Compute the MMIO base address for a device index.
#[inline]
#[must_use]
pub const fn device_mmio_addr(device_idx: usize) -> u64 {
    MMIO_BASE + (device_idx as u64) * MMIO_DEVICE_SIZE
}

/// Resolve an MMIO address to (`device_index`, `offset_within_device`).
///
/// Returns `None` if the address is outside the virtio MMIO region.
#[inline]
pub const fn resolve_mmio_addr(addr: u64) -> Option<(usize, u64)> {
    if addr < MMIO_BASE {
        return None;
    }
    let rel = addr - MMIO_BASE;
    if rel >= MMIO_TOTAL_SIZE {
        return None;
    }
    let dev_idx = (rel / MMIO_DEVICE_SIZE) as usize;
    let offset = rel % MMIO_DEVICE_SIZE;
    Some((dev_idx, offset))
}
