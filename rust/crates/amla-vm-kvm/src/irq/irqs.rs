// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Common IRQ assignments for virtio-mmio devices.

/// Serial port COM1 (`x86_64` only).
#[cfg(target_arch = "x86_64")]
pub const SERIAL_COM1: u32 = 4;

/// First virtio-mmio device IRQ, delegated to the architecture module.
#[cfg(target_arch = "x86_64")]
pub const VIRTIO_MMIO_BASE: u32 = crate::arch::consts::VIRTIO_IRQ_BASE;
/// First virtio-mmio device SPI on ARM64.
#[cfg(target_arch = "aarch64")]
pub const VIRTIO_MMIO_BASE: u32 = amla_boot::arm64::irq::VIRTIO_MMIO_SPI_BASE;

/// Get IRQ for virtio-mmio device N (0-indexed).
#[inline]
pub const fn virtio_mmio(device_index: u32) -> u32 {
    VIRTIO_MMIO_BASE + device_index
}
