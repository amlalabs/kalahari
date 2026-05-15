// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 `GICv3` snapshot POD layout.
//!
//! Fixed-size `repr(C)` types for the in-kernel KVM GIC state, stored inside
//! `IrqchipSectionState::arch_blob`. Used by `gic_state.rs` conversions to and
//! from `KvmGicState`.
//!
//! # Compatibility
//!
//! This is a backend-private, internal same-version snapshot layout for KVM's
//! in-kernel `GICv3`. It is not interchangeable with the userspace-GIC/HVF
//! `amla_vm_gic::GicState` blob even when field names overlap; for example, KVM
//! can carry active priority state through AP registers without the userspace
//! GIC's explicit active-priority stack. Producers and consumers must be built
//! from the same source version and the KVM backend, or an enclosing snapshot
//! header must reject the blob before these structs are interpreted.

use bytemuck::{Pod, Zeroable};

use amla_core::vm_state::{IRQCHIP_BLOB_SIZE, MAX_VCPUS};

/// Number of SGIs + PPIs per vCPU (fixed by `GICv3` architecture).
pub const GIC_PPI_SGI_COUNT: usize = 32;

/// Number of SPIs.
pub const GIC_SPI_COUNT: usize = amla_boot::arm64::irq::GIC_SPI_COUNT as usize;

/// Maximum active priority entries per CPU interface.
pub const GIC_MAX_ACTIVE_PRIORITIES: usize = 16;

/// Per-IRQ configuration.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicIrqConfig {
    pub enabled: u8,
    pub group: u8,
    pub priority: u8,
    /// 0 = Level, 1 = Edge
    pub trigger: u8,
}

/// Per-IRQ dynamic state.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicIrqDynState {
    pub pending: u8,
    pub active: u8,
    pub edge_latch: u8,
    pub hw_level: u8,
}

/// One active priority entry.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicActivePriority {
    pub priority: u8,
    pub pad: [u8; 3],
    pub intid: u32,
}

/// GICD (distributor) state.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicDistributorState {
    pub ctlr: u32,
    pub pad: u32,
    pub spi_config: [GicIrqConfig; GIC_SPI_COUNT],
    pub spi_state: [GicIrqDynState; GIC_SPI_COUNT],
    pub irouter: [u64; GIC_SPI_COUNT],
}

/// GICR (per-vCPU redistributor) state.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicRedistributorState {
    pub waker: u32,
    pub pad: u32,
    pub ppi_sgi_config: [GicIrqConfig; GIC_PPI_SGI_COUNT],
    pub ppi_sgi_state: [GicIrqDynState; GIC_PPI_SGI_COUNT],
}

/// ICC (per-vCPU CPU interface) state.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicCpuInterfaceState {
    pub pmr: u8,
    pub bpr0: u8,
    pub bpr1: u8,
    pub igrpen0: u8,
    pub igrpen1: u8,
    pub eoi_mode: u8,
    /// Running priority. Left zero in KVM conversion (KVM reconstructs it
    /// internally from AP registers).
    pub running_priority: u8,
    /// Number of valid entries in `active_priorities`. Left zero in KVM
    /// conversion (AP0R/AP1R bitmaps carry the same information).
    pub active_priority_count: u8,
    pub ap0r: [u32; 4],
    pub ap1r: [u32; 4],
    pub active_priorities: [GicActivePriority; GIC_MAX_ACTIVE_PRIORITIES],
}

/// Complete `GICv3` state (distributor + per-vCPU redistributor + CPU interface).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicState {
    pub vcpu_count: u32,
    pub pad: u32,
    pub distributor: GicDistributorState,
    pub redistributors: [GicRedistributorState; MAX_VCPUS],
    pub cpu_interfaces: [GicCpuInterfaceState; MAX_VCPUS],
}

// 8 bytes account for the magic + version envelope written by
// state::write_arch_blob. Keep in sync with ARCH_BLOB_HEADER_SIZE in state.rs.
const _: () = assert!(
    core::mem::size_of::<GicState>() + 8 <= IRQCHIP_BLOB_SIZE,
    "GicState + arch blob header exceeds IRQCHIP_BLOB_SIZE"
);
