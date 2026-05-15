// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! ARM64 `GICv3` state (repr(C), POD).
//!
//! Fixed-size layout for the GIC distributor, redistributors, and CPU
//! interfaces. Lives inside `IrqchipSectionState::arch_blob`.
//!
//! # Compatibility
//!
//! This is a backend-private, internal same-version snapshot layout for the
//! userspace GIC implementation used by HVF-style backends. `repr(C)` and `Pod`
//! make the current build's bytes well-defined, but they do not define a
//! durable migration ABI or a cross-backend interchange format. In particular,
//! this blob is not interchangeable with the KVM in-kernel GIC POD layout even
//! when field names overlap. Producers and consumers of `GicState` bytes must be
//! built from the same source version and the same backend family, or an
//! enclosing snapshot header must reject the blob before these structs are
//! interpreted.

use bytemuck::{Pod, Zeroable};

use amla_core::vm_state::{IRQCHIP_BLOB_SIZE, MAX_VCPUS};

/// Number of SGIs + PPIs per vCPU (fixed by `GICv3` architecture).
pub const GIC_PPI_SGI_COUNT: usize = 32;

/// Number of SPIs (matches `NR_SPIS` in amla-gic).
pub const GIC_SPI_COUNT: usize = amla_boot::arm64::irq::GIC_SPI_COUNT as usize;

/// Maximum active priority entries per CPU interface.
pub const GIC_MAX_ACTIVE_PRIORITIES: usize = 16;

/// Per-IRQ configuration (Pod equivalent of `IrqConfig`).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct GicIrqConfig {
    pub enabled: u8,
    pub group: u8,
    pub priority: u8,
    /// 0 = Level, 1 = Edge
    pub trigger: u8,
}

/// Per-IRQ dynamic state (Pod equivalent of `IrqState`).
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
    /// Running priority. Must match the last entry in `active_priorities`, or
    /// `PRIORITY_IDLE` when `active_priority_count` is zero.
    pub running_priority: u8,
    /// Number of valid entries in `active_priorities`.
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

// Compile-time assertion: GicState must fit in IRQCHIP_BLOB_SIZE.
const _: () = assert!(
    core::mem::size_of::<GicState>() <= IRQCHIP_BLOB_SIZE,
    "GicState exceeds IRQCHIP_BLOB_SIZE"
);
