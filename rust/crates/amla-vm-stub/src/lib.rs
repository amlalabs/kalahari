// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Stub hypervisor backend for unsupported platforms.
//!
//! Provides the same API shape as real backends (amla-kvm, amla-hvf,
//! amla-hyperv) so `define_backend!(amla_stub)` works uniformly.
//! `VmPools::new()` always returns `Err` — nothing is ever constructed.

use std::sync::Arc;

use amla_core::{DeviceWakeIndex, IrqFactory};

/// Stub backend error.
#[derive(Debug, thiserror::Error)]
#[error("no hypervisor backend on this platform")]
pub struct VmmError;

pub type Result<T> = std::result::Result<T, VmmError>;

// =============================================================================
// HardwareLayout
// =============================================================================

#[derive(Clone, Debug)]
pub struct HardwareLayout {
    pub device_slots: Vec<(u32, Option<DeviceWakeIndex>)>,
    pub io_slots: Vec<(usize, u64, u32, DeviceWakeIndex)>,
}

impl HardwareLayout {
    pub const fn empty() -> Self {
        Self {
            device_slots: Vec::new(),
            io_slots: Vec::new(),
        }
    }

    pub fn from_device_and_queue_slots(
        device_slots: impl IntoIterator<Item = (u32, Option<DeviceWakeIndex>)>,
        io_slots: impl IntoIterator<Item = (usize, u64, u32, DeviceWakeIndex)>,
    ) -> Self {
        Self {
            device_slots: device_slots.into_iter().collect(),
            io_slots: io_slots.into_iter().collect(),
        }
    }
}

// =============================================================================
// VmPools
// =============================================================================

pub struct VmPools(());

impl VmPools {
    pub const fn available() -> bool {
        false
    }

    pub fn new(_pool_size: usize, _vcpu_count: u32, _layout: HardwareLayout) -> Result<Self> {
        Err(VmmError)
    }

    pub fn vcpu_count(&self) -> u32 {
        unreachable!()
    }

    #[allow(clippy::unused_self)]
    pub const fn drain_console_output(&self) -> Vec<u8> {
        Vec::new()
    }

    pub fn prewarm(&self, _count: usize) -> Result<usize> {
        unreachable!()
    }
}

// =============================================================================
// Vm + VmBuilder
// =============================================================================

pub struct Vm(());

impl Vm {
    pub const fn builder(_pools: &VmPools) -> VmBuilder {
        VmBuilder
    }

    pub async fn resume(
        &self,
        _id: amla_core::VcpuId,
        _info: Option<amla_core::VcpuResponse>,
    ) -> Result<amla_core::VcpuExit> {
        unreachable!()
    }

    pub fn preempt_vcpu(&self, _id: amla_core::VcpuId) {
        unreachable!()
    }

    pub fn vcpu_count(&self) -> u32 {
        unreachable!()
    }

    #[allow(clippy::unused_self)]
    pub const fn drain_console_output(&self) -> Vec<u8> {
        Vec::new()
    }

    pub async fn map_memory(
        &mut self,
        _handles: &[&amla_mem::MemHandle],
        _mappings: &[amla_core::MemoryMapping],
    ) -> Result<()> {
        unreachable!()
    }

    pub async fn restore_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        unreachable!()
    }

    pub async fn save_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        unreachable!()
    }

    pub async fn write_boot_state(
        &self,
        _view: &mut amla_core::vm_state::VmState<'_>,
        _boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        unreachable!()
    }

    pub async fn create_device_waker(&self) -> Result<Arc<dyn amla_core::DeviceWaker>> {
        unreachable!()
    }

    /// Close the VM (unreachable in the stub backend).
    pub async fn close(self) -> Result<()> {
        unreachable!()
    }
}

impl IrqFactory for Vm {
    fn create_resampled_irq_line(
        &self,
        _gsi: u32,
    ) -> std::result::Result<Box<dyn amla_core::IrqLine>, Box<dyn std::error::Error + Send + Sync>>
    {
        unreachable!()
    }
}

/// Subprocess worker entry point (stub).
pub async fn worker_main() -> ! {
    unimplemented!("no hypervisor backend on this platform")
}

pub struct VmBuilder;

impl VmBuilder {
    pub async fn build_shell(self) -> Result<Vm> {
        Err(VmmError)
    }
}
