// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Stub types for non-macOS/non-arm64 platforms.
//!
//! All constructors return `NotImplemented`. The VM constructor is private so
//! external callers cannot create an impossible backend value.

use std::sync::Arc;

use amla_core::{IrqFactory, IrqLine, WorkerProcessConfig};

use crate::error::{Result, VmmError};
use crate::layout::HardwareLayout;

// =============================================================================
// VmPools (stub)
// =============================================================================

pub struct VmPools {
    _private: (),
}

impl VmPools {
    pub const fn available() -> bool {
        false
    }

    pub fn new(
        _pool_size: usize,
        _vcpu_count: u32,
        _layout: HardwareLayout,
        _worker: WorkerProcessConfig,
    ) -> Result<Self> {
        Err(VmmError::NotImplemented)
    }

    #[allow(clippy::unused_self)]
    pub fn vcpu_count(&self) -> u32 {
        unreachable!("stub VmPools is never constructed")
    }

    #[allow(clippy::unused_self)]
    pub const fn prewarm(&self, _count: usize) -> Result<usize> {
        Err(VmmError::NotImplemented)
    }
}

// =============================================================================
// Vm (stub)
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
        unreachable!("stub Vm is never constructed")
    }

    #[allow(clippy::unused_self)]
    pub fn preempt_vcpu(&self, _id: amla_core::VcpuId) {
        unreachable!("stub Vm is never constructed")
    }

    #[allow(clippy::unused_self)]
    pub fn vcpu_count(&self) -> u32 {
        unreachable!("stub Vm is never constructed")
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
        unreachable!("stub Vm is never constructed")
    }

    pub async fn restore_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        unreachable!("stub Vm is never constructed")
    }

    pub async fn save_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        unreachable!("stub Vm is never constructed")
    }

    pub async fn write_boot_state(
        &self,
        _view: &mut amla_core::vm_state::VmState<'_>,
        _boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        unreachable!("stub Vm is never constructed")
    }

    pub async fn create_device_waker(&self) -> crate::Result<Arc<dyn amla_core::DeviceWaker>> {
        unreachable!("stub Vm is never constructed")
    }
}

impl IrqFactory for Vm {
    fn create_resampled_irq_line(
        &self,
        _gsi: u32,
    ) -> std::result::Result<Box<dyn IrqLine>, Box<dyn std::error::Error + Send + Sync>> {
        unreachable!("stub Vm is never constructed")
    }
}

// =============================================================================
// VmBuilder (stub)
// =============================================================================

pub struct VmBuilder;

impl VmBuilder {
    pub async fn build_shell(self) -> Result<Vm> {
        Err(VmmError::NotImplemented)
    }
}
