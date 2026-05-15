// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Mock backend for `cfg(test)` unit tests.
//!
//! Pure stubs — no simulated hypervisor, no vCPU execution. Tests that need
//! actual vCPU execution use integration tests with the KVM backend.

use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use amla_core::{DeviceWaker, IrqFactory};

use crate::error::Result;

/// Error type for the mock backend.
#[derive(Debug, thiserror::Error)]
pub enum MockVmmError {
    /// Generic mock error.
    #[error("{0}")]
    Other(String),
}

struct MockIrqLineInner {
    assert_count: AtomicU32,
    deassert_count: AtomicU32,
}

struct MockIrqLine {
    inner: Arc<MockIrqLineInner>,
}

impl amla_core::IrqLine for MockIrqLine {
    fn assert(&self) {
        self.inner.assert_count.fetch_add(1, Ordering::Relaxed);
    }
    fn deassert(&self) {
        self.inner.deassert_count.fetch_add(1, Ordering::Relaxed);
    }
}

/// Test-observable IRQ state.
pub struct MockIrqState {
    lines: parking_lot::Mutex<Vec<Arc<MockIrqLineInner>>>,
}

impl MockIrqState {
    fn new() -> Self {
        Self {
            lines: parking_lot::Mutex::new(Vec::new()),
        }
    }

    /// Number of IRQ lines created.
    pub fn line_count(&self) -> usize {
        self.lines.lock().len()
    }

    /// Total `assert()` calls on the given IRQ line index.
    pub fn assert_count(&self, idx: usize) -> u32 {
        self.lines.lock()[idx].assert_count.load(Ordering::Relaxed)
    }

    /// Total `deassert()` calls on the given IRQ line index.
    pub fn deassert_count(&self, idx: usize) -> u32 {
        self.lines.lock()[idx]
            .deassert_count
            .load(Ordering::Relaxed)
    }
}

/// Worker entry point (mock — stub).
pub async fn worker_main() -> ! {
    unimplemented!("mock backend has no subprocess worker")
}

/// Mock shell pool.
#[derive(Clone)]
pub struct BackendPools {
    inner: Arc<BackendPoolsInner>,
}

struct BackendPoolsInner {
    vcpu_count: u32,
    device_layout: crate::devices::DeviceLayout,
    shells_in_use: AtomicUsize,
    closed_shells: AtomicUsize,
    /// Observable IRQ state.
    pub irq_state: Arc<MockIrqState>,
}

impl BackendPools {
    /// Always available.
    pub fn available() -> bool {
        true
    }

    /// Create a new mock pool.
    pub fn new(
        _pool_size: usize,
        config: &crate::VmConfig,
        _worker: amla_core::WorkerProcessConfig,
    ) -> Result<Self> {
        config.validate()?;
        let device_layout = crate::devices::DeviceLayout::from_config(config)?;
        Ok(Self {
            inner: Arc::new(BackendPoolsInner {
                vcpu_count: config.vcpu_count,
                device_layout,
                shells_in_use: AtomicUsize::new(0),
                closed_shells: AtomicUsize::new(0),
                irq_state: Arc::new(MockIrqState::new()),
            }),
        })
    }

    /// Number of vCPUs per shell.
    pub fn vcpu_count(&self) -> u32 {
        self.inner.vcpu_count
    }

    /// Device layout this pool was created for.
    pub(crate) fn device_layout(&self) -> &crate::devices::DeviceLayout {
        &self.inner.device_layout
    }

    /// No-op.
    pub fn prewarm(&self, _count: usize) -> Result<usize> {
        Ok(0)
    }

    /// Number of shells closed through the explicit close transition.
    pub fn closed_shell_count(&self) -> usize {
        self.inner.closed_shells.load(Ordering::Relaxed)
    }
}

/// Mock VM shell (stubs only).
pub struct BackendVm {
    pools: BackendPools,
}

impl Drop for BackendVm {
    fn drop(&mut self) {
        self.pools
            .inner
            .shells_in_use
            .fetch_sub(1, Ordering::Relaxed);
    }
}

impl BackendVm {
    /// Acquire a mock shell.
    pub async fn build(pools: &BackendPools) -> Result<Self> {
        pools.inner.shells_in_use.fetch_add(1, Ordering::Relaxed);
        Ok(Self {
            pools: pools.clone(),
        })
    }

    /// Map memory (mock — no-op).
    pub async fn map_memory(
        &mut self,
        _handles: &[&amla_mem::MemHandle],
        _mappings: &[amla_core::MemoryMapping],
    ) -> Result<()> {
        Ok(())
    }

    /// Restore state (stub — no-op).
    pub async fn restore_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        Ok(())
    }

    /// Save state (stub — no-op).
    pub async fn save_state(&self, _view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        Ok(())
    }

    /// Write boot state (stub — no-op).
    pub async fn write_boot_state(
        &self,
        _view: &mut amla_core::vm_state::VmState<'_>,
        _boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        Ok(())
    }

    /// Resume vCPU (stub -- returns Interrupted immediately).
    pub async fn resume(
        &self,
        _id: amla_core::VcpuId,
        _info: Option<amla_core::VcpuResponse>,
    ) -> Result<amla_core::VcpuExit> {
        Ok(amla_core::VcpuExit::Interrupted)
    }

    /// Preempt a vCPU (no-op in mock).
    #[allow(clippy::unused_self)]
    pub fn preempt_vcpu(&self, _id: amla_core::VcpuId) {}

    /// Number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.pools.inner.vcpu_count
    }

    /// Drain console output (no-op in mock).
    #[allow(clippy::unused_self)]
    pub fn drain_console_output(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Create device waker (stub).
    pub async fn create_device_waker(&self) -> crate::Result<Arc<dyn DeviceWaker>> {
        Ok(Arc::new(amla_core::BasicDeviceWaker::new()))
    }

    /// Close the mock VM.
    pub(crate) async fn close(self) -> Result<crate::state::BackendClosed> {
        self.pools
            .inner
            .closed_shells
            .fetch_add(1, Ordering::Relaxed);
        drop(self);
        Ok(crate::state::BackendClosed::new())
    }
}

impl IrqFactory for BackendVm {
    fn create_resampled_irq_line(
        &self,
        _gsi: u32,
    ) -> std::result::Result<Box<dyn amla_core::IrqLine>, Box<dyn std::error::Error + Send + Sync>>
    {
        let inner = Arc::new(MockIrqLineInner {
            assert_count: AtomicU32::new(0),
            deassert_count: AtomicU32::new(0),
        });
        self.pools
            .inner
            .irq_state
            .lines
            .lock()
            .push(Arc::clone(&inner));
        Ok(Box::new(MockIrqLine { inner }))
    }
}
