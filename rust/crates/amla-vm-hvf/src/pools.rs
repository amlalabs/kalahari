// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF subprocess VM pools — pre-spawns worker processes.
//!
//! Follows the same pooling pattern as the KVM subprocess backend:
//! `VmPools` maintains a channel of pre-warmed `SubprocessShell`s,
//! each representing a fully initialized worker process with a ring
//! buffer IPC channel.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use amla_core::WorkerProcessConfig;
use amla_ipc::{RingBuffer, Subprocess};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::error::{Result, VmmError};
use crate::protocol::{
    WorkerDeviceSlot, WorkerQueueSlot, WorkerRequest, WorkerResponse, WorkerTopology,
};

// Re-export layout types (they are platform-agnostic).
pub use crate::layout::HardwareLayout;

// ============================================================================
// SubprocessShell — the pooled unit
// ============================================================================

pub(crate) struct SubprocessShell {
    pub(crate) ring: RingBuffer,
    pub(crate) vcpu_count: u32,
}

// SAFETY: RingBuffer contains mmap + OwnedFd, both are Send.
unsafe impl Send for SubprocessShell {}

// ============================================================================
// Shell creation — spawn worker + ring + Init handshake
// ============================================================================

fn create_shell(
    worker: &WorkerProcessConfig,
    vcpu_count: u32,
    layout: &HardwareLayout,
) -> Result<SubprocessShell> {
    let worker_path = worker
        .executable_path()
        .map_err(VmmError::sys("resolve worker executable"))?;
    let worker_args: Vec<&std::ffi::OsStr> = worker
        .args()
        .iter()
        .map(std::ffi::OsString::as_os_str)
        .collect();
    let subprocess = Subprocess::spawn(&worker_path, &worker_args, &[])
        .map_err(|e| VmmError::Ipc(format!("spawn worker: {e}")))?;
    log::trace!("started {}: {subprocess:?}", worker_path.display());
    let mut ring =
        RingBuffer::establish(subprocess).map_err(|e| VmmError::Ipc(format!("ring: {e}")))?;

    let topology = worker_topology_from_layout(layout)?;

    // Synchronous handshake — we're typically in spawn_blocking.
    // Use the existing runtime's Handle when available (avoids creating
    // a throwaway runtime per shell). Fall back to a temporary runtime
    // for callers like prewarm() that may run outside tokio.
    {
        let (mut sender, mut receiver) = ring
            .split(true)
            .map_err(|e| VmmError::Ipc(format!("ring split: {e}")))?;
        let handshake = async {
            sender
                .send(WorkerRequest::Init {
                    vcpu_count,
                    topology,
                })
                .await
                .map_err(|e| VmmError::Ipc(format!("Init send: {e}")))?;

            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                receiver.recv::<WorkerResponse>(),
            )
            .await
            .map_err(|_| VmmError::Ipc("worker Init timeout".into()))?
            .map_err(|e| VmmError::Ipc(format!("Init recv: {e}")))?;

            match resp {
                WorkerResponse::Ready => Ok(()),
                WorkerResponse::Error { error } => Err(error.into_vmm_error()),
                _ => Err(VmmError::Ipc("unexpected Init response".into())),
            }
        };

        // Two call paths reach here:
        //   - `acquire_shell` / `refill_task` route through `spawn_blocking`,
        //     which runs on a tokio worker thread. `Handle::try_current()`
        //     succeeds and the handshake runs on the existing runtime. This
        //     is the hot path.
        //   - Synchronous `prewarm()` is called directly (not via
        //     `spawn_blocking`). If the caller is on a tokio thread this
        //     still hits the `try_current` branch; if the caller is NOT on
        //     tokio, we fall through and build a throwaway current-thread
        //     runtime just for the Init handshake.
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.block_on(handshake)?;
        } else {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .map_err(VmmError::sys("build Init runtime"))?;
            rt.block_on(handshake)?;
        }
    }

    Ok(SubprocessShell { ring, vcpu_count })
}

fn worker_topology_from_layout(layout: &HardwareLayout) -> Result<WorkerTopology> {
    let mut devices: Vec<_> = layout
        .device_slots
        .iter()
        .map(|slot| WorkerDeviceSlot {
            gsi: slot.gsi,
            resample_wake_idx: slot
                .resample_wake_idx
                .map(amla_core::DeviceWakeIndex::as_u8),
            queues: Vec::new(),
        })
        .collect();

    for queue in &layout.io_slots {
        let device_count = devices.len();
        let device = devices.get_mut(queue.device_idx).ok_or_else(|| {
            VmmError::Config(format!(
                "io slot references device {} but layout has {} devices",
                queue.device_idx, device_count
            ))
        })?;
        device.queues.push(WorkerQueueSlot {
            mmio_notify_addr: queue.mmio_notify_addr,
            queue_idx: queue.queue_idx,
            wake_idx: queue.wake_idx.as_u8(),
        });
    }

    Ok(WorkerTopology { devices })
}

// ============================================================================
// VmPools
// ============================================================================

/// HVF subprocess VM pools — pre-spawns worker processes.
#[derive(Clone, Debug)]
pub struct VmPools {
    inner: Arc<VmPoolsInner>,
    _owner: Arc<VmPoolsOwner>,
}

struct VmPoolsInner {
    shell_tx: mpsc::Sender<SubprocessShell>,
    shell_rx: tokio::sync::Mutex<mpsc::Receiver<SubprocessShell>>,
    vcpu_count: u32,
    layout: Arc<HardwareLayout>,
    worker: WorkerProcessConfig,
    pool_size: usize,
    refill_started: AtomicBool,
    shutdown: CancellationToken,
}

#[derive(Debug)]
struct VmPoolsOwner {
    shutdown: CancellationToken,
}

impl Drop for VmPoolsOwner {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

impl std::fmt::Debug for VmPoolsInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmPoolsInner")
            .field("vcpu_count", &self.vcpu_count)
            .field("pool_size", &self.pool_size)
            .finish_non_exhaustive()
    }
}

impl VmPools {
    /// Check if HVF is available (compile-time check).
    pub fn available() -> bool {
        cfg!(all(target_os = "macos", target_arch = "aarch64"))
    }

    /// Create HVF subprocess pools.
    pub fn new(
        pool_size: usize,
        vcpu_count: u32,
        layout: HardwareLayout,
        worker: WorkerProcessConfig,
    ) -> Result<Self> {
        if vcpu_count == 0 {
            return Err(VmmError::Config("vcpu_count must be >= 1".into()));
        }

        let (shell_tx, shell_rx) = mpsc::channel(pool_size.max(1));

        let shutdown = CancellationToken::new();

        Ok(VmPools {
            inner: Arc::new(VmPoolsInner {
                shell_tx,
                shell_rx: tokio::sync::Mutex::new(shell_rx),
                vcpu_count,
                layout: Arc::new(layout),
                worker,
                pool_size,
                refill_started: AtomicBool::new(false),
                shutdown: shutdown.clone(),
            }),
            _owner: Arc::new(VmPoolsOwner { shutdown }),
        })
    }

    /// vCPU count per shell.
    pub fn vcpu_count(&self) -> u32 {
        self.inner.vcpu_count
    }

    /// Maximum GSI used by the hardware layout, or 0 if no slots are declared.
    ///
    /// Used by `VmBuilder::build_shell` to size the resample flag vector
    /// so every GSI produced by the layout has a lookup entry.
    pub fn max_gsi(&self) -> u32 {
        self.inner
            .layout
            .device_slots
            .iter()
            .map(|s| s.gsi)
            .max()
            .unwrap_or(0)
    }

    /// Map GSI to queue wake bit for IRQ resample notifications.
    pub(crate) fn resample_wake_by_gsi(&self) -> Vec<Option<amla_core::DeviceWakeIndex>> {
        let len = (self.max_gsi() as usize).saturating_add(1).max(32);
        let mut wake_by_gsi = vec![None; len];
        for slot in &self.inner.layout.device_slots {
            let Some(wake_idx) = slot.resample_wake_idx else {
                continue;
            };
            if let Some(entry) = wake_by_gsi.get_mut(slot.gsi as usize) {
                *entry = Some(wake_idx);
            }
        }
        wake_by_gsi
    }

    /// Synchronous prewarm (best-effort).
    pub fn prewarm(&self, count: usize) -> Result<usize> {
        let mut created = 0;
        for _ in 0..count {
            let shell = create_shell(
                &self.inner.worker,
                self.inner.vcpu_count,
                &self.inner.layout,
            )?;
            if self.inner.shell_tx.try_send(shell).is_err() {
                break;
            }
            created += 1;
        }
        Ok(created)
    }

    /// Shutdown the pool.
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    /// Acquire a pre-warmed shell, or create one inline.
    pub(crate) async fn acquire_shell(&self) -> Result<SubprocessShell> {
        if self.inner.pool_size > 0 {
            self.ensure_refill_started();
        }

        let mut rx = self.inner.shell_rx.lock().await;
        if let Ok(shell) = rx.try_recv() {
            drop(rx);
            Ok(shell)
        } else {
            drop(rx);
            let vcpu_count = self.inner.vcpu_count;
            let layout = Arc::clone(&self.inner.layout);
            let worker = self.inner.worker.clone();
            tokio::task::spawn_blocking(move || create_shell(&worker, vcpu_count, &layout))
                .await
                .map_err(|e| VmmError::Config(format!("spawn_blocking panicked: {e}")))?
        }
    }

    fn ensure_refill_started(&self) {
        if self
            .inner
            .refill_started
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let inner = Arc::clone(&self.inner);
            let flag = Arc::clone(&self.inner);
            // lifetime: detached. Loop exits when `inner.shutdown`
            // (tokio_util CancellationToken) is cancelled -- triggered by
            // VmPools::shutdown(), which callers invoke on teardown. Also
            // exits if `inner.shell_tx` send fails (all receivers dropped).
            // No JoinHandle retained; `refill_started` is reset on exit so a
            // later acquire_shell() can respawn.
            tokio::spawn(async move {
                Self::refill_task(inner).await;
                // Reset so a new refill task can be spawned if this one
                // exits (e.g. panic, cancellation, or shutdown).
                flag.refill_started.store(false, Ordering::Release);
            });
        }
    }

    async fn refill_task(inner: Arc<VmPoolsInner>) {
        const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(5);
        let mut backoff = std::time::Duration::from_millis(100);

        loop {
            let permit = tokio::select! {
                biased;
                () = inner.shutdown.cancelled() => return,
                permit = inner.shell_tx.reserve() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return,
                },
            };

            let vcpu_count = inner.vcpu_count;
            let layout = Arc::clone(&inner.layout);
            let worker = inner.worker.clone();

            let result =
                tokio::task::spawn_blocking(move || create_shell(&worker, vcpu_count, &layout))
                    .await;

            match result {
                Ok(Ok(shell)) => {
                    if inner.shutdown.is_cancelled() {
                        return;
                    }
                    backoff = std::time::Duration::from_millis(100);
                    permit.send(shell);
                }
                Ok(Err(e)) => {
                    drop(permit);
                    log::error!("hvf refill_task: {e}");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = inner.shutdown.cancelled() => return,
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(e) => {
                    drop(permit);
                    log::error!("hvf refill_task panic: {e}");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = inner.shutdown.cancelled() => return,
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
            }
        }
    }
}
