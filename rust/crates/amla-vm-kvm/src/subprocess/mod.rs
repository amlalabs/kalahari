// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! KVM subprocess backend — vCPU threads run in a separate worker process.
//!
//! The parent (VMM) spawns worker subprocesses via `amla-ipc`. Each worker
//! creates its own KVM VM, vCPU threads, and hardware (ioeventfds/irqfds).
//! All KVM ioctls happen in the worker. The parent communicates via IPC
//! ring buffer messages.
//!
//! # Pooling
//!
//! The pooled unit is a fully initialized subprocess. `VmPools` pre-spawns
//! workers and keeps them in a ready queue, identical to the in-process
//! shell pool pattern.

pub mod worker;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use amla_core::vcpu::VcpuResponse;
use amla_core::{
    BasicDeviceWaker, DeviceWakeIndex, DeviceWakeResult, DeviceWaker, IrqFactory, IrqLine,
    MappingHandleInfo, MemoryMapping, ValidatedMemoryMappings, VcpuExit, WorkerProcessConfig,
};
use amla_ipc::{IpcMessage, RingBuffer, Subprocess};
use amla_mem::MemHandle;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::arch::{VcpuSnapshot, VmStateSnapshot};
use crate::error::{Result, VmmError};
use crate::shell::HardwareLayout;

// ============================================================================
// Protocol — KVM-local IPC messages
// ============================================================================

/// Exact device/queue topology sent to a KVM worker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerTopology {
    /// Device entries in VMM device-slot order.
    pub devices: Vec<WorkerDeviceSlot>,
}

/// One worker-visible device slot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerDeviceSlot {
    /// GSI for irqfd registration.
    pub gsi: u32,
    /// Queue wake bit to set when this interrupt line receives guest EOI.
    pub resample_wake_idx: Option<u8>,
    /// Exact queue notification slots owned by this device.
    pub queues: Vec<WorkerQueueSlot>,
}

/// One worker-visible queue notification slot.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerQueueSlot {
    /// MMIO `QueueNotify` address.
    pub mmio_notify_addr: u64,
    /// `QueueNotify` value.
    pub queue_idx: u32,
    /// Global queue wake bit.
    pub wake_idx: u8,
}

/// Request from parent (VMM) to worker.
#[derive(Debug, IpcMessage)]
pub(crate) enum WorkerRequest {
    /// Initialize KVM VM with device topology.
    Init {
        /// Number of vCPUs to create.
        vcpu_count: u32,
        /// Exact worker hardware topology.
        topology: WorkerTopology,
    },
    /// Map guest physical memory.
    MapMemory {
        /// Backing memory regions, transferred out-of-band.
        #[ipc_resource]
        handles: Vec<MemHandle>,
        /// How to project each handle into GPA space.
        mappings: Vec<MemoryMapping>,
    },
    /// Begin save: capture all vCPU + irqchip state atomically.
    /// Worker stores in a local buffer, replies Ok. Fetch with
    /// `GetSavedVcpu` / `GetSavedIrqchip`.
    SaveState {
        /// Number of vCPUs to capture.
        vcpu_count: u32,
    },
    /// Fetch one captured vCPU snapshot (raw bytes) from the saved buffer.
    GetSavedVcpu {
        /// vCPU index (0-based).
        id: u32,
    },
    /// Fetch captured irqchip blob from the saved buffer (drops buffer).
    GetSavedIrqchip,
    /// Capture the backend's default irqchip state for a first boot seed.
    CaptureDefaultIrqchip,
    /// Restore one vCPU from snapshot bytes.
    RestoreVcpu {
        /// vCPU index (0-based).
        id: u32,
        /// Raw `VcpuSnapshot` bytes (repr(C) Pod).
        data: Vec<u8>,
    },
    /// Restore irqchip from a non-empty arch blob.
    RestoreIrqchip {
        /// Irqchip blob bytes.
        blob: Vec<u8>,
    },
    /// Resume a vCPU after the parent handled its exit.
    ResumeVcpu {
        /// vCPU index (0-based).
        id: u32,
        /// Monotonic sequence number for correlating exits with resumes.
        seq: u64,
        /// State update before resuming. None for initial resume.
        response: Option<VcpuResponse>,
    },
    /// Preempt a running vCPU (fire-and-forget).
    Preempt {
        /// vCPU index.
        id: u32,
    },
    /// Assert or deassert an IRQ line (fire-and-forget).
    IrqLine {
        /// Global System Interrupt number.
        gsi: u32,
        /// true = assert, false = deassert.
        level: bool,
    },
    /// Shut down the worker.
    Shutdown,
}

/// Response from worker to parent.
#[derive(Debug, IpcMessage)]
pub(crate) enum WorkerResponse {
    /// Worker initialized. Reply to Init.
    Ready,
    /// A vCPU exited the hypervisor.
    VcpuExit {
        /// vCPU index.
        id: u32,
        /// Sequence number from the corresponding `ResumeVcpu`.
        seq: u64,
        /// Exit reason.
        exit: VcpuExit,
    },
    /// Guest kicked a device queue (ioeventfd fired).
    DeviceKick {
        /// Global queue wake bit index.
        wake_idx: u8,
    },
    /// IRQ line needs resampling (guest EOI).
    IrqResample {
        /// GSI that received EOI.
        gsi: u32,
    },
    /// Batched UART console output from the worker.
    ///
    /// Contains bytes written by the guest to the UART data register
    /// (PL011 on ARM64, COM1 on `x86_64`). Handled locally in the worker
    /// to avoid per-character IPC round-trips. Flushed before any
    /// `VcpuExit` or `DeviceKick` to preserve ordering.
    ConsoleOutput {
        /// Buffered bytes (up to 256).
        data: Vec<u8>,
    },
    /// Bulk state data reply (vCPU snapshot bytes, irqchip blob, etc.).
    /// The caller knows which kind based on the request it sent.
    StateData {
        /// Raw bytes (`VcpuSnapshot` or irqchip blob).
        data: Vec<u8>,
    },
    /// Generic success.
    Ok,
    /// Operation failed.
    Error {
        /// Human-readable description.
        message: String,
    },
}

// ============================================================================
// IPC command channel — Vm methods → IPC task
// ============================================================================

enum IpcCommand {
    /// Send request, await one response.
    Request {
        request: WorkerRequest,
        reply: oneshot::Sender<Result<WorkerResponse>>,
    },
    /// Resume a vCPU. The reply oneshot delivers the next `VcpuExit` for
    /// this `(id, seq)` pair. Dropping the future before the exit arrives
    /// drops the receiver; the `ipc_task`'s send then returns `Err` and is
    /// silently discarded, so a cancelled resume can never wedge the task.
    ResumeVcpu {
        id: u32,
        seq: u64,
        response: Option<VcpuResponse>,
        reply: oneshot::Sender<Result<VcpuExit>>,
    },
}

// ============================================================================
// SubprocessShell — the pooled unit
// ============================================================================

struct SubprocessShell {
    ring: RingBuffer,
    vcpu_count: u32,
    topology: WorkerTopology,
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
) -> std::result::Result<SubprocessShell, Box<dyn std::error::Error + Send + Sync>> {
    amla_ipc::dbg_log!("create_shell enter");
    let worker_path = worker.executable_path()?;
    let worker_args: Vec<&std::ffi::OsStr> = worker
        .args()
        .iter()
        .map(std::ffi::OsString::as_os_str)
        .collect();
    let subprocess = Subprocess::spawn(&worker_path, &worker_args, &[])?;
    amla_ipc::dbg_log!("create_shell after Subprocess::spawn");
    let ring = RingBuffer::establish(subprocess)?;
    amla_ipc::dbg_log!("create_shell after RingBuffer::establish");

    let topology = worker_topology_from_layout(layout)?;

    amla_ipc::dbg_log!("create_shell exit ok");
    Ok(SubprocessShell {
        ring,
        vcpu_count,
        topology,
    })
}

fn worker_topology_from_layout(layout: &HardwareLayout) -> Result<WorkerTopology> {
    let mut devices: Vec<_> = layout
        .device_slots
        .iter()
        .map(|slot| WorkerDeviceSlot {
            gsi: slot.gsi,
            resample_wake_idx: slot.resample_wake_idx.map(DeviceWakeIndex::as_u8),
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

/// Subprocess VM pools — pre-spawns worker processes.
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
    /// Check if KVM is available.
    pub fn available() -> bool {
        kvm_ioctls::Kvm::new().is_ok()
    }

    /// Create subprocess pools.
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

    /// Synchronous prewarm (best-effort).
    pub fn prewarm(&self, count: usize) -> Result<usize> {
        let mut created = 0;
        for _ in 0..count {
            let shell = create_shell(
                &self.inner.worker,
                self.inner.vcpu_count,
                &self.inner.layout,
            )
            .map_err(|e| VmmError::Config(format!("prewarm: {e}")))?;
            if self.inner.shell_tx.try_send(shell).is_err() {
                break;
            }
            created += 1;
        }
        Ok(created)
    }

    /// `kvm_run` mmap size (computed from local KVM handle).
    pub fn kvm_run_size(&self) -> Result<usize> {
        kvm_ioctls::Kvm::new()
            .and_then(|k| k.get_vcpu_mmap_size())
            .map_err(|e| VmmError::SystemCall {
                operation: "KVM_GET_VCPU_MMAP_SIZE",
                source: std::io::Error::other(e.to_string()),
            })
    }

    /// Shutdown the pool.
    pub fn shutdown(&self) {
        self.inner.shutdown.cancel();
    }

    /// Acquire a pre-warmed shell, or create one inline.
    async fn acquire_shell(&self) -> Result<SubprocessShell> {
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
            tokio::task::spawn_blocking(move || {
                create_shell(&worker, vcpu_count, &layout)
                    .map_err(|e| VmmError::Config(format!("create_shell: {e}")))
            })
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
            // lifetime: detached. Loop exits when `inner.shutdown`
            // (tokio_util CancellationToken) is cancelled via
            // VmPools::shutdown(), or when `inner.shell_tx.send()` fails
            // (receiver dropped). Backoff on create_shell errors; no
            // JoinHandle retained.
            tokio::spawn(async move {
                Self::refill_task(inner).await;
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
                    log::error!("subprocess refill_task: {e}");
                    tokio::select! {
                        () = tokio::time::sleep(backoff) => {}
                        () = inner.shutdown.cancelled() => return,
                    }
                    backoff = (backoff * 2).min(MAX_BACKOFF);
                }
                Err(e) => {
                    drop(permit);
                    log::error!("subprocess refill_task panic: {e}");
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

// ============================================================================
// VmBuilder
// ============================================================================

/// Builder for subprocess VMs.
pub struct VmBuilder {
    pools: VmPools,
}

impl VmBuilder {
    /// Create a builder.
    pub fn new(pools: &VmPools) -> Self {
        Self {
            pools: pools.clone(),
        }
    }

    /// Build a VM by acquiring a pre-warmed subprocess.
    #[allow(clippy::similar_names)]
    pub async fn build_shell(self) -> Result<Vm> {
        amla_ipc::dbg_log!("build_shell enter");
        let shell = self.pools.acquire_shell().await?;
        let vcpu_count = shell.vcpu_count;
        log::info!("subprocess: acquired shell with {vcpu_count} vCPUs");
        amla_ipc::dbg_log!("build_shell acquired vcpu_count={vcpu_count}");

        let vcpu_count_usz = vcpu_count as usize;
        let vcpu_seqs: Vec<std::sync::atomic::AtomicU64> = (0..vcpu_count)
            .map(|_| std::sync::atomic::AtomicU64::new(0))
            .collect();

        let device_waker = Arc::new(SubprocessDeviceWaker {
            base: BasicDeviceWaker::new(),
        });
        let dead = Arc::new(AtomicBool::new(false));

        let max_gsi = shell
            .topology
            .devices
            .iter()
            .map(|device| device.gsi)
            .max()
            .unwrap_or(0) as usize;
        let resample_len = max_gsi.saturating_add(1).max(32);
        let mut resample_wake_by_gsi = vec![None; resample_len];
        for device in &shell.topology.devices {
            if let Some(wake_idx) = device.resample_wake_idx
                && let Some(slot) = resample_wake_by_gsi.get_mut(device.gsi as usize)
            {
                *slot = Some(DeviceWakeIndex::try_from(wake_idx).map_err(|err| {
                    VmmError::Config(format!("worker resample wake index invalid: {err}"))
                })?);
            }
        }
        let resample_wake_by_gsi = Arc::new(resample_wake_by_gsi);

        // Resample flags — one per GSI used by the hardware layout.
        let resample_flags: Arc<Vec<AtomicBool>> = Arc::new(
            (0..resample_wake_by_gsi.len())
                .map(|_| AtomicBool::new(false))
                .collect(),
        );

        // Command channel: at most 1 locked request + 1 resume per vCPU.
        let (cmd_tx, cmd_rx) = mpsc::channel(vcpu_count_usz + 1);

        // Fire-and-forget channel for Preempt / IrqLine / Shutdown. Unbounded
        // because these must never apply backpressure: preempt_vcpu and
        // IrqLine::assert are sync contexts, and dropping a preempt on
        // try_send-full wedges run_inner's teardown waiting on all_vcpus.
        let (ff_tx, ff_rx) = mpsc::unbounded_channel::<WorkerRequest>();

        // Console output buffer — ipc_task appends, VMM layer drains.
        let console_output = Arc::new(parking_lot::Mutex::new(Vec::<u8>::new()));

        // Readiness channel — ipc_task signals after Init handshake.
        let (ready_tx, ready_rx) = oneshot::channel();

        // Spawn IPC task. `close()` awaits the handle so freeze can prove the
        // worker has acknowledged shutdown before CoW branching.
        amla_ipc::dbg_log!("build_shell spawning ipc_task");
        let ipc_handle = tokio::spawn(ipc_task(
            shell.ring,
            IpcTaskCtx {
                topology: shell.topology,
                ready_tx,
                cmd_rx,
                ff_rx,
                vcpu_count,
                device_waker: Arc::clone(&device_waker),
                resample_flags: Arc::clone(&resample_flags),
                resample_wake_by_gsi: Arc::clone(&resample_wake_by_gsi),
                dead: Arc::clone(&dead),
                console_output: Arc::clone(&console_output),
            },
        ));

        // Wait for the Init handshake to complete in the IPC task.
        amla_ipc::dbg_log!("build_shell awaiting ready");
        ready_rx
            .await
            .map_err(|_| VmmError::Config("IPC task died during Init".into()))?
            .map_err(|e| VmmError::Config(format!("worker Init failed: {e}")))?;
        amla_ipc::dbg_log!("build_shell ready received");

        Ok(Vm {
            inner: Some(Box::new(VmInner {
                _pools: self.pools,
                cmd_tx,
                ff_tx,
                request_lock: tokio::sync::Mutex::new(()),
                device_waker,
                resample_flags,
                vcpu_seqs,
                dead,
                vcpu_count,
                console_output,
                ipc_handle,
            })),
        })
    }
}

// ============================================================================
// Vm
// ============================================================================

/// A subprocess-backed virtual machine.
pub struct Vm {
    inner: Option<Box<VmInner>>,
}

struct VmInner {
    _pools: VmPools,
    cmd_tx: mpsc::Sender<IpcCommand>,
    /// Fire-and-forget channel. Unbounded: `Preempt` and `IrqLine` asserts
    /// are sync contexts that must never drop — a dropped preempt wedges
    /// vCPU teardown in `run_inner`, and a dropped `IrqLine` assert loses
    /// an IRQ that the resample path cannot recover.
    ff_tx: mpsc::UnboundedSender<WorkerRequest>,
    /// Serializes `send_request` calls so at most one request-response
    /// pair is in-flight on the IPC ring at a time.
    request_lock: tokio::sync::Mutex<()>,
    device_waker: Arc<SubprocessDeviceWaker>,
    resample_flags: Arc<Vec<AtomicBool>>,
    vcpu_seqs: Vec<std::sync::atomic::AtomicU64>,
    dead: Arc<AtomicBool>,
    vcpu_count: u32,
    /// Buffered UART console output from the worker, delivered via
    /// `ConsoleOutput` messages. The `ipc_task` appends here; the VMM
    /// layer drains via `drain_console_output()`.
    console_output: Arc<parking_lot::Mutex<Vec<u8>>>,
    /// IPC task that owns the worker ring until shutdown completes.
    ipc_handle: tokio::task::JoinHandle<()>,
}

// SAFETY: VmInner fields are all Send (channels, atomics, Arc).
unsafe impl Send for Vm {}

impl Vm {
    /// Create a VM builder.
    pub fn builder(pools: &VmPools) -> VmBuilder {
        VmBuilder::new(pools)
    }

    fn live(&self) -> Result<&VmInner> {
        self.inner.as_deref().ok_or(VmmError::UseAfterDrop)
    }

    fn check_dead(&self) -> Result<()> {
        let inner = self.live()?;
        if inner.dead.load(Ordering::Acquire) {
            return Err(VmmError::Config("subprocess worker died".into()));
        }
        Ok(())
    }

    /// Close the subprocess VM and wait until the worker has torn down KVM state.
    pub async fn close(mut self) -> Result<()> {
        let resp = self.send_request(WorkerRequest::Shutdown).await?;
        Self::expect_ok(resp)?;
        if let Some(inner) = self.inner.take() {
            inner
                .ipc_handle
                .await
                .map_err(|e| VmmError::Config(format!("IPC task panicked during close: {e}")))?;
        }
        Ok(())
    }

    async fn send_request(&self, request: WorkerRequest) -> Result<WorkerResponse> {
        self.check_dead()?;
        let inner = self.live()?;
        let _guard = inner.request_lock.lock().await;
        let (tx, rx) = oneshot::channel();
        inner
            .cmd_tx
            .send(IpcCommand::Request { request, reply: tx })
            .await
            .map_err(|_| VmmError::Config("IPC channel closed".into()))?;
        rx.await
            .map_err(|_| VmmError::Config("worker died".into()))?
    }

    fn expect_ok(resp: WorkerResponse) -> Result<()> {
        match resp {
            WorkerResponse::Ok => Ok(()),
            WorkerResponse::Error { message } => Err(VmmError::Config(message)),
            _ => Err(VmmError::Config("unexpected response".into())),
        }
    }

    // ========================================================================
    // Public API
    // ========================================================================

    /// Number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.inner.as_ref().map_or(0, |i| i.vcpu_count)
    }

    /// Map guest physical memory.
    pub async fn map_memory(
        &mut self,
        handles: &[&MemHandle],
        mappings: &[amla_core::MemoryMapping],
    ) -> Result<()> {
        let handle_info: Vec<_> = handles
            .iter()
            .map(|handle| MappingHandleInfo::from(*handle))
            .collect();
        let mappings = ValidatedMemoryMappings::new(mappings, &handle_info)
            .map_err(|e| VmmError::Config(e.to_string()))?;
        let cloned: Vec<MemHandle> = handles
            .iter()
            .map(|h| h.try_clone())
            .collect::<std::result::Result<_, _>>()
            .map_err(VmmError::from)?;
        let resp = self
            .send_request(WorkerRequest::MapMemory {
                handles: cloned,
                mappings: mappings.raw().to_vec(),
            })
            .await?;
        Self::expect_ok(resp)
    }

    /// Drain any buffered UART console bytes from the worker.
    ///
    /// Returns an empty Vec if no bytes are pending. The VMM layer
    /// should call this periodically and forward bytes to the
    /// console backend.
    pub fn drain_console_output(&self) -> Vec<u8> {
        self.inner
            .as_ref()
            .map(|i| std::mem::take(&mut *i.console_output.lock()))
            .unwrap_or_default()
    }

    /// Resume a vCPU: send response, await next exit.
    ///
    /// Dropping this future before it resolves is safe: `ipc_task` routes
    /// the eventual `VcpuExit` into the dropped oneshot, the send returns
    /// `Err`, and the exit is discarded. The next `resume()` with a fresh
    /// seq overwrites `pending_resume`, so stale exits are dropped by
    /// seq mismatch in `ipc_task_inner`.
    pub async fn resume(
        &self,
        id: amla_core::VcpuId,
        info: Option<VcpuResponse>,
    ) -> Result<VcpuExit> {
        self.check_dead()?;
        let inner = self.live()?;
        let idx = id.0 as usize;
        let seq = inner.vcpu_seqs[idx].fetch_add(1, Ordering::Relaxed) + 1;
        let t0 = std::time::Instant::now();

        let (reply_tx, reply_rx) = oneshot::channel();
        inner
            .cmd_tx
            .send(IpcCommand::ResumeVcpu {
                id: id.0,
                seq,
                response: info,
                reply: reply_tx,
            })
            .await
            .map_err(|_| VmmError::Config("IPC channel closed".into()))?;
        let t_send = t0.elapsed();

        let exit = reply_rx
            .await
            .map_err(|_| VmmError::Config("worker died".into()))??;
        let t_total = t0.elapsed();

        if t_total.as_millis() > 50 {
            log::warn!(
                "resume: SLOW id={id} seq={seq} send={t_send:?} total={t_total:?} exit={exit:?}"
            );
        } else {
            log::trace!("resume: id={id} seq={seq} send={t_send:?} total={t_total:?}");
        }

        Ok(exit)
    }

    /// Preempt a vCPU: send a preempt command to the worker process.
    /// The next `resume()` call will return `VcpuExit::Interrupted`.
    pub fn preempt_vcpu(&self, id: amla_core::VcpuId) {
        if let Ok(inner) = self.live() {
            drop(inner.ff_tx.send(WorkerRequest::Preempt { id: id.0 }));
        }
    }

    /// Save VM state (vCPU registers + irqchip) to `VmState`.
    ///
    /// Sends individual messages per vCPU snapshot through the ring buffer,
    /// avoiding `MemHandle` allocation and raw pointer arithmetic.
    pub async fn save_state(&self, view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        let vcpu_count = self.vcpu_count();

        // 1. Worker captures all state atomically.
        Self::expect_ok(
            self.send_request(WorkerRequest::SaveState { vcpu_count })
                .await?,
        )?;

        // 2. Fetch individual vCPU snapshots.
        for i in 0..vcpu_count {
            let resp = self
                .send_request(WorkerRequest::GetSavedVcpu { id: i })
                .await?;
            let WorkerResponse::StateData { data } = resp else {
                return Err(VmmError::Config(
                    "unexpected response for GetSavedVcpu".into(),
                ));
            };
            let slot = view
                .vcpu_slot_mut(i as usize)
                .ok_or(VmmError::InvalidState {
                    expected: "valid vcpu index",
                    actual: "out of bounds",
                })?;
            if data.len() > slot.len() {
                return Err(VmmError::Config(format!(
                    "vcpu snapshot {} bytes exceeds slot size {}",
                    data.len(),
                    slot.len()
                )));
            }
            slot[..data.len()].copy_from_slice(&data);
        }

        // 3. Fetch irqchip blob.
        let resp = self.send_request(WorkerRequest::GetSavedIrqchip).await?;
        let WorkerResponse::StateData { data } = resp else {
            return Err(VmmError::Config(
                "unexpected response for GetSavedIrqchip".into(),
            ));
        };
        view.irqchip_mut()
            .set_arch_blob(&data)
            .map_err(|e| VmmError::Config(format!("invalid irqchip blob: {e}")))?;
        Ok(())
    }

    /// Restore VM state from `VmState`.
    ///
    /// Validates the VM-level irqchip blob before mutating vCPU state, then
    /// preserves the KVM restore ordering:
    /// 1. Restore all vCPU states.
    /// 2. Restore irqchip state after vCPUs.
    pub async fn restore_state(&self, view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        let vcpu_count = self.vcpu_count();
        let snap_size = std::mem::size_of::<VcpuSnapshot>();
        let blob = view
            .irqchip()
            .arch_blob()
            .map_err(|e| VmmError::Config(format!("invalid irqchip blob: {e}")))?;
        if blob.is_empty() {
            return Err(VmmError::InvalidState {
                expected: "irqchip arch blob written by write_boot_state() or save_state()",
                actual: "missing irqchip arch blob",
            });
        }
        let blob = blob.to_vec();

        #[cfg(target_arch = "aarch64")]
        {
            let kvm_state = VmStateSnapshot::from_arch_blob(&blob)?;
            kvm_state.validate_vcpu_count(vcpu_count as usize)?;
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            let _kvm_state = VmStateSnapshot::from_arch_blob(&blob)?;
        }

        // Step 1: Restore all vCPU states.
        for i in 0..vcpu_count {
            let slot = view.vcpu_slot(i as usize).ok_or(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            })?;
            let data = slot[..snap_size].to_vec();
            Self::expect_ok(
                self.send_request(WorkerRequest::RestoreVcpu { id: i, data })
                    .await?,
            )?;
        }

        // Step 2: Apply irqchip state.
        Self::expect_ok(
            self.send_request(WorkerRequest::RestoreIrqchip { blob })
                .await?,
        )?;

        Ok(())
    }

    /// Write initial boot vCPU state. No IPC needed — pure computation.
    pub async fn write_boot_state(
        &self,
        view: &mut amla_core::vm_state::VmState<'_>,
        boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        let vcpu_count = self.vcpu_count();
        let bsp = VcpuSnapshot::for_boot(&boot_result.cpu_state);
        write_vcpu_to_slot(view, 0, &bsp)?;
        for i in 1..vcpu_count {
            let ap = VcpuSnapshot::for_init_received(i as usize)?;
            write_vcpu_to_slot(view, i as usize, &ap)?;
        }
        view.set_boot_psci_power_states();

        let resp = self
            .send_request(WorkerRequest::CaptureDefaultIrqchip)
            .await?;
        let WorkerResponse::StateData { data } = resp else {
            return Err(VmmError::Config(
                "unexpected response for CaptureDefaultIrqchip".into(),
            ));
        };
        view.irqchip_mut()
            .set_arch_blob(&data)
            .map_err(|e| VmmError::Config(format!("invalid default irqchip blob: {e}")))?;
        Ok(())
    }

    /// Create a device waker backed by IPC notifications.
    pub async fn create_device_waker(&self) -> Result<Arc<dyn DeviceWaker>> {
        let inner = self.live()?;
        Ok(Arc::clone(&inner.device_waker) as Arc<dyn DeviceWaker>)
    }

    /// Create a resampled IRQ line backed by IPC.
    pub async fn create_resampled_irq_line(&self, gsi: u32) -> Result<Box<dyn IrqLine>> {
        let inner = self.live()?;
        Ok(Box::new(SubprocessIrqLine {
            gsi,
            level: AtomicBool::new(false),
            resample_flags: Arc::clone(&inner.resample_flags),
            ff_tx: inner.ff_tx.clone(),
        }))
    }
}

impl IrqFactory for Vm {
    fn create_resampled_irq_line(
        &self,
        gsi: u32,
    ) -> std::result::Result<Box<dyn IrqLine>, Box<dyn std::error::Error + Send + Sync>> {
        // IrqFactory is sync. SubprocessIrqLine creation is actually sync
        // (no IPC needed), so we can bypass the async version.
        let inner = self.live()?;
        Ok(Box::new(SubprocessIrqLine {
            gsi,
            level: AtomicBool::new(false),
            resample_flags: Arc::clone(&inner.resample_flags),
            ff_tx: inner.ff_tx.clone(),
        }))
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        amla_ipc::dbg_log!("Vm::drop enter");
        if let Some(inner) = self.inner.take() {
            // ff_tx is unbounded; send always succeeds unless ipc_task has
            // already exited (in which case the worker is torn down anyway
            // via ChildHandle::Drop SIGKILL).
            drop(inner.ff_tx.send(WorkerRequest::Shutdown));
        }
    }
}

// ============================================================================
// SubprocessDeviceWaker
// ============================================================================

struct SubprocessDeviceWaker {
    base: BasicDeviceWaker,
}

impl DeviceWaker for SubprocessDeviceWaker {
    fn kick(&self, idx: DeviceWakeIndex) {
        self.base.kick(idx);
    }
    fn set_bit(&self, idx: DeviceWakeIndex) {
        self.base.set_bit(idx);
    }
    fn take_pending(&self) -> u64 {
        self.base.take_pending()
    }
    fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<DeviceWakeResult> {
        self.base.poll_wait(cx)
    }
}

// ============================================================================
// SubprocessIrqLine
// ============================================================================

struct SubprocessIrqLine {
    gsi: u32,
    level: AtomicBool,
    resample_flags: Arc<Vec<AtomicBool>>,
    ff_tx: mpsc::UnboundedSender<WorkerRequest>,
}

impl IrqLine for SubprocessIrqLine {
    fn assert(&self) {
        self.level.store(true, Ordering::Release);
        drop(self.ff_tx.send(WorkerRequest::IrqLine {
            gsi: self.gsi,
            level: true,
        }));
    }

    fn deassert(&self) {
        self.level.store(false, Ordering::Release);
        // No IPC needed: KVM irqfds are edge-triggered. The deassert takes
        // effect via the resample mechanism — check_resample() will not
        // re-assert after EOI because level is now false.
    }

    fn check_resample(&self) {
        if let Some(flag) = self.resample_flags.get(self.gsi as usize)
            && flag.swap(false, Ordering::AcqRel)
            && self.level.load(Ordering::Acquire)
        {
            // EOI from guest. Re-assert if level still high.
            drop(self.ff_tx.send(WorkerRequest::IrqLine {
                gsi: self.gsi,
                level: true,
            }));
        }
    }
}

// ============================================================================
// IPC task — bridges Vm methods to ring buffer
// ============================================================================

/// Owned state moved into the IPC task.
///
/// Bundled so [`ipc_task`] takes two arguments (the ring plus this context)
/// instead of ten. All fields are consumed by the task for its entire lifetime.
struct IpcTaskCtx {
    topology: WorkerTopology,
    ready_tx: oneshot::Sender<std::result::Result<(), String>>,
    cmd_rx: mpsc::Receiver<IpcCommand>,
    ff_rx: mpsc::UnboundedReceiver<WorkerRequest>,
    vcpu_count: u32,
    device_waker: Arc<SubprocessDeviceWaker>,
    resample_flags: Arc<Vec<AtomicBool>>,
    resample_wake_by_gsi: Arc<Vec<Option<DeviceWakeIndex>>>,
    dead: Arc<AtomicBool>,
    console_output: Arc<parking_lot::Mutex<Vec<u8>>>,
}

async fn ipc_task(mut ring: RingBuffer, ctx: IpcTaskCtx) {
    amla_ipc::dbg_log!("ipc_task enter");
    let IpcTaskCtx {
        topology,
        ready_tx,
        mut cmd_rx,
        mut ff_rx,
        vcpu_count,
        device_waker,
        resample_flags,
        resample_wake_by_gsi,
        dead,
        console_output,
    } = ctx;
    // Per-vCPU in-flight resume slot. Each entry holds (seq, reply) for the
    // most recent ResumeVcpu command; incoming VcpuExit routes here by id,
    // and a seq mismatch means the frame is stale from a cancelled resume.
    let mut pending_resume: Vec<Option<(u64, oneshot::Sender<Result<VcpuExit>>)>> =
        (0..vcpu_count as usize).map(|_| None).collect();
    // Split once — avoids the AsyncFd re-registration race that occurred
    // when create_shell split for the handshake and ipc_task split again.
    amla_ipc::dbg_log!("ipc_task pre-split");
    let split = ring.split(true);
    amla_ipc::dbg_log!("ipc_task post-split ok={}", split.is_ok());
    let result = match split {
        Ok((mut sender, mut receiver)) => {
            // Init handshake before entering the command loop.
            let init_result = handshake(&mut sender, &mut receiver, vcpu_count, topology).await;
            drop(ready_tx.send(init_result.clone()));
            if let Err(e) = init_result {
                Err(e.into())
            } else {
                ipc_task_inner(
                    &mut sender,
                    &mut receiver,
                    &mut cmd_rx,
                    &mut ff_rx,
                    &mut pending_resume,
                    &device_waker,
                    &resample_flags,
                    &resample_wake_by_gsi,
                    &console_output,
                )
                .await
            }
        }
        Err(e) => {
            drop(ready_tx.send(Err(format!("ring split: {e}"))));
            Err(e.into())
        }
    };

    if let Err(e) = result {
        log::error!("subprocess IPC task failed: {e}");
    }

    // Mark worker as dead.
    dead.store(true, Ordering::Release);

    // Drop any pending resume oneshots — resume() callers get "worker died".
    drop(pending_resume);

    // Drain pending commands, reply with errors so send_request and resume
    // callers don't block indefinitely on their oneshot receivers.
    cmd_rx.close();
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            IpcCommand::Request { reply, .. } => {
                drop(reply.send(Err(VmmError::Config("worker died".into()))));
            }
            IpcCommand::ResumeVcpu { reply, .. } => {
                drop(reply.send(Err(VmmError::Config("worker died".into()))));
            }
        }
    }
}

async fn handshake(
    sender: &mut amla_ipc::Sender<'_>,
    receiver: &mut amla_ipc::Receiver<'_>,
    vcpu_count: u32,
    topology: WorkerTopology,
) -> std::result::Result<(), String> {
    sender
        .send(WorkerRequest::Init {
            vcpu_count,
            topology,
        })
        .await
        .map_err(|e| format!("Init send: {e}"))?;

    let resp = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        receiver.recv::<WorkerResponse>(),
    )
    .await
    .map_err(|_| "worker Init timeout".to_owned())?
    .map_err(|e| format!("Init recv: {e}"))?;

    match resp {
        WorkerResponse::Ready => Ok(()),
        WorkerResponse::Error { message } => Err(message),
        _ => Err("unexpected Init response".into()),
    }
}

/// Slot holding the most recent pending resume for a given vCPU.
///
/// The `u64` is the seq of the in-flight `ResumeVcpu`; arriving
/// `VcpuExit` frames with a mismatching seq are stale and discarded.
type PendingResume = Option<(u64, oneshot::Sender<Result<VcpuExit>>)>;

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn ipc_task_inner(
    sender: &mut amla_ipc::Sender<'_>,
    receiver: &mut amla_ipc::Receiver<'_>,
    cmd_rx: &mut mpsc::Receiver<IpcCommand>,
    ff_rx: &mut mpsc::UnboundedReceiver<WorkerRequest>,
    pending_resume: &mut [PendingResume],
    device_waker: &SubprocessDeviceWaker,
    resample_flags: &[AtomicBool],
    resample_wake_by_gsi: &[Option<DeviceWakeIndex>],
    console_output: &parking_lot::Mutex<Vec<u8>>,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut pending_reply: Option<oneshot::Sender<Result<WorkerResponse>>> = None;

    loop {
        tokio::select! {
            cmd = cmd_rx.recv() => {
                let cmd = cmd.ok_or("cmd channel closed")?;
                match cmd {
                    IpcCommand::Request { request, reply } => {
                        debug_assert!(
                            pending_reply.is_none(),
                            "concurrent request despite request_lock"
                        );
                        log::trace!("ipc_task: send request {request:?}");
                        sender.send(request).await.map_err(|e| {
                            log::error!("ipc_task: send Request failed: {e}");
                            e
                        })?;
                        pending_reply = Some(reply);
                    }
                    IpcCommand::ResumeVcpu { id, seq, response, reply } => {
                        log::trace!("ipc_task: send ResumeVcpu id={id} seq={seq}");
                        if let Some(slot) = pending_resume.get_mut(id as usize) {
                            // Overwrite any prior pending oneshot; its
                            // receiver was dropped with a cancelled resume,
                            // so the sender is already orphaned.
                            *slot = Some((seq, reply));
                        } else {
                            drop(reply.send(Err(VmmError::Config(
                                "ResumeVcpu with invalid id".into(),
                            ))));
                            return Err("ResumeVcpu with invalid id".into());
                        }
                        sender.send(WorkerRequest::ResumeVcpu { id, seq, response }).await.map_err(|e| {
                            log::error!("ipc_task: send ResumeVcpu failed: {e}");
                            e
                        })?;
                    }
                }
            }
            ff = ff_rx.recv() => {
                let request = ff.ok_or("ff channel closed")?;
                log::trace!("ipc_task: send fire-and-forget {request:?}");
                sender.send(request).await.map_err(|e| {
                    log::error!("ipc_task: send fire-and-forget failed: {e}");
                    e
                })?;
            }
            resp = receiver.recv::<WorkerResponse>() => {
                let resp = resp.map_err(|e| {
                    log::error!("ipc_task: recv failed: {e}");
                    e
                })?;
                match resp {
                    WorkerResponse::VcpuExit { id, seq, exit } => {
                        log::trace!("ipc_task: recv VcpuExit id={id} seq={seq} exit={exit:?}");
                        let Some(slot) = pending_resume.get_mut(id as usize) else {
                            log::error!("VcpuExit with invalid id={id}");
                            continue;
                        };
                        // Only route if the pending seq matches the arriving
                        // frame's seq. A mismatch means either no resume is
                        // pending, or this exit is stale from a cancelled
                        // resume whose cmd was sent but whose reply was
                        // replaced. Discarding is correct in both cases.
                        match slot.take_if(|(pending_seq, _)| *pending_seq == seq) {
                            Some((_, tx)) => {
                                drop(tx.send(Ok(exit)));
                            }
                            None => {
                                log::trace!("ipc_task: discarding stale VcpuExit id={id} seq={seq}");
                            }
                        }
                    }
                    WorkerResponse::ConsoleOutput { ref data } => {
                        log::trace!("ipc_task: recv ConsoleOutput len={}", data.len());
                        console_output.lock().extend_from_slice(data);
                    }
                    WorkerResponse::DeviceKick { wake_idx } => {
                        log::trace!("ipc_task: recv DeviceKick wake_idx={wake_idx}");
                        let wake_idx = DeviceWakeIndex::try_from(wake_idx).map_err(|err| {
                            VmmError::Config(format!("worker device wake index invalid: {err}"))
                        })?;
                        device_waker.kick(wake_idx);
                    }
                    WorkerResponse::IrqResample { gsi } => {
                        log::trace!("ipc_task: recv IrqResample gsi={gsi}");
                        if let Some(flag) = resample_flags.get(gsi as usize) {
                            flag.store(true, Ordering::Release);
                        }
                        if let Some(Some(wake_idx)) = resample_wake_by_gsi.get(gsi as usize) {
                            device_waker.kick(*wake_idx);
                        }
                    }
                    resp @ (WorkerResponse::Ok
                    | WorkerResponse::Ready
                    | WorkerResponse::StateData { .. }) => {
                        if let Some(tx) = pending_reply.take() {
                            drop(tx.send(Ok(resp)));
                        }
                    }
                    WorkerResponse::Error { message } => {
                        if let Some(tx) = pending_reply.take() {
                            drop(tx.send(Err(VmmError::Config(message))));
                        } else {
                            // No pending request — this error came from a
                            // ResumeVcpu path (e.g. vCPU thread died). Treat
                            // as fatal: the parent's resume() would hang forever.
                            log::error!("unroutable worker error: {message}");
                            return Err(message.into());
                        }
                    }
                }
            }
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn write_vcpu_to_slot(
    view: &mut amla_core::vm_state::VmState<'_>,
    index: usize,
    snapshot: &VcpuSnapshot,
) -> Result<()> {
    let slot = view.vcpu_slot_mut(index).ok_or(VmmError::InvalidState {
        expected: "valid vcpu index",
        actual: "out of bounds",
    })?;
    let snap_size = std::mem::size_of::<VcpuSnapshot>();
    assert!(
        slot.len() >= snap_size,
        "vcpu slot {index} too small: {} < {snap_size}",
        slot.len()
    );
    // SAFETY: asserted slot.len() >= snap_size above; source and destination
    // are disjoint (slot is a mutable view, snapshot is an immutable ref).
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(snapshot).cast::<u8>(),
            slot.as_mut_ptr(),
            snap_size,
        );
    }
    Ok(())
}
