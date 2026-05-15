// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF subprocess VM — IPC-backed virtual machine handle.
//!
//! Follows the same architecture as the KVM subprocess backend:
//! - `VmBuilder` acquires a pre-warmed shell and spawns an IPC task
//! - `Vm` methods send commands through an mpsc channel to the IPC task
//! - The IPC task multiplexes ring buffer reads/writes via `tokio::select!`

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use amla_core::vcpu::VcpuResponse;
use amla_core::{
    DeviceWakeIndex, DeviceWaker, IrqFactory, IrqLine, MappingHandleInfo, MemoryMapping,
    ValidatedMemoryMappings, VcpuExit,
};
use amla_ipc::RingBuffer;
use amla_mem::MemHandle;
use tokio::sync::{mpsc, oneshot};

use crate::device_waker::HvfDeviceWaker;
use crate::error::{Result, VmmError};
use crate::irq::HvfIrqLine;
use crate::pools::VmPools;
use crate::protocol::{WorkerRequest, WorkerResponse};

// ============================================================================
// IPC command channel — Vm methods → IPC task
// ============================================================================

pub(crate) enum IpcCommand {
    /// Send request, await one response.
    Request {
        request: WorkerRequest,
        reply: oneshot::Sender<Result<WorkerResponse>>,
    },
    /// Resume a vCPU (response routed to per-vCPU channel).
    ResumeVcpu {
        id: u32,
        seq: u64,
        response: Option<VcpuResponse>,
    },
    /// Terminal shutdown request.
    Shutdown {
        /// Optional caller waiting for the worker's final response.
        reply: Option<oneshot::Sender<Result<WorkerResponse>>>,
    },
}

/// One-way IPC signals from synchronous call sites.
pub(crate) enum IpcSignal {
    /// Preempt a running vCPU.
    Preempt {
        /// vCPU index.
        id: u32,
    },
    /// Assert or deassert an IRQ line.
    IrqLine {
        /// Global System Interrupt number.
        gsi: u32,
        /// true = assert, false = deassert.
        level: bool,
    },
}

enum ShutdownWaiter {
    Caller(oneshot::Sender<Result<WorkerResponse>>),
    Detached,
}

enum ShutdownSend {
    Sent,
    PeerClosed,
}

impl ShutdownWaiter {
    fn send(self, result: Result<WorkerResponse>) {
        if let Self::Caller(reply) = self
            && reply.send(result).is_err()
        {
            log::debug!("ipc_task: shutdown caller dropped before reply");
        }
    }
}

// ============================================================================
// VmBuilder
// ============================================================================

/// Builder for HVF subprocess VMs.
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
        let shell = self.pools.acquire_shell().await?;
        let vcpu_count = shell.vcpu_count;
        let vcpu_count_usz = vcpu_count as usize;
        log::info!("hvf subprocess: acquired shell with {vcpu_count} vCPUs");

        // Per-vCPU exit channels (carry seq + exit).
        // Capacity 1: strict request-response protocol.
        let mut vcpu_exit_txs = Vec::with_capacity(vcpu_count_usz);
        let mut vcpu_exit_rxs = Vec::with_capacity(vcpu_count_usz);
        for _ in 0..vcpu_count {
            let (tx, rx) = mpsc::channel(1);
            vcpu_exit_txs.push(tx);
            vcpu_exit_rxs.push(tokio::sync::Mutex::new(rx));
        }
        let vcpu_seqs: Vec<AtomicU64> = (0..vcpu_count).map(|_| AtomicU64::new(0)).collect();

        let device_waker = Arc::new(HvfDeviceWaker::new());
        let dead = Arc::new(AtomicBool::new(false));

        let resample_wake_by_gsi = Arc::new(self.pools.resample_wake_by_gsi());
        let resample_flags: Arc<Vec<AtomicBool>> = Arc::new(
            (0..resample_wake_by_gsi.len())
                .map(|_| AtomicBool::new(false))
                .collect(),
        );

        // Command channel: request/reply calls, resumes, and terminal
        // shutdown. Unbounded is deliberate: Drop must be able to queue
        // shutdown without blocking or falling back to the no-reply IRQ lane.
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        // Unbounded channel for synchronous one-way signals (IRQ level
        // changes, preempt). These must never be dropped — a dropped IRQ
        // assert can leave the guest stuck (never wakes to read virtio ring).
        let (signal_tx, signal_rx) = mpsc::unbounded_channel();

        // Spawn IPC task.
        let ipc_handle = tokio::spawn(ipc_task(
            shell.ring,
            IpcTaskCtx {
                cmd_rx,
                signal_rx,
                vcpu_exit_txs,
                device_waker: Arc::clone(&device_waker),
                resample_flags: Arc::clone(&resample_flags),
                resample_wake_by_gsi: Arc::clone(&resample_wake_by_gsi),
                dead: Arc::clone(&dead),
            },
        ));

        Ok(Vm {
            inner: Some(Box::new(VmInner {
                cmd_tx,
                signal_tx,
                request_lock: tokio::sync::Mutex::new(()),
                vcpu_exit_rxs,
                device_waker,
                resample_flags,
                vcpu_seqs,
                dead,
                ipc_handle,
                vcpu_count,
                _pools: self.pools,
            })),
        })
    }
}

// ============================================================================
// Vm
// ============================================================================

/// An HVF subprocess-backed virtual machine.
pub struct Vm {
    inner: Option<Box<VmInner>>,
}

struct VmInner {
    _pools: VmPools,
    cmd_tx: mpsc::UnboundedSender<IpcCommand>,
    /// Unbounded channel for synchronous one-way signals (IRQ, preempt).
    signal_tx: mpsc::UnboundedSender<IpcSignal>,
    /// Serializes `send_request` calls so at most one request-response
    /// pair is in-flight on the IPC ring at a time.
    request_lock: tokio::sync::Mutex<()>,
    vcpu_exit_rxs: Vec<tokio::sync::Mutex<mpsc::Receiver<(u64, VcpuExit)>>>,
    device_waker: Arc<HvfDeviceWaker>,
    resample_flags: Arc<Vec<AtomicBool>>,
    vcpu_seqs: Vec<AtomicU64>,
    dead: Arc<AtomicBool>,
    /// IPC task that owns the worker ring until shutdown completes.
    ipc_handle: tokio::task::JoinHandle<()>,
    vcpu_count: u32,
}

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
            return Err(VmmError::Config("HVF subprocess worker died".into()));
        }
        Ok(())
    }

    /// Close the subprocess VM and wait until the worker has destroyed HVF state.
    pub async fn close(mut self) -> Result<()> {
        let Some(inner) = self.inner.take() else {
            return Err(VmmError::UseAfterDrop);
        };
        let VmInner {
            cmd_tx, ipc_handle, ..
        } = *inner;

        let (tx, rx) = oneshot::channel();
        log::debug!("Vm::close: sending terminal shutdown");
        cmd_tx
            .send(IpcCommand::Shutdown { reply: Some(tx) })
            .map_err(|_| VmmError::Config("IPC channel closed".into()))?;
        drop(cmd_tx);

        let resp = rx
            .await
            .map_err(|_| VmmError::Config("worker died during shutdown".into()))?;
        Self::expect_ok(resp?)?;

        log::debug!("Vm::close: awaiting IPC task");
        ipc_handle
            .await
            .map_err(|e| VmmError::Config(format!("IPC task panicked during close: {e}")))?;
        log::debug!("Vm::close: IPC task exited");
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
            .map_err(|_| VmmError::Config("IPC channel closed".into()))?;
        rx.await
            .map_err(|_| VmmError::Config("worker died".into()))?
    }

    fn expect_ok(resp: WorkerResponse) -> Result<()> {
        match resp {
            WorkerResponse::Ok => Ok(()),
            WorkerResponse::Error { error } => Err(error.into_vmm_error()),
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
        mappings: &[MemoryMapping],
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
            .map_err(|e| VmmError::Config(e.to_string()))?;
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
    /// Currently always returns empty on HVF: UART writes are dispatched in
    /// the parent's `vcpu_loop` (`amla-vm-vmm/src/vcpu_loop.rs`), not
    /// buffered in the worker process. Kept for backend-API parity with the
    /// KVM subprocess backend, which batches UART bytes in the worker.
    ///
    /// Worker-side buffering will be reintroduced for HVF in a future change
    /// (the IPC protocol already reserves a `ConsoleByte` carrier variant);
    /// at that point this method must actually drain the worker's buffer.
    /// Leaving this as a `Vec::new()` stub once worker buffering lands would
    /// silently lose console bytes.
    #[allow(clippy::unused_self)]
    pub fn drain_console_output(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Resume a vCPU: send response, await next exit.
    ///
    /// The caller must preempt via `preempt_vcpu` before dropping this
    /// future — there is no implicit cancellation guard.
    pub async fn resume(
        &self,
        id: amla_core::VcpuId,
        info: Option<VcpuResponse>,
    ) -> Result<VcpuExit> {
        self.check_dead()?;
        let inner = self.live()?;
        let idx = id.0 as usize;
        let t0 = std::time::Instant::now();

        let mut rx = inner.vcpu_exit_rxs[idx].lock().await;
        let t_lock = t0.elapsed();

        // Advance the seq before sending so any exits that were still in
        // flight from a prior Resume are correctly discarded by the
        // stale-exit loop below. A failed send still advances the seq, which
        // is harmless: the next successful resume will just use seq+2, and
        // the worker always stores the latest seq it receives in ResumeVcpu.
        let seq = inner.vcpu_seqs[idx].fetch_add(1, Ordering::AcqRel) + 1;

        inner
            .cmd_tx
            .send(IpcCommand::ResumeVcpu {
                id: id.0,
                seq,
                response: info,
            })
            .map_err(|_| VmmError::Config("IPC channel closed".into()))?;
        let t_send = t0.elapsed();

        let exit = loop {
            let (exit_seq, exit) = rx
                .recv()
                .await
                .ok_or_else(|| VmmError::Config("worker died".into()))?;
            if exit_seq == seq {
                break exit;
            }
            log::trace!("resume: discarding stale exit seq={exit_seq}, waiting for {seq}");
        };
        let t_total = t0.elapsed();

        if t_total.as_millis() > 50 {
            log::warn!(
                "resume: SLOW id={id} seq={seq} lock={t_lock:?} send={t_send:?} total={t_total:?} exit={exit:?}"
            );
        } else {
            log::trace!(
                "resume: id={id} seq={seq} lock={t_lock:?} send={t_send:?} total={t_total:?}"
            );
        }

        Ok(exit)
    }

    /// Preempt a vCPU: send a preempt command to the worker process.
    pub fn preempt_vcpu(&self, id: amla_core::VcpuId) {
        if let Ok(inner) = self.live()
            && inner
                .signal_tx
                .send(IpcSignal::Preempt { id: id.0 })
                .is_err()
        {
            log::debug!(
                "preempt_vcpu({}): worker channel closed (worker exited)",
                id.0
            );
        }
    }

    /// Save VM state (vCPU registers + GIC) to `VmState`.
    ///
    /// # Preconditions
    ///
    /// Every vCPU must be in the paused state (idle on `cmd_rx`, i.e. no
    /// in-flight `resume()` future) before this is called. The worker
    /// dispatches the `CaptureState` command through each vCPU's `cmd_tx`,
    /// and the vCPU thread only drains `cmd_rx` between `Resume` commands.
    /// If a vCPU is still inside `hv_vcpu_run` when `save_state` runs, the
    /// capture command sits in the channel and this future hangs waiting on
    /// its oneshot reply — the two ends deadlock.
    ///
    /// This crate does not preempt vCPUs on entry; coordination is the
    /// caller's responsibility. A resume future that was cancelled mid-flight
    /// must be recovered by calling [`Self::preempt_vcpu`] for that vCPU
    /// before issuing `save_state`, so the vCPU returns to `cmd_rx`.
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

        // 3. Fetch irqchip (GIC) blob.
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
    /// # Preconditions
    ///
    /// Every vCPU must be in the paused state (idle on `cmd_rx`, i.e. no
    /// in-flight `resume()` future) before this is called. The worker
    /// dispatches `RestoreVcpu` through each vCPU's `cmd_tx`, and the vCPU
    /// thread only drains `cmd_rx` between `Resume` commands. If a vCPU is
    /// still inside `hv_vcpu_run` when `restore_state` runs, the restore
    /// command sits in the channel and this future hangs waiting on its
    /// oneshot reply — the two ends deadlock.
    ///
    /// This crate does not preempt vCPUs on entry; coordination is the
    /// caller's responsibility. A resume future that was cancelled mid-flight
    /// must be recovered by calling [`Self::preempt_vcpu`] for that vCPU
    /// before issuing `restore_state`, so the vCPU returns to `cmd_rx`.
    pub async fn restore_state(&self, view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        let vcpu_count = self.vcpu_count();
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

        // Step 1: Restore global GIC state (distributor + redistributor) BEFORE
        // per-vCPU ICC/ICH registers. hv_gic_set_state internally zeroes and
        // rebuilds per-vCPU interrupt routing tables — calling it after per-vCPU
        // ICH_LR restore would wipe the LR→distributor linkage, causing
        // "no active virtual interrupt" traps on ICC_EOIR1 writes.
        Self::expect_ok(
            self.send_request(WorkerRequest::RestoreIrqchip { blob })
                .await?,
        )?;

        // Step 2: Rebase per-vCPU vtimer_offset coherently.
        //
        // `write_boot_state` marks fresh-boot snapshots with `capture_mach_time == 0`
        // and already writes a shared CNTVOFF into each slot, so this loop is a no-op
        // for fresh boot. For cross-process snapshot restore, the saved values were
        // written relative to the source process's mach clock; we advance every
        // vCPU's `vtimer_offset` by the elapsed host time so (a) `CNTVCT_EL0` is
        // preserved across save/restore and (b) every vCPU ends up with the SAME
        // `CNTVOFF_EL2` value (system-coherent virtual counter — hard requirement
        // for Linux sched_clock).
        rebase_vtimer_offsets(view, vcpu_count)?;

        // Step 3: Restore all vCPU states (GP regs + sys regs + SIMD +
        // per-vCPU ICC/ICH registers). Per-vCPU GIC state must come AFTER
        // the global distributor restore (matching VZ's sequence).
        for i in 0..vcpu_count {
            let slot = view.vcpu_slot(i as usize).ok_or(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            })?;
            let data = slot.to_vec();
            Self::expect_ok(
                self.send_request(WorkerRequest::RestoreVcpu { id: i, data })
                    .await?,
            )?;
        }

        Ok(())
    }

    /// Write initial boot vCPU state into `VmState`.
    ///
    /// Converts the shared `Arm64VcpuSnapshot` from the boot loader into
    /// `HvfVcpuSnapshot` bytes and writes them to the `VmState` vCPU slots.
    /// BSP (vCPU 0) gets the boot state; APs get powered-off state.
    /// The worker later restores these via `RestoreVcpu`.
    pub async fn write_boot_state(
        &self,
        view: &mut amla_core::vm_state::VmState<'_>,
        boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        let vcpu_count = self.vcpu_count();

        // Sample mach_absolute_time() ONCE and reuse for every vCPU so they
        // all apply the same CNTVOFF_EL2 → guest sees a coherent CNTVCT_EL0.
        // Result: guest CNTVCT starts at ~0 when write_boot_state runs and
        // advances with real host time thereafter.
        // SAFETY: mach_absolute_time has no preconditions.
        let boot_cntvoff = unsafe { mach_absolute_time() };

        // BSP: convert the shared Arm64VcpuSnapshot to HvfVcpuSnapshot.
        let bsp = hvf_snapshot_from_shared(&boot_result.cpu_state, 0, boot_cntvoff);
        write_snapshot_to_slot(view, 0, &bsp)?;

        // APs: powered-off (all registers zero, power_state=1).
        for i in 1..vcpu_count {
            let shared = amla_core::arm64::snapshot::Arm64VcpuSnapshot::for_ap_powered_off();
            let ap = hvf_snapshot_from_shared(&shared, 1, boot_cntvoff);
            write_snapshot_to_slot(view, i as usize, &ap)?;
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
}

impl IrqFactory for Vm {
    fn create_resampled_irq_line(
        &self,
        gsi: u32,
    ) -> std::result::Result<Box<dyn IrqLine>, Box<dyn std::error::Error + Send + Sync>> {
        let inner = self.live()?;
        Ok(Box::new(HvfIrqLine {
            gsi,
            level: AtomicBool::new(false),
            resample_flags: Arc::clone(&inner.resample_flags),
            signal_tx: inner.signal_tx.clone(),
        }))
    }
}

impl Drop for Vm {
    fn drop(&mut self) {
        if let Some(inner) = self.inner.take() {
            // Queue the same terminal shutdown used by `close()`, but with
            // no caller waiting for the result. The detached IPC task still
            // consumes the worker's final ack, avoiding broken-pipe logs.
            //
            // We no longer abort() the IPC task immediately — that could
            // fire before the Shutdown message reached the ring buffer,
            // leaving the worker with an unclean EOF. The task exits on
            // its own once the channel senders are dropped. If it somehow
            // hangs (e.g. blocked on a full ring buffer), the JoinHandle
            // drop detaches it and Tokio will clean up at runtime shutdown.
            if inner
                .cmd_tx
                .send(IpcCommand::Shutdown { reply: None })
                .is_err()
            {
                log::debug!("Vm::drop: shutdown send failed (worker channel already closed)");
            }
        }
    }
}

// ============================================================================
// IPC task — bridges Vm methods to ring buffer
// ============================================================================

/// Owned state moved into the IPC task.
///
/// Bundled so [`ipc_task`] takes two arguments (the ring plus this context)
/// instead of eight. All fields are consumed by the task for its entire lifetime.
struct IpcTaskCtx {
    cmd_rx: mpsc::UnboundedReceiver<IpcCommand>,
    signal_rx: mpsc::UnboundedReceiver<IpcSignal>,
    vcpu_exit_txs: Vec<mpsc::Sender<(u64, VcpuExit)>>,
    device_waker: Arc<HvfDeviceWaker>,
    resample_flags: Arc<Vec<AtomicBool>>,
    resample_wake_by_gsi: Arc<Vec<Option<DeviceWakeIndex>>>,
    dead: Arc<AtomicBool>,
}

async fn ipc_task(mut ring: RingBuffer, ctx: IpcTaskCtx) {
    let IpcTaskCtx {
        mut cmd_rx,
        mut signal_rx,
        vcpu_exit_txs,
        device_waker,
        resample_flags,
        resample_wake_by_gsi,
        dead,
    } = ctx;
    let result = ipc_task_inner(
        &mut ring,
        &mut cmd_rx,
        &mut signal_rx,
        &vcpu_exit_txs,
        &device_waker,
        &resample_flags,
        &resample_wake_by_gsi,
    )
    .await;

    if let Err(e) = result {
        log::error!("hvf subprocess IPC task failed: {e}");
    }

    // Mark worker as dead.
    dead.store(true, Ordering::Release);

    // Drop vcpu exit senders so resume() callers unblock (rx.recv() → None).
    // This MUST happen before the drain loop below: the drain loop only
    // replies to IpcCommand::Request entries, not ResumeVcpu.  resume()
    // callers are waiting on vcpu_exit_rxs, not on oneshot replies, so
    // they rely on sender drop to unblock.
    drop(vcpu_exit_txs);

    // Drain pending commands, reply with errors so send_request callers
    // don't block indefinitely on their oneshot receivers.
    cmd_rx.close();
    while let Some(cmd) = cmd_rx.recv().await {
        match cmd {
            IpcCommand::Request { reply, .. } | IpcCommand::Shutdown { reply: Some(reply) } => {
                if reply
                    .send(Err(VmmError::Config("worker died".into())))
                    .is_err()
                {
                    log::debug!("ipc_task drain: caller already gave up on Request reply");
                }
            }
            IpcCommand::ResumeVcpu { .. } | IpcCommand::Shutdown { reply: None } => {}
        }
    }
}

fn ipc_peer_closed(error: &amla_ipc::Error) -> bool {
    matches!(
        error,
        amla_ipc::Error::Io(io_err)
            if matches!(
                io_err.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::UnexpectedEof
            )
    )
}

async fn send_shutdown_request(
    sender: &mut amla_ipc::Sender<'_>,
    shutdown_waiter: &mut Option<ShutdownWaiter>,
) -> Result<ShutdownSend> {
    match sender.send(WorkerRequest::Shutdown).await {
        Ok(()) => Ok(ShutdownSend::Sent),
        Err(e) if ipc_peer_closed(&e) => {
            log::debug!("ipc_task: worker closed before shutdown send: {e}");
            if let Some(waiter) = shutdown_waiter.take() {
                waiter.send(Err(VmmError::Config(
                    "worker closed before shutdown".into(),
                )));
            }
            Ok(ShutdownSend::PeerClosed)
        }
        Err(e) => Err(VmmError::Config(format!("send Shutdown: {e}"))),
    }
}

fn should_exit_without_shutdown(
    inputs_closed: bool,
    shutdown_requested: bool,
    shutdown_sent: bool,
) -> bool {
    inputs_closed && !shutdown_requested && !shutdown_sent
}

#[allow(clippy::too_many_lines)]
async fn ipc_task_inner(
    ring: &mut RingBuffer,
    cmd_rx: &mut mpsc::UnboundedReceiver<IpcCommand>,
    signal_rx: &mut mpsc::UnboundedReceiver<IpcSignal>,
    vcpu_exit_txs: &[mpsc::Sender<(u64, VcpuExit)>],
    device_waker: &HvfDeviceWaker,
    resample_flags: &[AtomicBool],
    resample_wake_by_gsi: &[Option<DeviceWakeIndex>],
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (mut sender, mut receiver) = ring.split(true)?;
    let mut pending_reply: Option<oneshot::Sender<Result<WorkerResponse>>> = None;
    let mut shutdown_waiter: Option<ShutdownWaiter> = None;
    let mut cmd_closed = false;
    let mut signal_closed = false;
    let mut shutdown_sent = false;
    let mut resp_bridge_done = false;

    // Bridge IPC response reads into an mpsc channel to avoid edge-triggered
    // kqueue wakeup loss. The receiver.recv() future is kept alive in a pinned
    // bridge, so the doorbell readiness is never lost when other select arms win.
    let (resp_tx, mut resp_rx) =
        tokio::sync::mpsc::channel::<std::result::Result<WorkerResponse, amla_ipc::Error>>(8);
    let resp_bridge = async {
        loop {
            let resp = receiver.recv::<WorkerResponse>().await;
            let done = resp.is_err();
            if resp_tx.send(resp).await.is_err() {
                break;
            }
            if done {
                break;
            }
        }
        Ok::<(), VmmError>(())
    };
    tokio::pin!(resp_bridge);

    loop {
        if shutdown_waiter.is_some() && pending_reply.is_none() && !shutdown_sent {
            match send_shutdown_request(&mut sender, &mut shutdown_waiter).await? {
                ShutdownSend::Sent => shutdown_sent = true,
                ShutdownSend::PeerClosed => break Ok(()),
            }
            continue;
        }

        if should_exit_without_shutdown(
            cmd_closed && signal_closed,
            shutdown_waiter.is_some(),
            shutdown_sent,
        ) {
            break Ok(());
        }

        tokio::select! {
            result = &mut resp_bridge, if !resp_bridge_done => {
                result?;
                resp_bridge_done = true;
            }

            cmd = cmd_rx.recv(), if !cmd_closed && !shutdown_sent => {
                let Some(cmd) = cmd else {
                    cmd_closed = true;
                    log::debug!("ipc_task: command channel closed");
                    continue;
                };
                match cmd {
                    IpcCommand::Request { request, reply } => {
                        if pending_reply.is_some() {
                            if reply
                                .send(Err(VmmError::Config(
                                    "concurrent IPC request while reply is pending".into(),
                                )))
                                .is_err()
                            {
                                log::debug!(
                                    "ipc_task: concurrent request receiver dropped before error"
                                );
                            }
                            continue;
                        }
                        log::trace!("ipc_task: send request");
                        sender.send(request).await?;
                        pending_reply = Some(reply);
                    }
                    IpcCommand::ResumeVcpu { id, seq, response } => {
                        log::trace!("ipc_task: send ResumeVcpu id={id} seq={seq}");
                        sender.send(WorkerRequest::ResumeVcpu { id, seq, response }).await?;
                    }
                    IpcCommand::Shutdown { reply } => {
                        log::debug!("ipc_task: terminal shutdown requested");
                        cmd_rx.close();
                        signal_rx.close();
                        cmd_closed = true;
                        signal_closed = true;
                        shutdown_waiter = Some(match reply {
                            Some(reply) => ShutdownWaiter::Caller(reply),
                            None => ShutdownWaiter::Detached,
                        });
                        if pending_reply.is_some() {
                            log::debug!("ipc_task: draining stale reply before shutdown");
                        }
                    }
                }
            }
            signal = signal_rx.recv(), if !shutdown_sent && !signal_closed => {
                let Some(signal) = signal else {
                    signal_closed = true;
                    log::debug!("ipc_task: signal channel closed");
                    continue;
                };
                let request = match signal {
                    IpcSignal::Preempt { id } => WorkerRequest::Preempt { id },
                    IpcSignal::IrqLine { gsi, level } => {
                        log::debug!("ipc_task: forwarding IrqLine gsi={gsi} level={level}");
                        WorkerRequest::IrqLine { gsi, level }
                    }
                };
                match sender.send(request).await {
                    Ok(()) => {}
                    Err(e) => {
                        return Err(VmmError::Config(format!("send worker request: {e}")).into());
                    }
                }
            }
            resp = resp_rx.recv() => {
                let Some(resp) = resp else {
                    break Ok(());
                };
                let resp = match resp {
                    Ok(resp) => resp,
                    Err(e) if shutdown_sent && ipc_peer_closed(&e) => {
                        log::debug!("ipc_task: worker closed after shutdown: {e}");
                        break Ok(());
                    }
                    Err(e) => return Err(VmmError::Config(format!("recv: {e}")).into()),
                };
                match resp {
                    WorkerResponse::VcpuExit { id, seq, exit } => {
                        if shutdown_sent {
                            log::debug!(
                                "ipc_task: dropping VcpuExit id={id} seq={seq} during shutdown"
                            );
                            continue;
                        }
                        log::trace!("ipc_task: recv VcpuExit id={id} seq={seq} exit={exit:?}");
                        if let Some(tx) = vcpu_exit_txs.get(id as usize) {
                            if tx.send((seq, exit)).await.is_err() {
                                log::warn!("vcpu {id} exit channel closed");
                            }
                        } else {
                            log::error!("VcpuExit with invalid id={id}");
                        }
                    }
                    WorkerResponse::DeviceKick { wake_idx } => {
                        if shutdown_sent {
                            log::debug!("ipc_task: dropping DeviceKick during shutdown");
                            continue;
                        }
                        log::trace!("ipc_task: recv DeviceKick wake_idx={wake_idx}");
                        let wake_idx = DeviceWakeIndex::try_from(wake_idx).map_err(|err| {
                            VmmError::Config(format!("worker device wake index invalid: {err}"))
                        })?;
                        device_waker.kick(wake_idx);
                    }
                    WorkerResponse::IrqResample { gsi } => {
                        if shutdown_sent {
                            log::debug!("ipc_task: dropping IrqResample gsi={gsi} during shutdown");
                            continue;
                        }
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
                        if shutdown_sent {
                            log::debug!("ipc_task: shutdown response received");
                            if let Some(waiter) = shutdown_waiter.take() {
                                waiter.send(Ok(resp));
                            }
                            break Ok(());
                        }
                        log::trace!(
                            "ipc_task: recv response pending_reply={}",
                            pending_reply.is_some()
                        );
                        if let Some(tx) = pending_reply.take()
                            && tx.send(Ok(resp)).is_err()
                        {
                            log::debug!("ipc_task: response receiver dropped before reply");
                        }
                    }
                    WorkerResponse::Error { error } => {
                        log::debug!(
                            "ipc_task: recv error pending_reply={} shutdown_sent={shutdown_sent}: {}",
                            pending_reply.is_some(),
                            error.message()
                        );
                        if shutdown_sent {
                            log::debug!("ipc_task: shutdown error received");
                            if let Some(waiter) = shutdown_waiter.take() {
                                waiter.send(Err(error.into_vmm_error()));
                            }
                            break Ok(());
                        }
                        if let Some(tx) = pending_reply.take() {
                            if tx.send(Err(error.into_vmm_error())).is_err() {
                                log::debug!("ipc_task: error receiver dropped before reply");
                            }
                        } else {
                            let message = error.message();
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
// Boot state helpers
// ============================================================================

use crate::worker::state::{
    HvfSysRegEntry, HvfVcpuSnapshot, snapshot_from_bytes, snapshot_to_bytes,
};
use amla_core::arm64::snapshot::{Arm64SysReg, Arm64VcpuSnapshot, SIMD_REG_COUNT};

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

/// Convert a shared `Arm64VcpuSnapshot` to an `HvfVcpuSnapshot`.
///
/// `boot_cntvoff` MUST be identical for every vCPU of the same VM — this is
/// the `CNTVOFF_EL2` value each vCPU will load via `hv_vcpu_set_vtimer_offset`,
/// and the ARM architecture (plus Linux `sched_clock`) requires all vCPUs to
/// observe the same `CNTVCT_EL0`.
fn hvf_snapshot_from_shared(
    shared: &Arm64VcpuSnapshot,
    power_state: u8,
    boot_cntvoff: u64,
) -> HvfVcpuSnapshot {
    let mut snap = HvfVcpuSnapshot {
        gp_regs: [0; 35],
        _pad_gp: [0; 8],
        simd_regs: [0; SIMD_REG_COUNT],
        sys_regs: [HvfSysRegEntry {
            encoding: 0,
            _pad: [0; 6],
            value: 0,
        }; 32],
        sys_reg_count: 0,
        _pad: 0,
        // Shared across all vCPUs → CNTVCT_EL0 is system-coherent.
        vtimer_offset: boot_cntvoff,
        power_state,
        _pad2: [0; 7],
        capture_mach_time: 0,
    };

    // Copy GP regs.
    let n = shared.gp_regs.len().min(35);
    snap.gp_regs[..n].copy_from_slice(&shared.gp_regs[..n]);

    // Copy sys regs from shared snapshot.
    let sys_n = shared.sys_regs.len().min(32);
    for (i, &(enc, val)) in shared.sys_regs.iter().take(sys_n).enumerate() {
        snap.sys_regs[i] = HvfSysRegEntry {
            encoding: enc,
            _pad: [0; 6],
            value: val,
        };
    }
    let mut total_sys = sys_n;

    // HVF initializes SCTLR_EL1 to 0x0 (all bits cleared), which is invalid —
    // ARM64 requires certain RES1 bits. If the shared snapshot doesn't include
    // SCTLR_EL1 (boot snapshots typically don't), inject the standard reset
    // value used by crosvm/libkrun/kvmtool: MMU off, RES1 bits set.
    let sctlr_enc = Arm64SysReg::SctlrEl1.encoding();
    let sctlr_entry = HvfSysRegEntry {
        encoding: sctlr_enc,
        _pad: [0; 6],
        value: 0x30C5_0830,
    };
    if let Some(existing) = snap.sys_regs[..total_sys]
        .iter_mut()
        .find(|e| e.encoding == sctlr_enc)
    {
        // Already present — leave the caller's value as-is.
        let _ = existing;
    } else if total_sys < 32 {
        snap.sys_regs[total_sys] = sctlr_entry;
        total_sys += 1;
    } else {
        // Array is full without SCTLR_EL1 — replace the last entry.
        // SCTLR_EL1 is critical (ARM64 RES1 bits); the evicted register
        // is less important than a correct CPU mode.
        log::warn!("hvf: sys_regs full, replacing last entry to inject SCTLR_EL1");
        snap.sys_regs[31] = sctlr_entry;
    }

    #[allow(clippy::cast_possible_truncation)]
    {
        snap.sys_reg_count = total_sys as u32;
    }

    // Copy SIMD regs.
    let simd_n = shared.simd_regs.len().min(SIMD_REG_COUNT);
    snap.simd_regs[..simd_n].copy_from_slice(&shared.simd_regs[..simd_n]);

    snap
}

/// Write an `HvfVcpuSnapshot` into a `VmState` vCPU slot.
fn write_snapshot_to_slot(
    view: &mut amla_core::vm_state::VmState<'_>,
    index: usize,
    snap: &HvfVcpuSnapshot,
) -> Result<()> {
    let data = snapshot_to_bytes(snap);
    let slot = view.vcpu_slot_mut(index).ok_or(VmmError::InvalidState {
        expected: "valid vcpu index",
        actual: "out of bounds",
    })?;
    if data.len() > slot.len() {
        return Err(VmmError::Config(format!(
            "snapshot {} bytes exceeds slot size {}",
            data.len(),
            slot.len()
        )));
    }
    slot[..data.len()].copy_from_slice(&data);
    Ok(())
}

/// Advance every vCPU's `vtimer_offset` by the real host time that elapsed
/// since capture, and collapse any per-vCPU drift so every vCPU ends up with
/// the same `CNTVOFF_EL2` value.
///
/// Fresh-boot snapshots written by `write_boot_state` carry
/// `capture_mach_time == 0`; this function detects that and returns without
/// modification. For snapshot restore, vCPU 0's `(capture_mach_time,
/// vtimer_offset)` pair is taken as the reference — the new CNTVOFF is
/// `(now - capture_mach_time) + vtimer_offset`, applied identically to every
/// vCPU. This preserves `CNTVCT_EL0` across the save/restore boundary for
/// vCPU 0 and guarantees system-coherent CNTVCT across all vCPUs (required
/// by Linux `sched_clock`).
fn rebase_vtimer_offsets(
    view: &mut amla_core::vm_state::VmState<'_>,
    vcpu_count: u32,
) -> Result<()> {
    if vcpu_count == 0 {
        return Ok(());
    }
    let snap_size = std::mem::size_of::<HvfVcpuSnapshot>();

    let first_slot = view.vcpu_slot(0).ok_or(VmmError::InvalidState {
        expected: "valid vcpu index",
        actual: "out of bounds",
    })?;
    let first_snap = snapshot_from_bytes(&first_slot[..snap_size])?;
    if first_snap.capture_mach_time == 0 {
        return Ok(());
    }

    // SAFETY: mach_absolute_time has no preconditions.
    let now = unsafe { mach_absolute_time() };
    let elapsed = now.wrapping_sub(first_snap.capture_mach_time);
    let canonical_cntvoff = first_snap.vtimer_offset.wrapping_add(elapsed);

    for i in 0..vcpu_count {
        let slot = view
            .vcpu_slot_mut(i as usize)
            .ok_or(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            })?;
        let mut snap = snapshot_from_bytes(&slot[..snap_size])?;
        snap.vtimer_offset = canonical_cntvoff;
        snap.capture_mach_time = 0;
        let bytes = snapshot_to_bytes(&snap);
        slot[..bytes.len()].copy_from_slice(&bytes);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::should_exit_without_shutdown;

    #[test]
    fn deferred_shutdown_keeps_ipc_task_alive_after_inputs_close() {
        assert!(!should_exit_without_shutdown(true, true, false));
    }

    #[test]
    fn closed_inputs_without_shutdown_can_exit() {
        assert!(should_exit_without_shutdown(true, false, false));
    }

    #[test]
    fn shutdown_already_sent_waits_for_worker_ack() {
        assert!(!should_exit_without_shutdown(true, true, true));
    }
}
