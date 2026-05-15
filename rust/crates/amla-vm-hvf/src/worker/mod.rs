// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF subprocess worker — runs vCPU threads in an isolated process.
//!
//! Entry point: [`worker_main`]. Called from the `amla-hvf-worker` binary.
//! Bootstraps IPC from stdin, creates an HVF VM with `GICv3`, spawns
//! per-vCPU OS threads, and enters a message dispatch loop.

pub(crate) mod exit;
pub(crate) mod gic;
pub(crate) mod memory;
pub(crate) mod state;
pub(crate) mod vcpu_thread;
pub(crate) mod vtimer;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use parking_lot::RwLock;
use tokio::sync::mpsc;

use amla_core::{MappingHandleInfo, ValidatedMapSource, ValidatedMemoryMappings};
use amla_ipc::RingBuffer;

use crate::error::{Result, VmmError};
use crate::ffi;
use crate::protocol::{
    WorkerError, WorkerQueueSlot, WorkerRequest, WorkerResponse, WorkerTopology,
};

use vcpu_thread::{CapturedVcpuState, VcpuCommand, VcpuEvent, VcpuThreadHandle};

fn validate_topology(topology: &WorkerTopology) -> Result<()> {
    let mut gsis = HashSet::with_capacity(topology.devices.len());
    let mut wake_indexes = HashSet::new();
    let mut notify_slots = HashSet::new();

    for (device_idx, device) in topology.devices.iter().enumerate() {
        if !gsis.insert(device.gsi) {
            return Err(VmmError::Config(format!(
                "worker topology has duplicate GSI {}",
                device.gsi
            )));
        }
        if device.queues.is_empty() {
            return Err(VmmError::Config(format!(
                "worker topology device {device_idx} has no queues"
            )));
        }

        let mut local_queues = HashSet::with_capacity(device.queues.len());
        for queue in &device.queues {
            let queue_idx = usize::try_from(queue.queue_idx)
                .map_err(|_| VmmError::Config("queue_idx does not fit usize".into()))?;
            if queue_idx >= device.queues.len() {
                return Err(VmmError::Config(format!(
                    "worker topology device {device_idx} queue_idx {} outside 0..{}",
                    queue.queue_idx,
                    device.queues.len()
                )));
            }
            if !local_queues.insert(queue.queue_idx) {
                return Err(VmmError::Config(format!(
                    "worker topology device {device_idx} has duplicate queue_idx {}",
                    queue.queue_idx
                )));
            }
            if !wake_indexes.insert(queue.wake_idx) {
                return Err(VmmError::Config(format!(
                    "worker topology has duplicate wake_idx {}",
                    queue.wake_idx
                )));
            }
            if !notify_slots.insert((queue.mmio_notify_addr, queue.queue_idx)) {
                return Err(VmmError::Config(format!(
                    "worker topology has duplicate notify slot addr={:#x} queue={}",
                    queue.mmio_notify_addr, queue.queue_idx
                )));
            }
        }
    }

    Ok(())
}

// ============================================================================
// Entry point
// ============================================================================

/// Worker process entry point. Never returns.
pub async fn worker_main() -> ! {
    // Enable log output based on RUST_LOG inherited from parent via posix_spawn.
    // Best-effort; a worker restart may have already initialized the logger
    // (try_init returns SetLoggerError in that case, which we intentionally
    // discard since the existing logger remains functional).
    if let Err(e) = env_logger::try_init() {
        eprintln!("[hvf-worker] env_logger already initialized: {e}");
    }

    std::panic::set_hook(Box::new(|info| {
        eprintln!("[hvf-worker] PANIC: {info}");
        let bt = std::backtrace::Backtrace::force_capture();
        eprintln!("{bt}");
    }));

    let code = match worker_run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("hvf-worker failed: {e}");
            1
        }
    };
    std::process::exit(code);
}

// ============================================================================
// Worker state
// ============================================================================

#[derive(Clone)]
struct WorkerVcpuEndpoint {
    wfi_wake: Arc<vcpu_thread::WfiWake>,
    vcpu_handle: Arc<vcpu_thread::AtomicVcpuHandle>,
}

struct WorkerInterruptSink {
    endpoints: RwLock<Vec<WorkerVcpuEndpoint>>,
}

impl WorkerInterruptSink {
    fn new(vcpu_count: usize) -> Self {
        Self {
            endpoints: RwLock::new(Vec::with_capacity(vcpu_count)),
        }
    }

    fn register_vcpu(&self, thread: &VcpuThreadHandle) {
        self.endpoints.write().push(WorkerVcpuEndpoint {
            wfi_wake: Arc::clone(&thread.wfi_wake),
            vcpu_handle: Arc::clone(&thread.vcpu_handle),
        });
    }

    fn endpoint(&self, vcpu_id: usize) -> Option<WorkerVcpuEndpoint> {
        self.endpoints.read().get(vcpu_id).cloned()
    }
}

impl gic::InterruptSink for WorkerInterruptSink {
    fn signal_irq(&self, vcpu_id: usize, pending: bool) {
        // The userspace GIC is the source of truth for interrupt state. HVF's
        // IRQ input is redriven from GIC state on the owning vCPU thread
        // immediately before every guest entry. Calling
        // hv_vcpu_set_pending_interrupt here races HVF's thread-affine vCPU
        // state and can fail with HV_BAD_ARGUMENT during boot-time device IRQs.
        log::debug!("hvf-worker: signal_irq vcpu={vcpu_id} pending={pending}");
    }

    fn wake_vcpu(&self, vcpu_id: usize) {
        log::debug!("hvf-worker: wake_vcpu vcpu={vcpu_id}");
        let Some(endpoint) = self.endpoint(vcpu_id) else {
            return;
        };
        endpoint.wfi_wake.notify();
        if let Some(h) = endpoint.vcpu_handle.load() {
            // SAFETY: this is a cross-thread kick only. The vCPU thread
            // redrives HVF's IRQ input from userspace GIC state on its own
            // thread immediately before re-entering the guest.
            unsafe {
                let mut h = h.get();
                let ret = ffi::hv_vcpus_exit(&raw mut h, 1);
                if ret == ffi::HV_BAD_ARGUMENT {
                    log::debug!("hvf-worker: wake kick hit destroyed vcpu handle");
                } else if ret != ffi::HV_SUCCESS {
                    log::debug!("hvf-worker: wake kick hv_vcpus_exit ret={ret:#010x}");
                }
            }
        }
    }
}

struct WorkerState {
    vcpu_threads: Vec<VcpuThreadHandle>,
    vcpu_seqs: Arc<Vec<AtomicU64>>,
    maps: Vec<amla_mem::MmapSlice>,
    gic: Arc<gic::GicV3>,
    /// Per-vCPU register snapshots, saved as raw bytes.
    saved_vcpu_snapshots: Option<Vec<Vec<u8>>>,
    /// Serialized userspace GIC state.
    saved_gic_blob: Option<Vec<u8>>,
}

async fn report_init_error(sender: &mut amla_ipc::Sender<'_>, error: &VmmError) {
    if let Err(send_err) = sender
        .send(WorkerResponse::Error {
            error: WorkerError::from_vmm_error(error),
        })
        .await
    {
        log::error!("hvf-worker: failed to report Init error: {send_err}");
    }
}

fn create_hvf_vm() -> Result<()> {
    // SAFETY: first HVF call in this process. hv_vm_config_create returns a
    // new OS object or null; the other FFI calls operate on that config
    // handle (or null, which hv_vm_create accepts) and the OS object is
    // released below.
    unsafe {
        let config = ffi::hv_vm_config_create();
        let result = if config.is_null() {
            ffi::check("hv_vm_create", ffi::hv_vm_create(std::ptr::null()))
        } else {
            ffi::check(
                "hv_vm_config_set_ipa_size",
                ffi::hv_vm_config_set_ipa_size(config, 36),
            )
            .and_then(|()| ffi::check("hv_vm_create", ffi::hv_vm_create(config)))
        };
        if !config.is_null() {
            ffi::os_release(config);
        }
        result.map_err(VmmError::from)
    }
}

fn destroy_hvf_vm_after_startup_failure() {
    // SAFETY: called only after `create_hvf_vm` succeeded. Startup cleanup
    // joins all vCPU threads before this helper destroys the VM.
    let destroy_ret = unsafe { ffi::hv_vm_destroy() };
    if let Err(e) = ffi::check("hv_vm_destroy(startup failure)", destroy_ret) {
        log::error!("hvf-worker: hv_vm_destroy failed after startup failure: {e}");
    }
}

fn shutdown_vcpu_threads(vcpu_threads: &mut [VcpuThreadHandle]) {
    for thread in vcpu_threads.iter_mut() {
        let (dead_tx, _) = mpsc::channel(1);
        drop(std::mem::replace(&mut thread.cmd_tx, dead_tx));
        thread.wfi_wake.notify();
    }

    for thread in vcpu_threads {
        if let Some(handle) = thread.join_handle.take()
            && let Err(panic) = handle.join()
        {
            log::error!("hvf-worker: vCPU thread panicked during startup cleanup: {panic:?}");
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

// ============================================================================
// Main async loop
// ============================================================================

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
async fn worker_run() -> Result<()> {
    // Bootstrap IPC from stdin.
    let mut ring =
        RingBuffer::from_child_stdin().map_err(|e| VmmError::Config(format!("bootstrap: {e}")))?;
    let (mut sender, mut receiver) = ring
        .split(false)
        .map_err(|e| VmmError::Config(format!("ring split: {e}")))?;

    log::info!("hvf-worker started (pid={})", std::process::id());

    // Wait for Init.
    let req = receiver
        .recv::<WorkerRequest>()
        .await
        .map_err(|e| VmmError::Config(format!("recv Init: {e}")))?;

    let (vcpu_count, topology) = if let WorkerRequest::Init {
        vcpu_count,
        topology,
    } = req
    {
        log::info!(
            "hvf-worker Init vcpu_count={vcpu_count} device_gsis={} io_slots={}",
            topology.devices.len(),
            topology
                .devices
                .iter()
                .map(|device| device.queues.len())
                .sum::<usize>()
        );
        if vcpu_count == 0 {
            let err = VmmError::Config("vcpu_count must be >= 1".into());
            report_init_error(&mut sender, &err).await;
            return Err(err);
        }
        if vcpu_count as usize > amla_core::vm_state::MAX_VCPUS {
            let err = VmmError::Config(format!(
                "vcpu_count ({vcpu_count}) exceeds MAX_VCPUS ({})",
                amla_core::vm_state::MAX_VCPUS
            ));
            report_init_error(&mut sender, &err).await;
            return Err(err);
        }
        if let Err(e) = validate_topology(&topology) {
            report_init_error(&mut sender, &e).await;
            return Err(e);
        }
        (vcpu_count as usize, topology)
    } else {
        if let Err(e) = sender
            .send(WorkerResponse::Error {
                error: WorkerError::Message {
                    message: "expected Init".into(),
                },
            })
            .await
        {
            log::error!("hvf-worker: failed to report Init protocol error: {e}");
        }
        return Err(VmmError::Config("expected Init".into()));
    };

    // Step 1: Create HVF VM with 36-bit IPA space.
    if let Err(e) = create_hvf_vm() {
        report_init_error(&mut sender, &e).await;
        return Err(e);
    }
    log::debug!("hvf-worker: HVF VM created");

    // Step 2: Build notify map ((MMIO notify address, queue index) → wake bit).
    let queue_slots: Vec<WorkerQueueSlot> = topology
        .devices
        .iter()
        .flat_map(|device| device.queues.iter().copied())
        .collect();
    let notify_map: HashMap<(u64, u32), u8> = queue_slots
        .iter()
        .map(|queue| ((queue.mmio_notify_addr, queue.queue_idx), queue.wake_idx))
        .collect();
    let notify_map = Arc::new(notify_map);

    // Step 3: Build the userspace GIC and register vCPU endpoints as threads
    // come up. The shared GIC owns an Arc to the sink, while the worker keeps a
    // concrete Arc so it can register thread endpoints as each vCPU starts.
    let interrupt_sink = Arc::new(WorkerInterruptSink::new(vcpu_count));
    let gic = Arc::new(gic::GicV3::new(
        gic::GicConfig {
            num_vcpus: vcpu_count,
            gicd_base: gic::GICD_BASE,
            gicr_base: gic::GICR_BASE,
        },
        interrupt_sink.clone(),
    ));

    // Step 4: Spawn vCPU threads with a shared merged event channel.
    let (merged_tx, mut merged_rx) = mpsc::channel::<(u32, VcpuEvent)>(vcpu_count * 2);

    let mut vcpu_threads = Vec::with_capacity(vcpu_count);
    let mut startup_rxs = Vec::with_capacity(vcpu_count);
    for i in 0..vcpu_count {
        let (handle, startup_rx) = match vcpu_thread::spawn_vcpu_thread(
            i,
            Arc::clone(&gic),
            Arc::clone(&notify_map),
            merged_tx.clone(),
        ) {
            Ok(started) => started,
            Err(e) => {
                shutdown_vcpu_threads(&mut vcpu_threads);
                destroy_hvf_vm_after_startup_failure();
                report_init_error(&mut sender, &e).await;
                return Err(e);
            }
        };
        interrupt_sink.register_vcpu(&handle);
        vcpu_threads.push(handle);
        startup_rxs.push((i, startup_rx));
    }
    // Drop our copy so the channel closes when all vCPU threads exit.
    drop(merged_tx);

    let mut startup_error = None;
    for (i, startup_rx) in startup_rxs {
        match startup_rx.await {
            Ok(Ok(())) => {
                log::debug!("hvf-worker: vCPU {i} startup complete");
            }
            Ok(Err(e)) => {
                log::debug!("hvf-worker: vCPU {i} startup failed: {e}");
                startup_error = Some(e);
                break;
            }
            Err(_) => {
                log::debug!("hvf-worker: vCPU {i} startup channel dropped");
                startup_error = Some(VmmError::WorkerDead(format!(
                    "vCPU thread {i} dropped startup channel"
                )));
                break;
            }
        }
    }

    if let Some(e) = startup_error {
        shutdown_vcpu_threads(&mut vcpu_threads);
        destroy_hvf_vm_after_startup_failure();
        report_init_error(&mut sender, &e).await;
        return Err(e);
    }
    log::debug!("hvf-worker: all vCPUs started; reporting Ready");

    let vcpu_seqs: Arc<Vec<AtomicU64>> =
        Arc::new((0..vcpu_count).map(|_| AtomicU64::new(0)).collect());

    sender
        .send(WorkerResponse::Ready)
        .await
        .map_err(|e| VmmError::Config(format!("send Ready: {e}")))?;

    let mut state = WorkerState {
        vcpu_threads,
        vcpu_seqs,
        maps: Vec::new(),
        gic,
        saved_vcpu_snapshots: None,
        saved_gic_blob: None,
    };

    // Bridge IPC reads into an mpsc channel so the main select loop only
    // waits on level-triggered channels. This avoids lost wakeups from the
    // edge-triggered kqueue doorbell: when a `receiver.recv()` future is
    // dropped by `select!` (because the other arm won), the kqueue readiness
    // can be consumed without the message being read. By keeping the recv
    // future alive in a dedicated pinned bridge, the edge event is never lost.
    let (ipc_tx, mut ipc_rx) = mpsc::channel::<WorkerRequest>(4);
    let ipc_bridge = async {
        loop {
            let req = match receiver.recv::<WorkerRequest>().await {
                Ok(req) => req,
                // Parent closed the IPC channel — normal shutdown path.
                // Treat as clean exit so the worker doesn't spam stderr
                // with "hvf-worker failed: recv: io: doorbell: peer closed".
                Err(amla_ipc::Error::Io(io_err))
                    if io_err.kind() == std::io::ErrorKind::UnexpectedEof =>
                {
                    log::debug!("hvf-worker: parent closed IPC, exiting cleanly");
                    return Ok::<(), VmmError>(());
                }
                Err(e) => return Err(VmmError::Config(format!("recv: {e}"))),
            };
            if ipc_tx.send(req).await.is_err() {
                break;
            }
        }
        Ok::<(), VmmError>(())
    };
    tokio::pin!(ipc_bridge);

    // Main select loop — all arms are mpsc channels (level-triggered).
    loop {
        tokio::select! {
            result = &mut ipc_bridge => {
                // Bridge ended: either IPC error or main loop dropped ipc_rx.
                return result;
            }

            Some(req) = ipc_rx.recv() => {
                log::trace!("hvf-worker: request");
                match handle_request(req, &mut sender, &mut state).await {
                    Ok(true) => return Ok(()),  // Shutdown
                    Ok(false) => {}
                    Err(e) => {
                        log::error!("request handler: {e}");
                        if let Err(send_err) = sender.send(WorkerResponse::Error {
                            error: WorkerError::from_vmm_error(&e),
                        }).await {
                            log::error!("hvf-worker: failed to report handler error: {send_err}");
                        }
                    }
                }
            }

            Some((id, event)) = merged_rx.recv() => {
                match event {
                    VcpuEvent::Exit(exit) => {
                        let seq = state.vcpu_seqs
                            .get(id as usize)
                            .map_or(0, |s| s.load(Ordering::Acquire));
                        sender.send(WorkerResponse::VcpuExit { id, seq, exit }).await
                            .map_err(|e| VmmError::Config(format!("send VcpuExit: {e}")))?;
                    }
                    VcpuEvent::DeviceKick(wake_idx) => {
                        sender
                            .send(WorkerResponse::DeviceKick { wake_idx })
                            .await
                            .map_err(|e| VmmError::Config(format!("send DeviceKick: {e}")))?;
                    }
                }
            }
        }
    }
}

// ============================================================================
// Request handler
// ============================================================================

/// Handle a parent request. Returns `Ok(true)` on Shutdown.
#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
async fn handle_request(
    req: WorkerRequest,
    sender: &mut amla_ipc::Sender<'_>,
    state: &mut WorkerState,
) -> Result<bool> {
    match req {
        WorkerRequest::Init { .. } => {
            sender
                .send(WorkerResponse::Error {
                    error: WorkerError::Message {
                        message: "duplicate Init".into(),
                    },
                })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::MapMemory { handles, mappings } => {
            handle_map_memory(state, &handles, &mappings)?;
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::SaveState { vcpu_count } => {
            let count = validate_save_vcpu_count(vcpu_count, state.vcpu_threads.len())?;

            // Dispatch CaptureState to each vCPU thread (thread-affinity).
            let mut vcpu_snapshots = Vec::with_capacity(count);
            for thread in state.vcpu_threads.iter().take(count) {
                let (tx, rx) = tokio::sync::oneshot::channel();
                thread
                    .cmd_tx
                    .send(VcpuCommand::CaptureState(tx))
                    .await
                    .map_err(|_| VmmError::WorkerDead("vCPU thread gone".into()))?;
                let captured = rx
                    .await
                    .map_err(|_| VmmError::WorkerDead("capture oneshot".into()))??;
                vcpu_snapshots.push(state::snapshot_to_bytes(&captured.snapshot));
            }

            let gic_blob = bytemuck::bytes_of(&state.gic.freeze()).to_vec();

            state.saved_vcpu_snapshots = Some(vcpu_snapshots);
            state.saved_gic_blob = Some(gic_blob);

            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::GetSavedVcpu { id } => {
            let snapshots = state
                .saved_vcpu_snapshots
                .as_ref()
                .ok_or(VmmError::InvalidState {
                    expected: "saved vcpu state present",
                    actual: "no saved state",
                })?;
            let data = snapshots
                .get(id as usize)
                .ok_or(VmmError::InvalidState {
                    expected: "valid vcpu index",
                    actual: "out of bounds",
                })?
                .clone();

            sender
                .send(WorkerResponse::StateData { data })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::GetSavedIrqchip => {
            let gic_blob = state
                .saved_gic_blob
                .as_ref()
                .ok_or(VmmError::InvalidState {
                    expected: "saved GIC blob present",
                    actual: "no saved GIC state",
                })?
                .clone();
            sender
                .send(WorkerResponse::StateData { data: gic_blob })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::CaptureDefaultIrqchip => {
            let data = bytemuck::bytes_of(&state.gic.freeze()).to_vec();
            sender
                .send(WorkerResponse::StateData { data })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::RestoreVcpu { id, data } => {
            let snapshot = state::snapshot_from_bytes(&data)?;
            let captured = CapturedVcpuState { snapshot };

            let thread = state
                .vcpu_threads
                .get(id as usize)
                .ok_or(VmmError::InvalidState {
                    expected: "valid vcpu index",
                    actual: "out of bounds",
                })?;
            let (tx, rx) = tokio::sync::oneshot::channel();
            thread
                .cmd_tx
                .send(VcpuCommand::RestoreState(Box::new(captured), tx))
                .await
                .map_err(|_| VmmError::WorkerDead("vCPU thread gone".into()))?;
            rx.await
                .map_err(|_| VmmError::WorkerDead("restore oneshot".into()))??;
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::RestoreIrqchip { blob } => {
            if blob.is_empty() {
                return Err(VmmError::InvalidState {
                    expected: "non-empty GIC state blob",
                    actual: "empty GIC state blob",
                });
            }
            let gic_state = bytemuck::try_from_bytes::<gic::GicState>(&blob).map_err(|_| {
                VmmError::InvalidState {
                    expected: "serialized GIC state blob",
                    actual: "invalid GIC blob",
                }
            })?;
            state
                .gic
                .thaw(gic_state)
                .map_err(|e| VmmError::Config(e.to_string()))?;
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::ResumeVcpu { id, seq, response } => {
            log::debug!("hvf-worker: ResumeVcpu id={id} seq={seq}");
            if let Some(s) = state.vcpu_seqs.get(id as usize) {
                s.store(seq, Ordering::Release);
            }
            let thread = state
                .vcpu_threads
                .get(id as usize)
                .ok_or(VmmError::InvalidState {
                    expected: "valid vcpu index",
                    actual: "out of bounds",
                })?;
            thread
                .cmd_tx
                .send(VcpuCommand::Resume(response))
                .await
                .map_err(|_| VmmError::WorkerDead("vCPU thread gone".into()))?;
        }

        WorkerRequest::Preempt { id } => {
            if let Some(thread) = state.vcpu_threads.get(id as usize) {
                thread.preempt_flag.store(true, Ordering::Release);
                thread.wfi_wake.notify();
                if let Some(h) = thread.vcpu_handle.load() {
                    // SAFETY: hv_vcpus_exit is documented as thread-safe and
                    // accepts any valid vcpu handle from any thread. `h` is a
                    // live handle (still loaded from the atomic); a race with
                    // vCPU thread teardown is benign — HVF returns
                    // HV_BAD_ARGUMENT which we ignore here.
                    unsafe {
                        let mut h = h.get();
                        ffi::hv_vcpus_exit(&raw mut h, 1);
                    }
                }
            }
        }

        WorkerRequest::IrqLine { gsi, level } => {
            state.gic.set_spi_level(gsi, level);
            if level {
                for thread in &state.vcpu_threads {
                    thread.wfi_wake.notify();
                    if let Some(h) = thread.vcpu_handle.load() {
                        // SAFETY: this is a cross-thread kick only. The vCPU
                        // run loop treats the resulting CANCELED exit as
                        // spurious unless a real preempt flag was set, then
                        // redrives HVF IRQ from userspace GIC state before
                        // re-entering.
                        unsafe {
                            let mut h = h.get();
                            let ret = ffi::hv_vcpus_exit(&raw mut h, 1);
                            if ret == ffi::HV_BAD_ARGUMENT {
                                log::debug!("hvf-worker: irq kick hit destroyed vcpu handle");
                            } else if ret != ffi::HV_SUCCESS {
                                log::debug!("hvf-worker: irq kick hv_vcpus_exit ret={ret:#010x}");
                            }
                        }
                    }
                }
            }
        }

        WorkerRequest::Shutdown => {
            log::info!("hvf-worker: shutdown");

            // Preempt all vCPUs and wake any sleeping in WFI.
            // Note: hv_vcpus_exit races with the vCPU thread's teardown
            // (store(None) + hv_vcpu_destroy) — the handle may be destroyed
            // between our load() and the exit call. This is benign: HVF
            // returns HV_BAD_ARGUMENT which we log at debug level.
            for (index, thread) in state.vcpu_threads.iter().enumerate() {
                log::debug!("hvf-worker: shutdown vcpu {index}: set preempt");
                thread.preempt_flag.store(true, Ordering::Release);
                log::debug!("hvf-worker: shutdown vcpu {index}: notify WFI");
                thread.wfi_wake.notify();
                log::debug!("hvf-worker: shutdown vcpu {index}: load handle");
                let handle = thread.vcpu_handle.load();
                log::debug!(
                    "hvf-worker: shutdown vcpu {index}: handle={:?}",
                    handle.map(|h| h.get())
                );
                if let Some(h) = handle {
                    // SAFETY: hv_vcpus_exit is thread-safe; `h` is a handle
                    // we just loaded. The benign race with vCPU thread
                    // teardown (HV_BAD_ARGUMENT) is handled explicitly below.
                    unsafe {
                        let mut h = h.get();
                        log::info!("hvf-worker: shutdown hv_vcpus_exit enter handle={h:#x}");
                        let ret = ffi::hv_vcpus_exit(&raw mut h, 1);
                        log::info!("hvf-worker: shutdown hv_vcpus_exit ret={ret:#010x}");
                        if ret == ffi::HV_BAD_ARGUMENT {
                            // Expected: vCPU thread already destroyed the handle.
                            log::debug!("hvf-worker: hv_vcpus_exit: handle already destroyed");
                        } else if ret != ffi::HV_SUCCESS {
                            log::warn!("hvf-worker: hv_vcpus_exit during shutdown: {ret:#010x}");
                        }
                    }
                }
            }

            // Close command channels → threads will exit their loops.
            // Replacing the sender drops the original, closing the channel so
            // each vCPU thread's `blocking_recv` returns None and the loop exits.
            log::debug!("hvf-worker: closing vCPU command channels");
            for thread in &mut state.vcpu_threads {
                let (dead_tx, _) = mpsc::channel(1);
                drop(std::mem::replace(&mut thread.cmd_tx, dead_tx));
            }

            // Join threads.
            log::debug!("hvf-worker: joining vCPU threads");
            for thread in &mut state.vcpu_threads {
                if let Some(handle) = thread.join_handle.take()
                    && let Err(panic) = handle.join()
                {
                    log::error!("hvf-worker: vCPU thread panicked during shutdown: {panic:?}");
                }
            }
            log::debug!("hvf-worker: vCPU threads joined");

            // Destroy VM (requires all vCPUs destroyed first — threads did that).
            log::debug!("hvf-worker: destroying HVF VM");
            // SAFETY: all vCPU threads have been joined above, so every
            // hv_vcpu_destroy has completed before we call hv_vm_destroy.
            let destroy_ret = unsafe { ffi::hv_vm_destroy() };
            log::debug!("hvf-worker: hv_vm_destroy returned {destroy_ret:#010x}");
            if let Err(e) = ffi::check("hv_vm_destroy(worker shutdown)", destroy_ret) {
                log::error!("hvf-worker: hv_vm_destroy failed during shutdown: {e}");
            }

            state.maps.clear();
            match sender.send(WorkerResponse::Ok).await {
                Ok(()) => log::debug!("hvf-worker: shutdown ack sent"),
                Err(e) if ipc_peer_closed(&e) => {
                    log::debug!("hvf-worker: parent closed before shutdown ack: {e}");
                }
                Err(e) => return Err(VmmError::Config(format!("send shutdown ack: {e}"))),
            }
            return Ok(true);
        }
    }

    Ok(false)
}

fn validate_save_vcpu_count(requested: u32, actual: usize) -> Result<usize> {
    let requested = usize::try_from(requested)
        .map_err(|_| VmmError::Config(format!("SaveState vcpu_count {requested} exceeds usize")))?;
    if requested != actual {
        return Err(VmmError::Config(format!(
            "SaveState vcpu_count mismatch: requested {requested}, worker has {actual}"
        )));
    }
    Ok(requested)
}

// ============================================================================
// Memory mapping handler
// ============================================================================

/// Install memory mappings into HVF.
///
/// This is transactional at the worker boundary: newly-created host mappings
/// are retained only after every HVF `hv_vm_map` succeeds, and previously
/// installed IPA mappings from this request are unmapped if a later mapping
/// fails.
fn handle_map_memory(
    state: &mut WorkerState,
    handles: &[amla_mem::MemHandle],
    mappings: &[amla_core::MemoryMapping],
) -> Result<()> {
    let handle_info: Vec<_> = handles.iter().map(MappingHandleInfo::from).collect();
    let mappings = ValidatedMemoryMappings::new(mappings, &handle_info)
        .map_err(|e| VmmError::Config(e.to_string()))?;

    // mmap each handle for HVF registration. Keep new mappings local until
    // every hv_vm_map succeeds so a failed request does not leave stale host
    // slices in WorkerState.
    let mut new_maps: Vec<amla_mem::MmapSlice> = handles
        .iter()
        .map(|h| {
            amla_mem::map_handle(h).map_err(|e| VmmError::SystemCall {
                operation: "map_handle",
                source: std::io::Error::other(e.to_string()),
            })
        })
        .collect::<Result<_>>()?;

    let mut installed = Vec::with_capacity(mappings.entries().len());
    for m in mappings.entries() {
        let (host_ptr, extra) = match m.source() {
            ValidatedMapSource::Handle {
                offset,
                offset_usize,
                index,
            } => {
                let Some(region) = new_maps.get(index) else {
                    let err = VmmError::Config(format!("handle_maps index {index} out of range"));
                    rollback_guest_mappings(&installed);
                    return Err(err);
                };
                // SAFETY: the validated mapping token checked index, offset,
                // size, handle bounds, and writable capability.
                let Some(ptr) = (unsafe { region.offset_mut_ptr(offset_usize) }) else {
                    let err = VmmError::Config(format!(
                        "handle offset {offset:#x} out of bounds for mapping at GPA {:#x}",
                        m.gpa()
                    ));
                    rollback_guest_mappings(&installed);
                    return Err(err);
                };
                (ptr.as_ptr(), None)
            }
            ValidatedMapSource::AnonymousZero => {
                let zero = match amla_mem::MmapSlice::anonymous(m.size_usize()) {
                    Ok(zero) => zero,
                    Err(e) => {
                        rollback_guest_mappings(&installed);
                        return Err(VmmError::SystemCall {
                            operation: "mmap anonymous guest memory",
                            source: std::io::Error::other(e.to_string()),
                        });
                    }
                };
                let p = zero.as_ptr().cast_mut();
                (p, Some(zero))
            }
        };

        // SAFETY: `host_ptr` comes from a validated handle-backed slice or a
        // fresh anonymous mapping retained via the `extra` push below.
        // hv_vm_create was called during worker_run bootstrap.
        if let Err(e) = unsafe {
            memory::map_guest_memory(host_ptr.cast(), m.gpa(), m.size_usize(), m.readonly())
        } {
            rollback_guest_mappings(&installed);
            return Err(e);
        }

        installed.push((m.gpa(), m.size_usize()));
        if let Some(z) = extra {
            new_maps.push(z);
        }
    }

    state.maps.extend(new_maps);

    Ok(())
}

fn rollback_guest_mappings(installed: &[(u64, usize)]) {
    for &(ipa, size) in installed.iter().rev() {
        // SAFETY: each `(ipa, size)` pair was successfully mapped by this
        // worker request and has not yet been transferred into durable worker
        // state. Rollback is best-effort; worker init will fail either way.
        let ret = unsafe { ffi::hv_vm_unmap(ipa, size) };
        if let Err(e) = ffi::check("hv_vm_unmap(map rollback)", ret) {
            log::error!("hvf-worker: failed to roll back mapping ipa={ipa:#x} size={size:#x}: {e}");
        }
    }
}
