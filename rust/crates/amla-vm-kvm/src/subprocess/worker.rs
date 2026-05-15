// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Subprocess worker — runs KVM vCPU threads in an isolated process.
//!
//! Entry point: [`worker_main`]. Called from the subprocess worker binary.
//! Bootstraps IPC from stdin, creates a KVM VM, and enters a message loop.

use std::collections::HashSet;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use kvm_ioctls::{IoEventAddress, Kvm, VcpuFd, VmFd};
use tokio::io::unix::AsyncFd;
use tokio::sync::mpsc;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use amla_core::vm_state::IRQCHIP_BLOB_SIZE;
use amla_core::{MappingHandleInfo, ValidatedMapSource, ValidatedMemoryMappings, VcpuExit};
use amla_ipc::RingBuffer;

use crate::arch::{InitialDeviceState, VcpuSnapshot, VmStateSnapshot};
use crate::error::{Result, VmmError};
use crate::shell::create_raw_vm;
use crate::vcpu::KvmVcpuRunState;

use super::{WorkerQueueSlot, WorkerRequest, WorkerResponse, WorkerTopology};

// ============================================================================
// Entry point
// ============================================================================

/// Worker process entry point. Never returns.
pub async fn worker_main() -> ! {
    // Install panic hook that prints to stderr before aborting.
    std::panic::set_hook(Box::new(|info| {
        eprintln!("[subprocess-worker] PANIC: {info}");
        let bt = std::backtrace::Backtrace::force_capture();
        eprintln!("{bt}");
    }));

    let code = match worker_run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("[subprocess-worker] FATAL: {e}");
            eprintln!(
                "[subprocess-worker] backtrace: {}",
                std::backtrace::Backtrace::force_capture()
            );
            1
        }
    };
    std::process::exit(code);
}

// ============================================================================
// Worker state
// ============================================================================

struct IoEventSlot {
    /// Wrapped in `Arc` so monitor tasks can keep the fd alive across panics:
    /// if `WorkerState` unwinds while a monitor task is mid-`readable/read`,
    /// the fd must not be closed out from under it (which would let the OS
    /// recycle the number and cause UB).
    io_eventfd: Arc<EventFd>,
    wake_idx: u8,
}

struct DeviceSlot {
    irq_eventfd: EventFd,
    /// Monitored by a spawned task, must outlive the
    /// task on the panic path.
    resample_eventfd: Arc<EventFd>,
    gsi: u32,
}

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

struct VcpuHandle {
    join_handle: Option<std::thread::JoinHandle<()>>,
    resume_tx: mpsc::Sender<Option<amla_core::VcpuResponse>>,
    preempt_state: Arc<KvmVcpuRunState>,
    run_mutex: Arc<tokio::sync::Mutex<()>>,
    bridge_abort: tokio::task::AbortHandle,
}

/// Captured state from a `SaveState` request, fetched by
/// `GetSavedVcpu` / `GetSavedIrqchip`.
struct SavedState {
    vcpu_snapshots: Vec<Vec<u8>>,
    irqchip_blob: Vec<u8>,
}

struct WorkerState {
    vm_fd: VmFd,
    // `Arc<VcpuFd>` so each vcpu thread co-owns its fd for the thread's
    // entire lifetime — the raw fd stays live until the Arc drops, matching
    // the type-enforced ownership pattern in `shell::kvm_thread_loop`.
    vcpus: smallvec::SmallVec<[Arc<VcpuFd>; 4]>,
    initial_device_state: InitialDeviceState,
    /// Owns the userspace side of each KVM ioeventfd registration for the VM
    /// lifetime. Monitor tasks hold `Arc` clones for async reads; this field
    /// keeps the registrations explicit and drops them with the VM state.
    io_event_registrations: Vec<IoEventSlot>,
    device_slots: Vec<DeviceSlot>,
    vcpu_handles: Vec<VcpuHandle>,
    /// Current sequence number per vCPU, set by `ResumeVcpu`, read by bridge tasks.
    vcpu_seqs: Arc<Vec<AtomicU64>>,
    maps: Vec<amla_mem::MmapSlice>,
    next_slot: u32,
    saved_state: Option<SavedState>,
    /// Cancels eventfd/resamplefd monitor tasks on shutdown.
    monitor_cancel: tokio_util::sync::CancellationToken,
}

/// Flush buffered console bytes as a `ConsoleOutput` message.
/// Called before VcpuExit/DeviceKick to preserve output ordering.
async fn flush_console_buf(
    buf: &Arc<parking_lot::Mutex<Vec<u8>>>,
    sender: &mut amla_ipc::Sender<'_>,
) -> Result<()> {
    let data = {
        let mut guard = buf.lock();
        if guard.is_empty() {
            return Ok(());
        }
        std::mem::take(&mut *guard)
    };
    sender
        .send(WorkerResponse::ConsoleOutput { data })
        .await
        .map_err(|e| VmmError::Config(format!("send ConsoleOutput: {e}")))?;
    Ok(())
}

// ============================================================================
// Main async loop
// ============================================================================

#[allow(clippy::too_many_lines, clippy::cast_possible_truncation)]
async fn worker_run() -> Result<()> {
    // Bootstrap: recover ring buffer from stdin.
    let mut ring =
        RingBuffer::from_child_stdin().map_err(|e| VmmError::Config(format!("bootstrap: {e}")))?;
    let (mut sender, mut receiver) = ring
        .split(false)
        .map_err(|e| VmmError::Config(format!("ring split: {e}")))?;

    log::info!("subprocess-worker started (pid={})", std::process::id());

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
            "subprocess-worker Init vcpu_count={vcpu_count} device_slots={} io_slots={}",
            topology.devices.len(),
            topology
                .devices
                .iter()
                .map(|device| device.queues.len())
                .sum::<usize>()
        );
        validate_topology(&topology)?;
        (vcpu_count, topology)
    } else {
        drop(
            sender
                .send(WorkerResponse::Error {
                    message: "expected Init".into(),
                })
                .await,
        );
        return Err(VmmError::Config("expected Init".into()));
    };

    // Create KVM VM.
    log::debug!("subprocess-worker: creating KVM VM");
    let kvm = Kvm::new().inspect_err(|e| {
        log::error!("subprocess-worker: Kvm::new() failed: {e}");
    })?;
    let kvm_run_size = kvm.get_vcpu_mmap_size()?;
    let (vm_fd, vcpus, initial_device_state) =
        create_raw_vm(&kvm, vcpu_count).inspect_err(|e| {
            log::error!("subprocess-worker: create_raw_vm failed: {e}");
        })?;
    let vcpus: smallvec::SmallVec<[Arc<VcpuFd>; 4]> = vcpus.into_iter().map(Arc::new).collect();
    log::debug!("subprocess-worker: KVM VM created, registering hardware");

    // Register hardware: ioeventfds + irqfds.
    let queue_slots: Vec<WorkerQueueSlot> = topology
        .devices
        .iter()
        .flat_map(|device| device.queues.iter().copied())
        .collect();
    let mut io_slots = Vec::with_capacity(queue_slots.len());
    for WorkerQueueSlot {
        mmio_notify_addr,
        queue_idx,
        wake_idx,
    } in &queue_slots
    {
        log::debug!(
            "subprocess-worker register ioeventfd addr={mmio_notify_addr:#x} queue={queue_idx} wake={wake_idx}"
        );
        let io_eventfd = Arc::new(EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("ioeventfd"))?);
        vm_fd
            .register_ioevent(
                &io_eventfd,
                &IoEventAddress::Mmio(*mmio_notify_addr),
                *queue_idx,
            )
            .map_err(|e| {
                let err = VmmError::SystemCall {
                    operation: "KVM_IOEVENTFD",
                    source: std::io::Error::from_raw_os_error(e.errno()),
                };
                log::error!("subprocess-worker: {err}");
                err
            })?;

        io_slots.push(IoEventSlot {
            io_eventfd,
            wake_idx: *wake_idx,
        });
    }

    let mut device_slots = Vec::with_capacity(topology.devices.len());
    for device in &topology.devices {
        let irq_eventfd = EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("irqfd"))?;
        let resample_eventfd =
            Arc::new(EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("resamplefd"))?);
        vm_fd
            .register_irqfd_with_resample(&irq_eventfd, &resample_eventfd, device.gsi)
            .inspect_err(|e| {
                log::error!(
                    "subprocess-worker: register_irqfd_with_resample gsi={} failed: {e}",
                    device.gsi
                );
            })?;

        device_slots.push(DeviceSlot {
            irq_eventfd,
            resample_eventfd,
            gsi: device.gsi,
        });
    }

    // Console output buffer — bridge tasks append UART bytes here.
    // The main loop flushes before sending VcpuExit/DeviceKick.
    let console_buf = Arc::new(parking_lot::Mutex::new(Vec::<u8>::with_capacity(256)));
    let (console_flush_tx, mut console_flush_rx) = mpsc::channel::<()>(1);

    // Merged channels for internal events.
    // Capacities = number of producers: each has at most 1 outstanding send.
    let io_slot_count = io_slots.len();
    let device_count = device_slots.len();
    let vcpu_count_usz = vcpu_count as usize;
    let (exit_tx, mut exit_rx) = mpsc::channel::<(u32, u64, VcpuExit)>(vcpu_count_usz);
    let (kick_tx, mut kick_rx) = mpsc::channel::<u8>(io_slot_count.max(1));
    let (resample_tx, mut resample_rx) = mpsc::channel::<u32>(device_count.max(1));
    let (monitor_fault_tx, mut monitor_fault_rx) = mpsc::channel::<String>(1);
    let monitor_cancel = tokio_util::sync::CancellationToken::new();

    // Spawn ioeventfd monitoring tasks.
    // Each task captures an `Arc<EventFd>` so the fd outlives the task even on
    // the panic path (where `WorkerState` unwinds concurrently with monitors).
    for slot in &io_slots {
        let eventfd = Arc::clone(&slot.io_eventfd);
        let wake_idx = slot.wake_idx;
        let kick_tx = kick_tx.clone();
        let fault_tx = monitor_fault_tx.clone();
        let cancel = monitor_cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor_eventfd(eventfd, wake_idx, kick_tx, cancel).await {
                let message = format!("ioeventfd monitor wake_idx={wake_idx} failed: {e}");
                log::error!("{message}");
                drop(fault_tx.send(message).await);
            }
        });
    }

    // Spawn resamplefd monitoring tasks.
    for slot in &device_slots {
        let eventfd = Arc::clone(&slot.resample_eventfd);
        let gsi = slot.gsi;
        let resample_tx = resample_tx.clone();
        let fault_tx = monitor_fault_tx.clone();
        let cancel = monitor_cancel.clone();
        tokio::spawn(async move {
            if let Err(e) = monitor_resamplefd(eventfd, gsi, resample_tx, cancel).await {
                let message = format!("resamplefd monitor gsi={gsi} failed: {e}");
                log::error!("{message}");
                drop(fault_tx.send(message).await);
            }
        });
    }
    drop(kick_tx);
    drop(resample_tx);
    drop(monitor_fault_tx);

    // Per-vCPU sequence numbers — shared between the main loop (writer via
    // ResumeVcpu) and bridge tasks (reader at exit-forward time).
    let vcpu_seqs: Arc<Vec<AtomicU64>> =
        Arc::new((0..vcpu_count).map(|_| AtomicU64::new(0)).collect());

    // Spawn vCPU threads + bridge tasks. Threads block on blocking_recv()
    // until the parent sends ResumeVcpu.
    let mut vcpu_handles = Vec::with_capacity(vcpu_count_usz);
    for i in 0..vcpu_count {
        let i_usz = i as usize;
        let (resume_tx, resume_rx) = mpsc::channel(1);
        let (thread_exit_tx, mut thread_exit_rx) = mpsc::channel(1);
        let thread_vcpu = Arc::clone(&vcpus[i_usz]);
        let preempt_state = Arc::new(KvmVcpuRunState::default());
        let run_mutex = Arc::new(tokio::sync::Mutex::new(()));
        let thread_state = Arc::clone(&preempt_state);
        let thread_mutex = Arc::clone(&run_mutex);

        let join_handle = std::thread::Builder::new()
            .name(format!("kvm-vcpu-{i}"))
            .spawn(move || {
                crate::shell::kvm_thread_loop(
                    thread_vcpu,
                    i_usz,
                    kvm_run_size,
                    thread_state,
                    thread_mutex,
                    resume_rx,
                    thread_exit_tx,
                );
            })
            .map_err(|e| VmmError::SystemCall {
                operation: "spawn kvm thread",
                source: std::io::Error::other(e.to_string()),
            })?;

        // Bridge: forward exits to merged channel. UART writes are
        // buffered locally as ConsoleOutput; everything else forwards.
        let exit_tx = exit_tx.clone();
        let bridge_resume_tx = resume_tx.clone();
        let bridge_console = Arc::clone(&console_buf);
        let bridge_flush = console_flush_tx.clone();
        let bridge_seqs = Arc::clone(&vcpu_seqs);
        let id = i;
        let bridge_handle = tokio::spawn(async move {
            while let Some(exit) = thread_exit_rx.recv().await {
                let (action, needs_flush) = uart_local_handle(&exit, &bridge_console);
                if needs_flush {
                    match bridge_flush.try_send(()) {
                        Ok(()) | Err(_) => {}
                    }
                }
                match action {
                    LocalExit::Response(resp) => {
                        if bridge_resume_tx.send(Some(resp)).await.is_err() {
                            break;
                        }
                    }
                    LocalExit::ReEnter => {
                        if bridge_resume_tx.send(None).await.is_err() {
                            break;
                        }
                    }
                    LocalExit::Forward => {
                        // Capture seq at forward time (not lazily in main loop)
                        // to prevent a new ResumeVcpu from overwriting it.
                        let seq = bridge_seqs
                            .get(id as usize)
                            .map_or(0, |s| s.load(Ordering::Acquire));
                        if exit_tx.send((id, seq, exit)).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });

        vcpu_handles.push(VcpuHandle {
            join_handle: Some(join_handle),
            resume_tx,
            preempt_state,
            run_mutex,
            bridge_abort: bridge_handle.abort_handle(),
        });
    }
    drop(console_flush_tx);

    sender
        .send(WorkerResponse::Ready)
        .await
        .map_err(|e| VmmError::Config(format!("send Ready: {e}")))?;

    let mut state = WorkerState {
        vm_fd,
        vcpus,
        initial_device_state,
        io_event_registrations: io_slots,
        device_slots,
        vcpu_handles,
        vcpu_seqs,
        maps: Vec::new(),
        next_slot: 0,
        saved_state: None,
        monitor_cancel,
    };

    // Main select loop.
    loop {
        tokio::select! {
            biased;

            Some((id, seq, exit)) = exit_rx.recv() => {
                log::trace!("worker: vcpu exit id={id} seq={seq} exit={exit:?}");
                flush_console_buf(&console_buf, &mut sender).await?;
                sender.send(WorkerResponse::VcpuExit { id, seq, exit }).await
                    .map_err(|e| VmmError::Config(format!("send VcpuExit: {e}")))?;
            }
            Some(idx) = kick_rx.recv() => {
                log::trace!("worker: ioeventfd kick idx={idx}");
                flush_console_buf(&console_buf, &mut sender).await?;
                sender.send(WorkerResponse::DeviceKick { wake_idx: idx }).await
                    .map_err(|e| VmmError::Config(format!("send DeviceKick: {e}")))?;
            }
            Some(gsi) = resample_rx.recv() => {
                log::trace!("worker: resamplefd gsi={gsi}");
                sender.send(WorkerResponse::IrqResample { gsi }).await
                    .map_err(|e| VmmError::Config(format!("send IrqResample: {e}")))?;
            }
            Some(()) = console_flush_rx.recv() => {
                log::trace!("worker: console flush");
                flush_console_buf(&console_buf, &mut sender).await?;
            }
            Some(message) = monitor_fault_rx.recv() => {
                drop(sender.send(WorkerResponse::Error {
                    message: message.clone(),
                }).await);
                return Err(VmmError::Config(message));
            }
            req = receiver.recv::<WorkerRequest>() => {
                let req = req.map_err(|e| VmmError::Config(format!("recv: {e}")))?;
                log::trace!("worker: recv request {req:?}");
                match Box::pin(handle_request(req, &mut sender, &mut state)).await {
                    Ok(true) => return Ok(()),
                    Ok(false) => {} // Continue
                    Err(e) => {
                        log::error!("request handler error: {e}");
                        drop(sender.send(WorkerResponse::Error {
                            message: e.to_string(),
                        }).await);
                    }
                }
            }
        }
    }
}

// ============================================================================
// Request handler
// ============================================================================

/// Handle a request. Returns Ok(true) on Shutdown.
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
                    message: "duplicate Init".into(),
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
            let vcpu_count = validate_save_vcpu_count(vcpu_count, state.vcpus.len())?;

            // Lock all vCPU mutexes for atomic capture.
            let mut guards = Vec::with_capacity(state.vcpu_handles.len());
            for handle in &state.vcpu_handles {
                guards.push(handle.run_mutex.lock().await);
            }

            // Capture vCPU snapshots as bytes.
            let mut vcpu_snapshots = Vec::with_capacity(vcpu_count);
            for vcpu_fd in state.vcpus.iter().take(vcpu_count) {
                let snap = VcpuSnapshot::capture(vcpu_fd)?;
                vcpu_snapshots.push(bytemuck::bytes_of(&snap).to_vec());
            }

            // Capture irqchip.
            let vm_snap = VmStateSnapshot::capture(
                &state.vm_fd,
                &state.initial_device_state,
                state.vcpus.len(),
            )?;
            let mut blob_buf = vec![0u8; IRQCHIP_BLOB_SIZE];
            let blob_len = vm_snap.write_arch_blob(&mut blob_buf);
            blob_buf.truncate(blob_len);

            state.saved_state = Some(SavedState {
                vcpu_snapshots,
                irqchip_blob: blob_buf,
            });
            // guards dropped here — mutexes released.

            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::GetSavedVcpu { id } => {
            let saved = state.saved_state.as_ref().ok_or(VmmError::InvalidState {
                expected: "saved state present",
                actual: "no saved state",
            })?;
            let data = saved
                .vcpu_snapshots
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
            let saved = state.saved_state.take().ok_or(VmmError::InvalidState {
                expected: "saved state present",
                actual: "no saved state",
            })?;
            sender
                .send(WorkerResponse::StateData {
                    data: saved.irqchip_blob,
                })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::CaptureDefaultIrqchip => {
            let vm_snap = VmStateSnapshot::capture(
                &state.vm_fd,
                &state.initial_device_state,
                state.vcpus.len(),
            )?;
            let mut buf = vec![0u8; IRQCHIP_BLOB_SIZE];
            let written = vm_snap.write_boot_arch_blob(&mut buf);
            buf.truncate(written);
            sender
                .send(WorkerResponse::StateData { data: buf })
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::RestoreVcpu { id, data } => {
            let snap: &VcpuSnapshot = bytemuck::try_from_bytes(&data)
                .map_err(|e| VmmError::Config(format!("invalid vcpu snapshot: {e}")))?;
            snap.validate()?;
            snap.restore(state.vcpus.get(id as usize).ok_or(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            })?)?;
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::RestoreIrqchip { blob } => {
            if blob.is_empty() {
                return Err(VmmError::InvalidState {
                    expected: "non-empty irqchip arch blob",
                    actual: "empty irqchip arch blob",
                });
            }
            let vm_snap = VmStateSnapshot::from_arch_blob(&blob)?;
            #[cfg(target_arch = "aarch64")]
            vm_snap.validate_vcpu_count(state.vcpus.len())?;
            vm_snap.restore(&state.vm_fd, None, &state.initial_device_state)?;
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
        }

        WorkerRequest::ResumeVcpu { id, seq, response } => {
            let idx = id as usize;
            let handle = state.vcpu_handles.get(idx).ok_or(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            })?;
            if let Some(s) = state.vcpu_seqs.get(idx) {
                s.store(seq, Ordering::Release);
            }
            handle
                .resume_tx
                .send(response)
                .await
                .map_err(|_| VmmError::Config("vcpu thread exited".into()))?;
        }

        WorkerRequest::Preempt { id } => {
            if let Some(handle) = state.vcpu_handles.get(id as usize) {
                handle.preempt_state.request_preempt();
            }
        }

        WorkerRequest::IrqLine { gsi, level } => {
            if level {
                for slot in &state.device_slots {
                    if slot.gsi == gsi {
                        write_eventfd(slot.irq_eventfd.as_raw_fd());
                        break;
                    }
                }
            }
        }

        WorkerRequest::Shutdown => {
            log::trace!(
                "worker shutdown: closing {} ioeventfd registrations",
                state.io_event_registrations.len()
            );
            // Abort bridge tasks first — they hold clones of resume_tx,
            // which would prevent channel closure.
            for handle in &state.vcpu_handles {
                handle.bridge_abort.abort();
            }
            // Close resume channels so vCPU threads' blocking_recv returns None.
            for handle in &mut state.vcpu_handles {
                let (dead_tx, _) = mpsc::channel(1);
                drop(std::mem::replace(&mut handle.resume_tx, dead_tx));
            }
            // Preempt any vCPU threads still in KVM_RUN.
            for handle in &state.vcpu_handles {
                handle.preempt_state.request_preempt();
            }
            // Join all vCPU threads before tearing down the runtime.
            for handle in &mut state.vcpu_handles {
                if let Some(jh) = handle.join_handle.take() {
                    drop(jh.join());
                }
            }
            // Cancel monitor tasks so they release eventfds before WorkerState drops.
            state.monitor_cancel.cancel();
            state.maps.clear();
            sender
                .send(WorkerResponse::Ok)
                .await
                .map_err(|e| VmmError::Config(format!("send: {e}")))?;
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
// MapMemory handler
// ============================================================================

fn handle_map_memory(
    state: &mut WorkerState,
    handles: &[amla_mem::MemHandle],
    mappings: &[amla_core::MemoryMapping],
) -> Result<()> {
    let handle_info: Vec<_> = handles.iter().map(MappingHandleInfo::from).collect();
    let mappings = ValidatedMemoryMappings::new(mappings, &handle_info)
        .map_err(|e| VmmError::Config(e.to_string()))?;
    let mapping_count = u32::try_from(mappings.len())
        .map_err(|_| VmmError::Config(format!("too many mappings: {}", mappings.len())))?;
    state
        .next_slot
        .checked_add(mapping_count)
        .ok_or_else(|| VmmError::Config("KVM memslot index overflow".into()))?;

    let handle_maps: Vec<amla_mem::MmapSlice> = handles
        .iter()
        .map(|h| amla_mem::map_handle(h).map_err(VmmError::from))
        .collect::<Result<_>>()?;

    let mut leaked_maps: Vec<amla_mem::MmapSlice> = Vec::new();
    let first_slot = state.next_slot;

    let result = (|| {
        for m in mappings.entries() {
            let (host_ptr, extra) = match m.source() {
                ValidatedMapSource::Handle {
                    index,
                    offset,
                    offset_usize,
                } => {
                    let region = handle_maps.get(index).ok_or_else(|| {
                        VmmError::Config(format!("handle_maps index {index} out of range"))
                    })?;
                    // SAFETY: the validated mapping token checked index,
                    // offset, size, handle bounds, and writable capability.
                    let ptr = unsafe { region.offset_mut_ptr(offset_usize) }.ok_or_else(|| {
                        VmmError::Config(format!(
                            "handle offset {offset:#x} out of bounds for mapping at GPA {:#x}",
                            m.gpa()
                        ))
                    })?;
                    (ptr.as_ptr(), None)
                }
                ValidatedMapSource::AnonymousZero => {
                    let zero = amla_mem::MmapSlice::anonymous(m.size_usize())?;
                    let p = zero.as_ptr().cast_mut();
                    (p, Some(zero))
                }
            };

            let flags = if m.readonly() {
                kvm_bindings::KVM_MEM_READONLY
            } else {
                0
            };
            let slot = state.next_slot;
            state.next_slot = state
                .next_slot
                .checked_add(1)
                .ok_or_else(|| VmmError::Config("KVM memslot index overflow".into()))?;
            let userspace_addr = u64::try_from(host_ptr.addr()).map_err(|_| {
                VmmError::Config("host pointer does not fit in KVM userspace_addr".into())
            })?;
            let region = kvm_bindings::kvm_userspace_memory_region {
                slot,
                flags,
                guest_phys_addr: m.gpa(),
                memory_size: m.size(),
                userspace_addr,
            };
            // SAFETY: `region` describes a host userspace range backed by
            // `handle_maps` / `leaked_maps`, which are stored in `state.maps`
            // (or the error path unregisters the slot below) and outlive the
            // KVM vm_fd.
            unsafe {
                state.vm_fd.set_user_memory_region(region)?;
            }

            if let Some(z) = extra {
                leaked_maps.push(z);
            }
        }
        Ok(())
    })();

    if result.is_err() {
        // Unregister any KVM slots we already registered so they don't
        // reference memory that is about to be dropped.
        for slot in first_slot..state.next_slot {
            let empty = kvm_bindings::kvm_userspace_memory_region {
                slot,
                flags: 0,
                guest_phys_addr: 0,
                memory_size: 0,
                userspace_addr: 0,
            };
            // SAFETY: `empty` is a zero-slot region that removes the binding;
            // vm_fd is owned by this process.
            match unsafe { state.vm_fd.set_user_memory_region(empty) } {
                Ok(()) | Err(_) => {}
            }
        }
        state.next_slot = first_slot;
    } else {
        state.maps.extend(handle_maps);
        state.maps.extend(leaked_maps);
    }

    result
}

// ============================================================================
// Worker-local PL011 + Halt handling (avoids IPC round-trip)
// ============================================================================

/// PL011 UART constants (ARM64 earlycon).
#[cfg(target_arch = "aarch64")]
const PL011_BASE: u64 = 0x0900_0000;
#[cfg(target_arch = "aarch64")]
const PL011_END: u64 = PL011_BASE + 0x1000;

/// `x86_64` serial port (COM1).
#[cfg(target_arch = "x86_64")]
const SERIAL_PORT: u16 = 0x3F8;

enum LocalExit {
    Response(amla_core::VcpuResponse),
    ReEnter,
    Forward,
}

/// Handle UART and Halt exits locally in the worker, avoiding IPC
/// round-trips. UART data bytes are appended to the shared console buffer.
/// Returns true if the buffer needs flushing (hit capacity).
fn uart_local_handle(
    exit: &VcpuExit,
    console_buf: &parking_lot::Mutex<Vec<u8>>,
) -> (LocalExit, bool) {
    match exit {
        // ── ARM64: PL011 UART ──────────────────────────────────────
        #[cfg(target_arch = "aarch64")]
        VcpuExit::MmioRead { addr, size } if (*addr >= PL011_BASE && *addr < PL011_END) => {
            let data = match addr - PL011_BASE {
                0x018 => (1 << 7) | (1 << 4), // UARTFR: TX empty + RX empty
                0x030 => 0x301,               // UARTCR: enabled, TX enabled
                _ => 0,
            };
            (
                LocalExit::Response(amla_core::VcpuResponse::Mmio { data, size: *size }),
                false,
            )
        }
        #[cfg(target_arch = "aarch64")]
        VcpuExit::MmioWrite { addr, data, .. } if (*addr >= PL011_BASE && *addr < PL011_END) => {
            let needs_flush = if addr - PL011_BASE == 0x000 {
                let mut buf = console_buf.lock();
                buf.push((*data & 0xFF) as u8);
                buf.len() >= 256
            } else {
                false
            };
            (LocalExit::ReEnter, needs_flush)
        }

        // ── x86_64: COM1 serial port ──────────────────────────────
        #[cfg(target_arch = "x86_64")]
        VcpuExit::IoIn { port, size } if (*port >= SERIAL_PORT && *port < SERIAL_PORT + 8) => {
            let data = if *port == SERIAL_PORT + 5 { 0x60u32 } else { 0 };
            (
                LocalExit::Response(amla_core::VcpuResponse::Pio { data, size: *size }),
                false,
            )
        }
        #[cfg(target_arch = "x86_64")]
        VcpuExit::IoOut { port, data, size } if (*port == SERIAL_PORT && *size == 1) => {
            let mut buf = console_buf.lock();
            buf.push((*data & 0xFF) as u8);
            let needs_flush = buf.len() >= 256;
            (LocalExit::ReEnter, needs_flush)
        }

        _ => (LocalExit::Forward, false),
    }
}

// ============================================================================
// Eventfd monitoring tasks
// ============================================================================

/// Wrapper that owns an `Arc<EventFd>` and forwards `AsRawFd` so it can be
/// plugged into `tokio::io::unix::AsyncFd`. Holding the `Arc` inside the task
/// guarantees the fd stays open for the entire lifetime of the monitor — even
/// if `WorkerState` unwinds on a panic before the cancellation token fires.
struct EventFdHolder(Arc<EventFd>);
impl AsRawFd for EventFdHolder {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

async fn monitor_eventfd(
    eventfd: Arc<EventFd>,
    idx: u8,
    tx: mpsc::Sender<u8>,
    cancel: tokio_util::sync::CancellationToken,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let afd = AsyncFd::new(EventFdHolder(eventfd))?;
    loop {
        tokio::select! {
            result = afd.readable() => {
                let mut guard = result?;
                guard.clear_ready();
                match afd.get_ref().0.read() {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        log::warn!("eventfd {idx} read error: {e}");
                        break Err(Box::new(e));
                    }
                }
                if tx.send(idx).await.is_err() {
                    break Ok(());
                }
            }
            () = cancel.cancelled() => break Ok(()),
        }
    }
}

async fn monitor_resamplefd(
    eventfd: Arc<EventFd>,
    gsi: u32,
    tx: mpsc::Sender<u32>,
    cancel: tokio_util::sync::CancellationToken,
) -> std::result::Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let afd = AsyncFd::new(EventFdHolder(eventfd))?;
    loop {
        tokio::select! {
            result = afd.readable() => {
                let mut guard = result?;
                guard.clear_ready();
                match afd.get_ref().0.read() {
                    Ok(_) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
                    Err(e) => {
                        log::warn!("resamplefd gsi={gsi} read error: {e}");
                        break Err(Box::new(e));
                    }
                }
                if tx.send(gsi).await.is_err() {
                    break Ok(());
                }
            }
            () = cancel.cancelled() => break Ok(()),
        }
    }
}

fn write_eventfd(fd: i32) {
    // SAFETY: fd is a valid eventfd from the KVM worker, outlives this call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    if let Err(e) = rustix::io::write(borrowed, &1u64.to_ne_bytes()) {
        log::warn!("write_eventfd fd={fd}: {e}");
    }
}
