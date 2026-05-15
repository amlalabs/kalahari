// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Per-vCPU OS thread running the HVF execution loop.
//!
//! Each vCPU is permanently bound to the OS thread that creates it (HVF
//! thread-affinity requirement). This module provides the thread loop and
//! the types for cross-thread communication.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use nonmax::NonMaxU64;

use amla_core::{VcpuExit, VcpuResponse};
use parking_lot::{Condvar, Mutex};
use tokio::sync::{mpsc, oneshot};

use crate::ffi;

use super::gic;
use super::state::HvfVcpuSnapshot;

// ============================================================================
// AArch64 architectural constants
// ============================================================================

/// Initial CPSR/PSTATE for a vCPU entering the kernel at EL1.
///
/// Bit layout (`AArch64` PSTATE):
/// - `M[3:0] = 0b0101` — `EL1h` (EL1 using `SP_EL1`, not `SP_EL0`).
/// - `F (bit 6) = 1`  — FIQ masked.
/// - `I (bit 7) = 1`  — IRQ masked.
/// - `A (bit 8) = 1`  — `SError` masked.
/// - `D (bit 9) = 1`  — Debug exceptions masked.
///
/// All four DAIF bits are set so the kernel enters with a clean, fully
/// masked exception state and unmasks interrupts itself once its vector
/// table and exception handlers are wired up. Matches VZ's `CPU_ON` sequence.
const PSTATE_EL1H_DAIF_MASKED: u64 = 0x3C5;

const SYS_MDRAR_EL1: u32 = sys_reg(2, 0, 1, 0, 0);
const SYS_OSLAR_EL1: u32 = sys_reg(2, 0, 1, 0, 4);
const SYS_OSLSR_EL1: u32 = sys_reg(2, 0, 1, 1, 4);
const SYS_OSDLR_EL1: u32 = sys_reg(2, 0, 1, 3, 4);
const SYS_DBGPRCR_EL1: u32 = sys_reg(2, 0, 1, 4, 4);
const SYS_DBGCLAIMSET_EL1: u32 = sys_reg(2, 0, 7, 8, 6);
const SYS_DBGCLAIMCLR_EL1: u32 = sys_reg(2, 0, 7, 9, 6);
const SYS_DBGAUTHSTATUS_EL1: u32 = sys_reg(2, 0, 7, 14, 6);

const OSLSR_EL1_OSLM_IMPLEMENTED: u64 = 1 << 3;

const fn sys_reg(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

fn hvf_debug_sysreg_read_value(encoding: u32) -> Option<u64> {
    match encoding {
        // Match KVM's virtual debug surface closely enough for Linux boot:
        // debug/OS-lock registers are present but not backed by hardware
        // debug state in the guest, so most are RAZ/WI.
        SYS_MDRAR_EL1
        | SYS_OSLAR_EL1
        | SYS_OSDLR_EL1
        | SYS_DBGPRCR_EL1
        | SYS_DBGCLAIMSET_EL1
        | SYS_DBGCLAIMCLR_EL1
        | SYS_DBGAUTHSTATUS_EL1 => Some(0),
        SYS_OSLSR_EL1 => Some(OSLSR_EL1_OSLM_IMPLEMENTED),
        _ => None,
    }
}

// ============================================================================
// Channel types
// ============================================================================

/// Captured vCPU register state.
pub(crate) struct CapturedVcpuState {
    pub snapshot: HvfVcpuSnapshot,
}

/// Command sent from the worker bridge to a vCPU thread.
pub(crate) enum VcpuCommand {
    /// Resume execution with an optional response from the VMM.
    Resume(Option<VcpuResponse>),
    /// Capture register state + per-vCPU GIC state (dispatched to owning thread).
    CaptureState(tokio::sync::oneshot::Sender<crate::error::Result<CapturedVcpuState>>),
    /// Restore register state + per-vCPU GIC state (dispatched to owning thread).
    RestoreState(
        Box<CapturedVcpuState>,
        tokio::sync::oneshot::Sender<crate::error::Result<()>>,
    ),
}

/// Event sent from a vCPU thread back to the worker bridge.
pub(crate) enum VcpuEvent {
    /// vCPU exited — needs VMM handling.
    Exit(VcpuExit),
    /// Guest kicked a device queue (MMIO write to notify register).
    DeviceKick(u8),
}

struct StartupNotifier {
    index: usize,
    tx: Option<oneshot::Sender<crate::error::Result<()>>>,
}

impl StartupNotifier {
    fn new(index: usize, tx: oneshot::Sender<crate::error::Result<()>>) -> Self {
        Self {
            index,
            tx: Some(tx),
        }
    }

    fn ready(&mut self) {
        if let Some(tx) = self.tx.take() {
            drop(tx.send(Ok(())));
        }
    }

    fn fail(&mut self, error: crate::error::VmmError) {
        if let Some(tx) = self.tx.take() {
            drop(tx.send(Err(error)));
        }
    }
}

impl Drop for StartupNotifier {
    fn drop(&mut self) {
        if let Some(tx) = self.tx.take() {
            drop(tx.send(Err(crate::error::VmmError::WorkerDead(format!(
                "vCPU thread {} exited before startup completed",
                self.index
            )))));
        }
    }
}

/// Send a vCPU event upstream, logging at debug if the merged-channel
/// receiver has already been dropped (worker shutting down). This is the
/// only sink for vCPU exit events, so we can't propagate the failure —
/// but we surface it in the log instead of swallowing silently.
fn notify_vcpu_event(
    merged_tx: &mpsc::Sender<(u32, VcpuEvent)>,
    vcpu_id: u32,
    index: usize,
    event: VcpuEvent,
) {
    if let Err(e) = merged_tx.blocking_send((vcpu_id, event)) {
        log::debug!("hvf-vcpu-{index}: merged_tx receiver dropped, event lost: {e}");
    }
}

// ============================================================================
// WFI wake
// ============================================================================

/// Shared state for waking a vCPU thread from WFI sleep.
///
/// The vCPU thread sleeps on the condvar with a vtimer-derived timeout
/// when the guest executes WFI. IRQ injection and preemption wake it
/// by setting the flag and notifying the condvar.
pub(crate) struct WfiWake {
    wake: Mutex<bool>,
    condvar: Condvar,
}

impl WfiWake {
    fn new() -> Self {
        Self {
            wake: Mutex::new(false),
            condvar: Condvar::new(),
        }
    }

    /// Wake the vCPU thread from WFI sleep (called from any thread).
    pub fn notify(&self) {
        *self.wake.lock() = true;
        self.condvar.notify_one();
    }

    /// Sleep until woken or timeout expires. Returns immediately if
    /// already woken. Resets the wake flag before returning.
    fn wait(&self, timeout: Duration) {
        let mut guard = self.wake.lock();
        if !*guard {
            self.condvar.wait_for(&mut guard, timeout);
        }
        *guard = false;
    }
}

/// A valid HVF vCPU handle (guaranteed not `u64::MAX`).
pub(crate) type VcpuHandle = NonMaxU64;

/// Atomic storage for `Option<VcpuHandle>`.
///
/// Uses `u64::MAX` as the niche value (None) internally, matching
/// `NonMaxU64`'s invariant. This lets us do lock-free load/store
/// while exposing `Option<VcpuHandle>` at the API boundary.
pub(crate) struct AtomicVcpuHandle(AtomicU64);

impl AtomicVcpuHandle {
    fn new() -> Self {
        Self(AtomicU64::new(u64::MAX))
    }

    pub fn load(&self) -> Option<VcpuHandle> {
        NonMaxU64::new(self.0.load(Ordering::Acquire))
    }

    fn store(&self, handle: Option<VcpuHandle>) {
        let raw = handle.map_or(u64::MAX, |h| h.get());
        self.0.store(raw, Ordering::Release);
    }
}

// ============================================================================
// Watchdog
// ============================================================================

/// Shared state driving the persistent per-vCPU watchdog thread.
///
/// The vCPU thread flips `run_start` to `Some(generation)` right before
/// entering `hv_vcpu_run` and back to `None` once it returns. The watchdog
/// waits on the condvar for `run_start` to become `Some`, sleeps for the
/// configured timeout, then re-checks: if the same generation is still in
/// flight, it forces the vCPU out via `hv_vcpus_exit` (and asserts the
/// preempt flag so the vCPU loop reports `Interrupted`).
///
/// `shutdown` tells the watchdog to exit cleanly during vCPU teardown.
struct WatchdogState {
    inner: Mutex<WatchdogInner>,
    condvar: Condvar,
}

struct WatchdogInner {
    /// Monotonic generation of the current `hv_vcpu_run` (None = idle).
    run_start: Option<u64>,
    shutdown: bool,
}

impl WatchdogState {
    fn new() -> Self {
        Self {
            inner: Mutex::new(WatchdogInner {
                run_start: None,
                shutdown: false,
            }),
            condvar: Condvar::new(),
        }
    }
}

// ============================================================================
// Thread handle
// ============================================================================

/// Handle to a spawned vCPU thread.
pub(crate) struct VcpuThreadHandle {
    pub join_handle: Option<std::thread::JoinHandle<()>>,
    pub cmd_tx: mpsc::Sender<VcpuCommand>,
    /// Stored vCPU handle for cross-thread preemption via `hv_vcpus_exit`.
    pub vcpu_handle: Arc<AtomicVcpuHandle>,
    pub preempt_flag: Arc<AtomicBool>,
    /// Wake handle for interrupting WFI sleep from other threads.
    pub wfi_wake: Arc<WfiWake>,
}

// ============================================================================
// Spawn
// ============================================================================

/// Spawn a vCPU thread. Returns the handle for communication.
///
/// `merged_tx` is a sender to a shared channel; the vCPU thread sends
/// `(index, event)` tuples directly, eliminating per-vCPU receivers and
/// busy-poll bridging.
pub(crate) fn spawn_vcpu_thread(
    index: usize,
    gic: Arc<gic::GicV3>,
    notify_map: Arc<HashMap<(u64, u32), u8>>,
    merged_tx: mpsc::Sender<(u32, VcpuEvent)>,
) -> crate::error::Result<(
    VcpuThreadHandle,
    oneshot::Receiver<crate::error::Result<()>>,
)> {
    let (cmd_tx, cmd_rx) = mpsc::channel(2);
    let (startup_tx, startup_rx) = oneshot::channel();
    let vcpu_handle = Arc::new(AtomicVcpuHandle::new());
    let preempt_flag = Arc::new(AtomicBool::new(false));
    let wfi_wake = Arc::new(WfiWake::new());

    let thread_handle = Arc::clone(&vcpu_handle);
    let thread_preempt = Arc::clone(&preempt_flag);
    let thread_wfi = Arc::clone(&wfi_wake);

    let join_handle = std::thread::Builder::new()
        .name(format!("hvf-vcpu-{index}"))
        .spawn(move || {
            hvf_thread_loop(
                index,
                gic,
                thread_handle,
                thread_preempt,
                thread_wfi,
                cmd_rx,
                merged_tx,
                notify_map,
                startup_tx,
            );
        })
        .map_err(|e| crate::error::VmmError::SystemCall {
            operation: "spawn hvf thread",
            source: std::io::Error::other(e.to_string()),
        })?;

    Ok((
        VcpuThreadHandle {
            join_handle: Some(join_handle),
            cmd_tx,
            vcpu_handle,
            preempt_flag,
            wfi_wake,
        },
        startup_rx,
    ))
}

// ============================================================================
// Thread loop
// ============================================================================

/// The vCPU thread loop. Called on a dedicated OS thread.
///
/// Creates the vCPU (thread-affine), enters a command loop, and destroys
/// the vCPU on exit. Events are sent directly to the merged channel as
/// `(vcpu_index, event)` tuples.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    clippy::needless_pass_by_value
)]
fn hvf_thread_loop(
    index: usize,
    gic: Arc<gic::GicV3>,
    vcpu_handle_store: Arc<AtomicVcpuHandle>,
    preempt_flag: Arc<AtomicBool>,
    wfi_wake: Arc<WfiWake>,
    mut cmd_rx: mpsc::Receiver<VcpuCommand>,
    merged_tx: mpsc::Sender<(u32, VcpuEvent)>,
    notify_map: Arc<HashMap<(u64, u32), u8>>,
    startup_tx: oneshot::Sender<crate::error::Result<()>>,
) {
    let mut startup = StartupNotifier::new(index, startup_tx);

    #[allow(clippy::cast_possible_truncation)]
    let vcpu_id = index as u32;

    // Defensive guard: MPIDR encoding below only fills Aff0 ([7:0]), so
    // index >= 256 would collide on MPIDR with another vCPU. HVF's practical
    // vCPU max is ~16, so this is a never-observed safety net; aborting the
    // thread early causes the parent to see no Ready/Exit and fall through
    // normally.
    if index >= 256 {
        let err = crate::error::VmmError::Config(
            "MPIDR encoding only supports Aff0 (index < 256)".into(),
        );
        log::error!("hvf-vcpu-{index}: {err}");
        startup.fail(err);
        return;
    }

    let mut gic_vcpu = match gic.claim_vcpu_interface(index) {
        Ok(token) => token,
        Err(e) => {
            let err = crate::error::VmmError::Config(format!(
                "failed to claim GIC CPU-interface for vCPU {index}: {e}"
            ));
            log::error!("hvf-vcpu-{index}: {err}");
            startup.fail(err);
            return;
        }
    };

    // Step 1: Set QoS to prevent E-core scheduling stalls.
    // VZ uses THREAD_TIME_CONSTRAINT_POLICY (RT priority 37) but that causes
    // priority inversion under multi-VM load: RT vCPU threads starve the
    // normal-priority host tokio threads that process MMIO round-trips.
    // QOS_CLASS_USER_INTERACTIVE keeps vCPUs on P-cores without starving I/O.
    #[cfg(target_os = "macos")]
    // SAFETY: pthread_set_qos_class_self_np takes a qos class enum value and
    // a relative priority; it has no pointer preconditions and operates on
    // the calling thread.
    unsafe {
        let qos_ret =
            libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_USER_INTERACTIVE, 0);
        if qos_ret != 0 {
            log::debug!("hvf-vcpu-{index}: pthread_set_qos_class_self_np returned {qos_ret}");
        }
    }

    // Step 2: Create vCPU with TLBI workaround (matching VZ's sequence).
    let (mut vcpu, mut exit_info_ptr) = match create_vcpu() {
        Ok(v) => v,
        Err(e) => {
            log::error!("hvf-vcpu-{index}: create failed: {e}");
            startup.fail(e);
            return;
        }
    };
    let Some(handle) = NonMaxU64::new(vcpu) else {
        let err = crate::error::VmmError::Config("hv_vcpu_create returned u64::MAX".into());
        log::error!("hvf-vcpu-{index}: {err}");
        // SAFETY: `vcpu` was created on this thread and has not been published.
        let destroy_ret = unsafe { ffi::hv_vcpu_destroy(vcpu) };
        if let Err(de) = ffi::check("hv_vcpu_destroy(startup niche rollback)", destroy_ret) {
            log::error!("hvf-vcpu-{index}: leaked vCPU after u64::MAX handle: {de}");
        }
        startup.fail(err);
        return;
    };

    if let Err(e) = configure_created_vcpu(index, vcpu) {
        log::error!("hvf-vcpu-{index}: configure failed: {e}");
        // SAFETY: `vcpu` was created on this thread and has not been published.
        let destroy_ret = unsafe { ffi::hv_vcpu_destroy(vcpu) };
        if let Err(de) = ffi::check("hv_vcpu_destroy(startup config rollback)", destroy_ret) {
            log::error!("hvf-vcpu-{index}: leaked vCPU after config failure: {de}");
        }
        startup.fail(e);
        return;
    }

    log::info!("hvf-vcpu-{index}: created (handle={vcpu:#x})");

    // Publish handle for cross-thread preemption AFTER setup is complete.
    // Before this point, load() returns None so callers skip hv_vcpus_exit,
    // but preempt_flag is still checked before every hv_vcpu_run.
    vcpu_handle_store.store(Some(handle));
    startup.ready();
    let mut vcpu_alive = true;

    // Per-vCPU state for MMIO read response application.
    let mut last_mmio_register: u32 = 0;
    let mut current_vtimer_offset: u64 = 0;
    // Deferred vtimer offset adjustment — set by RestoreState, consumed on
    // the next Resume right before hv_vcpu_run so the guest clock doesn't
    // jump forward by the delay between restore and run.
    let mut pending_vtimer: Option<super::state::VtimerAdjust> = None;
    // PSCI power state: 0=running, 1=stopped. Powered-off vCPUs have no live
    // HVF vCPU object; Resume emits CpuOff until CPU_ON recreates the handle.
    let mut powered_off = false;
    let mut exit_log_budget: u32 = 2000;
    let mut run_log_budget: u32 = 4000;
    let mut irq_state_log_budget: u32 = 128;
    let watchdog_ms = std::env::var("AMLA_HVF_WATCHDOG_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|ms| *ms > 0);

    // Spawn a single persistent watchdog thread per vCPU (only when configured).
    // Replaces the prior per-run `std::thread::spawn` that leaked threads under
    // MMIO-heavy load. The watchdog sleeps on its condvar for `run_start`, then
    // re-checks after the timeout — if the same generation is still in flight,
    // it forces the vCPU out via `hv_vcpus_exit`.
    let watchdog_state: Option<Arc<WatchdogState>> =
        watchdog_ms.map(|_| Arc::new(WatchdogState::new()));
    // Monotonic generation for the watchdog's "same run still in flight?" test.
    let mut run_generation: u64 = 0;
    let watchdog_join: Option<std::thread::JoinHandle<()>> =
        match (watchdog_ms, watchdog_state.as_ref()) {
            (Some(ms), Some(state)) => {
                let state = Arc::clone(state);
                let handle_store = Arc::clone(&vcpu_handle_store);
                let preempt_flag = Arc::clone(&preempt_flag);
                std::thread::Builder::new()
                    .name(format!("hvf-vcpu-{index}-watchdog"))
                    .spawn(move || {
                        watchdog_loop(index, ms, &state, &handle_store, &preempt_flag);
                    })
                    .ok()
            }
            _ => None,
        };

    // Step 4: Command loop.
    while let Some(cmd) = cmd_rx.blocking_recv() {
        match cmd {
            VcpuCommand::Resume(response) => {
                log::debug!(
                    "hvf-vcpu-{index}: Resume command (response={:?})",
                    response.as_ref().map(std::mem::discriminant)
                );
                // CpuOnBoot transitions the vCPU from stopped to running.
                if let Some(VcpuResponse::CpuOnBoot {
                    entry_point,
                    context_id,
                }) = &response
                {
                    gic.reset_vcpu(&mut gic_vcpu);
                    if !vcpu_alive
                        && let Err(e) = create_vcpu_for_cpu_on(
                            index,
                            &mut vcpu,
                            &mut exit_info_ptr,
                            &vcpu_handle_store,
                            &mut vcpu_alive,
                            current_vtimer_offset,
                        )
                    {
                        log::warn!("hvf-vcpu-{index}: CPU_ON create failed: {e}");
                        notify_vcpu_event(
                            &merged_tx,
                            vcpu_id,
                            index,
                            VcpuEvent::Exit(VcpuExit::Unrecoverable),
                        );
                        continue;
                    }
                    powered_off = false;
                    log::info!(
                        "hvf-vcpu-{index}: CPU_ON boot received: entry={entry_point:#x} ctx={context_id:#x}"
                    );
                }

                // Stopped vCPUs report CpuOff — the VMM waits for a
                // CPU_ON before resuming them. Using CpuOff (not Halt)
                // lets the VMM distinguish "powered off" from "WFI idle"
                // without fragile heuristics that break across save/restore.
                if powered_off {
                    log::debug!("hvf-vcpu-{index}: powered_off — re-emitting CpuOff exit");
                    notify_vcpu_event(
                        &merged_tx,
                        vcpu_id,
                        index,
                        VcpuEvent::Exit(VcpuExit::CpuOff),
                    );
                    continue;
                }
                if !vcpu_alive {
                    log::warn!("hvf-vcpu-{index}: runnable vCPU missing");
                    notify_vcpu_event(
                        &merged_tx,
                        vcpu_id,
                        index,
                        VcpuEvent::Exit(VcpuExit::Unrecoverable),
                    );
                    continue;
                }

                // Apply the VMM's response to vCPU registers.
                if let Some(resp) = response
                    // SAFETY: `vcpu` is owned by this thread per HVF
                    // thread-affinity.
                    && let Err(e) = unsafe { apply_response(vcpu, resp, last_mmio_register) }
                {
                    log::warn!("hvf-vcpu-{index}: apply_response failed: {e}");
                    notify_vcpu_event(
                        &merged_tx,
                        vcpu_id,
                        index,
                        VcpuEvent::Exit(VcpuExit::Unrecoverable),
                    );
                    continue;
                }

                // Apply deferred vtimer offset right before entering the guest.
                if let Some(adjust) = pending_vtimer.take()
                    // SAFETY: `vcpu` is owned by this thread per HVF
                    // thread-affinity.
                    && let Err(e) = unsafe { adjust.apply(vcpu) }
                {
                    log::warn!("hvf-vcpu-{index}: vtimer adjust failed: {e}");
                    notify_vcpu_event(
                        &merged_tx,
                        vcpu_id,
                        index,
                        VcpuEvent::Exit(VcpuExit::Unrecoverable),
                    );
                    continue;
                }

                // Run loop: may re-enter for vtimer and device kicks.
                loop {
                    if run_log_budget > 0 {
                        run_log_budget -= 1;
                        log::debug!(
                            "hvf-vcpu-{index}: runloop start preempt={}",
                            preempt_flag.load(Ordering::Acquire)
                        );
                    }

                    // Keep the userspace GIC's timer PPI aligned with the guest-visible
                    // vtimer output. When the guest clears the timer condition, re-arm
                    // HVF so the next deadline can raise a fresh VTIMER_ACTIVATED exit.
                    if run_log_budget > 0 {
                        run_log_budget -= 1;
                        log::debug!("hvf-vcpu-{index}: vtimer sync enter");
                    }
                    // SAFETY: `vcpu` is owned by this thread; timer sync only
                    // reads/writes HVF state for that thread-affine vCPU.
                    if let Err(e) = unsafe {
                        super::vtimer::sync_vtimer_irq(vcpu, &gic, index, gic::VTIMER_PPI)
                    } {
                        log::warn!("hvf-vcpu-{index}: vtimer sync failed: {e}");
                    }
                    if run_log_budget > 0 {
                        run_log_budget -= 1;
                        log::debug!("hvf-vcpu-{index}: vtimer sync done");
                    }

                    // Check preempt flag before entering.
                    if preempt_flag.swap(false, Ordering::AcqRel) {
                        notify_vcpu_event(
                            &merged_tx,
                            vcpu_id,
                            index,
                            VcpuEvent::Exit(VcpuExit::Interrupted),
                        );
                        break;
                    }

                    // Redrive the HVF IRQ input from the userspace GIC after
                    // all timer/GIC state reads and immediately before entry.
                    // HVF treats pending IRQ as vCPU input state, so this must
                    // happen late; otherwise later HVF register accesses can
                    // observe or perturb stale input state before `run`.
                    // SAFETY: `vcpu` is owned by this thread and the helper
                    // only redrives HVF IRQ input for this vCPU before entry.
                    if let Err(e) = unsafe {
                        drive_hvf_irq_from_gic(vcpu, index, &gic, &mut irq_state_log_budget)
                    } {
                        log::warn!("hvf-vcpu-{index}: IRQ redrive failed: {e}");
                        notify_vcpu_event(
                            &merged_tx,
                            vcpu_id,
                            index,
                            VcpuEvent::Exit(VcpuExit::Unrecoverable),
                        );
                        break;
                    }

                    // Enter guest. Signal the persistent watchdog (if configured)
                    // with a fresh generation so it knows we're entering a run;
                    // cleared back to None after `hv_vcpu_run` returns.
                    if let Some(state) = watchdog_state.as_ref() {
                        run_generation = run_generation.wrapping_add(1);
                        let mut inner = state.inner.lock();
                        inner.run_start = Some(run_generation);
                        state.condvar.notify_one();
                    }
                    if run_log_budget > 0 {
                        run_log_budget -= 1;
                        log::debug!("hvf-vcpu-{index}: hv_vcpu_run enter");
                    }
                    // SAFETY: `vcpu` is owned by this thread per HVF
                    // thread-affinity and has not been destroyed.
                    let ret = unsafe { ffi::hv_vcpu_run(vcpu) };
                    if let Some(state) = watchdog_state.as_ref() {
                        state.inner.lock().run_start = None;
                    }
                    if run_log_budget > 0 {
                        run_log_budget -= 1;
                        log::debug!("hvf-vcpu-{index}: hv_vcpu_run ret={ret:#010x}");
                    }

                    if ret != ffi::HV_SUCCESS {
                        // Check if this was a preemption-caused error.
                        if preempt_flag.swap(false, Ordering::AcqRel) {
                            // SAFETY: `vcpu` is owned by this thread and is no
                            // longer inside hv_vcpu_run after the failed return.
                            let pc = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_PC) }.unwrap_or(0);
                            log::warn!(
                                "hvf-vcpu-{index}: preempted hv_vcpu_run ret={ret:#010x} pc={pc:#x}"
                            );
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Interrupted),
                            );
                            break;
                        }
                        log::error!("hvf-vcpu-{index}: hv_vcpu_run failed: {ret:#010x}");
                        notify_vcpu_event(
                            &merged_tx,
                            vcpu_id,
                            index,
                            VcpuEvent::Exit(VcpuExit::Unrecoverable),
                        );
                        break;
                    }

                    // Decode exit.
                    // SAFETY: `exit_info_ptr` was returned by hv_vcpu_create
                    // paired with `vcpu` and points to HVF-managed exit info
                    // that remains valid for the vCPU's lifetime; after a
                    // successful hv_vcpu_run it holds the latest exit record.
                    let exit_info = unsafe { &*exit_info_ptr };
                    // SAFETY: `vcpu` is owned by this thread; `exit_info`
                    // was produced by the just-completed hv_vcpu_run.
                    let decoded = match unsafe { super::exit::decode_exit(vcpu, exit_info) } {
                        Ok(d) => d,
                        Err(e) => {
                            log::error!("hvf-vcpu-{index}: decode_exit failed: {e}");
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Unrecoverable),
                            );
                            break;
                        }
                    };

                    if exit_log_budget > 0 {
                        exit_log_budget -= 1;
                        // SAFETY: `vcpu` is owned by this thread and the exit
                        // has already completed.
                        let pc = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_PC) }.unwrap_or(0);
                        log::debug!(
                            "hvf-vcpu-{index}: decoded exit={:?} pc={pc:#x} reenter={} vtimer={}",
                            decoded.exit,
                            decoded.reenter,
                            decoded.vtimer_activated
                        );
                    }

                    // Store MMIO read register for response application.
                    if let Some(reg) = decoded.mmio_read_register {
                        last_mmio_register = reg;
                    }

                    if decoded.vtimer_activated {
                        log::debug!("hvf-vcpu-{index}: vtimer -> PPI {}", gic::VTIMER_PPI);
                        gic.set_private_irq_level(index, gic::VTIMER_PPI, true);
                        continue;
                    }

                    // Fix: CANCELED exit may be a spurious cancel from IRQ
                    // injection rather than a genuine preemption. Only report
                    // Interrupted if the preempt_flag was actually set.
                    if matches!(decoded.exit, VcpuExit::Interrupted) {
                        if preempt_flag.swap(false, Ordering::AcqRel) {
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Interrupted),
                            );
                            break;
                        }
                        // Spurious cancel — re-enter the guest.
                        continue;
                    }

                    if let VcpuExit::MmioRead { addr, size } = decoded.exit
                        && let Some(value) = gic.handle_mmio_read(addr, size)
                    {
                        log::debug!(
                            "hvf-vcpu-{index}: GIC MMIO read addr={addr:#x} size={size} -> {value:#x}"
                        );
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        if let Err(e) = unsafe {
                            apply_response(
                                vcpu,
                                VcpuResponse::Mmio { data: value, size },
                                last_mmio_register,
                            )
                        } {
                            log::warn!("hvf-vcpu-{index}: local GIC MMIO read failed: {e}");
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Unrecoverable),
                            );
                            break;
                        }
                        continue;
                    }

                    if let VcpuExit::SysReg {
                        encoding,
                        register,
                        is_write,
                        write_data,
                    } = decoded.exit
                        && let Some(value) = hvf_debug_sysreg_read_value(encoding)
                    {
                        if is_write {
                            log::debug!(
                                "hvf-vcpu-{index}: debug sysreg write ignored enc={encoding:#06x} val={write_data:#x}"
                            );
                            // SAFETY: `vcpu` is owned by this thread per HVF
                            // thread-affinity.
                            if let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) } {
                                log::warn!(
                                    "hvf-vcpu-{index}: advance_pc failed in debug sysreg write: {e}"
                                );
                                notify_vcpu_event(
                                    &merged_tx,
                                    vcpu_id,
                                    index,
                                    VcpuEvent::Exit(VcpuExit::Unrecoverable),
                                );
                                break;
                            }
                        } else {
                            log::debug!(
                                "hvf-vcpu-{index}: debug sysreg read enc={encoding:#06x} -> {value:#x}"
                            );
                            // SAFETY: `vcpu` is owned by this thread per HVF
                            // thread-affinity.
                            if let Err(e) = unsafe {
                                apply_response(
                                    vcpu,
                                    VcpuResponse::SysReg { value, register },
                                    last_mmio_register,
                                )
                            } {
                                log::warn!("hvf-vcpu-{index}: local debug sysreg read failed: {e}");
                                notify_vcpu_event(
                                    &merged_tx,
                                    vcpu_id,
                                    index,
                                    VcpuEvent::Exit(VcpuExit::Unrecoverable),
                                );
                                break;
                            }
                        }
                        continue;
                    }

                    if let VcpuExit::SysReg {
                        encoding,
                        register,
                        is_write,
                        write_data,
                    } = decoded.exit
                        && gic.handles_sysreg(encoding)
                    {
                        if is_write {
                            log::debug!(
                                "hvf-vcpu-{index}: GIC sysreg write enc={encoding:#06x} val={write_data:#x}"
                            );
                            gic.handle_sysreg_write(&mut gic_vcpu, encoding, write_data);
                            // SAFETY: `vcpu` is owned by this thread per HVF
                            // thread-affinity.
                            if let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) } {
                                log::warn!(
                                    "hvf-vcpu-{index}: advance_pc failed in local GIC sysreg write: {e}"
                                );
                                notify_vcpu_event(
                                    &merged_tx,
                                    vcpu_id,
                                    index,
                                    VcpuEvent::Exit(VcpuExit::Unrecoverable),
                                );
                                break;
                            }
                        } else {
                            let value = gic.handle_sysreg_read(&mut gic_vcpu, encoding);
                            log::debug!(
                                "hvf-vcpu-{index}: GIC sysreg read enc={encoding:#06x} -> {value:#x}"
                            );
                            // SAFETY: `vcpu` is owned by this thread per HVF
                            // thread-affinity.
                            if let Err(e) = unsafe {
                                apply_response(
                                    vcpu,
                                    VcpuResponse::SysReg { value, register },
                                    last_mmio_register,
                                )
                            } {
                                log::warn!("hvf-vcpu-{index}: local GIC sysreg read failed: {e}");
                                notify_vcpu_event(
                                    &merged_tx,
                                    vcpu_id,
                                    index,
                                    VcpuEvent::Exit(VcpuExit::Unrecoverable),
                                );
                                break;
                            }
                        }
                        continue;
                    }

                    // HVF does NOT auto-advance PC for data aborts or sysreg
                    // traps (unlike KVM which advances in-kernel). Advance now
                    // for all MMIO writes and sysreg writes so the VMM doesn't
                    // need to know about PC semantics. (Sysreg reads are
                    // handled inline in decode_exit with their own PC advance.)
                    if let VcpuExit::MmioWrite { addr, data, size } = decoded.exit {
                        if gic.handle_mmio_write(addr, data, size) {
                            log::debug!(
                                "hvf-vcpu-{index}: GIC MMIO write addr={addr:#x} size={size} data={data:#x}"
                            );
                            // SAFETY: `vcpu` is owned by this thread per HVF
                            // thread-affinity.
                            if let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) } {
                                log::warn!(
                                    "hvf-vcpu-{index}: advance_pc failed in local GIC MMIO write: {e}"
                                );
                                notify_vcpu_event(
                                    &merged_tx,
                                    vcpu_id,
                                    index,
                                    VcpuEvent::Exit(VcpuExit::Unrecoverable),
                                );
                                break;
                            }
                            continue;
                        }

                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        if let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) } {
                            log::warn!("hvf-vcpu-{index}: advance_pc failed in MMIO write: {e}");
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Unrecoverable),
                            );
                            break;
                        }

                        // Device kicks re-enter immediately (no parent round-trip).
                        // Virtio-mmio QueueNotify is a 32-bit queue index; the
                        // parent consumes the resulting global queue-wake bit.
                        if size == 4
                            && let Ok(queue_idx) = u32::try_from(data)
                            && let Some(&wake_idx) = notify_map.get(&(addr, queue_idx))
                        {
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::DeviceKick(wake_idx),
                            );
                            continue;
                        }
                    } else if matches!(&decoded.exit, VcpuExit::SysReg { is_write: true, .. })
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        && let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) }
                    {
                        log::warn!("hvf-vcpu-{index}: advance_pc failed in SysReg write: {e}");
                        notify_vcpu_event(
                            &merged_tx,
                            vcpu_id,
                            index,
                            VcpuEvent::Exit(VcpuExit::Unrecoverable),
                        );
                        break;
                    }

                    // Handle vtimer / PSCI / sysreg — re-enter immediately.
                    if decoded.reenter {
                        continue;
                    }

                    // WFI: sleep locally with vtimer timeout (VZ condvar pattern).
                    // No IPC round-trip — re-enter when timer fires, IRQ arrives,
                    // or preemption wakes us.
                    if matches!(decoded.exit, VcpuExit::Halt) {
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        unsafe {
                            log_irq_state(index, vcpu, "wfi-enter", &mut irq_state_log_budget);
                        }
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        //
                        // Fallback is deliberately long (1s): `wfi_wake` is
                        // notified on every IRQ assert and preempt, so a
                        // longer timeout has no correctness cost — it only
                        // prevents ~10Hz busy-wakes during fresh-boot idle
                        // windows when the vtimer isn't armed.
                        let timeout = unsafe { super::vtimer::compute_wfi_timeout(vcpu) }
                            .unwrap_or(Duration::from_secs(1));
                        log::debug!("hvf-vcpu-{index}: WFI sleep timeout={timeout:?}");
                        wfi_wake.wait(timeout);
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        unsafe {
                            log_irq_state(index, vcpu, "wfi-wake", &mut irq_state_log_budget);
                        }
                        log::debug!(
                            "hvf-vcpu-{index}: WFI wake preempt={}",
                            preempt_flag.load(Ordering::Acquire)
                        );
                        // After wake: check preempt before re-entering.
                        if preempt_flag.swap(false, Ordering::AcqRel) {
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Interrupted),
                            );
                            break;
                        }
                        // HVF traps WFI with PC still pointing at the WFI
                        // instruction. Once the worker has performed the
                        // userspace wait, retire the instruction so the guest
                        // does not re-execute the same WFI forever.
                        // SAFETY: `vcpu` is owned by this thread and is parked
                        // outside hv_vcpu_run while handling the WFI exit.
                        if let Err(e) = unsafe { super::exit::advance_pc_pub(vcpu) } {
                            log::warn!("hvf-vcpu-{index}: advance_pc failed after WFI: {e}");
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Unrecoverable),
                            );
                            break;
                        }
                        // SAFETY: `vcpu` is owned by this thread per HVF
                        // thread-affinity.
                        unsafe {
                            log_irq_state(
                                index,
                                vcpu,
                                "wfi-after-advance",
                                &mut irq_state_log_budget,
                            );
                        }
                        continue; // Re-enter hv_vcpu_run — WFI retires when IRQ pending.
                    }

                    // Track PSCI CPU_OFF so CaptureState records the correct
                    // power_state and subsequent Resumes without CpuOnBoot
                    // stay in the powered-off loop.
                    if matches!(decoded.exit, VcpuExit::CpuOff) {
                        powered_off = true;
                        if let Err(e) = destroy_powered_off_vcpu(
                            index,
                            vcpu,
                            &vcpu_handle_store,
                            &mut vcpu_alive,
                            &mut current_vtimer_offset,
                        ) {
                            log::warn!("hvf-vcpu-{index}: CPU_OFF destroy failed: {e}");
                            notify_vcpu_event(
                                &merged_tx,
                                vcpu_id,
                                index,
                                VcpuEvent::Exit(VcpuExit::Unrecoverable),
                            );
                            break;
                        }
                        log::info!(
                            "hvf-vcpu-{index}: CPU_OFF — destroyed HVF vCPU, forwarding exit"
                        );
                    } else if matches!(decoded.exit, VcpuExit::CpuOn { .. }) {
                        log::info!(
                            "hvf-vcpu-{index}: CPU_ON exit forwarded: {:?}",
                            decoded.exit
                        );
                    }

                    // Forward exit to parent.
                    notify_vcpu_event(&merged_tx, vcpu_id, index, VcpuEvent::Exit(decoded.exit));
                    break;
                }
            }

            VcpuCommand::CaptureState(reply) => {
                let result = if powered_off || !vcpu_alive {
                    Ok(CapturedVcpuState {
                        snapshot: HvfVcpuSnapshot::powered_off(current_vtimer_offset),
                    })
                } else {
                    // SAFETY: `vcpu` is owned by this thread; the vCPU is not
                    // inside hv_vcpu_run (we're between command dispatches).
                    unsafe { super::state::capture_vcpu(vcpu) }.map(|mut snapshot| {
                        current_vtimer_offset = snapshot.vtimer_offset;
                        // Encode PSCI power state (tracked in userspace, HVF has no MP_STATE).
                        snapshot.power_state = 0;
                        CapturedVcpuState { snapshot }
                    })
                };
                if reply.send(result).is_err() {
                    log::debug!("hvf-vcpu-{index}: CaptureState reply receiver dropped");
                }
            }

            VcpuCommand::RestoreState(boxed_state, reply) => {
                let state = *boxed_state;
                // Track PSCI power state — stopped vCPUs don't enter hv_vcpu_run.
                powered_off = state.snapshot.power_state != 0;
                current_vtimer_offset = state.snapshot.vtimer_offset;
                // Compute deferred vtimer adjustment BEFORE restoring registers
                // (restore_vcpu no longer sets the offset — we apply it at Resume time).
                pending_vtimer = Some(super::state::VtimerAdjust::from_snapshot(&state.snapshot));
                let result = if powered_off {
                    destroy_powered_off_vcpu(
                        index,
                        vcpu,
                        &vcpu_handle_store,
                        &mut vcpu_alive,
                        &mut current_vtimer_offset,
                    )
                } else {
                    let created = if vcpu_alive {
                        Ok(())
                    } else {
                        create_vcpu_for_cpu_on(
                            index,
                            &mut vcpu,
                            &mut exit_info_ptr,
                            &vcpu_handle_store,
                            &mut vcpu_alive,
                            current_vtimer_offset,
                        )
                    };
                    if let Err(e) = created {
                        Err(e)
                    } else {
                        // SAFETY: `vcpu` is owned by this thread and is not inside
                        // hv_vcpu_run (we're dispatching a command).
                        unsafe { super::state::restore_vcpu(vcpu, &state.snapshot) }
                    }
                };
                if reply.send(result).is_err() {
                    log::debug!("hvf-vcpu-{index}: RestoreState reply receiver dropped");
                }
            }
        }
    }
    log::debug!("hvf-vcpu-{index}: command channel closed");

    // Step 5: Destroy vCPU (on this thread, as required by HVF).
    log::debug!("hvf-vcpu-{index}: teardown begin vcpu_alive={vcpu_alive}");
    vcpu_handle_store.store(None);
    if vcpu_alive {
        // SAFETY: `vcpu` was created on this thread and is being destroyed on
        // the same thread as HVF requires; we cleared the atomic handle above
        // so cross-thread hv_vcpus_exit races are benign.
        let ret = unsafe { ffi::hv_vcpu_destroy(vcpu) };
        if let Err(e) = ffi::check("hv_vcpu_destroy(thread teardown)", ret) {
            log::error!("hvf-vcpu-{index}: hv_vcpu_destroy failed during teardown: {e}");
        }
    }

    // Signal watchdog shutdown and join, so the watchdog thread does not
    // outlive the vCPU it was kicking. The handle is already None, so any
    // in-flight wake would no-op.
    if let Some(state) = watchdog_state.as_ref() {
        let mut inner = state.inner.lock();
        inner.shutdown = true;
        inner.run_start = None;
        state.condvar.notify_one();
    }
    if let Some(handle) = watchdog_join
        && let Err(panic) = handle.join()
    {
        log::error!("hvf-vcpu-{index}: watchdog thread panicked: {panic:?}");
    }

    log::debug!("hvf-vcpu-{index}: destroyed");
}

// ============================================================================
// Helpers
// ============================================================================

/// Persistent per-vCPU watchdog loop. Single thread (spawned once when
/// `AMLA_HVF_WATCHDOG_MS` is set) that waits on `state.condvar` for the vCPU
/// thread to signal entry into `hv_vcpu_run`, then waits for `ms` and
/// re-checks: if the same generation is still in flight, forces the vCPU
/// out via `hv_vcpus_exit`. Shutdown wakes the timed wait so teardown does
/// not block for the full watchdog interval.
///
/// `vcpu_handle_store.load()` is re-read on each kick — between vCPU destroy
/// and a hypothetical next create the handle is `None`, so we just skip the
/// kick and go back to waiting.
fn watchdog_loop(
    index: usize,
    ms: u64,
    state: &Arc<WatchdogState>,
    vcpu_handle_store: &Arc<AtomicVcpuHandle>,
    preempt_flag: &Arc<AtomicBool>,
) {
    loop {
        // Wait for a run to start (or shutdown).
        let generation = {
            let mut inner = state.inner.lock();
            loop {
                if inner.shutdown {
                    return;
                }
                if let Some(g) = inner.run_start {
                    break g;
                }
                state.condvar.wait(&mut inner);
            }
        };

        // Timed wait releases the lock while sleeping. Normal exits clear
        // `run_start`; shutdown also notifies the condvar so teardown does
        // not wait for the entire watchdog interval.
        let fire = {
            let mut inner = state.inner.lock();
            if inner.shutdown {
                return;
            }
            state
                .condvar
                .wait_for(&mut inner, Duration::from_millis(ms));
            if inner.shutdown {
                return;
            }
            inner.run_start == Some(generation)
        };
        if !fire {
            continue;
        }

        // Freshly load the handle — the vCPU thread may have destroyed the
        // vCPU between the sleep start and now. If so, skip the kick.
        let Some(handle) = vcpu_handle_store.load() else {
            continue;
        };

        preempt_flag.store(true, Ordering::Release);
        // SAFETY: `hv_vcpus_exit` is documented thread-safe; `handle` was
        // loaded atomically and is still the currently-published vCPU. If
        // the vCPU thread races and tears down right now, HVF returns
        // HV_BAD_ARGUMENT which we log at debug.
        unsafe {
            let mut raw = handle.get();
            let ret = ffi::hv_vcpus_exit(&raw mut raw, 1);
            if ret == ffi::HV_BAD_ARGUMENT {
                log::debug!("hvf-vcpu-{index} watchdog: hv_vcpus_exit: handle already destroyed");
            } else if ret != ffi::HV_SUCCESS {
                log::warn!("hvf-vcpu-{index} watchdog: forced exit after {ms}ms ret={ret:#010x}");
            } else {
                log::warn!("hvf-vcpu-{index} watchdog: forced exit after {ms}ms");
            }
        }
    }
}

/// Log the architectural and HVF interrupt state for the first few interesting
/// timer/WFI transitions.
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn log_irq_state(index: usize, vcpu: ffi::hv_vcpu_t, label: &'static str, budget: &mut u32) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;

    // SAFETY: caller guarantees `vcpu` is valid on this thread.
    let pc = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_PC) }.ok();
    // SAFETY: caller guarantees `vcpu` is valid on this thread.
    let cpsr = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_CPSR) }.ok();
    let irq_masked = cpsr.map(|v| (v & (1 << 7)) != 0);
    let daif = cpsr.map(|v| (v >> 6) & 0xF);
    let mode = cpsr.map(|v| v & 0xF);
    // SAFETY: caller guarantees `vcpu` is valid on this thread.
    let vtimer_masked = unsafe { hvf_vtimer_masked(vcpu) };
    // SAFETY: caller guarantees `vcpu` is valid on this thread.
    let vtimer_asserted = unsafe { super::vtimer::is_vtimer_asserted(vcpu) }.ok();

    log::debug!(
        "hvf-vcpu-{index}: irq-state {label}: pc={pc:?} cpsr={cpsr:?} mode={mode:?} daif={daif:?} irq_masked={irq_masked:?} hv_vtimer_masked={vtimer_masked:?} vtimer_asserted={vtimer_asserted:?}"
    );
}

/// Drive HVF's pending IRQ input from the userspace GIC.
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn drive_hvf_irq_from_gic(
    vcpu: ffi::hv_vcpu_t,
    index: usize,
    gic: &gic::GicV3,
    budget: &mut u32,
) -> crate::error::Result<()> {
    let pending = gic.update_delivery_for_vcpu(index).pending;
    // SAFETY: caller guarantees `vcpu` is valid on this thread; this only
    // updates HVF's pending IRQ input for the same vCPU.
    let ret =
        unsafe { ffi::hv_vcpu_set_pending_interrupt(vcpu, ffi::HV_INTERRUPT_TYPE_IRQ, pending) };
    ffi::check("hv_vcpu_set_pending_interrupt(redrive)", ret)
        .map_err(crate::error::VmmError::from)?;

    if pending && *budget > 0 {
        *budget -= 1;
        log::debug!("hvf-vcpu-{index}: redrive IRQ before run pending=true");
    }
    Ok(())
}

/// Return HVF's host-side virtual timer mask state.
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn hvf_vtimer_masked(vcpu: ffi::hv_vcpu_t) -> Option<bool> {
    let mut masked = false;
    // SAFETY: caller guarantees `vcpu` is valid on this thread and `masked`
    // is a live out-pointer for the duration of the call.
    let ret = unsafe { ffi::hv_vcpu_get_vtimer_mask(vcpu, &raw mut masked) };
    if ret == ffi::HV_SUCCESS {
        Some(masked)
    } else {
        None
    }
}

/// Create a vCPU with config (including TLBI workaround).
/// Must be called on the thread that will own the vCPU.
fn create_vcpu() -> crate::error::Result<(ffi::hv_vcpu_t, ffi::hv_vcpu_exit_t)> {
    // SAFETY: called on the thread that will own the vCPU per the fn doc;
    // hv_vm_create has already been called during worker_run bootstrap, so
    // hv_vcpu_config_create and hv_vcpu_create are callable. Local `vcpu`
    // and `exit_info` are live output parameters; `config` is the just-
    // created config object, released after the create call.
    unsafe {
        let config = ffi::hv_vcpu_config_create();
        if config.is_null() {
            return Err(crate::error::VmmError::Config(
                "hv_vcpu_config_create returned null".into(),
            ));
        }

        // Apply TLBI workaround (VZ does this unconditionally before every
        // hv_vcpu_create). HV_UNSUPPORTED is documented on hardware without
        // the errata. Any other failure leaves the config in an undefined
        // state — proceeding would hand back a vCPU whose TLB-flush semantics
        // are silently wrong under heavy TLB pressure, so we fail hard here.
        let tlbi_ret = ffi::hv_vcpu_config_set_tlbi_workaround(config);
        if tlbi_ret != ffi::HV_UNSUPPORTED
            && let Err(e) = ffi::check("hv_vcpu_config_set_tlbi_workaround", tlbi_ret)
        {
            ffi::os_release(config);
            return Err(crate::error::VmmError::from(e));
        }

        let mut vcpu: ffi::hv_vcpu_t = 0;
        let mut exit_info: ffi::hv_vcpu_exit_t = std::ptr::null();

        let ret = ffi::hv_vcpu_create(&raw mut vcpu, &raw mut exit_info, config);
        ffi::os_release(config);
        ffi::check("hv_vcpu_create", ret).map_err(crate::error::VmmError::from)?;

        Ok((vcpu, exit_info))
    }
}

fn configure_created_vcpu(index: usize, vcpu: ffi::hv_vcpu_t) -> crate::error::Result<()> {
    // Set MPIDR_EL1 for GIC affinity routing.
    // SAFETY: `vcpu` was just created on this thread; MPIDR_EL1 is valid.
    unsafe {
        ffi::check(
            "set_mpidr",
            ffi::hv_vcpu_set_sys_reg(
                vcpu,
                ffi::HV_SYS_REG_MPIDR_EL1,
                (1u64 << 31) | (index as u64 & 0xFF),
            ),
        )
        .map_err(crate::error::VmmError::from)?;
    }

    // Mask SME bits [27:24] in ID_AA64PFR1_EL1. HVF does not support SME;
    // exposing these bits causes the guest to probe unsupported registers.
    // SAFETY: `vcpu` is owned by this thread; ID_AA64PFR1_EL1 is valid.
    unsafe {
        let mut pfr1: u64 = 0;
        if ffi::hv_vcpu_get_sys_reg(vcpu, ffi::HV_SYS_REG_ID_AA64PFR1_EL1, &raw mut pfr1)
            == ffi::HV_SUCCESS
        {
            let masked = pfr1 & !(0xF << 24);
            if masked != pfr1 {
                let ret = ffi::hv_vcpu_set_sys_reg(vcpu, ffi::HV_SYS_REG_ID_AA64PFR1_EL1, masked);
                if let Err(e) = ffi::check("hv_vcpu_set_sys_reg(ID_AA64PFR1_EL1)", ret) {
                    log::warn!("hvf-vcpu-{index}: failed to mask SME in ID_AA64PFR1_EL1: {e}");
                } else {
                    log::debug!(
                        "hvf-vcpu-{index}: masked SME in ID_AA64PFR1_EL1: {pfr1:#x} -> {masked:#x}"
                    );
                }
            }
        }
    }

    park_physical_timer(vcpu);
    Ok(())
}

fn park_physical_timer(vcpu: ffi::hv_vcpu_t) {
    // Park the EL1 physical timer so it never asserts PPI 30. Linux uses the
    // virtual timer (CNTV_*) for event delivery; leaving CNTP_CVAL at HVF's
    // default 0 can storm the physical timer PPI during secondary CPU probe.
    // SAFETY: `vcpu` is owned by this thread; encodings are valid. This is
    // defensive — older hosts may reject the writes, so we log at debug
    // (not warn) when it happens.
    unsafe {
        if let Err(e) = ffi::check(
            "hv_vcpu_set_sys_reg(CNTP_CTL_EL0)",
            ffi::hv_vcpu_set_sys_reg(vcpu, ffi::HV_SYS_REG_CNTP_CTL_EL0, 0),
        ) {
            log::debug!("park_physical_timer: CNTP_CTL_EL0 write rejected: {e}");
        }
        if let Err(e) = ffi::check(
            "hv_vcpu_set_sys_reg(CNTP_CVAL_EL0)",
            ffi::hv_vcpu_set_sys_reg(vcpu, ffi::HV_SYS_REG_CNTP_CVAL_EL0, u64::MAX),
        ) {
            log::debug!("park_physical_timer: CNTP_CVAL_EL0 write rejected: {e}");
        }
    }
}

fn destroy_powered_off_vcpu(
    index: usize,
    vcpu: ffi::hv_vcpu_t,
    vcpu_handle_store: &AtomicVcpuHandle,
    vcpu_alive: &mut bool,
    current_vtimer_offset: &mut u64,
) -> crate::error::Result<()> {
    if !*vcpu_alive {
        return Ok(());
    }

    // SAFETY: the vCPU is owned by this thread and is parked outside
    // hv_vcpu_run while handling CPU_OFF or RestoreState.
    unsafe {
        let mut vtimer_offset = 0;
        ffi::check(
            "hv_vcpu_get_vtimer_offset(power off)",
            ffi::hv_vcpu_get_vtimer_offset(vcpu, &raw mut vtimer_offset),
        )
        .map_err(crate::error::VmmError::from)?;
        *current_vtimer_offset = vtimer_offset;
    }

    vcpu_handle_store.store(None);
    // SAFETY: vCPU was created on this thread and is not running.
    unsafe {
        ffi::check("hv_vcpu_destroy(power off)", ffi::hv_vcpu_destroy(vcpu))
            .map_err(crate::error::VmmError::from)?;
    }
    *vcpu_alive = false;
    log::info!("hvf-vcpu-{index}: destroyed for powered-off state");
    Ok(())
}

fn create_vcpu_for_cpu_on(
    index: usize,
    vcpu: &mut ffi::hv_vcpu_t,
    exit_info_ptr: &mut ffi::hv_vcpu_exit_t,
    vcpu_handle_store: &AtomicVcpuHandle,
    vcpu_alive: &mut bool,
    current_vtimer_offset: u64,
) -> crate::error::Result<()> {
    if *vcpu_alive {
        return Ok(());
    }
    let (new_vcpu, new_exit_info) = create_vcpu()?;
    let configured = configure_created_vcpu(index, new_vcpu).and_then(|()| {
        // SAFETY: `new_vcpu` is owned by this thread.
        unsafe {
            ffi::check(
                "hv_vcpu_set_vtimer_offset(CPU_ON create)",
                ffi::hv_vcpu_set_vtimer_offset(new_vcpu, current_vtimer_offset),
            )
            .map_err(crate::error::VmmError::from)
            .and_then(|()| {
                ffi::check(
                    "hv_vcpu_set_vtimer_mask(CPU_ON create)",
                    ffi::hv_vcpu_set_vtimer_mask(new_vcpu, false),
                )
                .map_err(crate::error::VmmError::from)
            })
        }
    });
    if let Err(e) = configured {
        // SAFETY: `new_vcpu` was created on this thread and has not been published.
        let destroy_ret = unsafe { ffi::hv_vcpu_destroy(new_vcpu) };
        if let Err(de) = ffi::check("hv_vcpu_destroy(CPU_ON config rollback)", destroy_ret) {
            log::error!("hvf-vcpu-{index}: leaked vCPU after config failure: {de}");
        }
        return Err(e);
    }

    let Some(handle) = NonMaxU64::new(new_vcpu) else {
        // SAFETY: `new_vcpu` was created on this thread and has not been published.
        let destroy_ret = unsafe { ffi::hv_vcpu_destroy(new_vcpu) };
        if let Err(de) = ffi::check("hv_vcpu_destroy(CPU_ON niche rollback)", destroy_ret) {
            log::error!("hvf-vcpu-{index}: leaked vCPU after u64::MAX handle: {de}");
        }
        return Err(crate::error::VmmError::Config(
            "hv_vcpu_create returned u64::MAX".into(),
        ));
    };

    *vcpu = new_vcpu;
    *exit_info_ptr = new_exit_info;
    *vcpu_alive = true;
    vcpu_handle_store.store(Some(handle));
    log::info!("hvf-vcpu-{index}: created for CPU_ON (handle={new_vcpu:#x})");
    Ok(())
}

/// Apply a `VcpuResponse` to vCPU registers before resuming.
///
/// For MMIO/sysreg reads, writes the result to the destination register
/// and advances PC past the faulting instruction. Write exits (`MmioWrite`)
/// have their PC advanced eagerly during exit decode, so no response is
/// needed from the VMM for writes.
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn apply_response(
    vcpu: ffi::hv_vcpu_t,
    resp: VcpuResponse,
    mmio_register: u32,
) -> crate::error::Result<()> {
    match resp {
        VcpuResponse::Mmio { data, .. } => {
            // Write the MMIO read result to the destination register (SRT).
            if mmio_register < 31 {
                // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid
                // on this thread; HV_REG_X0+mmio_register (mmio_register<31)
                // is a valid hv_reg_t.
                unsafe {
                    ffi::check(
                        "hv_vcpu_set_reg(mmio)",
                        ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0 + mmio_register, data),
                    )
                    .map_err(crate::error::VmmError::from)?;
                }
            }
            // XZR (31) = discard.
            // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
            unsafe { super::exit::advance_pc_pub(vcpu)? };
        }
        VcpuResponse::SysReg { value, register } => {
            if register < 31 {
                // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid
                // on this thread; HV_REG_X0+register is a valid hv_reg_t.
                unsafe {
                    ffi::check(
                        "hv_vcpu_set_reg(sysreg)",
                        ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0 + register, value),
                    )
                    .map_err(crate::error::VmmError::from)?;
                }
            }
            // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
            unsafe { super::exit::advance_pc_pub(vcpu)? };
        }
        VcpuResponse::CpuOnBoot {
            entry_point,
            context_id,
        } => {
            // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
            unsafe {
                ffi::check(
                    "hv_vcpu_set_reg(PC/CpuOnBoot)",
                    ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_PC, entry_point),
                )
                .map_err(crate::error::VmmError::from)?;
                ffi::check(
                    "hv_vcpu_set_reg(X0/CpuOnBoot)",
                    ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0, context_id),
                )
                .map_err(crate::error::VmmError::from)?;
                ffi::check(
                    "hv_vcpu_set_reg(CPSR/CpuOnBoot)",
                    ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_CPSR, PSTATE_EL1H_DAIF_MASKED),
                )
                .map_err(crate::error::VmmError::from)?;
            }
        }
        VcpuResponse::CpuOnResult { psci_return } => {
            // Write the PSCI return value (success or error) to BSP's X0.
            // PC was already advanced by hardware for the HVC trap.
            // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
            unsafe {
                ffi::check(
                    "hv_vcpu_set_reg(X0/CpuOnResult)",
                    ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0, psci_return),
                )
                .map_err(crate::error::VmmError::from)?;
            }
        }
    }
    Ok(())
}
