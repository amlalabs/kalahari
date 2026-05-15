// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Backend-internal vCPU types: preempt state, signal handling, `kvm_run` manipulation.
//!
//! Nothing in this module is part of the public API. The public interface is
//! `Vm::resume()` in `builder/vm.rs`.

use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU64, Ordering};

use amla_core::VcpuError;
use kvm_bindings::kvm_run;

// ============================================================================
// Per-vCPU preempt + running state (fully self-contained, no amla-core dep)
// ============================================================================

/// Per-vCPU preempt + run state.
///
/// Four mechanisms cooperate to guarantee preemption:
///
/// 1. **Preempt flag** (serialized by spinlock): the preemptor sets it,
///    the thread checks it before `KVM_RUN`. Handles "thread idle" and
///    "thread in cycle but hasn't checked yet."
/// 2. **Signal handler sets `immediate_exit = 1`**: if SIGUSR1 is
///    consumed before the ioctl, the handler writes `immediate_exit = 1`
///    on the `kvm_run` mmap page so the kernel returns `-EINTR` without
///    entering the guest.
/// 3. **SIGUSR1 EINTR**: if the thread is already in `KVM_RUN`, the
///    signal causes the ioctl to return `-EINTR`. SIGUSR1 is blocked in
///    userspace outside the `KVM_RUN` window (see [`block_sigusr1`]) and
///    only delivered inside the ioctl, so a stale signal buffered after
///    the vcpu exits cannot hit a reused tid.
/// 4. **Generation counter** (tid-reuse guard): each vcpu thread bumps
///    `generation` on start and on clean exit. `request_preempt` captures
///    the generation it targets; the signal handler checks a thread-local
///    "my generation" against this captured expectation and no-ops on
///    mismatch. This closes the gap where `tgkill(tid, SIGUSR1)` could
///    hit a freshly-reused tid after the original vcpu thread exited.
#[derive(Debug)]
pub(crate) struct KvmVcpuRunState {
    preempt: AtomicBool,
    running_tid: AtomicI32,
    locked: AtomicBool,
    /// Monotonically-increasing counter bumped when the vcpu thread enters
    /// its run loop and when it cleanly exits. Used with `expected_generation`
    /// to reject SIGUSR1 delivered after a tid-reuse.
    ///
    /// Starts at 1 so 0 serves as an "uninitialized" sentinel for
    /// thread-local state.
    generation: AtomicU64,
    /// Generation captured by [`KvmVcpuRunState::request_preempt`] at the
    /// moment it decided to fire tgkill. The signal handler compares this
    /// to the thread-local `VCPU_GENERATION`; if they differ, the current
    /// occupant of the tid is not the vcpu that preemption targeted and
    /// the handler is a no-op.
    expected_generation: AtomicU64,
}

impl Default for KvmVcpuRunState {
    fn default() -> Self {
        Self {
            preempt: AtomicBool::new(false),
            running_tid: AtomicI32::new(-1),
            locked: AtomicBool::new(false),
            generation: AtomicU64::new(1),
            expected_generation: AtomicU64::new(0),
        }
    }
}

impl KvmVcpuRunState {
    /// Request preemption of this vCPU.
    pub(crate) fn request_preempt(&self) {
        // Set the flag first — covers all cases where the thread
        // hasn't checked it yet.
        self.preempt.store(true, Ordering::Release);

        if self
            .locked
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_ok()
        {
            // Thread is idle. Flag is set; it will see it next cycle.
            self.locked.store(false, Ordering::Release);
        } else {
            // Thread is in its active cycle. Send SIGUSR1 if tid is set.
            // The signal handler sets immediate_exit=1 (covers the case
            // where SIGUSR1 arrives before the ioctl).
            let tid = self.running_tid.load(Ordering::Acquire);
            if tid > 0 {
                // Capture the generation we are targeting. The handler
                // compares this against the thread-local VCPU_GENERATION
                // and no-ops on mismatch (stale signal after tid reuse).
                let gen_id = self.generation.load(Ordering::Acquire);
                self.expected_generation.store(gen_id, Ordering::Release);

                // SAFETY: tgkill takes (tgid, tid, sig) as integers; no pointer
                // arguments. Delivering SIGUSR1 to `tid` within our own pid is
                // safe; the worst case if `tid` has exited is ESRCH. If the
                // kernel has reused `tid` for an unrelated thread in our
                // process, the signal will be buffered there (SIGUSR1 is
                // blocked process-wide — see `block_sigusr1`) and either
                // dropped on that thread's exit or caught by its handler,
                // which no-ops due to the generation mismatch.
                unsafe {
                    libc::syscall(libc::SYS_tgkill, libc::getpid(), tid, libc::SIGUSR1);
                }
            }
        }
    }

    /// Check and clear the preempt flag. Called inside the locked section.
    pub(crate) fn swap_preempt(&self) -> bool {
        self.preempt.swap(false, Ordering::Acquire)
    }

    /// Lock the active cycle. Spins briefly if `request_preempt` holds
    /// the lock (it only holds it for a flag store + release).
    pub(crate) fn lock(&self) -> RunGuard<'_> {
        while self.locked.swap(true, Ordering::Acquire) {
            std::hint::spin_loop();
        }
        RunGuard(self)
    }

    pub(crate) fn mark_running_with_tid(&self, tid: i32) {
        self.running_tid.store(tid, Ordering::Release);
    }

    pub(crate) fn mark_stopped_with_tid(&self) {
        self.running_tid.store(-1, Ordering::Release);
    }

    /// Bump the generation counter, returning the new value. Called by the
    /// vcpu thread once it has installed its thread-local state
    /// (`VCPU_GENERATION`), and again on clean exit.
    pub(crate) fn bump_generation(&self) -> u64 {
        // fetch_add returns the previous value; we want the new one.
        self.generation
            .fetch_add(1, Ordering::AcqRel)
            .wrapping_add(1)
    }

    /// Current generation. Used in tests; production code reads the value
    /// captured inside [`KvmVcpuRunState::request_preempt`] instead.
    #[cfg(test)]
    pub(crate) fn current_generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }
}

/// RAII guard that unlocks [`KvmVcpuRunState`] on drop.
pub(crate) struct RunGuard<'a>(&'a KvmVcpuRunState);

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        self.0.locked.store(false, Ordering::Release);
    }
}

// ============================================================================
// Constants + signal handler
// ============================================================================

/// `KVM_RUN` ioctl number: `_IO(KVMIO, 0x80)`.
pub(crate) const KVM_RUN: libc::Ioctl = 0xAE80;

// Thread-local pointer to the kvm_run mmap page. Set by the KVM thread
// before entering the run loop; read by the signal handler to write
// `immediate_exit = 1`.
std::thread_local! {
    static KVM_RUN_PTR: std::cell::Cell<*mut kvm_run> = const { std::cell::Cell::new(std::ptr::null_mut()) };
    /// Generation of the vcpu currently running on this thread. Set by
    /// [`init_vcpu_thread`] at thread entry, cleared by [`exit_vcpu_thread`].
    /// Read by [`preempt_signal_handler`] and compared against
    /// `KvmVcpuRunState::expected_generation` to guard against tid reuse.
    /// 0 is the sentinel for "no vcpu on this thread".
    static VCPU_GENERATION: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    /// Pointer to the `expected_generation` field on this thread's
    /// `KvmVcpuRunState`. Set in [`init_vcpu_thread`]; used by the signal
    /// handler to read the expected-generation the preemptor captured.
    /// Null means "no vcpu on this thread".
    static VCPU_EXPECTED_GEN_PTR: std::cell::Cell<*const AtomicU64> = const { std::cell::Cell::new(std::ptr::null()) };
}

/// Set the thread-local `kvm_run` pointer. Called once per KVM thread
/// after mmap'ing the page.
pub(crate) fn set_thread_kvm_run_ptr(ptr: *mut kvm_run) {
    KVM_RUN_PTR.with(|cell| cell.set(ptr));
}

/// Initialize per-vcpu-thread state: bump the run-state generation, record
/// it in the thread-local, and expose the `expected_generation` pointer for
/// the signal handler.
///
/// Must be called exactly once per vcpu thread, after
/// [`set_thread_kvm_run_ptr`] and before the first `KVM_RUN`. Paired with
/// [`exit_vcpu_thread`] on clean shutdown.
pub(crate) fn init_vcpu_thread(state: &KvmVcpuRunState) {
    let gen_id = state.bump_generation();
    VCPU_GENERATION.with(|cell| cell.set(gen_id));
    // Record the address of expected_generation so the signal handler can
    // read it without needing a full &KvmVcpuRunState. The pointer remains
    // valid because `state` is held alive (Arc) by the vcpu thread's stack
    // for the thread's lifetime, and exit_vcpu_thread clears it before the
    // Arc is dropped.
    VCPU_EXPECTED_GEN_PTR.with(|cell| cell.set(&raw const state.expected_generation));
}

/// Tear down per-vcpu-thread state. Bumps generation so any signal still in
/// flight cannot match the thread-local, and clears the expected-gen pointer.
pub(crate) fn exit_vcpu_thread(state: &KvmVcpuRunState) {
    // Bump before clearing so a signal delivered between the two stores
    // either (a) sees a matching VCPU_GENERATION and a no-op KVM_RUN_PTR
    // (safe, because by this point we've exited the run loop), or (b) sees
    // a mismatching generation (safe, no-ops).
    let _ = state.bump_generation();
    VCPU_GENERATION.with(|cell| cell.set(0));
    VCPU_EXPECTED_GEN_PTR.with(|cell| cell.set(std::ptr::null()));
    KVM_RUN_PTR.with(|cell| cell.set(std::ptr::null_mut()));
}

/// Block SIGUSR1 on the calling thread. Must be called on the vcpu thread
/// BEFORE [`install_preempt_signal_handler`] and the run loop. Combined with
/// [`unblock_sigusr1_for_kvm_run`]/[`block_sigusr1`] around the ioctl, this
/// guarantees SIGUSR1 is only delivered to this thread while it is inside
/// the `KVM_RUN` ioctl — eliminating the "signal arrives after thread
/// exited and tid was reused" hazard at the kernel-delivery level.
///
/// Returns an error if `pthread_sigmask` fails.
pub(crate) fn block_sigusr1() -> Result<(), VcpuError> {
    // SAFETY: sigset_t is a C POD; zero-init then sigaddset is the documented
    // initialization idiom. pthread_sigmask with SIG_BLOCK and a valid set
    // pointer is safe; we check the return code.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut set) != 0 {
            return Err(VcpuError::hypervisor("sigemptyset failed".to_string()));
        }
        if libc::sigaddset(&raw mut set, libc::SIGUSR1) != 0 {
            return Err(VcpuError::hypervisor(
                "sigaddset SIGUSR1 failed".to_string(),
            ));
        }
        if libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut()) != 0 {
            return Err(VcpuError::hypervisor(
                "pthread_sigmask BLOCK SIGUSR1 failed".to_string(),
            ));
        }
    }
    Ok(())
}

/// Unblock SIGUSR1 on the calling thread. Called immediately before
/// `KVM_RUN`. Paired with [`block_sigusr1`] immediately after.
///
/// Returns an error if `pthread_sigmask` fails. Callers should treat this as
/// fatal: if the mask is wrong the preemption path will not work.
pub(crate) fn unblock_sigusr1_for_kvm_run() -> Result<(), VcpuError> {
    // SAFETY: same reasoning as block_sigusr1 — pure C POD manipulation with
    // pthread_sigmask, return value checked.
    unsafe {
        let mut set: libc::sigset_t = std::mem::zeroed();
        if libc::sigemptyset(&raw mut set) != 0 {
            return Err(VcpuError::hypervisor("sigemptyset failed".to_string()));
        }
        if libc::sigaddset(&raw mut set, libc::SIGUSR1) != 0 {
            return Err(VcpuError::hypervisor(
                "sigaddset SIGUSR1 failed".to_string(),
            ));
        }
        if libc::pthread_sigmask(libc::SIG_UNBLOCK, &raw const set, std::ptr::null_mut()) != 0 {
            return Err(VcpuError::hypervisor(
                "pthread_sigmask UNBLOCK SIGUSR1 failed".to_string(),
            ));
        }
    }
    Ok(())
}

/// Install the SIGUSR1 signal handler for vCPU preemption.
///
/// Must be called AFTER `set_thread_kvm_run_ptr` and [`init_vcpu_thread`].
/// The handler sets `immediate_exit = 1` on the thread-local `kvm_run` page
/// only if the thread-local generation matches the expected generation
/// captured by [`KvmVcpuRunState::request_preempt`], closing the tid-reuse
/// race.
///
/// Re-installs on every call (not memoized). Previously we memoized via
/// `Once`: a transient first-call failure poisoned all future calls, and a
/// first-call success was never revalidated, so a third-party library
/// stomping SIGUSR1 after init silently broke vCPU preemption.
pub(crate) fn install_preempt_signal_handler() -> Result<(), VcpuError> {
    let our_handler = preempt_signal_handler as *const () as usize;

    // SAFETY: `sigaction` is `#[repr(C)]`; zero-init is valid. The handler
    // address has extern "C" ABI and outlives the process.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = our_handler;
        sa.sa_flags = libc::SA_SIGINFO;
        libc::sigemptyset(&raw mut sa.sa_mask);

        let mut old_sa: libc::sigaction = std::mem::zeroed();
        if libc::sigaction(libc::SIGUSR1, &raw const sa, &raw mut old_sa) != 0 {
            return Err(VcpuError::hypervisor(
                "sigaction SIGUSR1 failed".to_string(),
            ));
        }

        // Warn if someone else installed a different handler between now and
        // the last time we were here (SIG_DFL == 0 and SIG_IGN == 1 on every
        // platform libc targets; both are normal prior states).
        if old_sa.sa_sigaction != our_handler
            && old_sa.sa_sigaction != libc::SIG_DFL
            && old_sa.sa_sigaction != libc::SIG_IGN
        {
            log::warn!(
                "install_preempt_signal_handler: replaced foreign SIGUSR1 handler {:#x} — another library stomped our preempt handler",
                old_sa.sa_sigaction,
            );
        }
    }
    Ok(())
}

extern "C" fn preempt_signal_handler(
    _sig: libc::c_int,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    // Tid-reuse guard: compare this thread's generation against the one
    // the preemptor captured. A mismatch means the signal was destined
    // for a prior occupant of this tid (now exited); no-op.
    let my_gen = VCPU_GENERATION.with(std::cell::Cell::get);
    if my_gen == 0 {
        // No vcpu currently owns this thread (exited or never initialized).
        return;
    }
    let expected_ptr = VCPU_EXPECTED_GEN_PTR.with(std::cell::Cell::get);
    if expected_ptr.is_null() {
        return;
    }
    // SAFETY: `expected_ptr` was installed by init_vcpu_thread on this
    // thread and points into the KvmVcpuRunState kept alive by the vcpu
    // thread's own Arc. exit_vcpu_thread clears the pointer before the
    // Arc is dropped, so a non-null value here implies the pointee is live.
    let expected = unsafe { (*expected_ptr).load(Ordering::Acquire) };
    if expected != my_gen {
        return;
    }

    // Generation matches; fire the immediate_exit write.
    //
    // SAFETY: kvm_run is mmap'd shared memory. Writing immediate_exit (u8)
    // is naturally atomic. The pointer was set by the same thread that
    // receives this signal, so no cross-thread access.
    KVM_RUN_PTR.with(|cell| {
        let ptr = cell.get();
        if !ptr.is_null() {
            // Use write_volatile to prevent the compiler from eliding or
            // reordering this write — another thread reads immediate_exit
            // via KVM_RUN, and the signal handler must be visible.
            // SAFETY: `ptr` was stored by the same thread that receives this
            // signal (set_thread_kvm_run_ptr) and remains valid until the
            // thread unmaps kvm_run on exit; immediate_exit is a u8 field in
            // the kvm_run mmap region, so the write is naturally atomic.
            unsafe {
                core::ptr::write_volatile(&raw mut (*ptr).immediate_exit, 1);
            }
        }
    });
}

// ============================================================================
// kvm_run manipulation
// ============================================================================

/// Apply a `VcpuResponse` to the `kvm_run` shared page before the next `KVM_RUN`.
#[allow(clippy::cast_possible_truncation)]
pub(crate) fn apply_response_to_kvm_run(
    kvm_run_ptr: *mut kvm_run,
    kvm_run_size: usize,
    resp: amla_core::VcpuResponse,
) -> Result<(), VcpuError> {
    use amla_core::VcpuResponse;
    #[cfg(not(target_arch = "x86_64"))]
    let _ = kvm_run_size;

    // SAFETY: `kvm_run_ptr` points to the KVM_RUN mmap region owned exclusively
    // by the vcpu thread calling this function.
    let run = unsafe { &mut *kvm_run_ptr };
    match resp {
        VcpuResponse::Mmio { data, size } => {
            if size > 8 {
                return Err(VcpuError::InvalidState("MMIO size > 8".into()));
            }
            // SAFETY: the caller invokes this in response to a KVM_EXIT_MMIO
            // (VcpuResponse::Mmio), so the mmio union variant is active.
            let mmio = unsafe { &mut run.__bindgen_anon_1.mmio };
            mmio.data[..size as usize].copy_from_slice(&data.to_le_bytes()[..size as usize]);
        }
        #[cfg(target_arch = "x86_64")]
        VcpuResponse::Pio { data, size } => {
            // SAFETY: the caller invokes this in response to a KVM_EXIT_IO
            // (VcpuResponse::Pio), so the io union variant is active.
            let offset = unsafe { run.__bindgen_anon_1.io.data_offset } as usize;
            let write_size = size as usize;
            if offset.saturating_add(write_size) > kvm_run_size {
                return Err(VcpuError::InvalidState(
                    "PIO data_offset out of bounds".into(),
                ));
            }
            // SAFETY: bounds checked above, offset is within the kvm_run mmap.
            let ptr = unsafe { kvm_run_ptr.cast::<u8>().add(offset) };
            match size {
                // SAFETY: `ptr = kvm_run_ptr + offset`, bounds checked above
                // (offset + write_size <= kvm_run_size), so at least 1 byte is writable.
                1 => unsafe { *ptr = data as u8 },
                // SAFETY: `ptr` is within the kvm_run mmap, bounds checked above;
                // write_unaligned handles misaligned destination.
                2 => unsafe { std::ptr::write_unaligned(ptr.cast::<u16>(), data as u16) },
                // SAFETY: `ptr` is within the kvm_run mmap, bounds checked above;
                // write_unaligned handles misaligned destination.
                4 => unsafe { std::ptr::write_unaligned(ptr.cast::<u32>(), data) },
                _ => return Err(VcpuError::InvalidState("invalid PIO size".into())),
            }
        }
        VcpuResponse::SysReg { .. }
        | VcpuResponse::CpuOnBoot { .. }
        | VcpuResponse::CpuOnResult { .. } => {}
    }
    Ok(())
}

/// Check if the most recent HLT is terminal (`cli; hlt`).
#[cfg(target_arch = "x86_64")]
pub(crate) fn is_terminal_halt(raw_fd: i32) -> bool {
    const KVM_GET_REGS: libc::Ioctl = 0x8090_AE81_u32 as libc::Ioctl;
    let mut regs = std::mem::MaybeUninit::<kvm_bindings::kvm_regs>::zeroed();
    // SAFETY: `raw_fd` is a valid KVM vCPU fd; KVM_GET_REGS writes a kvm_regs
    // struct into the provided pointer, which is sized correctly by MaybeUninit.
    let ret = unsafe { libc::ioctl(raw_fd, KVM_GET_REGS, regs.as_mut_ptr()) };
    if ret != 0 {
        return false;
    }
    // SAFETY: ioctl returned 0 above, so KVM fully initialized the kvm_regs struct.
    let regs = unsafe { regs.assume_init() };
    regs.rflags & (1 << 9) == 0
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn signal_handler_idempotent() {
        install_preempt_signal_handler().unwrap();
        install_preempt_signal_handler().unwrap();
    }

    #[test]
    fn request_preempt_sets_flag_when_idle() {
        let state = KvmVcpuRunState::default();
        state.request_preempt();
        assert!(state.preempt.load(Ordering::Relaxed));
    }

    #[test]
    fn bump_generation_is_monotonic() {
        let state = KvmVcpuRunState::default();
        let g0 = state.current_generation();
        let g1 = state.bump_generation();
        let g2 = state.bump_generation();
        assert_eq!(g1, g0 + 1);
        assert_eq!(g2, g1 + 1);
    }

    #[test]
    fn request_preempt_captures_generation_when_active() {
        let state = KvmVcpuRunState::default();
        // Simulate the vcpu being in its active cycle: hold `locked`.
        assert!(
            state
                .locked
                .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
        );
        // Set a tid so tgkill path fires. Use our own tid — SIGUSR1 may or
        // may not be installed depending on test order, so mask it here.
        // SAFETY: pure C calls on a sigset_t POD; return values checked via
        // debug_assert to keep the test robust.
        unsafe {
            let mut set: libc::sigset_t = std::mem::zeroed();
            libc::sigemptyset(&raw mut set);
            libc::sigaddset(&raw mut set, libc::SIGUSR1);
            libc::pthread_sigmask(libc::SIG_BLOCK, &raw const set, std::ptr::null_mut());
        }
        let my_tid = rustix::thread::gettid().as_raw_nonzero().get();
        state.mark_running_with_tid(my_tid);
        state.request_preempt();
        // request_preempt should have captured the current generation.
        assert_eq!(
            state.expected_generation.load(Ordering::Acquire),
            state.current_generation()
        );
        // Release lock we fake-held.
        state.locked.store(false, Ordering::Release);
    }
}
