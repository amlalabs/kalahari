// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Observable VM status shared between vCPU loops and user-facing APIs.

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

/// Terminal outcome of a VM run, reported by whichever vCPU observed it.
///
/// The private outcome code defines severity order: [`VmEnd::report`] uses it
/// to implement the "Fatal dominates" rule — a later report of a more severe
/// outcome overwrites an earlier lighter one, but not vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmOutcome {
    /// Guest asked to power off cleanly (e.g. x86 `outb(0xFE, 0x64)` or
    /// ARM PSCI `SYSTEM_OFF`). State snapshot is valid.
    CleanShutdown,
    /// Guest asked to reboot (PSCI `SYSTEM_RESET`). State snapshot is
    /// valid but represents pre-reset state.
    Reboot,
    /// Unrecoverable vCPU exit (triple fault, resume error, fatal sysreg).
    /// State snapshot is untrustworthy; `run()` must return `Err`.
    Fatal,
}

impl VmOutcome {
    const fn code(self) -> VmOutcomeCode {
        match self {
            Self::CleanShutdown => VmOutcomeCode::CLEAN_SHUTDOWN,
            Self::Reboot => VmOutcomeCode::REBOOT,
            Self::Fatal => VmOutcomeCode::FATAL,
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct VmOutcomeCode(u8);

impl VmOutcomeCode {
    const NONE: Self = Self(0);
    const CLEAN_SHUTDOWN: Self = Self(1);
    const REBOOT: Self = Self(2);
    const FATAL: Self = Self(3);

    const fn outcome(self) -> Option<VmOutcome> {
        match self.0 {
            1 => Some(VmOutcome::CleanShutdown),
            2 => Some(VmOutcome::Reboot),
            3 => Some(VmOutcome::Fatal),
            _ => None,
        }
    }
}

struct AtomicVmOutcome {
    code: AtomicU8,
}

impl AtomicVmOutcome {
    const fn new() -> Self {
        Self {
            code: AtomicU8::new(VmOutcomeCode::NONE.0),
        }
    }

    fn report(&self, outcome: VmOutcome) {
        let new = outcome.code();
        let mut cur = VmOutcomeCode(self.code.load(Ordering::Acquire));
        while cur < new {
            match self
                .code
                .compare_exchange_weak(cur.0, new.0, Ordering::AcqRel, Ordering::Acquire)
            {
                Ok(_) => break,
                Err(actual) => cur = VmOutcomeCode(actual),
            }
        }
    }

    fn outcome(&self) -> Option<VmOutcome> {
        VmOutcomeCode(self.code.load(Ordering::Acquire)).outcome()
    }
}

/// One authoritative VM terminal-outcome channel.
///
/// Fuses the "please stop" signal (previously a bare [`CancellationToken`])
/// with the "what happened" record so the two can never disagree. Every
/// vCPU-side terminal exit reports an outcome via [`report`]; callers that
/// just want to tear down (e.g. the user-closure arm of `machine::run()`)
/// use [`stop`], which signals peers without recording an outcome.
///
/// The discriminator for `run()` is [`outcome`]\[^1\] — no inference from
/// cancel-state, host-shutdown flags, or polling order.
///
/// [^1]: [`outcome`]: Self::outcome
pub struct VmEnd {
    outcome: AtomicVmOutcome,
    /// Signals peers to exit their loops. Internal — never expose the raw
    /// token; all cancellation goes through [`report`] or [`stop`].
    notify: CancellationToken,
}

impl VmEnd {
    pub fn new() -> Self {
        Self {
            outcome: AtomicVmOutcome::new(),
            notify: CancellationToken::new(),
        }
    }

    /// Record a terminal outcome and signal peers to stop.
    ///
    /// Dominance rule: higher-valued outcomes overwrite lower-valued ones
    /// (`Fatal` > `Reboot` > `CleanShutdown`). A second report of the same-
    /// or-lower severity is a no-op. This means a triple-fault that races
    /// with a clean PSCI shutdown correctly ends up as `Fatal`.
    pub fn report(&self, outcome: VmOutcome) {
        self.outcome.report(outcome);
        self.notify.cancel();
    }

    /// Signal peers to stop without recording an outcome.
    ///
    /// Used when the user closure completed of its own accord — whether
    /// the VM "died" is determined by whether any vCPU already called
    /// [`report`], not by this call.
    pub fn stop(&self) {
        self.notify.cancel();
    }

    /// Terminal outcome, if any vCPU has reported one.
    pub fn outcome(&self) -> Option<VmOutcome> {
        self.outcome.outcome()
    }

    pub fn is_stopped(&self) -> bool {
        self.notify.is_cancelled()
    }

    pub async fn stopped(&self) {
        self.notify.cancelled().await;
    }
}

/// One-shot gate that releases a paused VM run.
///
/// `VmHandle<Paused>::start()` opens this gate after it has registered all
/// attached command sessions. The VM run loop must not poll vCPUs or devices
/// before the gate opens, otherwise guest-ring output from forked sessions can
/// be consumed before the replacement host channels exist.
pub struct StartGate {
    started: AtomicBool,
    notify: Notify,
}

impl StartGate {
    /// Create a closed start gate.
    pub(crate) fn new() -> Self {
        Self {
            started: AtomicBool::new(false),
            notify: Notify::new(),
        }
    }

    /// Open the gate. Returns `true` for the first caller.
    pub(crate) fn start(&self) -> bool {
        let was_started = self.started.swap(true, Ordering::AcqRel);
        if !was_started {
            self.notify.notify_waiters();
        }
        !was_started
    }

    /// Check whether the gate has opened.
    pub(crate) fn is_started(&self) -> bool {
        self.started.load(Ordering::Acquire)
    }

    /// Wait until the gate opens.
    pub(crate) async fn wait_started(&self) {
        loop {
            let notified = self.notify.notified();
            if self.is_started() {
                return;
            }
            notified.await;
        }
    }
}

/// Observable VM status shared between vCPU threads and the user-facing API.
///
/// Lives behind `Arc` so it can be cloned into `VmHandle` without lifetime
/// constraints. All fields are lock-free (atomics + `Notify`).
pub struct VmStatus {
    /// Flag indicating guest has requested exit.
    exited: AtomicBool,

    /// Notifies waiters when the guest exits.
    exit_notify: tokio::sync::Notify,
}

impl VmStatus {
    /// Create a new `VmStatus` with default values.
    pub fn new() -> Self {
        Self {
            exited: AtomicBool::new(false),
            exit_notify: tokio::sync::Notify::new(),
        }
    }

    /// Atomically mark guest as exited and notify waiters.
    ///
    /// Returns `true` if this call was the first to set the flag.
    pub fn set_exited(&self) -> bool {
        let was_first = self
            .exited
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok();
        self.exit_notify.notify_waiters();
        was_first
    }

    /// Check if guest has exited.
    pub fn has_exited(&self) -> bool {
        self.exited.load(Ordering::Acquire)
    }

    /// Wait until the guest exits.
    pub async fn wait_for_exit(&self) {
        loop {
            // Register the `Notified` future BEFORE checking the condition.
            // `notify_waiters()` only wakes existing futures — if we checked
            // `has_exited()` first and `set_exited()` fired before `notified()`
            // was created, the notification would be lost and we'd hang forever.
            let notified = self.exit_notify.notified();
            if self.has_exited() {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn test_start_gate_waits_until_opened() {
        let gate = Arc::new(StartGate::new());
        assert!(!gate.is_started());

        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), gate.wait_started())
                .await
                .is_err(),
            "closed gate should not complete"
        );

        assert!(gate.start());
        assert!(gate.is_started());
        assert!(!gate.start(), "start gate should only open once");

        tokio::time::timeout(std::time::Duration::from_secs(1), gate.wait_started())
            .await
            .expect("open gate should complete");
    }

    #[test]
    fn test_initial_state() {
        let status = VmStatus::new();
        assert!(!status.has_exited());
    }

    #[test]
    fn test_exit_flag() {
        let status = VmStatus::new();
        assert!(!status.has_exited());
        assert!(status.set_exited());
        assert!(status.has_exited());
        // Second call returns false (already set).
        assert!(!status.set_exited());
    }

    #[test]
    fn test_vm_end_initial_state() {
        let end = VmEnd::new();
        assert_eq!(end.outcome(), None);
        assert!(!end.is_stopped());
    }

    #[test]
    fn test_vm_end_report_sets_outcome_and_stops() {
        let end = VmEnd::new();
        end.report(VmOutcome::CleanShutdown);
        assert_eq!(end.outcome(), Some(VmOutcome::CleanShutdown));
        assert!(end.is_stopped());
    }

    #[test]
    fn test_vm_end_stop_signals_without_outcome() {
        let end = VmEnd::new();
        end.stop();
        assert_eq!(end.outcome(), None);
        assert!(end.is_stopped());
    }

    #[test]
    fn test_vm_end_fatal_dominates_clean() {
        let end = VmEnd::new();
        end.report(VmOutcome::CleanShutdown);
        end.report(VmOutcome::Fatal);
        assert_eq!(end.outcome(), Some(VmOutcome::Fatal));
    }

    #[test]
    fn test_vm_end_fatal_dominates_reboot() {
        let end = VmEnd::new();
        end.report(VmOutcome::Reboot);
        end.report(VmOutcome::Fatal);
        assert_eq!(end.outcome(), Some(VmOutcome::Fatal));
    }

    #[test]
    fn test_vm_end_clean_does_not_overwrite_fatal() {
        let end = VmEnd::new();
        end.report(VmOutcome::Fatal);
        end.report(VmOutcome::CleanShutdown);
        assert_eq!(end.outcome(), Some(VmOutcome::Fatal));
    }

    #[test]
    fn test_vm_end_reboot_does_not_overwrite_fatal() {
        let end = VmEnd::new();
        end.report(VmOutcome::Fatal);
        end.report(VmOutcome::Reboot);
        assert_eq!(end.outcome(), Some(VmOutcome::Fatal));
    }

    #[test]
    fn test_vm_end_stop_does_not_clear_outcome() {
        let end = VmEnd::new();
        end.report(VmOutcome::Fatal);
        end.stop();
        assert_eq!(end.outcome(), Some(VmOutcome::Fatal));
    }

    #[tokio::test]
    async fn test_vm_end_stopped_future_resolves() {
        let end = std::sync::Arc::new(VmEnd::new());
        let e = std::sync::Arc::clone(&end);
        let task = tokio::spawn(async move { e.stopped().await });
        tokio::task::yield_now().await;
        end.report(VmOutcome::Fatal);
        tokio::time::timeout(std::time::Duration::from_secs(1), task)
            .await
            .expect("stopped() should resolve")
            .expect("task should not panic");
    }

    #[tokio::test]
    async fn test_wait_for_exit_no_hang() {
        // Regression test: set_exited() uses notify_waiters() which only
        // wakes existing Notified futures. If wait_for_exit() checked
        // has_exited() BEFORE creating the Notified future, a race could
        // cause it to hang forever. Run many iterations to shake out the race.
        for _ in 0..1000 {
            let status = Arc::new(VmStatus::new());
            let s = Arc::clone(&status);
            let handle = tokio::spawn(async move {
                s.wait_for_exit().await;
            });
            // Yield to give wait_for_exit a chance to start polling
            tokio::task::yield_now().await;
            status.set_exited();
            tokio::time::timeout(std::time::Duration::from_secs(1), handle)
                .await
                .expect("wait_for_exit should not hang")
                .expect("task should not panic");
        }
    }
}
