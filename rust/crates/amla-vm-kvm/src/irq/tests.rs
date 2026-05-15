// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use super::*;

use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

/// Create a test `ShellIrqLine` with `EventFd` handles for observation.
///
/// Returns `(line, irq_eventfd, resample_eventfd)` where the `EventFds`
/// are the backing fds for the line (for reading/writing in tests).
fn test_line() -> (ShellIrqLine, EventFd, EventFd) {
    let irq_eventfd = EventFd::new(EFD_NONBLOCK).unwrap();
    let resample_eventfd = EventFd::new(EFD_NONBLOCK).unwrap();

    let line = ShellIrqLine::new(
        irq_eventfd.as_raw_fd(),
        resample_eventfd.as_raw_fd(),
        Arc::new(AtomicBool::new(false)),
    );
    (line, irq_eventfd, resample_eventfd)
}

#[cfg(target_arch = "x86_64")]
#[test]
fn test_virtio_irq_assignment() {
    assert_eq!(irqs::virtio_mmio(0), 5);
    assert_eq!(irqs::virtio_mmio(1), 6);
    assert_eq!(irqs::virtio_mmio(2), 7);
}

// ========================================================================
// ShellIrqLine tests
// ========================================================================

#[test]
fn test_shell_irq_line_level_tracking() {
    let (line, _irq_efd, _resample_efd) = test_line();

    assert!(!line.is_asserted());
    assert!(!line.is_resample_armed());

    line.assert();
    assert!(line.is_asserted());
    assert!(line.is_resample_armed());

    line.deassert();
    assert!(!line.is_asserted());
    // resample_armed stays true until EOI arrives
    assert!(line.is_resample_armed());
}

#[test]
fn test_shell_assert_always_writes_eventfd() {
    let (line, irq_efd, _resample_efd) = test_line();

    // First assert writes to eventfd
    line.assert();
    assert_eq!(irq_efd.read().unwrap(), 1);

    // Repeated asserts always write (ensures guest sees interrupt even
    // when level is already high — needed for virtio-console ctrl queue)
    line.assert();
    assert_eq!(irq_efd.read().unwrap(), 1);
    line.assert();
    assert_eq!(irq_efd.read().unwrap(), 1);

    // Deassert then assert still works
    line.deassert();
    line.assert();
    assert_eq!(irq_efd.read().unwrap(), 1);
}

#[test]
fn test_shell_poll_resample_with_level_high() {
    let (line, irq_efd, resample_efd) = test_line();

    // Assert the line
    line.assert();
    assert!(line.is_asserted());
    assert!(line.is_resample_armed());

    // Drain the eventfd from assert
    irq_efd.read().unwrap();

    // Simulate guest EOI by writing to resamplefd
    resample_efd.write(1).unwrap();

    // check_resample should handle the resample and retrigger (level still high)
    line.check_resample();

    // After retrigger, resample_armed stays true (new interrupt in flight)
    assert!(line.is_resample_armed());

    // The check_resample should have written to eventfd (retrigger)
    assert_eq!(irq_efd.read().unwrap(), 1);
}

#[test]
fn test_shell_poll_resample_with_level_low() {
    let (line, irq_efd, resample_efd) = test_line();

    // Assert then deassert
    line.assert();
    line.deassert();
    assert!(!line.is_asserted());
    assert!(line.is_resample_armed());

    // Drain the eventfd from assert
    irq_efd.read().unwrap();

    // Simulate guest EOI
    resample_efd.write(1).unwrap();

    // check_resample should handle the resample but NOT retrigger (level is low)
    line.check_resample();
    assert!(!line.is_resample_armed()); // Cleared, not re-armed

    // No retrigger - eventfd should be empty
    assert!(irq_efd.read().is_err()); // EAGAIN
}

#[test]
fn test_shell_poll_resample_no_token() {
    let (line, _irq_efd, _resample_efd) = test_line();

    // No resample token - check_resample should be a no-op
    line.check_resample();
    assert!(!line.is_resample_armed());
}

#[test]
fn test_shell_irq_line_always_starts_deasserted() {
    let (line, _irq_efd, _resample_efd) = test_line();
    assert!(!line.is_asserted());
    assert!(!line.is_resample_armed());
}

#[test]
fn test_shell_check_resample_handles_eagain_correctly() {
    let (line, _irq_efd, _resample_efd) = test_line();

    // With no token written, check_resample should handle EAGAIN gracefully
    line.check_resample();
    line.check_resample();
    line.check_resample();

    // State should remain unchanged
    assert!(!line.is_resample_armed());
}

#[test]
fn test_shell_check_resample_retrigger_stuck_high() {
    let (line, irq_efd, _resample_efd) = test_line();

    // Assert the line — level HIGH, resample armed
    line.assert();
    irq_efd.read().unwrap(); // drain the initial assert

    // No EOI token, but level is high and resample is armed.
    // check_resample should re-assert (write eventfd) to unstick.
    line.check_resample();
    assert_eq!(irq_efd.read().unwrap(), 1);
}
