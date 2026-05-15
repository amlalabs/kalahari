// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use amla_core::IrqLine;

/// Level-triggered IRQ line backed by shell's pre-registered eventfds.
///
/// Stores raw fd numbers (not owned). The shell's `EventFd` objects outlive
/// this struct — guaranteed by `VirtualMachine` drop ordering (devices drop
/// before shell) and `run()`'s scoped task block.
///
/// # How it works
///
/// 1. Device calls `assert()` → sets level HIGH, writes eventfd, arms resample
/// 2. KVM injects IRQ to guest via irqfd
/// 3. Guest runs ISR handler and does EOI (writes to LAPIC/IOAPIC)
/// 4. KVM writes to resamplefd (notifies host of EOI)
/// 5. Device loop calls `check_resample()` → handles retrigger if level still HIGH
///
/// # Thread Safety
///
/// - `assert()`: Lock-free (atomic CAS + eventfd write)
/// - `deassert()`: Lock-free (atomic store)
/// - `check_resample()`: Lock-free (eventfd read + conditional write)
pub struct ShellIrqLine {
    /// Eventfd that KVM reads for interrupt injection (raw fd, not owned).
    irq_fd: RawFd,
    /// Eventfd that KVM writes to on guest EOI (raw fd, not owned).
    resample_fd: RawFd,
    /// Device's logical level (true = asserted/wants interrupt).
    level: AtomicBool,
    /// Whether we're waiting for a resample (EOI) notification.
    resample_armed: AtomicBool,
    /// Set when the device waker consumes the resamplefd to wake the device loop.
    resample_pending: Arc<AtomicBool>,
}

impl ShellIrqLine {
    /// Create a new shell IRQ line from pre-registered eventfds.
    ///
    /// `irq_fd` and `resample_fd` must be valid eventfd file descriptors
    /// that outlive this `ShellIrqLine`.
    pub(crate) const fn new(
        irq_fd: RawFd,
        resample_fd: RawFd,
        resample_pending: Arc<AtomicBool>,
    ) -> Self {
        Self {
            irq_fd,
            resample_fd,
            level: AtomicBool::new(false),
            resample_armed: AtomicBool::new(false),
            resample_pending,
        }
    }
}

impl IrqLine for ShellIrqLine {
    fn assert(&self) {
        self.level.store(true, Ordering::Release);
        write_eventfd(self.irq_fd);
        self.resample_armed.store(true, Ordering::Release);
    }

    fn deassert(&self) {
        self.level.store(false, Ordering::Release);
    }

    fn check_resample(&self) {
        if self.resample_pending.swap(false, Ordering::AcqRel)
            || read_eventfd(self.resample_fd).is_ok()
        {
            // Guest EOI arrived. Clear armed state, then retrigger if level
            // is still HIGH (device wants another interrupt).
            self.resample_armed.store(false, Ordering::Release);
            if self.level.load(Ordering::Acquire) {
                write_eventfd(self.irq_fd);
                self.resample_armed.store(true, Ordering::Release);
            }
            return;
        }
        // No resamplefd token. If level is stuck high, the original eventfd
        // write was likely swallowed (IOAPIC entry masked during guest boot).
        // Re-write the eventfd — idempotent for level-triggered IOAPIC pins.
        if self.level.load(Ordering::Acquire) && self.resample_armed.load(Ordering::Acquire) {
            write_eventfd(self.irq_fd);
        }
    }
}

/// Write `1u64` to an eventfd (triggers KVM interrupt injection).
fn write_eventfd(fd: RawFd) {
    // SAFETY: fd is a valid eventfd from the shell, outlives this call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    if let Err(e) = rustix::io::write(borrowed, &1u64.to_ne_bytes()) {
        log::warn!("write_eventfd(fd={fd}): {e}");
    }
}

/// Non-blocking read from an eventfd. Returns the counter value or Err on EAGAIN.
fn read_eventfd(fd: RawFd) -> Result<u64, ()> {
    let mut buf = [0u8; 8];
    // SAFETY: fd is a valid eventfd from the shell, outlives this call.
    let borrowed = unsafe { std::os::fd::BorrowedFd::borrow_raw(fd) };
    match rustix::io::read(borrowed, &mut buf) {
        Ok(8) => Ok(u64::from_ne_bytes(buf)),
        _ => Err(()),
    }
}

#[cfg(test)]
impl ShellIrqLine {
    /// Check if level is currently asserted (test only).
    pub(super) fn is_asserted(&self) -> bool {
        self.level.load(Ordering::Acquire)
    }

    /// Check if we're waiting for guest EOI (test only).
    pub(super) fn is_resample_armed(&self) -> bool {
        self.resample_armed.load(Ordering::Acquire)
    }
}
