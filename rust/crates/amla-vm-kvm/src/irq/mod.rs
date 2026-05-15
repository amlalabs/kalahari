// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! IRQ injection via KVM irqfd.
//!
//! Uses eventfd + irqfd for fast, lockless interrupt injection:
//! - Device calls `assert()` → eventfd write → KVM injects IRQ
//! - No mutex on hot path, no `VmFd` reference needed by device
//! - Level tracking via `AtomicBool` for snapshot/restore
//!
//! All IRQ lines are resampled (level-triggered with EOI notification).
//!
//! # Shell Hardware
//!
//! Shell hardware owns permanent irqfd registrations — eventfds are created
//! once with the shell and never unregistered. `ShellIrqLine` stores raw fd
//! numbers (not owned) from the shell's eventfds.

pub mod irqs;
mod resampled_line;

pub(crate) use resampled_line::ShellIrqLine;

// Re-export the canonical IrqLine trait from amla-core.
pub use amla_core::IrqLine;

#[cfg(test)]
mod tests;
