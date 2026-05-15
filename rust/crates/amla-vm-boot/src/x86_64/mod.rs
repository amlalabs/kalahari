// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! x86_64 Linux boot protocol.
//!
//! ELF kernel loading (vmlinux), boot parameters (zero page), identity-mapped
//! page tables, 64-bit GDT, MP table for SMP discovery.
//!
//! Returns platform-agnostic `X86BootState` for backend conversion.

pub mod consts;
mod cpu_state;
mod gdt;
mod memory;
mod mptable;
mod page_tables;
pub(crate) mod writer;

mod builder;

#[cfg(test)]
mod tests;

pub use builder::{BootError, BootResult, LinuxBootBuilder, Result, setup_linux_boot};
pub use consts::{IOAPIC_ADDR, LAPIC_ADDR, MPTABLE_START};
pub use cpu_state::{SegmentState, TableState, X86BootState};
pub use memory::{BootGuestMemory, BootRamLayout, GuestPhysAddr, GuestRange, RamSegment};

/// Internal helpers re-exported for backend crates (e.g., amla-kvm CPU state conversion).
#[doc(hidden)]
pub mod internals {
    pub use crate::x86_64::cpu_state::setup_cpu_state;
}
