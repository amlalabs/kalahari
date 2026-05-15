// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! 64-bit GDT with TSS for long mode entry.

use crate::x86_64::builder::Result;
use crate::x86_64::consts::{
    GDT_ADDR, GDT_ENTRY_CODE64, GDT_ENTRY_DATA64, GDT_ENTRY_TSS64_HIGH, GDT_ENTRY_TSS64_LOW,
    GDT_SIZE_BYTES,
};
use crate::x86_64::memory::{BootGuestMemory, GuestPhysAddr};

/// Set up 64-bit GDT at `GDT_ADDR`.
pub fn setup_gdt(mem: &mut BootGuestMemory<'_>) -> Result<()> {
    mem.zero_guest(GuestPhysAddr::new(GDT_ADDR).range(GDT_SIZE_BYTES)?)?;

    // Entry 0: NULL descriptor
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR), 0)?;
    // Entry 1: NULL (Linux compatibility)
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR + 8), 0)?;
    // Entry 2 (selector 0x10): 64-bit code segment
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR + 16), GDT_ENTRY_CODE64)?;
    // Entry 3 (selector 0x18): 64-bit data segment
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR + 24), GDT_ENTRY_DATA64)?;
    // Entry 4-5 (selector 0x20): 64-bit TSS descriptor (16 bytes)
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR + 32), GDT_ENTRY_TSS64_LOW)?;
    mem.write_u64_guest(GuestPhysAddr::new(GDT_ADDR + 40), GDT_ENTRY_TSS64_HIGH)?;
    Ok(())
}
