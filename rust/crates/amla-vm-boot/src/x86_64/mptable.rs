// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! MP table (Multi-Processor Specification 1.4) for SMP CPU discovery.

use crate::x86_64::builder::{BootError, Result};
use crate::x86_64::consts::{
    CPU_FEATURE_FLAGS, CPU_SIGNATURE, IOAPIC_ADDR, IOAPIC_VERSION, LAPIC_ADDR, LAPIC_VERSION,
    LOW_MEMORY_END, MP_BUS_ENTRY_SIZE, MP_CONFIG_HEADER_SIZE, MP_CPU_BSP, MP_CPU_ENABLED,
    MP_DEST_ALL_APICS, MP_ENTRY_BUS, MP_ENTRY_INTSRC, MP_ENTRY_IOAPIC, MP_ENTRY_LINTSRC,
    MP_ENTRY_PROCESSOR, MP_FP_SIZE, MP_INTSRC_ENTRY_SIZE, MP_IOAPIC_ENTRY_SIZE, MP_IRQ_TYPE_EXTINT,
    MP_IRQ_TYPE_NMI, MP_IRQ_TYPE_VECTORED, MP_LINTSRC_ENTRY_SIZE, MP_NUM_ISA_IRQS,
    MP_NUM_LINT_SOURCES, MP_PROC_ENTRY_SIZE, MP_SPEC_REV_1_4, MPTABLE_START,
};
use crate::x86_64::memory::{BootGuestMemory, GuestPhysAddr};

// All u64→usize casts in this module are sound: the compile_error! in writer.rs
// guarantees a 64-bit target where usize == u64.

/// Set up MP tables in guest memory.
///
pub fn setup_mptable(mem: &mut BootGuestMemory<'_>, num_cpus: usize) -> Result<()> {
    let max_cpus = max_mptable_cpus();
    if num_cpus == 0 || num_cpus > max_cpus {
        return Err(BootError::InvalidCpuCount {
            requested: num_cpus,
            max: max_cpus,
        });
    }
    let num_cpus_u8 = u8::try_from(num_cpus).map_err(|_| BootError::InvalidCpuCount {
        requested: num_cpus,
        max: max_cpus,
    })?;

    let proc_count = num_cpus as u64;
    let io_intsrc_count = u64::from(MP_NUM_ISA_IRQS);
    let local_intsrc_count = u64::from(MP_NUM_LINT_SOURCES);

    let total_entries = proc_count + 1 + 1 + io_intsrc_count + local_intsrc_count;

    let config_table_size = MP_CONFIG_HEADER_SIZE
        + proc_count * MP_PROC_ENTRY_SIZE
        + MP_BUS_ENTRY_SIZE
        + MP_IOAPIC_ENTRY_SIZE
        + io_intsrc_count * MP_INTSRC_ENTRY_SIZE
        + local_intsrc_count * MP_LINTSRC_ENTRY_SIZE;

    let mp_fp_addr = MPTABLE_START;
    let mp_config_addr = mp_fp_addr + MP_FP_SIZE;

    let total_table_size = MP_FP_SIZE + config_table_size;
    if mp_fp_addr + total_table_size > LOW_MEMORY_END {
        return Err(BootError::MpTableOverflow {
            size: total_table_size,
            num_cpus,
        });
    }

    mem.zero_guest(
        GuestPhysAddr::new(mp_fp_addr).range((MP_FP_SIZE + config_table_size) as usize)?,
    )?;

    let mut offset = mp_config_addr + MP_CONFIG_HEADER_SIZE;
    let ioapic_id = num_cpus_u8;

    offset = write_processor_entries(mem, offset, num_cpus_u8)?;
    offset = write_bus_entry(mem, offset)?;
    offset = write_ioapic_entry(mem, offset, ioapic_id)?;
    offset = write_intsrc_entries(mem, offset, ioapic_id)?;
    let _ = write_lintsrc_entries(mem, offset)?;

    let config_table_size_u16 =
        u16::try_from(config_table_size).map_err(|_| BootError::MpTableOverflow {
            size: total_table_size,
            num_cpus,
        })?;
    let total_entries_u16 =
        u16::try_from(total_entries).map_err(|_| BootError::MpTableOverflow {
            size: total_table_size,
            num_cpus,
        })?;
    write_config_header(
        mem,
        mp_config_addr,
        config_table_size_u16,
        total_entries_u16,
    )?;

    // Config table checksum
    let config_checksum = {
        let slice =
            mem.read_guest(GuestPhysAddr::new(mp_config_addr).range(config_table_size as usize)?)?;
        compute_mp_checksum(slice)
    };
    mem.write_u8_guest(GuestPhysAddr::new(mp_config_addr + 7), config_checksum)?;

    let mp_config_addr_u32 =
        u32::try_from(mp_config_addr).map_err(|_| BootError::MpTableOverflow {
            size: total_table_size,
            num_cpus,
        })?;
    write_floating_pointer(mem, mp_fp_addr, mp_config_addr_u32)?;

    let fp_checksum = {
        let slice = mem.read_guest(GuestPhysAddr::new(mp_fp_addr).range(MP_FP_SIZE as usize)?)?;
        compute_mp_checksum(slice)
    };
    mem.write_u8_guest(GuestPhysAddr::new(mp_fp_addr + 10), fp_checksum)?;

    log::debug!("MP table written at {MPTABLE_START:#x}: {num_cpus} CPUs, {total_entries} entries");

    Ok(())
}

/// Maximum CPU count supported by the fixed x86 boot MP-table placement.
#[must_use]
pub const fn max_mptable_cpus() -> usize {
    let fixed_size = MP_FP_SIZE
        + MP_CONFIG_HEADER_SIZE
        + MP_BUS_ENTRY_SIZE
        + MP_IOAPIC_ENTRY_SIZE
        + (MP_NUM_ISA_IRQS as u64 * MP_INTSRC_ENTRY_SIZE)
        + (MP_NUM_LINT_SOURCES as u64 * MP_LINTSRC_ENTRY_SIZE);
    let available = LOW_MEMORY_END - MPTABLE_START - fixed_size;
    let max_by_space = available / MP_PROC_ENTRY_SIZE;
    if max_by_space < 254 {
        max_by_space as usize
    } else {
        254
    }
}

// =============================================================================
// Table entry writers
// =============================================================================

fn write_processor_entries(
    mem: &mut BootGuestMemory<'_>,
    mut offset: u64,
    num_cpus: u8,
) -> Result<u64> {
    for cpu_id in 0..num_cpus {
        mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_PROCESSOR)?;
        mem.write_u8_guest(GuestPhysAddr::new(offset + 1), cpu_id)?;
        mem.write_u8_guest(GuestPhysAddr::new(offset + 2), LAPIC_VERSION)?;
        let cpu_flags = MP_CPU_ENABLED | if cpu_id == 0 { MP_CPU_BSP } else { 0 };
        mem.write_u8_guest(GuestPhysAddr::new(offset + 3), cpu_flags)?;
        mem.write_u32_guest(GuestPhysAddr::new(offset + 4), CPU_SIGNATURE)?;
        mem.write_u32_guest(GuestPhysAddr::new(offset + 8), CPU_FEATURE_FLAGS)?;
        offset += MP_PROC_ENTRY_SIZE;
    }
    Ok(offset)
}

fn write_bus_entry(mem: &mut BootGuestMemory<'_>, offset: u64) -> Result<u64> {
    mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_BUS)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 1), 0)?;
    mem.write_guest(GuestPhysAddr::new(offset + 2), b"ISA   ")?;
    Ok(offset + MP_BUS_ENTRY_SIZE)
}

fn write_ioapic_entry(mem: &mut BootGuestMemory<'_>, offset: u64, ioapic_id: u8) -> Result<u64> {
    mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_IOAPIC)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 1), ioapic_id)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 2), IOAPIC_VERSION)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 3), 1)?; // enabled
    mem.write_u32_guest(GuestPhysAddr::new(offset + 4), IOAPIC_ADDR)?;
    Ok(offset + MP_IOAPIC_ENTRY_SIZE)
}

fn write_intsrc_entries(
    mem: &mut BootGuestMemory<'_>,
    mut offset: u64,
    ioapic_id: u8,
) -> Result<u64> {
    for irq in 0..MP_NUM_ISA_IRQS {
        mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_INTSRC)?;
        mem.write_u8_guest(GuestPhysAddr::new(offset + 1), MP_IRQ_TYPE_VECTORED)?;
        mem.write_u16_guest(GuestPhysAddr::new(offset + 2), 0)?; // flags
        mem.write_u8_guest(GuestPhysAddr::new(offset + 4), 0)?; // bus ID
        mem.write_u8_guest(GuestPhysAddr::new(offset + 5), irq)?;
        mem.write_u8_guest(GuestPhysAddr::new(offset + 6), ioapic_id)?;
        mem.write_u8_guest(GuestPhysAddr::new(offset + 7), irq)?;
        offset += MP_INTSRC_ENTRY_SIZE;
    }
    Ok(offset)
}

fn write_lintsrc_entries(mem: &mut BootGuestMemory<'_>, offset: u64) -> Result<u64> {
    // LINT0 = ExtINT
    mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_LINTSRC)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 1), MP_IRQ_TYPE_EXTINT)?;
    mem.write_u16_guest(GuestPhysAddr::new(offset + 2), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 4), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 5), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 6), MP_DEST_ALL_APICS)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 7), 0)?;
    let offset = offset + MP_LINTSRC_ENTRY_SIZE;

    // LINT1 = NMI
    mem.write_u8_guest(GuestPhysAddr::new(offset), MP_ENTRY_LINTSRC)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 1), MP_IRQ_TYPE_NMI)?;
    mem.write_u16_guest(GuestPhysAddr::new(offset + 2), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 4), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 5), 0)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 6), MP_DEST_ALL_APICS)?;
    mem.write_u8_guest(GuestPhysAddr::new(offset + 7), 1)?;
    Ok(offset + MP_LINTSRC_ENTRY_SIZE)
}

fn write_config_header(
    mem: &mut BootGuestMemory<'_>,
    config_addr: u64,
    config_table_size: u16,
    total_entries: u16,
) -> Result<()> {
    mem.write_guest(GuestPhysAddr::new(config_addr), b"PCMP")?;
    mem.write_u16_guest(GuestPhysAddr::new(config_addr + 4), config_table_size)?;
    mem.write_u8_guest(GuestPhysAddr::new(config_addr + 6), MP_SPEC_REV_1_4)?;
    mem.write_guest(GuestPhysAddr::new(config_addr + 8), b"AMLA-VM ")?;
    mem.write_guest(GuestPhysAddr::new(config_addr + 16), b"AMLA-VM 0.1 ")?;
    mem.write_u16_guest(GuestPhysAddr::new(config_addr + 34), total_entries)?;
    mem.write_u32_guest(GuestPhysAddr::new(config_addr + 36), LAPIC_ADDR)?;
    Ok(())
}

fn write_floating_pointer(
    mem: &mut BootGuestMemory<'_>,
    fp_addr: u64,
    config_addr: u32,
) -> Result<()> {
    mem.write_guest(GuestPhysAddr::new(fp_addr), b"_MP_")?;
    mem.write_u32_guest(GuestPhysAddr::new(fp_addr + 4), config_addr)?;
    mem.write_u8_guest(GuestPhysAddr::new(fp_addr + 8), 1)?; // length in 16-byte units
    mem.write_u8_guest(GuestPhysAddr::new(fp_addr + 9), MP_SPEC_REV_1_4)?;
    Ok(())
}

/// Compute MP table checksum (all bytes must sum to 0).
pub fn compute_mp_checksum(data: &[u8]) -> u8 {
    let sum: u8 = data.iter().fold(0u8, |acc, &b| acc.wrapping_add(b));
    0u8.wrapping_sub(sum)
}
