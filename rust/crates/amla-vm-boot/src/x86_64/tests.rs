// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Unit tests for boot setup.

use std::ptr::NonNull;

use crate::x86_64::builder::{load_elf_kernel, setup_boot_params};
use crate::x86_64::memory::RamBackingRange;
use crate::x86_64::writer::GuestMemWriter;
use crate::x86_64::*;

/// Verify memory layout constants don't overlap (compile-time validation).
#[test]
fn test_memory_layout_no_overlap() {
    use consts::*;

    // Kernel load address (1MB) - used only for layout verification
    const KERNEL_LOAD_ADDR: u64 = 0x0010_0000;

    // Compile-time assertions for memory layout
    const { assert!(GDT_ADDR + GDT_SIZE <= ZERO_PAGE_ADDR) };
    const { assert!(ZERO_PAGE_ADDR + 4096 <= INITIAL_STACK_POINTER - 0x1000) };
    const { assert!(INITIAL_STACK_POINTER <= PML4_ADDR) };
    const { assert!(PML4_ADDR + 4096 <= PDPT_ADDR) };
    const { assert!(PDPT_ADDR + 4096 <= PD_ADDR) };
    const { assert!(PD_ADDR + 16384 <= HIGH_PDPT_ADDR) };
    const { assert!(HIGH_PDPT_ADDR + 4096 <= CMDLINE_ADDR) };
    const { assert!(CMDLINE_ADDR + CMDLINE_MAX_SIZE as u64 <= KERNEL_LOAD_ADDR) };
    const { assert!(MPTABLE_START < LOW_MEMORY_END) };
}

/// Verify CPU register setup produces valid long mode state.
#[test]
fn test_cpu_state_long_mode() {
    use consts::*;

    let entry_point = 0x100_0000; // Typical kernel entry
    let state = cpu_state::setup_cpu_state(entry_point);

    // RIP points to entry
    assert_eq!(state.rip, entry_point);

    // RSI points to boot params
    assert_eq!(state.rsi, ZERO_PAGE_ADDR);

    // RFLAGS has reserved bit set
    assert_ne!(state.rflags & RFLAGS_RESERVED_BIT, 0);

    // Code segment is 64-bit
    assert_eq!(state.cs.selector, GDT_SELECTOR_CODE);
    assert_eq!(state.cs.l, 1); // Long mode flag

    // Data segments use correct selector
    assert_eq!(state.ds.selector, GDT_SELECTOR_DATA);
    assert_eq!(state.ss.selector, GDT_SELECTOR_DATA);

    // TSS is present (required for 64-bit mode)
    assert_eq!(state.tr.selector, GDT_SELECTOR_TSS);
    assert_eq!(state.tr.present, 1);

    // Long mode is enabled in EFER
    assert_ne!(state.efer & EFER_LME, 0);
    assert_ne!(state.efer & EFER_LMA, 0);

    // Paging is enabled
    assert_ne!(state.cr0 & CR0_PG, 0);

    // PAE is enabled (required for long mode)
    assert_ne!(state.cr4 & CR4_PAE, 0);

    // CR3 points to PML4
    assert_eq!(state.cr3, PML4_ADDR);
}

/// Verify GDT descriptor values are correct.
#[test]
fn test_gdt_descriptors() {
    use consts::*;

    // 64-bit code segment: L=1, D=0, executable
    assert_eq!(GDT_ENTRY_CODE64, 0x00AF_9B00_0000_FFFF);

    // 64-bit data segment: L=0, D=1, writable
    assert_eq!(GDT_ENTRY_DATA64, 0x00CF_9300_0000_FFFF);

    // 64-bit TSS: present, type=9
    assert_eq!(GDT_ENTRY_TSS64_LOW, 0x0000_8900_0000_0067);
}

/// Verify MP table constants are consistent.
#[test]
fn test_mp_table_constants() {
    use consts::*;

    // MP floating pointer is 16 bytes
    assert_eq!(MP_FP_SIZE, 16);

    // MP config header is 44 bytes
    assert_eq!(MP_CONFIG_HEADER_SIZE, 44);

    // Entry sizes match MP spec
    assert_eq!(MP_PROC_ENTRY_SIZE, 20);
    assert_eq!(MP_BUS_ENTRY_SIZE, 8);
    assert_eq!(MP_IOAPIC_ENTRY_SIZE, 8);
    assert_eq!(MP_INTSRC_ENTRY_SIZE, 8);
    assert_eq!(MP_LINTSRC_ENTRY_SIZE, 8);
}

/// Verify `GuestMemWriter` catches out-of-bounds writes.
#[test]
fn test_guest_mem_writer_bounds_check() {
    let mut buf = [0u8; 100];
    // SAFETY: buf is a stack array; pointer is valid for 100 bytes.
    let writer = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 100) };
    // This should fail: writing 8 bytes at offset 96 would access bytes 96-103,
    // but buffer is only 100 bytes (valid range 0-99)
    let err = writer
        .write_at(
            RamBackingRange::new_for_test(96, 8),
            &0x1234u64.to_le_bytes(),
        )
        .unwrap_err();
    assert!(matches!(err, BootError::GuestMemoryOutOfBounds { .. }));
}

// =========================================================================
// Helper: allocate a guest memory buffer and return (buf, NonNull)
// =========================================================================

/// Allocate a zeroed buffer simulating guest physical memory.
fn guest_mem(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

fn boot_guest_mem(buf: &mut [u8]) -> BootGuestMemory<'_> {
    boot_guest_mem_with_holes(buf, amla_core::MEMORY_HOLES)
}

fn boot_guest_mem_with_holes<'a>(
    buf: &'a mut [u8],
    holes: amla_core::MemoryHoles<'_>,
) -> BootGuestMemory<'a> {
    let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
    let layout = BootRamLayout::from_ram(GuestPhysAddr::new(0), buf.len(), holes).unwrap();
    // SAFETY: `buf` is writable and uniquely borrowed for the returned boot memory.
    unsafe { BootGuestMemory::from_raw_parts(ptr, buf.len(), layout).unwrap() }
}

fn page_table_test_mem<'a>(
    buf: &'a mut [u8],
    ram_size: usize,
    holes: amla_core::MemoryHoles<'_>,
) -> BootGuestMemory<'a> {
    let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
    let layout = BootRamLayout::from_ram(GuestPhysAddr::new(0), ram_size, holes).unwrap();
    // SAFETY: page-table setup only writes fixed low boot workspace pages in
    // these tests; the oversized layout is the behavior under test.
    unsafe { BootGuestMemory::from_raw_parts_for_test(ptr, buf.len(), layout) }
}

/// Convert a u64 address to usize (panics on 32-bit targets; these tests are 64-bit only).
fn addr(v: u64) -> usize {
    usize::try_from(v).unwrap()
}

/// Read a little-endian u8 from a buffer at the given offset.
fn read_u8(buf: &[u8], offset: usize) -> u8 {
    buf[offset]
}

/// Read a little-endian u16 from a buffer at the given offset.
fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(buf[offset..offset + 2].try_into().unwrap())
}

/// Read a little-endian u32 from a buffer at the given offset.
fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(buf[offset..offset + 4].try_into().unwrap())
}

/// Read a little-endian u64 from a buffer at the given offset.
fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(buf[offset..offset + 8].try_into().unwrap())
}

fn read_e820_entries(buf: &[u8]) -> Vec<(u64, u64, u32)> {
    use consts::{BP_E820_ENTRIES, BP_E820_TABLE, E820_ENTRY_SIZE, ZERO_PAGE_ADDR};

    let count = usize::from(read_u8(buf, addr(ZERO_PAGE_ADDR + BP_E820_ENTRIES)));
    (0..count)
        .map(|index| {
            let entry = addr(ZERO_PAGE_ADDR + BP_E820_TABLE + index as u64 * E820_ENTRY_SIZE);
            (
                read_u64(buf, entry),
                read_u64(buf, entry + 8),
                read_u32(buf, entry + 16),
            )
        })
        .collect()
}

fn assert_e820_sorted_non_overlapping(entries: &[(u64, u64, u32)]) {
    let mut prev_end = None;
    for &(start, size, _) in entries {
        let end = start.checked_add(size).unwrap();
        if let Some(prev_end) = prev_end {
            assert!(
                start >= prev_end,
                "E820 entry [{start:#x}..{end:#x}) overlaps or sorts before previous end {prev_end:#x}"
            );
        }
        prev_end = Some(end);
    }
}

fn identity_mapping(buf: &[u8], gpa: u64) -> Option<(u64, u64)> {
    use consts::*;

    const PAGE_4K: u64 = 4096;
    const PAGE_2M: u64 = 2 << 20;
    const PAGE_1G: u64 = 1 << 30;

    let pml4_index = (gpa >> 39) & 0x1FF;
    let pml4_entry = read_u64(buf, addr(PML4_ADDR + pml4_index * 8));
    if pml4_entry & PAGE_PRESENT == 0 {
        return None;
    }

    let pdpt_addr = pml4_entry & !0xFFF;
    let pdpt_index = (gpa >> 30) & 0x1FF;
    let pdpt_entry = read_u64(buf, addr(pdpt_addr + pdpt_index * 8));
    if pdpt_entry & PAGE_PRESENT == 0 {
        return None;
    }
    if pdpt_entry & PAGE_SIZE != 0 {
        return Some((pdpt_entry & !(PAGE_1G - 1), PAGE_1G));
    }

    let directory_addr = pdpt_entry & !0xFFF;
    let directory_index = (gpa >> 21) & 0x1FF;
    let directory_entry = read_u64(buf, addr(directory_addr + directory_index * 8));
    if directory_entry & PAGE_PRESENT == 0 {
        return None;
    }
    if directory_entry & PAGE_SIZE != 0 {
        return Some((directory_entry & !(PAGE_2M - 1), PAGE_2M));
    }

    let table_addr = directory_entry & !0xFFF;
    let table_index = (gpa >> 12) & 0x1FF;
    let table_entry = read_u64(buf, addr(table_addr + table_index * 8));
    if table_entry & PAGE_PRESENT == 0 {
        return None;
    }
    Some((table_entry & !(PAGE_4K - 1), PAGE_4K))
}

fn assert_identity_present(buf: &[u8], gpa: u64) -> u64 {
    let Some((base, size)) = identity_mapping(buf, gpa) else {
        panic!("expected GPA {gpa:#x} to be identity mapped");
    };
    assert_eq!(base, gpa & !(size - 1), "GPA {gpa:#x} maps to wrong base");
    size
}

fn assert_identity_absent(buf: &[u8], gpa: u64) {
    assert!(
        identity_mapping(buf, gpa).is_none(),
        "expected GPA {gpa:#x} to be unmapped"
    );
}

// =========================================================================
// BootRamLayout translation tests
// =========================================================================

fn test_hole(start: u64, end: u64, advertise_reserved: bool) -> amla_core::MemoryHole {
    amla_core::MemoryHole {
        start,
        end,
        advertise_reserved,
    }
}

fn memory_holes(holes: &[amla_core::MemoryHole]) -> amla_core::MemoryHoles<'_> {
    amla_core::MemoryHoles::new(holes).unwrap()
}

#[test]
fn test_boot_ram_layout_translates_before_and_after_hole() {
    let holes = [test_hole(0x0020_0000, 0x0030_0000, true)];
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), 4 * 1024 * 1024, memory_holes(&holes))
            .unwrap();

    let before = layout
        .translate_contiguous(GuestPhysAddr::new(0x0010_0000), 0x1000)
        .unwrap();
    assert_eq!(before.offset(), 0x0010_0000);

    let after = layout
        .translate_contiguous(GuestPhysAddr::new(0x0030_1000), 0x1000)
        .unwrap();
    assert_eq!(after.offset(), 0x0020_1000);
}

#[test]
fn test_boot_ram_layout_translates_before_and_after_virtio_mmio_hole() {
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), 0x0A20_0000, amla_core::MEMORY_HOLES)
            .unwrap();

    let before = layout
        .translate_contiguous(GuestPhysAddr::new(0x09FF_F000), 0x1000)
        .unwrap();
    assert_eq!(before.offset(), 0x09FF_F000);

    let after = layout
        .translate_contiguous(GuestPhysAddr::new(0x0A00_8000), 0x1000)
        .unwrap();
    assert_eq!(after.offset(), 0x0A00_0000);
}

#[test]
fn test_boot_ram_layout_rejects_range_crossing_hole() {
    let holes = [test_hole(0x0020_0000, 0x0030_0000, true)];
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), 4 * 1024 * 1024, memory_holes(&holes))
            .unwrap();

    let err = layout
        .translate_contiguous(GuestPhysAddr::new(0x001F_F000), 0x2000)
        .unwrap_err();
    assert!(matches!(err, BootError::GuestRangeUnmapped { .. }));
}

#[test]
fn test_boot_ram_layout_large_ram_crosses_both_x86_holes() {
    let backing_before_pci_hole = 0xE000_0000usize - 0x8000;
    let ram_size = backing_before_pci_hole + 2 * 1024 * 1024;
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), ram_size, amla_core::MEMORY_HOLES).unwrap();

    let after_virtio = layout
        .translate_contiguous(GuestPhysAddr::new(0x0A00_8000), 0x1000)
        .unwrap();
    assert_eq!(after_virtio.offset(), 0x0A00_0000);

    let after_pci = layout
        .translate_contiguous(GuestPhysAddr::new(0x1_0000_0000), 0x1000)
        .unwrap();
    assert_eq!(after_pci.offset(), backing_before_pci_hole);
    assert_eq!(layout.last_guest_end().unwrap().as_u64(), 0x1_0020_0000);
}

#[test]
fn test_boot_ram_layout_from_vm_state_uses_view_guest_mappings() {
    let region = amla_core::vm_state::test_mmap(4 * 1024 * 1024);
    let mapped = amla_core::vm_state::MappedVmState::new(region, 0x09F0_0000).unwrap();
    let view = mapped.view().unwrap();

    let layout = BootRamLayout::from_vm_state(&view).unwrap();
    let after = layout
        .translate_contiguous(GuestPhysAddr::new(0x0A00_8000), 0x1000)
        .unwrap();

    assert_eq!(view.guest_region_count(), 2);
    assert_eq!(after.offset(), 0x0010_0000);
}

#[test]
fn test_boot_ram_layout_from_vm_state_rejects_unsplit_hole_mapping() {
    let region = amla_core::vm_state::test_mmap(4 * 1024 * 1024);
    let view = amla_core::vm_state::make_test_vmstate(&region, 0x09F0_0000);

    let err = BootRamLayout::from_vm_state(&view).unwrap_err();
    assert!(
        matches!(err, BootError::InvalidBootMemory { .. }),
        "Expected InvalidBootMemory, got {err:?}"
    );
}

#[test]
fn test_boot_guest_memory_from_vm_state_accepts_view_ram_layout() {
    let region = amla_core::vm_state::test_mmap(16 * 1024 * 1024);
    let mapped = amla_core::vm_state::MappedVmState::new(region, 0).unwrap();
    let view = mapped.view().unwrap();

    // SAFETY: this test creates one boot-memory writer for a private mmap.
    let mem = unsafe { BootGuestMemory::from_vm_state(&view, mapped.unified()) }.unwrap();

    assert_eq!(mem.layout().backing_len(), 16 * 1024 * 1024);
    assert_eq!(mem.layout().ram_segments().len(), 1);
}

#[test]
fn test_low_boot_workspace_validation_fails_if_hole_overlaps_zero_page() {
    let mut buf = guest_mem(2 * 1024 * 1024);
    let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
    let holes = [test_hole(
        consts::ZERO_PAGE_ADDR,
        consts::ZERO_PAGE_ADDR + 0x1000,
        true,
    )];
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), buf.len(), memory_holes(&holes)).unwrap();

    // SAFETY: `buf` is valid for its full length.
    let Err(err) = (unsafe { BootGuestMemory::from_raw_parts(ptr, buf.len(), layout) }) else {
        panic!("expected zero-page workspace validation to fail");
    };
    assert!(matches!(
        err,
        BootError::BootWorkspaceUnmapped {
            region: "zero page",
            ..
        }
    ));
}

#[test]
fn test_elf_segment_after_hole_writes_translated_backing_offset() {
    let holes = [test_hole(0x0020_0000, 0x0030_0000, true)];
    let mut buf = guest_mem(4 * 1024 * 1024);
    let mut mem = boot_guest_mem_with_holes(&mut buf, memory_holes(&holes));
    let kernel = minimal_elf64_with_load(0x0030_0000, 0x1000);

    load_elf_kernel(&mut mem, &kernel).unwrap();

    assert_eq!(&buf[0x0020_0000..0x0020_0004], b"BOOT");
    assert_eq!(&buf[0x0030_0000..0x0030_0004], &[0, 0, 0, 0]);
}

#[test]
fn test_elf_segment_crossing_hole_is_rejected() {
    let holes = [test_hole(0x0020_0000, 0x0030_0000, true)];
    let mut buf = guest_mem(4 * 1024 * 1024);
    let mut mem = boot_guest_mem_with_holes(&mut buf, memory_holes(&holes));
    let kernel = minimal_elf64_with_load(0x001F_F000, 0x3000);

    let err = load_elf_kernel(&mut mem, &kernel).unwrap_err();
    assert!(matches!(err, BootError::GuestRangeUnmapped { .. }));
}

// =========================================================================
// MP table tests
// =========================================================================

#[test]
fn test_mptable_single_cpu() {
    use consts::*;

    let mut buf = guest_mem(1 << 20); // 1MB
    let mut mem = boot_guest_mem(&mut buf);
    mptable::setup_mptable(&mut mem, 1).expect("setup_mptable failed");

    let fp = addr(MPTABLE_START);
    let config = fp + addr(MP_FP_SIZE);

    // MP floating pointer: "_MP_" signature
    assert_eq!(&buf[fp..fp + 4], b"_MP_");
    // Points to config table
    assert_eq!(read_u32(&buf, fp + 4), u32::try_from(config).unwrap());
    // Length = 1 (16-byte unit)
    assert_eq!(read_u8(&buf, fp + 8), 1);
    // Spec rev 1.4
    assert_eq!(read_u8(&buf, fp + 9), MP_SPEC_REV_1_4);

    // Config table: "PCMP" signature
    assert_eq!(&buf[config..config + 4], b"PCMP");
    // Spec rev
    assert_eq!(read_u8(&buf, config + 6), MP_SPEC_REV_1_4);
    // OEM ID
    assert_eq!(&buf[config + 8..config + 16], b"AMLA-VM ");

    // Entry count: 1 proc + 1 bus + 1 ioapic + 16 intsrc + 2 lintsrc = 21
    assert_eq!(read_u16(&buf, config + 34), 21);

    // LAPIC address
    assert_eq!(read_u32(&buf, config + 36), LAPIC_ADDR);

    // First processor entry: CPU 0 is BSP + enabled
    let proc0 = config + addr(MP_CONFIG_HEADER_SIZE);
    assert_eq!(read_u8(&buf, proc0), MP_ENTRY_PROCESSOR);
    assert_eq!(read_u8(&buf, proc0 + 1), 0); // APIC ID
    assert_eq!(read_u8(&buf, proc0 + 3), MP_CPU_ENABLED | MP_CPU_BSP);

    // IOAPIC entry (after proc + bus)
    let ioapic = proc0 + addr(MP_PROC_ENTRY_SIZE) + addr(MP_BUS_ENTRY_SIZE);
    assert_eq!(read_u8(&buf, ioapic), MP_ENTRY_IOAPIC);
    assert_eq!(read_u8(&buf, ioapic + 1), 1); // IOAPIC ID = num_cpus
    assert_eq!(read_u32(&buf, ioapic + 4), IOAPIC_ADDR);

    // Verify both checksums (all bytes must sum to 0)
    let fp_sum: u8 = buf[fp..fp + addr(MP_FP_SIZE)]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(fp_sum, 0, "FP checksum invalid");

    let config_size = usize::from(read_u16(&buf, config + 4));
    let config_sum: u8 = buf[config..config + config_size]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(config_sum, 0, "Config table checksum invalid");
}

#[test]
fn test_mptable_multi_cpu() {
    use consts::*;

    let mut buf = guest_mem(1 << 20);
    let mut mem = boot_guest_mem(&mut buf);
    mptable::setup_mptable(&mut mem, 4).expect("setup_mptable 4 CPUs");

    let config = addr(MPTABLE_START + MP_FP_SIZE);

    // 4 proc + 1 bus + 1 ioapic + 16 intsrc + 2 lintsrc = 24
    assert_eq!(read_u16(&buf, config + 34), 24);

    // Verify 4 processor entries
    let mut offset = config + addr(MP_CONFIG_HEADER_SIZE);
    for cpu_id in 0u8..4 {
        assert_eq!(read_u8(&buf, offset), MP_ENTRY_PROCESSOR);
        assert_eq!(read_u8(&buf, offset + 1), cpu_id);
        let expected_flags = MP_CPU_ENABLED | if cpu_id == 0 { MP_CPU_BSP } else { 0 };
        assert_eq!(
            read_u8(&buf, offset + 3),
            expected_flags,
            "CPU {cpu_id} flags"
        );
        offset += addr(MP_PROC_ENTRY_SIZE);
    }

    // IOAPIC ID should be 4 (comes after CPU IDs)
    let ioapic = offset + addr(MP_BUS_ENTRY_SIZE); // skip bus entry
    assert_eq!(read_u8(&buf, ioapic + 1), 4);

    // Both checksums valid
    let fp = addr(MPTABLE_START);
    let fp_sum: u8 = buf[fp..fp + addr(MP_FP_SIZE)]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(fp_sum, 0);

    let config_size = usize::from(read_u16(&buf, config + 4));
    let config_sum: u8 = buf[config..config + config_size]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(config_sum, 0);
}

#[test]
fn test_mptable_max_fitting_cpus() {
    // 40 CPUs is near the max that fits in the ~1KB EBDA area
    let mut buf = guest_mem(1 << 20);
    let mut mem = boot_guest_mem(&mut buf);
    mptable::setup_mptable(&mut mem, 40).expect("40 CPUs should fit");

    let config = addr(consts::MPTABLE_START + consts::MP_FP_SIZE);
    let config_size = usize::from(read_u16(&buf, config + 4));
    let config_sum: u8 = buf[config..config + config_size]
        .iter()
        .fold(0u8, |acc, &b| acc.wrapping_add(b));
    assert_eq!(config_sum, 0, "Checksum must be valid for 40 CPUs");
}

#[test]
fn test_mptable_zero_cpus_error() {
    let mut buf = guest_mem(1 << 20);
    let mut mem = boot_guest_mem(&mut buf);
    let err = mptable::setup_mptable(&mut mem, 0).unwrap_err();
    assert!(
        matches!(err, BootError::InvalidCpuCount { requested: 0, .. }),
        "Expected InvalidCpuCount(0), got {err:?}"
    );
}

#[test]
fn test_mptable_overflow_error() {
    let mut buf = guest_mem(1 << 20);
    let mut mem = boot_guest_mem(&mut buf);
    // 255 is out of the 1-254 range
    let err = mptable::setup_mptable(&mut mem, 255).unwrap_err();
    assert!(
        matches!(err, BootError::InvalidCpuCount { requested: 255, .. }),
        "Expected InvalidCpuCount(255), got {err:?}"
    );
}

#[test]
fn test_mptable_rejects_counts_above_fixed_capacity() {
    let mut buf = guest_mem(1 << 20);
    let mut mem = boot_guest_mem(&mut buf);
    let err = mptable::setup_mptable(&mut mem, 254).unwrap_err();
    assert!(
        matches!(
            err,
            BootError::InvalidCpuCount {
                requested: 254,
                max: 40
            }
        ),
        "Expected InvalidCpuCount for fixed MP-table capacity, got {err:?}"
    );
}

#[test]
fn test_mp_checksum_direct() {
    // compute_mp_checksum should produce a two's complement value
    let data = [1u8, 2, 3, 4, 5];
    let sum: u8 = data.iter().fold(0u8, |a, &b| a.wrapping_add(b)); // 15
    let checksum = mptable::compute_mp_checksum(&data);
    // checksum + sum should be 0 mod 256
    assert_eq!(sum.wrapping_add(checksum), 0);

    // All zeros should produce checksum 0
    let zeros = [0u8; 10];
    let c = mptable::compute_mp_checksum(&zeros);
    assert_eq!(c, 0);
}

// =========================================================================
// Page table tests
// =========================================================================

#[test]
fn test_page_tables_4mb() {
    use consts::*;

    let mem_size = 4 * 1024 * 1024; // 4MB
    let mut buf = guest_mem(mem_size);
    let mut mem = boot_guest_mem(&mut buf);
    page_tables::setup_page_tables(&mut mem).unwrap();

    // PML4[0] -> PDPT with present + writable
    let pml4_0 = read_u64(&buf, addr(PML4_ADDR));
    assert_eq!(pml4_0 & !0xFFF, PDPT_ADDR); // address bits
    assert_ne!(pml4_0 & PAGE_PRESENT, 0);
    assert_ne!(pml4_0 & PAGE_WRITABLE, 0);

    // PML4[511] -> HIGH_PDPT
    let pml4_511 = read_u64(&buf, addr(PML4_ADDR + 511 * 8));
    assert_eq!(pml4_511 & !0xFFF, HIGH_PDPT_ADDR);

    // PDPT[0] -> PD[0]
    let pdpt_0 = read_u64(&buf, addr(PDPT_ADDR));
    assert_eq!(pdpt_0 & !0xFFF, PD_ADDR);

    // PD[0] should have 2 entries for 4MB (2 x 2MB huge pages)
    let pd0_entry0 = read_u64(&buf, addr(PD_ADDR));
    assert_eq!(pd0_entry0 & !0xFFF, 0); // maps PA 0
    assert_ne!(pd0_entry0 & PAGE_SIZE, 0, "PS bit must be set for 2MB page");
    assert_ne!(pd0_entry0 & PAGE_PRESENT, 0);

    let pd0_entry1 = read_u64(&buf, addr(PD_ADDR + 8));
    assert_eq!(pd0_entry1 & !0xFFF, 0x0020_0000); // maps PA 2MB

    // PD entry 2 should be zero (no more memory)
    assert_eq!(read_u64(&buf, addr(PD_ADDR + 16)), 0);
}

#[test]
fn test_page_tables_4gb() {
    use consts::*;

    let mem_size = 4 * 1024 * 1024 * 1024; // 4GB
    let mut buf = guest_mem(1 << 20);
    let mut mem = page_table_test_mem(&mut buf, mem_size, amla_core::MemoryHoles::EMPTY);
    page_tables::setup_page_tables(&mut mem).unwrap();

    // All 4 PDPT entries should point to PD tables
    for i in 0u64..4 {
        let pdpt_entry = read_u64(&buf, addr(PDPT_ADDR + i * 8));
        let expected_pd = PD_ADDR + i * 4096;
        assert_eq!(
            pdpt_entry & !0xFFF,
            expected_pd,
            "PDPT[{i}] should point to PD[{i}]"
        );
    }

    // Each PD should have 512 entries (full GB mapped)
    for i in 0u64..4 {
        let pd_addr = PD_ADDR + i * 4096;
        for j in 0u64..512 {
            let entry = read_u64(&buf, addr(pd_addr + j * 8));
            let expected_pa = (i << 30) | (j << 21);
            assert_eq!(entry & !0xFFF, expected_pa, "PD[{i}][{j}] address mismatch");
            assert_ne!(entry & PAGE_SIZE, 0);
        }
    }

    // Higher-half: HIGH_PDPT[510] -> PD[0], HIGH_PDPT[511] -> PD[1]
    let high_510 = read_u64(&buf, addr(HIGH_PDPT_ADDR + 510 * 8));
    assert_eq!(high_510 & !0xFFF, PD_ADDR);
    let high_511 = read_u64(&buf, addr(HIGH_PDPT_ADDR + 511 * 8));
    assert_eq!(high_511 & !0xFFF, PD_ADDR + 4096);
}

#[test]
fn test_page_tables_8gb() {
    use consts::*;

    let mem_size = 8 * 1024 * 1024 * 1024; // 8GB
    let mut buf = guest_mem(1 << 20);
    let mut mem = page_table_test_mem(&mut buf, mem_size, amla_core::MemoryHoles::EMPTY);
    page_tables::setup_page_tables(&mut mem).unwrap();

    // PDPT[0..4] use PD tables (2MB pages)
    for i in 0u64..4 {
        let entry = read_u64(&buf, addr(PDPT_ADDR + i * 8));
        assert_eq!(entry & PAGE_SIZE, 0, "PDPT[{i}] should NOT have PS bit");
        assert_ne!(entry & PAGE_PRESENT, 0);
    }

    // PDPT[4..8] use 1GB huge pages directly
    for i in 4u64..8 {
        let entry = read_u64(&buf, addr(PDPT_ADDR + i * 8));
        let expected_pa = i << 30;
        assert_eq!(entry & !0xFFF, expected_pa, "PDPT[{i}] address mismatch");
        assert_ne!(
            entry & PAGE_SIZE,
            0,
            "PDPT[{i}] should have PS bit for 1GB page"
        );
    }
}

#[test]
fn test_page_tables_higher_half() {
    use consts::*;

    // Small memory (1GB): only HIGH_PDPT[510] mapped
    let mem_size = 64 * 1024 * 1024;
    let mut buf = guest_mem(1 << 20);
    let mut mem = page_table_test_mem(&mut buf, mem_size, amla_core::MemoryHoles::EMPTY);
    page_tables::setup_page_tables(&mut mem).unwrap();

    let high_510 = read_u64(&buf, addr(HIGH_PDPT_ADDR + 510 * 8));
    assert_ne!(high_510 & PAGE_PRESENT, 0, "HIGH_PDPT[510] must be present");
    assert_eq!(high_510 & !0xFFF, PD_ADDR);

    // With only 1GB, HIGH_PDPT[511] should be 0 (no second GB to map)
    let high_511 = read_u64(&buf, addr(HIGH_PDPT_ADDR + 511 * 8));
    assert_eq!(high_511, 0, "HIGH_PDPT[511] should be empty for 1GB");

    // Larger memory (2GB+): both mapped
    let mem_size = 2 * 1024 * 1024 * 1024;
    let mut buf = guest_mem(1 << 20);
    let mut mem = page_table_test_mem(&mut buf, mem_size, amla_core::MemoryHoles::EMPTY);
    page_tables::setup_page_tables(&mut mem).unwrap();

    let high_511 = read_u64(&buf, addr(HIGH_PDPT_ADDR + 511 * 8));
    assert_ne!(
        high_511 & PAGE_PRESENT,
        0,
        "HIGH_PDPT[511] must be present for >=2GB"
    );
    assert_eq!(high_511 & !0xFFF, PD_ADDR + 4096);
}

#[test]
fn test_page_tables_non_gb_aligned_above_4gb_error() {
    // 5 GB + 512 MB is allowed; the final 512 MiB is mapped with 2 MiB entries.
    let mem_size = 5 * 1024 * 1024 * 1024 + 512 * 1024 * 1024;
    let mut buf = guest_mem(1 << 20);
    let mut mem = page_table_test_mem(&mut buf, mem_size, amla_core::MemoryHoles::EMPTY);
    page_tables::setup_page_tables(&mut mem).unwrap();
}

#[test]
fn test_page_tables_split_unaligned_ram_hole_with_4k_entries() {
    let hole_start = 0x0060_3000;
    let hole_end = 0x0060_6000;
    let holes = [test_hole(hole_start, hole_end, true)];
    let mut buf = guest_mem(8 * 1024 * 1024);
    let mut mem = boot_guest_mem_with_holes(&mut buf, memory_holes(&holes));

    page_tables::setup_page_tables(&mut mem).unwrap();

    assert_identity_present(&buf, hole_start - 0x1000);
    assert_identity_absent(&buf, hole_start);
    assert_identity_absent(&buf, hole_end - 0x1000);
    assert_eq!(
        assert_identity_present(&buf, hole_end),
        4096,
        "the 2 MiB block containing a small hole must be split to 4 KiB pages"
    );
}

#[test]
fn test_page_tables_leave_virtio_mmio_hole_unmapped() {
    let mut buf = guest_mem(1 << 20);
    let ram_size = 0x0A20_0000;
    let mut mem = page_table_test_mem(&mut buf, ram_size, amla_core::MEMORY_HOLES);

    page_tables::setup_page_tables(&mut mem).unwrap();

    assert_identity_present(&buf, 0x09FF_F000);
    assert_identity_absent(&buf, 0x0A00_0000);
    assert_identity_absent(&buf, 0x0A00_7000);
    assert_eq!(
        assert_identity_present(&buf, 0x0A00_8000),
        4096,
        "RAM immediately after the virtio-MMIO hole needs a 4 KiB PTE"
    );
}

#[test]
fn test_page_tables_leave_pci_hole_unmapped_and_map_tail_ram() {
    let mut buf = guest_mem(1 << 20);
    let backing_before_pci_hole = 0xE000_0000usize - 0x8000;
    let ram_size = backing_before_pci_hole + 2 * 1024 * 1024;
    let mut mem = page_table_test_mem(&mut buf, ram_size, amla_core::MEMORY_HOLES);

    page_tables::setup_page_tables(&mut mem).unwrap();

    assert_identity_present(&buf, 0xDFFF_F000);
    assert_identity_absent(&buf, 0xE000_0000);
    assert_identity_absent(&buf, 0xF000_0000);
    assert_eq!(
        assert_identity_present(&buf, 0x1_0000_0000),
        2 << 20,
        "RAM after the PCI hole should be reachable without mapping the hole"
    );
}

#[test]
fn test_e820_and_page_tables_reflect_same_layout_hole() {
    use consts::*;

    let hole_start = 0x0060_0000;
    let hole_end = 0x0070_0000;
    let holes = [test_hole(hole_start, hole_end, true)];
    let mut buf = guest_mem(8 * 1024 * 1024);
    let mut mem = boot_guest_mem_with_holes(&mut buf, memory_holes(&holes));

    setup_boot_params(&mut mem, "console=ttyS0").unwrap();
    page_tables::setup_page_tables(&mut mem).unwrap();

    let e820 = read_e820_entries(&buf);
    assert!(e820.contains(&(HIGH_MEMORY_START, hole_start - HIGH_MEMORY_START, E820_TYPE_RAM)));
    assert!(e820.contains(&(hole_start, hole_end - hole_start, E820_TYPE_RESERVED)));
    assert_identity_present(&buf, hole_start - 0x1000);
    assert_identity_absent(&buf, hole_start);
    assert_identity_present(&buf, hole_end);
}

// =========================================================================
// GuestMemWriter tests
// =========================================================================

#[test]
fn test_guest_mem_writer_u8() {
    let mut buf = [0u8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.write_at(RamBackingRange::new_for_test(10, 1), &[0xAB])
        .unwrap();
    assert_eq!(buf[10], 0xAB);
}

#[test]
fn test_guest_mem_writer_u16() {
    let mut buf = [0u8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.write_at(
        RamBackingRange::new_for_test(20, 2),
        &0x1234u16.to_le_bytes(),
    )
    .unwrap();
    assert_eq!(u16::from_le_bytes([buf[20], buf[21]]), 0x1234);
}

#[test]
fn test_guest_mem_writer_u32() {
    let mut buf = [0u8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.write_at(
        RamBackingRange::new_for_test(8, 4),
        &0xDEAD_BEEFu32.to_le_bytes(),
    )
    .unwrap();
    assert_eq!(
        u32::from_le_bytes(buf[8..12].try_into().unwrap()),
        0xDEAD_BEEF
    );
}

#[test]
fn test_guest_mem_writer_u64() {
    let mut buf = [0u8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.write_at(
        RamBackingRange::new_for_test(0, 8),
        &0x0123_4567_89AB_CDEFu64.to_le_bytes(),
    )
    .unwrap();
    assert_eq!(
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        0x0123_4567_89AB_CDEF
    );
}

#[test]
fn test_guest_mem_writer_write_bytes() {
    let mut buf = [0u8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.write_at(RamBackingRange::new_for_test(5, 5), b"hello")
        .unwrap();
    assert_eq!(&buf[5..10], b"hello");
}

#[test]
fn test_guest_mem_writer_zero() {
    let mut buf = [0xFFu8; 64];
    // SAFETY: buf is a stack array; pointer is valid for 64 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 64) };
    w.zero_at(RamBackingRange::new_for_test(10, 20)).unwrap();
    assert!(buf[10..30].iter().all(|&b| b == 0));
    assert_eq!(buf[9], 0xFF); // untouched
    assert_eq!(buf[30], 0xFF); // untouched
}

#[test]
fn test_guest_mem_writer_boundary() {
    let mut buf = [0u8; 16];
    // SAFETY: buf is a stack array; pointer is valid for 16 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 16) };
    // Write u64 at last valid position (offset 8, bytes 8..16)
    w.write_at(
        RamBackingRange::new_for_test(8, 8),
        &0xFFFF_FFFF_FFFF_FFFFu64.to_le_bytes(),
    )
    .unwrap();
    assert_eq!(
        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        0xFFFF_FFFF_FFFF_FFFF
    );
}

#[test]
fn test_guest_mem_writer_oob() {
    let mut buf = [0u8; 16];
    // SAFETY: buf is a stack array; pointer is valid for 16 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 16) };
    // Writing u64 at offset 9 needs bytes 9..17, which is OOB.
    let err = w
        .write_at(
            RamBackingRange::new_for_test(9, 8),
            &0x1234u64.to_le_bytes(),
        )
        .unwrap_err();
    assert!(matches!(err, BootError::GuestMemoryOutOfBounds { .. }));
}

#[test]
fn test_guest_mem_writer_offset_len_overflow() {
    // The checked-add path must catch offset+len overflow before pointer math.
    let mut buf = [0u8; 16];
    // SAFETY: buf is a stack array; pointer is valid for 16 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 16) };
    let err = w
        .write_at(RamBackingRange::new_for_test(usize::MAX, 1), &[0])
        .unwrap_err();
    assert!(matches!(err, BootError::GuestMemoryOutOfBounds { .. }));
}

#[test]
fn test_boot_builder_defaults() {
    let kernel = [0u8; 64];
    let mut buf = guest_mem(2 * 1024 * 1024);
    let mem = boot_guest_mem(&mut buf);
    let b = LinuxBootBuilder::new(mem, &kernel);
    // Verify default fields via the builder's public behavior:
    // cmdline default is "console=ttyS0", num_cpus default is 1
    // We can't inspect private fields, but we can chain and verify no panic
    let b = b.cmdline_append("rdinit=/init");
    // This should not panic — just verify construction works
    drop(b);
}

#[test]
fn test_boot_builder_cmdline_append() {
    let kernel = [0u8; 64];
    let mut buf = guest_mem(2 * 1024 * 1024);
    let mem = boot_guest_mem(&mut buf);
    let b = LinuxBootBuilder::new(mem, &kernel).cmdline_append("rdinit=/init");
    // Append to empty extra shouldn't add space
    let mut buf2 = guest_mem(2 * 1024 * 1024);
    let mem2 = boot_guest_mem(&mut buf2);
    let b2 = LinuxBootBuilder::new(mem2, &kernel).cmdline_append("");
    drop(b);
    drop(b2);
}

#[test]
fn test_boot_builder_num_cpus() {
    let kernel = [0u8; 64];
    let mut buf = guest_mem(2 * 1024 * 1024);
    let mem = boot_guest_mem(&mut buf);
    // Setting num_cpus should not panic for valid values
    let b = LinuxBootBuilder::new(mem, &kernel).num_cpus(4);
    drop(b);
}

#[test]
fn test_boot_builder_num_cpus_zero_deferred_error() {
    // num_cpus(0) no longer panics — validation is deferred to build()
    let kernel = [0u8; 64];
    let mut buf = guest_mem(16 * 1024 * 1024);
    let mem = boot_guest_mem(&mut buf);
    let err = LinuxBootBuilder::new(mem, &kernel)
        .num_cpus(0)
        .build()
        .unwrap_err();
    assert!(
        matches!(err, BootError::InvalidCpuCount { requested: 0, .. }),
        "Expected InvalidCpuCount(0), got {err:?}"
    );
}

// =========================================================================
// setup_boot_params tests
// =========================================================================

#[test]
fn test_boot_params_e820() {
    use consts::*;

    let mem_size = 16 * 1024 * 1024; // 16MB
    let mut buf = guest_mem(mem_size);
    let mut mem = boot_guest_mem(&mut buf);
    setup_boot_params(&mut mem, "console=ttyS0").unwrap();

    // Boot signature
    assert_eq!(
        read_u16(&buf, addr(ZERO_PAGE_ADDR + BP_BOOT_FLAG)),
        BOOT_SIGNATURE
    );
    // Header magic
    assert_eq!(
        read_u32(&buf, addr(ZERO_PAGE_ADDR + BP_HEADER_MAGIC)),
        BZIMAGE_MAGIC
    );
    // Protocol version
    assert_eq!(
        read_u16(&buf, addr(ZERO_PAGE_ADDR + BP_VERSION)),
        BOOT_PROTOCOL_VERSION
    );
    // Load flags
    assert_eq!(
        read_u8(&buf, addr(ZERO_PAGE_ADDR + BP_LOADFLAGS)),
        LOAD_FLAGS
    );
    // Command line pointer
    assert_eq!(
        read_u32(&buf, addr(ZERO_PAGE_ADDR + BP_CMD_LINE_PTR)),
        u32::try_from(CMDLINE_ADDR).unwrap()
    );

    // Command line contents
    let cmdline = addr(CMDLINE_ADDR);
    assert_eq!(&buf[cmdline..cmdline + 14], b"console=ttyS0\0");

    // 3 E820 entries
    assert_eq!(read_u8(&buf, addr(ZERO_PAGE_ADDR + BP_E820_ENTRIES)), 3);

    // Entry 0: 0 - 640KB RAM
    let e0 = addr(ZERO_PAGE_ADDR + BP_E820_TABLE);
    assert_eq!(read_u64(&buf, e0), 0); // addr
    assert_eq!(read_u64(&buf, e0 + 8), LOW_MEMORY_END); // size
    assert_eq!(read_u32(&buf, e0 + 16), E820_TYPE_RAM);

    // Entry 1: 640KB - 1MB reserved
    let e1 = e0 + addr(E820_ENTRY_SIZE);
    assert_eq!(read_u64(&buf, e1), LOW_MEMORY_END);
    assert_eq!(read_u64(&buf, e1 + 8), RESERVED_REGION_SIZE);
    assert_eq!(read_u32(&buf, e1 + 16), E820_TYPE_RESERVED);

    // Entry 2: 1MB - top RAM
    let e2 = e1 + addr(E820_ENTRY_SIZE);
    assert_eq!(read_u64(&buf, e2), HIGH_MEMORY_START);
    assert_eq!(read_u64(&buf, e2 + 8), mem_size as u64 - HIGH_MEMORY_START);
    assert_eq!(read_u32(&buf, e2 + 16), E820_TYPE_RAM);
}

#[test]
fn test_boot_params_e820_sorted_with_advertised_virtio_mmio_hole() {
    use consts::*;

    let mut buf = guest_mem(1 << 20);
    let ram_size = 0x0A20_0000;
    let mut mem = page_table_test_mem(&mut buf, ram_size, amla_core::MEMORY_HOLES);

    setup_boot_params(&mut mem, "console=ttyS0").unwrap();

    let entries = read_e820_entries(&buf);
    assert_e820_sorted_non_overlapping(&entries);
    assert_eq!(
        entries,
        vec![
            (0, LOW_MEMORY_END, E820_TYPE_RAM),
            (LOW_MEMORY_END, RESERVED_REGION_SIZE, E820_TYPE_RESERVED),
            (
                HIGH_MEMORY_START,
                0x0A00_0000 - HIGH_MEMORY_START,
                E820_TYPE_RAM,
            ),
            (0x0A00_0000, 0x8000, E820_TYPE_RESERVED),
            (0x0A00_8000, 0x20_0000, E820_TYPE_RAM),
        ]
    );
}

#[test]
fn test_agent_boot_normal_memory_size() {
    let mem_size = amla_core::MIN_MEMORY_MB * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mem = boot_guest_mem(&mut buf);
    let kernel = minimal_elf64_with_load(0x0010_0000, 0x1000);
    let result = setup_linux_boot(mem, &kernel, "console=ttyS0", 1).unwrap();

    assert_eq!(result.entry_point, 0x10_0000);
    assert_eq!(&buf[0x0010_0000..0x0010_0004], b"BOOT");
}

#[test]
fn test_boot_params_cmdline_too_long() {
    use consts::*;

    let mem_size = 16 * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mut mem = boot_guest_mem(&mut buf);
    let long_cmdline = "x".repeat(CMDLINE_MAX_SIZE); // exactly at limit
    let err = setup_boot_params(&mut mem, &long_cmdline).unwrap_err();
    assert!(
        matches!(err, BootError::CmdlineTooLong { .. }),
        "Expected CmdlineTooLong, got {err:?}"
    );
}

#[test]
fn test_boot_params_rejects_too_many_e820_entries() {
    use consts::*;

    let mem_size = 4 * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mut holes = Vec::new();
    let mut start = HIGH_MEMORY_START + 0x2000;
    for _ in 0..70 {
        holes.push(amla_core::MemoryHole {
            start,
            end: start + 0x1000,
            advertise_reserved: true,
        });
        start += 0x2000;
    }

    let mut mem = boot_guest_mem_with_holes(&mut buf, memory_holes(&holes));
    let err = setup_boot_params(&mut mem, "console=ttyS0").unwrap_err();
    assert!(
        matches!(err, BootError::E820TableTooLarge { .. }),
        "Expected E820TableTooLarge, got {err:?}"
    );
}

#[test]
fn test_gdt_setup() {
    use consts::*;

    let mem_size = 1 << 20; // 1MB
    let mut buf = guest_mem(mem_size);
    let mut mem = boot_guest_mem(&mut buf);
    gdt::setup_gdt(&mut mem).unwrap();

    // Entry 0: NULL descriptor
    assert_eq!(read_u64(&buf, addr(GDT_ADDR)), 0);
    // Entry 1: NULL (Linux compatibility)
    assert_eq!(read_u64(&buf, addr(GDT_ADDR + 8)), 0);
    // Entry 2 (selector 0x10): 64-bit code segment
    assert_eq!(read_u64(&buf, addr(GDT_ADDR + 16)), GDT_ENTRY_CODE64);
    // Entry 3 (selector 0x18): 64-bit data segment
    assert_eq!(read_u64(&buf, addr(GDT_ADDR + 24)), GDT_ENTRY_DATA64);
    // Entry 4-5 (selector 0x20): 64-bit TSS descriptor (16 bytes)
    assert_eq!(read_u64(&buf, addr(GDT_ADDR + 32)), GDT_ENTRY_TSS64_LOW);
    assert_eq!(read_u64(&buf, addr(GDT_ADDR + 40)), GDT_ENTRY_TSS64_HIGH);
}

// ELF loading error path tests
// =========================================================================

fn minimal_elf64_with_load(paddr: u64, memsz: u64) -> Vec<u8> {
    const ELF_HEADER_SIZE: usize = 64;
    const PHDR_SIZE: usize = 56;
    const PHDR_OFFSET: usize = ELF_HEADER_SIZE;
    const FILE_OFFSET: usize = 0x100;

    let filesz = 4u64;
    let mut elf_bytes = vec![0u8; FILE_OFFSET + filesz as usize];
    elf_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    elf_bytes[4] = 2; // ELFCLASS64
    elf_bytes[5] = 1; // ELFDATA2LSB
    elf_bytes[6] = 1; // EV_CURRENT
    elf_bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    elf_bytes[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    elf_bytes[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
    elf_bytes[24..32].copy_from_slice(&0x10_0000u64.to_le_bytes()); // e_entry
    elf_bytes[32..40].copy_from_slice(&(PHDR_OFFSET as u64).to_le_bytes());
    elf_bytes[52..54].copy_from_slice(&(ELF_HEADER_SIZE as u16).to_le_bytes());
    elf_bytes[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
    elf_bytes[56..58].copy_from_slice(&1u16.to_le_bytes());

    let ph = PHDR_OFFSET;
    elf_bytes[ph..ph + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    elf_bytes[ph + 4..ph + 8].copy_from_slice(&5u32.to_le_bytes()); // R|X
    elf_bytes[ph + 8..ph + 16].copy_from_slice(&(FILE_OFFSET as u64).to_le_bytes());
    elf_bytes[ph + 16..ph + 24].copy_from_slice(&paddr.to_le_bytes());
    elf_bytes[ph + 24..ph + 32].copy_from_slice(&paddr.to_le_bytes());
    elf_bytes[ph + 32..ph + 40].copy_from_slice(&filesz.to_le_bytes());
    elf_bytes[ph + 40..ph + 48].copy_from_slice(&memsz.to_le_bytes());
    elf_bytes[ph + 48..ph + 56].copy_from_slice(&0x1000u64.to_le_bytes());
    elf_bytes[FILE_OFFSET..FILE_OFFSET + filesz as usize].copy_from_slice(b"BOOT");
    elf_bytes
}

#[test]
fn test_elf_not_elf() {
    let mem_size = 16 * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mem = boot_guest_mem(&mut buf);
    let garbage = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let err = setup_linux_boot(mem, &garbage, "console=ttyS0", 1).unwrap_err();
    assert!(
        matches!(err, BootError::ElfParse(_)),
        "Expected ElfParse, got {err:?}"
    );
}

#[test]
fn test_elf_low_boot_memory_segment_rejected() {
    let mem_size = 16 * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mem = boot_guest_mem(&mut buf);
    let kernel = minimal_elf64_with_load(consts::ZERO_PAGE_ADDR, 0x1000);

    let err = setup_linux_boot(mem, &kernel, "console=ttyS0", 1).unwrap_err();
    assert!(
        matches!(err, BootError::KernelOverlapsBootRegion { .. }),
        "Expected KernelOverlapsBootRegion, got {err:?}"
    );
}

#[test]
fn test_elf_memory_too_small() {
    let mem_size = 1024 * 1024; // 1MB — below 2MB minimum
    let mut buf = guest_mem(mem_size);
    let mem = boot_guest_mem(&mut buf);
    let err = setup_linux_boot(mem, &[0u8; 64], "console=ttyS0", 1).unwrap_err();
    assert!(
        matches!(err, BootError::MemoryTooSmall { .. }),
        "Expected MemoryTooSmall, got {err:?}"
    );
}

// =========================================================================
// ELF machine type validation tests (P1.1)
// =========================================================================

#[test]
fn test_elf_wrong_machine_type_aarch64() {
    // Construct a minimal valid ELF64 header with e_machine = EM_AARCH64 (183)
    let mut elf_bytes = vec![0u8; 128];
    // ELF magic
    elf_bytes[0..4].copy_from_slice(&[0x7f, b'E', b'L', b'F']);
    // EI_CLASS = ELFCLASS64 (2)
    elf_bytes[4] = 2;
    // EI_DATA = ELFDATA2LSB (1)
    elf_bytes[5] = 1;
    // EI_VERSION = 1
    elf_bytes[6] = 1;
    // e_type = ET_EXEC (2) at offset 16
    elf_bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
    // e_machine = EM_AARCH64 (183) at offset 18
    elf_bytes[18..20].copy_from_slice(&183u16.to_le_bytes());
    // e_version = 1 at offset 20
    elf_bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    // e_ehsize = 64 at offset 52
    elf_bytes[52..54].copy_from_slice(&64u16.to_le_bytes());

    let mem_size = 16 * 1024 * 1024;
    let mut buf = guest_mem(mem_size);
    let mem = boot_guest_mem(&mut buf);
    let err = setup_linux_boot(mem, &elf_bytes, "console=ttyS0", 1).unwrap_err();
    match &err {
        BootError::ElfParse(msg) => {
            assert!(
                msg.contains("x86_64") && msg.contains("183"),
                "Error should mention x86_64 and actual machine type: {msg}"
            );
        }
        other => panic!("Expected ElfParse with machine type error, got {other:?}"),
    }
}

// =========================================================================
// T4: >512 GiB page table error test
// =========================================================================

#[test]
fn test_page_tables_exceeds_512gb_error() {
    let mem_size = 513 * (1 << 30); // 513 GiB
    let mut buf = guest_mem(1 << 20);
    let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
    let layout =
        BootRamLayout::from_ram(GuestPhysAddr::new(0), mem_size, amla_core::MemoryHoles::EMPTY)
            .unwrap();
    // SAFETY: the page-table limit check happens before any write.
    let mut mem = unsafe { BootGuestMemory::from_raw_parts_for_test(ptr, buf.len(), layout) };
    let err = page_tables::setup_page_tables(&mut mem).unwrap_err();
    assert!(
        matches!(err, BootError::PageTableLimit { .. }),
        "Expected PageTableLimit for >512 GiB, got {err:?}"
    );
}

// =========================================================================
// T5: empty write_bytes edge case
// =========================================================================

#[test]
fn test_guest_mem_writer_empty_write() {
    let mut buf = [0xFFu8; 16];
    // SAFETY: buf is a stack array; pointer is valid for 16 bytes.
    let w = unsafe { GuestMemWriter::new(NonNull::new(buf.as_mut_ptr()).unwrap(), 16) };
    // Writing an empty slice should succeed without modifying anything
    w.write_at(RamBackingRange::new_for_test(0, 0), &[])
        .unwrap();
    w.write_at(RamBackingRange::new_for_test(15, 0), &[])
        .unwrap();
    assert!(buf.iter().all(|&b| b == 0xFF), "Buffer should be unchanged");
}
