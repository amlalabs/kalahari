// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//\! Boot setup constants: memory layout, page tables, GDT, E820, MP table.

// =============================================================================
// Memory Layout Constants
// =============================================================================

/// GDT address. Placed after BIOS data area, before zero page.
pub const GDT_ADDR: u64 = 0x0000_0500;

/// Boot parameters (zero page) address.
pub const ZERO_PAGE_ADDR: u64 = 0x0000_7000;

/// Initial stack pointer. Stack grows down from here.
/// Placed at the end of the stack page below PML4; the first push lands below it.
pub const INITIAL_STACK_POINTER: u64 = 0x0000_9000;

/// Command line address.
pub const CMDLINE_ADDR: u64 = 0x0002_0000;

/// Maximum command line length (64KB).
pub const CMDLINE_MAX_SIZE: usize = 0x0001_0000;

// Page Table Addresses

/// PML4 (Page Map Level 4) table address.
pub const PML4_ADDR: u64 = 0x0000_9000;

/// PDPT for low memory identity mapping.
pub const PDPT_ADDR: u64 = 0x0000_a000;

/// PD tables base address (4 consecutive tables, 16KB).
pub const PD_ADDR: u64 = 0x0000_b000;

/// PDPT for higher-half kernel mapping.
pub const HIGH_PDPT_ADDR: u64 = 0x0000_f000;
/// Extra page-table pages used for unaligned mappings around RAM holes.
pub const PAGE_TABLE_EXTRA_ARENA_ADDR: u64 = 0x0001_0000;
/// Size of the extra page-table arena.
pub const PAGE_TABLE_EXTRA_ARENA_SIZE: usize = 0x0001_0000;

// Page Table Flags

/// Page present flag (bit 0).
pub const PAGE_PRESENT: u64 = 1 << 0;

/// Page writable flag (bit 1).
pub const PAGE_WRITABLE: u64 = 1 << 1;

/// Page size flag (bit 7). 2MB in PD, 1GB in PDPT.
pub const PAGE_SIZE: u64 = 1 << 7;

// Control Register Bits

/// CR0.PE - Protected mode enable.
pub const CR0_PE: u64 = 1 << 0;
/// CR0.ET - Extension type.
pub const CR0_ET: u64 = 1 << 4;
/// CR0.WP - Write protect.
pub const CR0_WP: u64 = 1 << 16;
/// CR0.PG - Paging enable.
pub const CR0_PG: u64 = 1 << 31;

/// CR4.PAE - Physical Address Extension. Required for long mode.
pub const CR4_PAE: u64 = 1 << 5;
/// CR4.OSFXSR - OS support for FXSAVE/FXRSTOR.
pub const CR4_OSFXSR: u64 = 1 << 9;
/// CR4.OSXMMEXCPT - OS support for unmasked SIMD exceptions.
pub const CR4_OSXMMEXCPT: u64 = 1 << 10;

/// EFER.SCE - System Call Extensions.
pub const EFER_SCE: u64 = 1 << 0;
/// EFER.LME - Long Mode Enable.
pub const EFER_LME: u64 = 1 << 8;
/// EFER.LMA - Long Mode Active.
pub const EFER_LMA: u64 = 1 << 10;

/// RFLAGS reserved bit (bit 1). Must always be set.
pub const RFLAGS_RESERVED_BIT: u64 = 1 << 1;

// GDT Selectors and Descriptors

/// GDT size as `usize` (for `GuestMemWriter::zero` calls).
pub const GDT_SIZE_BYTES: usize = 6 * 8;
/// GDT size in bytes: 6 entries × 8 bytes (entries 4–5 form a single 16-byte TSS descriptor).
pub const GDT_SIZE: u64 = GDT_SIZE_BYTES as u64;
/// GDT limit (`size − 1`) as `u16` for GDTR.
pub const GDT_LIMIT: u16 = (GDT_SIZE_BYTES - 1) as u16;
/// Code segment selector (entry 2, RPL 0).
pub const GDT_SELECTOR_CODE: u16 = 0x10;
/// Data segment selector (entry 3, RPL 0).
pub const GDT_SELECTOR_DATA: u16 = 0x18;
/// TSS segment selector (entry 4, RPL 0).
pub const GDT_SELECTOR_TSS: u16 = 0x20;

/// 64-bit code segment descriptor.
pub const GDT_ENTRY_CODE64: u64 = 0x00AF_9B00_0000_FFFF;
/// 64-bit data segment descriptor.
pub const GDT_ENTRY_DATA64: u64 = 0x00CF_9300_0000_FFFF;
/// 64-bit TSS descriptor (low 8 bytes).
pub const GDT_ENTRY_TSS64_LOW: u64 = 0x0000_8900_0000_0067;
/// 64-bit TSS descriptor (high 8 bytes).
pub const GDT_ENTRY_TSS64_HIGH: u64 = 0x0000_0000_0000_0000;
/// Minimum 64-bit TSS size minus 1.
pub const TSS_LIMIT: u32 = 0x67;

// Segment Descriptor Types

/// Code segment type: execute/read, accessed.
pub const SEG_TYPE_CODE_EXEC_READ: u8 = 11;
/// Data segment type: read/write, accessed.
pub const SEG_TYPE_DATA_READ_WRITE: u8 = 3;
/// TSS type: 64-bit TSS available.
pub const SEG_TYPE_TSS64_AVAILABLE: u8 = 9;

// E820 Memory Map

/// E820 type: usable RAM.
pub const E820_TYPE_RAM: u32 = 1;
/// E820 type: reserved.
pub const E820_TYPE_RESERVED: u32 = 2;
/// Low memory end (640KB).
pub const LOW_MEMORY_END: u64 = 0x000A_0000;
/// Reserved region size (384KB).
pub const RESERVED_REGION_SIZE: u64 = 0x0006_0000;
/// High memory start (1MB).
pub const HIGH_MEMORY_START: u64 = 0x0010_0000;

// Boot Protocol Constants

/// bzImage header magic "`HdrS`".
pub const BZIMAGE_MAGIC: u32 = 0x5372_6448;
/// Boot protocol version 2.15.
pub const BOOT_PROTOCOL_VERSION: u16 = 0x020F;
/// Type of loader: undefined.
pub const LOADER_TYPE_UNDEFINED: u8 = 0xFF;
/// Load flags: `LOADED_HIGH` | `KEEP_SEGMENTS`.
pub const LOAD_FLAGS: u8 = 0x41;
/// Boot signature 0xAA55.
pub const BOOT_SIGNATURE: u16 = 0xAA55;
/// Minimum memory size (2MB).
pub const MINIMUM_MEMORY_SIZE: usize = 2 * 1024 * 1024;

// Boot Params Offsets

/// Offset of `boot_flag` (u16).
pub const BP_BOOT_FLAG: u64 = 0x1FE;
/// Offset of header magic (u32).
pub const BP_HEADER_MAGIC: u64 = 0x202;
/// Offset of boot protocol version (u16).
pub const BP_VERSION: u64 = 0x206;
/// Offset of `type_of_loader` (u8).
pub const BP_TYPE_OF_LOADER: u64 = 0x210;
/// Offset of loadflags (u8).
pub const BP_LOADFLAGS: u64 = 0x211;
/// Offset of `cmd_line_ptr` (u32).
pub const BP_CMD_LINE_PTR: u64 = 0x228;
/// Offset of `cmdline_size` (u32).
pub const BP_CMDLINE_SIZE: u64 = 0x238;
/// Offset of `e820_entries` (u8).
pub const BP_E820_ENTRIES: u64 = 0x1E8;
/// Offset of `e820_table`.
pub const BP_E820_TABLE: u64 = 0x2D0;
/// Size of one E820 entry (20 bytes).
pub const E820_ENTRY_SIZE: u64 = 20;
/// Maximum E820 entries in the Linux boot zero-page table.
pub const E820_MAX_ENTRIES: u64 = 128;

// APIC Constants

/// Local APIC base address.
pub const LAPIC_BASE_ADDR: u64 = 0xFEE0_0000;
/// APIC base MSR: APIC enabled (bit 11).
pub const APIC_BASE_ENABLE: u64 = 1 << 11;
/// APIC base MSR: BSP flag (bit 8).
pub const APIC_BASE_BSP: u64 = 1 << 8;

// MP Table Constants

/// MP table base address.
pub const MPTABLE_START: u64 = 0x0009_FC00;
/// I/O APIC physical address.
pub const IOAPIC_ADDR: u32 = 0xFEC0_0000;
/// Local APIC physical address (u32 for MP table entries).
///
/// Same value as [`LAPIC_BASE_ADDR`] (u64, used for the APIC base MSR which
/// includes BSP/enable flag bits in the upper portion).
pub const LAPIC_ADDR: u32 = 0xFEE0_0000;
/// MP floating pointer structure size (16 bytes).
pub const MP_FP_SIZE: u64 = 16;
/// MP config table header size (44 bytes).
pub const MP_CONFIG_HEADER_SIZE: u64 = 44;
/// Processor entry size (20 bytes).
pub const MP_PROC_ENTRY_SIZE: u64 = 20;
/// Bus entry size (8 bytes).
pub const MP_BUS_ENTRY_SIZE: u64 = 8;
/// I/O APIC entry size (8 bytes).
pub const MP_IOAPIC_ENTRY_SIZE: u64 = 8;
/// I/O interrupt source entry size (8 bytes).
pub const MP_INTSRC_ENTRY_SIZE: u64 = 8;
/// Local interrupt source entry size (8 bytes).
pub const MP_LINTSRC_ENTRY_SIZE: u64 = 8;
/// Number of ISA IRQ sources.
pub const MP_NUM_ISA_IRQS: u8 = 16;
/// Number of local interrupt sources.
pub const MP_NUM_LINT_SOURCES: u8 = 2;
/// MP entry type: processor.
pub const MP_ENTRY_PROCESSOR: u8 = 0;
/// MP entry type: bus.
pub const MP_ENTRY_BUS: u8 = 1;
/// MP entry type: I/O APIC.
pub const MP_ENTRY_IOAPIC: u8 = 2;
/// MP entry type: I/O interrupt source.
pub const MP_ENTRY_INTSRC: u8 = 3;
/// MP entry type: local interrupt source.
pub const MP_ENTRY_LINTSRC: u8 = 4;
/// MP processor flags: CPU enabled.
pub const MP_CPU_ENABLED: u8 = 0x01;
/// MP processor flags: bootstrap processor.
pub const MP_CPU_BSP: u8 = 0x02;
/// MP interrupt type: vectored interrupt.
pub const MP_IRQ_TYPE_VECTORED: u8 = 0;
/// MP interrupt type: NMI.
pub const MP_IRQ_TYPE_NMI: u8 = 1;
/// MP interrupt type: `ExtINT`.
pub const MP_IRQ_TYPE_EXTINT: u8 = 3;
/// MP destination APIC ID for "all APICs".
pub const MP_DEST_ALL_APICS: u8 = 0xFF;
/// MP spec revision 1.4.
pub const MP_SPEC_REV_1_4: u8 = 4;
/// Local APIC version.
pub const LAPIC_VERSION: u8 = 0x14;
/// I/O APIC version.
pub const IOAPIC_VERSION: u8 = 0x11;
/// CPU signature (CPUID leaf 1 EAX).
pub const CPU_SIGNATURE: u32 = 0x0006_0FB1;
/// CPU feature flags (CPUID leaf 1 EDX).
pub const CPU_FEATURE_FLAGS: u32 = 0x0781_FBFF;
