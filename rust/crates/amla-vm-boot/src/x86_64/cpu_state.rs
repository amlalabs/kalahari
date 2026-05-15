// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Platform-agnostic CPU register state for 64-bit long mode entry.
//!
//! Defines [`X86BootState`] which captures all register values needed for BSP
//! `startup_64` entry. Each backend (KVM, WHP, HVF) converts this to its own
//! register types.

use crate::x86_64::consts::{
    APIC_BASE_BSP, APIC_BASE_ENABLE, CR0_ET, CR0_PE, CR0_PG, CR0_WP, CR4_OSFXSR, CR4_OSXMMEXCPT,
    CR4_PAE, EFER_LMA, EFER_LME, EFER_SCE, GDT_ADDR, GDT_LIMIT, GDT_SELECTOR_CODE,
    GDT_SELECTOR_DATA, GDT_SELECTOR_TSS, INITIAL_STACK_POINTER, LAPIC_BASE_ADDR, PML4_ADDR,
    RFLAGS_RESERVED_BIT, SEG_TYPE_CODE_EXEC_READ, SEG_TYPE_DATA_READ_WRITE,
    SEG_TYPE_TSS64_AVAILABLE, TSS_LIMIT, ZERO_PAGE_ADDR,
};

/// Platform-agnostic `x86_64` segment register state.
///
/// Maps directly to KVM's `kvm_segment` and can be converted to WHP's
/// segment register attributes. Boolean-like fields use `u8` to match
/// the `kvm_segment` ABI (`__u8` fields in the kernel struct).
#[derive(Debug, Clone, Copy)]
pub struct SegmentState {
    /// 64-bit base address.
    pub base: u64,
    /// 32-bit limit.
    pub limit: u32,
    /// 16-bit selector.
    pub selector: u16,
    /// Segment type (4-bit field from descriptor).
    pub type_: u8,
    /// Present bit.
    pub present: u8,
    /// Descriptor privilege level (0-3).
    pub dpl: u8,
    /// Default operation size (D/B flag): 0=16-bit, 1=32-bit.
    pub db: u8,
    /// Code/data segment flag (S flag): 0=system, 1=code/data.
    pub s: u8,
    /// Long mode flag (L flag): 1=64-bit code segment.
    pub l: u8,
    /// Granularity flag (G flag): 0=byte, 1=4KB.
    pub g: u8,
    /// Unusable flag (KVM extension): 1=segment is unusable.
    pub unusable: u8,
}

/// Platform-agnostic `x86_64` table register state (GDTR/IDTR).
#[derive(Debug, Clone, Copy)]
pub struct TableState {
    /// 64-bit base address.
    pub base: u64,
    /// 16-bit limit.
    pub limit: u16,
}

/// Platform-agnostic `x86_64` BSP register state for 64-bit long mode entry.
///
/// Contains all register values needed for the kernel entry point.
/// Each backend converts this to its own register types:
/// - KVM: `(kvm_regs, kvm_sregs)`
/// - WHP: `Vec<(WHV_REGISTER_NAME, WHV_REGISTER_VALUE)>`
#[derive(Debug, Clone)]
pub struct X86BootState {
    // General purpose registers
    /// Instruction pointer — kernel entry point.
    pub rip: u64,
    /// Stack pointer — initial stack address.
    pub rsp: u64,
    /// Source index — boot params address (Linux convention).
    pub rsi: u64,
    /// Flags register — reserved bit 1 must be set.
    pub rflags: u64,

    // Segment registers
    /// Code segment — 64-bit long mode.
    pub cs: SegmentState,
    /// Data segment.
    pub ds: SegmentState,
    /// Extra segment.
    pub es: SegmentState,
    /// FS segment.
    pub fs: SegmentState,
    /// GS segment.
    pub gs: SegmentState,
    /// Stack segment.
    pub ss: SegmentState,
    /// Task register — 64-bit TSS (required for long mode).
    pub tr: SegmentState,
    /// Local descriptor table — unused, marked unusable.
    pub ldt: SegmentState,

    // Table registers
    /// Global descriptor table register.
    pub gdt: TableState,
    /// Interrupt descriptor table register.
    pub idt: TableState,

    // Control registers
    /// CR0 — protected mode + paging enabled.
    pub cr0: u64,
    /// CR2 — page fault linear address (zero at boot).
    pub cr2: u64,
    /// CR3 — PML4 physical address.
    pub cr3: u64,
    /// CR4 — PAE + SSE support.
    pub cr4: u64,
    /// CR8 — task priority register (zero = allow all interrupts).
    pub cr8: u64,

    /// EFER — long mode enabled + syscall enabled.
    pub efer: u64,

    /// APIC base MSR — standard address with BSP flag.
    pub apic_base: u64,
}

/// Set up CPU registers for 64-bit long mode entry.
///
/// Returns a platform-agnostic [`X86BootState`] containing all register
/// values for the BSP (bootstrap processor) at kernel entry.
#[must_use]
pub const fn setup_cpu_state(entry_point: u64) -> X86BootState {
    let cs = SegmentState {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: GDT_SELECTOR_CODE,
        type_: SEG_TYPE_CODE_EXEC_READ,
        present: 1,
        dpl: 0,
        db: 0, // Must be 0 for 64-bit code
        s: 1,  // Code/data segment
        l: 1,  // 64-bit mode
        g: 1,  // 4KB granularity
        unusable: 0,
    };

    let data_seg = SegmentState {
        base: 0,
        limit: 0xFFFF_FFFF,
        selector: GDT_SELECTOR_DATA,
        type_: SEG_TYPE_DATA_READ_WRITE,
        present: 1,
        dpl: 0,
        db: 1, // 32-bit operand size
        s: 1,  // Code/data segment
        l: 0,  // Not 64-bit code
        g: 1,  // 4KB granularity
        unusable: 0,
    };

    let ldt = SegmentState {
        base: 0,
        limit: 0,
        selector: 0,
        type_: 0,
        present: 0,
        dpl: 0,
        db: 0,
        s: 0,
        l: 0,
        g: 0,
        unusable: 1,
    };

    let tr = SegmentState {
        base: 0,
        limit: TSS_LIMIT,
        selector: GDT_SELECTOR_TSS,
        type_: SEG_TYPE_TSS64_AVAILABLE,
        present: 1,
        dpl: 0,
        db: 0,
        s: 0, // System segment
        l: 0,
        g: 0,
        unusable: 0,
    };

    X86BootState {
        rip: entry_point,
        rsp: INITIAL_STACK_POINTER,
        rsi: ZERO_PAGE_ADDR,
        rflags: RFLAGS_RESERVED_BIT,

        cs,
        ds: data_seg,
        es: data_seg,
        fs: data_seg,
        gs: data_seg,
        ss: data_seg,
        tr,
        ldt,

        gdt: TableState {
            base: GDT_ADDR,
            limit: GDT_LIMIT,
        },
        idt: TableState {
            base: 0,
            limit: 0xFFFF,
        },

        cr0: CR0_PE | CR0_ET | CR0_WP | CR0_PG,
        cr2: 0,
        cr3: PML4_ADDR,
        cr4: CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT,
        cr8: 0,

        efer: EFER_SCE | EFER_LME | EFER_LMA,
        apic_base: LAPIC_BASE_ADDR | APIC_BASE_ENABLE | APIC_BASE_BSP,
    }
}
