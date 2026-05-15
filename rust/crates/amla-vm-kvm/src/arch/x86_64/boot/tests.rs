// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Tests for KVM-specific boot wrapper.
//!
//! The shared boot logic (page tables, GDT, MP table, boot params, ELF loading,
//! `GuestMemWriter`) is tested in `amla-boot-x86`. These tests verify the
//! KVM-specific conversion: `X86BootState` → (`kvm_regs`, `kvm_sregs`).

use amla_boot::x86_64::consts::*;

/// Verify KVM CPU register setup produces valid long mode state.
#[test]
fn test_cpu_regs_long_mode() {
    let entry_point = 0x100_0000;
    let (regs, sregs) = super::cpu_state::setup_cpu_regs(entry_point);

    // RIP points to entry
    assert_eq!(regs.rip, entry_point);

    // RSI points to boot params
    assert_eq!(regs.rsi, ZERO_PAGE_ADDR);

    // RFLAGS has reserved bit set
    assert_ne!(regs.rflags & RFLAGS_RESERVED_BIT, 0);

    // Code segment is 64-bit
    assert_eq!(sregs.cs.selector, GDT_SELECTOR_CODE);
    assert_eq!(sregs.cs.l, 1); // Long mode flag

    // Data segments use correct selector
    assert_eq!(sregs.ds.selector, GDT_SELECTOR_DATA);
    assert_eq!(sregs.ss.selector, GDT_SELECTOR_DATA);

    // TSS is present (required for 64-bit mode)
    assert_eq!(sregs.tr.selector, GDT_SELECTOR_TSS);
    assert_eq!(sregs.tr.present, 1);

    // Long mode is enabled in EFER
    assert_ne!(sregs.efer & EFER_LME, 0);
    assert_ne!(sregs.efer & EFER_LMA, 0);

    // Paging is enabled
    assert_ne!(sregs.cr0 & CR0_PG, 0);

    // PAE is enabled (required for long mode)
    assert_ne!(sregs.cr4 & CR4_PAE, 0);

    // CR3 points to PML4
    assert_eq!(sregs.cr3, PML4_ADDR);
}

/// Verify all segment registers have correct KVM fields.
#[test]
fn test_segment_conversion() {
    let (_, sregs) = super::cpu_state::setup_cpu_regs(0x100_0000);

    // Code segment: L=1, D=0, S=1, present
    assert_eq!(sregs.cs.l, 1);
    assert_eq!(sregs.cs.db, 0);
    assert_eq!(sregs.cs.s, 1);
    assert_eq!(sregs.cs.present, 1);
    assert_eq!(sregs.cs.unusable, 0);

    // Data segment: L=0, D=1, S=1, present
    assert_eq!(sregs.ds.l, 0);
    assert_eq!(sregs.ds.db, 1);
    assert_eq!(sregs.ds.s, 1);
    assert_eq!(sregs.ds.present, 1);

    // TSS: system segment, present
    assert_eq!(sregs.tr.s, 0);
    assert_eq!(sregs.tr.present, 1);
    assert_eq!(sregs.tr.type_, SEG_TYPE_TSS64_AVAILABLE);

    // LDT: unusable
    assert_eq!(sregs.ldt.unusable, 1);
    assert_eq!(sregs.ldt.present, 0);
}

/// Verify GDT table register setup.
#[test]
fn test_gdt_idt_registers() {
    let (_, sregs) = super::cpu_state::setup_cpu_regs(0x100_0000);

    assert_eq!(sregs.gdt.base, GDT_ADDR);
    assert_eq!(sregs.gdt.limit, u16::try_from(GDT_SIZE - 1).unwrap());

    assert_eq!(sregs.idt.base, 0);
    assert_eq!(sregs.idt.limit, 0xFFFF);
}

/// Verify APIC base MSR.
#[test]
fn test_apic_base() {
    let (_, sregs) = super::cpu_state::setup_cpu_regs(0x100_0000);

    assert_ne!(sregs.apic_base & APIC_BASE_ENABLE, 0);
    assert_ne!(sregs.apic_base & APIC_BASE_BSP, 0);
    assert_eq!(sregs.apic_base & !0xFFF, LAPIC_BASE_ADDR);
}
