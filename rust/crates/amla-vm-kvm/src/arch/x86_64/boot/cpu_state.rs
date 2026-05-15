// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! CPU register setup for 64-bit long mode entry (KVM backend).
//!
//! Converts the platform-agnostic [`X86BootState`] from `amla-boot-x86`
//! into KVM's `(kvm_regs, kvm_sregs)` types.

use amla_boot::x86_64::{SegmentState, X86BootState};
use kvm_bindings::{kvm_regs, kvm_segment, kvm_sregs};

/// Set up CPU registers for 64-bit long mode entry (test helper).
#[cfg(test)]
pub(super) fn setup_cpu_regs(entry_point: u64) -> (kvm_regs, kvm_sregs) {
    let state = amla_boot::x86_64::internals::setup_cpu_state(entry_point);
    x86_boot_state_to_kvm(&state)
}

/// Convert platform-agnostic boot state to KVM register types.
pub fn x86_boot_state_to_kvm(state: &X86BootState) -> (kvm_regs, kvm_sregs) {
    let mut regs = kvm_regs::default();
    let mut sregs = kvm_sregs::default();

    // General purpose registers
    regs.rip = state.rip;
    regs.rsp = state.rsp;
    regs.rsi = state.rsi;
    regs.rflags = state.rflags;

    // Segment registers
    sregs.cs = segment_to_kvm(&state.cs);
    sregs.ds = segment_to_kvm(&state.ds);
    sregs.es = segment_to_kvm(&state.es);
    sregs.fs = segment_to_kvm(&state.fs);
    sregs.gs = segment_to_kvm(&state.gs);
    sregs.ss = segment_to_kvm(&state.ss);
    sregs.tr = segment_to_kvm(&state.tr);
    sregs.ldt = segment_to_kvm(&state.ldt);

    // Table registers
    sregs.gdt.base = state.gdt.base;
    sregs.gdt.limit = state.gdt.limit;
    sregs.gdt.padding = [0; 3];

    sregs.idt.base = state.idt.base;
    sregs.idt.limit = state.idt.limit;
    sregs.idt.padding = [0; 3];

    // Control registers
    sregs.cr0 = state.cr0;
    sregs.cr2 = state.cr2;
    sregs.cr3 = state.cr3;
    sregs.cr4 = state.cr4;
    sregs.cr8 = state.cr8;

    // EFER
    sregs.efer = state.efer;

    // APIC base
    sregs.apic_base = state.apic_base;

    // No pending interrupts
    sregs.interrupt_bitmap = [0; 4];

    (regs, sregs)
}

/// Convert a platform-agnostic segment to KVM's `kvm_segment`.
const fn segment_to_kvm(seg: &SegmentState) -> kvm_segment {
    kvm_segment {
        base: seg.base,
        limit: seg.limit,
        selector: seg.selector,
        type_: seg.type_,
        present: seg.present,
        dpl: seg.dpl,
        db: seg.db,
        s: seg.s,
        l: seg.l,
        g: seg.g,
        avl: 0,
        unusable: seg.unusable,
        padding: 0,
    }
}
