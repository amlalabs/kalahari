// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Shared `x86_64` vCPU snapshot types.
//!
//! These types provide a hypervisor-agnostic representation of `x86_64` vCPU state.
//! Each backend (KVM, Hyper-V) converts to/from its native representation via
//! `to_shared()`/`from_shared()` methods on the backend-specific snapshot type.

use super::MpState;
use super::msr::{self, SNAPSHOT_MSRS};

/// Snapshot of an `x86_64` vCPU's complete state.
///
/// Unlike the KVM `VcpuSnapshot` (which is `repr(C)` for zero-copy transfer),
/// this type uses `Vec`-based fields for cross-backend portability.
#[derive(Debug, Clone)]
pub struct X86VcpuSnapshot {
    /// General-purpose registers.
    pub regs: X86GeneralRegs,
    /// Segment and control registers.
    pub sregs: X86SegmentRegs,
    /// Raw FPU state (opaque, variable size).
    pub fpu: Vec<u8>,
    /// Raw XSAVE state (AVX/AVX-512/MPX/PKRU, opaque, variable size).
    pub xsave: Vec<u8>,
    /// Raw LAPIC register page (typically 1024 bytes).
    pub lapic: Vec<u8>,
    /// MSR values as (index, value) pairs.
    pub msrs: Vec<(u32, u64)>,
    /// Multi-processor state.
    pub mp_state: MpState,
    /// Extended Control Registers as (index, value) pairs.
    pub xcrs: Vec<(u32, u64)>,
    /// Debug registers.
    pub debugregs: X86DebugRegs,
    /// Raw `vcpu_events` (opaque, backend-specific).
    pub vcpu_events: Vec<u8>,
}

/// `x86_64` general-purpose registers.
#[derive(Debug, Clone, Default)]
pub struct X86GeneralRegs {
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub rflags: u64,
}

/// `x86_64` segment descriptor.
#[derive(Debug, Clone, Default)]
pub struct X86Segment {
    pub base: u64,
    pub limit: u32,
    pub selector: u16,
    pub type_: u8,
    pub present: u8,
    pub dpl: u8,
    pub db: u8,
    pub s: u8,
    pub l: u8,
    pub g: u8,
    /// Segment unusable flag. Must be 1 for LDT on `x86_64`.
    pub unusable: u8,
}

/// `x86_64` descriptor table register (GDT/IDT).
#[derive(Debug, Clone, Default)]
pub struct X86DtReg {
    pub base: u64,
    pub limit: u16,
}

/// `x86_64` segment and control registers.
#[derive(Debug, Clone, Default)]
pub struct X86SegmentRegs {
    pub cs: X86Segment,
    pub ds: X86Segment,
    pub es: X86Segment,
    pub fs: X86Segment,
    pub gs: X86Segment,
    pub ss: X86Segment,
    pub tr: X86Segment,
    pub ldt: X86Segment,
    pub gdt: X86DtReg,
    pub idt: X86DtReg,
    pub cr0: u64,
    pub cr2: u64,
    pub cr3: u64,
    pub cr4: u64,
    pub cr8: u64,
    pub efer: u64,
    pub apic_base: u64,
}

/// `x86_64` debug registers (DR0–DR3, DR6, DR7).
#[derive(Debug, Clone, Default)]
pub struct X86DebugRegs {
    pub db: [u64; 4],
    pub dr6: u64,
    pub dr7: u64,
}

impl X86VcpuSnapshot {
    /// Create an empty snapshot (all registers zero, no MSRs).
    pub fn empty() -> Self {
        Self {
            regs: X86GeneralRegs::default(),
            sregs: X86SegmentRegs::default(),
            fpu: Vec::new(),
            xsave: Vec::new(),
            lapic: Vec::new(),
            msrs: Vec::new(),
            mp_state: MpState::Runnable,
            xcrs: Vec::new(),
            debugregs: X86DebugRegs::default(),
            vcpu_events: Vec::new(),
        }
    }

    /// Create a snapshot for an AP in `INIT_RECEIVED` state.
    ///
    /// Mirrors the KVM `VcpuSnapshot::for_init_received()` logic:
    /// - FPU: x87 CW=0x37f, MXCSR=0x1f80
    /// - LAPIC: SPIV enabled with spurious vector 0xFF, APIC ID set
    /// - MSRs: all zero except PAT (default value)
    /// - MP state: `InitReceived`
    pub fn for_init_received(apic_id: u8) -> Self {
        // Build LAPIC with SPIV register enabled and correct APIC ID
        let mut lapic = vec![0u8; 1024];
        let spiv_offset = 0xF0;
        let spiv_value: u32 = 0x1FF; // APIC enabled + spurious vector 0xFF
        lapic[spiv_offset..spiv_offset + 4].copy_from_slice(&spiv_value.to_le_bytes());
        // xAPIC ID register at offset 0x20, bits [31:24]
        let id_offset = 0x20;
        let id_value: u32 = u32::from(apic_id) << 24;
        lapic[id_offset..id_offset + 4].copy_from_slice(&id_value.to_le_bytes());

        // Build MSR list with defaults
        let msrs: Vec<(u32, u64)> = SNAPSHOT_MSRS
            .iter()
            .map(|&index| {
                let value = if index == msr::IA32_PAT {
                    msr::IA32_PAT_DEFAULT
                } else {
                    0
                };
                (index, value)
            })
            .collect();

        // FPU state: x87 control word + MXCSR
        // kvm_fpu is 416 bytes; fcw at offset 0, mxcsr at offset 24
        let mut fpu = vec![0u8; 416];
        fpu[0..2].copy_from_slice(&0x37f_u16.to_le_bytes()); // fcw
        fpu[24..28].copy_from_slice(&0x1f80_u32.to_le_bytes()); // mxcsr

        Self {
            regs: X86GeneralRegs::default(),
            sregs: X86SegmentRegs::default(),
            fpu,
            xsave: Vec::new(),
            lapic,
            msrs,
            mp_state: MpState::InitReceived,
            xcrs: Vec::new(),
            debugregs: X86DebugRegs::default(),
            vcpu_events: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_snapshot() {
        let snap = X86VcpuSnapshot::empty();
        assert_eq!(snap.mp_state, MpState::Runnable);
        assert!(snap.msrs.is_empty());
        assert!(snap.fpu.is_empty());
        assert!(snap.lapic.is_empty());
        assert_eq!(snap.regs.rip, 0);
    }

    #[test]
    fn for_init_received_snapshot() {
        let snap = X86VcpuSnapshot::for_init_received(1);
        assert_eq!(snap.mp_state, MpState::InitReceived);
        assert_eq!(snap.msrs.len(), SNAPSHOT_MSRS.len());

        // Check PAT has default value
        let pat = snap.msrs.iter().find(|(idx, _)| *idx == msr::IA32_PAT);
        assert_eq!(pat, Some(&(msr::IA32_PAT, msr::IA32_PAT_DEFAULT)));

        // Check non-PAT MSRs are zero
        for &(idx, val) in &snap.msrs {
            if idx != msr::IA32_PAT {
                assert_eq!(val, 0, "MSR {idx:#x} should be 0");
            }
        }

        // Check LAPIC SPIV
        assert_eq!(snap.lapic.len(), 1024);
        let spiv = u32::from_le_bytes(snap.lapic[0xF0..0xF4].try_into().unwrap());
        assert_eq!(spiv, 0x1FF);

        // Check FPU defaults
        let fcw = u16::from_le_bytes(snap.fpu[0..2].try_into().unwrap());
        assert_eq!(fcw, 0x37f);
        let mxcsr = u32::from_le_bytes(snap.fpu[24..28].try_into().unwrap());
        assert_eq!(mxcsr, 0x1f80);
    }

    #[test]
    fn debug_regs_default() {
        let dregs = X86DebugRegs::default();
        assert_eq!(dregs.db, [0; 4]);
        assert_eq!(dregs.dr6, 0);
        assert_eq!(dregs.dr7, 0);
    }
}
