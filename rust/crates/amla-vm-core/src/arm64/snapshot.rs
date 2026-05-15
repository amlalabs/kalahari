// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 shared register types and snapshot structures.
//!
//! These types are hypervisor-agnostic — usable by both HVF (macOS) and
//! KVM (Linux) ARM64 backends for snapshot/restore operations.

// =============================================================================
// Shared ARM64 register types (hypervisor-agnostic)
// =============================================================================

/// ARM64 general-purpose and control registers.
///
/// Sequential discriminants (0–34) match the Apple HVF `hv_reg_t` ABI so
/// snapshots are format-compatible across backends. Each backend maps these
/// to its native register encoding:
/// - HVF: `hv_reg_t` (identical numeric values)
/// - KVM: `KVM_REG_ARM64 | ...` bit-packed encoding
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Arm64Reg {
    /// General-purpose register X0.
    X0 = 0,
    /// General-purpose register X1.
    X1 = 1,
    /// General-purpose register X2.
    X2 = 2,
    /// General-purpose register X3.
    X3 = 3,
    /// General-purpose register X4.
    X4 = 4,
    /// General-purpose register X5.
    X5 = 5,
    /// General-purpose register X6.
    X6 = 6,
    /// General-purpose register X7.
    X7 = 7,
    /// General-purpose register X8.
    X8 = 8,
    /// General-purpose register X9.
    X9 = 9,
    /// General-purpose register X10.
    X10 = 10,
    /// General-purpose register X11.
    X11 = 11,
    /// General-purpose register X12.
    X12 = 12,
    /// General-purpose register X13.
    X13 = 13,
    /// General-purpose register X14.
    X14 = 14,
    /// General-purpose register X15.
    X15 = 15,
    /// General-purpose register X16.
    X16 = 16,
    /// General-purpose register X17.
    X17 = 17,
    /// General-purpose register X18.
    X18 = 18,
    /// General-purpose register X19.
    X19 = 19,
    /// General-purpose register X20.
    X20 = 20,
    /// General-purpose register X21.
    X21 = 21,
    /// General-purpose register X22.
    X22 = 22,
    /// General-purpose register X23.
    X23 = 23,
    /// General-purpose register X24.
    X24 = 24,
    /// General-purpose register X25.
    X25 = 25,
    /// General-purpose register X26.
    X26 = 26,
    /// General-purpose register X27.
    X27 = 27,
    /// General-purpose register X28.
    X28 = 28,
    /// Frame pointer (X29).
    X29 = 29,
    /// Link register (X30).
    X30 = 30,
    /// Program counter.
    PC = 31,
    /// Floating-point control register.
    FPCR = 32,
    /// Floating-point status register.
    FPSR = 33,
    /// Current program status register.
    CPSR = 34,
}

impl Arm64Reg {
    /// Frame pointer alias.
    pub const FP: Self = Self::X29;
    /// Link register alias.
    pub const LR: Self = Self::X30;
    /// Total number of registers in a full snapshot.
    pub const COUNT: usize = 35;

    /// Array index for this register (matches discriminant).
    #[inline]
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// ARM64 system registers for snapshot/restore.
///
/// The `encoding()` values match the Apple HVF `hv_sys_reg_t` discriminants
/// so that serialized snapshots are format-compatible across backends.
#[repr(u16)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Arm64SysReg {
    /// System control register.
    SctlrEl1 = 0xc080,
    /// Architectural feature access control.
    CpacrEl1 = 0xc082,
    /// Translation table base register 0.
    Ttbr0El1 = 0xc100,
    /// Translation table base register 1.
    Ttbr1El1 = 0xc101,
    /// Translation control register.
    TcrEl1 = 0xc102,
    /// Saved program status register (EL1).
    SpsrEl1 = 0xc200,
    /// Exception link register (EL1).
    ElrEl1 = 0xc201,
    /// Stack pointer (EL0).
    SpEl0 = 0xc208,
    /// Stack pointer (EL1).
    SpEl1 = 0xe208,
    /// Exception syndrome register (EL1).
    EsrEl1 = 0xc290,
    /// Fault address register (EL1).
    FarEl1 = 0xc300,
    /// Memory attribute indirection register.
    MairEl1 = 0xc510,
    /// Vector base address register.
    VbarEl1 = 0xc600,
    /// Counter-timer virtual timer control.
    CntvCtlEl0 = 0xdf19,
    /// Counter-timer virtual timer compare value.
    CntvCvalEl0 = 0xdf1a,
    /// Counter-timer physical timer control (EL0).
    ///
    /// Linux on arm64 uses the *virtual* timer for event delivery, not this
    /// one. We save/restore it anyway so guest-visible state round-trips
    /// cleanly across snapshots, and initialise each new vCPU with CTL=0 to
    /// prevent HVF's `update_physical_timer_ppis` from storming PPI 30.
    CntpCtlEl0 = 0xdf11,
    /// Counter-timer physical timer compare value (EL0).
    CntpCvalEl0 = 0xdf12,
    /// Thread pointer (EL0). Used by kernel for TLS/per-CPU data.
    TpidrEl0 = 0xde82,
    /// Thread pointer (EL1). Kernel stores current task or per-CPU offset.
    TpidrEl1 = 0xc684,
    /// Thread pointer (read-only from EL0).
    TpidrroEl0 = 0xde83,
    /// Counter-timer kernel control. Controls timer access from EL0.
    CntkctlEl1 = 0xc708,
    /// Context ID register (EL1). Used for TLB management.
    ContextidrEl1 = 0xc681,
}

impl Arm64SysReg {
    /// Stable numeric encoding for serialization (matches HVF discriminants).
    #[inline]
    pub const fn encoding(self) -> u16 {
        self as u16
    }
}

/// All 31 general-purpose registers in order.
pub const GP_REGS: [Arm64Reg; 31] = [
    Arm64Reg::X0,
    Arm64Reg::X1,
    Arm64Reg::X2,
    Arm64Reg::X3,
    Arm64Reg::X4,
    Arm64Reg::X5,
    Arm64Reg::X6,
    Arm64Reg::X7,
    Arm64Reg::X8,
    Arm64Reg::X9,
    Arm64Reg::X10,
    Arm64Reg::X11,
    Arm64Reg::X12,
    Arm64Reg::X13,
    Arm64Reg::X14,
    Arm64Reg::X15,
    Arm64Reg::X16,
    Arm64Reg::X17,
    Arm64Reg::X18,
    Arm64Reg::X19,
    Arm64Reg::X20,
    Arm64Reg::X21,
    Arm64Reg::X22,
    Arm64Reg::X23,
    Arm64Reg::X24,
    Arm64Reg::X25,
    Arm64Reg::X26,
    Arm64Reg::X27,
    Arm64Reg::X28,
    Arm64Reg::X29,
    Arm64Reg::X30,
];

/// All 35 registers needed for a complete vCPU snapshot.
///
/// Compile-time assertion ensures this array stays in sync with `Arm64Reg::COUNT`.
pub const ALL_REGS: [Arm64Reg; 35] = [
    Arm64Reg::X0,
    Arm64Reg::X1,
    Arm64Reg::X2,
    Arm64Reg::X3,
    Arm64Reg::X4,
    Arm64Reg::X5,
    Arm64Reg::X6,
    Arm64Reg::X7,
    Arm64Reg::X8,
    Arm64Reg::X9,
    Arm64Reg::X10,
    Arm64Reg::X11,
    Arm64Reg::X12,
    Arm64Reg::X13,
    Arm64Reg::X14,
    Arm64Reg::X15,
    Arm64Reg::X16,
    Arm64Reg::X17,
    Arm64Reg::X18,
    Arm64Reg::X19,
    Arm64Reg::X20,
    Arm64Reg::X21,
    Arm64Reg::X22,
    Arm64Reg::X23,
    Arm64Reg::X24,
    Arm64Reg::X25,
    Arm64Reg::X26,
    Arm64Reg::X27,
    Arm64Reg::X28,
    Arm64Reg::X29,
    Arm64Reg::X30,
    Arm64Reg::PC,
    Arm64Reg::FPCR,
    Arm64Reg::FPSR,
    Arm64Reg::CPSR,
];

// Compile-time check: ALL_REGS must contain exactly Arm64Reg::COUNT entries.
// This catches missing registers when new variants are added to Arm64Reg.
const _: () = assert!(ALL_REGS.len() == Arm64Reg::COUNT);

/// Key system registers for a minimal vCPU snapshot.
pub const SNAPSHOT_SYS_REGS: [Arm64SysReg; 22] = [
    Arm64SysReg::SctlrEl1,
    Arm64SysReg::CpacrEl1,
    Arm64SysReg::Ttbr0El1,
    Arm64SysReg::Ttbr1El1,
    Arm64SysReg::TcrEl1,
    Arm64SysReg::SpsrEl1,
    Arm64SysReg::ElrEl1,
    Arm64SysReg::SpEl0,
    Arm64SysReg::SpEl1,
    Arm64SysReg::EsrEl1,
    Arm64SysReg::FarEl1,
    Arm64SysReg::MairEl1,
    Arm64SysReg::VbarEl1,
    Arm64SysReg::CntvCtlEl0,
    Arm64SysReg::CntvCvalEl0,
    Arm64SysReg::CntpCtlEl0,
    Arm64SysReg::CntpCvalEl0,
    // Thread pointers — kernel uses for per-CPU data and TLS.
    // Without these, the kernel can't find its own task_struct or
    // per-CPU structures and silently hangs.
    Arm64SysReg::TpidrEl0,
    Arm64SysReg::TpidrEl1,
    Arm64SysReg::TpidrroEl0,
    Arm64SysReg::CntkctlEl1,
    Arm64SysReg::ContextidrEl1,
];

/// Number of NEON/SIMD registers (V0–V31), each 128-bit.
pub const SIMD_REG_COUNT: usize = 32;

/// Snapshot of an ARM64 vCPU's register state.
///
/// Shared between KVM and HVF backends. System register keys use the
/// stable `encoding()` values so snapshots are portable across backends.
#[derive(Debug, Clone)]
pub struct Arm64VcpuSnapshot {
    /// General-purpose registers: X0–X30, PC, FPCR, FPSR, CPSR (35 values).
    pub gp_regs: Vec<u64>,
    /// System registers as (encoding, value) pairs.
    pub sys_regs: Vec<(u16, u64)>,
    /// NEON/SIMD registers V0–V31 (128-bit each).
    pub simd_regs: Vec<u128>,
}

impl Arm64VcpuSnapshot {
    /// Create an empty snapshot (all registers zero).
    pub fn empty() -> Self {
        Self {
            gp_regs: vec![0; Arm64Reg::COUNT],
            sys_regs: Vec::new(),
            simd_regs: vec![0; SIMD_REG_COUNT],
        }
    }

    /// Create a snapshot for an AP in powered-off state (awaiting PSCI `CPU_ON`).
    ///
    /// ARM64 APs start powered off with all registers zero — the kernel
    /// sets them via the PSCI `CPU_ON` entry point and context ID.
    ///
    /// Hypervisor backends add their own metadata on top (e.g. KVM adds
    /// `power_state = KVM_MP_STATE_STOPPED`).
    pub fn for_ap_powered_off() -> Self {
        Self::empty()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gp_regs_count() {
        assert_eq!(GP_REGS.len(), 31);
    }

    #[test]
    fn all_regs_count() {
        assert_eq!(ALL_REGS.len(), Arm64Reg::COUNT);
    }

    #[test]
    fn gp_regs_sequential() {
        for (i, reg) in GP_REGS.iter().enumerate() {
            assert_eq!(reg.index(), i);
        }
    }

    #[test]
    fn all_regs_includes_control() {
        assert!(ALL_REGS.contains(&Arm64Reg::PC));
        assert!(ALL_REGS.contains(&Arm64Reg::FPCR));
        assert!(ALL_REGS.contains(&Arm64Reg::FPSR));
        assert!(ALL_REGS.contains(&Arm64Reg::CPSR));
    }

    #[test]
    fn snapshot_sys_regs_essential() {
        assert!(SNAPSHOT_SYS_REGS.contains(&Arm64SysReg::SctlrEl1));
        assert!(SNAPSHOT_SYS_REGS.contains(&Arm64SysReg::Ttbr0El1));
        assert!(SNAPSHOT_SYS_REGS.contains(&Arm64SysReg::SpsrEl1));
        assert!(SNAPSHOT_SYS_REGS.contains(&Arm64SysReg::CntvCtlEl0));
    }

    #[test]
    fn sys_reg_encodings_match_hvf() {
        assert_eq!(Arm64SysReg::SctlrEl1.encoding(), 0xc080);
        assert_eq!(Arm64SysReg::Ttbr0El1.encoding(), 0xc100);
        assert_eq!(Arm64SysReg::SpsrEl1.encoding(), 0xc200);
        assert_eq!(Arm64SysReg::SpEl1.encoding(), 0xe208);
        assert_eq!(Arm64SysReg::CntvCvalEl0.encoding(), 0xdf1a);
    }

    #[test]
    fn reg_aliases() {
        assert_eq!(Arm64Reg::FP, Arm64Reg::X29);
        assert_eq!(Arm64Reg::LR, Arm64Reg::X30);
    }

    #[test]
    fn vcpu_snapshot_empty() {
        let snap = Arm64VcpuSnapshot::empty();
        assert_eq!(snap.gp_regs.len(), 35);
        assert!(snap.sys_regs.is_empty());
        assert!(snap.gp_regs.iter().all(|&v| v == 0));
        assert_eq!(snap.simd_regs.len(), SIMD_REG_COUNT);
        assert!(snap.simd_regs.iter().all(|&v| v == 0));
    }

    #[test]
    fn vcpu_snapshot_ap_powered_off() {
        let snap = Arm64VcpuSnapshot::for_ap_powered_off();
        assert_eq!(snap.gp_regs.len(), Arm64Reg::COUNT);
        assert!(snap.gp_regs.iter().all(|&v| v == 0));
        assert!(snap.sys_regs.is_empty());
        assert_eq!(snap.simd_regs.len(), SIMD_REG_COUNT);
    }
}
