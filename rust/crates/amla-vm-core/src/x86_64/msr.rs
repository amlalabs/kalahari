// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` Model Specific Register (MSR) index constants.
//!
//! These are architecture-defined values from the Intel/AMD SDMs, shared across
//! hypervisor backends (KVM, WHP/Hyper-V). KVM paravirt MSRs are also included
//! since KVM+WHP paravirt is a common pattern.

// ============================================================================
// Architecture MSRs (Intel/AMD SDM)
// ============================================================================

/// Timestamp counter.
pub const IA32_TSC: u32 = 0x10;
/// TSC adjustment (added to TSC on RDTSC).
pub const IA32_TSC_ADJUST: u32 = 0x3b;
/// APIC base address.
pub const IA32_APIC_BASE: u32 = 0x1b;
/// 32-bit SYSENTER code segment.
pub const IA32_SYSENTER_CS: u32 = 0x174;
/// 32-bit SYSENTER stack pointer.
pub const IA32_SYSENTER_ESP: u32 = 0x175;
/// 32-bit SYSENTER instruction pointer.
pub const IA32_SYSENTER_EIP: u32 = 0x176;
/// 64-bit SYSCALL segment selectors (CS/SS for SYSCALL/SYSRET).
pub const IA32_STAR: u32 = 0xc000_0081;
/// 64-bit SYSCALL entry point (long mode).
pub const IA32_LSTAR: u32 = 0xc000_0082;
/// Compat mode SYSCALL entry point.
pub const IA32_CSTAR: u32 = 0xc000_0083;
/// SYSCALL RFLAGS mask.
pub const IA32_FMASK: u32 = 0xc000_0084;
/// FS segment base (used for TLS).
pub const IA32_FS_BASE: u32 = 0xc000_0100;
/// GS segment base.
pub const IA32_GS_BASE: u32 = 0xc000_0101;
/// Kernel GS base (target for SWAPGS).
pub const IA32_KERNEL_GS_BASE: u32 = 0xc000_0102;
/// Page Attribute Table.
pub const IA32_PAT: u32 = 0x277;
/// Miscellaneous feature enables.
pub const IA32_MISC_ENABLE: u32 = 0x1a0;
/// Spectre mitigation control.
pub const IA32_SPEC_CTRL: u32 = 0x48;
/// LAPIC TSC deadline timer.
pub const IA32_TSC_DEADLINE: u32 = 0x6e0;
/// RDTSCP auxiliary value.
pub const IA32_TSC_AUX: u32 = 0xc000_0103;
/// Extended feature enables for XSAVES/XRSTORS (supervisor components).
///
/// Controls which supervisor XSAVE components (e.g. CET) are enabled.
/// Must be captured/restored for snapshot correctness — without it,
/// `xrstors` in the guest kernel faults with `#GP` because supervisor
/// components referenced by fpstate are missing from `XCR0 | XSS`.
pub const IA32_XSS: u32 = 0x0DA0;

// ============================================================================
// KVM Paravirt MSRs
// ============================================================================

/// KVM paravirt wall clock (new interface).
pub const MSR_KVM_WALL_CLOCK_NEW: u32 = 0x4b56_4d00;
/// KVM paravirt system time (new interface).
pub const MSR_KVM_SYSTEM_TIME_NEW: u32 = 0x4b56_4d01;
/// KVM async page fault enable.
pub const MSR_KVM_ASYNC_PF_EN: u32 = 0x4b56_4d02;
/// KVM steal time accounting.
pub const MSR_KVM_STEAL_TIME: u32 = 0x4b56_4d03;
/// KVM paravirt EOI enable.
pub const MSR_KVM_PV_EOI_EN: u32 = 0x4b56_4d04;

// ============================================================================
// AMD/Hygon vendor-specific MSRs
// ============================================================================

/// AMD K7 Hardware Configuration Register.
///
/// Bit 24 (`TscFreqSel`) asserts that the TSC counts at the P0 frequency
/// (invariant TSC). AMD family >= 0x11 with `X86_FEATURE_CONSTANT_TSC`
/// warns `[Firmware Bug] TSC doesn't count with P0 frequency!` when this
/// bit is clear. KVM returns 0 by default, so VMMs that advertise an AMD
/// CPU must set it explicitly.
pub const MSR_K7_HWCR: u32 = 0xc001_0015;

/// `MSR_K7_HWCR` bit 24 = `TscFreqSel`.
pub const MSR_K7_HWCR_TSCFREQSEL: u64 = 1 << 24;

// ============================================================================
// Canonical MSR list for snapshots
// ============================================================================

/// Ordered list of MSRs to capture/restore for deterministic serialization.
pub const SNAPSHOT_MSRS: &[u32] = &[
    IA32_TSC,
    IA32_TSC_ADJUST,
    IA32_APIC_BASE,
    IA32_SYSENTER_CS,
    IA32_SYSENTER_ESP,
    IA32_SYSENTER_EIP,
    IA32_STAR,
    IA32_LSTAR,
    IA32_CSTAR,
    IA32_FMASK,
    IA32_FS_BASE,
    IA32_GS_BASE,
    IA32_KERNEL_GS_BASE,
    IA32_PAT,
    IA32_MISC_ENABLE,
    IA32_SPEC_CTRL,
    IA32_TSC_DEADLINE,
    IA32_TSC_AUX,
    IA32_XSS,
    MSR_KVM_WALL_CLOCK_NEW,
    MSR_KVM_SYSTEM_TIME_NEW,
    MSR_KVM_ASYNC_PF_EN,
    MSR_KVM_STEAL_TIME,
    MSR_KVM_PV_EOI_EN,
];

/// Default PAT (Page Attribute Table) value after processor reset.
///
/// Each of the 8 PAT entries is 3 bits, packed into a 64-bit value.
/// The default maps: WB, WT, UC-, UC, WB, WT, UC-, UC.
pub const IA32_PAT_DEFAULT: u64 = 0x0007_0406_0007_0406;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_msrs_count() {
        assert_eq!(SNAPSHOT_MSRS.len(), 24);
    }

    #[test]
    fn snapshot_msrs_no_duplicates() {
        let mut sorted = SNAPSHOT_MSRS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), SNAPSHOT_MSRS.len(), "duplicate MSR indices");
    }

    #[test]
    fn architecture_msr_values() {
        assert_eq!(IA32_TSC, 0x10);
        assert_eq!(IA32_LSTAR, 0xc000_0082);
        assert_eq!(IA32_PAT, 0x277);
        assert_eq!(IA32_SPEC_CTRL, 0x48);
        assert_eq!(IA32_XSS, 0x0DA0);
    }

    #[test]
    fn kvm_paravirt_msr_range() {
        // KVM paravirt MSRs are in the 0x4b564dXX range
        for &msr in &[
            MSR_KVM_WALL_CLOCK_NEW,
            MSR_KVM_SYSTEM_TIME_NEW,
            MSR_KVM_ASYNC_PF_EN,
            MSR_KVM_STEAL_TIME,
            MSR_KVM_PV_EOI_EN,
        ] {
            assert!(
                (0x4b56_4d00..=0x4b56_4d0f).contains(&msr),
                "MSR {msr:#x} not in KVM range"
            );
        }
    }

    #[test]
    fn pat_default_value() {
        assert_eq!(IA32_PAT_DEFAULT, 0x0007_0406_0007_0406);
    }
}
