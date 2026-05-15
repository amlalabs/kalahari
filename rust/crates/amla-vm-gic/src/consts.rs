// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! `GICv3` register offsets, bit masks, and ICC sysreg encodings.
//!
//! All constants are derived from the ARM `GICv3` architecture specification
//! (IHI0069D) and verified against Linux kernel headers.

// =============================================================================
// Address Map (must match DTB in amla-boot-arm64/src/dtb.rs)
// =============================================================================

/// GICD (distributor) base address.
pub const GICD_BASE: u64 = 0x0800_0000;
/// GICD region size (64 KiB).
pub const GICD_SIZE: u64 = 0x1_0000;

/// GICR (redistributors) base address.
pub const GICR_BASE: u64 = 0x080A_0000;
/// Per-vCPU redistributor size (128 KiB = `RD_base` + `SGI_base`).
pub const GICR_CPU_SIZE: u64 = 0x2_0000;
/// `SGI_base` frame offset within each redistributor.
pub const GICR_SGI_BASE_OFFSET: u64 = 0x1_0000;

/// Total number of IRQs (32 SGI/PPI + 64 SPI).
pub const NR_IRQS: u32 = amla_boot::arm64::irq::GIC_NR_IRQS;
/// Number of SPIs (IRQs 32..96).
pub const NR_SPIS: u32 = amla_boot::arm64::irq::GIC_SPI_COUNT;
/// First SPI INTID.
pub const SPI_START: u32 = amla_boot::arm64::irq::GIC_SPI_START_INTID;

// =============================================================================
// GICD Register Offsets
// =============================================================================

pub const GICD_CTLR: u64 = 0x0000;
pub const GICD_TYPER: u64 = 0x0004;
pub const GICD_IIDR: u64 = 0x0008;
pub const GICD_IGROUPR: u64 = 0x0080;
pub const GICD_ISENABLER: u64 = 0x0100;
pub const GICD_ICENABLER: u64 = 0x0180;
pub const GICD_ISPENDR: u64 = 0x0200;
pub const GICD_ICPENDR: u64 = 0x0280;
pub const GICD_ISACTIVER: u64 = 0x0300;
pub const GICD_ICACTIVER: u64 = 0x0380;
pub const GICD_IPRIORITYR: u64 = 0x0400;
pub const GICD_ICFGR: u64 = 0x0C00;
pub const GICD_IGRPMODR: u64 = 0x0D00;
pub const GICD_IROUTER: u64 = 0x6100;
pub const GICD_PIDR2: u64 = 0xFFE8;

// =============================================================================
// GICD_CTLR Bit Definitions
// =============================================================================

/// Enable Group 1 Non-Secure interrupts.
pub const GICD_CTLR_ENABLE_GRP1A: u32 = 1 << 1;
/// Affinity Routing Enable (Non-Secure).
pub const GICD_CTLR_ARE_NS: u32 = 1 << 4;
/// Disable Security — read-only 1 (single security state).
pub const GICD_CTLR_DS: u32 = 1 << 6;

/// Read-only CTLR bits: DS is always 1, `ARE_NS` is forced on (no legacy mode).
pub const GICD_CTLR_RO_MASK: u32 = GICD_CTLR_DS | GICD_CTLR_ARE_NS;
/// Writable CTLR bits (`ARE_NS` is read-only since we only support affinity routing).
pub const GICD_CTLR_RW_MASK: u32 = GICD_CTLR_ENABLE_GRP1A;

// =============================================================================
// GICD_TYPER Encoding
// =============================================================================

/// `GICD_TYPER` value: `ITLinesNumber` = (NR_IRQS/32)-1 = 2.
pub const GICD_TYPER_VAL: u32 = (NR_IRQS / 32 - 1) & 0x1F;

/// `GICD_PIDR2` value: ArchRev=3 (`GICv3`) in bits \[7:4\].
pub const GICD_PIDR2_VAL: u32 = 0x3 << 4; // 0x30

/// `GICD_IIDR` value (implementation-defined). Amla VMM, revision 0.
pub const GICD_IIDR_VAL: u32 = 0x0000_0000;

// =============================================================================
// GICR Register Offsets (RD_base frame)
// =============================================================================

pub const GICR_CTLR: u64 = 0x0000;
pub const GICR_IIDR: u64 = 0x0004;
pub const GICR_TYPER: u64 = 0x0008;
pub const GICR_STATUSR: u64 = 0x0010;
pub const GICR_WAKER: u64 = 0x0014;
pub const GICR_PIDR2: u64 = 0xFFE8;

// =============================================================================
// GICR Register Offsets (SGI_base frame, relative to SGI_base)
// =============================================================================

pub const GICR_IGROUPR0: u64 = 0x0080;
pub const GICR_ISENABLER0: u64 = 0x0100;
pub const GICR_ICENABLER0: u64 = 0x0180;
pub const GICR_ISPENDR0: u64 = 0x0200;
pub const GICR_ICPENDR0: u64 = 0x0280;
pub const GICR_ISACTIVER0: u64 = 0x0300;
pub const GICR_ICACTIVER0: u64 = 0x0380;
pub const GICR_IPRIORITYR: u64 = 0x0400;
pub const GICR_ICFGR0: u64 = 0x0C00;
pub const GICR_ICFGR1: u64 = 0x0C04;
pub const GICR_IGRPMODR0: u64 = 0x0D00;

// =============================================================================
// GICR_WAKER Bits
// =============================================================================

/// `ProcessorSleep` bit.
pub const GICR_WAKER_PROCESSOR_SLEEP: u32 = 1 << 1;
/// `ChildrenAsleep` bit.
pub const GICR_WAKER_CHILDREN_ASLEEP: u32 = 1 << 2;

// =============================================================================
// ICC System Register Encodings (16-bit packed: Op0:Op1:CRn:CRm:Op2)
//
// Encoding: (Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2
// This matches the Linux sys_reg() macro.
// =============================================================================

/// Pack an ARM64 sysreg encoding into a 16-bit ID.
pub const fn icc_encode(op0: u32, op1: u32, crn: u32, crm: u32, op2: u32) -> u32 {
    (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2
}

pub const ICC_IAR1_EL1: u32 = icc_encode(3, 0, 12, 12, 0); // 0xC660
pub const ICC_EOIR1_EL1: u32 = icc_encode(3, 0, 12, 12, 1); // 0xC661
pub const ICC_HPPIR1_EL1: u32 = icc_encode(3, 0, 12, 12, 2); // 0xC662
pub const ICC_BPR1_EL1: u32 = icc_encode(3, 0, 12, 12, 3); // 0xC663
pub const ICC_CTLR_EL1: u32 = icc_encode(3, 0, 12, 12, 4); // 0xC664
pub const ICC_SRE_EL1: u32 = icc_encode(3, 0, 12, 12, 5); // 0xC665
pub const ICC_IGRPEN1_EL1: u32 = icc_encode(3, 0, 12, 12, 7); // 0xC667
pub const ICC_SGI1R_EL1: u32 = icc_encode(3, 0, 12, 11, 5); // 0xC65D
pub const ICC_DIR_EL1: u32 = icc_encode(3, 0, 12, 11, 1); // 0xC659
pub const ICC_RPR_EL1: u32 = icc_encode(3, 0, 12, 11, 3); // 0xC65B
pub const ICC_PMR_EL1: u32 = icc_encode(3, 0, 4, 6, 0); // 0xC230

pub const ICC_AP1R0_EL1: u32 = icc_encode(3, 0, 12, 9, 0); // 0xC648
pub const ICC_AP1R1_EL1: u32 = icc_encode(3, 0, 12, 9, 1); // 0xC649
pub const ICC_AP1R2_EL1: u32 = icc_encode(3, 0, 12, 9, 2); // 0xC64A
pub const ICC_AP1R3_EL1: u32 = icc_encode(3, 0, 12, 9, 3); // 0xC64B

pub const ICC_AP0R0_EL1: u32 = icc_encode(3, 0, 12, 8, 4); // 0xC644
pub const ICC_AP0R1_EL1: u32 = icc_encode(3, 0, 12, 8, 5); // 0xC645
pub const ICC_AP0R2_EL1: u32 = icc_encode(3, 0, 12, 8, 6); // 0xC646
pub const ICC_AP0R3_EL1: u32 = icc_encode(3, 0, 12, 8, 7); // 0xC647

// =============================================================================
// Special INTIDs (IHI0069D section 2.2)
// =============================================================================

/// Spurious INTID — returned by IAR when no interrupt qualifies.
pub const INTID_SPURIOUS: u32 = 1023;

/// First reserved special INTID.
pub const INTID_SPECIAL_START: u32 = 1020;

// =============================================================================
// Priority
// =============================================================================

/// Idle priority (no active interrupt).
pub const PRIORITY_IDLE: u8 = 0xFF;
/// Number of implemented priority bits (5 → 32 levels).
pub const PRIORITY_BITS: u32 = 5;
/// Mask for implemented priority bits (top 5 bits). Unimplemented low bits RAZ/WI.
#[allow(clippy::cast_possible_truncation)] // PRIORITY_BITS is always < 8
pub const PRIORITY_MASK: u8 = !((1u8 << (8 - PRIORITY_BITS as u8)) - 1); // 0xF8

// =============================================================================
// ICC_SRE_EL1 fixed value
// =============================================================================

/// SRE | DFB | DIB — system register interface always enabled.
pub const ICC_SRE_EL1_VAL: u64 = 0x7;

// =============================================================================
// ICC_CTLR_EL1 fixed bits
// =============================================================================

/// `PRI_BITS` field (bits \[10:8\]) = `PRIORITY_BITS` - 1 = 4.
pub const ICC_CTLR_PRI_BITS: u32 = (PRIORITY_BITS - 1) << 8;

/// Return whether the encoding is an ICC sysreg implemented by the userspace GIC.
pub const fn is_gic_sysreg(encoding: u32) -> bool {
    matches!(
        encoding,
        ICC_IAR1_EL1
            | ICC_EOIR1_EL1
            | ICC_HPPIR1_EL1
            | ICC_BPR1_EL1
            | ICC_CTLR_EL1
            | ICC_SRE_EL1
            | ICC_IGRPEN1_EL1
            | ICC_SGI1R_EL1
            | ICC_DIR_EL1
            | ICC_RPR_EL1
            | ICC_PMR_EL1
            | ICC_AP1R0_EL1
            | ICC_AP1R1_EL1
            | ICC_AP1R2_EL1
            | ICC_AP1R3_EL1
            | ICC_AP0R0_EL1
            | ICC_AP0R1_EL1
            | ICC_AP0R2_EL1
            | ICC_AP0R3_EL1
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn icc_encoding_iar1() {
        assert_eq!(ICC_IAR1_EL1, 0xC660);
    }

    #[test]
    fn icc_encoding_pmr() {
        assert_eq!(ICC_PMR_EL1, 0xC230);
    }

    #[test]
    fn icc_encoding_sgi1r() {
        assert_eq!(ICC_SGI1R_EL1, 0xC65D);
    }

    #[test]
    fn icc_encoding_eoir1() {
        assert_eq!(ICC_EOIR1_EL1, 0xC661);
    }

    #[test]
    fn icc_encoding_hppir1() {
        assert_eq!(ICC_HPPIR1_EL1, 0xC662);
    }

    #[test]
    fn icc_encoding_dir() {
        assert_eq!(ICC_DIR_EL1, 0xC659);
    }

    #[test]
    fn icc_encoding_rpr() {
        assert_eq!(ICC_RPR_EL1, 0xC65B);
    }

    #[test]
    fn icc_encoding_bpr1() {
        assert_eq!(ICC_BPR1_EL1, 0xC663);
    }

    #[test]
    fn icc_encoding_ctlr() {
        assert_eq!(ICC_CTLR_EL1, 0xC664);
    }

    #[test]
    fn icc_encoding_sre() {
        assert_eq!(ICC_SRE_EL1, 0xC665);
    }

    #[test]
    fn icc_encoding_igrpen1() {
        assert_eq!(ICC_IGRPEN1_EL1, 0xC667);
    }

    #[test]
    fn icc_encoding_ap1r0() {
        assert_eq!(ICC_AP1R0_EL1, 0xC648);
    }

    #[test]
    fn icc_encoding_ap0r0() {
        assert_eq!(ICC_AP0R0_EL1, 0xC644);
    }

    #[test]
    fn gicd_typer_encodes_96_irqs() {
        // ITLinesNumber = 2 → (2+1)*32 = 96 IRQs
        assert_eq!(GICD_TYPER_VAL, 2);
    }

    #[test]
    fn gicd_pidr2_arch_rev_3() {
        // ArchRev in bits [7:4] = 0x3
        assert_eq!((GICD_PIDR2_VAL >> 4) & 0xF, 3);
    }

    #[test]
    fn gicr_cpu_size_is_128k() {
        assert_eq!(GICR_CPU_SIZE, 0x2_0000);
    }

    #[test]
    fn address_map_no_overlap() {
        let gicd_end = GICD_BASE + GICD_SIZE;
        assert!(gicd_end <= GICR_BASE, "GICD overlaps GICR");

        // 8 vCPUs max check
        let gicr_max = GICR_BASE + 8 * GICR_CPU_SIZE;
        assert!(gicr_max <= 0x0900_0000, "GICR overlaps UART at 0x0900_0000");
    }
}
