// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 `ESR_EL2` syndrome decoding.
//!
//! Pure logic for decoding `ESR_EL2` syndrome values into structured types.
//! Hypervisor-agnostic — usable by both HVF (macOS) and KVM (Linux) backends.

use crate::{ExitSource, VcpuExit};

// =============================================================================
// ESR_EL2 bitfield constants
// =============================================================================

/// Exception Class: bits [31:26] of `ESR_EL2`.
const EC_SHIFT: u32 = 26;
const EC_MASK: u64 = 0x3F;

/// Data Abort from lower EL (EC = 0x24).
pub const EC_DATA_ABORT_LOWER: u64 = 0x24;
/// Data Abort from same EL (EC = 0x25).
pub const EC_DATA_ABORT_SAME: u64 = 0x25;
/// HVC instruction from `AArch64` (EC = 0x16).
pub const EC_HVC64: u64 = 0x16;
/// WFI/WFE instruction (EC = 0x01).
pub const EC_WFI_WFE: u64 = 0x01;
/// MSR/MRS/System instruction trap (EC = 0x18).
pub const EC_SYSREG: u64 = 0x18;

/// Instruction Syndrome Valid: bit 24.
const ISV_BIT: u64 = 1 << 24;
/// Syndrome Access Size: bits [23:22].
const SAS_SHIFT: u32 = 22;
const SAS_MASK: u64 = 0x3;
/// Syndrome Register Transfer: bits [20:16].
const SRT_SHIFT: u32 = 16;
const SRT_MASK: u64 = 0x1F;
/// Write not Read: bit 6.
const WNR_BIT: u64 = 1 << 6;
/// Data Fault Status Code: bits [5:0].
const DFSC_MASK: u64 = 0x3F;

/// Translation faults (DFSC 0x04–0x07): level 0–3 translation fault.
const DFSC_TRANSLATION_L0: u64 = 0x04;
const DFSC_TRANSLATION_L3: u64 = 0x07;

// =============================================================================
// Decoded MMIO information
// =============================================================================

/// Decoded MMIO access from a data abort syndrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmioAccess {
    /// Guest physical address (IPA) of the access.
    pub addr: u64,
    /// Access size in bytes (1, 2, 4, or 8).
    pub size: u8,
    /// The register index involved (SRT field, 0–30 = X0–X30).
    pub register: u32,
    /// Whether this is a write (true) or read (false).
    pub is_write: bool,
}

/// Decoded system register access from an EC=0x18 syndrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysRegAccess {
    /// Packed register encoding: `(Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2`.
    /// Matches the Linux kernel's `sys_reg()` macro encoding.
    pub encoding: u32,
    /// Guest register index (Rt field): 0-30 = X0-X30, 31 = XZR.
    pub register: u32,
    /// Whether this is a write (MSR, guest writes to sysreg) or read (MRS, guest reads sysreg).
    pub is_write: bool,
}

/// Decode a system register trap syndrome (EC = 0x18).
///
/// ISS bit layout for EC=0x18 (verified against Linux `esr.h`):
/// - Bits \[21:20\] = Op0
/// - Bits \[19:17\] = Op2 (note: Op2 before Op1!)
/// - Bits \[16:14\] = Op1
/// - Bits \[13:10\] = `CRn`
/// - Bits \[9:5\]   = Rt (register transfer)
/// - Bits \[4:1\]   = `CRm`
/// - Bit \[0\]      = Direction (0 = MSR/write, 1 = MRS/read)
pub const fn decode_sysreg(iss: u64) -> SysRegAccess {
    let op0 = ((iss >> 20) & 0x3) as u32;
    let op2 = ((iss >> 17) & 0x7) as u32;
    let op1 = ((iss >> 14) & 0x7) as u32;
    let crn = ((iss >> 10) & 0xF) as u32;
    let rt = ((iss >> 5) & 0x1F) as u32;
    let crm = ((iss >> 1) & 0xF) as u32;
    let is_read = (iss & 1) == 1;

    let encoding = (op0 << 14) | (op1 << 11) | (crn << 7) | (crm << 3) | op2;

    SysRegAccess {
        encoding,
        register: rt,
        is_write: !is_read,
    }
}

/// Result of decoding an `ESR_EL2` data abort syndrome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataAbortDecode {
    /// Successfully decoded as an MMIO access.
    Mmio(MmioAccess),
    /// Not a translation fault — some other data fault type.
    NotTranslationFault(u64),
    /// ISV bit not set — can't decode the instruction (e.g., LDP/STP).
    IsvNotSet,
}

/// Result of decoding an HVC call via X0 register.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HvcDecode {
    Shutdown,
    Reboot,
    /// PSCI `CPU_OFF` — stop the calling vCPU only (not the entire VM).
    CpuOff,
    /// PSCI `CPU_ON` — start a stopped vCPU.
    CpuOn {
        /// MPIDR of the target CPU.
        target_cpu: u64,
        /// Entry point address.
        entry_point: u64,
        /// Context ID (passed in x0 to target).
        context_id: u64,
    },
    /// PSCI `AFFINITY_INFO` — query a CPU's power state.
    AffinityInfo {
        /// MPIDR of the target CPU.
        target_cpu: u64,
        /// Lowest affinity level requested by the guest.
        lowest_affinity_level: u64,
    },
    Unknown(u64),
}

/// Decoded ARM64 exception from `ESR_EL2`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExceptionDecode {
    /// Data abort decoded as an MMIO access, WFI, or PSCI call.
    DataAbort(DataAbortDecode),
    /// HVC (hypercall) decoded as PSCI or unknown.
    Hvc(HvcDecode),
    /// WFI or WFE instruction — guest is idle.
    Wfi,
    /// System register access (MSR/MRS trap, EC = 0x18).
    SysReg(SysRegAccess),
    /// Unknown exception class.
    UnknownEc(u64),
}

// =============================================================================
// Decoding functions
// =============================================================================

/// Extract the Exception Class (EC) field from an `ESR_EL2` value.
#[inline]
pub const fn extract_ec(syndrome: u64) -> u64 {
    (syndrome >> EC_SHIFT) & EC_MASK
}

/// Extract the SRT (source/destination register transfer) field.
#[inline]
pub const fn extract_srt(syndrome: u64) -> u32 {
    ((syndrome >> SRT_SHIFT) & SRT_MASK) as u32
}

/// Decode a data abort syndrome (EC = 0x24 or 0x25).
///
/// # Arguments
/// - `syndrome`: `ESR_EL2` value
/// - `ipa`: Intermediate Physical Address (guest physical address from `FAR_EL2` / `HPFAR_EL2`)
pub fn decode_data_abort(syndrome: u64, ipa: u64) -> DataAbortDecode {
    let dfsc = syndrome & DFSC_MASK;

    // Only decode MMIO for translation faults (levels 0–3).
    if !(DFSC_TRANSLATION_L0..=DFSC_TRANSLATION_L3).contains(&dfsc) {
        return DataAbortDecode::NotTranslationFault(dfsc);
    }

    // ISV must be set to decode the instruction syndrome.
    if syndrome & ISV_BIT == 0 {
        return DataAbortDecode::IsvNotSet;
    }

    let sas = (syndrome >> SAS_SHIFT) & SAS_MASK;
    let size = 1u8 << sas; // 0→1, 1→2, 2→4, 3→8
    let register = extract_srt(syndrome);
    let is_write = syndrome & WNR_BIT != 0;

    DataAbortDecode::Mmio(MmioAccess {
        addr: ipa,
        size,
        register,
        is_write,
    })
}

/// Decode an HVC call by examining the PSCI function ID in X0.
///
/// `x1`-`x3` are needed for calls like `CPU_ON` that pass arguments.
pub const fn decode_hvc(x0: u64, x1: u64, x2: u64, x3: u64) -> HvcDecode {
    use super::{
        PSCI_AFFINITY_INFO_32, PSCI_AFFINITY_INFO_64, PSCI_CPU_OFF, PSCI_CPU_ON, PSCI_SYSTEM_OFF,
        PSCI_SYSTEM_RESET,
    };

    match x0 {
        PSCI_SYSTEM_OFF => HvcDecode::Shutdown,
        PSCI_CPU_OFF => HvcDecode::CpuOff,
        PSCI_SYSTEM_RESET => HvcDecode::Reboot,
        PSCI_CPU_ON => HvcDecode::CpuOn {
            target_cpu: x1,
            entry_point: x2,
            context_id: x3,
        },
        PSCI_AFFINITY_INFO_32 | PSCI_AFFINITY_INFO_64 => HvcDecode::AffinityInfo {
            target_cpu: x1,
            lowest_affinity_level: x2,
        },
        _ => HvcDecode::Unknown(x0),
    }
}

/// Decode an ARM64 exception from the `ESR_EL2` syndrome.
///
/// # Arguments
/// - `syndrome`: `ESR_EL2` value
/// - `ipa`: Guest physical address (for data aborts)
/// - `x0`-`x3`: General-purpose registers (for HVC/PSCI decoding)
pub fn decode_exception(
    syndrome: u64,
    ipa: u64,
    x0: u64,
    x1: u64,
    x2: u64,
    x3: u64,
) -> ExceptionDecode {
    let ec = extract_ec(syndrome);

    match ec {
        EC_DATA_ABORT_LOWER | EC_DATA_ABORT_SAME => {
            ExceptionDecode::DataAbort(decode_data_abort(syndrome, ipa))
        }
        EC_HVC64 => ExceptionDecode::Hvc(decode_hvc(x0, x1, x2, x3)),
        EC_WFI_WFE => ExceptionDecode::Wfi,
        EC_SYSREG => {
            let iss = syndrome & 0x01FF_FFFF; // ISS is bits [24:0]
            ExceptionDecode::SysReg(decode_sysreg(iss))
        }
        _ => ExceptionDecode::UnknownEc(ec),
    }
}

/// Convert a decoded exception into a `VcpuExit`.
///
/// For MMIO writes, `write_data` must be provided (read from the source register
/// by the caller). For MMIO reads, the caller is responsible for writing the
/// response into the destination register after handling the exit.
pub const fn exception_to_vcpu_exit(decoded: ExceptionDecode, write_data: u64) -> VcpuExit {
    match decoded {
        ExceptionDecode::Wfi => VcpuExit::Halt,

        ExceptionDecode::Hvc(hvc) => match hvc {
            HvcDecode::Shutdown => VcpuExit::CleanShutdown,
            HvcDecode::Reboot => VcpuExit::Reboot,
            HvcDecode::CpuOff => VcpuExit::CpuOff,
            HvcDecode::CpuOn {
                target_cpu,
                entry_point,
                context_id,
            } => VcpuExit::CpuOn {
                target_cpu,
                entry_point,
                context_id,
            },
            HvcDecode::AffinityInfo {
                target_cpu,
                lowest_affinity_level,
            } => VcpuExit::CpuAffinityInfo {
                target_cpu,
                lowest_affinity_level,
            },
            HvcDecode::Unknown(fid) => VcpuExit::Unknown {
                code: fid.cast_signed(),
                source: ExitSource::HvcFunctionId,
            },
        },

        ExceptionDecode::DataAbort(da) => match da {
            DataAbortDecode::Mmio(mmio) if mmio.is_write => VcpuExit::MmioWrite {
                addr: mmio.addr,
                data: write_data,
                size: mmio.size,
            },
            DataAbortDecode::Mmio(mmio) => VcpuExit::MmioRead {
                addr: mmio.addr,
                size: mmio.size,
            },
            DataAbortDecode::NotTranslationFault(dfsc) => VcpuExit::Unknown {
                code: dfsc.cast_signed(),
                source: ExitSource::DataFaultStatus,
            },
            DataAbortDecode::IsvNotSet => VcpuExit::Unknown {
                code: -2,
                source: ExitSource::InstructionNotDecodable,
            },
        },

        ExceptionDecode::SysReg(access) => VcpuExit::SysReg {
            encoding: access.encoding,
            register: access.register,
            is_write: access.is_write,
            write_data: if access.is_write { write_data } else { 0 },
        },

        ExceptionDecode::UnknownEc(ec) => VcpuExit::Unknown {
            code: ec.cast_signed(),
            source: ExitSource::ExceptionClass,
        },
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arm64::{PSCI_CPU_OFF, PSCI_SYSTEM_OFF, PSCI_SYSTEM_RESET};

    /// Build a data abort syndrome with the given fields.
    fn make_syndrome(ec: u64, isv: bool, sas: u64, wnr: bool, srt: u64, dfsc: u64) -> u64 {
        let mut syn = (ec & EC_MASK) << EC_SHIFT;
        if isv {
            syn |= ISV_BIT;
        }
        syn |= (sas & SAS_MASK) << SAS_SHIFT;
        syn |= (srt & SRT_MASK) << SRT_SHIFT;
        if wnr {
            syn |= WNR_BIT;
        }
        syn |= dfsc & DFSC_MASK;
        syn
    }

    // --- extract_ec ---

    #[test]
    fn extract_ec_data_abort() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, false, 0, 0x04);
        assert_eq!(extract_ec(syn), EC_DATA_ABORT_LOWER);
    }

    #[test]
    fn extract_ec_hvc() {
        let syn = (EC_HVC64 & EC_MASK) << EC_SHIFT;
        assert_eq!(extract_ec(syn), EC_HVC64);
    }

    // --- extract_srt ---

    #[test]
    fn extract_srt_various() {
        for reg in [0_u32, 5, 15, 30] {
            let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, true, u64::from(reg), 0x04);
            assert_eq!(extract_srt(syn), reg);
        }
    }

    // --- decode_data_abort ---

    #[test]
    fn data_abort_mmio_read_word() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, false, 5, 0x04);
        match decode_data_abort(syn, 0xd000_0000) {
            DataAbortDecode::Mmio(mmio) => {
                assert_eq!(mmio.addr, 0xd000_0000);
                assert_eq!(mmio.size, 4);
                assert_eq!(mmio.register, 5);
                assert!(!mmio.is_write);
            }
            other => panic!("expected Mmio, got {other:?}"),
        }
    }

    #[test]
    fn data_abort_mmio_write_byte() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 0, true, 3, 0x05);
        match decode_data_abort(syn, 0xd000_1000) {
            DataAbortDecode::Mmio(mmio) => {
                assert_eq!(mmio.addr, 0xd000_1000);
                assert_eq!(mmio.size, 1);
                assert_eq!(mmio.register, 3);
                assert!(mmio.is_write);
            }
            other => panic!("expected Mmio, got {other:?}"),
        }
    }

    #[test]
    fn data_abort_mmio_doubleword() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 3, false, 10, 0x07);
        match decode_data_abort(syn, 0x4000_0000) {
            DataAbortDecode::Mmio(mmio) => {
                assert_eq!(mmio.size, 8);
                assert_eq!(mmio.register, 10);
            }
            other => panic!("expected Mmio, got {other:?}"),
        }
    }

    #[test]
    fn data_abort_not_translation_fault() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, false, 0, 0x09);
        assert!(matches!(
            decode_data_abort(syn, 0),
            DataAbortDecode::NotTranslationFault(0x09)
        ));
    }

    #[test]
    fn data_abort_isv_not_set() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, false, 2, false, 5, 0x04);
        assert!(matches!(
            decode_data_abort(syn, 0),
            DataAbortDecode::IsvNotSet
        ));
    }

    #[test]
    fn all_translation_fault_levels() {
        for dfsc in 0x04..=0x07 {
            let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, false, 0, dfsc);
            assert!(
                matches!(decode_data_abort(syn, 0x1000), DataAbortDecode::Mmio(_)),
                "DFSC {dfsc:#x} should decode as MMIO"
            );
        }
    }

    #[test]
    fn all_access_sizes() {
        for (sas, expected) in [(0, 1), (1, 2), (2, 4), (3, 8)] {
            let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, sas, false, 0, 0x04);
            match decode_data_abort(syn, 0x1000) {
                DataAbortDecode::Mmio(mmio) => assert_eq!(mmio.size, expected),
                other => panic!("expected Mmio, got {other:?}"),
            }
        }
    }

    // --- decode_hvc ---

    #[test]
    fn hvc_psci_shutdown() {
        assert_eq!(decode_hvc(PSCI_SYSTEM_OFF, 0, 0, 0), HvcDecode::Shutdown);
    }

    #[test]
    fn hvc_psci_cpu_off() {
        assert_eq!(decode_hvc(PSCI_CPU_OFF, 0, 0, 0), HvcDecode::CpuOff);
    }

    #[test]
    fn hvc_psci_reboot() {
        assert_eq!(decode_hvc(PSCI_SYSTEM_RESET, 0, 0, 0), HvcDecode::Reboot);
    }

    #[test]
    fn hvc_psci_cpu_on() {
        use crate::arm64::PSCI_CPU_ON;
        assert_eq!(
            decode_hvc(PSCI_CPU_ON, 3, 0x8_0000, 42),
            HvcDecode::CpuOn {
                target_cpu: 3,
                entry_point: 0x8_0000,
                context_id: 42,
            }
        );
    }

    #[test]
    fn hvc_psci_affinity_info() {
        use crate::arm64::PSCI_AFFINITY_INFO_64;
        assert_eq!(
            decode_hvc(PSCI_AFFINITY_INFO_64, 3, 0, 0),
            HvcDecode::AffinityInfo {
                target_cpu: 3,
                lowest_affinity_level: 0,
            }
        );
    }

    #[test]
    fn hvc_unknown() {
        assert_eq!(decode_hvc(0x1234, 0, 0, 0), HvcDecode::Unknown(0x1234));
    }

    // --- decode_exception ---

    #[test]
    fn exception_wfi() {
        let syn = (EC_WFI_WFE & EC_MASK) << EC_SHIFT;
        assert_eq!(decode_exception(syn, 0, 0, 0, 0, 0), ExceptionDecode::Wfi);
    }

    #[test]
    fn exception_hvc_shutdown() {
        let syn = (EC_HVC64 & EC_MASK) << EC_SHIFT;
        assert_eq!(
            decode_exception(syn, 0, PSCI_SYSTEM_OFF, 0, 0, 0),
            ExceptionDecode::Hvc(HvcDecode::Shutdown)
        );
    }

    #[test]
    fn exception_data_abort() {
        let syn = make_syndrome(EC_DATA_ABORT_LOWER, true, 2, false, 5, 0x04);
        match decode_exception(syn, 0xd000_0000, 0, 0, 0, 0) {
            ExceptionDecode::DataAbort(DataAbortDecode::Mmio(mmio)) => {
                assert_eq!(mmio.addr, 0xd000_0000);
                assert_eq!(mmio.size, 4);
            }
            other => panic!("expected DataAbort(Mmio), got {other:?}"),
        }
    }

    #[test]
    fn exception_unknown_ec() {
        let syn = (0x3F_u64) << EC_SHIFT; // max EC value, undefined
        assert!(matches!(
            decode_exception(syn, 0, 0, 0, 0, 0),
            ExceptionDecode::UnknownEc(0x3F)
        ));
    }

    // --- exception_to_vcpu_exit ---

    #[test]
    fn vcpu_exit_halt_from_wfi() {
        let decoded = ExceptionDecode::Wfi;
        assert_eq!(exception_to_vcpu_exit(decoded, 0), VcpuExit::Halt);
    }

    #[test]
    fn vcpu_exit_clean_shutdown_from_psci() {
        let decoded = ExceptionDecode::Hvc(HvcDecode::Shutdown);
        assert_eq!(exception_to_vcpu_exit(decoded, 0), VcpuExit::CleanShutdown);
    }

    #[test]
    fn vcpu_exit_mmio_read() {
        let mmio = MmioAccess {
            addr: 0xd000_0000,
            size: 4,
            register: 5,
            is_write: false,
        };
        let decoded = ExceptionDecode::DataAbort(DataAbortDecode::Mmio(mmio));
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::MmioRead {
                addr: 0xd000_0000,
                size: 4,
            }
        );
    }

    #[test]
    fn vcpu_exit_mmio_write() {
        let mmio = MmioAccess {
            addr: 0xd000_0000,
            size: 4,
            register: 3,
            is_write: true,
        };
        let decoded = ExceptionDecode::DataAbort(DataAbortDecode::Mmio(mmio));
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0xCAFE),
            VcpuExit::MmioWrite {
                addr: 0xd000_0000,
                data: 0xCAFE,
                size: 4,
            }
        );
    }

    // --- data abort same EL ---

    #[test]
    fn data_abort_same_el_decodes() {
        let syn = make_syndrome(EC_DATA_ABORT_SAME, true, 2, false, 1, 0x04);
        match decode_exception(syn, 0x2000, 0, 0, 0, 0) {
            ExceptionDecode::DataAbort(DataAbortDecode::Mmio(mmio)) => {
                assert_eq!(mmio.addr, 0x2000);
            }
            other => panic!("expected DataAbort(Mmio), got {other:?}"),
        }
    }

    // --- exception_to_vcpu_exit: uncovered paths ---

    #[test]
    fn vcpu_exit_reboot_from_hvc() {
        let decoded = ExceptionDecode::Hvc(HvcDecode::Reboot);
        assert_eq!(exception_to_vcpu_exit(decoded, 0), VcpuExit::Reboot);
    }

    #[test]
    fn vcpu_exit_affinity_info_from_hvc() {
        let decoded = ExceptionDecode::Hvc(HvcDecode::AffinityInfo {
            target_cpu: 2,
            lowest_affinity_level: 0,
        });
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::CpuAffinityInfo {
                target_cpu: 2,
                lowest_affinity_level: 0,
            }
        );
    }

    #[test]
    fn vcpu_exit_unknown_hvc_large_fid() {
        let decoded = ExceptionDecode::Hvc(HvcDecode::Unknown(u64::MAX));
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::Unknown {
                code: u64::MAX.cast_signed(),
                source: ExitSource::HvcFunctionId,
            }
        );
    }

    #[test]
    fn vcpu_exit_not_translation_fault() {
        let decoded = ExceptionDecode::DataAbort(DataAbortDecode::NotTranslationFault(0x09));
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::Unknown {
                code: 0x09,
                source: ExitSource::DataFaultStatus,
            }
        );
    }

    #[test]
    fn vcpu_exit_isv_not_set() {
        let decoded = ExceptionDecode::DataAbort(DataAbortDecode::IsvNotSet);
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::Unknown {
                code: -2,
                source: ExitSource::InstructionNotDecodable,
            }
        );
    }

    #[test]
    fn vcpu_exit_unknown_ec() {
        let decoded = ExceptionDecode::UnknownEc(0x3F);
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::Unknown {
                code: 0x3F,
                source: ExitSource::ExceptionClass,
            }
        );
    }

    // --- decode_sysreg tests ---

    /// Helper: encode an ISS for EC=0x18 from individual fields.
    fn make_sysreg_iss(
        op0: u32,
        op1: u32,
        crn: u32,
        crm: u32,
        op2: u32,
        rt: u32,
        is_read: bool,
    ) -> u64 {
        let direction = u64::from(is_read); // 1 = MRS (read), 0 = MSR (write)
        (u64::from(op0) << 20)
            | (u64::from(op2) << 17)
            | (u64::from(op1) << 14)
            | (u64::from(crn) << 10)
            | (u64::from(rt) << 5)
            | (u64::from(crm) << 1)
            | direction
    }

    #[test]
    fn decode_sysreg_icc_iar1() {
        // ICC_IAR1_EL1: Op0=3, Op1=0, CRn=12, CRm=12, Op2=0, MRS (read), Rt=5
        let iss = make_sysreg_iss(3, 0, 12, 12, 0, 5, true);
        let access = decode_sysreg(iss);
        assert_eq!(access.encoding, 0xC660); // Known IAR1 encoding
        assert_eq!(access.register, 5);
        assert!(!access.is_write); // MRS = read
    }

    #[test]
    fn decode_sysreg_icc_eoir1() {
        // ICC_EOIR1_EL1: Op0=3, Op1=0, CRn=12, CRm=12, Op2=1, MSR (write), Rt=7
        let iss = make_sysreg_iss(3, 0, 12, 12, 1, 7, false);
        let access = decode_sysreg(iss);
        assert_eq!(access.encoding, 0xC661); // Known EOIR1 encoding
        assert_eq!(access.register, 7);
        assert!(access.is_write); // MSR = write
    }

    #[test]
    fn decode_sysreg_icc_pmr() {
        // ICC_PMR_EL1: Op0=3, Op1=0, CRn=4, CRm=6, Op2=0, MRS (read), Rt=0
        let iss = make_sysreg_iss(3, 0, 4, 6, 0, 0, true);
        let access = decode_sysreg(iss);
        assert_eq!(access.encoding, 0xC230);
        assert_eq!(access.register, 0);
        assert!(!access.is_write);
    }

    #[test]
    fn decode_sysreg_icc_sgi1r() {
        // ICC_SGI1R_EL1: Op0=3, Op1=0, CRn=12, CRm=11, Op2=5, MSR (write), Rt=31 (XZR)
        let iss = make_sysreg_iss(3, 0, 12, 11, 5, 31, false);
        let access = decode_sysreg(iss);
        assert_eq!(access.encoding, 0xC65D);
        assert_eq!(access.register, 31); // XZR
        assert!(access.is_write);
    }

    #[test]
    fn decode_sysreg_roundtrip_all_fields() {
        // Use maximally distinct values to verify no field overlap
        // Op0=2, Op1=5, CRn=9, CRm=7, Op2=3
        let iss = make_sysreg_iss(2, 5, 9, 7, 3, 15, true);
        let access = decode_sysreg(iss);
        let expected = (2 << 14) | (5 << 11) | (9 << 7) | (7 << 3) | 3;
        assert_eq!(access.encoding, expected);
        assert_eq!(access.register, 15);
        assert!(!access.is_write); // read (MRS)
    }

    // --- exception_to_vcpu_exit: SysReg ---

    #[test]
    fn vcpu_exit_sysreg_read() {
        let access = SysRegAccess {
            encoding: 0xC660,
            register: 5,
            is_write: false,
        };
        let decoded = ExceptionDecode::SysReg(access);
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0),
            VcpuExit::SysReg {
                encoding: 0xC660,
                register: 5,
                is_write: false,
                write_data: 0,
            }
        );
    }

    #[test]
    fn vcpu_exit_sysreg_write() {
        let access = SysRegAccess {
            encoding: 0xC661,
            register: 7,
            is_write: true,
        };
        let decoded = ExceptionDecode::SysReg(access);
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0xDEAD_BEEF),
            VcpuExit::SysReg {
                encoding: 0xC661,
                register: 7,
                is_write: true,
                write_data: 0xDEAD_BEEF,
            }
        );
    }

    #[test]
    fn vcpu_exit_sysreg_write_xzr() {
        // XZR writes should pass write_data=0 (the VMM caller provides 0 for Rt=31)
        let access = SysRegAccess {
            encoding: 0xC65D, // SGI1R
            register: 31,     // XZR
            is_write: true,
        };
        let decoded = ExceptionDecode::SysReg(access);
        assert_eq!(
            exception_to_vcpu_exit(decoded, 0), // caller provides 0 for XZR
            VcpuExit::SysReg {
                encoding: 0xC65D,
                register: 31,
                is_write: true,
                write_data: 0,
            }
        );
    }

    // --- decode_exception: EC_SYSREG ---

    #[test]
    fn exception_sysreg_decode() {
        // Build a full ESR_EL2 with EC=0x18 and an ISS encoding ICC_IAR1_EL1 read
        let iss = make_sysreg_iss(3, 0, 12, 12, 0, 5, true);
        let esr = ((EC_SYSREG & EC_MASK) << EC_SHIFT) | (iss & 0x1FF_FFFF);
        match decode_exception(esr, 0, 0, 0, 0, 0) {
            ExceptionDecode::SysReg(access) => {
                assert_eq!(access.encoding, 0xC660);
                assert_eq!(access.register, 5);
                assert!(!access.is_write);
            }
            other => panic!("expected SysReg, got {other:?}"),
        }
    }
}
