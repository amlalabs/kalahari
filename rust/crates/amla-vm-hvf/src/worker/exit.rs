// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF exit reason decoding.
//!
//! Converts Hypervisor.framework exit info into `amla_core::VcpuExit`.
//!
//! PSCI query calls (VERSION, FEATURES, `SMCCC_VERSION`, `MIGRATE_INFO`) are
//! handled inline — the return value is written to X0 and the vCPU re-enters
//! immediately. KVM handles these in-kernel; HVF must do it in userspace.

use crate::ffi;
use amla_core::VcpuExit;
use amla_core::arm64::syndrome::{self, ExceptionDecode, HvcDecode};

// PSCI function IDs handled locally (not forwarded to parent).
const PSCI_VERSION: u64 = 0x8400_0000;
const PSCI_MIGRATE_INFO_TYPE: u64 = 0x8400_0006;
const PSCI_FEATURES: u64 = 0x8400_000A;
const PSCI_CPU_OFF: u64 = 0x8400_0002;
const PSCI_CPU_ON_32: u64 = 0x8400_0003;
const PSCI_CPU_ON_64: u64 = 0xC400_0003;
const PSCI_AFFINITY_INFO_32: u64 = 0x8400_0004;
const PSCI_AFFINITY_INFO_64: u64 = 0xC400_0004;
const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
const PSCI_MEM_PROTECT_CHECK: u64 = 0x8400_0050;
const SMCCC_VERSION: u64 = 0x8000_0000;
const SMCCC_ARCH_FEATURES: u64 = 0x8000_0001;

const PSCI_RET_NOT_SUPPORTED: u64 = (-1_i64).cast_unsigned();
const PSCI_VERSION_1_1: u64 = 0x0001_0001;
const SMCCC_VERSION_1_1: u64 = 0x0001_0001;

/// Decoded HVF exit with optional metadata for response application.
pub(crate) struct DecodedExit {
    pub exit: VcpuExit,
    /// For `MmioRead`: the destination register index (SRT).
    /// Worker stores this to apply the response later.
    pub mmio_read_register: Option<u32>,
    /// Whether the vCPU should re-enter immediately (no parent round-trip).
    pub reenter: bool,
    /// Whether this exit represents a virtual timer expiry.
    pub vtimer_activated: bool,
}

/// Decode an HVF exit. Must be called on the vCPU's owning thread.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
/// `exit_info` must point to valid exit info from `hv_vcpu_create`.
pub(crate) unsafe fn decode_exit(
    vcpu: ffi::hv_vcpu_t,
    exit_info: &ffi::VcpuExitInfo,
) -> crate::error::Result<DecodedExit> {
    match exit_info.reason {
        ffi::HV_EXIT_REASON_CANCELED => Ok(DecodedExit {
            exit: VcpuExit::Interrupted,
            mmio_read_register: None,
            reenter: false,
            vtimer_activated: false,
        }),

        ffi::HV_EXIT_REASON_EXCEPTION => {
            // SAFETY: vcpu is valid on this thread per caller contract.
            unsafe { decode_exception_exit(vcpu, exit_info) }
        }

        ffi::HV_EXIT_REASON_VTIMER_ACTIVATED => {
            // HVF masks the host-side vtimer when this exit is reported.
            // Keep it masked while the userspace GIC presents PPI 27 to the
            // guest; the vCPU loop rearms HVF only after the guest-visible
            // CNTV_* condition clears.
            Ok(DecodedExit {
                exit: VcpuExit::Halt, // placeholder; re-enter immediately
                mmio_read_register: None,
                reenter: true,
                vtimer_activated: true,
            })
        }

        // HVF reports this for vCPU states it cannot decode. Re-entering
        // without advancing PC would spin the worker thread indefinitely
        // on any guest instruction that triggers it, so shut the VM down
        // instead.
        ffi::HV_EXIT_REASON_UNKNOWN => {
            log::error!("hvf: HV_EXIT_REASON_UNKNOWN — shutting down vCPU");
            Ok(DecodedExit {
                exit: VcpuExit::Unrecoverable,
                mmio_read_register: None,
                reenter: false,
                vtimer_activated: false,
            })
        }

        _ => Ok(DecodedExit {
            exit: VcpuExit::Unknown {
                code: i64::from(exit_info.reason),
                source: amla_core::ExitSource::Hypervisor,
            },
            mmio_read_register: None,
            reenter: false,
            vtimer_activated: false,
        }),
    }
}

/// Decode an EXCEPTION exit using the `ESR_EL2` syndrome.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn decode_exception_exit(
    vcpu: ffi::hv_vcpu_t,
    exit_info: &ffi::VcpuExitInfo,
) -> crate::error::Result<DecodedExit> {
    let syndrome = exit_info.exception.syndrome;
    let ipa = exit_info.exception.physical_address;

    // Read X0-X3 for HVC/PSCI decoding. These are cheap reads and only
    // meaningful for HVC, but reading unconditionally keeps the code simple.
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    let x0 = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0) }?;
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    let x1 = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0 + 1) }?;
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    let x2 = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0 + 2) }?;
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    let x3 = unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0 + 3) }?;

    let decoded = syndrome::decode_exception(syndrome, ipa, x0, x1, x2, x3);

    // Handle PSCI query calls inline — write return value to X0 and
    // re-enter immediately. HVC auto-advances PC.
    if let ExceptionDecode::Hvc(HvcDecode::Unknown(fid)) = &decoded
        && let Some(ret) = psci_query_return(*fid, x1)
    {
        // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
        unsafe {
            ffi::check(
                "hv_vcpu_set_reg(PSCI return)",
                ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0, ret),
            )
            .map_err(crate::error::VmmError::from)?;
        }
        return Ok(DecodedExit {
            exit: VcpuExit::Halt, // re-enter immediately
            mmio_read_register: None,
            reenter: true,
            vtimer_activated: false,
        });
    }

    // PSCI CPU_OFF: write PSCI_SUCCESS (0) to X0 before forwarding.
    // HVC auto-advances PC. CPU_OFF technically doesn't return on success,
    // but we keep running until the VMM blocks the vCPU — writing X0 here
    // ensures a consistent register state if the snapshot is captured while
    // the vCPU is powered off.
    //
    // CPU_ON X0 is NOT written here — the VMM evaluates whether the target
    // vCPU accepts the request and returns the PSCI status via
    // `VcpuResponse::CpuOnResult`.
    if matches!(&decoded, ExceptionDecode::Hvc(HvcDecode::CpuOff)) {
        // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
        unsafe {
            ffi::check(
                "hv_vcpu_set_reg(PSCI CPU_ON/OFF success)",
                ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_X0, 0),
            )
            .map_err(crate::error::VmmError::from)?;
        }
    }

    // Determine if we need to read a source register for MMIO writes or
    // sysreg writes, and track the SRT for MMIO reads.
    let mut mmio_read_register: Option<u32> = None;
    let mut write_data: u64 = 0;

    match &decoded {
        ExceptionDecode::DataAbort(syndrome::DataAbortDecode::Mmio(mmio)) => {
            if mmio.is_write {
                // Read the source register value for the write.
                // SRT=31 means XZR (zero register) in the ARM architecture,
                // but HVF's hv_reg_t value 31 is PC. Handle XZR explicitly.
                let raw = if mmio.register == 31 {
                    0 // XZR always reads as zero
                } else {
                    // SAFETY: vcpu is valid on this thread, register 0-30 maps to X0-X30.
                    unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0 + mmio.register) }?
                };
                // Mask to the access size — ARM64 STR wN stores only the lower
                // 32 bits but hv_vcpu_get_reg returns the full 64-bit register.
                write_data = match mmio.size {
                    1 => raw & 0xFF,
                    2 => raw & 0xFFFF,
                    4 => raw & 0xFFFF_FFFF,
                    _ => raw, // 8-byte access uses full register
                };
            } else {
                // Store the destination register for later response application.
                mmio_read_register = Some(mmio.register);
            }
        }
        ExceptionDecode::SysReg(access) if access.is_write => {
            // Read the source register for sysreg writes (MSR Rt).
            write_data = if access.register == 31 {
                0 // XZR always reads as zero
            } else {
                // SAFETY: vcpu is valid on this thread, register 0-30 maps to X0-X30.
                unsafe { ffi::read_reg(vcpu, ffi::HV_REG_X0 + access.register) }?
            };
        }
        _ => {}
    }

    let exit = syndrome::exception_to_vcpu_exit(decoded, write_data);

    // PC advancement for MMIO writes is done eagerly in the vcpu thread
    // loop (before forwarding to parent). For reads, apply_response
    // advances PC when writing the result register. HVC auto-advances
    // in hardware. WFI does not advance.

    Ok(DecodedExit {
        exit,
        mmio_read_register,
        reenter: false,
        vtimer_activated: false,
    })
}

// =============================================================================
// PSCI query handler (inline in worker, no IPC round-trip)
// =============================================================================

/// Return the PSCI/SMCCC return value for a query call, or `None` if the
/// call should be forwarded to the parent VMM.
fn psci_query_return(fid: u64, x1: u64) -> Option<u64> {
    match fid {
        PSCI_VERSION => Some(PSCI_VERSION_1_1),
        SMCCC_VERSION => Some(SMCCC_VERSION_1_1),
        PSCI_FEATURES => {
            // X1 holds the function ID being queried.
            let supported = matches!(
                x1,
                PSCI_VERSION
                    | PSCI_CPU_OFF
                    | PSCI_CPU_ON_32
                    | PSCI_CPU_ON_64
                    | PSCI_AFFINITY_INFO_32
                    | PSCI_AFFINITY_INFO_64
                    | PSCI_SYSTEM_OFF
                    | PSCI_SYSTEM_RESET
                    | PSCI_FEATURES
            );
            Some(if supported { 0 } else { PSCI_RET_NOT_SUPPORTED })
        }
        PSCI_MIGRATE_INFO_TYPE => Some(2), // "Trusted OS not present"
        SMCCC_ARCH_FEATURES | PSCI_MEM_PROTECT_CHECK => Some(PSCI_RET_NOT_SUPPORTED),
        _ => None, // Forward to parent (CPU_ON, SYSTEM_OFF, etc. need VMM state)
    }
}

/// Advance PC by 4 bytes (one ARM64 instruction).
/// Public wrapper for use by `vcpu_thread` (device kick path).
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
pub(crate) unsafe fn advance_pc_pub(vcpu: ffi::hv_vcpu_t) -> crate::error::Result<()> {
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    unsafe { advance_pc(vcpu) }
}

/// Advance PC by 4 bytes (one ARM64 instruction).
///
/// # Safety
/// `vcpu` must be a valid handle on the calling thread.
unsafe fn advance_pc(vcpu: ffi::hv_vcpu_t) -> crate::error::Result<()> {
    let mut pc: u64 = 0;
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this thread.
    unsafe {
        ffi::check(
            "hv_vcpu_get_reg(PC)",
            ffi::hv_vcpu_get_reg(vcpu, ffi::HV_REG_PC, &raw mut pc),
        )
        .map_err(crate::error::VmmError::from)?;
        ffi::check(
            "hv_vcpu_set_reg(PC)",
            ffi::hv_vcpu_set_reg(vcpu, ffi::HV_REG_PC, pc.wrapping_add(4)),
        )
        .map_err(crate::error::VmmError::from)?;
    }
    Ok(())
}
