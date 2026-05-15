// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! vCPU exit types and response protocol.
//!
//! This module provides backend-agnostic types for virtual CPU exits and
//! the response protocol used to resume vCPUs after handling an exit.
//!
//! The backend provides a `resume(vcpu_index, response)` async method.
//! Dropping the resume future preempts the vCPU. No traits needed.

// =============================================================================
// ExitSource - Provenance of an unknown vCPU exit
// =============================================================================

/// Source/kind of an unknown vCPU exit.
///
/// When a vCPU exits for an unrecognized reason, this enum records *what*
/// the unknown code represents, making debug logs actionable rather than
/// just printing an opaque integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum ExitSource {
    /// Raw exit code from the hypervisor (KVM/HVF/WHP).
    Hypervisor,
    /// Unrecognized HVC/PSCI function ID (ARM64 X0 register).
    HvcFunctionId,
    /// Data abort with non-translation DFSC (ARM64).
    DataFaultStatus,
    /// Data abort where ISV bit is not set (instruction not decodable).
    InstructionNotDecodable,
    /// Unrecognized exception class (ARM64 `ESR_EL2` EC field).
    ExceptionClass,
    /// Internal error (e.g. unsupported IO/MMIO access size).
    Internal,
}

// =============================================================================
// VcpuExit - Exit reasons from vCPU run
// =============================================================================

/// Exit reason from a vCPU run.
///
/// This enum represents the different reasons why a vCPU might exit from
/// its execution loop. The VMM handles each exit type appropriately.
///
/// # Architecture Notes
///
/// `IoIn`/`IoOut` are x86-specific (port I/O instructions) and only exist on
/// x86 builds. ARM64 has no port I/O; ARM backends emit MMIO exits instead.
///
/// # Performance
///
/// This type derives `Copy` because it's returned from the hot `run()` path.
/// All variants are small (largest is `MmioWrite` at ~17 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum VcpuExit {
    /// Guest executed HLT instruction.
    Halt,

    /// `run()` was interrupted (EINTR from signal, preemption request).
    ///
    /// This is a normal exit used for pause/preemption. The VMM should check
    /// whether pause was requested and act accordingly.
    Interrupted,

    /// Guest requested a clean shutdown.
    ///
    /// Produced by:
    /// - ARM PSCI `SYSTEM_OFF` (via the guest agent's `reboot(POWER_OFF)`)
    /// - x86 terminal HLT with IRQs disabled (Linux `poweroff_halt` path)
    ///
    /// The vCPU state is consistent and safe to snapshot. Contrast with
    /// [`Unrecoverable`](Self::Unrecoverable), which signals a fault.
    CleanShutdown,

    /// Guest requested a reboot.
    ///
    /// Produced by ARM PSCI `SYSTEM_RESET`. May follow a kernel panic —
    /// the exit only records that the guest asked to reset, not whether
    /// it did so cleanly. Callers that care about panic-vs-intentional
    /// should layer a separate signal on top.
    Reboot,

    /// Unrecoverable vCPU state; the VMM must tear the VM down.
    ///
    /// Produced by:
    /// - x86 KVM `KVM_EXIT_SHUTDOWN` (triple fault)
    /// - KVM ioctl failures (apply-response, `KVM_RUN`, signal blocking)
    /// - HVF decode / `advance_pc` / apply-response failures
    /// - Unsupported sysreg or unknown vCPU exits in the VMM loop
    ///
    /// The vCPU register state is untrustworthy. `run()` must return `Err`
    /// and skip any state snapshot.
    Unrecoverable,

    /// PSCI `CPU_OFF` — stop this vCPU only (ARM64).
    ///
    /// Unlike `Shutdown` which terminates the entire VM, `CpuOff` only
    /// stops the calling vCPU. The VMM should park this vCPU without
    /// signaling VM-level exit.
    CpuOff,

    /// PSCI `CPU_ON` — start a stopped vCPU (ARM64).
    ///
    /// The calling vCPU requests that `target_cpu` be brought online at
    /// the given `entry_point` with `context_id` in x0.
    CpuOn {
        /// MPIDR of the target CPU to bring online.
        target_cpu: u64,
        /// Entry point address for the target CPU.
        entry_point: u64,
        /// Context ID passed in x0 to the target CPU.
        context_id: u64,
    },

    /// PSCI `AFFINITY_INFO` — query a CPU's power state (ARM64).
    CpuAffinityInfo {
        /// MPIDR of the target CPU to query.
        target_cpu: u64,
        /// Lowest affinity level requested by the guest.
        lowest_affinity_level: u64,
    },

    /// Port I/O read (guest IN instruction).
    ///
    /// After this exit, the VMM must call `set_pio_response()` with the
    /// data to return to the guest before the next `run()`.
    #[cfg(target_arch = "x86_64")]
    IoIn {
        /// I/O port number (0x0000-0xFFFF).
        port: u16,
        /// Access size in bytes (1, 2, or 4).
        size: u8,
    },

    /// Port I/O write (guest OUT instruction).
    #[cfg(target_arch = "x86_64")]
    IoOut {
        /// I/O port number (0x0000-0xFFFF).
        port: u16,
        /// Data written by guest.
        data: u32,
        /// Access size in bytes (1, 2, or 4).
        size: u8,
    },

    /// Memory-mapped I/O read.
    ///
    /// After this exit, the VMM must call `set_mmio_response()` with the
    /// data to return to the guest before the next `run()`.
    MmioRead {
        /// Guest physical address.
        addr: u64,
        /// Access size in bytes (1, 2, 4, or 8).
        size: u8,
    },

    /// Memory-mapped I/O write.
    MmioWrite {
        /// Guest physical address.
        addr: u64,
        /// Data written by guest.
        data: u64,
        /// Access size in bytes (1, 2, 4, or 8).
        size: u8,
    },

    /// System register access trap (ARM64 MSR/MRS, EC = 0x18).
    ///
    /// Used by the userspace GIC for ICC_* register emulation. Supported
    /// architectural RAZ/WI behavior should be handled by an explicit emulator;
    /// generic VMM handling treats unclaimed sysreg traps as fatal. The VMM must:
    /// - For reads (`is_write=false`): call `set_sysreg_response()` with the value
    /// - For writes (`is_write=true`): process the write, then advance PC
    SysReg {
        /// Packed register encoding: `(Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2`.
        encoding: u32,
        /// Guest register index (Rt field): 0-30 = X0-X30, 31 = XZR.
        register: u32,
        /// true = write (MSR), false = read (MRS).
        is_write: bool,
        /// Data written by guest (only valid when `is_write=true`; XZR reads as 0).
        write_data: u64,
    },

    /// Unknown or unhandled exit reason.
    ///
    /// `code` holds the full (up to 64-bit) exit code from the hypervisor
    /// or syndrome decoder, and `source` records what kind of code it is.
    /// Generic VMM handling treats this as fatal because there are no safe
    /// response or PC-advance semantics attached to an unknown exit.
    Unknown { code: i64, source: ExitSource },
}

// =============================================================================
// VcpuError - Errors from vCPU operations
// =============================================================================

/// Error from vCPU operations.
///
/// # Design Notes
///
/// - `Hypervisor` wraps `std::io::Error` to preserve errno and syscall context
///   (recommended by Codex review - avoids lossy `String` conversion)
/// - No `Interrupted` variant - use `VcpuExit::Interrupted` for normal preemption
#[derive(Debug, thiserror::Error)]
pub enum VcpuError {
    /// Hypervisor syscall failed.
    ///
    /// Wraps the underlying `std::io::Error` to preserve errno for debugging.
    /// Callers can match on `err.kind()` to distinguish retryable errors.
    #[error("Hypervisor error: {0}")]
    Hypervisor(#[from] std::io::Error),

    /// vCPU is in an invalid state for the requested operation.
    ///
    /// Examples: calling `set_pio_response()` without a pending PIO exit,
    /// or passing an invalid size parameter.
    #[error("Invalid state: {0}")]
    InvalidState(String),
}

impl VcpuError {
    /// Create a hypervisor error from a string message.
    ///
    /// This creates an `io::Error` with `ErrorKind::Other` for cases where
    /// we need to construct an error without an actual syscall failure.
    pub fn hypervisor(msg: impl Into<String>) -> Self {
        Self::Hypervisor(std::io::Error::other(msg.into()))
    }
}

// =============================================================================
// VcpuResponse - How to update vCPU state before resuming
// =============================================================================

/// How to update vCPU state before resuming execution.
///
/// The VMM determines the appropriate response by handling the `VcpuExit`,
/// then passes it to the backend's `resume()` method.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub enum VcpuResponse {
    /// MMIO read data.
    Mmio {
        /// Value to return to the guest.
        data: u64,
        /// Access size in bytes (1, 2, 4, or 8).
        size: u8,
    },

    /// Port I/O read data (x86 only).
    #[cfg(target_arch = "x86_64")]
    Pio {
        /// Value to return to the guest.
        data: u32,
        /// Access size in bytes (1, 2, or 4).
        size: u8,
    },

    /// System register read value.
    SysReg {
        /// Register value to return.
        value: u64,
        /// Guest register index (Rt field).
        register: u32,
    },

    /// PSCI `CPU_ON` boot configuration.
    CpuOnBoot {
        /// Entry point address.
        entry_point: u64,
        /// Context ID (passed in x0).
        context_id: u64,
    },

    /// PSCI `CPU_ON` result for the calling (BSP) vCPU.
    ///
    /// Written to X0 after the VMM evaluates whether the target vCPU
    /// accepted the `CPU_ON` request. Replaces the former fire-and-forget
    /// path where the backend wrote `PSCI_SUCCESS` unconditionally.
    CpuOnResult {
        /// PSCI return value (cast from `i64`): 0 = success, negative = error.
        psci_return: u64,
    },
}

// =============================================================================
// VcpuId - Type-safe vCPU index
// =============================================================================

/// Type-safe vCPU identifier.
///
/// A transparent wrapper over `u32` so conversions to/from the hypervisor ABI
/// (KVM, HVF, WHP all use 0-based `u32` indices) are zero-cost. Exists to
/// distinguish vCPU indices from other integer quantities (device indices,
/// IRQ numbers) at the type level.
#[repr(transparent)]
#[derive(
    Copy, Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
pub struct VcpuId(pub u32);

impl From<u32> for VcpuId {
    #[inline]
    fn from(index: u32) -> Self {
        Self(index)
    }
}

impl From<VcpuId> for u32 {
    #[inline]
    fn from(id: VcpuId) -> Self {
        id.0
    }
}

impl core::fmt::Display for VcpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vcpu_exit_is_copy() {
        #[cfg(target_arch = "x86_64")]
        let exit = VcpuExit::IoIn {
            port: 0x3F8,
            size: 1,
        };
        #[cfg(not(target_arch = "x86_64"))]
        let exit = VcpuExit::MmioRead {
            addr: 0xd000_0000,
            size: 4,
        };
        let copy = exit; // This would fail if VcpuExit wasn't Copy
        assert_eq!(exit, copy);
    }

    #[test]
    fn vcpu_exit_size_invariant() {
        // Ensure VcpuExit doesn't bloat (performance invariant)
        // SysReg is largest: encoding(4) + register(4) + is_write(1) + write_data(8) + discriminant
        assert!(
            std::mem::size_of::<VcpuExit>() <= 32,
            "VcpuExit size {} exceeds 32 bytes",
            std::mem::size_of::<VcpuExit>()
        );
    }

    #[test]
    fn vcpu_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::Interrupted, "test");
        let vcpu_err: VcpuError = io_err.into();
        assert!(matches!(vcpu_err, VcpuError::Hypervisor(_)));
    }

    #[test]
    fn vcpu_error_hypervisor_helper() {
        let err = VcpuError::hypervisor("test error");
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn vcpu_error_invalid_state() {
        let err = VcpuError::InvalidState("bad size".into());
        assert!(err.to_string().contains("bad size"));
    }

    #[test]
    fn vcpu_id_is_transparent() {
        assert_eq!(std::mem::size_of::<VcpuId>(), std::mem::size_of::<u32>());
    }

    #[test]
    fn vcpu_id_conversions_are_free() {
        let id: VcpuId = 7u32.into();
        assert_eq!(id.0, 7);
        let raw: u32 = id.into();
        assert_eq!(raw, 7);
    }

    #[test]
    fn vcpu_id_display() {
        let id = VcpuId(3);
        assert_eq!(id.to_string(), "3");
    }

    #[test]
    fn vcpu_id_ord() {
        let mut ids = [VcpuId(2), VcpuId(0), VcpuId(1)];
        ids.sort();
        assert_eq!(ids, [VcpuId(0), VcpuId(1), VcpuId(2)]);
    }

    #[test]
    fn vcpu_exit_debug_all_variants() {
        // Ensure all variants have sensible Debug output (catches formatting regressions)
        let variants: Vec<VcpuExit> = vec![
            VcpuExit::Halt,
            VcpuExit::Interrupted,
            VcpuExit::CleanShutdown,
            VcpuExit::Reboot,
            VcpuExit::Unrecoverable,
            #[cfg(target_arch = "x86_64")]
            VcpuExit::IoIn {
                port: 0x3F8,
                size: 1,
            },
            #[cfg(target_arch = "x86_64")]
            VcpuExit::IoOut {
                port: 0x3F8,
                data: 0x41,
                size: 1,
            },
            VcpuExit::MmioRead {
                addr: 0xd000_0000,
                size: 4,
            },
            VcpuExit::MmioWrite {
                addr: 0xd000_0000,
                data: 0xFF,
                size: 4,
            },
            VcpuExit::SysReg {
                encoding: 0xC660,
                register: 5,
                is_write: false,
                write_data: 0,
            },
            VcpuExit::Unknown {
                code: 99,
                source: ExitSource::Hypervisor,
            },
        ];
        for variant in &variants {
            let debug = format!("{variant:?}");
            assert!(!debug.is_empty(), "Debug output should not be empty");
        }
    }
}
