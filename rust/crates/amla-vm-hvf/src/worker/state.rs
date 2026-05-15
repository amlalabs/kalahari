// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF vCPU state snapshot — capture and restore all registers.
//!
//! The `HvfVcpuSnapshot` struct is `#[repr(C)]` for zero-copy mmap-based
//! IPC transfer between the coordinator and worker processes.

use crate::error::{Result, VmmError};
use crate::ffi;
use amla_core::arm64::snapshot::{ALL_REGS, SIMD_REG_COUNT, SNAPSHOT_SYS_REGS};

/// Maximum number of system-register entries captured in a snapshot.
/// Also the length of the `sys_regs` array below; the two must match so that
/// `sys_reg_count` can never OOB-index the array after validation.
pub(crate) const HVF_SNAPSHOT_SYS_REGS: usize = 32;

const _: () = assert!(
    SNAPSHOT_SYS_REGS.len() <= HVF_SNAPSHOT_SYS_REGS,
    "SNAPSHOT_SYS_REGS exceeds HvfVcpuSnapshot::sys_regs capacity"
);

const _: () = assert!(
    ALL_REGS.len() == 35,
    "ALL_REGS length mismatch with HvfVcpuSnapshot::gp_regs capacity (35)"
);

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn mach_absolute_time() -> u64;
}

// ============================================================================
// Snapshot structure
// ============================================================================

/// A system register entry with explicit padding for Pod safety.
///
/// Replaces `(u16, u64)` tuple which has no guaranteed layout and cannot
/// safely implement `bytemuck::Pod`.
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(crate) struct HvfSysRegEntry {
    pub encoding: u16,
    pub _pad: [u8; 6],
    pub value: u64,
}

/// Complete vCPU register snapshot for save/restore.
///
/// Layout is `#[repr(C)]` and contains only POD types, making it safe for
/// raw byte serialization and mmap-based IPC. Total size fits in a single
/// 16 KiB page.
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub(crate) struct HvfVcpuSnapshot {
    /// GP + control registers: X0-X30, PC, FPCR, FPSR, CPSR (35 values).
    pub gp_regs: [u64; 35],
    /// Explicit padding: 35 × u64 = 280 bytes, `simd_regs` needs 16-byte alignment.
    pub _pad_gp: [u8; 8],
    /// SIMD/FP registers V0-V31 (32 x 128-bit).
    pub simd_regs: [u128; SIMD_REG_COUNT],
    /// System register (encoding, value) pairs.
    pub sys_regs: [HvfSysRegEntry; HVF_SNAPSHOT_SYS_REGS],
    /// Number of valid entries in `sys_regs`.
    pub sys_reg_count: u32,
    pub _pad: u32,
    /// Target `CNTVOFF_EL2` — passed straight to `hv_vcpu_set_vtimer_offset`.
    ///
    /// This is the value HVF will load into the per-vCPU `CNTVOFF_EL2` register,
    /// giving `CNTVCT_EL0 = mach_absolute_time() - vtimer_offset` once applied.
    /// All vCPUs belonging to the same VM MUST share the same value here so
    /// that the guest sees a system-coherent virtual counter (required by the
    /// ARM architecture and by Linux `sched_clock`).
    pub vtimer_offset: u64,
    /// Power state: 0=running, 1=stopped, 2=suspended.
    pub power_state: u8,
    pub _pad2: [u8; 7],
    /// `mach_absolute_time()` at the moment of capture. Reserved for
    /// cross-process snapshot restore (not used on fresh boot).
    pub capture_mach_time: u64,
}

impl HvfVcpuSnapshot {
    /// Validate snapshot fields that could cause out-of-bounds access if a
    /// corrupted (truncated, stale, or tampered) snapshot reaches restore.
    ///
    /// Mirrors `VcpuSnapshot::validate` in the KVM arm64 path. Does NOT
    /// validate register semantics — HVF itself rejects invalid register
    /// state via `hv_vcpu_set_sys_reg`.
    pub(crate) fn validate(&self) -> Result<()> {
        if self.sys_reg_count as usize > HVF_SNAPSHOT_SYS_REGS {
            return Err(VmmError::InvalidState {
                expected: "sys_reg_count <= 32",
                actual: "sys_reg_count out of range",
            });
        }
        Ok(())
    }

    /// Build a powered-off snapshot when no HVF vCPU currently exists.
    pub(crate) fn powered_off(vtimer_offset: u64) -> Self {
        Self {
            gp_regs: [0; 35],
            _pad_gp: [0; 8],
            simd_regs: [0; SIMD_REG_COUNT],
            sys_regs: [HvfSysRegEntry {
                encoding: 0,
                _pad: [0; 6],
                value: 0,
            }; 32],
            sys_reg_count: 0,
            _pad: 0,
            vtimer_offset,
            power_state: 1,
            _pad2: [0; 7],
            capture_mach_time: 0,
        }
    }
}

// ============================================================================
// Capture
// ============================================================================

/// Capture all vCPU registers into a snapshot.
///
/// Must be called on the vCPU's owning thread while the vCPU is stopped
/// (not inside `hv_vcpu_run`).
///
/// # Safety
///
/// - `vcpu` must be a valid handle on the calling thread.
/// - The vCPU must not be running.
pub(crate) unsafe fn capture_vcpu(vcpu: ffi::hv_vcpu_t) -> Result<HvfVcpuSnapshot> {
    let mut snap = HvfVcpuSnapshot {
        gp_regs: [0; 35],
        _pad_gp: [0; 8],
        simd_regs: [0; SIMD_REG_COUNT],
        sys_regs: [HvfSysRegEntry {
            encoding: 0,
            _pad: [0; 6],
            value: 0,
        }; HVF_SNAPSHOT_SYS_REGS],
        sys_reg_count: 0,
        _pad: 0,
        vtimer_offset: 0,
        power_state: 0,
        _pad2: [0; 7],
        capture_mach_time: 0,
    };

    // Read GP + control registers using ALL_REGS discriminants as hv_reg_t.
    // The Arm64Reg discriminant values match HVF's hv_reg_t by design.
    for (i, &reg) in ALL_REGS.iter().enumerate() {
        let mut value: u64 = 0;
        // SAFETY: vcpu is valid on this thread and not running. reg discriminant
        // matches hv_reg_t values.
        unsafe {
            ffi::check(
                "hv_vcpu_get_reg",
                ffi::hv_vcpu_get_reg(vcpu, reg as u32, &raw mut value),
            )
            .map_err(VmmError::from)?;
        }
        snap.gp_regs[i] = value;
    }

    // Read system registers using SNAPSHOT_SYS_REGS encodings as hv_sys_reg_t.
    for (i, &sys_reg) in SNAPSHOT_SYS_REGS.iter().enumerate() {
        let encoding = sys_reg.encoding();
        let mut value: u64 = 0;
        // SAFETY: vcpu is valid on this thread. Encoding matches hv_sys_reg_t.
        unsafe {
            let ret = ffi::hv_vcpu_get_sys_reg(vcpu, encoding, &raw mut value);
            if ret == ffi::HV_UNSUPPORTED
                && let Some(default) = unsupported_sys_reg_default(encoding)
            {
                value = default;
                log::debug!(
                    "capture_vcpu: sysreg {sys_reg:?} ({encoding:#06x}) unsupported by HVF, using {value:#x}"
                );
            } else {
                ffi::check(
                    &format!("hv_vcpu_get_sys_reg({sys_reg:?}, {encoding:#06x})"),
                    ret,
                )
                .map_err(VmmError::from)?;
            }
        }
        snap.sys_regs[i] = HvfSysRegEntry {
            encoding,
            _pad: [0; 6],
            value,
        };
    }
    #[allow(clippy::cast_possible_truncation)]
    {
        snap.sys_reg_count = SNAPSHOT_SYS_REGS.len() as u32;
    }

    // Read SIMD/FP registers Q0-Q31 (128-bit each).
    for i in 0..SIMD_REG_COUNT {
        let mut value: u128 = 0;
        // SAFETY: vcpu is valid on this thread. Register index 0-31 is valid.
        unsafe {
            ffi::check(
                "hv_vcpu_get_simd_fp_reg",
                ffi::hv_vcpu_get_simd_fp_reg(
                    vcpu,
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        ffi::HV_SIMD_FP_REG_Q0 + i as u32
                    },
                    &raw mut value,
                ),
            )
            .map_err(VmmError::from)?;
        }
        snap.simd_regs[i] = value;
    }

    // Read vtimer offset.
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        ffi::check(
            "hv_vcpu_get_vtimer_offset",
            ffi::hv_vcpu_get_vtimer_offset(vcpu, &raw mut snap.vtimer_offset),
        )
        .map_err(VmmError::from)?;
    }

    // Record the current mach_absolute_time so restore can adjust the vtimer
    // offset when migrating across processes (different time base).
    // SAFETY: mach_absolute_time has no preconditions.
    snap.capture_mach_time = unsafe { mach_absolute_time() };

    Ok(snap)
}

// ============================================================================
// Restore
// ============================================================================

/// Restore all vCPU registers from a snapshot.
///
/// The caller should set `MPIDR_EL1` before calling this if needed for GIC
/// affinity routing.
///
/// Must be called on the vCPU's owning thread while the vCPU is stopped.
///
/// # Safety
///
/// - `vcpu` must be a valid handle on the calling thread.
/// - The vCPU must not be running.
pub(crate) unsafe fn restore_vcpu(vcpu: ffi::hv_vcpu_t, snap: &HvfVcpuSnapshot) -> Result<()> {
    // Reject malformed snapshots before touching HVF — mirrors
    // `VcpuSnapshot::validate` on the KVM path. A corrupted `sys_reg_count`
    // would OOB-index `snap.sys_regs` below.
    snap.validate()?;

    // Powered-off vCPUs (PSCI stopped): keep HVF's default register state.
    // CpuOnBoot will set PC/X0/CPSR when the AP is activated via CPU_ON.
    // Restoring the all-zero powered-off snapshot would zero out system
    // registers (SCTLR_EL1, TCR_EL1, etc.) that HVF initializes with
    // working defaults, causing instruction aborts on the secondary CPU.
    if snap.power_state != 0 {
        return Ok(());
    }

    // Write GP + control registers.
    for (i, &reg) in ALL_REGS.iter().enumerate() {
        // SAFETY: vcpu is valid on this thread and not running.
        unsafe {
            ffi::check(
                "hv_vcpu_set_reg",
                ffi::hv_vcpu_set_reg(vcpu, reg as u32, snap.gp_regs[i]),
            )
            .map_err(VmmError::from)?;
        }
    }

    // Write system registers.
    let count = snap.sys_reg_count as usize;
    for i in 0..count {
        let HvfSysRegEntry {
            encoding, value, ..
        } = snap.sys_regs[i];
        // SAFETY: vcpu is valid on this thread. Encoding is a valid hv_sys_reg_t.
        unsafe {
            let ret = ffi::hv_vcpu_set_sys_reg(vcpu, encoding, value);
            if ret == ffi::HV_UNSUPPORTED && unsupported_sys_reg_default(encoding).is_some() {
                log::debug!(
                    "restore_vcpu: sysreg {encoding:#06x} unsupported by HVF, skipping value {value:#x}"
                );
            } else {
                ffi::check(&format!("hv_vcpu_set_sys_reg({encoding:#06x})"), ret)
                    .map_err(VmmError::from)?;
            }
        }
    }

    // Write SIMD/FP registers Q0-Q31.
    for i in 0..SIMD_REG_COUNT {
        // SAFETY: vcpu is valid on this thread. Register index 0-31 is valid.
        unsafe {
            ffi::check(
                "hv_vcpu_set_simd_fp_reg",
                ffi::hv_vcpu_set_simd_fp_reg(
                    vcpu,
                    #[allow(clippy::cast_possible_truncation)]
                    {
                        ffi::HV_SIMD_FP_REG_Q0 + i as u32
                    },
                    snap.simd_regs[i],
                ),
            )
            .map_err(VmmError::from)?;
        }
    }

    // DO NOT set the vtimer offset here. The adjustment uses
    // mach_absolute_time(), so any delay between restore and the first
    // hv_vcpu_run causes the guest clock to jump forward by that gap.
    // The caller applies the adjustment right before hv_vcpu_run via
    // apply_vtimer_adjust().

    Ok(())
}

fn unsupported_sys_reg_default(encoding: u16) -> Option<u64> {
    match encoding {
        ffi::HV_SYS_REG_CNTP_CTL_EL0 => Some(0),
        ffi::HV_SYS_REG_CNTP_CVAL_EL0 => Some(u64::MAX),
        _ => None,
    }
}

// ============================================================================
// Deferred vtimer offset application
// ============================================================================

/// Pending `CNTVOFF_EL2` application — consumed right before `hv_vcpu_run`.
///
/// The value is pre-computed at snapshot build time and shared across every
/// vCPU of the VM, so all vCPUs end up with identical `CNTVOFF_EL2` and the
/// guest observes a system-coherent `CNTVCT_EL0` (ARM architectural requirement
/// and a hard prerequisite for Linux `sched_clock`).
pub(crate) struct VtimerAdjust {
    /// Value to write into `CNTVOFF_EL2` via `hv_vcpu_set_vtimer_offset`.
    /// After apply: `CNTVCT_EL0 = mach_absolute_time() - target_cntvoff`.
    pub target_cntvoff: u64,
}

impl VtimerAdjust {
    /// Create from a restored snapshot. Reads the pre-computed target CNTVOFF
    /// directly; no per-vCPU timing math.
    pub fn from_snapshot(snap: &HvfVcpuSnapshot) -> Self {
        Self {
            target_cntvoff: snap.vtimer_offset,
        }
    }

    /// Apply the `CNTVOFF_EL2` value to this vCPU. Must be called on the vCPU's
    /// owning thread.
    ///
    /// # Safety
    /// `vcpu` must be a valid handle on the calling thread.
    pub unsafe fn apply(self, vcpu: ffi::hv_vcpu_t) -> Result<()> {
        // SAFETY: per the fn's `# Safety` contract, `vcpu` is valid on this
        // thread.
        unsafe {
            ffi::check(
                "hv_vcpu_set_vtimer_offset",
                ffi::hv_vcpu_set_vtimer_offset(vcpu, self.target_cntvoff),
            )
            .map_err(VmmError::from)?;
            ffi::check(
                "hv_vcpu_set_vtimer_mask",
                ffi::hv_vcpu_set_vtimer_mask(vcpu, false),
            )
            .map_err(VmmError::from)?;
        }
        Ok(())
    }
}

// ============================================================================
// Serialization
// ============================================================================

/// Serialize a snapshot to bytes.
///
/// Safe because `HvfVcpuSnapshot` is `#[repr(C)]` with only POD fields.
pub(crate) fn snapshot_to_bytes(snap: &HvfVcpuSnapshot) -> Vec<u8> {
    bytemuck::bytes_of(snap).to_vec()
}

/// Deserialize a snapshot from bytes.
///
/// Returns an error if the byte slice is too small. Extra trailing
/// bytes (e.g., `VmState` slot padding) are ignored.
pub(crate) fn snapshot_from_bytes(data: &[u8]) -> Result<HvfVcpuSnapshot> {
    let snap_size = std::mem::size_of::<HvfVcpuSnapshot>();
    if data.len() < snap_size {
        return Err(VmmError::InvalidState {
            expected: "valid snapshot size",
            actual: "too small",
        });
    }
    Ok(*bytemuck::from_bytes(&data[..snap_size]))
}
