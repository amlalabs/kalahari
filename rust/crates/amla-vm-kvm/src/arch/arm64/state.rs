// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 vCPU and VM state snapshot types.
//!
//! Captures and restores ARM64 register state via `KVM_GET/SET_ONE_REG`.
//! Core registers (X0–X30, PC, CPSR, FPCR, FPSR) and NEON/SIMD registers
//! (V0–V31, 128-bit each) use `KVM_REG_ARM_CORE`, while system registers
//! (`SCTLR_EL1`, `TTBR0_EL1`, etc.) use `KVM_REG_ARM64_SYSREG`.
//!
//! # Endianness
//!
//! Snapshot serialization uses native-endian byte order (little-endian on
//! ARM64 Linux). Cross-architecture restore is not supported.

use amla_core::arm64::{ALL_REGS, Arm64Reg, Arm64VcpuSnapshot, SIMD_REG_COUNT, SNAPSHOT_SYS_REGS};
use kvm_bindings::{
    KVM_ARM_VCPU_POWER_OFF, KVM_ARM_VCPU_PSCI_0_2, KVM_REG_ARM_CORE, KVM_REG_ARM64,
    KVM_REG_ARM64_SYSREG, KVM_REG_SIZE_U32, KVM_REG_SIZE_U64, KVM_REG_SIZE_U128, kvm_mp_state,
    kvm_vcpu_init,
};

/// KVM firmware register: virtual timer counter value (CNTVCT).
/// Saving and restoring this preserves the guest's view of elapsed time
/// across freeze→spawn, preventing timer deadlocks.
const KVM_REG_ARM_TIMER_CNT: u64 = KVM_REG_ARM64 | KVM_REG_SIZE_U64 | (0x11 << 16) | 1;

use kvm_ioctls::VmFd;

use super::gic_state;
use crate::error::{Result, VmmError};

/// Maximum number of system registers in a snapshot.
///
/// Exported as `MAX_SNAPSHOT_MSRS` from `arch::arm64` for arch-neutral
/// wire format code (parallels x86's MSR count).
pub(crate) const MAX_SNAPSHOT_REGS: usize = 32;

const SNAPSHOT_HAS_TIMER_CNT: u64 = 1 << 0;
const SNAPSHOT_HAS_MP_STATE: u64 = 1 << 1;
const SNAPSHOT_KNOWN_FLAGS: u64 = SNAPSHOT_HAS_TIMER_CNT | SNAPSHOT_HAS_MP_STATE;

/// Magic prefix for the arm64 arch blob wire format. "AKA1" = Amla KVM Arm64.
/// A distinct magic per arch means a cross-arch restore attempt fails loudly.
const ARCH_BLOB_MAGIC: [u8; 4] = *b"AKA1";

/// Arch blob format version. Bump for ANY layout change to the serialized
/// `GicState` — new field, reorder, size change due to vCPU count bumps, etc.
const ARCH_BLOB_VERSION: u32 = 1;

/// Bytes occupied by the magic + version header.
const ARCH_BLOB_HEADER_SIZE: usize = 8;

/// A system register entry with explicit padding for Pod safety.
///
/// Replaces `(u16, u64)` tuple which has implicit padding and cannot
/// safely implement `bytemuck::Pod`.
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct SysRegEntry {
    /// System register encoding (op0/op1/crn/crm/op2 packed into 16 bits).
    pub encoding: u16,
    /// Explicit padding for alignment to 8 bytes.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad: [u8; 6],
    /// Register value.
    pub value: u64,
}

impl SysRegEntry {
    /// Create a new entry from encoding and value.
    pub const fn new(encoding: u16, value: u64) -> Self {
        Self {
            encoding,
            _pad: [0; 6],
            value,
        }
    }

    /// Zero entry.
    pub const ZERO: Self = Self::new(0, 0);
}

// Compile-time check: SNAPSHOT_SYS_REGS list must fit in the fixed-size array.
const _: () = assert!(SNAPSHOT_SYS_REGS.len() <= MAX_SNAPSHOT_REGS);

// ============================================================================
// KVM register ID encoding
// ============================================================================

/// Build a KVM core register ID for a 64-bit register.
///
/// Core registers are indexed by byte offset into `struct kvm_regs`
/// divided by `sizeof(u32)` (4). For u64 registers, each occupies
/// 2 u32 slots, so `X_n` → u32 offset = n * 2.
#[allow(clippy::cast_lossless)] // u32→u64 in const fn where From is unavailable
pub(crate) const fn core_reg_u64(u32_offset: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | (KVM_REG_ARM_CORE as u64) | u32_offset
}

/// Build a KVM core register ID for a 32-bit register.
#[allow(clippy::cast_lossless)] // u32→u64 in const fn where From is unavailable
const fn core_reg_u32(u32_offset: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U32 | (KVM_REG_ARM_CORE as u64) | u32_offset
}

/// Build a KVM core register ID for a 128-bit register.
#[allow(clippy::cast_lossless)] // u32→u64 in const fn where From is unavailable
const fn core_reg_u128(u32_offset: u64) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U128 | (KVM_REG_ARM_CORE as u64) | u32_offset
}

/// Build a KVM system register ID from the (op0,op1,crn,crm,op2) encoding.
///
/// The encoding matches `Arm64SysReg::encoding()` (same bit layout as HVF).
#[allow(clippy::cast_lossless)] // u32→u64 and u16→u64 in const fn where From is unavailable
const fn sysreg_id(encoding: u16) -> u64 {
    KVM_REG_ARM64 | KVM_REG_SIZE_U64 | (KVM_REG_ARM64_SYSREG as u64) | (encoding as u64)
}

/// Map an `Arm64SysReg` encoding to its KVM register ID.
///
/// On KVM, `SPSR_EL1`, `ELR_EL1`, `SP_EL0`, and `SP_EL1` are part of the core
/// register set (`struct kvm_regs`), not system registers. HVF exposes
/// them as `hv_sys_reg_t` values. This function translates the shared
/// encoding to the correct KVM register ID for either kind.
const fn sysreg_kvm_id(encoding: u16) -> u64 {
    match encoding {
        // SP_EL0: kvm_regs.regs.sp, byte offset 248, u32 offset 62
        0xc208 => core_reg_u64(62),
        // SP_EL1: kvm_regs.sp_el1, byte offset 272, u32 offset 68
        0xe208 => core_reg_u64(68),
        // ELR_EL1: kvm_regs.elr_el1, byte offset 280, u32 offset 70
        0xc201 => core_reg_u64(70),
        // SPSR_EL1: kvm_regs.spsr[0], byte offset 288, u32 offset 72
        0xc200 => core_reg_u64(72),
        // All other system registers use KVM_REG_ARM64_SYSREG
        _ => sysreg_id(encoding),
    }
}

/// Byte offsets within ARM64 `struct kvm_regs` for FPCR/FPSR.
///
/// Layout: `user_pt_regs` (272B) + `sp_el1` (8) + `elr_el1` (8) +
/// `spsr[5]` (40) + **8B padding** (16-byte align for `__uint128_t`) +
/// `user_fpsimd_state { vregs[32] (512B), fpsr (4), fpcr (4) }`.
///
/// Total offset to `fp_regs` = 272 + 8 + 8 + 40 + 8(pad) = 336.
/// - FPSR: byte offset 336+512 = 848 → u32 offset 212
/// - FPCR: byte offset 336+512+4 = 852 → u32 offset 213
const FPSR_U32_OFFSET: u64 = 212;
const FPCR_U32_OFFSET: u64 = 213;

/// Byte offset of `user_fpsimd_state.vregs[0]` within `struct kvm_regs`.
///
/// Layout: `user_pt_regs` (272B) + `sp_el1` (8) + `elr_el1` (8) +
/// `spsr[5]` (40) + 8B padding = 336. Each V register is 16 bytes
/// (`__uint128_t`), so `V_n` starts at byte offset 336 + n * 16,
/// giving u32 offset (336 + n * 16) / 4 = 84 + n * 4.
const VREG_BASE_U32_OFFSET: u64 = 84;

/// Build a KVM register ID for SIMD/FP register `V_n` (128-bit).
const fn simd_reg_kvm_id(n: usize) -> u64 {
    core_reg_u128(VREG_BASE_U32_OFFSET + (n as u64) * 4)
}

/// Map an `Arm64Reg` to its KVM register ID and whether it's 32-bit.
///
/// Returns `(kvm_reg_id, is_u32)`.
fn arm64_reg_kvm_id(reg: Arm64Reg) -> (u64, bool) {
    match reg {
        // FPCR/FPSR are 32-bit registers in the FP state area
        Arm64Reg::FPCR => (core_reg_u32(FPCR_U32_OFFSET), true),
        Arm64Reg::FPSR => (core_reg_u32(FPSR_U32_OFFSET), true),
        // PC: byte offset 256 in user_pt_regs (after regs[31] + sp), u32 offset = 64
        Arm64Reg::PC => (core_reg_u64(64), false),
        // CPSR/PSTATE: byte offset 264, u32 offset = 66
        Arm64Reg::CPSR => (core_reg_u64(66), false),
        // X0–X30: byte offset = index * 8, u32 offset = index * 2
        other => {
            let idx = other.index();
            debug_assert!(idx <= 30, "unexpected Arm64Reg index {idx}");
            (core_reg_u64((idx as u64) * 2), false)
        }
    }
}

// ============================================================================
// VcpuSnapshot
// ============================================================================

/// ARM64 vCPU register snapshot.
///
/// Uses `#[repr(C)]` with fixed-size arrays so the wire format can use raw
/// `memcpy` (matching x86's `VcpuSnapshot` pattern). For serde-friendly
/// exchange, use `to_shared()` / `from_shared()`.
///
/// On ARM64, register state is captured via `KVM_GET_ONE_REG` for each
/// register individually (unlike x86 which has bulk get/set ioctls).
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
#[repr(C)]
pub struct VcpuSnapshot {
    /// General-purpose registers: X0–X30, PC, FPCR, FPSR, CPSR (35 values).
    pub gp_regs: [u64; Arm64Reg::COUNT],
    /// Explicit padding: 35 × u64 = 280 bytes, `simd_regs` needs 16-byte alignment.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad_gp: [u8; 8],
    /// NEON/SIMD registers V0–V31 (128-bit each).
    pub simd_regs: [u128; SIMD_REG_COUNT],
    /// System registers as (encoding, value) pairs with explicit padding.
    pub sys_regs: [SysRegEntry; MAX_SNAPSHOT_REGS],
    /// Number of valid entries in `sys_regs`.
    pub sys_reg_count: u32,
    /// PSCI power state (0 = running).
    pub power_state: u32,
    /// Virtual timer counter value (`KVM_REG_ARM_TIMER_CNT`).
    /// Restored on spawn to preserve guest's view of elapsed time.
    pub timer_cnt: u64,
    /// Presence flags for optional KVM state captured from a running vCPU.
    ///
    /// Boot seed snapshots leave these clear; captured snapshots set bits only
    /// for host capabilities that were actually available during capture.
    pub snapshot_flags: u64,
    /// Explicit padding to keep the 16-byte-aligned struct free of trailing padding.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad_snapshot_flags: u64,
}

// Compile-time layout assertions: prove that #[repr(C)] packs the fields
// contiguously with no implicit padding (beyond the explicit `_pad_gp`).
// These guarantee the Pod implementation is sound across compiler versions.
const _: () = {
    use std::mem::{offset_of, size_of};

    assert!(offset_of!(VcpuSnapshot, gp_regs) == 0);
    assert!(
        offset_of!(VcpuSnapshot, _pad_gp) == size_of::<[u64; amla_core::arm64::Arm64Reg::COUNT]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, simd_regs)
            == offset_of!(VcpuSnapshot, _pad_gp) + size_of::<[u8; 8]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, sys_regs)
            == offset_of!(VcpuSnapshot, simd_regs) + size_of::<[u128; SIMD_REG_COUNT]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, sys_reg_count)
            == offset_of!(VcpuSnapshot, sys_regs) + size_of::<[SysRegEntry; MAX_SNAPSHOT_REGS]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, power_state)
            == offset_of!(VcpuSnapshot, sys_reg_count) + size_of::<u32>()
    );
    assert!(
        offset_of!(VcpuSnapshot, timer_cnt)
            == offset_of!(VcpuSnapshot, power_state) + size_of::<u32>()
    );
    assert!(
        offset_of!(VcpuSnapshot, snapshot_flags)
            == offset_of!(VcpuSnapshot, timer_cnt) + size_of::<u64>()
    );
    assert!(
        offset_of!(VcpuSnapshot, _pad_snapshot_flags)
            == offset_of!(VcpuSnapshot, snapshot_flags) + size_of::<u64>()
    );

    // Total size equals last field end — no trailing padding.
    assert!(
        size_of::<VcpuSnapshot>()
            == offset_of!(VcpuSnapshot, _pad_snapshot_flags) + size_of::<u64>()
    );
};

// Compile-time check: VcpuSnapshot must fit in a VCPU_SLOT_SIZE slot.
amla_core::assert_vcpu_fits!(VcpuSnapshot);

impl std::fmt::Debug for VcpuSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use amla_core::arm64::Arm64Reg;
        let r = &self.gp_regs;
        let mut s = f.debug_struct("VcpuSnapshot");
        // GP registers
        for (i, val) in r[..=30].iter().enumerate() {
            s.field(&format!("x{i}"), &format_args!("{val:#018x}"));
        }
        s.field("pc", &format_args!("{:#018x}", r[Arm64Reg::PC as usize]))
            .field(
                "cpsr",
                &format_args!("{:#010x}", r[Arm64Reg::CPSR as usize]),
            )
            .field(
                "fpcr",
                &format_args!("{:#010x}", r[Arm64Reg::FPCR as usize]),
            )
            .field(
                "fpsr",
                &format_args!("{:#010x}", r[Arm64Reg::FPSR as usize]),
            );
        // System registers
        for i in 0..self.sys_reg_count as usize {
            let entry = &self.sys_regs[i];
            s.field(
                &format!("sysreg({:#06x})", entry.encoding),
                &format_args!("{:#018x}", entry.value),
            );
        }
        s.field("power_state", &self.power_state)
            .finish_non_exhaustive()
    }
}

impl VcpuSnapshot {
    /// Validate snapshot fields that could cause out-of-bounds access or
    /// undefined KVM behavior if corrupted in the shared-memory slot.
    pub fn validate(&self) -> Result<()> {
        if self.sys_reg_count as usize > MAX_SNAPSHOT_REGS {
            return Err(VmmError::InvalidState {
                expected: "sys_reg_count <= MAX_SNAPSHOT_REGS (32)",
                actual: "sys_reg_count out of range",
            });
        }
        if self.snapshot_flags & !SNAPSHOT_KNOWN_FLAGS != 0 {
            return Err(VmmError::InvalidState {
                expected: "known arm64 snapshot_flags bits only",
                actual: "snapshot_flags has unknown bits",
            });
        }
        Ok(())
    }

    /// Capture vCPU state from a KVM vCPU fd.
    ///
    /// Reads 35 core registers, 32 NEON/SIMD registers (V0–V31), and
    /// 15 system registers individually via `KVM_GET_ONE_REG`.
    pub(crate) fn capture(vcpu: &kvm_ioctls::VcpuFd) -> Result<Self> {
        let mut gp_regs = [0u64; Arm64Reg::COUNT];

        // Capture core registers (X0-X30, PC, CPSR, FPCR, FPSR)
        for &reg in &ALL_REGS {
            let (kvm_id, is_u32) = arm64_reg_kvm_id(reg);
            let value = if is_u32 {
                let mut buf = [0u8; 4];
                vcpu.get_one_reg(kvm_id, &mut buf).map_err(|e| {
                    VmmError::Config(format!(
                        "GET_ONE_REG failed for {reg:?} (id={kvm_id:#018x}): {e}"
                    ))
                })?;
                u64::from(u32::from_ne_bytes(buf))
            } else {
                let mut buf = [0u8; 8];
                vcpu.get_one_reg(kvm_id, &mut buf).map_err(|e| {
                    VmmError::Config(format!(
                        "GET_ONE_REG failed for {reg:?} (id={kvm_id:#018x}): {e}"
                    ))
                })?;
                u64::from_ne_bytes(buf)
            };
            gp_regs[reg.index()] = value;
        }

        // Capture NEON/SIMD registers V0–V31 (128-bit each)
        let mut simd_regs = [0u128; SIMD_REG_COUNT];
        for (n, slot) in simd_regs.iter_mut().enumerate() {
            let kvm_id = simd_reg_kvm_id(n);
            let mut buf = [0u8; 16];
            vcpu.get_one_reg(kvm_id, &mut buf).map_err(|e| {
                VmmError::Config(format!(
                    "GET_ONE_REG failed for V{n} (id={kvm_id:#018x}): {e}"
                ))
            })?;
            *slot = u128::from_ne_bytes(buf);
        }

        // Capture system registers (SCTLR_EL1, TTBR0_EL1, etc.)
        let mut sys_regs = [SysRegEntry::ZERO; MAX_SNAPSHOT_REGS];
        for (i, &sysreg) in SNAPSHOT_SYS_REGS.iter().enumerate() {
            let kvm_id = sysreg_kvm_id(sysreg.encoding());
            let mut buf = [0u8; 8];
            vcpu.get_one_reg(kvm_id, &mut buf).map_err(|e| {
                VmmError::Config(format!(
                    "GET_ONE_REG failed for sysreg {:?} (enc={:#06x}, id={kvm_id:#018x}): {e}",
                    sysreg,
                    sysreg.encoding()
                ))
            })?;
            sys_regs[i] = SysRegEntry::new(sysreg.encoding(), u64::from_ne_bytes(buf));
        }

        // Capture virtual timer counter (preserves guest time across freeze→spawn).
        // Optional: QEMU TCG may not expose this firmware register.
        let (timer_cnt, timer_cnt_present) = {
            let mut buf = [0u8; 8];
            match vcpu.get_one_reg(KVM_REG_ARM_TIMER_CNT, &mut buf) {
                Ok(_) => (u64::from_ne_bytes(buf), true),
                Err(e) => {
                    log::debug!("KVM_REG_ARM_TIMER_CNT not available: {e}");
                    (0, false)
                }
            }
        };
        let mut snapshot_flags = if timer_cnt_present {
            SNAPSHOT_HAS_TIMER_CNT
        } else {
            0
        };

        // Capture MP state (RUNNABLE/STOPPED/SUSPENDED).
        // Required for correct restore — without this, KVM may not deliver
        // interrupts to the vCPU (matches Firecracker's proven approach).
        let mp = vcpu.get_mp_state()?;
        snapshot_flags |= SNAPSHOT_HAS_MP_STATE;

        Ok(Self {
            gp_regs,
            _pad_gp: [0; 8],
            simd_regs,
            sys_regs,
            #[allow(clippy::cast_possible_truncation)] // ARM64 KVM: sys reg count always < u32::MAX
            sys_reg_count: SNAPSHOT_SYS_REGS.len() as u32,
            power_state: mp.mp_state,
            timer_cnt,
            snapshot_flags,
            _pad_snapshot_flags: 0,
        })
    }

    /// Restore vCPU state to a KVM vCPU fd.
    ///
    /// Sets all registers via `KVM_SET_ONE_REG`, then sets MP state last
    /// so KVM knows the vCPU's execution state after all registers are
    /// configured (matches Firecracker's proven ordering).
    ///
    /// Note: unlike Firecracker (which creates new VMs), we reuse shells
    /// so we do NOT call `KVM_ARM_VCPU_INIT` here — that would reset
    /// internal PSCI state and break mid-execution register restore.
    pub(crate) fn restore(&self, vcpu: &kvm_ioctls::VcpuFd) -> Result<()> {
        const KVM_MP_STATE_STOPPED: u32 = 3;

        // For stopped APs (PSCI powered-off), re-init with POWER_OFF flag
        // instead of restoring registers. ARM64 KVM rejects MP_STATE=STOPPED;
        // the correct way is KVM_ARM_VCPU_INIT with KVM_ARM_VCPU_POWER_OFF.
        let has_captured_mp_state = self.snapshot_flags & SNAPSHOT_HAS_MP_STATE != 0;
        if self.power_state == KVM_MP_STATE_STOPPED {
            #[allow(clippy::field_reassign_with_default)]
            let kvi = {
                let mut kvi = kvm_vcpu_init::default();
                kvi.target = 5; // KVM_ARM_TARGET_GENERIC_V8
                kvi.features[0] = (1 << KVM_ARM_VCPU_PSCI_0_2) | (1 << KVM_ARM_VCPU_POWER_OFF);
                kvi
            };
            vcpu.vcpu_init(&kvi).map_err(|e| {
                VmmError::Config(format!("KVM_ARM_VCPU_INIT (POWER_OFF) failed: {e}"))
            })?;
            return Ok(());
        }

        // Restore core registers
        for &reg in &ALL_REGS {
            let (kvm_id, is_u32) = arm64_reg_kvm_id(reg);
            let value = self.gp_regs[reg.index()];
            let result = if is_u32 {
                #[allow(clippy::cast_possible_truncation)] // 32-bit regs (FPCR/FPSR) stored in u64
                let buf = (value as u32).to_ne_bytes();
                vcpu.set_one_reg(kvm_id, &buf)
            } else {
                let buf = value.to_ne_bytes();
                vcpu.set_one_reg(kvm_id, &buf)
            };
            result.map_err(|e| {
                VmmError::Config(format!(
                    "SET_ONE_REG failed for {reg:?} (id={kvm_id:#018x}, val={value:#x}): {e}"
                ))
            })?;
        }

        // Restore NEON/SIMD registers V0–V31
        for n in 0..SIMD_REG_COUNT {
            let kvm_id = simd_reg_kvm_id(n);
            let buf = self.simd_regs[n].to_ne_bytes();
            vcpu.set_one_reg(kvm_id, &buf).map_err(|e| {
                VmmError::Config(format!(
                    "SET_ONE_REG failed for V{n} (id={kvm_id:#018x}, val={:#x}): {e}",
                    self.simd_regs[n]
                ))
            })?;
        }

        // Restore all system registers including timer state.
        // Firecracker restores CNTV_CTL_EL0 and CNTV_CVAL_EL0 without filtering —
        // KVM handles the CNTVOFF translation transparently. Without these, the
        // guest kernel's scheduler timer is disabled and the kernel hangs in WFI.
        for i in 0..self.sys_reg_count as usize {
            let entry = self.sys_regs[i];
            let kvm_id = sysreg_kvm_id(entry.encoding);
            let buf = entry.value.to_ne_bytes();
            vcpu.set_one_reg(kvm_id, &buf).map_err(|e| {
                VmmError::Config(format!(
                    "SET_ONE_REG failed for sysreg {:#06x} (id={kvm_id:#018x}, val={:#x}): {e}",
                    entry.encoding, entry.value
                ))
            })?;
        }

        // Restore virtual timer counter offset if the source host exposed it.
        if self.snapshot_flags & SNAPSHOT_HAS_TIMER_CNT != 0 {
            let buf = self.timer_cnt.to_ne_bytes();
            vcpu.set_one_reg(KVM_REG_ARM_TIMER_CNT, &buf).map_err(|e| {
                VmmError::Config(format!(
                    "SET_ONE_REG failed for KVM_REG_ARM_TIMER_CNT (val={:#x}): {e}",
                    self.timer_cnt
                ))
            })?;
        }

        // MP state LAST — tells KVM the vCPU's execution state after all
        // registers are configured (Firecracker ordering). Boot seeds did not
        // capture KVM MP state, so keep their MP-state programming best-effort;
        // captured snapshots set SNAPSHOT_HAS_MP_STATE and must restore exactly.
        let result = vcpu.set_mp_state(kvm_mp_state {
            mp_state: self.power_state,
        });
        if has_captured_mp_state {
            result?;
        } else if let Err(e) = result {
            log::debug!(
                "KVM_SET_MP_STATE skipped for boot seed (state={}): {e}",
                self.power_state
            );
        }

        Ok(())
    }

    /// Create a minimal snapshot for an AP waiting for power-on.
    ///
    /// Delegates register values to [`Arm64VcpuSnapshot::for_ap_powered_off()`]
    /// and adds KVM-specific `power_state = KVM_MP_STATE_STOPPED`.
    ///
    /// # Errors
    ///
    /// Infallible on arm64 today — the `Result` signature exists so the call
    /// sites in `write_boot_state` stay arch-independent. `x86_64`'s version can
    /// reject vcpu indices that overflow the xAPIC 8-bit ID field.
    pub fn for_init_received(_vcpu_index: usize) -> crate::error::Result<Self> {
        const KVM_MP_STATE_STOPPED: u32 = 3;
        let shared = Arm64VcpuSnapshot::for_ap_powered_off();
        let mut snap = Self::from_boot_shared(&shared);
        snap.power_state = KVM_MP_STATE_STOPPED;
        Ok(snap)
    }

    /// Create a snapshot suitable for ARM64 Linux boot.
    ///
    /// Takes the register state from `LinuxBootBuilder` and converts it
    /// to a KVM-specific snapshot.
    pub fn for_boot(shared: &Arm64VcpuSnapshot) -> Self {
        Self::from_boot_shared(shared)
    }

    /// Convert to the shared, serde-friendly snapshot type.
    pub fn to_shared(&self) -> Arm64VcpuSnapshot {
        let gp_regs = self.gp_regs.to_vec();
        let sys_regs = self.sys_regs[..self.sys_reg_count as usize]
            .iter()
            .map(|e| (e.encoding, e.value))
            .collect();
        let simd_regs = self.simd_regs.to_vec();
        Arm64VcpuSnapshot {
            gp_regs,
            sys_regs,
            simd_regs,
        }
    }

    /// Create from the shared serde-friendly type.
    ///
    /// This is the strict restore conversion: GP and SIMD arrays must be exact,
    /// and system register entries must fit without truncation. Boot seeding
    /// uses [`Self::for_boot`] and [`Self::for_init_received`] instead.
    pub fn try_from_shared(shared: &Arm64VcpuSnapshot) -> Result<Self> {
        Self::try_from(shared)
    }

    fn from_boot_shared(shared: &Arm64VcpuSnapshot) -> Self {
        let mut gp_regs = [0u64; Arm64Reg::COUNT];
        let copy_len = shared.gp_regs.len().min(Arm64Reg::COUNT);
        gp_regs[..copy_len].copy_from_slice(&shared.gp_regs[..copy_len]);

        let mut simd_regs = [0u128; SIMD_REG_COUNT];
        let simd_count = shared.simd_regs.len().min(SIMD_REG_COUNT);
        simd_regs[..simd_count].copy_from_slice(&shared.simd_regs[..simd_count]);

        let mut sys_regs = [SysRegEntry::ZERO; MAX_SNAPSHOT_REGS];
        let sys_count = shared.sys_regs.len().min(MAX_SNAPSHOT_REGS);
        for (i, &(enc, val)) in shared.sys_regs[..sys_count].iter().enumerate() {
            sys_regs[i] = SysRegEntry::new(enc, val);
        }

        Self {
            gp_regs,
            _pad_gp: [0; 8],
            simd_regs,
            sys_regs,
            #[allow(clippy::cast_possible_truncation)] // ARM64 KVM: sys reg count always < u32::MAX
            sys_reg_count: sys_count as u32,
            power_state: 0,
            timer_cnt: 0,
            snapshot_flags: 0,
            _pad_snapshot_flags: 0,
        }
    }
}

impl TryFrom<&Arm64VcpuSnapshot> for VcpuSnapshot {
    type Error = VmmError;

    fn try_from(shared: &Arm64VcpuSnapshot) -> Result<Self> {
        if shared.gp_regs.len() != Arm64Reg::COUNT {
            return Err(VmmError::SizeMismatch {
                expected: Arm64Reg::COUNT,
                actual: shared.gp_regs.len(),
            });
        }
        if shared.simd_regs.len() != SIMD_REG_COUNT {
            return Err(VmmError::SizeMismatch {
                expected: SIMD_REG_COUNT,
                actual: shared.simd_regs.len(),
            });
        }
        if shared.sys_regs.len() > MAX_SNAPSHOT_REGS {
            return Err(VmmError::InvalidState {
                expected: "sys_regs length <= MAX_SNAPSHOT_REGS",
                actual: "too many system registers",
            });
        }

        let mut gp_regs = [0u64; Arm64Reg::COUNT];
        gp_regs.copy_from_slice(&shared.gp_regs);

        let mut simd_regs = [0u128; SIMD_REG_COUNT];
        simd_regs.copy_from_slice(&shared.simd_regs);

        let mut sys_regs = [SysRegEntry::ZERO; MAX_SNAPSHOT_REGS];
        for (i, &(enc, val)) in shared.sys_regs.iter().enumerate() {
            sys_regs[i] = SysRegEntry::new(enc, val);
        }

        Ok(Self {
            gp_regs,
            _pad_gp: [0; 8],
            simd_regs,
            sys_regs,
            #[allow(clippy::cast_possible_truncation)] // length checked against MAX_SNAPSHOT_REGS
            sys_reg_count: shared.sys_regs.len() as u32,
            power_state: 0,
            timer_cnt: 0,
            snapshot_flags: 0,
            _pad_snapshot_flags: 0,
        })
    }
}

// ============================================================================
// VmStateSnapshot
// ============================================================================

/// ARM64 VM-level state snapshot.
///
/// Uses the KVM backend-private `gic_pod::GicState` byte format for the
/// in-kernel KVM GIC. A zeroed `GicState` represents a fresh VM with no prior
/// interrupt state. This blob is not interchangeable with the userspace-GIC/HVF
/// `amla_vm_gic::GicState` blob even though both model `GICv3`.
#[derive(Clone, Debug)]
pub struct VmStateSnapshot {
    /// `GICv3` state in Pod format. Zeroed = fresh VM.
    pub gic_state: super::gic_pod::GicState,
}

impl VmStateSnapshot {
    /// Capture VM state from the in-kernel GIC.
    ///
    /// Reads KVM GIC registers via `KVM_GET_DEVICE_ATTR` and converts
    /// to the `GicState` Pod format.
    pub(crate) fn capture(
        _vm_fd: &VmFd,
        device_state: &super::InitialDeviceState,
        num_vcpus: usize,
    ) -> Result<Self> {
        let kvm_state = gic_state::save_gic_state(device_state.gic_fd(), num_vcpus)?;
        Ok(Self {
            gic_state: (&kvm_state).into(),
        })
    }

    /// Restore in-kernel GIC state from this snapshot.
    pub(crate) fn restore(
        &self,
        _vm_fd: &VmFd,
        _clock_offset_ns: Option<u64>,
        device_state: &super::InitialDeviceState,
    ) -> Result<()> {
        let kvm_state: gic_state::KvmGicState = (&self.gic_state).into();
        gic_state::restore_gic_state(device_state.gic_fd(), &kvm_state)
    }

    /// Validate that this irqchip snapshot matches the VM vCPU topology before
    /// any per-vCPU state is restored into a reusable shell.
    pub(crate) fn validate_vcpu_count(&self, expected: usize) -> Result<()> {
        let actual = self.gic_state.vcpu_count as usize;
        if actual != expected {
            return Err(VmmError::Config(format!(
                "GIC arch blob vCPU count {actual} does not match VM vCPU count {expected}"
            )));
        }
        Ok(())
    }

    /// Serialize GIC state into `buf`. Returns the number of bytes written.
    ///
    /// The blob is prefixed with an 8-byte envelope: 4-byte magic + 4-byte LE
    /// version. Bump `ARCH_BLOB_VERSION` whenever `GicState`'s layout changes
    /// (new field, size change, reordering). The distinct `AKA1` magic also
    /// rejects blobs from a different host architecture.
    pub fn write_arch_blob(&self, buf: &mut [u8]) -> usize {
        let state_bytes = bytemuck::bytes_of(&self.gic_state);
        let total = ARCH_BLOB_HEADER_SIZE + state_bytes.len();
        assert!(total <= buf.len(), "GIC blob overflow");
        buf[..4].copy_from_slice(&ARCH_BLOB_MAGIC);
        buf[4..8].copy_from_slice(&ARCH_BLOB_VERSION.to_le_bytes());
        buf[ARCH_BLOB_HEADER_SIZE..total].copy_from_slice(state_bytes);
        total
    }

    pub(crate) fn write_boot_arch_blob(&self, buf: &mut [u8]) -> usize {
        self.write_arch_blob(buf)
    }

    /// Deserialize GIC state from `buf`.
    ///
    /// Strict: rejects missing header, bad magic, wrong version, or truncated
    /// payload. There is no backwards-compat path — a fresh VM gets its real
    /// default state written via [`Self::write_arch_blob`] at restore time by
    /// the caller, not via a zero fallback here.
    pub fn from_arch_blob(buf: &[u8]) -> Result<Self> {
        if buf.len() < ARCH_BLOB_HEADER_SIZE {
            return Err(VmmError::Config(format!(
                "from_arch_blob: buffer too short for header ({} bytes, need {ARCH_BLOB_HEADER_SIZE})",
                buf.len(),
            )));
        }
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != ARCH_BLOB_MAGIC {
            return Err(VmmError::Config(format!(
                "from_arch_blob: bad magic {magic:?}, expected {ARCH_BLOB_MAGIC:?}"
            )));
        }
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != ARCH_BLOB_VERSION {
            return Err(VmmError::Config(format!(
                "from_arch_blob: version {version} does not match expected {ARCH_BLOB_VERSION}"
            )));
        }
        let gic_size = core::mem::size_of::<super::gic_pod::GicState>();
        let payload_end = ARCH_BLOB_HEADER_SIZE + gic_size;
        if buf.len() < payload_end {
            return Err(VmmError::Config(format!(
                "from_arch_blob: payload too short ({} bytes, need {payload_end})",
                buf.len(),
            )));
        }
        let state: &super::gic_pod::GicState =
            bytemuck::from_bytes(&buf[ARCH_BLOB_HEADER_SIZE..payload_end]);
        Ok(Self { gic_state: *state })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn zeroed_snapshot() -> VmStateSnapshot {
        VmStateSnapshot {
            gic_state: bytemuck::Zeroable::zeroed(),
        }
    }

    fn blob_size() -> usize {
        ARCH_BLOB_HEADER_SIZE + core::mem::size_of::<super::super::gic_pod::GicState>()
    }

    #[test]
    fn arch_blob_roundtrip() {
        let original = zeroed_snapshot();
        let mut buf = vec![0u8; blob_size()];
        let written = original.write_arch_blob(&mut buf);
        assert_eq!(written, blob_size());
        let restored = VmStateSnapshot::from_arch_blob(&buf[..written]).unwrap();
        assert_eq!(
            bytemuck::bytes_of(&restored.gic_state),
            bytemuck::bytes_of(&original.gic_state),
        );
    }

    #[test]
    fn from_arch_blob_empty_rejected() {
        // No more silent zero-fallback for empty buffers.
        assert!(VmStateSnapshot::from_arch_blob(&[]).is_err());
    }

    #[test]
    fn from_arch_blob_bad_magic_rejected() {
        let mut buf = vec![0u8; blob_size()];
        zeroed_snapshot().write_arch_blob(&mut buf);
        buf[0] = b'X';
        let err = VmStateSnapshot::from_arch_blob(&buf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("bad magic"), "unexpected error: {err}");
    }

    #[test]
    fn from_arch_blob_bad_version_rejected() {
        let mut buf = vec![0u8; blob_size()];
        zeroed_snapshot().write_arch_blob(&mut buf);
        buf[4..8].copy_from_slice(&(ARCH_BLOB_VERSION + 99).to_le_bytes());
        let err = VmStateSnapshot::from_arch_blob(&buf)
            .unwrap_err()
            .to_string();
        assert!(err.contains("version"), "unexpected error: {err}");
    }

    #[test]
    fn from_arch_blob_truncated_payload_rejected() {
        let mut buf = vec![0u8; blob_size()];
        zeroed_snapshot().write_arch_blob(&mut buf);
        let truncated = &buf[..ARCH_BLOB_HEADER_SIZE + 4];
        let err = VmStateSnapshot::from_arch_blob(truncated)
            .unwrap_err()
            .to_string();
        assert!(err.contains("payload too short"), "unexpected error: {err}");
    }

    #[test]
    fn validate_vcpu_count_rejects_blob_vm_mismatch() {
        let mut snap = zeroed_snapshot();
        snap.gic_state.vcpu_count = 1;
        let err = snap.validate_vcpu_count(2).unwrap_err().to_string();
        assert!(
            err.contains("GIC arch blob vCPU count 1 does not match VM vCPU count 2"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn vcpu_validate_rejects_unknown_snapshot_flags() {
        let mut snap: VcpuSnapshot = bytemuck::Zeroable::zeroed();
        snap.snapshot_flags = SNAPSHOT_KNOWN_FLAGS | (1 << 63);
        assert!(snap.validate().is_err());
    }

    #[test]
    fn try_from_shared_accepts_exact_gp_and_simd_lengths() {
        let shared = Arm64VcpuSnapshot::empty();
        let snap = VcpuSnapshot::try_from_shared(&shared).unwrap();
        assert_eq!(snap.sys_reg_count, 0);
        assert_eq!(snap.snapshot_flags, 0);
    }

    #[test]
    fn try_from_shared_rejects_short_gp_regs() {
        let mut shared = Arm64VcpuSnapshot::empty();
        shared.gp_regs.pop();
        let err = VcpuSnapshot::try_from_shared(&shared)
            .unwrap_err()
            .to_string();
        assert!(err.contains("size mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn try_from_shared_rejects_too_many_sys_regs() {
        let mut shared = Arm64VcpuSnapshot::empty();
        shared.sys_regs = vec![(0, 0); MAX_SNAPSHOT_REGS + 1];
        let err = VcpuSnapshot::try_from_shared(&shared)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("too many system registers"),
            "unexpected error: {err}"
        );
    }
}
