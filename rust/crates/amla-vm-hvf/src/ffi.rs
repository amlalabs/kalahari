// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Raw FFI bindings to Apple's Hypervisor.framework.
//!
//! These bindings cover the ARM64 (Apple Silicon) API surface needed for
//! VM creation, vCPU execution, memory mapping, register access, and
//! interrupt delivery.
//!
//! # Safety
//!
//! All functions in this module are `unsafe extern "C"`. Callers must:
//! - Call `hv_vm_create` before any other HVF function
//! - Only call `hv_vcpu_run`/register accessors from the thread that
//!   created the vCPU (HVF has thread-affinity for vCPUs)
//! - Ensure memory regions passed to `hv_vm_map` remain valid until unmapped
//!
//! # Linking
//!
//! The `Hypervisor` framework is linked via `#[link(name = "Hypervisor", kind = "framework")]`.
//! The binary must be signed with the `com.apple.security.hypervisor` entitlement.

#![allow(non_camel_case_types)]

use std::ffi::c_void;

// =============================================================================
// Return type
// =============================================================================

/// HVF return code. 0 = `HV_SUCCESS`.
pub type hv_return_t = i32;

pub const HV_SUCCESS: hv_return_t = 0;
pub const HV_ERROR: hv_return_t = 0xfae9_4001_u32.cast_signed();
pub const HV_BUSY: hv_return_t = 0xfae9_4002_u32.cast_signed();
pub const HV_BAD_ARGUMENT: hv_return_t = 0xfae9_4003_u32.cast_signed();
pub const HV_NO_RESOURCES: hv_return_t = 0xfae9_4005_u32.cast_signed();
pub const HV_NO_DEVICE: hv_return_t = 0xfae9_4006_u32.cast_signed();
pub const HV_DENIED: hv_return_t = 0xfae9_4007_u32.cast_signed();
pub const HV_UNSUPPORTED: hv_return_t = 0xfae9_400f_u32.cast_signed();
pub const HV_ILLEGAL_GUEST_STATE: hv_return_t = 0xfae9_4004_u32.cast_signed();
pub const HV_EXISTS: hv_return_t = 0xfae9_4008_u32.cast_signed();

// =============================================================================
// Opaque handles
// =============================================================================

/// vCPU instance handle, created by `hv_vcpu_create`.
pub type hv_vcpu_t = u64;

/// Pointer to HVF-managed exit information.
pub type hv_vcpu_exit_t = *const VcpuExitInfo;

// =============================================================================
// vCPU exit information
// =============================================================================

/// Exit information populated by `hv_vcpu_run`.
///
/// Layout: `reason` (4 bytes) + 4 bytes padding + `exception` (24 bytes) = 32 bytes.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VcpuExitInfo {
    pub reason: hv_exit_reason_t,
    _pad: u32,
    pub exception: ExceptionSyndrome,
}

/// Exception syndrome from `ESR_EL2`.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionSyndrome {
    pub syndrome: u64,
    pub virtual_address: u64,
    /// Physical address (Stage 2 fault address for MMIO).
    pub physical_address: u64,
}

// =============================================================================
// Exit reasons
// =============================================================================

pub type hv_exit_reason_t = u32;

pub const HV_EXIT_REASON_CANCELED: hv_exit_reason_t = 0;
/// Exception taken to EL2 (MMIO, HVC, WFI, sysreg trap, etc.).
pub const HV_EXIT_REASON_EXCEPTION: hv_exit_reason_t = 1;
pub const HV_EXIT_REASON_VTIMER_ACTIVATED: hv_exit_reason_t = 2;
pub const HV_EXIT_REASON_UNKNOWN: hv_exit_reason_t = 3;

// =============================================================================
// ARM64 register enums
// =============================================================================

/// General-purpose + control register identifiers.
///
/// Discriminant values match Apple's `hv_reg_t` and our `Arm64Reg` enum,
/// so no translation layer is needed.
pub type hv_reg_t = u32;

// GP registers X0-X30
pub const HV_REG_X0: hv_reg_t = 0;
pub const HV_REG_X30: hv_reg_t = 30;
pub const HV_REG_PC: hv_reg_t = 31;
pub const HV_REG_FPCR: hv_reg_t = 32;
pub const HV_REG_FPSR: hv_reg_t = 33;
pub const HV_REG_CPSR: hv_reg_t = 34;

/// System register identifiers.
///
/// Encoding: `(Op0 << 14) | (Op1 << 11) | (CRn << 7) | (CRm << 3) | Op2`.
/// Matches `Arm64SysReg::encoding()` by design.
pub type hv_sys_reg_t = u16;

/// SIMD/FP register identifiers (V0 = 0 .. V31 = 31).
pub type hv_simd_fp_reg_t = u32;

pub const HV_SIMD_FP_REG_Q0: hv_simd_fp_reg_t = 0;
#[allow(dead_code)]
pub const HV_SIMD_FP_REG_Q31: hv_simd_fp_reg_t = 31;

// System register encodings (Op0<<14 | Op1<<11 | CRn<<7 | CRm<<3 | Op2).
// MPIDR_EL1: Op0=3, Op1=0, CRn=0, CRm=0, Op2=5
pub const HV_SYS_REG_MPIDR_EL1: hv_sys_reg_t = 0xC005;
// ID_AA64PFR0_EL1: Op0=3, Op1=0, CRn=0, CRm=4, Op2=0
#[allow(dead_code)]
pub const HV_SYS_REG_ID_AA64PFR0_EL1: hv_sys_reg_t = 0xC020;
// ID_AA64PFR1_EL1: Op0=3, Op1=0, CRn=0, CRm=4, Op2=1
pub const HV_SYS_REG_ID_AA64PFR1_EL1: hv_sys_reg_t = 0xC021;
// CNTV_CTL_EL0: Op0=3, Op1=3, CRn=14, CRm=3, Op2=1
pub const HV_SYS_REG_CNTV_CTL_EL0: hv_sys_reg_t = 0xDF19;
// CNTV_CVAL_EL0: Op0=3, Op1=3, CRn=14, CRm=3, Op2=2
pub const HV_SYS_REG_CNTV_CVAL_EL0: hv_sys_reg_t = 0xDF1A;
// CNTP_CTL_EL0: Op0=3, Op1=3, CRn=14, CRm=2, Op2=1 (macOS 15+)
pub const HV_SYS_REG_CNTP_CTL_EL0: hv_sys_reg_t = 0xDF11;
// CNTP_CVAL_EL0: Op0=3, Op1=3, CRn=14, CRm=2, Op2=2 (macOS 15+)
pub const HV_SYS_REG_CNTP_CVAL_EL0: hv_sys_reg_t = 0xDF12;

/// Interrupt types for `hv_vcpu_set_pending_interrupt`.
pub const HV_INTERRUPT_TYPE_IRQ: u32 = 0;
pub const HV_INTERRUPT_TYPE_FIQ: u32 = 1;

// =============================================================================
// Memory permission flags
// =============================================================================

pub type hv_memory_flags_t = u64;

pub const HV_MEMORY_READ: hv_memory_flags_t = 1 << 0;
pub const HV_MEMORY_WRITE: hv_memory_flags_t = 1 << 1;
pub const HV_MEMORY_EXEC: hv_memory_flags_t = 1 << 2;

// =============================================================================
// GIC types (macOS 15+ / Sequoia)
// =============================================================================

pub type hv_gic_intid_t = u32;

/// Opaque GIC configuration object (created by `hv_gic_config_create`).
pub type hv_gic_config_t = *mut c_void;

/// Guest Intermediate Physical Address.
pub type hv_ipa_t = u64;

/// Allocation flags for `hv_vm_allocate`.
pub type hv_allocate_flags_t = u64;

// =============================================================================
// FFI function declarations
// =============================================================================

#[cfg(target_os = "macos")]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    // -- VM lifecycle --

    /// Must be called before any other HVF function. Only one VM per process.
    pub fn hv_vm_create(config: *const c_void) -> hv_return_t;
    pub fn hv_vm_destroy() -> hv_return_t;
    /// Query the maximum number of vCPUs supported.
    pub fn hv_vm_get_max_vcpu_count(max_vcpu_count: *mut u32) -> hv_return_t;

    // -- Memory mapping --

    /// Map host memory into guest IPA space. `addr` must be page-aligned.
    pub fn hv_vm_map(
        addr: *const c_void,
        ipa: u64,
        size: usize,
        flags: hv_memory_flags_t,
    ) -> hv_return_t;
    pub fn hv_vm_unmap(ipa: u64, size: usize) -> hv_return_t;
    /// Change memory protection flags without unmapping.
    pub fn hv_vm_protect(ipa: u64, size: usize, flags: hv_memory_flags_t) -> hv_return_t;
    /// Allocate page-aligned memory suitable for guest mapping.
    pub fn hv_vm_allocate(
        uvap: *mut *mut c_void,
        size: usize,
        flags: hv_allocate_flags_t,
    ) -> hv_return_t;
    /// Deallocate memory previously allocated with `hv_vm_allocate`.
    pub fn hv_vm_deallocate(uvap: *mut c_void, size: usize) -> hv_return_t;

    // -- vCPU lifecycle (all calls must be on the creating thread) --

    pub fn hv_vcpu_create(
        vcpu: *mut hv_vcpu_t,
        exit: *mut hv_vcpu_exit_t,
        config: *const c_void,
    ) -> hv_return_t;
    pub fn hv_vcpu_destroy(vcpu: hv_vcpu_t) -> hv_return_t;
    pub fn hv_vcpu_run(vcpu: hv_vcpu_t) -> hv_return_t;

    // -- Register access (must be on vCPU's thread) --

    pub fn hv_vcpu_get_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_reg(vcpu: hv_vcpu_t, reg: hv_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: *mut u64) -> hv_return_t;
    pub fn hv_vcpu_set_sys_reg(vcpu: hv_vcpu_t, reg: hv_sys_reg_t, value: u64) -> hv_return_t;
    pub fn hv_vcpu_get_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: *mut u128,
    ) -> hv_return_t;
    pub fn hv_vcpu_set_simd_fp_reg(
        vcpu: hv_vcpu_t,
        reg: hv_simd_fp_reg_t,
        value: u128,
    ) -> hv_return_t;

    // -- vCPU control --

    /// Force vCPUs to exit with `HV_EXIT_REASON_CANCELED`. Thread-safe.
    pub fn hv_vcpus_exit(vcpus: *mut hv_vcpu_t, vcpu_count: u32) -> hv_return_t;

    /// Set the virtual timer mask. `false` = timer fires normally.
    pub fn hv_vcpu_set_vtimer_mask(vcpu: hv_vcpu_t, vtimer_is_masked: bool) -> hv_return_t;

    /// Get the vtimer offset. `CNTVCT_EL0` = `mach_absolute_time()` - offset.
    pub fn hv_vcpu_get_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: *mut u64) -> hv_return_t;
    /// Set the vtimer offset.
    pub fn hv_vcpu_set_vtimer_offset(vcpu: hv_vcpu_t, vtimer_offset: u64) -> hv_return_t;

    /// Inject a pending interrupt into the vCPU.
    pub fn hv_vcpu_set_pending_interrupt(
        vcpu: hv_vcpu_t,
        r#type: u32,
        pending: bool,
    ) -> hv_return_t;
    /// Read back pending interrupt state.
    pub fn hv_vcpu_get_pending_interrupt(
        vcpu: hv_vcpu_t,
        r#type: u32,
        pending: *mut bool,
    ) -> hv_return_t;
    /// Get the vtimer mask state.
    pub fn hv_vcpu_get_vtimer_mask(vcpu: hv_vcpu_t, vtimer_is_masked: *mut bool) -> hv_return_t;
    /// Get cumulative vCPU execution time in `mach_absolute_time` units.
    pub fn hv_vcpu_get_exec_time(vcpu: hv_vcpu_t, exec_time: *mut u64) -> hv_return_t;

    // -- vCPU debug trap control --

    /// Enable/disable trapping of debug exceptions to the VMM.
    pub fn hv_vcpu_set_trap_debug_exceptions(vcpu: hv_vcpu_t, enable: bool) -> hv_return_t;
    pub fn hv_vcpu_get_trap_debug_exceptions(vcpu: hv_vcpu_t, enabled: *mut bool) -> hv_return_t;
    /// Enable/disable trapping of debug register accesses to the VMM.
    pub fn hv_vcpu_set_trap_debug_reg_accesses(vcpu: hv_vcpu_t, enable: bool) -> hv_return_t;
    pub fn hv_vcpu_get_trap_debug_reg_accesses(vcpu: hv_vcpu_t, enabled: *mut bool) -> hv_return_t;

    // -- VM config --

    /// Create a VM configuration object.
    pub fn hv_vm_config_create() -> *mut c_void;
    /// Set the IPA (Intermediate Physical Address) size in bits.
    pub fn hv_vm_config_set_ipa_size(config: *mut c_void, ipa_size: u32) -> hv_return_t;
    /// Get the configured IPA size in bits.
    pub fn hv_vm_config_get_ipa_size(config: *mut c_void, ipa_size: *mut u32) -> hv_return_t;
    /// Get the maximum supported IPA size in bits.
    pub fn hv_vm_config_get_max_ipa_size(
        config: *mut c_void,
        max_ipa_size: *mut u32,
    ) -> hv_return_t;
    /// Get the default IPA size in bits.
    pub fn hv_vm_config_get_default_ipa_size(
        config: *mut c_void,
        ipa_size: *mut u32,
    ) -> hv_return_t;
    /// Enable EL2 (nested virtualization).
    pub fn hv_vm_config_set_el2_enabled(config: *mut c_void, el2_enabled: bool) -> hv_return_t;
    /// Query whether EL2 is enabled.
    pub fn hv_vm_config_get_el2_enabled(config: *mut c_void, el2_enabled: *mut bool)
    -> hv_return_t;
    /// Query whether EL2 is supported on this hardware.
    pub fn hv_vm_config_get_el2_supported(
        config: *mut c_void,
        el2_supported: *mut bool,
    ) -> hv_return_t;

    // -- vCPU config --

    /// Read a CPU feature/ID register value from the vCPU config.
    pub fn hv_vcpu_config_get_feature_reg(
        config: *const c_void,
        reg: hv_sys_reg_t,
        value: *mut u64,
    ) -> hv_return_t;
    /// Get `CCSIDR_EL1` values for all cache levels.
    pub fn hv_vcpu_config_get_ccsidr_el1_sys_reg_values(
        config: *const c_void,
        values: *mut u64,
        count: *mut usize,
    ) -> hv_return_t;

    // -- GIC (macOS 15+) --

    /// Create a GIC configuration object.
    pub fn hv_gic_config_create() -> hv_gic_config_t;
    /// Set the GIC distributor base address.
    pub fn hv_gic_config_set_distributor_base(
        config: hv_gic_config_t,
        distributor_base_address: hv_ipa_t,
    ) -> hv_return_t;
    /// Set the GIC redistributor base address.
    pub fn hv_gic_config_set_redistributor_base(
        config: hv_gic_config_t,
        redistributor_base_address: hv_ipa_t,
    ) -> hv_return_t;
    /// Set the MSI region base address.
    pub fn hv_gic_config_set_msi_region_base(
        config: hv_gic_config_t,
        msi_region_base: hv_ipa_t,
    ) -> hv_return_t;
    /// Set the MSI interrupt range.
    pub fn hv_gic_config_set_msi_interrupt_range(
        config: hv_gic_config_t,
        intid_base: hv_gic_intid_t,
        intid_count: u32,
    ) -> hv_return_t;
    /// Create the GIC. Must be called after `hv_vm_create`, before vCPU use.
    pub fn hv_gic_create(gic_config: hv_gic_config_t) -> hv_return_t;
    /// Assert/deassert a Shared Peripheral Interrupt.
    pub fn hv_gic_set_spi(intid: hv_gic_intid_t, level: bool) -> hv_return_t;
    /// Send an MSI to the GIC. `address` is the IPA of the GIC MSI frame register.
    pub fn hv_gic_send_msi(address: hv_ipa_t, intid: u32) -> hv_return_t;
    /// Reset the GIC to its initial state.
    pub fn hv_gic_reset() -> hv_return_t;

    // -- GIC parameter queries --

    /// Get the required distributor base alignment.
    pub fn hv_gic_get_distributor_base_alignment(alignment: *mut usize) -> hv_return_t;
    /// Get the distributor MMIO region size.
    pub fn hv_gic_get_distributor_size(size: *mut usize) -> hv_return_t;
    /// Get the required redistributor base alignment.
    pub fn hv_gic_get_redistributor_base_alignment(alignment: *mut usize) -> hv_return_t;
    /// Get the per-vCPU redistributor size.
    pub fn hv_gic_get_redistributor_size(size: *mut usize) -> hv_return_t;
    /// Get the total redistributor region size (all vCPUs).
    pub fn hv_gic_get_redistributor_region_size(size: *mut usize) -> hv_return_t;
    /// Get the redistributor base address.
    pub fn hv_gic_get_redistributor_base(base: *mut hv_ipa_t) -> hv_return_t;
    /// Get the SPI interrupt range.
    pub fn hv_gic_get_spi_interrupt_range(
        intid_base: *mut hv_gic_intid_t,
        intid_count: *mut u32,
    ) -> hv_return_t;
    /// Get the MSI region base alignment.
    pub fn hv_gic_get_msi_region_base_alignment(alignment: *mut usize) -> hv_return_t;
    /// Get the MSI region size.
    pub fn hv_gic_get_msi_region_size(size: *mut usize) -> hv_return_t;
    /// Get an interrupt ID from the GIC.
    pub fn hv_gic_get_intid(intid_type: u32, intid: *mut hv_gic_intid_t) -> hv_return_t;

    // -- GIC distributor/redistributor register access --

    pub fn hv_gic_get_distributor_reg(reg: u64, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_distributor_reg(reg: u64, value: u64) -> hv_return_t;
    pub fn hv_gic_get_redistributor_reg(vcpu: hv_vcpu_t, reg: u64, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_redistributor_reg(vcpu: hv_vcpu_t, reg: u64, value: u64) -> hv_return_t;
    pub fn hv_gic_get_msi_reg(reg: u64, value: *mut u64) -> hv_return_t;

    // -- GIC state save/restore (macOS 15+) --

    /// Create a GIC state snapshot. Returns an OS object (release with `os_release`).
    /// VM must be stopped.
    pub fn hv_gic_state_create() -> *mut c_void;
    /// Get the serialized size of GIC state.
    pub fn hv_gic_state_get_size(state: *mut c_void, size: *mut usize) -> hv_return_t;
    /// Serialize GIC state into a buffer. Buffer must be >= size from `get_size`.
    pub fn hv_gic_state_get_data(state: *mut c_void, data: *mut c_void) -> hv_return_t;
    /// Restore GIC state from a serialized buffer.
    pub fn hv_gic_set_state(data: *const c_void, size: usize) -> hv_return_t;

    // -- GIC ICC (CPU interface) registers --

    /// Read a GIC ICC system register for a vCPU.
    pub fn hv_gic_get_icc_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    /// Write a GIC ICC system register for a vCPU.
    pub fn hv_gic_set_icc_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;

    // -- GIC ICH (hypervisor) registers --

    pub fn hv_gic_get_ich_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_ich_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;

    // -- GIC ICV (virtual CPU interface) registers --

    pub fn hv_gic_get_icv_reg(vcpu: hv_vcpu_t, reg: u16, value: *mut u64) -> hv_return_t;
    pub fn hv_gic_set_icv_reg(vcpu: hv_vcpu_t, reg: u16, value: u64) -> hv_return_t;

    // -- vCPU config --

    /// Create a vCPU configuration object.
    pub fn hv_vcpu_config_create() -> *mut c_void;
}

// OS object release (from libSystem).
#[cfg(target_os = "macos")]
unsafe extern "C" {
    /// Release an OS object (GIC state, config objects, etc.).
    pub fn os_release(object: *mut c_void);
}

// =============================================================================
// Private API declarations (used by Apple's Virtualization.framework)
// =============================================================================

#[cfg(target_os = "macos")]
#[link(name = "Hypervisor", kind = "framework")]
unsafe extern "C" {
    /// Enable TLBI (TLB Invalidate) hardware errata workaround.
    ///
    /// Apple's Virtualization.framework calls this unconditionally before
    /// every `hv_vcpu_create`. Must be called on the vCPU config before
    /// creation. Returns `HV_UNSUPPORTED` on hardware without the errata.
    #[link_name = "_hv_vcpu_config_set_tlbi_workaround_enabled"]
    pub fn hv_vcpu_config_set_tlbi_workaround(config: *mut c_void) -> hv_return_t;

    /// Get a direct pointer to the kernel-mapped vCPU register context.
    ///
    /// Returns a pointer whose layout is undocumented. Virtualization.framework
    /// uses this at 224 call sites for ~50x faster bulk register reads vs
    /// individual `hv_vcpu_get_reg` calls.
    #[link_name = "_hv_vcpu_get_context"]
    pub fn hv_vcpu_get_context(vcpu: hv_vcpu_t) -> *mut c_void;
}

// =============================================================================
// Helper: check return code
// =============================================================================

/// Typed HVF error code.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum HvfErrorCode {
    /// Generic HVF failure.
    Error,
    /// HVF object is busy.
    Busy,
    /// Invalid argument passed to HVF.
    BadArgument,
    /// Guest state cannot be executed by HVF.
    IllegalGuestState,
    /// Host has no HVF resources available for the requested operation.
    NoResources,
    /// Requested HVF device is absent.
    NoDevice,
    /// HVF denied the operation, often because the process lacks entitlement.
    Denied,
    /// HVF object already exists.
    Exists,
    /// Requested HVF feature is unsupported.
    Unsupported,
    /// Unknown HVF return code.
    Unknown(hv_return_t),
}

impl HvfErrorCode {
    const fn from_return(ret: hv_return_t) -> Self {
        match ret {
            HV_ERROR => Self::Error,
            HV_BUSY => Self::Busy,
            HV_BAD_ARGUMENT => Self::BadArgument,
            HV_ILLEGAL_GUEST_STATE => Self::IllegalGuestState,
            HV_NO_RESOURCES => Self::NoResources,
            HV_NO_DEVICE => Self::NoDevice,
            HV_DENIED => Self::Denied,
            HV_EXISTS => Self::Exists,
            HV_UNSUPPORTED => Self::Unsupported,
            other => Self::Unknown(other),
        }
    }

    const fn detail(self) -> &'static str {
        match self {
            Self::Error => "HV_ERROR",
            Self::Busy => "HV_BUSY",
            Self::BadArgument => "HV_BAD_ARGUMENT",
            Self::IllegalGuestState => "HV_ILLEGAL_GUEST_STATE",
            Self::NoResources => "HV_NO_RESOURCES",
            Self::NoDevice => "HV_NO_DEVICE",
            Self::Denied => "HV_DENIED (missing entitlement?)",
            Self::Exists => "HV_EXISTS",
            Self::Unsupported => "HV_UNSUPPORTED",
            Self::Unknown(_) => "unknown",
        }
    }
}

/// Error returned by an HVF call.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HvfError {
    operation: String,
    code: HvfErrorCode,
    raw: hv_return_t,
}

impl HvfError {
    fn new(operation: &str, ret: hv_return_t) -> Self {
        Self {
            operation: operation.to_owned(),
            code: HvfErrorCode::from_return(ret),
            raw: ret,
        }
    }

    /// Operation that returned the HVF error.
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Typed HVF error code.
    pub const fn code(&self) -> HvfErrorCode {
        self.code
    }

    /// Raw `hv_return_t` value.
    pub const fn raw_code(&self) -> hv_return_t {
        self.raw
    }

    /// Whether this is `HV_NO_RESOURCES`.
    pub const fn is_no_resources(&self) -> bool {
        matches!(self.code, HvfErrorCode::NoResources)
    }
}

impl std::fmt::Display for HvfError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: {} ({:#010x})",
            self.operation,
            self.code.detail(),
            self.raw
        )
    }
}

impl std::error::Error for HvfError {}

/// Convert an HVF return code into a `Result`.
pub fn check(operation: &str, ret: hv_return_t) -> Result<(), HvfError> {
    if ret == HV_SUCCESS {
        return Ok(());
    }
    Err(HvfError::new(operation, ret))
}

/// Read a GP register. Surfaces the underlying HVF error on failure so
/// callers never silently consume a fabricated zero as register data.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
#[cfg(target_os = "macos")]
pub unsafe fn read_reg(vcpu: hv_vcpu_t, reg: hv_reg_t) -> Result<u64, HvfError> {
    let mut val: u64 = 0;
    // SAFETY: per the fn's `# Safety` contract, `vcpu` is a valid handle on
    // the calling thread; `reg` is a valid hv_reg_t identifier.
    unsafe {
        check("hv_vcpu_get_reg", hv_vcpu_get_reg(vcpu, reg, &raw mut val))?;
    }
    Ok(val)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_success() {
        assert!(check("test", HV_SUCCESS).is_ok());
    }

    #[test]
    fn check_error() {
        let err = check("hv_vm_create", HV_ERROR).unwrap_err();
        assert!(err.to_string().contains("HV_ERROR"));
        assert!(err.to_string().contains("hv_vm_create"));
        assert_eq!(err.code(), HvfErrorCode::Error);
    }

    #[test]
    fn check_denied() {
        let err = check("hv_vm_create", HV_DENIED).unwrap_err();
        assert!(err.to_string().contains("HV_DENIED"));
        assert!(err.to_string().contains("entitlement"));
        assert_eq!(err.code(), HvfErrorCode::Denied);
    }

    #[test]
    fn check_no_resources_is_typed() {
        let err = check("hv_vcpu_create", HV_NO_RESOURCES).unwrap_err();
        assert_eq!(err.operation(), "hv_vcpu_create");
        assert_eq!(err.code(), HvfErrorCode::NoResources);
        assert!(err.is_no_resources());
    }

    #[test]
    fn check_unknown_code() {
        let err = check("op", 0x1234_5678).unwrap_err();
        assert!(err.to_string().contains("unknown"));
        assert!(err.to_string().contains("0x12345678"));
    }

    #[test]
    fn reg_constants_match_arm64reg() {
        use amla_core::arm64::Arm64Reg;
        assert_eq!(HV_REG_X0, Arm64Reg::X0 as u32);
        assert_eq!(HV_REG_X30, Arm64Reg::X30 as u32);
        assert_eq!(HV_REG_PC, Arm64Reg::PC as u32);
        assert_eq!(HV_REG_FPCR, Arm64Reg::FPCR as u32);
        assert_eq!(HV_REG_FPSR, Arm64Reg::FPSR as u32);
        assert_eq!(HV_REG_CPSR, Arm64Reg::CPSR as u32);
    }

    #[test]
    fn vcpu_exit_info_layout() {
        assert_eq!(std::mem::size_of::<VcpuExitInfo>(), 32);
    }
}
