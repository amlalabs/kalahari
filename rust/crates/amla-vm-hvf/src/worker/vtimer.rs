// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Virtual timer (vtimer) handling for HVF.
//!
//! Provides vtimer unmask and WFI timeout computation using the ARM virtual
//! timer state and `mach_absolute_time` timebase.

use crate::ffi;

#[repr(C)]
#[derive(Copy, Clone)]
struct MachTimebaseInfo {
    numer: u32,
    denom: u32,
}

unsafe extern "C" {
    fn mach_absolute_time() -> u64;
    fn mach_timebase_info(info: *mut MachTimebaseInfo) -> i32;
}

/// Unmask the virtual timer after `VTIMER_ACTIVATED` exit.
///
/// After `hv_vcpu_run` returns with `HV_EXIT_REASON_VTIMER_ACTIVATED`, the
/// framework automatically masks the vtimer. This function clears that mask
/// so the timer can fire again on the next deadline.
///
/// Must be called on the vCPU's owning thread.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
#[allow(dead_code)]
pub(crate) unsafe fn unmask_vtimer(vcpu: ffi::hv_vcpu_t) {
    // SAFETY: vcpu is valid on this thread per caller contract.
    unsafe {
        if let Err(e) = ffi::check("vtimer_unmask", ffi::hv_vcpu_set_vtimer_mask(vcpu, false)) {
            log::error!("hv_vcpu_set_vtimer_mask(false) failed: {e}");
        }
    }
}

/// Compute the sleep duration for a WFI exit based on vtimer state.
///
/// Returns `None` if no timer is pending (caller should use a fallback timeout).
/// Returns `Some(Duration::ZERO)` if the timer has already expired.
///
/// Must be called on the vCPU's owning thread.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
pub(crate) unsafe fn compute_wfi_timeout(vcpu: ffi::hv_vcpu_t) -> Option<std::time::Duration> {
    // Read CNTV_CTL_EL0: bit 0 = enabled, bit 1 = masked.
    let mut ctl: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        if let Err(e) = ffi::check(
            "get_cntv_ctl",
            ffi::hv_vcpu_get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CTL_EL0, &raw mut ctl),
        ) {
            log::error!("hv_vcpu_get_sys_reg(CNTV_CTL_EL0) failed: {e}");
            return None;
        }
    }

    let enabled = (ctl & 1) != 0;
    let masked = (ctl & 2) != 0;

    // If the timer is not enabled or is masked, no deadline is pending.
    if !enabled || masked {
        log::debug!("vtimer: no pending deadline enabled={enabled} masked={masked} ctl={ctl:#x}");
        return None;
    }

    // Read CNTV_CVAL_EL0: the compare value (absolute counter).
    let mut cval: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        if let Err(e) = ffi::check(
            "get_cntv_cval",
            ffi::hv_vcpu_get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CVAL_EL0, &raw mut cval),
        ) {
            log::error!("hv_vcpu_get_sys_reg(CNTV_CVAL_EL0) failed: {e}");
            return None;
        }
    }

    // Read the vtimer offset: CNTVCT_EL0 = mach_absolute_time() - offset.
    let mut offset: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        if let Err(e) = ffi::check(
            "get_vtimer_offset",
            ffi::hv_vcpu_get_vtimer_offset(vcpu, &raw mut offset),
        ) {
            log::error!("hv_vcpu_get_vtimer_offset failed: {e}");
            return None;
        }
    }

    // Compute the current virtual count.
    // SAFETY: mach_absolute_time is always safe to call.
    let now = unsafe { mach_absolute_time() };
    let vcount = now.wrapping_sub(offset);

    // If cval <= vcount, the timer has already expired.
    if cval <= vcount {
        log::debug!(
            "vtimer: expired deadline ctl={ctl:#x} cval={cval:#x} vcount={vcount:#x} offset={offset:#x}"
        );
        return Some(std::time::Duration::ZERO);
    }

    // Compute remaining ticks and convert to nanoseconds.
    let delta_ticks = cval - vcount;
    let info = timebase_info();
    let delta_ns = u128::from(delta_ticks) * u128::from(info.numer) / u128::from(info.denom);

    // Clamp to u64::MAX to avoid truncation that could wrap a very large
    // delta (e.g. CNTV_CVAL = u64::MAX during UEFI init) to a near-zero
    // timeout, causing WFI busy-spin at 100% CPU.
    let clamped = delta_ns.min(u128::from(u64::MAX));

    #[allow(clippy::cast_possible_truncation)]
    let duration = std::time::Duration::from_nanos(clamped as u64);
    log::debug!(
        "vtimer: pending deadline ctl={ctl:#x} cval={cval:#x} vcount={vcount:#x} offset={offset:#x} sleep={duration:?}"
    );
    Some(duration)
}

/// Return whether the guest virtual timer output is currently asserted.
///
/// This is the guest-visible timer condition:
/// `CNTV_CTL_EL0.ENABLE && !CNTV_CTL_EL0.IMASK && CNTV_CVAL_EL0 <= CNTVCT_EL0`.
///
/// Unlike `hv_vcpu_get_vtimer_mask`, this ignores HVF's host-side masking so
/// the worker can hold the PPI asserted in the userspace GIC while keeping HVF
/// masked until the guest deasserts the timer.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
pub(crate) unsafe fn is_vtimer_asserted(vcpu: ffi::hv_vcpu_t) -> crate::error::Result<bool> {
    // Read CNTV_CTL_EL0: bit 0 = enabled, bit 1 = masked.
    let mut ctl: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        ffi::check(
            "get_cntv_ctl",
            ffi::hv_vcpu_get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CTL_EL0, &raw mut ctl),
        )
        .map_err(crate::error::VmmError::from)?;
    }

    let enabled = (ctl & 1) != 0;
    let guest_masked = (ctl & 2) != 0;
    if !enabled || guest_masked {
        return Ok(false);
    }

    // Read CNTV_CVAL_EL0.
    let mut cval: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        ffi::check(
            "get_cntv_cval",
            ffi::hv_vcpu_get_sys_reg(vcpu, ffi::HV_SYS_REG_CNTV_CVAL_EL0, &raw mut cval),
        )
        .map_err(crate::error::VmmError::from)?;
    }

    // Read CNTVOFF_EL2 via HVF's vtimer offset API.
    let mut offset: u64 = 0;
    // SAFETY: vcpu is valid on this thread.
    unsafe {
        ffi::check(
            "get_vtimer_offset",
            ffi::hv_vcpu_get_vtimer_offset(vcpu, &raw mut offset),
        )
        .map_err(crate::error::VmmError::from)?;
    }

    // SAFETY: mach_absolute_time is always safe to call.
    let now = unsafe { mach_absolute_time() };
    let vcount = now.wrapping_sub(offset);
    Ok(cval <= vcount)
}

/// Synchronize the userspace GIC's vtimer PPI level with the guest timer state.
///
/// If the timer is no longer asserted, also unmask HVF's host-side timer so the
/// next deadline can raise another `VTIMER_ACTIVATED` exit.
///
/// # Safety
///
/// `vcpu` must be a valid handle on the calling thread.
pub(crate) unsafe fn sync_vtimer_irq(
    vcpu: ffi::hv_vcpu_t,
    gic: &amla_vm_gic::GicV3,
    vcpu_id: usize,
    intid: u32,
) -> crate::error::Result<()> {
    // SAFETY: vcpu is valid on this thread per caller contract.
    let asserted = unsafe { is_vtimer_asserted(vcpu) }?;
    gic.set_private_irq_level(vcpu_id, intid, asserted);
    if !asserted {
        // SAFETY: vcpu is valid on this thread per caller contract.
        unsafe {
            ffi::check("vtimer_unmask", ffi::hv_vcpu_set_vtimer_mask(vcpu, false))
                .map_err(crate::error::VmmError::from)?;
        }
    }
    Ok(())
}

/// Get `mach_absolute_time` timebase info (cached).
///
/// The timebase info is constant for the lifetime of the process, so we
/// compute it once and cache it in a `OnceLock`.
fn timebase_info() -> MachTimebaseInfo {
    use std::sync::OnceLock;
    static INFO: OnceLock<MachTimebaseInfo> = OnceLock::new();
    *INFO.get_or_init(|| {
        let mut info = MachTimebaseInfo { numer: 0, denom: 0 };
        // SAFETY: mach_timebase_info fills the provided struct and always succeeds.
        unsafe { mach_timebase_info(&raw mut info) };
        info
    })
}
