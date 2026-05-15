// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Guest memory mapping for HVF.
//!
//! Enforces Apple Silicon's 16 KiB page alignment requirement for all
//! memory mapping operations.

use crate::error::{Result, VmmError};
use crate::ffi;

/// Apple Silicon page size (16 KiB).
const HVF_PAGE_SIZE: usize = 16384;

/// Map a host memory region into guest IPA space.
///
/// All parameters must be 16 KiB aligned. The host memory region must remain
/// valid for the lifetime of the mapping.
///
/// # Safety
///
/// - `addr` must point to valid, page-aligned memory of at least `size` bytes.
/// - The memory must remain mapped in the host process until `hv_vm_destroy`
///   returns, which tears down every IPA mapping for this process.
/// - `hv_vm_create` must have been called before this function.
pub(crate) unsafe fn map_guest_memory(
    addr: *const u8,
    ipa: u64,
    size: usize,
    readonly: bool,
) -> Result<()> {
    // Verify alignment.
    if !(addr as usize).is_multiple_of(HVF_PAGE_SIZE) {
        return Err(VmmError::Alignment {
            msg: format!("host address {addr:?} is not 16 KiB aligned"),
        });
    }
    #[allow(clippy::cast_possible_truncation)]
    if !(ipa as usize).is_multiple_of(HVF_PAGE_SIZE) {
        return Err(VmmError::Alignment {
            msg: format!("guest IPA {ipa:#x} is not 16 KiB aligned"),
        });
    }
    if !size.is_multiple_of(HVF_PAGE_SIZE) {
        return Err(VmmError::Alignment {
            msg: format!("size {size:#x} is not a multiple of 16 KiB"),
        });
    }

    // EXEC is granted at stage-2 for every mapping. The guest's own stage-1
    // page tables enforce W^X, kernel vs. user, and which pages are actually
    // executable — stage-2 EXEC only controls whether the hypervisor will
    // trap on instruction fetch. Stripping EXEC from data-only regions (DTB,
    // ramdisk) would buy no real defense because the guest allocator can
    // later repurpose RAM pages for kernel text, which would then require
    // `hv_vm_protect` round-trips. Revisit if we add dirty-page tracking or
    // a hardened policy that wants the hypervisor to veto code fetch from
    // known-data regions.
    let flags = if readonly {
        ffi::HV_MEMORY_READ | ffi::HV_MEMORY_EXEC
    } else {
        ffi::HV_MEMORY_READ | ffi::HV_MEMORY_WRITE | ffi::HV_MEMORY_EXEC
    };

    // SAFETY: All alignment requirements are verified above. The caller
    // guarantees addr points to valid memory and hv_vm_create was called.
    unsafe {
        ffi::check("hv_vm_map", ffi::hv_vm_map(addr.cast(), ipa, size, flags))
            .map_err(VmmError::from)
    }
}
