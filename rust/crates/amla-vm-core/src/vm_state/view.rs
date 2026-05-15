// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::cast_possible_truncation)]

//! Self-describing view over mapped VM state.
//!
//! `VmState<'a>` wraps two kinds of memory:
//!
//! - **`metadata`**: a single `&MmapSlice` covering the memfd prefix (header,
//!   vCPU slots, irqchip, device slots, device metadata, ring buffer, pmem
//!   headers, and RAM descriptors). This region is NOT mapped into the guest.
//!
//! - **`guest_memory`**: validated guest-visible memory regions sorted by GPA.
//!   GPA lookups use binary search.
//!
//! Host-owned sections are accessed via `&[u8]`/`&mut [u8]` from `metadata`.
//! Guest RAM is accessed via the [`GuestMemory`] trait with volatile semantics.

use bytemuck::Pod;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

use super::device_meta::DeviceMetaSlot;
use super::header::{
    DEVICE_KIND_CONSOLE, DEVICE_KIND_FS, DEVICE_KIND_NET, DEVICE_KIND_RNG, DEVICE_KIND_UNUSED,
    DEVICE_META_SLOT_SIZE, DEVICE_SLOT_SIZE, DeviceKindCode, MAX_DEVICES, PSCI_POWER_OFF,
    PSCI_POWER_ON, PsciPowerState, PsciPowerStateBusy, VmStateHeader, is_valid_psci_power_state,
};
use super::irqchip::IrqchipSectionState;
use super::layout::VCPU_SLOT_SIZE;
use super::ram_descriptor::{BITMAP_BLOCK_SIZE, RamDescriptorView, RamSize};

use crate::VmmError;

// ============================================================================
// BorrowTracker (debug-only)
// ============================================================================

/// Debug-only tracker for overlapping mutable borrows in `VmState`.
///
/// Tracks byte ranges `[start..end)` of outstanding mutable borrows.
/// Panics if a new borrow overlaps any existing borrow.
///
/// Uses `parking_lot::Mutex` (not `RefCell`) because `VmState` is Sync —
/// it is accessed from multiple vCPU threads + device loop concurrently.
#[cfg(debug_assertions)]
struct BorrowTracker {
    spans: parking_lot::Mutex<Vec<(usize, usize)>>,
}

#[cfg(debug_assertions)]
#[allow(clippy::expect_used)] // debug-only safety checker — panicking is the point
impl BorrowTracker {
    const fn new() -> Self {
        Self {
            spans: parking_lot::Mutex::new(Vec::new()),
        }
    }

    fn acquire(&self, start: usize, len: usize) {
        let end = start
            .checked_add(len)
            .expect("BorrowTracker: start + len overflow");
        let mut spans = self.spans.lock();
        for &(s, e) in spans.iter() {
            assert!(
                end <= s || start >= e,
                "VmState: overlapping mutable borrow [{start:#x}..{end:#x}) \
                 conflicts with existing [{s:#x}..{e:#x})"
            );
        }
        spans.push((start, end));
    }

    fn release(&self, start: usize, len: usize) {
        let end = start
            .checked_add(len)
            .expect("BorrowTracker: start + len overflow");
        let found = {
            let mut spans = self.spans.lock();
            spans
                .iter()
                .position(|&(s, e)| s == start && e == end)
                .is_some_and(|pos| {
                    spans.swap_remove(pos);
                    true
                })
        };
        assert!(
            found,
            "BorrowTracker: release [{start:#x}..{end:#x}) not found — \
             double-drop or missing acquire"
        );
    }
}

// ============================================================================
// DeviceSlotLocks
// ============================================================================

/// Per-device-slot exclusivity state for interior mutable device access.
struct DeviceSlotLocks {
    slots: [parking_lot::Mutex<()>; MAX_DEVICES],
}

impl DeviceSlotLocks {
    fn new() -> Self {
        Self {
            slots: core::array::from_fn(|_| parking_lot::Mutex::new(())),
        }
    }

    fn lock(&self, index: usize) -> parking_lot::MutexGuard<'_, ()> {
        self.slots[index].lock()
    }

    fn try_lock(&self, index: usize) -> Option<parking_lot::MutexGuard<'_, ()>> {
        self.slots[index].try_lock()
    }
}

// ============================================================================
// RefGuard — RAII mutable borrow guard
// ============================================================================

/// Typed guard for a mutable borrow from `VmState`.
///
/// Stores a raw `*mut T` — never creates `&mut T` through a shared `&self`
/// on `VmState`. Instead, `&mut T` is only produced transiently in
/// `DerefMut::deref_mut(&mut self)`, which requires exclusive access to the
/// guard itself. This avoids UB under Rust's aliasing model.
///
/// The per-device-slot lock guard enforces runtime exclusivity in every build.
/// In debug mode, the `BorrowTracker` also checks byte ranges as an extra
/// assertion.
pub struct RefGuard<'a, T> {
    ptr: *mut T,
    _slot_lock: parking_lot::MutexGuard<'a, ()>,
    _lifetime: core::marker::PhantomData<&'a mut T>,
    #[cfg(debug_assertions)]
    offset: usize,
    #[cfg(debug_assertions)]
    len: usize,
    #[cfg(debug_assertions)]
    tracker: &'a BorrowTracker,
}

impl<T> core::ops::Deref for RefGuard<'_, T> {
    type Target = T;
    #[inline]
    fn deref(&self) -> &T {
        // SAFETY: ptr is valid, aligned, and points to initialized Pod data
        // in mmap'd memory. The slot lease ensures no overlapping mutable
        // guard exists, with BorrowTracker as an extra debug assertion.
        unsafe { &*self.ptr }
    }
}

impl<T> core::ops::DerefMut for RefGuard<'_, T> {
    #[inline]
    fn deref_mut(&mut self) -> &mut T {
        // SAFETY: &mut self guarantees we are the only active accessor of
        // this guard. The underlying memory is exclusively ours (per-device
        // Mutex + debug BorrowTracker). Creating &mut T here is sound
        // because no other &mut T to this memory can exist simultaneously.
        unsafe { &mut *self.ptr }
    }
}

#[cfg(debug_assertions)]
impl<T> Drop for RefGuard<'_, T> {
    fn drop(&mut self) {
        self.tracker.release(self.offset, self.len);
    }
}

// ============================================================================
// DeviceState / DeviceSlot — typed device-state slot capabilities
// ============================================================================

/// Persisted device-state type.
///
/// # Safety
///
/// Implementors must be the exact POD layout stored in a VM-state device slot
/// for [`Self::DEVICE_KIND`]. The kind code is checked against the durable
/// VM-state header before bytes are reinterpreted as `Self`.
pub unsafe trait DeviceState: Pod {
    /// Durable device-kind code for this state layout.
    const DEVICE_KIND: u8;
}

/// Typed capability for mutating one device-state slot as `T`.
///
/// `VmState` owns device state as a homogeneous byte-slot array. The slot index
/// alone cannot prove which concrete virtio state type lives in that slot, so a
/// [`DeviceState`] kind check is performed before the slot bytes are borrowed.
pub struct DeviceSlot<T> {
    index: usize,
    _state: PhantomData<fn() -> T>,
}

impl<T> Copy for DeviceSlot<T> {}

impl<T> Clone for DeviceSlot<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> core::fmt::Debug for DeviceSlot<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("DeviceSlot").field(&self.index).finish()
    }
}

impl<T> PartialEq for DeviceSlot<T> {
    fn eq(&self, other: &Self) -> bool {
        self.index == other.index
    }
}

impl<T> Eq for DeviceSlot<T> {}

impl<T> core::hash::Hash for DeviceSlot<T> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.index.hash(state);
    }
}

impl<T> DeviceSlot<T> {
    /// Mint a typed device slot from an externally validated layout index.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that `index` refers to a live device slot and
    /// that the slot's persisted bytes are owned exclusively as a `T` device
    /// state for the duration of every use of this token.
    pub unsafe fn new_unchecked(index: usize) -> Self {
        Self {
            index,
            _state: PhantomData,
        }
    }

    /// Return the raw slot index represented by this typed token.
    #[must_use]
    pub const fn index(self) -> usize {
        self.index
    }
}

// ============================================================================
// PSCI vCPU Power State
// ============================================================================

/// Atomic view over the persisted PSCI per-vCPU power-state table.
///
/// The bytes live in a dedicated host-owned VM-state section, not in
/// [`VmStateHeader`]. During VM execution, the PSCI `CPU_ON` bus updates them
/// atomically so the mmap remains the single source of truth across
/// freeze/spawn without mixing atomic mutation with normal header reads.
#[derive(Clone, Copy)]
pub struct PsciPowerStateTable<'a> {
    ptr: NonNull<u8>,
    len: usize,
    _lifetime: PhantomData<&'a [u8]>,
}

// SAFETY: the table points at mmap-backed bytes that outlive `'a`. All shared
// mutation goes through byte-sized atomics, and setup/teardown mutable access is
// kept outside the vCPU run loop by callers.
unsafe impl Send for PsciPowerStateTable<'_> {}
// SAFETY: see the `Send` impl; concurrent access uses `AtomicU8`.
unsafe impl Sync for PsciPowerStateTable<'_> {}

impl PsciPowerStateTable<'_> {
    fn new(ptr: *mut u8, len: usize) -> Self {
        assert!(
            !ptr.is_null(),
            "PSCI power-state table pointer must not be null"
        );
        // SAFETY: asserted non-null above.
        let ptr = unsafe { NonNull::new_unchecked(ptr) };
        Self {
            ptr,
            len,
            _lifetime: PhantomData,
        }
    }

    /// Number of vCPU power-state entries in the table.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Return whether the table contains no vCPU power-state entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn atomic(&self, index: usize) -> Option<&AtomicU8> {
        if index >= self.len {
            return None;
        }
        // SAFETY: bounds are checked above. `AtomicU8` has alignment 1, the
        // same as `u8`, and the bytes remain mapped for `'a`.
        Some(unsafe { &*self.ptr.as_ptr().add(index).cast::<AtomicU8>() })
    }

    /// Atomically load a vCPU power state.
    pub fn load(&self, index: usize, ordering: Ordering) -> Option<PsciPowerState> {
        self.atomic(index)
            .and_then(|state| PsciPowerState::from_u8(state.load(ordering)))
    }

    /// Atomically store a vCPU power state.
    ///
    /// Returns `false` if `index` is out of range.
    pub fn store(&self, index: usize, state: PsciPowerState, ordering: Ordering) -> bool {
        let Some(slot) = self.atomic(index) else {
            return false;
        };
        slot.store(state.as_u8(), ordering);
        true
    }

    /// Atomically compare and exchange a vCPU power state.
    ///
    /// Returns `None` if `index` is out of range or the current persisted byte
    /// is not a valid PSCI power state.
    pub fn compare_exchange(
        &self,
        index: usize,
        current: PsciPowerState,
        new: PsciPowerState,
        success: Ordering,
        failure: Ordering,
    ) -> Option<Result<PsciPowerState, PsciPowerState>> {
        let state = self.atomic(index)?;
        let result = state.compare_exchange(current.as_u8(), new.as_u8(), success, failure);
        Some(match result {
            Ok(previous) => Ok(PsciPowerState::from_u8(previous)?),
            Err(actual) => Err(PsciPowerState::from_u8(actual)?),
        })
    }

    /// Atomically transition an `Off` vCPU to `OnPending`.
    ///
    /// Returns `Ok(())` when the caller claimed the off vCPU. Returns a typed
    /// busy state when the vCPU was already running or already had a pending
    /// `CPU_ON`; `Off` is not representable in the error path.
    pub fn claim_off_for_cpu_on(
        &self,
        index: usize,
        success: Ordering,
        failure: Ordering,
    ) -> Option<Result<(), PsciPowerStateBusy>> {
        let state = self.atomic(index)?;
        loop {
            let actual = PsciPowerState::from_u8(state.load(failure))?;
            match actual {
                PsciPowerState::On => return Some(Err(PsciPowerStateBusy::On)),
                PsciPowerState::OnPending => return Some(Err(PsciPowerStateBusy::OnPending)),
                PsciPowerState::Off => {
                    if state
                        .compare_exchange(
                            PsciPowerState::Off.as_u8(),
                            PsciPowerState::OnPending.as_u8(),
                            success,
                            failure,
                        )
                        .is_ok()
                    {
                        return Some(Ok(()));
                    }
                }
            }
        }
    }
}

// ============================================================================
// VmState
// ============================================================================

/// Self-describing, lifetime-tied view over mapped VM state.
///
/// `metadata` is a single `&MmapSlice` covering the memfd prefix: header,
/// vCPU slots, irqchip, device slots, device metadata, ring buffer, pmem
/// headers, and RAM descriptors. This region is NOT mapped into the guest.
///
/// `guest_memory` contains validated guest-visible memory regions sorted by
/// GPA. Binary search maps GPAs to host pointers.
///
/// # Mutability Model
///
/// Section mutators (`header_mut`, `irqchip_mut`, `vcpu_slot_mut`, etc.)
/// require `&mut self`. They are only used during sequential setup/teardown
/// when no vCPUs are running.
///
/// GPA access uses the [`GuestMemory`] trait with volatile semantics — `&self`
/// with interior mutability — these operate on mmap'd guest RAM during
/// concurrent device operation, matching hardware memory semantics.
pub struct VmState<'a> {
    /// Immutable copy of the header that passed canonical layout validation.
    ///
    /// Accessors derive offsets from this host-owned copy, never from the live
    /// mmap bytes. That keeps later accidental or malicious mutation of the
    /// shared header from changing safe pointer arithmetic after validation.
    header: VmStateHeader,
    /// Host-only metadata region: header, vcpu slots, irqchip, device slots,
    /// device metadata, ring buffer, pmem headers, and RAM descriptors.
    /// This is a separate mmap of the memfd prefix (everything before RAM).
    /// NOT mapped into the guest.
    metadata: &'a amla_mem::MmapSlice,
    /// Guest-visible memory regions sorted by GPA and bounds-checked against
    /// their backing mmap.
    guest_memory: ValidatedGuestMemory<'a>,
    /// Hotplug memory regions with validated RAM descriptor headers.
    hotplug_regions: ValidatedHotplugRegions<'a>,
    /// Per-device-slot leases for safe interior mutable device access.
    device_slot_locks: Arc<DeviceSlotLocks>,
    #[cfg(debug_assertions)]
    borrows: Arc<BorrowTracker>,
}

// SAFETY: The underlying memory is mmap'd VM state. Access is synchronized
// via the VM typestate machine (no concurrent writes during setup) and
// hardware coherence + device mutexes during run.
unsafe impl Send for VmState<'_> {}
// SAFETY: see `Send` impl above — the typestate machine ensures no
// concurrent writes during setup, and device mutexes + hardware
// coherence arbitrate run-time sharing.
unsafe impl Sync for VmState<'_> {}

impl VmState<'_> {
    /// Initialize a freshly allocated region with a valid `VmState` layout.
    ///
    /// Zeroes host metadata, then writes the `VmStateHeader`, RAM descriptor
    /// (hole bitmap), PSCI table, and PFN superblocks for all pmem devices. The
    /// ring buffer bytes are zeroed here; callers that use `amla-ringbuf` still
    /// initialize the ring protocol header before exposing it to the guest.
    ///
    /// PMEM geometry comes from the host-owned header, not from the
    /// guest-visible PFN superblocks.
    pub fn init_region(
        region: &mut amla_mem::MmapSlice,
        header: VmStateHeader,
    ) -> Result<(), VmmError> {
        header
            .validate_layout(region.len() as u64)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState init: {e}")))?;
        validate_pmem_sections(region, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState init pmem: {e}")))?;

        let metadata_len = usize::try_from(header.ram_offset).map_err(|_| {
            VmmError::DeviceConfig("VmState init: metadata prefix too large".into())
        })?;
        if metadata_len > region.len() {
            return Err(VmmError::DeviceConfig(
                "VmState init: metadata prefix extends past region".into(),
            ));
        }
        // SAFETY: `init_region` has exclusive access to this writable mapping.
        // Only the host-owned metadata prefix is cleared; RAM contents remain
        // the responsibility of the fresh/branched memory handle lifecycle.
        unsafe { region.as_mut_slice()[..metadata_len].fill(0) };

        init_device_metadata(region, &header, metadata_len)?;

        let page_size = super::pfn::GUEST_PAGE_SIZE;

        // 1. Write PFN superblocks.
        let mut section_offset = header.pmem_offset as usize;
        for i in 0..header.pmem_count as usize {
            let dataoff = header.pmem_data_offsets[i];
            let total = header.pmem_total_sizes[i];
            let sb = super::pfn::build_superblock(total, dataoff, page_size, i as u32).ok_or_else(
                || {
                    VmmError::DeviceConfig(format!(
                        "VmState init: pmem {i} has invalid PFN superblock geometry"
                    ))
                },
            )?;
            let sb_offset = section_offset + super::PFN_SB_OFFSET;
            let sb_end = sb_offset.checked_add(sb.len()).ok_or_else(|| {
                VmmError::DeviceConfig(format!("VmState init: pmem {i} superblock end overflow"))
            })?;
            if sb_end > region.len() {
                return Err(VmmError::DeviceConfig(format!(
                    "VmState init: pmem {i} superblock extends past region"
                )));
            }
            // SAFETY: `init_region` has exclusive access to a writable VM-state
            // mapping, and bounds were checked above.
            let dst = unsafe { region.offset_mut_ptr(sb_offset) }.ok_or_else(|| {
                VmmError::DeviceConfig(format!(
                    "VmState init: pmem {i} superblock offset is invalid"
                ))
            })?;
            // SAFETY: region is freshly allocated, offsets derived from
            // VmStateHeader::compute() which sizes the region to fit.
            unsafe {
                std::ptr::copy_nonoverlapping(sb.as_ptr(), dst.as_ptr(), sb.len());
            }
            section_offset += super::page_align(dataoff) as usize;
        }

        // 2. Init RAM descriptor (hole bitmap).
        let ram_desc_offset = header.ram_desc_offset as usize;
        let ram_size = RamSize::new(header.ram_size)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState init: {e}")))?;
        let ram_desc_size = usize::try_from(super::ram_desc_section_size(ram_size))
            .map_err(|_| VmmError::DeviceConfig("VmState init: RAM descriptor too large".into()))?;
        let ram_desc_end = ram_desc_offset.checked_add(ram_desc_size).ok_or_else(|| {
            VmmError::DeviceConfig("VmState init: RAM descriptor end overflow".into())
        })?;
        if ram_desc_end > region.len() {
            return Err(VmmError::DeviceConfig(
                "VmState init: RAM descriptor extends past region".into(),
            ));
        }
        // SAFETY: `init_region` has exclusive access to a writable VM-state
        // mapping, and bounds were checked above.
        let ptr = unsafe { region.offset_mut_ptr(ram_desc_offset) }.ok_or_else(|| {
            VmmError::DeviceConfig("VmState init: RAM descriptor offset is invalid".into())
        })?;
        // SAFETY: `init_region` has exclusive setup-time access, and checks
        // above prove the descriptor section is contained.
        unsafe { super::RamDescriptorView::init_region(ptr.as_ptr(), ram_size) };

        // 3. Init PSCI power-state section.
        let psci_offset = header.psci_offset as usize;
        let psci_size = header.psci_size as usize;
        let psci_end = psci_offset.checked_add(psci_size).ok_or_else(|| {
            VmmError::DeviceConfig("VmState init: PSCI section end overflow".into())
        })?;
        if psci_end > region.len() {
            return Err(VmmError::DeviceConfig(
                "VmState init: PSCI section extends past region".into(),
            ));
        }
        // SAFETY: `init_region` has exclusive access to a writable VM-state
        // mapping, and bounds were checked above.
        let psci_ptr = unsafe { region.offset_mut_ptr(psci_offset) }.ok_or_else(|| {
            VmmError::DeviceConfig("VmState init: PSCI section offset is invalid".into())
        })?;
        // SAFETY: checks above prove the PSCI section is contained. The
        // region is freshly allocated and not concurrently visible.
        let psci = unsafe { core::slice::from_raw_parts_mut(psci_ptr.as_ptr(), psci_size) };
        psci.fill(0);
        for (index, state) in psci.iter_mut().take(header.vcpu_count as usize).enumerate() {
            *state = if index == 0 {
                PSCI_POWER_ON
            } else {
                PSCI_POWER_OFF
            };
        }

        // 4. Write header at offset 0 (last — superblocks and PSCI are in place for VmState reads).
        if region.len() < size_of::<VmStateHeader>() {
            return Err(VmmError::DeviceConfig(
                "VmState init: region too small for header".into(),
            ));
        }
        // SAFETY: region is freshly allocated, page-aligned, and no concurrent access;
        // `bytes_of(&header)` is exactly `size_of::<VmStateHeader>()` bytes.
        unsafe {
            std::ptr::copy_nonoverlapping(
                bytemuck::bytes_of(&header).as_ptr(),
                region.as_mut_ptr(),
                size_of::<VmStateHeader>(),
            );
        }
        Ok(())
    }
}

fn init_device_metadata(
    region: &mut amla_mem::MmapSlice,
    header: &VmStateHeader,
    metadata_len: usize,
) -> Result<(), VmmError> {
    let device_meta_offset = usize::try_from(header.device_meta_offset).map_err(|_| {
        VmmError::DeviceConfig("VmState init: device metadata offset too large".into())
    })?;
    let device_count = usize::try_from(header.device_count)
        .map_err(|_| VmmError::DeviceConfig("VmState init: device count too large".into()))?;
    for index in 0..device_count {
        let slot_offset = device_meta_offset
            .checked_add(index.checked_mul(DEVICE_META_SLOT_SIZE).ok_or_else(|| {
                VmmError::DeviceConfig("VmState init: device metadata slot offset overflow".into())
            })?)
            .ok_or_else(|| {
                VmmError::DeviceConfig("VmState init: device metadata slot offset overflow".into())
            })?;
        let slot_end = slot_offset
            .checked_add(DEVICE_META_SLOT_SIZE)
            .ok_or_else(|| {
                VmmError::DeviceConfig("VmState init: device metadata slot end overflow".into())
            })?;
        if slot_end > metadata_len {
            return Err(VmmError::DeviceConfig(
                "VmState init: device metadata slot extends past metadata".into(),
            ));
        }
        let slot = DeviceMetaSlot::new(header.device_kinds[index]);
        // SAFETY: caller has exclusive access to the mapping and bounds were
        // checked above.
        unsafe {
            region.as_mut_slice()[slot_offset..slot_end].copy_from_slice(bytemuck::bytes_of(&slot));
        }
    }
    Ok(())
}

// Reason: cross-target stdlib doesn't expose `MmapSlice::as_slice_unchecked`
// as `const fn`, so this can't be const on every supported cross-build.
#[allow(clippy::missing_const_for_fn)]
fn mmap_bytes(mapping: &amla_mem::MmapSlice) -> &[u8] {
    // SAFETY: Callers in this module only use ordinary shared byte slices for
    // host-owned metadata validation/access windows. Guest RAM access is
    // routed through `GuestMemory` volatile views instead.
    unsafe { mapping.as_slice_unchecked() }
}

/// Walk the PMEM region and verify each PFN superblock stays in-bounds.
///
/// `validate_layout` proves the aggregate PMEM range is inside metadata, but
/// this checks each per-device PMEM metadata section using host-owned geometry.
fn validate_pmem_sections(
    metadata: &amla_mem::MmapSlice,
    h: &VmStateHeader,
) -> Result<(), &'static str> {
    let pmem_start = h.pmem_offset as usize;
    let pmem_size = h.pmem_size as usize;
    let pmem_end = pmem_start
        .checked_add(pmem_size)
        .ok_or("pmem end overflow")?;
    if pmem_end > metadata.len() {
        return Err("pmem section extends past metadata");
    }

    let mut section_off = pmem_start;
    for i in 0..h.pmem_count as usize {
        let sb_start = section_off
            .checked_add(super::PFN_SB_OFFSET)
            .ok_or("pmem sb offset overflow")?;
        let sb_end = sb_start
            .checked_add(super::PFN_SB_SIZE)
            .ok_or("pmem sb end overflow")?;
        if sb_end > pmem_end {
            return Err("pmem superblock extends past pmem section");
        }
        let aligned_dataoff = super::layout::checked_page_align(h.pmem_data_offsets[i])
            .ok_or("pmem dataoff overflow on page-align")?;
        let advance = aligned_dataoff as usize;
        let next_off = section_off
            .checked_add(advance)
            .ok_or("pmem section advance overflow")?;
        if next_off > pmem_end {
            return Err("pmem section advances past pmem section");
        }
        section_off = next_off;
    }
    Ok(())
}

fn validate_primary_ram_descriptor(
    metadata: &amla_mem::MmapSlice,
    h: &VmStateHeader,
) -> Result<(), &'static str> {
    let desc_start =
        usize::try_from(h.ram_desc_offset).map_err(|_| "ram descriptor offset too large")?;
    let desc_size =
        usize::try_from(h.ram_desc_size).map_err(|_| "ram descriptor size too large")?;
    let desc_end = desc_start
        .checked_add(desc_size)
        .ok_or("ram descriptor end overflow")?;
    if desc_end > metadata.len() {
        return Err("ram descriptor extends past metadata");
    }

    let metadata = mmap_bytes(metadata);
    let ram_size = RamDescriptorView::validate_initialized_region(&metadata[desc_start..desc_end])?;
    if ram_size.bytes() != h.ram_size {
        return Err("ram descriptor size disagrees with header");
    }
    if ram_size.descriptor_section_size() != h.ram_desc_size {
        return Err("ram descriptor section size disagrees with header");
    }
    Ok(())
}

fn validate_psci_section(
    metadata: &amla_mem::MmapSlice,
    h: &VmStateHeader,
) -> Result<(), &'static str> {
    let psci_start = h.psci_offset as usize;
    let psci_size = h.psci_size as usize;
    let psci_end = psci_start
        .checked_add(psci_size)
        .ok_or("psci section end overflow")?;
    if psci_end > metadata.len() {
        return Err("psci section extends past metadata");
    }
    if psci_size < h.vcpu_count as usize {
        return Err("psci section smaller than vcpu_count");
    }

    let metadata = mmap_bytes(metadata);
    let psci = &metadata[psci_start..psci_end];
    for &state in psci.iter().take(h.vcpu_count as usize) {
        if !is_valid_psci_power_state(state) {
            return Err("invalid PSCI vCPU power state");
        }
    }
    if psci[h.vcpu_count as usize..].iter().any(|&byte| byte != 0) {
        return Err("inactive PSCI padding is nonzero");
    }

    Ok(())
}

fn validate_irqchip_section(
    metadata: &amla_mem::MmapSlice,
    h: &VmStateHeader,
) -> Result<(), &'static str> {
    let irqchip_start =
        usize::try_from(h.irqchip_offset).map_err(|_| "irqchip offset too large")?;
    let irqchip_size = usize::try_from(h.irqchip_size).map_err(|_| "irqchip size too large")?;
    let irqchip_end = irqchip_start
        .checked_add(irqchip_size)
        .ok_or("irqchip section end overflow")?;
    if irqchip_end > metadata.len() {
        return Err("irqchip section extends past metadata");
    }
    if irqchip_size < size_of::<IrqchipSectionState>() {
        return Err("irqchip section is smaller than IrqchipSectionState");
    }

    let metadata = mmap_bytes(metadata);
    let irqchip: &IrqchipSectionState = bytemuck::from_bytes(
        &metadata[irqchip_start..irqchip_start + size_of::<IrqchipSectionState>()],
    );
    irqchip.validate()
}

fn validate_device_metadata(
    metadata: &amla_mem::MmapSlice,
    h: &VmStateHeader,
) -> Result<(), String> {
    let start = usize::try_from(h.device_meta_offset)
        .map_err(|_| String::from("device metadata offset too large"))?;
    let size = usize::try_from(h.device_meta_size)
        .map_err(|_| String::from("device metadata size too large"))?;
    let end = start
        .checked_add(size)
        .ok_or_else(|| String::from("device metadata section end overflow"))?;
    if end > metadata.len() {
        return Err(String::from(
            "device metadata section extends past metadata",
        ));
    }
    let slots_size = DEVICE_META_SLOT_SIZE
        .checked_mul(MAX_DEVICES)
        .ok_or_else(|| String::from("device metadata section size overflow"))?;
    if size < slots_size {
        return Err(String::from(
            "device metadata section is smaller than slot table",
        ));
    }

    let bytes = mmap_bytes(metadata);
    for index in 0..MAX_DEVICES {
        let slot_start = start + index * DEVICE_META_SLOT_SIZE;
        let slot_end = slot_start + DEVICE_META_SLOT_SIZE;
        let slot: &DeviceMetaSlot = bytemuck::from_bytes(&bytes[slot_start..slot_end]);
        if index < h.device_count as usize {
            slot.validate_active(h.device_kinds[index])
                .map_err(|err| format!("slot {index}: {err}"))?;
        } else {
            slot.validate_inactive()
                .map_err(|err| format!("slot {index}: {err}"))?;
        }
    }
    if bytes[start + slots_size..end].iter().any(|&byte| byte != 0) {
        return Err(String::from("device metadata padding is nonzero"));
    }
    Ok(())
}

fn checked_host_page_align(size: u64) -> Result<u64, VmmError> {
    let page_size = u64::try_from(amla_mem::page_size())
        .map_err(|_| VmmError::DeviceConfig("host page size does not fit in u64".into()))?;
    size.checked_add(page_size - 1)
        .map(|v| v & !(page_size - 1))
        .ok_or_else(|| VmmError::DeviceConfig(format!("host page-align overflow for {size}")))
}

fn checked_pmem_data_gpa(
    device_gpa: u64,
    dataoff: u64,
    data_offset: u64,
    context: &str,
) -> Result<u64, VmmError> {
    device_gpa
        .checked_add(dataoff)
        .and_then(|gpa| gpa.checked_add(data_offset))
        .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: GPA overflow")))
}

/// Proof-of-validation wrapper around the metadata mmap.
///
/// Constructible only via [`ValidatedMetadata::parse`], which runs
/// [`VmStateHeader::validate_layout`]. Holding one guarantees the header,
/// every section offset/size, and the metadata length are mutually
/// consistent. `VmState::new` accepts this type and only this type, so
/// no future constructor path can skip validation.
// Reason: `ValidatedMetadata::parse` is the crate-local constructor that
// the type-level invariant is built around. The link is informative to
// downstream readers of `cargo doc` even though it's a crate-private
// method.
#[allow(rustdoc::private_intra_doc_links)]
#[derive(Clone, Copy)]
pub struct ValidatedMetadata<'a> {
    metadata: &'a amla_mem::MmapSlice,
    header: VmStateHeader,
}

impl<'a> ValidatedMetadata<'a> {
    /// Parse and validate the header in `metadata`.
    ///
    /// Runs the full `VmStateHeader::validate_layout` pass. On success,
    /// every accessor reachable through the resulting `VmState` is safe
    /// without per-call bounds or alignment checks.
    pub(crate) fn parse(metadata: &'a amla_mem::MmapSlice) -> Result<Self, VmmError> {
        if metadata.len() < size_of::<VmStateHeader>() {
            return Err(VmmError::DeviceConfig(format!(
                "VmState: metadata too small for VmStateHeader ({} < {})",
                metadata.len(),
                size_of::<VmStateHeader>(),
            )));
        }
        let header: VmStateHeader =
            *bytemuck::from_bytes(&mmap_bytes(metadata)[..size_of::<VmStateHeader>()]);
        header
            .validate_canonical_layout(metadata.len() as u64)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState: {e}")))?;
        validate_pmem_sections(metadata, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState pmem: {e}")))?;
        validate_primary_ram_descriptor(metadata, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState RAM descriptor: {e}")))?;
        validate_psci_section(metadata, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState PSCI: {e}")))?;
        validate_irqchip_section(metadata, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState irqchip: {e}")))?;
        validate_device_metadata(metadata, &header)
            .map_err(|e| VmmError::DeviceConfig(format!("VmState device metadata: {e}")))?;
        Ok(Self { metadata, header })
    }

    /// The validated header.
    pub(crate) const fn header(&self) -> &VmStateHeader {
        &self.header
    }
}

/// A guest memory region proven safe for GPA-to-host-pointer translation.
#[derive(Clone, Copy)]
pub struct GuestRegion<'a> {
    mmap: &'a amla_mem::MmapSlice,
    mapping: crate::MemoryMapping,
    gpa_end: u64,
    host_offset: usize,
}

/// Guest memory mappings validated for sorted, non-overlapping GPA lookup.
///
/// Construction proves each mapping is handle-backed, has a checked GPA end,
/// has a host offset and end that fit in `usize`, and is fully contained in
/// the paired mmap. `VmState` only stores this type, so `resolve_gpa` never
/// sees unchecked mappings.
#[derive(Clone)]
pub struct ValidatedGuestMemory<'a> {
    regions: Vec<GuestRegion<'a>>,
}

impl<'a> ValidatedGuestMemory<'a> {
    /// Validate and sort raw guest memory mappings.
    fn new(
        mut regions: Vec<(&'a amla_mem::MmapSlice, crate::MemoryMapping)>,
    ) -> Result<Self, VmmError> {
        regions.sort_by_key(|(_, m)| m.gpa);

        let mut validated = Vec::with_capacity(regions.len());
        let mut prev_gpa_end = 0u64;
        for (idx, (mmap, mapping)) in regions.into_iter().enumerate() {
            let region = validate_guest_region(idx, mmap, mapping, prev_gpa_end)?;
            prev_gpa_end = region.gpa_end;
            validated.push(region);
        }

        Ok(Self { regions: validated })
    }

    /// Number of validated guest memory mappings.
    pub(crate) const fn len(&self) -> usize {
        self.regions.len()
    }

    /// Iterate over validated guest memory mappings.
    pub(crate) fn iter(&self) -> impl ExactSizeIterator<Item = GuestRegion<'a>> + '_ {
        self.regions.iter().copied()
    }
}

impl<'a> core::ops::Index<usize> for ValidatedGuestMemory<'a> {
    type Output = GuestRegion<'a>;

    fn index(&self, index: usize) -> &Self::Output {
        &self.regions[index]
    }
}

struct ResolvedGuestRange<'a> {
    ptr: NonNull<u8>,
    len: usize,
    readonly: bool,
    _memory: PhantomData<&'a UnsafeCell<[u8]>>,
}

fn validate_guest_region(
    idx: usize,
    mmap: &amla_mem::MmapSlice,
    mapping: crate::MemoryMapping,
    prev_gpa_end: u64,
) -> Result<GuestRegion<'_>, VmmError> {
    if mapping.size == 0 {
        return Err(VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: zero-sized mappings are invalid"
        )));
    }
    if mapping.gpa < prev_gpa_end {
        return Err(VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: GPA range overlaps previous mapping"
        )));
    }
    let gpa_end = mapping.gpa.checked_add(mapping.size).ok_or_else(|| {
        VmmError::DeviceConfig(format!("guest memory mapping {idx}: GPA end overflow"))
    })?;

    let crate::MapSource::Handle { offset, .. } = mapping.source else {
        return Err(VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: source must be handle-backed"
        )));
    };
    let host_offset = usize::try_from(offset).map_err(|_| {
        VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: host offset does not fit usize"
        ))
    })?;
    let host_size = usize::try_from(mapping.size).map_err(|_| {
        VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: size does not fit usize"
        ))
    })?;
    let host_end = host_offset.checked_add(host_size).ok_or_else(|| {
        VmmError::DeviceConfig(format!("guest memory mapping {idx}: host end overflow"))
    })?;
    if host_end > mmap.len() {
        return Err(VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: host range extends past mmap"
        )));
    }
    if host_size != 0 && host_offset >= mmap.len() {
        return Err(VmmError::DeviceConfig(format!(
            "guest memory mapping {idx}: host offset is not addressable"
        )));
    }

    Ok(GuestRegion {
        mmap,
        mapping,
        gpa_end,
        host_offset,
    })
}

#[derive(Clone, Copy)]
struct ValidatedHotplugRegion<'a> {
    region: &'a amla_mem::MmapSlice,
    ram_size: RamSize,
}

/// Hotplug memory regions with validated RAM descriptor headers.
#[derive(Clone)]
pub struct ValidatedHotplugRegions<'a> {
    regions: Vec<ValidatedHotplugRegion<'a>>,
}

impl<'a> ValidatedHotplugRegions<'a> {
    /// Validate hotplug RAM descriptor headers for each region.
    pub(crate) fn new(regions: Vec<&'a amla_mem::MmapSlice>) -> Result<Self, VmmError> {
        let mut validated = Vec::with_capacity(regions.len());
        for (idx, region) in regions.into_iter().enumerate() {
            if region
                .as_ptr()
                .align_offset(align_of::<super::ram_descriptor::RamDescriptorHeader>())
                != 0
            {
                return Err(VmmError::DeviceConfig(format!(
                    "hotplug region {idx}: RAM descriptor header is misaligned"
                )));
            }
            let ram_size = RamDescriptorView::validate_initialized_region(mmap_bytes(region))
                .map_err(|e| VmmError::DeviceConfig(format!("hotplug region {idx}: {e}")))?;
            let desc_size =
                usize::try_from(super::ram_desc_section_size(ram_size)).map_err(|_| {
                    VmmError::DeviceConfig(format!(
                        "hotplug region {idx}: RAM descriptor section too large"
                    ))
                })?;
            let ram_size_len = usize::try_from(ram_size.bytes()).map_err(|_| {
                VmmError::DeviceConfig(format!("hotplug region {idx}: RAM size too large"))
            })?;
            let required_len = desc_size.checked_add(ram_size_len).ok_or_else(|| {
                VmmError::DeviceConfig(format!("hotplug region {idx}: region length overflow"))
            })?;
            if required_len > region.len() {
                return Err(VmmError::DeviceConfig(format!(
                    "hotplug region {idx}: RAM extends past region"
                )));
            }
            validated.push(ValidatedHotplugRegion { region, ram_size });
        }
        Ok(Self { regions: validated })
    }

    /// Return an empty validated hotplug-region set.
    pub(crate) const fn empty() -> Self {
        Self {
            regions: Vec::new(),
        }
    }

    /// Iterate over validated hotplug regions.
    pub(crate) fn iter(&self) -> impl Iterator<Item = (&'a amla_mem::MmapSlice, RamSize)> + '_ {
        self.regions.iter().map(|r| (r.region, r.ram_size))
    }
}

impl<'a> VmState<'a> {
    /// Create a view over validated metadata and guest memory regions.
    ///
    /// Infallible — validation is encoded in the [`ValidatedMetadata`]
    /// parameter, which can only be constructed via
    /// [`ValidatedMetadata::parse`]. Accessors (`slice_at`, `ref_at`,
    /// `vcpu_slot`, …) run without per-call bounds or alignment checks.
    ///
    /// `guest_memory` and `hotplug_regions` are proof wrappers; their
    /// constructors validate all bounds and descriptor headers before this
    /// view can be created.
    const fn new(
        metadata: &ValidatedMetadata<'a>,
        guest_memory: ValidatedGuestMemory<'a>,
        hotplug_regions: ValidatedHotplugRegions<'a>,
        device_slot_locks: Arc<DeviceSlotLocks>,
        #[cfg(debug_assertions)] borrows: Arc<BorrowTracker>,
    ) -> Self {
        Self {
            header: metadata.header,
            metadata: metadata.metadata,
            guest_memory,
            hotplug_regions,
            device_slot_locks,
            #[cfg(debug_assertions)]
            borrows,
        }
    }

    /// Number of guest memory regions.
    pub const fn guest_region_count(&self) -> usize {
        self.guest_memory.len()
    }

    /// Guest-visible memory mappings, sorted by guest physical address.
    pub fn guest_memory_mappings(
        &self,
    ) -> impl ExactSizeIterator<Item = crate::MemoryMapping> + '_ {
        self.guest_memory.iter().map(|region| region.mapping)
    }

    // ========================================================================
    // Core: metadata byte access with runtime checks
    // ========================================================================

    /// Debug assertion: reject offsets that fall in the guest RAM region.
    /// Prevents accidental `&[u8]` leaks to guest memory through `slice_at`/`ref_at`.
    ///
    /// Reads the header directly from the raw pointer to avoid recursion
    /// (`header()` calls `ref_at(0)` which would call `assert_not_ram` again).
    #[cfg(debug_assertions)]
    fn assert_not_ram(&self, offset: usize, len: usize) {
        let ram_start = self.header.ram_offset as usize;
        let ram_end = ram_start + self.header.ram_size as usize;
        let end = offset + len;
        assert!(
            end <= ram_start || offset >= ram_end,
            "VmState: slice_at/ref_at must not touch guest RAM [{ram_start:#x}..{ram_end:#x}) \
             — use GuestMemory::gpa_read/gpa_write instead (requested [{offset:#x}..{end:#x}))"
        );
    }

    /// Shared slice at `offset` for `len` bytes within metadata.
    ///
    /// Only for host-owned sections. Debug-asserts not in RAM.
    fn slice_at(&self, offset: usize, len: usize) -> &[u8] {
        #[cfg(debug_assertions)]
        self.assert_not_ram(offset, len);
        // SAFETY: `validate_layout` in `VmState::new` proved every section
        // offset+size fits within `metadata.len()`; callers only pass
        // offsets/lengths derived from those validated header fields.
        unsafe { core::slice::from_raw_parts(self.metadata.as_ptr().add(offset), len) }
    }

    /// Mutable slice at `offset` for `len` bytes within metadata.
    ///
    /// Requires `&mut self` — used only during sequential setup/teardown.
    fn slice_at_mut(&mut self, offset: usize, len: usize) -> &mut [u8] {
        #[cfg(debug_assertions)]
        self.assert_not_ram(offset, len);
        // SAFETY: see `slice_at` — bounds guaranteed by `validate_layout`.
        unsafe { core::slice::from_raw_parts_mut(self.metadata.as_mut_ptr().add(offset), len) }
    }

    /// Cast metadata offset to `&T`.
    fn ref_at<T: Pod>(&self, offset: usize) -> &T {
        #[cfg(debug_assertions)]
        self.assert_not_ram(offset, size_of::<T>());
        // SAFETY: `validate_layout` proved the containing section is
        // in-bounds and page-aligned; `T` is Pod (no invalid bit patterns)
        // and its required alignment is <= PAGE_SIZE for every Pod used
        // with this accessor.
        let typed_ptr = unsafe { self.metadata.as_ptr().add(offset).cast::<T>() };
        debug_assert!(
            typed_ptr.align_offset(align_of::<T>()) == 0,
            "VmState: offset {offset:#x} not aligned for {} (align={})",
            core::any::type_name::<T>(),
            align_of::<T>(),
        );
        // SAFETY: see pointer derivation above.
        unsafe { &*typed_ptr }
    }

    /// Cast metadata offset to `&mut T`.
    ///
    /// Requires `&mut self` — used only during sequential setup/teardown.
    fn mut_at<T: Pod>(&mut self, offset: usize) -> &mut T {
        #[cfg(debug_assertions)]
        self.assert_not_ram(offset, size_of::<T>());
        // SAFETY: see `ref_at` — bounds and alignment guaranteed by
        // `validate_layout`; `&mut self` gives exclusive metadata access.
        let typed_ptr = unsafe { self.metadata.as_mut_ptr().add(offset).cast::<T>() };
        debug_assert!(
            typed_ptr.align_offset(align_of::<T>()) == 0,
            "VmState: offset {offset:#x} not aligned for {} (align={})",
            core::any::type_name::<T>(),
            align_of::<T>(),
        );
        // SAFETY: see pointer derivation above.
        unsafe { &mut *typed_ptr }
    }

    // ========================================================================
    // Header — cast at offset 0
    // ========================================================================

    /// The `VmStateHeader` at offset 0 of the metadata region.
    pub const fn header(&self) -> &VmStateHeader {
        &self.header
    }

    /// Atomic view over the persisted PSCI per-vCPU power states.
    pub fn psci_power_states(&self) -> PsciPowerStateTable<'_> {
        let h = self.header();
        let len = h.vcpu_count as usize;
        // SAFETY: `ValidatedMetadata::parse` proved the PSCI section is
        // in-bounds and at least `vcpu_count` bytes long for this mapping.
        let states_ptr = unsafe { self.metadata.as_mut_ptr().add(h.psci_offset as usize) };
        PsciPowerStateTable::new(states_ptr, len)
    }

    /// Set one persisted PSCI vCPU power state during setup/teardown.
    ///
    /// Runtime transitions should use [`Self::psci_power_states`] so updates
    /// are atomic. Returns `false` for invalid indexes.
    pub fn set_psci_power_state(&mut self, index: usize, state: PsciPowerState) -> bool {
        let h = self.header();
        let vcpu_count = h.vcpu_count as usize;
        let psci_offset = h.psci_offset as usize;
        if index >= vcpu_count {
            return false;
        }
        self.slice_at_mut(psci_offset + index, 1)[0] = state.as_u8();
        true
    }

    /// Reset persisted PSCI power states for a fresh boot.
    ///
    /// vCPU 0 starts running. All APs start stopped and must be activated via
    /// PSCI `CPU_ON`.
    pub fn set_boot_psci_power_states(&mut self) {
        let h = self.header();
        let vcpu_count = h.vcpu_count as usize;
        let psci_offset = h.psci_offset as usize;
        let states = self.slice_at_mut(psci_offset, vcpu_count);
        for (index, state) in states.iter_mut().enumerate() {
            *state = if index == 0 {
                PSCI_POWER_ON
            } else {
                PSCI_POWER_OFF
            };
        }
    }

    // ========================================================================
    // vCPU state
    // ========================================================================

    /// Raw bytes for vCPU slot `index` (`VCPU_SLOT_SIZE` bytes).
    pub fn vcpu_slot(&self, index: usize) -> Option<&[u8]> {
        if index >= self.header().vcpu_count as usize {
            return None;
        }
        let offset = self.header().vcpu_offset as usize + index * VCPU_SLOT_SIZE;
        Some(self.slice_at(offset, VCPU_SLOT_SIZE))
    }

    /// Mutable bytes for vCPU slot `index` (setup/teardown only).
    pub fn vcpu_slot_mut(&mut self, index: usize) -> Option<&mut [u8]> {
        if index >= self.header().vcpu_count as usize {
            return None;
        }
        let offset = self.header().vcpu_offset as usize + index * VCPU_SLOT_SIZE;
        Some(self.slice_at_mut(offset, VCPU_SLOT_SIZE))
    }

    /// Iterate over all vCPU slots as byte slices.
    pub fn vcpu_slots(&self) -> impl Iterator<Item = &[u8]> {
        let count = self.header().vcpu_count as usize;
        let base = self.header().vcpu_offset as usize;
        (0..count).map(move |i| self.slice_at(base + i * VCPU_SLOT_SIZE, VCPU_SLOT_SIZE))
    }

    /// Typed reference to vCPU slot `index`.
    ///
    /// `T` must match the backend's `VcpuSnapshot` type. Panics if `T`'s
    /// size or alignment exceed `VCPU_SLOT_SIZE`.
    pub fn vcpu_slot_as<T: Pod>(&self, index: usize) -> Option<&T> {
        if index >= self.header().vcpu_count as usize {
            return None;
        }
        assert!(size_of::<T>() <= VCPU_SLOT_SIZE);
        assert!(align_of::<T>() <= VCPU_SLOT_SIZE);
        let offset = self.header().vcpu_offset as usize + index * VCPU_SLOT_SIZE;
        Some(self.ref_at::<T>(offset))
    }

    /// Mutable typed reference to vCPU slot `index` (setup/teardown only).
    ///
    /// `T` must match the backend's `VcpuSnapshot` type. Panics if `T`'s
    /// size or alignment exceed `VCPU_SLOT_SIZE`.
    pub fn vcpu_slot_as_mut<T: Pod>(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.header().vcpu_count as usize {
            return None;
        }
        assert!(size_of::<T>() <= VCPU_SLOT_SIZE);
        assert!(align_of::<T>() <= VCPU_SLOT_SIZE);
        let offset = self.header().vcpu_offset as usize + index * VCPU_SLOT_SIZE;
        Some(self.mut_at::<T>(offset))
    }

    // ========================================================================
    // Irqchip
    // ========================================================================

    /// Shared access to the irqchip section.
    pub fn irqchip(&self) -> &IrqchipSectionState {
        self.ref_at(self.header().irqchip_offset as usize)
    }

    /// Mutable access to irqchip section (setup/teardown only).
    pub fn irqchip_mut(&mut self) -> &mut IrqchipSectionState {
        self.mut_at(self.header().irqchip_offset as usize)
    }

    // ========================================================================
    // Device state
    // ========================================================================

    fn checked_device_slot_offset<T: DeviceState>(&self, slot: DeviceSlot<T>) -> (usize, usize) {
        let index = slot.index();
        let h = self.header();
        assert!(
            index < h.device_count as usize,
            "VmState: device_slot_mut index {index} >= device_count {}",
            h.device_count,
        );
        assert!(
            size_of::<T>() <= DEVICE_SLOT_SIZE,
            "VmState: device_slot_mut size {} > DEVICE_SLOT_SIZE {DEVICE_SLOT_SIZE}",
            size_of::<T>(),
        );
        assert!(
            align_of::<T>() <= DEVICE_SLOT_SIZE,
            "VmState: device_slot_mut alignment {} > DEVICE_SLOT_SIZE {DEVICE_SLOT_SIZE}",
            align_of::<T>(),
        );
        let durable_kind = h.device_kinds[index];
        assert!(
            durable_kind == T::DEVICE_KIND,
            "VmState: device slot {index} has durable kind {durable_kind}, \
             but {} expects kind {}",
            core::any::type_name::<T>(),
            T::DEVICE_KIND,
        );
        let offset = h.device_offset as usize + index * DEVICE_SLOT_SIZE;
        (index, offset)
    }

    fn device_slot_guard<'state, T: DeviceState>(
        &'state self,
        offset: usize,
        slot_lock: parking_lot::MutexGuard<'state, ()>,
    ) -> RefGuard<'state, T> {
        #[cfg(debug_assertions)]
        self.borrows.acquire(offset, size_of::<T>());
        // SAFETY: offset+size_of::<T>() is within the device slot region (bounds asserted above); cast to T is valid for Pod (no invalid bit patterns).
        let typed_ptr = unsafe { self.metadata.as_mut_ptr().add(offset).cast::<T>() };
        debug_assert!(
            typed_ptr.align_offset(align_of::<T>()) == 0,
            "VmState: device_slot_mut not aligned for {}",
            core::any::type_name::<T>(),
        );
        RefGuard {
            ptr: typed_ptr,
            _slot_lock: slot_lock,
            _lifetime: core::marker::PhantomData,
            #[cfg(debug_assertions)]
            offset,
            #[cfg(debug_assertions)]
            len: size_of::<T>(),
            #[cfg(debug_assertions)]
            tracker: self.borrows.as_ref(),
        }
    }

    /// Typed mutable reference to a device slot via interior mutability.
    ///
    /// Returns a [`RefGuard`] that derefs to `&mut T`. The guard holds the
    /// target device slot's runtime lease until drop, so unrelated slots can be
    /// accessed independently while overlapping mutable access to the same slot
    /// is serialized. In debug mode, byte-range tracking remains as an extra
    /// assertion.
    ///
    /// The [`DeviceSlot<T>`] token carries the raw slot index while
    /// [`DeviceState::DEVICE_KIND`] ties `T` to the durable device-kind table.
    /// Runtime bounds, kind, size, and alignment checks remain here because
    /// they depend on the mapped VM-state header.
    pub fn device_slot_mut<T: DeviceState>(&self, slot: DeviceSlot<T>) -> RefGuard<'_, T> {
        let (index, offset) = self.checked_device_slot_offset(slot);
        let slot_lock = self.device_slot_locks.lock(index);
        self.device_slot_guard(offset, slot_lock)
    }

    /// Try to borrow a typed mutable reference to a device slot.
    ///
    /// Returns `None` when another [`RefGuard`] currently holds the same slot.
    /// Bounds, size, and alignment failures panic in the same cases as
    /// [`Self::device_slot_mut`].
    pub fn try_device_slot_mut<T: DeviceState>(
        &self,
        slot: DeviceSlot<T>,
    ) -> Option<RefGuard<'_, T>> {
        let (index, offset) = self.checked_device_slot_offset(slot);
        let slot_lock = self.device_slot_locks.try_lock(index)?;
        Some(self.device_slot_guard(offset, slot_lock))
    }

    /// Typed reference to device metadata slot `index`.
    pub fn device_meta(&self, index: usize) -> Option<&DeviceMetaSlot> {
        if index >= MAX_DEVICES {
            return None;
        }
        let offset = self.header().device_meta_offset as usize + index * DEVICE_META_SLOT_SIZE;
        Some(self.ref_at(offset))
    }

    /// Mutable typed reference to device metadata slot `index` (setup/teardown only).
    pub fn device_meta_mut(&mut self, index: usize) -> Option<&mut DeviceMetaSlot> {
        if index >= MAX_DEVICES {
            return None;
        }
        let offset = self.header().device_meta_offset as usize + index * DEVICE_META_SLOT_SIZE;
        Some(self.mut_at(offset))
    }

    /// Iterate over all device metadata slots.
    pub fn device_metas(&self) -> impl Iterator<Item = &DeviceMetaSlot> {
        let count = self.header().device_count as usize;
        let base = self.header().device_meta_offset as usize;
        (0..count).map(move |i| self.ref_at(base + i * DEVICE_META_SLOT_SIZE))
    }

    // ========================================================================
    // Ring buffer
    // ========================================================================

    /// Mutable access to ring buffer (setup/teardown only).
    pub fn ring_buffer_mut(&mut self) -> &mut [u8] {
        let offset = self.header().ring_offset as usize;
        let size = self.header().ring_size as usize;
        self.slice_at_mut(offset, size)
    }

    /// Host virtual address of the ring buffer.
    ///
    /// # Safety
    ///
    /// Callers must only pass the returned pointer to an abstraction that
    /// owns synchronization for the shared ring memory.
    // Reason: native clippy/rust 1.95 admits `const` here, but cross-compile
    // toolchains for aarch64-apple-darwin etc. ship a stdlib where the
    // underlying `MmapSlice::offset_mut_ptr` isn't yet `const fn`. Keep
    // this non-const to remain portable across the supported targets.
    #[allow(clippy::missing_const_for_fn)]
    pub unsafe fn ring_buffer_hva(&self) -> Option<std::ptr::NonNull<u8>> {
        let offset = self.header().ring_offset as usize;
        // SAFETY: delegated to this method's caller.
        unsafe { self.metadata.offset_mut_ptr(offset) }
    }

    // ========================================================================
    // RAM descriptor
    // ========================================================================

    /// Host virtual address of the primary RAM descriptor section.
    // Reason: cross-target stdlib doesn't expose `MmapSlice::offset_mut_ptr`
    // as `const fn`, so this can't be const on the cross-build matrix.
    #[allow(clippy::missing_const_for_fn)]
    fn ram_desc_hva(&self) -> Option<std::ptr::NonNull<u8>> {
        let offset = self.header().ram_desc_offset as usize;
        // SAFETY: the returned pointer is immediately wrapped in
        // `RamDescriptorView`, which enforces volatile guest-RAM access.
        unsafe { self.metadata.offset_mut_ptr(offset) }
    }

    /// Primary RAM descriptor view.
    ///
    /// Returns `None` if the descriptor offset is out of bounds.
    pub fn ram_descriptor(&self) -> Option<RamDescriptorView<'_>> {
        let h = self.header();
        let ptr = self.ram_desc_hva()?;
        let ram_size = RamSize::new(h.ram_size).ok()?;
        // SAFETY: `ptr` points to a buffer of the size computed from `ram_size`; single exclusive view.
        Some(unsafe { RamDescriptorView::new(ptr.as_ptr(), ram_size, self) })
    }

    /// Iterator over all RAM descriptors: primary first, then hotplug regions.
    ///
    /// Hotplug descriptor headers are validated at `VmState` construction.
    pub fn ram_descriptors(&self) -> impl Iterator<Item = RamDescriptorView<'_>> + '_ {
        let primary = self.ram_descriptor();
        let hotplug = self.hotplug_regions.iter().map(|(region, ram_size)| {
            // SAFETY: `ValidatedHotplugRegions` proved header alignment and
            // descriptor-section containment for this `ram_size`.
            unsafe { RamDescriptorView::new(region.as_mut_ptr(), ram_size, region) }
        });
        primary.into_iter().chain(hotplug)
    }

    /// Total usable RAM across all hotplug regions (computed, not cached).
    ///
    /// Sums `ram_size()` from each hotplug descriptor (skips the primary).
    pub fn hotplug_usable_size(&self) -> u64 {
        self.ram_descriptors()
            .skip(1)
            .map(|desc| desc.ram_size())
            .sum()
    }

    // ========================================================================
    // PMEM
    // ========================================================================

    /// Byte offset of the PMEM section in the metadata.
    pub const fn pmem_offset(&self) -> usize {
        self.header().pmem_offset as usize
    }

    /// Total size of all PMEM sections.
    pub const fn pmem_size(&self) -> usize {
        self.header().pmem_size as usize
    }

    // ========================================================================
    // GPA layout — on-demand computation from host-owned header geometry
    // ========================================================================

    const FOUR_GIB: u64 = 4 * 1024 * 1024 * 1024;

    /// Read host-owned PMEM geometry for device `i`.
    fn pmem_info(&self, i: usize) -> Result<(u64, u64), VmmError> {
        let h = self.header();
        if i >= h.pmem_count as usize {
            return Err(VmmError::MemoryOutOfBounds {
                addr: i as u64,
                size: 0,
                memory_size: h.pmem_count as usize,
            });
        }
        let dataoff = h.pmem_data_offsets[i];
        let aligned_total =
            super::checked_section_align(h.pmem_total_sizes[i]).ok_or_else(|| {
                VmmError::DeviceConfig(format!("pmem device {i}: total size overflows alignment"))
            })?;
        Ok((dataoff, aligned_total))
    }

    /// 4 GiB-aligned base GPA above RAM end where pmem + ring live.
    pub fn extra_base(&self) -> Result<u64, VmmError> {
        let h = self.header();
        let ram = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: h.ram_offset,
            },
            size: h.ram_size,
            gpa: crate::GUEST_PHYS_ADDR,
            readonly: false,
        };
        let split = crate::MemoryMapping::split_holes(&[ram], crate::MEMORY_HOLES)?;
        let gpa_end = match split.last() {
            Some(s) => s
                .gpa
                .checked_add(s.size)
                .ok_or_else(|| VmmError::AddressOverflow {
                    addr: s.gpa,
                    size: usize::try_from(s.size).unwrap_or(usize::MAX),
                })?,
            None => crate::GUEST_PHYS_ADDR,
        };
        gpa_end
            .checked_add(Self::FOUR_GIB - 1)
            .map(|end| end & !(Self::FOUR_GIB - 1))
            .ok_or(VmmError::AddressOverflow {
                addr: gpa_end,
                size: usize::MAX,
            })
    }

    /// GPA of the ring buffer.
    pub fn ring_gpa(&self) -> Result<u64, VmmError> {
        let h = self.header();
        let mut pmem_total = 0u64;
        for i in 0..h.pmem_count as usize {
            let (_, aligned_total) = self.pmem_info(i)?;
            pmem_total = pmem_total
                .checked_add(aligned_total)
                .ok_or_else(|| VmmError::DeviceConfig("pmem GPA total overflow".into()))?;
        }
        self.extra_base()?
            .checked_add(pmem_total)
            .ok_or_else(|| VmmError::DeviceConfig("ring GPA overflow".into()))
    }

    /// (GPA, section-aligned total size) for pmem device `i`.
    ///
    /// Returns `Err` if `i >= pmem_count`.
    pub fn pmem_device_gpa(&self, i: usize) -> Result<(u64, u64), VmmError> {
        let mut gpa_offset = 0u64;
        for j in 0..i {
            let (_, aligned_total) = self.pmem_info(j)?;
            gpa_offset = gpa_offset
                .checked_add(aligned_total)
                .ok_or_else(|| VmmError::DeviceConfig("pmem GPA offset overflow".into()))?;
        }
        let (_, aligned_total) = self.pmem_info(i)?;
        Ok((
            self.extra_base()?
                .checked_add(gpa_offset)
                .ok_or_else(|| VmmError::DeviceConfig("pmem GPA overflow".into()))?,
            aligned_total,
        ))
    }

    /// Build the complete `Vec<MemoryMapping>` for backend `map_memory`.
    ///
    /// `pmem_image_sizes`: flat list of ALL image sizes across all devices
    /// (device 0's images first, then device 1's, etc.).
    #[allow(clippy::too_many_lines)]
    pub fn memory_mappings(
        &self,
        pmem_image_sizes: &[u64],
    ) -> Result<Vec<crate::MemoryMapping>, VmmError> {
        let h = self.header();
        let extra_base = self.extra_base()?;

        // RAM: split around memory holes.
        let ram = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: h.ram_offset,
            },
            size: h.ram_size,
            gpa: crate::GUEST_PHYS_ADDR,
            readonly: false,
        };
        let mut mappings = crate::MemoryMapping::split_holes(&[ram], crate::MEMORY_HOLES)?;

        // Pmem devices: handle 0 = unified, handles 1..N = images (contiguous).
        let mut handle_idx: u32 = 1;
        let mut image_idx: usize = 0;
        let mut gpa_offset = 0u64;
        let mut section_off = h.pmem_offset as usize;
        for i in 0..h.pmem_count as usize {
            let (dataoff, aligned_total) = self.pmem_info(i)?;
            let device_gpa = extra_base
                .checked_add(gpa_offset)
                .ok_or_else(|| VmmError::DeviceConfig("pmem device GPA overflow".into()))?;

            // Superblock + vmemmap (RW, from unified VM-state handle).
            mappings.push(crate::MemoryMapping {
                source: crate::MapSource::Handle {
                    index: 0,
                    offset: section_off as u64,
                },
                size: dataoff,
                gpa: device_gpa,
                readonly: false,
            });

            // Map each image handle contiguously in the data region.
            let num_images = h.pmem_image_counts[i] as usize;
            let image_end = image_idx
                .checked_add(num_images)
                .ok_or_else(|| VmmError::DeviceConfig("pmem image index overflow".into()))?;
            if image_end > pmem_image_sizes.len() {
                return Err(VmmError::DeviceConfig(format!(
                    "pmem device {i}: image count {num_images} at index {image_idx} exceeds \
                     provided image sizes ({})",
                    pmem_image_sizes.len(),
                )));
            }
            let packed_data_size = h.pmem_total_sizes[i].checked_sub(dataoff).ok_or_else(|| {
                VmmError::DeviceConfig(format!(
                    "pmem device {i}: total size smaller than data offset"
                ))
            })?;
            let section_data_size = aligned_total.checked_sub(dataoff).ok_or_else(|| {
                VmmError::DeviceConfig(format!(
                    "pmem device {i}: aligned total smaller than data offset"
                ))
            })?;
            let mut data_offset = 0u64;
            for _ in 0..num_images {
                let raw_size = pmem_image_sizes[image_idx];
                let image_size = checked_host_page_align(raw_size)?;
                let image_end = data_offset.checked_add(image_size).ok_or_else(|| {
                    VmmError::DeviceConfig(format!("pmem device {i}: image data offset overflow"))
                })?;
                if image_end > packed_data_size {
                    return Err(VmmError::DeviceConfig(format!(
                        "pmem device {i}: image sizes exceed canonical packed data size"
                    )));
                }
                if image_size > 0 {
                    mappings.push(crate::MemoryMapping {
                        source: crate::MapSource::Handle {
                            index: handle_idx,
                            offset: 0,
                        },
                        size: image_size,
                        gpa: checked_pmem_data_gpa(
                            device_gpa,
                            dataoff,
                            data_offset,
                            &format!("pmem device {i}: image"),
                        )?,
                        readonly: true,
                    });
                }
                data_offset = image_end;
                handle_idx = handle_idx
                    .checked_add(1)
                    .ok_or_else(|| VmmError::DeviceConfig("pmem handle index overflow".into()))?;
                image_idx = image_idx
                    .checked_add(1)
                    .ok_or_else(|| VmmError::DeviceConfig("pmem image index overflow".into()))?;
            }
            if data_offset != packed_data_size {
                return Err(VmmError::DeviceConfig(format!(
                    "pmem device {i}: image sizes do not match canonical packed data size"
                )));
            }

            // Zero padding for remainder of data region.
            let padding = section_data_size.checked_sub(data_offset).ok_or_else(|| {
                VmmError::DeviceConfig(format!("pmem device {i}: section data underflow"))
            })?;
            if padding > 0 {
                mappings.push(crate::MemoryMapping {
                    source: crate::MapSource::AnonymousZero,
                    size: padding,
                    gpa: checked_pmem_data_gpa(
                        device_gpa,
                        dataoff,
                        data_offset,
                        &format!("pmem device {i}: padding"),
                    )?,
                    readonly: true,
                });
            }

            let section_advance = usize::try_from(super::page_align(dataoff)).map_err(|_| {
                VmmError::DeviceConfig(format!("pmem device {i}: section advance too large"))
            })?;
            section_off = section_off.checked_add(section_advance).ok_or_else(|| {
                VmmError::DeviceConfig(format!("pmem device {i}: section offset overflow"))
            })?;
            gpa_offset = gpa_offset
                .checked_add(aligned_total)
                .ok_or_else(|| VmmError::DeviceConfig("pmem GPA offset overflow".into()))?;
        }
        if image_idx != pmem_image_sizes.len() {
            return Err(VmmError::DeviceConfig(format!(
                "provided {} pmem image sizes, but header expects {image_idx}",
                pmem_image_sizes.len()
            )));
        }

        // Ring buffer.
        mappings.push(crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: h.ring_offset,
            },
            size: h.ring_size,
            gpa: extra_base
                .checked_add(gpa_offset)
                .ok_or_else(|| VmmError::DeviceConfig("ring mapping GPA overflow".into()))?,
            readonly: false,
        });

        Ok(mappings)
    }

    // ========================================================================
    // GPA access — binary search over guest_memory
    // ========================================================================

    /// Resolve a guest physical address to a readable guest-memory proof.
    fn resolve_gpa_read(&self, addr: u64, len: usize) -> Result<ResolvedGuestRead<'_>, VmmError> {
        let range = self.resolve_gpa(addr, len)?;
        // SAFETY: `resolve_gpa` proved that this range is backed by mapped
        // guest memory owned by `self` for the returned lifetime.
        Ok(unsafe { ResolvedGuestRead::from_raw_parts(range.ptr.as_ptr(), range.len, self) })
    }

    /// Resolve a guest physical address to a writable guest-memory proof.
    ///
    /// Rejects writes into read-only mappings (e.g. pmem images): those
    /// mappings are installed with `PROT_READ`.
    fn resolve_gpa_write(&self, addr: u64, len: usize) -> Result<ResolvedGuestWrite<'_>, VmmError> {
        let range = self.resolve_gpa(addr, len)?;
        if range.readonly {
            return Err(VmmError::MemoryAccessDenied(
                "write to read-only mapping".into(),
            ));
        }
        // SAFETY: `resolve_gpa` proved that this range is backed by mapped
        // guest memory owned by `self`, and the read-only check above proves
        // the host mapping is writable.
        Ok(unsafe { ResolvedGuestWrite::from_raw_parts(range.ptr.as_ptr(), range.len, self) })
    }

    fn scalar_read_ptr<T>(&self, addr: u64) -> Result<*const T, VmmError> {
        let align = align_of::<T>();
        if !(addr as usize).is_multiple_of(align) {
            return Err(VmmError::UnalignedGuestMemoryAccess {
                addr,
                size: size_of::<T>(),
                align,
            });
        }
        let resolved = self.resolve_gpa_read(addr, size_of::<T>())?;
        let ptr = resolved.as_ptr();
        if !(ptr as usize).is_multiple_of(align) {
            return Err(VmmError::UnalignedGuestMemoryAccess {
                addr,
                size: size_of::<T>(),
                align,
            });
        }
        Ok(ptr.cast::<T>())
    }

    fn scalar_write_ptr<T>(&self, addr: u64) -> Result<*mut T, VmmError> {
        let align = align_of::<T>();
        if !(addr as usize).is_multiple_of(align) {
            return Err(VmmError::UnalignedGuestMemoryAccess {
                addr,
                size: size_of::<T>(),
                align,
            });
        }
        let resolved = self.resolve_gpa_write(addr, size_of::<T>())?;
        let ptr = resolved.as_mut_ptr();
        if !(ptr as usize).is_multiple_of(align) {
            return Err(VmmError::UnalignedGuestMemoryAccess {
                addr,
                size: size_of::<T>(),
                align,
            });
        }
        Ok(ptr.cast::<T>())
    }

    /// Resolve a guest physical address to a host-backed range.
    ///
    /// Binary-searches `guest_memory` for the mapping containing `addr`.
    fn resolve_gpa(&self, addr: u64, len: usize) -> Result<ResolvedGuestRange<'_>, VmmError> {
        let len64 = len as u64;
        let idx = self
            .guest_memory
            .regions
            .partition_point(|r| r.gpa_end <= addr);
        if idx >= self.guest_memory.len() {
            return Err(VmmError::MemoryOutOfBounds {
                addr,
                size: len,
                memory_size: 0,
            });
        }
        let region = self.guest_memory[idx];
        let mmap = region.mmap;
        let mapping = region.mapping;
        if addr < mapping.gpa {
            return Err(VmmError::MemoryOutOfBounds {
                addr,
                size: len,
                memory_size: usize::try_from(mapping.size).unwrap_or(usize::MAX),
            });
        }
        let local_off = addr - mapping.gpa;
        let end = local_off
            .checked_add(len64)
            .ok_or_else(|| VmmError::MemoryOutOfBounds {
                addr,
                size: len,
                memory_size: usize::try_from(mapping.size).unwrap_or(usize::MAX),
            })?;
        if end > mapping.size {
            return Err(VmmError::MemoryOutOfBounds {
                addr,
                size: len,
                memory_size: usize::try_from(mapping.size).unwrap_or(usize::MAX),
            });
        }
        let host_off = usize::try_from(local_off)
            .ok()
            .and_then(|local| region.host_offset.checked_add(local))
            .ok_or_else(|| VmmError::MemoryOutOfBounds {
                addr,
                size: len,
                memory_size: usize::try_from(mapping.size).unwrap_or(usize::MAX),
            })?;
        // SAFETY: `ValidatedGuestMemory` proved `host_off..host_off+len` is
        // inside the mapped region. The returned pointer is only used through
        // volatile guest-memory views after read-only checks.
        let host_ptr = unsafe { mmap.as_mut_ptr().wrapping_add(host_off) };
        let ptr = NonNull::new(host_ptr).ok_or_else(|| VmmError::MemoryOutOfBounds {
            addr,
            size: len,
            memory_size: usize::try_from(mapping.size).unwrap_or(usize::MAX),
        })?;
        Ok(ResolvedGuestRange {
            ptr,
            len,
            readonly: mapping.readonly,
            _memory: PhantomData,
        })
    }
}

// ============================================================================
// GuestMemory implementation — volatile access to guest RAM
// ============================================================================

use super::guest_mem::{
    self, GuestMemory, ResolvedGuestRead, ResolvedGuestWrite, VolatileSlice, VolatileSliceMut,
};

impl GuestMemory for VmState<'_> {
    type Slice<'m>
        = VolatileSlice<'m>
    where
        Self: 'm;
    type SliceMut<'m>
        = VolatileSliceMut<'m>
    where
        Self: 'm;

    fn gpa_read(&self, addr: u64, len: usize) -> Result<VolatileSlice<'_>, VmmError> {
        if len == 0 {
            // SAFETY: zero-length slices never dereference the dangling pointer;
            // the owner borrow ties the view to this `VmState`.
            let resolved = unsafe {
                ResolvedGuestRead::from_raw_parts(core::ptr::NonNull::dangling().as_ptr(), 0, self)
            };
            return Ok(VolatileSlice::from_resolved(resolved));
        }
        Ok(VolatileSlice::from_resolved(
            self.resolve_gpa_read(addr, len)?,
        ))
    }

    fn gpa_write(&self, addr: u64, len: usize) -> Result<VolatileSliceMut<'_>, VmmError> {
        if len == 0 {
            // SAFETY: zero-length slices never dereference the dangling pointer;
            // the owner borrow ties the view to this `VmState`.
            let resolved = unsafe {
                ResolvedGuestWrite::from_raw_parts(core::ptr::NonNull::dangling().as_ptr(), 0, self)
            };
            return Ok(VolatileSliceMut::from_resolved(resolved));
        }
        Ok(VolatileSliceMut::from_resolved(
            self.resolve_gpa_write(addr, len)?,
        ))
    }

    fn read_obj<T: Pod>(&self, addr: u64) -> Result<T, VmmError> {
        let resolved = self.resolve_gpa_read(addr, size_of::<T>())?;
        let mut val = T::zeroed();
        guest_mem::volatile_read(resolved.as_ptr(), bytemuck::bytes_of_mut(&mut val));
        Ok(val)
    }

    fn write_obj<T: bytemuck::NoUninit>(&self, addr: u64, val: &T) -> Result<(), VmmError> {
        let resolved = self.resolve_gpa_write(addr, size_of::<T>())?;
        guest_mem::volatile_write(resolved.as_mut_ptr(), bytemuck::bytes_of(val));
        Ok(())
    }

    fn read_le_u16(&self, addr: u64) -> Result<u16, VmmError> {
        let ptr = self.scalar_read_ptr::<u16>(addr)?;
        // SAFETY: `scalar_read_ptr` bounds-checks the guest range and verifies
        // natural alignment for the typed volatile load.
        let raw = unsafe { core::ptr::read_volatile(ptr) };
        Ok(u16::from_le(raw))
    }

    fn read_le_u32(&self, addr: u64) -> Result<u32, VmmError> {
        let ptr = self.scalar_read_ptr::<u32>(addr)?;
        // SAFETY: see `read_le_u16`.
        let raw = unsafe { core::ptr::read_volatile(ptr) };
        Ok(u32::from_le(raw))
    }

    fn read_le_u64(&self, addr: u64) -> Result<u64, VmmError> {
        let ptr = self.scalar_read_ptr::<u64>(addr)?;
        // SAFETY: see `read_le_u16`.
        let raw = unsafe { core::ptr::read_volatile(ptr) };
        Ok(u64::from_le(raw))
    }

    fn write_le_u16(&self, addr: u64, val: u16) -> Result<(), VmmError> {
        let ptr = self.scalar_write_ptr::<u16>(addr)?;
        // SAFETY: `scalar_write_ptr` bounds-checks the guest range, rejects
        // read-only mappings, and verifies natural alignment.
        unsafe { core::ptr::write_volatile(ptr, val.to_le()) };
        Ok(())
    }

    fn write_le_u32(&self, addr: u64, val: u32) -> Result<(), VmmError> {
        let ptr = self.scalar_write_ptr::<u32>(addr)?;
        // SAFETY: see `write_le_u16`.
        unsafe { core::ptr::write_volatile(ptr, val.to_le()) };
        Ok(())
    }

    fn write_le_u64(&self, addr: u64, val: u64) -> Result<(), VmmError> {
        let ptr = self.scalar_write_ptr::<u64>(addr)?;
        // SAFETY: see `write_le_u16`.
        unsafe { core::ptr::write_volatile(ptr, val.to_le()) };
        Ok(())
    }

    fn validate_write_le_u16(&self, addr: u64) -> Result<(), VmmError> {
        self.scalar_write_ptr::<u16>(addr).map(drop)
    }

    fn validate_write_le_u32(&self, addr: u64) -> Result<(), VmmError> {
        self.scalar_write_ptr::<u32>(addr).map(drop)
    }

    fn validate_read_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
        if len == 0 {
            return Ok(());
        }
        self.resolve_gpa_read(addr, len).map(drop)
    }

    fn validate_write_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
        if len == 0 {
            return Ok(());
        }
        self.resolve_gpa_write(addr, len).map(drop)
    }
}

impl core::fmt::Debug for VmState<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VmState")
            .field("metadata_len", &self.metadata.len())
            .field("guest_regions", &self.guest_memory.len())
            .finish()
    }
}

// ============================================================================
// Test Helpers (public for cross-crate test use)
// ============================================================================

/// Re-export `MmapSlice` for cross-crate test use.
///
/// Test helpers return `MmapSlice` and downstream test crates may not
/// depend on `amla-mem` directly. This re-export avoids adding that dep.
#[doc(hidden)]
pub type TestMmap = amla_mem::MmapSlice;

/// Smallest RAM size that can be represented by the canonical RAM descriptor.
///
/// This is exposed only for VM-state-backed tests in downstream crates. It keeps
/// those fixtures aligned with the production layout invariant instead of
/// silently constructing impossible VM states.
#[doc(hidden)]
pub const TEST_RAM_SIZE: usize = BITMAP_BLOCK_SIZE as usize;

/// Allocate an `MmapSlice` with a valid `VmStateHeader` suitable for testing.
///
/// Creates an anonymous read-write mmap with a properly initialized header.
/// The mapping contains the full VM state layout (metadata + RAM).
///
/// This is a test-support function exposed for use by other crates' tests.
/// Production code should never call this.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn test_mmap(ram_size: usize) -> amla_mem::MmapSlice {
    test_mmap_with_vcpus(2, ram_size)
}

/// Allocate a test `MmapSlice` with caller-selected durable device-kind codes.
///
/// Production code should never call this.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn test_mmap_with_device_kinds(ram_size: usize, device_kinds: &[u8]) -> amla_mem::MmapSlice {
    test_mmap_with_vcpus_and_device_kinds(2, ram_size, device_kinds)
}

/// Allocate a test `MmapSlice` with a caller-selected vCPU count.
///
/// Production code should never call this.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn test_mmap_with_vcpus(vcpu_count: u32, ram_size: usize) -> amla_mem::MmapSlice {
    test_mmap_with_vcpus_and_device_kinds(vcpu_count, ram_size, &[])
}

/// Allocate a test `MmapSlice` with caller-selected vCPUs and device kinds.
///
/// Production code should never call this.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn test_mmap_with_vcpus_and_device_kinds(
    vcpu_count: u32,
    ram_size: usize,
    device_kinds: &[u8],
) -> amla_mem::MmapSlice {
    use super::header::VmStateHeader;
    let mut header = VmStateHeader::compute(vcpu_count, 4, ram_size as u64, &[], &[])
        .expect("test layout must fit");
    assert!(
        device_kinds.len() <= header.device_count as usize,
        "test device kinds exceed device_count"
    );
    test_stamp_device_topology(&mut header, device_kinds);
    let total = header.total_size() as usize;
    let mut mmap = amla_mem::MmapSlice::anonymous_rw(total).expect("anonymous_rw failed");
    VmState::init_region(&mut mmap, header).expect("test VM state init must succeed");
    mmap
}

/// Stamp a computed test header with valid durable device topology.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn test_stamp_device_topology(header: &mut VmStateHeader, device_kinds: &[u8]) {
    let active_count = header.device_count as usize;
    assert!(
        active_count <= MAX_DEVICES,
        "test device count exceeds MAX_DEVICES"
    );
    assert!(
        device_kinds.len() <= active_count,
        "test device kinds exceed device_count"
    );

    let default_kinds = [
        DEVICE_KIND_CONSOLE,
        DEVICE_KIND_RNG,
        DEVICE_KIND_NET,
        DEVICE_KIND_FS,
    ];
    header.device_kinds = [DEVICE_KIND_UNUSED; MAX_DEVICES];
    header.device_queue_counts = [0; MAX_DEVICES];
    for index in 0..active_count {
        header.device_kinds[index] = default_kinds.get(index).copied().unwrap_or(DEVICE_KIND_FS);
    }
    header.device_kinds[..device_kinds.len()].copy_from_slice(device_kinds);
    for index in 0..active_count {
        header.device_queue_counts[index] = test_queue_count_for_kind(header.device_kinds[index]);
    }
}

/// Return a valid minimal queue-count shape for a test device kind.
#[doc(hidden)]
pub const fn test_queue_count_for_kind(kind: u8) -> u16 {
    let Some(kind) = DeviceKindCode::from_active_code(kind) else {
        return 1;
    };
    match kind {
        DeviceKindCode::Console => 6,
        DeviceKindCode::Net | DeviceKindCode::Fs => 2,
        DeviceKindCode::Rng | DeviceKindCode::Pmem => 1,
    }
}

/// Owner for mapped VM-state memory.
///
/// This keeps the public model small: [`MappedVmState`] owns the mmaps and
/// shared access leases, while [`VmState`] is a borrowed view over it.
///
/// The unified mapping contains host metadata and guest RAM. PMEM image
/// mappings are kept here only to preserve host mapping lifetime and drop
/// ordering; VM-state parsing never derives layout from them. Hotplug RAM is
/// explicit because those mappings carry RAM descriptor headers.
pub struct MappedVmState {
    unified: amla_mem::MmapSlice,
    pmem_images: Vec<amla_mem::MmapSlice>,
    hotplug_ram: Vec<amla_mem::MmapSlice>,
    gpa_base: u64,
    device_slot_locks: Arc<DeviceSlotLocks>,
    #[cfg(debug_assertions)]
    borrows: Arc<BorrowTracker>,
}

impl MappedVmState {
    /// Create mapped VM-state memory with only the unified metadata/RAM mapping.
    pub fn new(unified: amla_mem::MmapSlice, gpa_base: u64) -> Result<Self, VmmError> {
        Self::from_parts(unified, Vec::new(), Vec::new(), gpa_base)
    }

    /// Create mapped VM-state memory and keep PMEM image mappings alive.
    pub fn with_pmem_images(
        unified: amla_mem::MmapSlice,
        pmem_images: Vec<amla_mem::MmapSlice>,
        gpa_base: u64,
    ) -> Result<Self, VmmError> {
        Self::from_parts(unified, pmem_images, Vec::new(), gpa_base)
    }

    /// Create mapped VM-state memory with explicit hotplug RAM mappings.
    pub fn with_hotplug_ram(
        unified: amla_mem::MmapSlice,
        pmem_images: Vec<amla_mem::MmapSlice>,
        hotplug_ram: Vec<amla_mem::MmapSlice>,
        gpa_base: u64,
    ) -> Result<Self, VmmError> {
        Self::from_parts(unified, pmem_images, hotplug_ram, gpa_base)
    }

    fn from_parts(
        unified: amla_mem::MmapSlice,
        pmem_images: Vec<amla_mem::MmapSlice>,
        hotplug_ram: Vec<amla_mem::MmapSlice>,
        gpa_base: u64,
    ) -> Result<Self, VmmError> {
        let mapped = Self {
            unified,
            pmem_images,
            hotplug_ram,
            gpa_base,
            device_slot_locks: Arc::new(DeviceSlotLocks::new()),
            #[cfg(debug_assertions)]
            borrows: Arc::new(BorrowTracker::new()),
        };
        mapped.view()?;
        Ok(mapped)
    }

    /// Borrow a validated VM-state view.
    pub fn view(&self) -> Result<VmState<'_>, VmmError> {
        vm_state_view_from_parts(
            &self.unified,
            self.gpa_base,
            &self.hotplug_ram,
            self.device_slot_locks.clone(),
            #[cfg(debug_assertions)]
            self.borrows.clone(),
        )
    }

    /// The unified metadata/RAM mapping.
    pub const fn unified(&self) -> &amla_mem::MmapSlice {
        &self.unified
    }

    /// Consume the owner and return the unified metadata/RAM mapping.
    pub fn into_unified(self) -> amla_mem::MmapSlice {
        self.unified
    }

    /// Number of host mappings kept alive by this owner.
    pub const fn mapping_count(&self) -> usize {
        1 + self.pmem_images.len() + self.hotplug_ram.len()
    }
}

fn vm_state_view_from_parts<'a>(
    unified: &'a amla_mem::MmapSlice,
    gpa_base: u64,
    hotplug_ram: &'a [amla_mem::MmapSlice],
    device_slot_locks: Arc<DeviceSlotLocks>,
    #[cfg(debug_assertions)] borrows: Arc<BorrowTracker>,
) -> Result<VmState<'a>, VmmError> {
    let validated = ValidatedMetadata::parse(unified)?;
    let header = validated.header();
    let ram_offset = header.ram_offset;
    let ram_size = header.ram_size;

    // Create a single RAM mapping and split around memory holes.
    let ram = crate::MemoryMapping {
        source: crate::MapSource::Handle {
            index: 0,
            offset: ram_offset,
        },
        size: ram_size,
        gpa: gpa_base,
        readonly: false,
    };
    let split = crate::MemoryMapping::split_holes(&[ram], crate::MEMORY_HOLES)?;
    let guest_memory: Vec<(&amla_mem::MmapSlice, crate::MemoryMapping)> =
        split.into_iter().map(|m| (unified, m)).collect();

    let hotplug_regions: Vec<&amla_mem::MmapSlice> = hotplug_ram.iter().collect();
    Ok(VmState::new(
        &validated,
        ValidatedGuestMemory::new(guest_memory)?,
        ValidatedHotplugRegions::new(hotplug_regions)?,
        device_slot_locks,
        #[cfg(debug_assertions)]
        borrows,
    ))
}

/// Build a `VmState` from a single `MmapSlice` (test helper).
///
/// The mmap is used as both metadata and guest memory. The RAM section
/// (starting at `header.ram_offset`) is mapped at `gpa_base`.
#[doc(hidden)]
#[allow(clippy::expect_used)] // test helper — panic is intentional
pub fn make_test_vmstate(mmap: &amla_mem::MmapSlice, gpa_base: u64) -> VmState<'_> {
    let validated = ValidatedMetadata::parse(mmap).expect("make_test_vmstate: invalid test layout");
    let header = validated.header();
    let ram_offset = header.ram_offset;
    let ram_size = header.ram_size;

    let guest_memory = vec![(
        mmap,
        crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: ram_offset,
            },
            size: ram_size,
            gpa: gpa_base,
            readonly: false,
        },
    )];
    VmState::new(
        &validated,
        ValidatedGuestMemory::new(guest_memory).expect("make_test_vmstate: invalid guest memory"),
        ValidatedHotplugRegions::empty(),
        Arc::new(DeviceSlotLocks::new()),
        #[cfg(debug_assertions)]
        Arc::new(BorrowTracker::new()),
    )
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::super::guest_mem::{GuestMemory, GuestRead, GuestWrite};
    use super::super::header::DEVICE_KIND_PMEM;
    use super::super::header::{VM_STATE_MAGIC, VM_STATE_VERSION};
    use super::*;

    const TEST_DEVICE_KIND: u8 = DEVICE_KIND_FS;

    #[derive(Clone, Copy, Debug, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
    #[repr(C)]
    struct TestDeviceState {
        value: u64,
    }

    // SAFETY: test-only state layout used with test VM-state slots stamped
    // with `TEST_DEVICE_KIND`.
    unsafe impl DeviceState for TestDeviceState {
        const DEVICE_KIND: u8 = TEST_DEVICE_KIND;
    }

    #[derive(Clone, Copy, Debug, PartialEq, bytemuck::Pod, bytemuck::Zeroable)]
    #[repr(C)]
    struct MismatchedDeviceState {
        value: u64,
    }

    // SAFETY: test-only state layout used to verify durable kind rejection.
    unsafe impl DeviceState for MismatchedDeviceState {
        const DEVICE_KIND: u8 = DEVICE_KIND_NET;
    }

    fn test_region(ram_mb: u64) -> amla_mem::MmapSlice {
        test_mmap((ram_mb * 1024 * 1024) as usize)
    }

    fn make_state(mmap: &amla_mem::MmapSlice) -> VmState<'_> {
        make_test_vmstate(mmap, 0)
    }

    fn write_header(mmap: &mut amla_mem::MmapSlice, header: &VmStateHeader) {
        let bytes = bytemuck::bytes_of(header);
        // SAFETY: test callers allocate a VM-state mmap large enough for the
        // header and mutate it before sharing it with any VM-state view.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), mmap.as_mut_ptr(), bytes.len());
        }
    }

    fn write_header_aliasing_view(mmap: &amla_mem::MmapSlice, header: &VmStateHeader) {
        let bytes = bytemuck::bytes_of(header);
        // SAFETY: this intentionally simulates out-of-band shared-mmap
        // corruption after a `VmState` view has been constructed.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), mmap.as_mut_ptr(), bytes.len());
        }
    }

    fn write_u32(mmap: &mut amla_mem::MmapSlice, offset: usize, value: u32) {
        let bytes = value.to_le_bytes();
        // SAFETY: test callers pass offsets inside an anonymous test mmap and
        // mutate it before sharing it with any VM-state view.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                mmap.as_mut_ptr().add(offset),
                bytes.len(),
            );
        }
    }

    #[test]
    fn header_readable() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        assert_eq!(state.header().magic, VM_STATE_MAGIC);
        assert_eq!(state.header().version, VM_STATE_VERSION);
        assert_eq!(state.header().vcpu_count, 2);
        assert_eq!(state.header().device_count, 4);
    }

    #[test]
    fn validated_header_copy_survives_live_header_corruption() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let original = *state.header();
        let mut corrupted = original;
        corrupted.ram_offset = u64::MAX;
        corrupted.vcpu_count = 0;
        corrupted.device_count = MAX_DEVICES as u32;

        write_header_aliasing_view(&mmap, &corrupted);

        assert_eq!(state.header().ram_offset, original.ram_offset);
        assert_eq!(state.header().vcpu_count, original.vcpu_count);
        assert_eq!(state.header().device_count, original.device_count);
        assert!(state.vcpu_slot(1).is_some());
    }

    #[test]
    fn init_region_zeros_ring_bytes_before_protocol_init() {
        let mut header = VmStateHeader::compute(1, 1, BITMAP_BLOCK_SIZE, &[], &[]).unwrap();
        test_stamp_device_topology(&mut header, &[]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        // SAFETY: test owns this anonymous writable mapping.
        unsafe { mmap.as_mut_slice().fill(0xA5) };

        VmState::init_region(&mut mmap, header).unwrap();

        let ring_start = header.ring_offset as usize;
        let ring_end = ring_start + header.ring_size as usize;
        let bytes = mmap_bytes(&mmap);
        assert!(bytes[ring_start..ring_end].iter().all(|&byte| byte == 0));
    }

    #[test]
    fn vcpu_slots_iterable() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let slots: Vec<&[u8]> = state.vcpu_slots().collect();
        assert_eq!(slots.len(), 2);
        assert_eq!(slots[0].len(), VCPU_SLOT_SIZE);
    }

    #[test]
    fn vcpu_slot_by_index() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        assert!(state.vcpu_slot(0).is_some());
        assert!(state.vcpu_slot(1).is_some());
        assert!(state.vcpu_slot(2).is_none()); // only 2 vcpus
    }

    #[test]
    fn device_meta_accessible() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let meta = state.device_meta(0).unwrap();
        assert_eq!(meta.kind(), DEVICE_KIND_CONSOLE);
    }

    #[test]
    fn device_slot_mut_excludes_overlapping_same_slot_guards() {
        let mmap =
            test_mmap_with_device_kinds(256 * 1024 * 1024, &[TEST_DEVICE_KIND, TEST_DEVICE_KIND]);
        let state = make_state(&mmap);
        // SAFETY: the test layout has four initialized device slots, and this
        // test is only checking slot lease behavior.
        let slot0 = unsafe { DeviceSlot::<TestDeviceState>::new_unchecked(0) };
        // SAFETY: see `slot0`; slot 1 is also part of the test layout.
        let slot1 = unsafe { DeviceSlot::<TestDeviceState>::new_unchecked(1) };

        let mut first = state.device_slot_mut(slot0);
        first.value = 1;

        assert!(state.try_device_slot_mut(slot0).is_none());

        let other_slot = state
            .try_device_slot_mut(slot1)
            .expect("different device slots must not share a lease");
        assert_eq!(other_slot.value, 0);
        drop(other_slot);

        drop(first);

        let mut second = state
            .try_device_slot_mut(slot0)
            .expect("dropping the first guard must release the slot lease");
        assert_eq!(second.value, 1);
        second.value = 2;
    }

    #[test]
    fn mapped_vm_state_shares_device_slot_leases_across_views() {
        let mmap = test_mmap_with_device_kinds(256 * 1024 * 1024, &[TEST_DEVICE_KIND]);

        let mapped = MappedVmState::new(mmap, crate::GUEST_PHYS_ADDR).unwrap();
        let view_a = mapped.view().unwrap();
        let view_b = mapped.view().unwrap();

        // SAFETY: slot 0 is initialized above with `TEST_DEVICE_KIND`.
        let slot = unsafe { DeviceSlot::<TestDeviceState>::new_unchecked(0) };
        let _guard = view_a.device_slot_mut(slot);

        assert!(
            view_b.try_device_slot_mut(slot).is_none(),
            "views from one mapped VM state must share slot leases"
        );
    }

    #[test]
    #[should_panic(expected = "durable kind")]
    fn device_slot_mut_rejects_durable_kind_mismatch() {
        let mmap = test_mmap_with_device_kinds(256 * 1024 * 1024, &[DEVICE_KIND_FS]);
        let state = make_state(&mmap);
        // SAFETY: this deliberately mints a mismatched test token to verify
        // the durable header kind check rejects it before casting slot bytes.
        let slot = unsafe { DeviceSlot::<MismatchedDeviceState>::new_unchecked(0) };
        let _guard = state.device_slot_mut(slot);
    }

    #[test]
    fn pmem_layout_ignores_guest_writable_pfn_superblock_geometry() {
        let data_size = 0x4000u64;
        let mut header =
            VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[data_size], &[1]).unwrap();
        test_stamp_device_topology(&mut header, &[DEVICE_KIND_CONSOLE, DEVICE_KIND_PMEM]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut mmap, header).unwrap();
        let mapped = MappedVmState::new(mmap, crate::GUEST_PHYS_ADDR).unwrap();

        let state = mapped.view().unwrap();
        let expected_pmem = state.pmem_device_gpa(0).unwrap();
        let expected_ring = state.ring_gpa().unwrap();
        drop(state);

        let corrupt_dataoff = u64::MAX.to_le_bytes();
        let dataoff_offset = header.pmem_offset as usize
            + super::super::PFN_SB_OFFSET
            + super::super::PFN_SB_DATAOFF;
        // SAFETY: offset targets the PFN superblock inside the freshly allocated mmap.
        unsafe {
            let dst = mapped.unified().offset_mut_ptr(dataoff_offset).unwrap();
            core::ptr::copy_nonoverlapping(corrupt_dataoff.as_ptr(), dst.as_ptr(), 8);
        }

        let state = mapped.view().unwrap();
        assert_eq!(state.pmem_device_gpa(0).unwrap(), expected_pmem);
        assert_eq!(state.ring_gpa().unwrap(), expected_ring);
        let mappings = state.memory_mappings(&[data_size]).unwrap();
        let pmem_header_mapping = mappings
            .iter()
            .find(|mapping| {
                matches!(
                    mapping.source,
                    crate::MapSource::Handle { index: 0, offset }
                        if offset == header.pmem_offset
                )
            })
            .unwrap();
        assert_eq!(pmem_header_mapping.size, header.pmem_data_offsets[0]);
    }

    #[test]
    fn canonical_layout_rejects_oversized_sections() {
        let mut mmap = test_region(256);
        let mut header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        header.vcpu_size += super::super::header::PAGE_SIZE as u64;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("oversized vCPU section must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("vcpu section is not canonical"))
        );
    }

    #[test]
    fn canonical_layout_rejects_noncanonical_pmem_geometry() {
        let data_size = 0x4000u64;
        let mut header =
            VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[data_size], &[1]).unwrap();
        test_stamp_device_topology(&mut header, &[DEVICE_KIND_CONSOLE, DEVICE_KIND_PMEM]);
        header.pmem_data_offsets[0] += super::super::header::PAGE_SIZE as u64;
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("noncanonical PMEM geometry must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("pmem geometry is not canonical"))
        );
    }

    #[test]
    fn canonical_layout_rejects_noncanonical_ring_size() {
        let mut header = VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[], &[]).unwrap();
        test_stamp_device_topology(&mut header, &[]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut mmap, header).unwrap();
        header.ring_size += super::super::header::PAGE_SIZE as u64;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("noncanonical ring size must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("ring section is not canonical"))
        );
    }

    #[test]
    fn device_metadata_validation_rejects_kind_mismatch() {
        let mut mmap = test_mmap_with_device_kinds(TEST_RAM_SIZE, &[DEVICE_KIND_FS]);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        // SAFETY: the test mutates durable metadata before creating a VM-state view.
        unsafe {
            mmap.as_mut_slice()[header.device_meta_offset as usize] = DEVICE_KIND_NET;
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("device metadata kind mismatch must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("device metadata") && message.contains("kind"))
        );
    }

    #[test]
    fn device_metadata_validation_rejects_reserved_bytes() {
        let mut mmap = test_mmap_with_device_kinds(TEST_RAM_SIZE, &[DEVICE_KIND_FS]);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        // SAFETY: the test mutates durable metadata before creating a VM-state view.
        unsafe {
            mmap.as_mut_slice()[header.device_meta_offset as usize + 1] = 1;
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("device metadata reserved bytes must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("reserved device metadata"))
        );
    }

    #[test]
    fn device_metadata_validation_rejects_noncanonical_string_tail() {
        let mut mmap = test_mmap_with_device_kinds(TEST_RAM_SIZE, &[DEVICE_KIND_FS]);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        let tag_offset = header.device_meta_offset as usize + 8;
        // SAFETY: the test mutates durable metadata before creating a VM-state view.
        unsafe {
            mmap.as_mut_slice()[tag_offset] = 0;
            mmap.as_mut_slice()[tag_offset + 1] = b'x';
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("device metadata trailing string bytes must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("NUL terminator"))
        );
    }

    #[test]
    fn device_metadata_validation_rejects_inactive_slot_bytes() {
        let mut mmap = test_mmap_with_device_kinds(TEST_RAM_SIZE, &[DEVICE_KIND_FS]);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        let inactive_slot_offset = header.device_meta_offset as usize
            + header.device_count as usize * DEVICE_META_SLOT_SIZE;
        // SAFETY: the test mutates durable metadata before creating a VM-state view.
        unsafe {
            mmap.as_mut_slice()[inactive_slot_offset] = DEVICE_KIND_NET;
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("inactive device metadata bytes must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("inactive device metadata"))
        );
    }

    #[test]
    fn header_topology_rejects_unknown_active_kind() {
        let mut mmap = test_mmap(TEST_RAM_SIZE);
        let mut header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        header.device_kinds[0] = 99;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("unknown active device kind must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("active device kind"))
        );
    }

    #[test]
    fn header_topology_rejects_inactive_kind_bytes() {
        let mut mmap = test_mmap(TEST_RAM_SIZE);
        let mut header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        header.device_kinds[header.device_count as usize] = DEVICE_KIND_NET;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("inactive device kind bytes must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("inactive device kind"))
        );
    }

    #[test]
    fn header_topology_rejects_zero_active_queue_count() {
        let mut mmap = test_mmap(TEST_RAM_SIZE);
        let mut header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        header.device_queue_counts[0] = 0;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("zero active device queue count must be rejected");
        };
        assert!(matches!(err, VmmError::DeviceConfig(message) if message.contains("queue count")));
    }

    #[test]
    fn header_topology_rejects_pmem_count_without_pmem_slot() {
        let mut mmap = test_mmap(TEST_RAM_SIZE);
        let mut header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        header.device_kinds[0] = DEVICE_KIND_PMEM;
        header.device_queue_counts[0] = 1;
        write_header(&mut mmap, &header);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("PMEM slot/count mismatch must be rejected");
        };
        assert!(matches!(err, VmmError::DeviceConfig(message) if message.contains("pmem_count")));
    }

    #[test]
    fn irqchip_validation_rejects_oversized_blob_len() {
        let mut header = VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[], &[]).unwrap();
        test_stamp_device_topology(&mut header, &[]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut mmap, header).unwrap();
        write_u32(
            &mut mmap,
            header.irqchip_offset as usize,
            super::super::irqchip::IRQCHIP_BLOB_SIZE as u32 + 1,
        );

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("oversized irqchip blob length must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("irqchip arch blob length exceeds section capacity"))
        );
    }

    #[test]
    fn irqchip_validation_rejects_nonzero_padding() {
        let mut header = VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[], &[]).unwrap();
        test_stamp_device_topology(&mut header, &[]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut mmap, header).unwrap();
        write_u32(&mut mmap, header.irqchip_offset as usize + 4, 1);

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("nonzero irqchip padding must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(message) if message.contains("irqchip padding is nonzero"))
        );
    }

    #[test]
    fn pmem_memory_mappings_reject_non_exact_image_sizes() {
        let data_size = 0x4000u64;
        let mut header =
            VmStateHeader::compute(1, 2, 64 * 1024 * 1024, &[data_size], &[1]).unwrap();
        test_stamp_device_topology(&mut header, &[DEVICE_KIND_CONSOLE, DEVICE_KIND_PMEM]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut mmap, header).unwrap();
        let mapped = MappedVmState::new(mmap, crate::GUEST_PHYS_ADDR).unwrap();
        let state = mapped.view().unwrap();

        let too_large = state
            .memory_mappings(&[data_size + super::super::header::PAGE_SIZE as u64])
            .unwrap_err();
        assert!(
            matches!(too_large, VmmError::DeviceConfig(message) if message.contains("image sizes exceed canonical packed data size"))
        );

        let too_small = state
            .memory_mappings(&[data_size - super::super::header::PAGE_SIZE as u64])
            .unwrap_err();
        assert!(
            matches!(too_small, VmmError::DeviceConfig(message) if message.contains("image sizes do not match canonical packed data size"))
        );
    }

    #[test]
    fn irqchip_accessible() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        assert_eq!(state.irqchip().arch_blob().unwrap().len(), 0);
    }

    #[test]
    fn gpa_read_write() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        state.write_obj(0x1000, b"hello").unwrap();
        let gs = state.gpa_read(0x1000, 5).unwrap();
        assert_eq!(gs.to_vec(), b"hello");
    }

    #[test]
    fn gpa_read_obj_write_obj() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let val: u64 = 0xDEAD_BEEF;
        state.write_obj(0x2000, &val).unwrap();
        let read_back: u64 = state.read_obj(0x2000).unwrap();
        assert_eq!(read_back, 0xDEAD_BEEF);
    }

    #[test]
    fn gpa_little_endian_scalar_accessors() {
        let mmap = test_region(256);
        let state = make_state(&mmap);

        let input = [
            0x34, 0x12, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0xef, 0xcd, 0xab, 0x89, 0x67, 0x45,
            0x23, 0x01,
        ];
        state
            .gpa_write(0x3000, input.len())
            .unwrap()
            .write_from(&input);

        assert_eq!(state.read_le_u16(0x3000).unwrap(), 0x1234);
        assert_eq!(state.read_le_u32(0x3004).unwrap(), 0x1234_5678);
        assert_eq!(state.read_le_u64(0x3008).unwrap(), 0x0123_4567_89ab_cdef);

        state.write_le_u16(0x3020, 0x1234).unwrap();
        state.write_le_u32(0x3024, 0x1234_5678).unwrap();
        state.write_le_u64(0x3028, 0x0123_4567_89ab_cdef).unwrap();

        let output = state.gpa_read(0x3020, input.len()).unwrap().to_vec();
        assert_eq!(output, input);
    }

    #[test]
    fn gpa_scalar_accessors_reject_unaligned_addresses() {
        let mmap = test_region(256);
        let state = make_state(&mmap);

        assert!(matches!(
            state.read_le_u16(0x3001),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 2, .. })
        ));
        assert!(matches!(
            state.read_le_u32(0x3002),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 4, .. })
        ));
        assert!(matches!(
            state.read_le_u64(0x3004),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 8, .. })
        ));
        assert!(matches!(
            state.write_le_u16(0x3001, 0),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 2, .. })
        ));
        assert!(matches!(
            state.write_le_u32(0x3002, 0),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 4, .. })
        ));
        assert!(matches!(
            state.write_le_u64(0x3004, 0),
            Err(VmmError::UnalignedGuestMemoryAccess { align: 8, .. })
        ));
    }

    #[test]
    fn psci_power_state_writable() {
        let mmap = test_region(256);
        let mut state = make_state(&mmap);
        assert_eq!(
            state.psci_power_states().load(0, Ordering::Acquire),
            Some(PsciPowerState::On)
        );
        assert_eq!(
            state.psci_power_states().load(1, Ordering::Acquire),
            Some(PsciPowerState::Off)
        );
        assert!(state.set_psci_power_state(1, PsciPowerState::On));
        assert_eq!(
            state.psci_power_states().load(1, Ordering::Acquire),
            Some(PsciPowerState::On)
        );
    }

    #[test]
    fn psci_power_state_table_updates_dedicated_section() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let table = state.psci_power_states();
        assert_eq!(table.len(), 2);
        assert_eq!(table.load(1, Ordering::Acquire), Some(PsciPowerState::Off));
        assert!(table.store(1, PsciPowerState::On, Ordering::Release));
        assert_eq!(
            state.psci_power_states().load(1, Ordering::Acquire),
            Some(PsciPowerState::On)
        );
    }

    #[test]
    fn validated_metadata_rejects_invalid_psci_section_state() {
        let mmap = test_region(256);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        // SAFETY: offset targets the initialized PSCI section inside this
        // test mmap, before any shared `VmState` view is created.
        unsafe {
            mmap.offset_mut_ptr(header.psci_offset as usize + 1)
                .unwrap()
                .as_ptr()
                .write(0xff);
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("invalid PSCI state must be rejected");
        };
        assert!(matches!(err, VmmError::DeviceConfig(msg) if msg.contains("invalid PSCI")));
    }

    #[test]
    fn validated_metadata_rejects_corrupt_primary_ram_descriptor() {
        let mmap = test_region(256);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        // SAFETY: offset targets the initialized primary RAM descriptor inside
        // this test mmap, before any shared `VmState` view is created.
        unsafe {
            let hdr = super::super::ram_descriptor::RamDescriptorHeader {
                block_size: u32::try_from(super::super::ram_descriptor::BITMAP_BLOCK_SIZE).unwrap(),
                block_count: 0,
                reserved: [0],
            };
            let ptr = mmap
                .offset_mut_ptr(header.ram_desc_offset as usize)
                .unwrap()
                .as_ptr();
            std::ptr::copy_nonoverlapping(
                bytemuck::bytes_of(&hdr).as_ptr(),
                ptr,
                size_of::<super::super::ram_descriptor::RamDescriptorHeader>(),
            );
        }

        let Err(err) = ValidatedMetadata::parse(&mmap) else {
            panic!("corrupt primary RAM descriptor must be rejected");
        };
        assert!(
            matches!(err, VmmError::DeviceConfig(ref msg) if msg.contains("RAM descriptor")),
            "unexpected error: {err:?}",
        );
    }

    #[test]
    fn zero_length_gpa_access() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let gs = state.gpa_read(0xFFFF_FFFF, 0).unwrap();
        assert!(gs.is_empty());
        let gw = state.gpa_write(0xFFFF_FFFF, 0).unwrap();
        assert!(gw.is_empty());
    }

    #[test]
    fn alignment_check_catches_misaligned() {
        let mmap = test_region(256);
        let state = make_state(&mmap);
        let _ = state.header();
    }

    #[test]
    fn empty_guest_memory_metadata_only() {
        let mmap = test_region(256);
        let validated = ValidatedMetadata::parse(&mmap).unwrap();
        let state = VmState::new(
            &validated,
            ValidatedGuestMemory::new(vec![]).unwrap(),
            ValidatedHotplugRegions::empty(),
            Arc::new(DeviceSlotLocks::new()),
            #[cfg(debug_assertions)]
            Arc::new(BorrowTracker::new()),
        );
        assert_eq!(state.header().magic, VM_STATE_MAGIC);
        assert_eq!(state.guest_region_count(), 0);
        // GPA access should fail with no guest memory.
        assert!(state.gpa_read(0x1000, 4).is_err());
    }

    #[test]
    fn validated_guest_memory_rejects_unbacked_and_out_of_bounds_mappings() {
        let mmap = test_region(256);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();

        let anonymous = crate::MemoryMapping {
            source: crate::MapSource::AnonymousZero,
            size: 0x1000,
            gpa: 0,
            readonly: false,
        };
        assert!(matches!(
            ValidatedGuestMemory::new(vec![(&mmap, anonymous)]),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("source must be handle-backed")
        ));

        let out_of_bounds = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: mmap.len() as u64,
            },
            size: 1,
            gpa: 0,
            readonly: false,
        };
        assert!(matches!(
            ValidatedGuestMemory::new(vec![(&mmap, out_of_bounds)]),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("host range extends past mmap")
        ));

        let gpa_overflow = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: header.ram_offset,
            },
            size: 2,
            gpa: u64::MAX - 1,
            readonly: false,
        };
        assert!(matches!(
            ValidatedGuestMemory::new(vec![(&mmap, gpa_overflow)]),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("GPA end overflow")
        ));
    }

    #[test]
    fn validated_guest_memory_rejects_overlapping_mappings() {
        let mmap = test_region(256);
        let header = *ValidatedMetadata::parse(&mmap).unwrap().header();
        let first = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: header.ram_offset,
            },
            size: 0x2000,
            gpa: 0x1000,
            readonly: false,
        };
        let second = crate::MemoryMapping {
            source: crate::MapSource::Handle {
                index: 0,
                offset: header.ram_offset + 0x2000,
            },
            size: 0x1000,
            gpa: 0x2000,
            readonly: false,
        };

        assert!(matches!(
            ValidatedGuestMemory::new(vec![(&mmap, second), (&mmap, first)]),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("overlaps previous mapping")
        ));
    }

    fn write_hotplug_header(
        region: &mut amla_mem::MmapSlice,
        header: super::super::ram_descriptor::RamDescriptorHeader,
    ) {
        // SAFETY: test helper writes exactly one header into a freshly allocated mmap.
        unsafe {
            core::ptr::copy_nonoverlapping(
                bytemuck::bytes_of(&header).as_ptr(),
                region.as_mut_ptr(),
                size_of::<super::super::ram_descriptor::RamDescriptorHeader>(),
            );
        }
    }

    #[test]
    fn mapped_vm_state_rejects_malformed_hotplug_descriptor() {
        let unified = test_region(256);
        let mut hotplug = amla_mem::MmapSlice::anonymous_rw(4096).unwrap();
        write_hotplug_header(
            &mut hotplug,
            super::super::ram_descriptor::RamDescriptorHeader {
                block_size: 4096,
                block_count: 1,
                reserved: [0],
            },
        );

        assert!(matches!(
            MappedVmState::with_hotplug_ram(
                unified,
                Vec::new(),
                vec![hotplug],
                crate::GUEST_PHYS_ADDR,
            ),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("block_size is invalid")
        ));
    }

    #[test]
    fn mapped_vm_state_rejects_truncated_hotplug_descriptor_section() {
        let unified = test_region(256);
        let mut hotplug = amla_mem::MmapSlice::anonymous_rw(size_of::<
            super::super::ram_descriptor::RamDescriptorHeader,
        >())
        .unwrap();
        write_hotplug_header(
            &mut hotplug,
            super::super::ram_descriptor::RamDescriptorHeader {
                block_size: super::super::ram_descriptor::BITMAP_BLOCK_SIZE as u32,
                block_count: 1,
                reserved: [0],
            },
        );

        assert!(matches!(
            MappedVmState::with_hotplug_ram(
                unified,
                Vec::new(),
                vec![hotplug],
                crate::GUEST_PHYS_ADDR,
            ),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("extends past region")
        ));
    }

    #[test]
    fn mapped_vm_state_rejects_hotplug_ram_size_past_region() {
        let unified = test_region(256);
        let ram_size = super::super::ram_descriptor::RamSize::new(
            super::super::ram_descriptor::BITMAP_BLOCK_SIZE,
        )
        .unwrap();
        let desc_size = super::super::ram_descriptor::ram_desc_section_size(ram_size);
        let mut hotplug = amla_mem::MmapSlice::anonymous_rw(desc_size as usize).unwrap();
        write_hotplug_header(
            &mut hotplug,
            super::super::ram_descriptor::RamDescriptorHeader {
                block_size: u32::try_from(super::super::ram_descriptor::BITMAP_BLOCK_SIZE).unwrap(),
                block_count: 1,
                reserved: [0],
            },
        );

        assert!(matches!(
            MappedVmState::with_hotplug_ram(
                unified,
                Vec::new(),
                vec![hotplug],
                crate::GUEST_PHYS_ADDR,
            ),
            Err(VmmError::DeviceConfig(msg)) if msg.contains("RAM extends past region")
        ));
    }

    #[test]
    fn mapped_vm_state_does_not_treat_pmem_images_as_hotplug() {
        let mut header = VmStateHeader::compute(1, 1, 64 * 1024 * 1024, &[4096], &[1]).unwrap();
        test_stamp_device_topology(&mut header, &[DEVICE_KIND_PMEM]);
        let mut unified = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        VmState::init_region(&mut unified, header).unwrap();

        // PMEM image backing maps in the VMM are not
        // hotplug RAM descriptor regions and may begin with arbitrary image
        // bytes that would be invalid as a RamDescriptorHeader.
        let pmem_image = amla_mem::MmapSlice::anonymous_rw(4096).unwrap();
        let mapped =
            MappedVmState::with_pmem_images(unified, vec![pmem_image], crate::GUEST_PHYS_ADDR)
                .unwrap();
        let state = mapped.view().unwrap();

        assert_eq!(state.hotplug_usable_size(), 0);
    }

    #[test]
    fn init_region_rejects_too_short_region() {
        let mut header = VmStateHeader::compute(1, 1, 64 * 1024 * 1024, &[], &[]).unwrap();
        test_stamp_device_topology(&mut header, &[]);
        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize - 1).unwrap();

        assert!(matches!(
            VmState::init_region(&mut mmap, header),
            Err(VmmError::DeviceConfig(_))
        ));
    }
}
