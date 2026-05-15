// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Trait-based guest memory access with volatile semantics.
//!
//! Guest RAM is concurrently modified by vCPUs and accessed by multiple
//! devices. Rust references (`&[u8]`, `&mut [u8]`) into guest memory are
//! unsound under the aliasing model. This module provides:
//!
//! - [`GuestMemory`]: trait for GPA-based memory access (implemented by `VmState`)
//! - [`GuestRead`] / [`GuestWrite`]: traits for volatile read/write views
//! - [`VolatileSlice`] / [`VolatileSliceMut`]: production impls using `read_volatile`/`write_volatile`
//!
//! Bulk guest memory access uses volatile copies. Protocol metadata that has
//! fixed access-width requirements uses the explicit little-endian scalar
//! methods on [`GuestMemory`].

use bytemuck::Pod;
use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::ptr::NonNull;

use crate::VmmError;

// =============================================================================
// Volatile helpers (internal)
// =============================================================================

/// Volatile copy from guest memory to host buffer.
///
/// Three-phase: align to 8-byte boundary → u64 volatile loads → byte tail.
/// Each `read_volatile` is one atomic-width load the compiler cannot split,
/// elide, or reorder. This gives 8x throughput vs byte-at-a-time for bulk
/// copies (e.g. 1500-byte network frames: ~188 loads instead of 1500).
///
/// Alignment note: `read_obj<T>` calls this with arbitrary guest GPAs.
/// Unaligned GPAs are handled correctly — phase 1 aligns the source pointer,
/// so the u64 loads in phase 2 are always naturally aligned.
pub(crate) fn volatile_read(src: *const u8, dst: &mut [u8]) {
    let len = dst.len();
    let mut i = 0;

    // Phase 1: byte-at-a-time until src is 8-byte aligned.
    let misalign = (src as usize) % 8;
    if misalign != 0 {
        let align_end = (8 - misalign).min(len);
        while i < align_end {
            // SAFETY: `src` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
            dst[i] = unsafe { src.add(i).read_volatile() };
            i += 1;
        }
    }

    // Phase 2: u64 volatile reads (src + i is now 8-byte aligned).
    // Use ptr::add to preserve provenance (usize round-trips erase it).
    while i + 8 <= len {
        #[allow(clippy::cast_ptr_alignment)] // Phase 1 aligned i to 8 bytes
        // SAFETY: `src` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        let val = unsafe { core::ptr::read_volatile(src.add(i).cast::<u64>()) };
        dst[i..i + 8].copy_from_slice(&val.to_ne_bytes());
        i += 8;
    }

    // Phase 3: remaining tail bytes.
    while i < len {
        // SAFETY: `src` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        dst[i] = unsafe { src.add(i).read_volatile() };
        i += 1;
    }
}

/// Volatile copy from host buffer to guest memory.
///
/// Same three-phase align → u64 → tail pattern as `volatile_read`.
pub(crate) fn volatile_write(dst: *mut u8, src: &[u8]) {
    let len = src.len();
    let mut i = 0;

    // Phase 1: byte-at-a-time until dst is 8-byte aligned.
    let misalign = (dst as usize) % 8;
    if misalign != 0 {
        let align_end = (8 - misalign).min(len);
        while i < align_end {
            // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
            unsafe { dst.add(i).write_volatile(src[i]) };
            i += 1;
        }
    }

    // Phase 2: u64 volatile writes (dst + i is now 8-byte aligned).
    // Use ptr::add to preserve provenance (usize round-trips erase it).
    while i + 8 <= len {
        let val = u64::from_ne_bytes([
            src[i],
            src[i + 1],
            src[i + 2],
            src[i + 3],
            src[i + 4],
            src[i + 5],
            src[i + 6],
            src[i + 7],
        ]);
        #[allow(clippy::cast_ptr_alignment)] // Phase 1 aligned i to 8 bytes
        // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe {
            core::ptr::write_volatile(dst.add(i).cast::<u64>(), val);
        }
        i += 8;
    }

    // Phase 3: remaining tail bytes.
    while i < len {
        // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe { dst.add(i).write_volatile(src[i]) };
        i += 1;
    }
}

/// Volatile fill of guest memory.
///
/// Uses u64 fills for the aligned middle, byte fills for head/tail.
pub(crate) fn volatile_fill(dst: *mut u8, val: u8, len: usize) {
    let mut i = 0;
    let fill8 = u64::from_ne_bytes([val; 8]);

    // Phase 1: byte-at-a-time until dst is 8-byte aligned.
    let misalign = (dst as usize) % 8;
    if misalign != 0 {
        let align_end = (8 - misalign).min(len);
        while i < align_end {
            // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
            unsafe { dst.add(i).write_volatile(val) };
            i += 1;
        }
    }

    // Phase 2: u64 volatile fills (dst + i is now 8-byte aligned).
    // Use ptr::add to preserve provenance (usize round-trips erase it).
    while i + 8 <= len {
        #[allow(clippy::cast_ptr_alignment)] // Phase 1 aligned i to 8 bytes
        // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe {
            core::ptr::write_volatile(dst.add(i).cast::<u64>(), fill8);
        }
        i += 8;
    }

    // Phase 3: remaining tail bytes.
    while i < len {
        // SAFETY: `dst` points to at least `len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe { dst.add(i).write_volatile(val) };
        i += 1;
    }
}

// =============================================================================
// Traits
// =============================================================================

/// Backend for guest physical memory access.
///
/// Parameterizes the virtio stack so devices work with any memory backend:
/// - Production: `VmState` with volatile raw-pointer access
/// - Testing: `MockMemory` with TOCTOU fault injection
pub trait GuestMemory {
    /// Read view type (volatile in production, mockable in tests).
    type Slice<'m>: GuestRead + 'm
    where
        Self: 'm;
    /// Write view type.
    type SliceMut<'m>: GuestWrite + 'm
    where
        Self: 'm;

    /// Get a read view at guest physical address `addr` for `len` bytes.
    fn gpa_read(&self, addr: u64, len: usize) -> Result<Self::Slice<'_>, VmmError>;

    /// Get a write view at guest physical address `addr` for `len` bytes.
    fn gpa_write(&self, addr: u64, len: usize) -> Result<Self::SliceMut<'_>, VmmError>;

    /// Read a typed value from guest memory (volatile copy to stack).
    ///
    /// This is a bulk POD copy helper. Shared protocol metadata that requires
    /// fixed access width or little-endian conversion must use the scalar
    /// methods below.
    fn read_obj<T: Pod>(&self, addr: u64) -> Result<T, VmmError>;

    /// Write a typed value to guest memory (volatile copy from stack).
    ///
    /// This is a bulk POD copy helper. Shared protocol metadata that requires
    /// fixed access width or little-endian conversion must use the scalar
    /// methods below.
    fn write_obj<T: bytemuck::NoUninit>(&self, addr: u64, val: &T) -> Result<(), VmmError>;

    /// Read one little-endian 16-bit protocol field from guest memory.
    ///
    /// Production implementations must perform one naturally aligned volatile
    /// load of the scalar width. This is for shared metadata such as virtqueue
    /// indices where byte-wise copies can tear relative to guest vCPUs.
    fn read_le_u16(&self, addr: u64) -> Result<u16, VmmError>;

    /// Read one little-endian 32-bit protocol field from guest memory.
    fn read_le_u32(&self, addr: u64) -> Result<u32, VmmError>;

    /// Read one little-endian 64-bit protocol field from guest memory.
    fn read_le_u64(&self, addr: u64) -> Result<u64, VmmError>;

    /// Write one little-endian 16-bit protocol field to guest memory.
    ///
    /// Production implementations must perform one naturally aligned volatile
    /// store of the scalar width.
    fn write_le_u16(&self, addr: u64, val: u16) -> Result<(), VmmError>;

    /// Write one little-endian 32-bit protocol field to guest memory.
    fn write_le_u32(&self, addr: u64, val: u32) -> Result<(), VmmError>;

    /// Write one little-endian 64-bit protocol field to guest memory.
    fn write_le_u64(&self, addr: u64, val: u64) -> Result<(), VmmError>;

    /// Validate that a later [`Self::write_le_u16`] at `addr` can use the
    /// required scalar store shape without mutating guest memory.
    fn validate_write_le_u16(&self, addr: u64) -> Result<(), VmmError> {
        self.validate_write_range(addr, core::mem::size_of::<u16>())
    }

    /// Validate that a later [`Self::write_le_u32`] at `addr` can use the
    /// required scalar store shape without mutating guest memory.
    fn validate_write_le_u32(&self, addr: u64) -> Result<(), VmmError> {
        self.validate_write_range(addr, core::mem::size_of::<u32>())
    }

    /// Validate that `[addr, addr+len)` can be read from guest RAM.
    fn validate_read_range(&self, addr: u64, len: usize) -> Result<(), VmmError>;

    /// Validate that `[addr, addr+len)` can be written to guest RAM.
    fn validate_write_range(&self, addr: u64, len: usize) -> Result<(), VmmError>;
}

/// Read view into guest memory — never creates `&[u8]`.
///
/// All reads use volatile semantics. After copying to a host buffer,
/// the host buffer is non-volatile and can be used normally.
pub trait GuestRead: Sized + Clone {
    /// Volatile copy to caller-provided buffer. Panics on length mismatch.
    fn read_to(&self, buf: &mut [u8]);

    /// Volatile copy to a new `Vec<u8>`.
    fn to_vec(&self) -> Vec<u8>;

    /// Volatile read of one byte at offset.
    fn read_byte(&self, offset: usize) -> u8;

    /// Length in bytes.
    fn len(&self) -> usize;

    /// Whether the slice is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sub-slice at byte offset.
    #[must_use]
    fn offset(&self, off: usize, len: usize) -> Self;

    /// Volatile copy, appending to an existing `Vec`.
    fn extend_vec(&self, vec: &mut Vec<u8>);
}

/// Write view into guest memory — never creates `&mut [u8]`.
///
/// All writes use volatile semantics.
pub trait GuestWrite: Sized {
    /// Volatile copy from host slice. Panics on length mismatch.
    fn write_from(&self, data: &[u8]);

    /// Volatile copy from host slice at byte offset within this view.
    fn write_at(&self, off: usize, data: &[u8]);

    /// Volatile write of one byte at offset.
    fn write_byte(&self, offset: usize, val: u8);

    /// Volatile fill with a byte value.
    fn fill(&self, val: u8);

    /// Length in bytes.
    fn len(&self) -> usize;

    /// Whether the slice is empty.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Sub-slice at byte offset.
    #[must_use]
    fn offset(self, off: usize, len: usize) -> Self;
}

// =============================================================================
// Resolved guest memory proofs
// =============================================================================

/// Resolved readable guest-memory range.
pub(crate) struct ResolvedGuestRead<'m> {
    ptr: NonNull<u8>,
    len: usize,
    _memory: PhantomData<&'m [UnsafeCell<u8>]>,
}

impl<'m> ResolvedGuestRead<'m> {
    /// Construct a resolved readable guest range.
    ///
    /// # Safety
    ///
    /// `ptr` must point to at least `len` readable bytes that remain mapped
    /// for the lifetime of `owner`. If `len > 0`, `ptr` must be non-null.
    pub(crate) const unsafe fn from_raw_parts(
        ptr: *const u8,
        len: usize,
        _owner: &'m impl ?Sized,
    ) -> Self {
        let ptr = if len == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: required by this function's safety contract.
            unsafe { NonNull::new_unchecked(ptr.cast_mut()) }
        };
        Self {
            ptr,
            len,
            _memory: PhantomData,
        }
    }

    /// Raw pointer for volatile reads.
    pub(crate) const fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr().cast_const()
    }
}

/// Resolved writable guest-memory range.
pub(crate) struct ResolvedGuestWrite<'m> {
    ptr: NonNull<u8>,
    len: usize,
    _memory: PhantomData<&'m UnsafeCell<[u8]>>,
}

impl<'m> ResolvedGuestWrite<'m> {
    /// Construct a resolved writable guest range.
    ///
    /// # Safety
    ///
    /// `ptr` must point to at least `len` writable bytes that remain mapped
    /// for the lifetime of `owner`. If `len > 0`, `ptr` must be non-null.
    pub(crate) const unsafe fn from_raw_parts(
        ptr: *mut u8,
        len: usize,
        _owner: &'m impl ?Sized,
    ) -> Self {
        let ptr = if len == 0 {
            NonNull::dangling()
        } else {
            // SAFETY: required by this function's safety contract.
            unsafe { NonNull::new_unchecked(ptr) }
        };
        Self {
            ptr,
            len,
            _memory: PhantomData,
        }
    }

    /// Raw pointer for volatile writes.
    pub(crate) const fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

// =============================================================================
// VolatileSlice — production read impl
// =============================================================================

/// Volatile read view into guest memory via raw pointer.
///
/// Never creates `&[u8]`. All reads go through `read_volatile`.
/// The lifetime ties the raw pointer view to the [`GuestMemory`] borrow that
/// produced it, so it cannot outlive the mapped VM memory.
#[derive(Clone, Copy)]
pub struct VolatileSlice<'m> {
    ptr: NonNull<u8>,
    len: usize,
    _memory: PhantomData<&'m [UnsafeCell<u8>]>,
}

// SAFETY: Points to mmap'd guest memory shared across threads.
// Access is volatile — no Rust aliasing assumptions.
unsafe impl Send for VolatileSlice<'_> {}
// SAFETY: see `Send` impl above — all access is volatile, so shared access
// from multiple threads does not violate Rust's aliasing model.
unsafe impl Sync for VolatileSlice<'_> {}

impl<'m> VolatileSlice<'m> {
    /// Construct from a resolved guest-memory range.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) const fn from_resolved(resolved: ResolvedGuestRead<'m>) -> Self {
        let ResolvedGuestRead {
            ptr,
            len,
            _memory: _,
        } = resolved;
        Self {
            ptr,
            len,
            _memory: PhantomData,
        }
    }
}

impl GuestRead for VolatileSlice<'_> {
    fn read_to(&self, buf: &mut [u8]) {
        assert_eq!(
            buf.len(),
            self.len,
            "VolatileSlice::read_to length mismatch"
        );
        volatile_read(self.ptr.as_ptr().cast_const(), buf);
    }

    fn to_vec(&self) -> Vec<u8> {
        let mut v = vec![0u8; self.len];
        volatile_read(self.ptr.as_ptr().cast_const(), &mut v);
        v
    }

    fn read_byte(&self, offset: usize) -> u8 {
        assert!(offset < self.len, "VolatileSlice::read_byte OOB");
        // SAFETY: `self.ptr` points to at least `self.len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe { self.ptr.as_ptr().add(offset).read_volatile() }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn offset(&self, off: usize, len: usize) -> Self {
        assert!(
            off.checked_add(len).is_some_and(|end| end <= self.len),
            "VolatileSlice::offset OOB"
        );
        Self {
            // SAFETY: bounds-checked above; result stays within the backing allocation.
            ptr: unsafe { NonNull::new_unchecked(self.ptr.as_ptr().add(off)) },
            len,
            _memory: PhantomData,
        }
    }

    fn extend_vec(&self, vec: &mut Vec<u8>) {
        let old_len = vec.len();
        vec.resize(old_len + self.len, 0);
        volatile_read(self.ptr.as_ptr().cast_const(), &mut vec[old_len..]);
    }
}

// =============================================================================
// VolatileSliceMut — production write impl
// =============================================================================

/// Volatile write view into guest memory via raw pointer.
///
/// Never creates `&mut [u8]`. All writes go through `write_volatile`.
pub struct VolatileSliceMut<'m> {
    ptr: NonNull<u8>,
    len: usize,
    _memory: PhantomData<&'m UnsafeCell<[u8]>>,
}

// SAFETY: Points to mmap'd guest memory shared across threads.
// Access is volatile — no Rust aliasing assumptions.
unsafe impl Send for VolatileSliceMut<'_> {}
impl<'m> VolatileSliceMut<'m> {
    /// Construct from a resolved guest-memory range.
    #[allow(clippy::needless_pass_by_value)]
    pub(crate) const fn from_resolved(resolved: ResolvedGuestWrite<'m>) -> Self {
        let ResolvedGuestWrite {
            ptr,
            len,
            _memory: _,
        } = resolved;
        Self {
            ptr,
            len,
            _memory: PhantomData,
        }
    }
}

impl GuestWrite for VolatileSliceMut<'_> {
    fn write_from(&self, data: &[u8]) {
        assert_eq!(
            data.len(),
            self.len,
            "VolatileSliceMut::write_from length mismatch"
        );
        volatile_write(self.ptr.as_ptr(), data);
    }

    fn write_at(&self, off: usize, data: &[u8]) {
        assert!(
            off.checked_add(data.len())
                .is_some_and(|end| end <= self.len),
            "VolatileSliceMut::write_at OOB"
        );
        // SAFETY: bounds-checked above; result stays within the backing allocation.
        volatile_write(unsafe { self.ptr.as_ptr().add(off) }, data);
    }

    fn write_byte(&self, offset: usize, val: u8) {
        assert!(offset < self.len, "VolatileSliceMut::write_byte OOB");
        // SAFETY: `self.ptr` points to at least `self.len` bytes of guest-mapped memory (bounds checked above); volatile ensures no read/write coalescing across the MMIO boundary.
        unsafe { self.ptr.as_ptr().add(offset).write_volatile(val) };
    }

    fn fill(&self, val: u8) {
        volatile_fill(self.ptr.as_ptr(), val, self.len);
    }

    fn len(&self) -> usize {
        self.len
    }

    fn offset(self, off: usize, len: usize) -> Self {
        assert!(
            off.checked_add(len).is_some_and(|end| end <= self.len),
            "VolatileSliceMut::offset OOB"
        );
        Self {
            // SAFETY: bounds-checked above; result stays within the backing allocation.
            ptr: unsafe { NonNull::new_unchecked(self.ptr.as_ptr().add(off)) },
            len,
            _memory: PhantomData,
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use core::cell::UnsafeCell;

    fn volatile_slice(data: &[u8]) -> VolatileSlice<'_> {
        // SAFETY: `data.as_ptr()` covers exactly `data.len()` bytes and is
        // tied to the returned slice lifetime by the owner argument.
        let resolved =
            unsafe { ResolvedGuestRead::from_raw_parts(data.as_ptr(), data.len(), data) };
        VolatileSlice::from_resolved(resolved)
    }

    fn volatile_slice_mut<const N: usize>(data: &UnsafeCell<[u8; N]>) -> VolatileSliceMut<'_> {
        // SAFETY: `data` is an UnsafeCell-backed byte array of exactly `N`
        // bytes and is tied to the returned slice lifetime by the owner.
        let resolved =
            unsafe { ResolvedGuestWrite::from_raw_parts(data.get().cast::<u8>(), N, data) };
        VolatileSliceMut::from_resolved(resolved)
    }

    fn cell_bytes<const N: usize>(data: &UnsafeCell<[u8; N]>) -> [u8; N] {
        // SAFETY: tests are single-threaded and all writes go through the
        // volatile view before this copy.
        unsafe { *data.get() }
    }

    #[test]
    fn volatile_slice_read_to() {
        let data = [1u8, 2, 3, 4, 5];
        let vs = volatile_slice(&data);
        let mut buf = [0u8; 5];
        vs.read_to(&mut buf);
        assert_eq!(buf, data);
    }

    #[test]
    fn volatile_slice_to_vec() {
        let data = [10u8, 20, 30];
        let vs = volatile_slice(&data);
        assert_eq!(vs.to_vec(), vec![10, 20, 30]);
    }

    #[test]
    fn volatile_slice_read_byte() {
        let data = [0xAAu8, 0xBB, 0xCC];
        let vs = volatile_slice(&data);
        assert_eq!(vs.read_byte(0), 0xAA);
        assert_eq!(vs.read_byte(2), 0xCC);
    }

    #[test]
    fn volatile_slice_offset() {
        let data = [1u8, 2, 3, 4, 5];
        let vs = volatile_slice(&data);
        let sub = vs.offset(2, 2);
        assert_eq!(sub.to_vec(), vec![3, 4]);
    }

    #[test]
    fn volatile_slice_extend_vec() {
        let data = [7u8, 8, 9];
        let vs = volatile_slice(&data);
        let mut v = vec![1, 2, 3];
        vs.extend_vec(&mut v);
        assert_eq!(v, vec![1, 2, 3, 7, 8, 9]);
    }

    #[test]
    fn volatile_slice_mut_write_from() {
        let data = UnsafeCell::new([0u8; 4]);
        let vs = volatile_slice_mut(&data);
        vs.write_from(&[1, 2, 3, 4]);
        assert_eq!(cell_bytes(&data), [1, 2, 3, 4]);
    }

    #[test]
    fn volatile_slice_mut_write_at() {
        let data = UnsafeCell::new([0u8; 5]);
        let vs = volatile_slice_mut(&data);
        vs.write_at(2, &[0xAA, 0xBB]);
        assert_eq!(cell_bytes(&data), [0, 0, 0xAA, 0xBB, 0]);
    }

    #[test]
    fn volatile_slice_mut_write_byte() {
        let data = UnsafeCell::new([0u8; 3]);
        let vs = volatile_slice_mut(&data);
        vs.write_byte(1, 0xFF);
        assert_eq!(cell_bytes(&data), [0, 0xFF, 0]);
    }

    #[test]
    fn volatile_slice_mut_fill() {
        let data = UnsafeCell::new([0u8; 4]);
        let vs = volatile_slice_mut(&data);
        vs.fill(0x42);
        assert_eq!(cell_bytes(&data), [0x42; 4]);
    }

    #[test]
    fn volatile_slice_mut_offset() {
        let data = UnsafeCell::new([0u8; 6]);
        let vs = volatile_slice_mut(&data);
        let sub = vs.offset(3, 2);
        sub.write_from(&[0xDE, 0xAD]);
        assert_eq!(cell_bytes(&data), [0, 0, 0, 0xDE, 0xAD, 0]);
    }

    #[test]
    fn zero_length_slices() {
        let owner = ();
        // SAFETY: zero-length slices never dereference the dangling pointer;
        // the owner borrow still constrains the returned lifetime.
        let resolved = unsafe {
            ResolvedGuestRead::from_raw_parts(core::ptr::NonNull::dangling().as_ptr(), 0, &owner)
        };
        let vs = VolatileSlice::from_resolved(resolved);
        assert!(vs.is_empty());
        assert_eq!(vs.to_vec(), Vec::<u8>::new());

        let mut_owner: UnsafeCell<[u8; 0]> = UnsafeCell::new([]);
        // SAFETY: zero-length slices never dereference the dangling pointer;
        // the owner borrow still constrains the returned lifetime.
        let resolved = unsafe {
            ResolvedGuestWrite::from_raw_parts(
                core::ptr::NonNull::dangling().as_ptr(),
                0,
                &mut_owner,
            )
        };
        let vsm = VolatileSliceMut::from_resolved(resolved);
        assert!(vsm.is_empty());
        vsm.write_from(&[]);
    }
}
