// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Bounds-checked guest memory writer for boot setup.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-boot-x86 requires a 64-bit host");

use std::ptr::NonNull;

use crate::x86_64::builder::{BootError, Result};
use crate::x86_64::memory::RamBackingRange;

/// Writer for RAM backing memory with bounds checking.
///
/// Consolidates raw pointer operations for boot setup into a single
/// type that tracks the memory region bounds. All writes are performed
/// using unaligned operations (little-endian) suitable for x86.
///
/// All writes are bounds-checked and return an error if the write would
/// exceed the memory region.
pub struct GuestMemWriter {
    base: NonNull<u8>,
    size: usize,
}

#[derive(Debug, Clone, Copy)]
struct GuestMemRange {
    offset: usize,
    len: usize,
}

impl GuestMemWriter {
    /// Create a new writer for the given memory region.
    ///
    /// # Safety
    ///
    /// Caller must ensure `base` points to valid memory of at least `size` bytes.
    #[inline]
    #[must_use]
    pub const unsafe fn new(base: NonNull<u8>, size: usize) -> Self {
        Self { base, size }
    }

    /// Write a byte slice at a validated RAM backing range.
    #[inline]
    pub(crate) fn write_at(&self, dst: RamBackingRange, data: &[u8]) -> Result<()> {
        if dst.len() != data.len() {
            return Err(BootError::InvalidBootMemory {
                reason: format!(
                    "backing write length {} does not match range length {}",
                    data.len(),
                    dst.len()
                ),
            });
        }
        let range = self.checked_range(dst.offset(), dst.len())?;
        // SAFETY: `range` proves the destination bytes are within this memory region.
        // `ptr::copy` permits overlap, so this safe API does not require callers to
        // prove `data` is disjoint from guest memory.
        unsafe {
            std::ptr::copy(
                data.as_ptr(),
                self.base.as_ptr().add(range.offset),
                range.len,
            );
        }
        Ok(())
    }

    /// Zero a validated RAM backing range.
    #[inline]
    pub(crate) fn zero_at(&self, dst: RamBackingRange) -> Result<()> {
        let range = self.checked_range(dst.offset(), dst.len())?;
        // SAFETY: `range` proves the destination bytes are within this memory region.
        unsafe {
            std::ptr::write_bytes(self.base.as_ptr().add(range.offset), 0, range.len);
        }
        Ok(())
    }

    /// Read a validated RAM backing range.
    #[inline]
    pub(crate) fn read_at(&self, src: RamBackingRange) -> Result<&[u8]> {
        let range = self.checked_range(src.offset(), src.len())?;
        // SAFETY: `range` proves the source bytes are within this memory region.
        Ok(unsafe { std::slice::from_raw_parts(self.base.as_ptr().add(range.offset), range.len) })
    }

    #[inline]
    fn checked_range(&self, offset: usize, len: usize) -> Result<GuestMemRange> {
        let end = offset
            .checked_add(len)
            .ok_or(BootError::GuestMemoryOutOfBounds {
                offset: offset as u64,
                len,
                mem_size: self.size,
            })?;
        if end > self.size {
            return Err(BootError::GuestMemoryOutOfBounds {
                offset: offset as u64,
                len,
                mem_size: self.size,
            });
        }
        Ok(GuestMemRange { offset, len })
    }
}
