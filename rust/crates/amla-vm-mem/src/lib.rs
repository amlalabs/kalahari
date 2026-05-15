// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

// Require documentation for all public items
#![deny(missing_docs)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Cross-platform guest memory backing with copy-on-write branching.
//!
//! Core types:
//!
//! - [`MemHandle`] — fd ownership, `CoW` branching (`branch()`), page release (`punch_hole()`)
//! - [`PageAlignedLen`] and [`PageRange`] — checked memory length/range proofs
//! - [`MmapSlice`] — RAII mmap wrapper (read-only or shared RW via [`map_handle`])
//!
//! # Example
//!
//! ```ignore
//! use amla_mem::{MemHandle, backing::map_handle};
//!
//! let handle = MemHandle::allocate(c"vm-mem", size)?;
//! let mmap = map_handle(&handle)?;
//! let child = unsafe { handle.branch()? };  // CoW branch
//! ```

pub mod backing;
pub mod error;
mod handle;
pub mod platform;
pub use backing::{MmapSlice, map_handle};
pub use error::{MemError, Result};
pub use handle::MemHandle;

// Re-export platform-specific types.
#[cfg(windows)]
pub use platform::SectionObject;

/// Get the system page size (cached after first call).
#[cfg(unix)]
#[inline]
pub fn page_size() -> usize {
    rustix::param::page_size()
}

/// Get the system page size (Windows: via `GetSystemInfo`).
#[cfg(windows)]
#[inline]
pub fn page_size() -> usize {
    use std::sync::OnceLock;
    static PAGE_SIZE: OnceLock<usize> = OnceLock::new();
    *PAGE_SIZE.get_or_init(|| {
        // SAFETY: SYSTEM_INFO is a plain POD struct with no validity
        // invariants; GetSystemInfo below overwrites every field.
        let mut info = unsafe {
            std::mem::zeroed::<windows_sys::Win32::System::SystemInformation::SYSTEM_INFO>()
        };
        // SAFETY: `&mut info` is a valid, writable pointer to a SYSTEM_INFO
        // on the stack; GetSystemInfo requires exactly this.
        unsafe {
            windows_sys::Win32::System::SystemInformation::GetSystemInfo(&mut info);
        }
        info.dwPageSize as usize
    })
}

/// A non-zero `usize` guaranteed to be a multiple of the native page size.
///
/// Use [`PageAlignedLen::round_up`] when callers intentionally accept
/// page-rounding, or [`PageAlignedLen::from_page_aligned`] when the input must
/// already carry the proof. Both constructors reject zero and overflow.
///
/// Derefs to `usize` for existing arithmetic and comparison call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PageAlignedLen(usize);

impl PageAlignedLen {
    /// Round `size` up to the next native page boundary.
    #[inline]
    pub fn round_up(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(MemError::InvalidSize {
                size,
                reason: "page-aligned length must be non-zero",
            });
        }
        let ps = page_size();
        let rem = size % ps;
        let aligned = if rem == 0 {
            size
        } else {
            size.checked_add(ps - rem).ok_or(MemError::InvalidSize {
                size,
                reason: "rounding to page size overflows",
            })?
        };
        Ok(Self(aligned))
    }

    /// Construct from an already page-aligned size.
    #[inline]
    pub fn from_page_aligned(size: usize) -> Result<Self> {
        if size == 0 {
            return Err(MemError::InvalidSize {
                size,
                reason: "page-aligned length must be non-zero",
            });
        }
        if !size.is_multiple_of(page_size()) {
            return Err(MemError::NotPageAligned { size });
        }
        Ok(Self(size))
    }

    /// Return the length in bytes.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Convert to `u64` (common for KVM/device config APIs).
    #[inline]
    #[allow(clippy::cast_possible_truncation)] // 64-bit only
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }
}

/// A non-empty page-aligned byte range contained within a memory handle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageRange {
    offset: u64,
    len: PageAlignedLen,
}

impl PageRange {
    /// Validate a raw byte range against a containing object size.
    #[inline]
    pub fn new(offset: u64, len: u64, size: PageAlignedLen) -> Result<Self> {
        let size_usize = size.as_usize();
        if len == 0 {
            return Err(MemError::InvalidRange {
                offset,
                len,
                size: size_usize,
                reason: "range length must be non-zero",
            });
        }

        let ps = u64::try_from(page_size()).map_err(|_| MemError::InvalidRange {
            offset,
            len,
            size: size_usize,
            reason: "page size does not fit in u64",
        })?;
        if !offset.is_multiple_of(ps) {
            return Err(MemError::InvalidRange {
                offset,
                len,
                size: size_usize,
                reason: "range offset is not page-aligned",
            });
        }
        if !len.is_multiple_of(ps) {
            return Err(MemError::InvalidRange {
                offset,
                len,
                size: size_usize,
                reason: "range length is not page-aligned",
            });
        }

        let end = offset.checked_add(len).ok_or(MemError::InvalidRange {
            offset,
            len,
            size: size_usize,
            reason: "range end overflows",
        })?;
        if end > size.as_u64() {
            return Err(MemError::InvalidRange {
                offset,
                len,
                size: size_usize,
                reason: "range extends past handle size",
            });
        }

        let len_usize = usize::try_from(len).map_err(|_| MemError::InvalidRange {
            offset,
            len,
            size: size_usize,
            reason: "range length does not fit in usize",
        })?;
        Ok(Self {
            offset,
            len: PageAlignedLen::from_page_aligned(len_usize)?,
        })
    }

    /// Range start in bytes.
    #[inline]
    pub const fn offset(self) -> u64 {
        self.offset
    }

    /// Range length in bytes.
    #[inline]
    pub const fn len_bytes(self) -> u64 {
        self.len.as_u64()
    }

    /// Range length as a `usize`.
    #[inline]
    pub const fn len_usize(self) -> usize {
        self.len.as_usize()
    }
}

impl std::ops::Deref for PageAlignedLen {
    type Target = usize;
    #[inline]
    fn deref(&self) -> &usize {
        &self.0
    }
}

impl std::fmt::Display for PageAlignedLen {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_aligned_len_rejects_zero() {
        let err = PageAlignedLen::round_up(0).unwrap_err();
        assert!(matches!(err, MemError::InvalidSize { .. }));
    }

    #[test]
    fn page_aligned_len_rejects_rounding_overflow() {
        let err = PageAlignedLen::round_up(usize::MAX).unwrap_err();
        assert!(matches!(err, MemError::InvalidSize { .. }));
    }

    #[test]
    fn page_aligned_len_rounds_nonzero_size() {
        let page = page_size();
        let len = PageAlignedLen::round_up(page + 1).unwrap();
        assert_eq!(len.as_usize(), page * 2);
    }

    #[test]
    fn page_range_rejects_invalid_ranges() {
        let page = page_size();
        let size = PageAlignedLen::from_page_aligned(page * 2).unwrap();
        let page_u64 = u64::try_from(page).unwrap();

        assert!(matches!(
            PageRange::new(0, 0, size),
            Err(MemError::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(1, page_u64, size),
            Err(MemError::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(0, page_u64 + 1, size),
            Err(MemError::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(page_u64, page_u64 * 2, size),
            Err(MemError::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(u64::MAX, page_u64, size),
            Err(MemError::InvalidRange { .. })
        ));
    }
}
