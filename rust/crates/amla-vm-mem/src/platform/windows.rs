// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Windows-specific memory helpers.
//!
//! This module currently provides [`SectionObject`], a pagefile-backed section
//! object used for read-only image sharing (the Windows counterpart to a memfd).

use amla_constants::num::{hi32, lo32};
use std::io;
use std::os::windows::io::{AsHandle, BorrowedHandle, FromRawHandle, OwnedHandle};

/// Pagefile-backed section object containing immutable image bytes.
///
/// The section is created with `CreateFileMappingW(INVALID_HANDLE_VALUE, ...)`,
/// filled once, and then used as the source for read-only views
/// (`MapViewOfFile3`) in pmem padded mappings.
pub struct SectionObject {
    handle: OwnedHandle,
    size: usize,
}

impl SectionObject {
    /// Create a section object from in-memory bytes.
    pub fn from_memory(data: &[u8]) -> io::Result<Self> {
        use windows_sys::Win32::Foundation::{CloseHandle, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::System::Memory::{
            CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
        };

        // Use allocation granularity so placeholder replacement can map the
        // file-backed prefix as a whole.
        const GRANULARITY: usize = 64 * 1024;

        if data.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "section size must be > 0",
            ));
        }
        let mapping_len = round_up_pow2(data.len(), GRANULARITY)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "section size overflow"))?;
        let mapping_hi = hi32(mapping_len as u64);
        let mapping_lo = lo32(mapping_len as u64);

        // SAFETY: INVALID_HANDLE_VALUE requests a pagefile-backed section;
        // null SECURITY_ATTRIBUTES uses defaults; null name makes the section
        // anonymous. `mapping_len` is non-zero and split into the required
        // hi/lo DWORDs.
        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE.cast(),
                std::ptr::null(),
                PAGE_READWRITE,
                mapping_hi,
                mapping_lo,
                std::ptr::null(),
            )
        };
        if section.is_null() {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `section` is a valid non-null HANDLE (checked above);
        // offset 0 + `mapping_len` maps the entire section.
        let view = unsafe { MapViewOfFile(section, FILE_MAP_WRITE, 0, 0, mapping_len) };
        if view.Value.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: `section` is a valid non-null HANDLE we just created
            // and did not transfer ownership of.
            unsafe {
                let _ = CloseHandle(section);
            }
            return Err(err);
        }

        // SAFETY: `view.Value` is non-null (checked above) and covers
        // `mapping_len >= data.len()` writable bytes; `data.as_ptr()` is a
        // valid read pointer for `data.len()` bytes; regions are disjoint.
        unsafe {
            std::ptr::copy_nonoverlapping(data.as_ptr(), view.Value.cast::<u8>(), data.len());
        }
        // SAFETY: `view` was returned by the matching MapViewOfFile above
        // (non-null checked) and has not been unmapped yet.
        let unmapped = unsafe { UnmapViewOfFile(view) };
        if unmapped == 0 {
            let err = io::Error::last_os_error();
            // SAFETY: `section` is a valid non-null HANDLE we just created
            // and did not transfer ownership of.
            unsafe {
                let _ = CloseHandle(section);
            }
            return Err(err);
        }

        // SAFETY: `section` is a fresh non-null HANDLE from CreateFileMappingW
        // (checked above) with no other owners; OwnedHandle takes ownership
        // and closes it on drop.
        let handle = unsafe { OwnedHandle::from_raw_handle(section.cast()) };
        Ok(Self {
            handle,
            size: data.len(),
        })
    }

    /// Borrow the native section handle.
    pub fn as_handle(&self) -> BorrowedHandle<'_> {
        self.handle.as_handle()
    }

    /// Size of the original image bytes.
    pub fn size(&self) -> usize {
        self.size
    }
}

impl std::fmt::Debug for SectionObject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SectionObject")
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

#[inline]
fn round_up_pow2(value: usize, alignment: usize) -> Option<usize> {
    debug_assert!(alignment.is_power_of_two());
    value
        .checked_add(alignment - 1)
        .map(|v| v & !(alignment - 1))
}
