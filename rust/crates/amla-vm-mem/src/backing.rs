// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Memory backing helpers for guest memory.
//!
//! Provides [`MmapSlice`] for memory-mapped file regions and [`map_handle`]
//! for mapping a [`crate::MemHandle`] into the current process.

#[cfg(unix)]
use std::os::fd::OwnedFd;
#[cfg(unix)]
use std::sync::Arc;

#[cfg(unix)]
use crate::error::MemError;

// =============================================================================
// MmapSlice — memory-mapped file region with RAII cleanup
// =============================================================================

/// Memory-mapped file region with RAII cleanup.
///
/// Keeps the source fd alive for the duration of the mapping.
///
/// Created via [`MmapSlice::new`] (read-only) or [`map_handle`] (read-write shared).
#[cfg(unix)]
pub struct MmapSlice {
    ptr: *mut u8,
    len: usize,
    /// Source fd (kept alive so file-backed mappings stay valid).
    /// `None` for anonymous mappings. Shared via `Arc` so several
    /// `MmapSlice`/`MemHandle` instances can keep one kernel fd alive
    /// without duplicating fd-table entries.
    _fd: Option<Arc<OwnedFd>>,
}

#[cfg(unix)]
impl MmapSlice {
    /// Create a read-only mapping of the given fd.
    ///
    /// Shares ownership of the fd via `Arc` — no kernel fd is duplicated.
    /// The entire fd is mapped (size determined via fstat).
    pub fn new(fd: Arc<OwnedFd>) -> std::result::Result<Self, MemError> {
        use std::os::fd::AsFd;
        let stat = rustix::fs::fstat(fd.as_fd()).map_err(MemError::sys("fstat"))?;
        #[allow(clippy::cast_sign_loss)]
        #[allow(clippy::cast_possible_truncation)]
        let len = stat.st_size as usize;
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot mmap zero-length fd",
            });
        }
        // SAFETY: null hint + non-zero `len` requests a kernel-chosen address;
        // `fd` is a valid OwnedFd whose fstat size matches `len`. Returned ptr
        // is owned by the resulting MmapSlice and unmapped on drop.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                fd.as_fd(),
                0,
            )
        }
        .map_err(MemError::sys("mmap"))?;
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            _fd: Some(fd),
        })
    }

    /// Create a read-only mapping, taking sole ownership of the fd.
    ///
    /// Convenience wrapper around [`new`](Self::new) for callers that have an
    /// `OwnedFd`. The entire fd is mapped (size determined via fstat).
    pub fn from_owned(fd: OwnedFd) -> std::result::Result<Self, MemError> {
        Self::new(Arc::new(fd))
    }

    /// Create a read-only mapping with explicit length.
    ///
    /// Maps `len` bytes from the fd (which may be larger than the file's
    /// actual size — the kernel zero-fills bytes past EOF within the mapped
    /// pages). Shares ownership of the fd via `Arc`.
    ///
    /// `len` must be > 0.
    pub fn read_only(fd: Arc<OwnedFd>, len: usize) -> std::result::Result<Self, MemError> {
        Self::read_only_at_offset(fd, len, 0)
    }

    /// Create a read-only mapping at a specific byte offset within the fd.
    ///
    /// `offset` must be a multiple of the system page size. Used by
    /// `MemHandle::from_fd_range` to expose an embedded blob (e.g. an EROFS
    /// image packed into the running executable) as a DAX-compatible mapping
    /// without copying. Shares ownership of the fd via `Arc`.
    pub fn read_only_at_offset(
        fd: Arc<OwnedFd>,
        len: usize,
        offset: u64,
    ) -> std::result::Result<Self, MemError> {
        use std::os::fd::AsFd;
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot mmap zero-length region",
            });
        }
        let offset_as_usize = usize::try_from(offset).map_err(|_| MemError::InvalidMemfd {
            reason: "offset does not fit in usize",
        })?;
        if !offset_as_usize.is_multiple_of(crate::page_size()) {
            return Err(MemError::NotPageAligned {
                size: offset_as_usize,
            });
        }
        // SAFETY: null hint requests a kernel-chosen address; `fd` is a valid
        // OwnedFd kept alive by the Arc stored in the returned MmapSlice,
        // `offset` is page-aligned (checked above), and `len` is non-zero.
        // Returned ptr is owned by the resulting MmapSlice and unmapped on drop.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
                fd.as_fd(),
                offset,
            )
        }
        .map_err(MemError::sys("mmap"))?;
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            _fd: Some(fd),
        })
    }

    /// Create a read-only anonymous zero-filled mapping.
    ///
    /// Returns `len` bytes of zero-filled memory. Used for pmem padding.
    /// `len` must be > 0.
    pub fn anonymous(len: usize) -> std::result::Result<Self, MemError> {
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot mmap zero-length region",
            });
        }
        // SAFETY: anonymous mapping with null hint; `len` is non-zero. The
        // returned ptr is owned by the resulting MmapSlice and unmapped on drop.
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ,
                rustix::mm::MapFlags::PRIVATE,
            )
        }
        .map_err(MemError::sys("mmap"))?;
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            _fd: None,
        })
    }

    /// Create a read-write anonymous mapping.
    ///
    /// Returns `len` bytes of zero-filled writable memory. Useful for tests
    /// that need to construct VM state regions without real file descriptors.
    /// `len` must be > 0.
    pub fn anonymous_rw(len: usize) -> std::result::Result<Self, MemError> {
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot mmap zero-length region",
            });
        }
        // SAFETY: anonymous RW mapping with null hint; `len` is non-zero. The
        // returned ptr is owned by the resulting MmapSlice and unmapped on drop.
        let ptr = unsafe {
            rustix::mm::mmap_anonymous(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::PRIVATE,
            )
        }
        .map_err(MemError::sys("mmap"))?;
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            _fd: None,
        })
    }

    /// Create a read-write `MAP_SHARED` mapping of the given fd with explicit size.
    #[cfg(target_os = "linux")]
    fn shared_rw(fd: Arc<OwnedFd>, len: usize) -> std::result::Result<Self, MemError> {
        use std::os::fd::AsFd;
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot mmap zero-length region",
            });
        }
        // SAFETY: null hint + non-zero `len` requests a kernel-chosen address;
        // `fd` is a valid OwnedFd whose size matches `len` (caller contract).
        // The returned ptr is owned by the resulting MmapSlice and unmapped
        // on drop; `_fd` keeps the backing alive.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                len,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::SHARED,
                fd.as_fd(),
                0,
            )
        }
        .map_err(MemError::sys("mmap"))?;
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            _fd: Some(fd),
        })
    }

    /// Map a Mach memory entry port into the current process (shared RW).
    #[cfg(target_os = "macos")]
    fn from_mach_port(port: u32, len: usize) -> std::result::Result<Self, MemError> {
        use crate::platform::macos;
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot map zero-length Mach port",
            });
        }
        let addr = macos::map_entry_anywhere(port, len)?;
        Ok(Self {
            ptr: addr as *mut u8,
            len,
            _fd: None,
        })
    }

    /// Map a Mach memory entry port into the current process (shared RO).
    #[cfg(target_os = "macos")]
    fn from_mach_port_ro(port: u32, len: usize) -> std::result::Result<Self, MemError> {
        use crate::platform::macos;
        if len == 0 {
            return Err(MemError::InvalidMemfd {
                reason: "cannot map zero-length Mach port",
            });
        }
        let addr = macos::map_entry_ro_anywhere(port, len)?;
        Ok(Self {
            ptr: addr as *mut u8,
            len,
            _fd: None,
        })
    }

    /// Wrap a raw mmap pointer and length into an `MmapSlice`.
    ///
    /// # Safety
    ///
    /// The caller must ensure `ptr` is a valid mmap'd region of at least
    /// `len` bytes that will be properly cleaned up via `munmap` on drop.
    #[cfg(target_os = "macos")]
    pub(crate) unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            _fd: None,
        }
    }

    /// Size of the mapped region in bytes.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the mapped region is empty (always false for valid mappings).
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw const pointer to the start of the mapping.
    #[inline]
    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }

    /// Raw mutable pointer to the start of the mapping.
    ///
    /// # Safety
    ///
    /// The mapping must have been created with write permissions, and the
    /// caller must uphold the aliasing and synchronization rules for whatever
    /// writes are performed through the returned pointer.
    #[inline]
    pub const unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Shared byte slice of the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure ordinary Rust shared-slice access is valid for
    /// this mapping for the returned lifetime. In particular, writable shared
    /// guest memory that may be concurrently mutated by a vCPU or device must
    /// not be exposed through this method; use volatile/atomic views instead.
    pub const unsafe fn as_slice_unchecked(&self) -> &[u8] {
        // SAFETY: delegated to the caller by the method contract.
        unsafe { std::slice::from_raw_parts(self.ptr.cast_const(), self.len) }
    }

    /// Mutable byte slice of the entire mapping.
    ///
    /// # Safety
    ///
    /// Caller must ensure the mapping was created with write permissions
    /// (e.g. via `anonymous_rw` or `shared_rw`).
    pub const unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: per the `# Safety` contract, the mapping was created with
        // write permissions; `self.ptr`/`self.len` back a writable region
        // for the duration of `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Const pointer at `byte_offset` within the mapping.
    ///
    /// Returns `None` if `byte_offset` exceeds the mapping length.
    #[inline]
    pub const fn offset_ptr(&self, byte_offset: usize) -> Option<*const u8> {
        if byte_offset >= self.len {
            return None;
        }
        // SAFETY: offset is within the mmap'd region (checked above),
        // and self.ptr is non-null (from a successful mmap).
        Some(unsafe { self.ptr.add(byte_offset).cast_const() })
    }

    /// Mutable pointer at `byte_offset` within the mapping.
    ///
    /// Returns `None` if `byte_offset` exceeds the mapping length.
    ///
    /// # Safety
    ///
    /// The mapping must have been created with write permissions or the
    /// caller must pass the pointer only to an API that will enforce read-only
    /// access. The caller also owns aliasing and synchronization for any
    /// mutation performed through the returned pointer.
    #[inline]
    pub const unsafe fn offset_mut_ptr(&self, byte_offset: usize) -> Option<std::ptr::NonNull<u8>> {
        if byte_offset >= self.len {
            return None;
        }
        // SAFETY: offset is within the mmap'd region (checked above),
        // and self.ptr is non-null (from a successful mmap).
        Some(unsafe { std::ptr::NonNull::new_unchecked(self.ptr.add(byte_offset)) })
    }
}

#[cfg(unix)]
impl Drop for MmapSlice {
    fn drop(&mut self) {
        // SAFETY: ptr/len from successful mmap in constructor.
        let result = unsafe { rustix::mm::munmap(self.ptr.cast(), self.len) };
        if let Err(e) = result {
            log::error!(
                "MmapSlice::drop: munmap(ptr={:p}, len={}) failed: {e}",
                self.ptr,
                self.len,
            );
        }
    }
}

// SAFETY: The mapping is process-wide; access synchronization is the caller's
// responsibility (same as raw pointers from mmap).
#[cfg(unix)]
unsafe impl Send for MmapSlice {}
// SAFETY: Same rationale as Send — no interior mutability, no thread-local state.
#[cfg(unix)]
unsafe impl Sync for MmapSlice {}

#[cfg(unix)]
impl std::fmt::Debug for MmapSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapSlice")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

// =============================================================================
// map_handle — MAP_SHARED RW mapping of a MemHandle
// =============================================================================

/// Map a [`crate::MemHandle`] into the current process.
///
/// - Writable handles (memfd from `allocate`/`branch`): `MAP_SHARED` read-write.
/// - Read-only handles (file from `from_file`): `MAP_PRIVATE` read-only.
///
/// Shares the underlying fd with the handle via `Arc` — no new kernel fd is
/// created. Returns an [`MmapSlice`] that unmaps on drop.
#[cfg(target_os = "linux")]
pub fn map_handle(handle: &crate::MemHandle) -> crate::Result<MmapSlice> {
    if handle.is_writable() {
        MmapSlice::shared_rw(handle.fd_arc(), *handle.size())
    } else {
        handle.read_only_mapping(*handle.size())
    }
}

/// Map a [`crate::MemHandle`] into the current process (macOS).
///
/// - Writable handles (`allocate`/`branch`): shared read-write mapping.
/// - Read-only handles (`from_file`): shared read-only mapping.
#[cfg(target_os = "macos")]
pub fn map_handle(handle: &crate::MemHandle) -> crate::Result<MmapSlice> {
    if handle.is_writable() {
        MmapSlice::from_mach_port(handle.entry(), *handle.size())
    } else {
        MmapSlice::from_mach_port_ro(handle.entry(), *handle.size())
    }
}

// =============================================================================
// Windows implementation
// =============================================================================

/// Memory-mapped region with RAII cleanup (Windows).
///
/// Wraps a `MapViewOfFile` view. Unmaps via `UnmapViewOfFile` on drop.
/// Provides the same API surface as the Unix `MmapSlice`.
#[cfg(windows)]
pub struct MmapSlice {
    ptr: *mut u8,
    len: usize,
    /// True if this was allocated via `VirtualAlloc` (anonymous mappings).
    /// False if created via `MapViewOfFile` (section-backed).
    is_virtual_alloc: bool,
}

#[cfg(windows)]
impl MmapSlice {
    /// Create a read-only anonymous zero-filled mapping.
    pub fn anonymous(len: usize) -> crate::Result<Self> {
        if len == 0 {
            return Err(crate::MemError::InvalidMemfd {
                reason: "cannot map zero-length region",
            });
        }
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READONLY, VirtualAlloc,
        };
        // SAFETY: null address lets the system choose the allocation;
        // `len` is non-zero (checked above). The returned ptr is owned by
        // the resulting MmapSlice and released via VirtualFree on drop.
        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READONLY,
            )
        };
        if ptr.is_null() {
            return Err(crate::MemError::AllocationFailed { size: len });
        }
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            is_virtual_alloc: true,
        })
    }

    /// Create a read-write anonymous zero-filled mapping.
    pub fn anonymous_rw(len: usize) -> crate::Result<Self> {
        if len == 0 {
            return Err(crate::MemError::InvalidMemfd {
                reason: "cannot map zero-length region",
            });
        }
        use windows_sys::Win32::System::Memory::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, VirtualAlloc,
        };
        // SAFETY: null address lets the system choose the allocation;
        // `len` is non-zero (checked above). The returned ptr is owned by
        // the resulting MmapSlice and released via VirtualFree on drop.
        let ptr = unsafe {
            VirtualAlloc(
                std::ptr::null(),
                len,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READWRITE,
            )
        };
        if ptr.is_null() {
            return Err(crate::MemError::AllocationFailed { size: len });
        }
        Ok(Self {
            ptr: ptr.cast::<u8>(),
            len,
            is_virtual_alloc: true,
        })
    }

    /// Wrap a raw `MapViewOfFile` pointer into an `MmapSlice`.
    ///
    /// # Safety
    ///
    /// `ptr` must be a valid view returned by `MapViewOfFile` with at
    /// least `len` bytes mapped. The view will be unmapped on drop.
    pub(crate) unsafe fn from_raw(ptr: *mut u8, len: usize) -> Self {
        Self {
            ptr,
            len,
            is_virtual_alloc: false,
        }
    }

    /// Size of the mapped region in bytes.
    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Returns `true` if the mapped region is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Raw const pointer to the start of the mapping.
    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }

    /// Raw mutable pointer to the start of the mapping.
    ///
    /// # Safety
    ///
    /// The mapping must have been created with write permissions, and the
    /// caller must uphold the aliasing and synchronization rules for whatever
    /// writes are performed through the returned pointer.
    #[inline]
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Shared byte slice of the mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure ordinary Rust shared-slice access is valid for
    /// this mapping for the returned lifetime. Writable shared guest memory
    /// that may be concurrently mutated must not be exposed through this
    /// method; use volatile/atomic views instead.
    pub unsafe fn as_slice_unchecked(&self) -> &[u8] {
        // SAFETY: delegated to the caller by the method contract.
        unsafe { std::slice::from_raw_parts(self.ptr.cast_const(), self.len) }
    }

    /// Mutable byte slice of the entire mapping.
    ///
    /// # Safety
    ///
    /// Caller must ensure the mapping was created with write permissions.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: per the `# Safety` contract, the mapping was created with
        // write permissions; `self.ptr`/`self.len` back a writable region
        // for the duration of `&mut self`.
        unsafe { std::slice::from_raw_parts_mut(self.ptr, self.len) }
    }

    /// Const pointer at `byte_offset` within the mapping.
    ///
    /// Returns `None` if `byte_offset` exceeds the mapping length.
    #[inline]
    pub fn offset_ptr(&self, byte_offset: usize) -> Option<*const u8> {
        if byte_offset >= self.len {
            return None;
        }
        // SAFETY: `byte_offset` is within the mapped region (checked above)
        // and `self.ptr` is non-null (from a successful VirtualAlloc/MapViewOfFile).
        Some(unsafe { self.ptr.add(byte_offset).cast_const() })
    }

    /// Mutable pointer at `byte_offset` within the mapping.
    ///
    /// Returns `None` if `byte_offset` exceeds the mapping length.
    ///
    /// # Safety
    ///
    /// The mapping must have been created with write permissions or the
    /// caller must pass the pointer only to an API that will enforce read-only
    /// access. The caller also owns aliasing and synchronization for any
    /// mutation performed through the returned pointer.
    #[inline]
    pub unsafe fn offset_mut_ptr(&self, byte_offset: usize) -> Option<std::ptr::NonNull<u8>> {
        if byte_offset >= self.len {
            return None;
        }
        // SAFETY: `byte_offset` is within the mapped region (checked above)
        // and `self.ptr` is non-null (from a successful VirtualAlloc/MapViewOfFile).
        Some(unsafe { std::ptr::NonNull::new_unchecked(self.ptr.add(byte_offset)) })
    }
}

#[cfg(windows)]
impl Drop for MmapSlice {
    fn drop(&mut self) {
        if self.is_virtual_alloc {
            // SAFETY: `self.ptr` was returned by VirtualAlloc in the constructor;
            // MEM_RELEASE with size=0 releases the entire reservation.
            unsafe {
                windows_sys::Win32::System::Memory::VirtualFree(
                    self.ptr.cast(),
                    0,
                    windows_sys::Win32::System::Memory::MEM_RELEASE,
                );
            }
        } else {
            // SAFETY: `self.ptr` was returned by MapViewOfFile (via from_raw);
            // unmapping is the documented cleanup for that view.
            unsafe {
                windows_sys::Win32::System::Memory::UnmapViewOfFile(
                    windows_sys::Win32::System::Memory::MEMORY_MAPPED_VIEW_ADDRESS {
                        Value: self.ptr.cast(),
                    },
                );
            }
        }
    }
}

// SAFETY: The mapping is process-wide; access synchronization is the caller's
// responsibility (same as raw pointers from VirtualAlloc / MapViewOfFile).
#[cfg(windows)]
unsafe impl Send for MmapSlice {}
// SAFETY: Same rationale as Send — no interior mutability, no thread-local state.
#[cfg(windows)]
unsafe impl Sync for MmapSlice {}

#[cfg(windows)]
impl std::fmt::Debug for MmapSlice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MmapSlice")
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

/// Map a [`crate::MemHandle`] into the current process (Windows).
///
/// - Writable handles: `FILE_MAP_WRITE` (shared read-write view).
/// - Read-only handles: `FILE_MAP_READ` (read-only view).
#[cfg(windows)]
pub fn map_handle(handle: &crate::MemHandle) -> crate::Result<MmapSlice> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Memory::{FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile};

    let access = if handle.is_writable() {
        FILE_MAP_WRITE
    } else {
        FILE_MAP_READ
    };
    let size = *handle.size();

    // SAFETY: `handle.as_handle()` yields a valid section object; `access`
    // matches the handle's writability; offset 0 + `size` maps the whole
    // section which was sized to `size` at construction.
    let view = unsafe {
        MapViewOfFile(
            handle.as_handle().as_raw_handle().cast(),
            access,
            0,
            0,
            size,
        )
    };
    if view.Value.is_null() {
        return Err(crate::MemError::SystemCall {
            operation: "MapViewOfFile (map_handle)",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `view.Value` was just returned by MapViewOfFile (non-null
    // checked above) and covers `size` bytes; ownership transfers to MmapSlice
    // which unmaps on drop.
    Ok(unsafe { MmapSlice::from_raw(view.Value.cast::<u8>(), size) })
}

// =============================================================================
// Non-Unix, non-Windows stubs
// =============================================================================

/// Memory-mapped region stub (unsupported platform).
#[cfg(not(any(unix, windows)))]
pub struct MmapSlice {
    _private: (),
}

#[cfg(not(any(unix, windows)))]
impl MmapSlice {
    /// Anonymous zero-filled mapping (stub — always errors).
    pub fn anonymous(_len: usize) -> crate::Result<Self> {
        Err(crate::MemError::Unsupported(
            "MmapSlice::anonymous not supported on this platform",
        ))
    }

    /// Anonymous read-write mapping (stub — always errors).
    pub fn anonymous_rw(_len: usize) -> crate::Result<Self> {
        Err(crate::MemError::Unsupported(
            "MmapSlice::anonymous_rw not supported on this platform",
        ))
    }

    /// Size of the mapped region in bytes.
    pub fn len(&self) -> usize {
        0
    }
    /// Returns `true` if empty.
    pub fn is_empty(&self) -> bool {
        true
    }
    /// Raw const pointer.
    pub fn as_ptr(&self) -> *const u8 {
        std::ptr::null()
    }

    /// Raw mutable pointer.
    ///
    /// # Safety
    ///
    /// Unsupported on this platform.
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        std::ptr::null_mut()
    }

    /// Shared byte slice.
    ///
    /// # Safety
    ///
    /// Unsupported on this platform.
    pub unsafe fn as_slice_unchecked(&self) -> &[u8] {
        &[]
    }

    /// Mutable byte slice (stub — panics).
    ///
    /// # Safety
    ///
    /// Same as the Unix version.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        panic!("MmapSlice::as_mut_slice not supported on this platform");
    }

    /// Const pointer at offset (stub — always None).
    pub fn offset_ptr(&self, _byte_offset: usize) -> Option<*const u8> {
        None
    }

    /// Mutable pointer at offset (stub — always None).
    ///
    /// # Safety
    ///
    /// Unsupported on this platform.
    pub unsafe fn offset_mut_ptr(&self, _byte_offset: usize) -> Option<std::ptr::NonNull<u8>> {
        None
    }
}

/// Map a [`crate::MemHandle`] (unsupported platform stub).
#[cfg(not(any(unix, windows)))]
pub fn map_handle(_handle: &crate::MemHandle) -> crate::Result<MmapSlice> {
    Err(crate::MemError::Unsupported(
        "map_handle not supported on this platform",
    ))
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use rustix::fs::{MemfdFlags, memfd_create};
    use std::os::fd::AsFd;

    fn create_memfd_with_data(data: &[u8]) -> OwnedFd {
        let fd = memfd_create(c"test", MemfdFlags::CLOEXEC).unwrap();
        rustix::io::write(&fd, data).unwrap();
        fd
    }

    #[test]
    fn mmap_slice_reads_file_data() {
        let data = b"hello world";
        let fd = create_memfd_with_data(data);
        let slice = MmapSlice::from_owned(fd).unwrap();
        // SAFETY: read-only mapping in a single-threaded test.
        assert_eq!(unsafe { slice.as_slice_unchecked() }, data);
        assert_eq!(slice.len(), data.len());
        assert!(!slice.is_empty());
    }

    #[test]
    fn mmap_slice_new_shares_fd_arc() {
        let data = b"arc test";
        let fd = Arc::new(create_memfd_with_data(data));
        let slice = MmapSlice::new(Arc::clone(&fd)).unwrap();
        // Original fd Arc is still valid (shared, not consumed).
        let stat = rustix::fs::fstat(fd.as_fd()).unwrap();
        assert_eq!(stat.st_size, i64::try_from(data.len()).unwrap());
        // Mapped data matches.
        // SAFETY: read-only mapping in a single-threaded test.
        assert_eq!(unsafe { slice.as_slice_unchecked() }, data);
    }

    #[test]
    fn mmap_slice_rejects_zero_length() {
        let fd = memfd_create(c"empty", MemfdFlags::CLOEXEC).unwrap();
        // Don't write anything — fd has size 0
        let err = MmapSlice::from_owned(fd).unwrap_err();
        assert!(
            err.to_string().contains("zero-length"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn mmap_slice_large_data() {
        let data: Vec<u8> = (0u8..=255).cycle().take(8192).collect();
        let fd = create_memfd_with_data(&data);
        let slice = MmapSlice::from_owned(fd).unwrap();
        assert_eq!(slice.len(), 8192);
        // SAFETY: read-only mapping in a single-threaded test.
        let bytes = unsafe { slice.as_slice_unchecked() };
        assert_eq!(&bytes[0..4], &[0, 1, 2, 3]);
        assert_eq!(&bytes[8188..8192], &[252, 253, 254, 255]);
    }

    #[test]
    fn map_handle_creates_rw_mapping() {
        let h = crate::MemHandle::allocate(c"test", 4096).unwrap();
        let mmap = map_handle(&h).unwrap();
        assert_eq!(mmap.len(), 4096);
        // Should be zeroed.
        // SAFETY: test-local mapping; no concurrent writers.
        assert!(unsafe { mmap.as_slice_unchecked() }.iter().all(|&b| b == 0));
        // Write through raw pointer (MAP_SHARED).
        // SAFETY: `mmap.as_mut_ptr()` is a valid writable byte in the shared
        // RW mapping; no other thread observes this test-local region.
        unsafe { *mmap.as_mut_ptr() = 0xAB };
        // SAFETY: test-local mapping; no concurrent writers.
        assert_eq!((unsafe { mmap.as_slice_unchecked() })[0], 0xAB);
    }
}
