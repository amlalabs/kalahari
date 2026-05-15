// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Platform-specific memory handle.
//!
//! [`MemHandle`] is a lightweight ownership wrapper around a platform-specific
//! memory backing (memfd on Linux, Mach port on macOS, section handle on
//! Windows) paired with its size.

use crate::error::{MemError, Result};

// ============================================================================
// Linux
// ============================================================================

#[cfg(target_os = "linux")]
mod inner {
    use std::ffi::CStr;
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
    use std::sync::Arc;

    use rustix::fs::{MemfdFlags, OFlags, fcntl_getfl, fstat, ftruncate, memfd_create};

    use super::{MemError, Result};

    /// Platform-specific memory handle (Linux: memfd with `CoW` backend).
    ///
    /// For root handles (created via `allocate()`), all pages are in the memfd.
    /// For branched handles (created via `branch()`), data is managed by the
    /// active `CoW` backend. Backend selection at `allocate()` time:
    /// 1. `CowTree` kernel module (fastest, in-kernel `CoW`)
    /// 2. Eager copy via `sendfile` (compatibility path when the module is missing)
    pub struct MemHandle {
        /// Source fd. Stored in an `Arc` so `try_clone`, `map_handle`, and `CoW`
        /// backend fd-sharing all multiplex the same kernel fd-table entry;
        /// the kernel `close` runs exactly once when the last Arc drops.
        fd: Arc<OwnedFd>,
        size: crate::PageAlignedLen,
        /// Byte offset within `fd` where the mapped region starts.
        ///
        /// `0` for memfd-backed handles (`allocate`, `branch`) and
        /// whole-file handles (`from_file`, `from_fd`). Non-zero only for
        /// handles created via [`MemHandle::from_fd_range`] — typically
        /// referencing an EROFS image embedded in the running executable.
        ///
        /// Must be page-aligned (enforced at construction).
        offset: u64,
        /// Active `CoW` backend, or `None` for eager copy fallback.
        backend: Option<CowBackend>,
        /// Whether this handle was opened for writing. `from_file()` creates
        /// read-only handles; `allocate()` and `branch()` create writable ones.
        writable: bool,
    }

    /// Runtime-selected `CoW` backend.
    #[derive(Clone)]
    enum CowBackend {
        /// In-kernel `CoW` via the cowtree kernel module.
        CowTree(CowTreeRef),
    }

    /// Reference to a `CowTree` branch (kernel module `CoW`).
    #[derive(Clone)]
    struct CowTreeRef {
        tree: std::sync::Arc<amla_cowtree::CowTree>,
        branch_id: amla_cowtree::BranchId,
        _branch_fd: Option<std::sync::Arc<amla_cowtree::BranchFd>>,
    }

    /// Eagerly copy populated data from one fd to another, skipping holes.
    ///
    /// Uses `SEEK_DATA`/`SEEK_HOLE` to find populated regions in the source,
    /// then `sendfile` to copy only those regions. This preserves sparsity:
    /// the child memfd has holes where the parent does, avoiding materializing
    /// hundreds of MiB of zero pages for sparse regions (PMEM padding, unwritten RAM).
    #[allow(
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::cast_possible_truncation
    )]
    fn eager_copy_fd(src: BorrowedFd<'_>, dst: BorrowedFd<'_>, size: usize) -> Result<()> {
        let end = size as i64;
        let mut pos: i64 = 0;

        loop {
            // Find next data region.
            // SAFETY: `src` is a valid BorrowedFd; lseek with SEEK_DATA is a
            // pure kernel syscall with no memory requirements.
            let data_start = unsafe { libc::lseek(src.as_raw_fd(), pos, libc::SEEK_DATA) };
            if data_start < 0 {
                let err = std::io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::ENXIO) {
                    break; // No more data — rest is holes.
                }
                return Err(MemError::sys("lseek SEEK_DATA")(err));
            }
            if data_start >= end {
                break;
            }

            // Find where this data region ends (next hole).
            // SAFETY: `src` is a valid BorrowedFd; lseek with SEEK_HOLE is a
            // pure kernel syscall with no memory requirements.
            let hole_start = unsafe { libc::lseek(src.as_raw_fd(), data_start, libc::SEEK_HOLE) };
            let data_end = if hole_start < 0 {
                end
            } else {
                hole_start.min(end)
            };
            let len = (data_end - data_start) as usize;

            // Copy this data region via sendfile.
            // Seek the destination to the correct offset — sendfile writes at
            // the destination's current file position, so we must advance past
            // any holes to preserve the source layout in the destination.
            // SAFETY: `dst` is a valid BorrowedFd; lseek with SEEK_SET is a
            // pure kernel syscall that just repositions the file offset.
            if unsafe { libc::lseek(dst.as_raw_fd(), data_start, libc::SEEK_SET) } < 0 {
                return Err(MemError::sys("lseek dst")(std::io::Error::last_os_error()));
            }
            let mut off = data_start;
            let mut remaining = len;
            while remaining > 0 {
                // SAFETY: both fds are valid BorrowedFds; `&raw mut off` is a
                // pointer to a local i64 that sendfile updates in place;
                // `remaining` is the number of bytes authorized to copy.
                let n = unsafe {
                    libc::sendfile(dst.as_raw_fd(), src.as_raw_fd(), &raw mut off, remaining)
                };
                if n < 0 {
                    return Err(MemError::sys("sendfile")(std::io::Error::last_os_error()));
                }
                if n == 0 {
                    break;
                }
                remaining -= n as usize;
            }

            pos = data_end;
        }
        Ok(())
    }

    impl MemHandle {
        fn fd_len(fd: BorrowedFd<'_>) -> Result<u64> {
            let stat = fstat(fd).map_err(MemError::sys("fstat"))?;
            u64::try_from(stat.st_size).map_err(|_| MemError::InvalidMemfd {
                reason: "negative st_size from fstat",
            })
        }

        fn validate_fd_range(fd: BorrowedFd<'_>, offset: u64, len: usize) -> Result<()> {
            let file_len = Self::fd_len(fd)?;
            let len = u64::try_from(len).map_err(|_| MemError::InvalidMemfd {
                reason: "range length does not fit in u64",
            })?;
            let end = offset.checked_add(len).ok_or(MemError::InvalidMemfd {
                reason: "fd range overflows u64",
            })?;
            if end > file_len {
                return Err(MemError::InvalidMemfd {
                    reason: "fd range extends past end of file",
                });
            }
            Ok(())
        }

        fn validate_fd_exact_len(fd: BorrowedFd<'_>, expected_size: usize) -> Result<()> {
            let actual =
                usize::try_from(Self::fd_len(fd)?).map_err(|_| MemError::InvalidMemfd {
                    reason: "fd size does not fit in usize",
                })?;
            if actual != expected_size {
                return Err(MemError::SizeMismatch {
                    expected: expected_size,
                    actual,
                });
            }
            Ok(())
        }

        fn validate_fd_access(fd: BorrowedFd<'_>, writable: bool) -> Result<()> {
            let flags = fcntl_getfl(fd).map_err(MemError::sys("fcntl_getfl"))?;
            if flags.contains(OFlags::PATH) {
                return Err(MemError::InvalidMemfd {
                    reason: "O_PATH fd is not mappable",
                });
            }

            let access = flags & OFlags::RWMODE;
            let valid = if writable {
                access == OFlags::RDWR
            } else {
                access == OFlags::RDONLY
            };
            if !valid {
                return Err(MemError::InvalidMemfd {
                    reason: if writable {
                        "writable handle requires O_RDWR fd"
                    } else {
                        "read-only handle requires O_RDONLY fd"
                    },
                });
            }
            Ok(())
        }

        fn validate_external_fd(fd: BorrowedFd<'_>, size: usize, writable: bool) -> Result<()> {
            if size == 0 {
                return Err(MemError::InvalidMemfd {
                    reason: "cannot create handle with zero length",
                });
            }
            if !size.is_multiple_of(crate::page_size()) {
                return Err(MemError::NotPageAligned { size });
            }
            if writable {
                Self::validate_fd_exact_len(fd, size)?;
            } else {
                let actual =
                    usize::try_from(Self::fd_len(fd)?).map_err(|_| MemError::InvalidMemfd {
                        reason: "fd size does not fit in usize",
                    })?;
                if actual == 0 {
                    return Err(MemError::InvalidMemfd {
                        reason: "cannot create handle from zero-length fd",
                    });
                }
                let actual_page_rounded = crate::PageAlignedLen::round_up(actual)?;
                if *actual_page_rounded != size {
                    return Err(MemError::SizeMismatch {
                        expected: size,
                        actual,
                    });
                }
            }
            Self::validate_fd_access(fd, writable)
        }

        /// Allocate a new memfd with the given name and size.
        ///
        /// Creates a memfd via `memfd_create` + `ftruncate`. The memfd is
        /// created with `MFD_CLOEXEC | MFD_ALLOW_SEALING` so it can be
        /// sealed later by tree backends if needed.
        pub fn allocate(name: &CStr, size: usize) -> Result<Self> {
            let size = crate::PageAlignedLen::round_up(size)?;
            let fd = memfd_create(name, MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
                .map_err(MemError::sys("memfd_create"))?;
            ftruncate(&fd, *size as u64).map_err(MemError::sys("ftruncate"))?;
            let fd = Arc::new(fd);

            // Try CowTree (in-kernel CoW); fall back to eager copy if the
            // module is not loaded. `AMLA_MEM_BACKEND=eager` forces eager
            // copy unconditionally.
            let force_eager = std::env::var("AMLA_MEM_BACKEND").as_deref() == Ok("eager");

            let backend = if force_eager {
                log::debug!("AMLA_MEM_BACKEND=eager, skipping CowTree");
                None
            } else {
                match amla_cowtree::CowTree::from_base(fd.as_fd(), *size) {
                    Ok(tree) => {
                        log::debug!("CowTree available, using kernel CoW");
                        Some(CowBackend::CowTree(CowTreeRef {
                            tree: std::sync::Arc::new(tree),
                            branch_id: amla_cowtree::BranchId::BASE,
                            _branch_fd: None,
                        }))
                    }
                    Err(amla_cowtree::Error::DeviceOpen(_)) => {
                        log::trace!("CowTree module not loaded, using eager copy");
                        None
                    }
                    Err(e) => {
                        return Err(MemError::SystemCall {
                            operation: "cowtree from_base",
                            source: std::io::Error::other(e.to_string()),
                        });
                    }
                }
            };

            Ok(Self {
                fd,
                size,
                offset: 0,
                backend,
                writable: true,
            })
        }

        /// Wrap a shared `Arc<OwnedFd>` with a known size (writable handle).
        ///
        /// Used by IPC deserialization where the fd arrives inside an
        /// `Arc<OwnedFd>` that the aux transport keeps alive alongside.
        pub fn from_fd_arc(fd: Arc<OwnedFd>, size: usize) -> Result<Self> {
            Self::validate_external_fd(fd.as_fd(), size, true)?;
            Ok(Self {
                fd,
                size: crate::PageAlignedLen::from_page_aligned(size)?,
                offset: 0,
                backend: None,
                writable: true,
            })
        }

        /// Wrap a shared `Arc<OwnedFd>` with a known size (read-only handle).
        pub fn from_fd_arc_readonly(fd: Arc<OwnedFd>, size: usize) -> Result<Self> {
            Self::validate_external_fd(fd.as_fd(), size, false)?;
            Ok(Self {
                fd,
                size: crate::PageAlignedLen::from_page_aligned(size)?,
                offset: 0,
                backend: None,
                writable: false,
            })
        }

        /// Wrap a byte range `[offset, offset+len)` within a read-only fd.
        ///
        /// The fd is retained; `read_only_mapping(len)` issues `mmap` at the
        /// stored offset, giving a DAX-compatible host mapping that aliases
        /// the same physical pages as the source file's page cache.
        ///
        /// Intended for embedding an EROFS image inside the running executable
        /// (`/proc/self/exe`) and exposing it via virtio-pmem without copying.
        ///
        /// Constraints:
        /// - `offset` must be page-aligned.
        /// - `len` must be page-aligned for DAX. Callers must page-pad the
        ///   embedded object itself rather than relying on this constructor to
        ///   expose trailing bytes from the source file.
        /// - `offset + len` must fit inside the fd's current size.
        /// - The fd must be opened read-only.
        /// - The resulting handle is read-only and cannot be `punch_hole`d.
        /// - `branch()` is rejected (use `allocate_and_write` + memcpy for a
        ///   writable copy; embedded rootfs is read-only by design).
        pub fn from_fd_range(fd: OwnedFd, offset: u64, len: usize) -> Result<Self> {
            if len == 0 {
                return Err(MemError::InvalidMemfd {
                    reason: "cannot create handle with zero length",
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
            if !len.is_multiple_of(crate::page_size()) {
                return Err(MemError::NotPageAligned { size: len });
            }
            Self::validate_fd_range(fd.as_fd(), offset, len)?;
            Self::validate_fd_access(fd.as_fd(), false)?;
            Ok(Self {
                fd: Arc::new(fd),
                size: crate::PageAlignedLen::from_page_aligned(len)?,
                offset,
                backend: None,
                writable: false,
            })
        }

        /// Open a read-only file and wrap it as a `MemHandle`.
        ///
        /// The file is opened read-only. `map_handle()` will create a
        /// `MAP_PRIVATE` read-only mmap. This handle cannot be punched
        /// (no `fallocate` on read-only fds).
        ///
        /// Branching is supported: `branch()` creates a new writable memfd
        /// and copies the file data via `SEEK_DATA`/`sendfile`.
        pub fn from_file(path: &std::path::Path) -> Result<Self> {
            use std::os::unix::io::{FromRawFd, IntoRawFd};
            let file = std::fs::File::open(path).map_err(|e| MemError::SystemCall {
                operation: "open",
                source: e,
            })?;
            #[allow(clippy::cast_possible_truncation)] // 64-bit only
            let file_size = file
                .metadata()
                .map_err(|e| MemError::SystemCall {
                    operation: "fstat",
                    source: e,
                })?
                .len() as usize;
            if file_size == 0 {
                return Err(MemError::InvalidMemfd {
                    reason: "cannot create handle from zero-length file",
                });
            }
            let size = crate::PageAlignedLen::round_up(file_size)?;
            // SAFETY: `file.into_raw_fd()` yields a fresh owned fd with no
            // other owners; wrapping it in OwnedFd transfers that ownership.
            let fd = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
            Ok(Self {
                fd: Arc::new(fd),
                size,
                offset: 0,
                backend: None,
                writable: false,
            })
        }

        /// Wrap an existing fd, validating its size via `fstat`.
        ///
        /// Returns an error if the fd's actual size doesn't match `expected_size`
        /// or if the size is not page-aligned.
        pub fn from_fd_validated(fd: OwnedFd, expected_size: usize) -> Result<Self> {
            if !expected_size.is_multiple_of(crate::page_size()) {
                return Err(MemError::NotPageAligned {
                    size: expected_size,
                });
            }

            Self::validate_fd_exact_len(fd.as_fd(), expected_size)?;
            Self::validate_fd_access(fd.as_fd(), true)?;

            Ok(Self {
                fd: Arc::new(fd),
                size: crate::PageAlignedLen::from_page_aligned(expected_size)?,
                offset: 0,
                backend: None,
                writable: true,
            })
        }

        /// Allocate a memfd of `size` bytes, map it, call `f` to write data,
        /// then unmap. The written data persists via `MAP_SHARED`.
        pub fn allocate_and_write(
            name: &CStr,
            size: usize,
            f: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
        ) -> Result<Self> {
            let handle = Self::allocate(name, size)?;
            let mmap = crate::map_handle(&handle)?;
            // SAFETY: `mmap` is a MAP_SHARED RW mapping of exactly `size` bytes
            // (Self::allocate rounds up to page-aligned). `mmap.as_mut_ptr()`
            // is non-null and points to the start of the mapping. No other thread
            // or process holds a handle to this memfd yet — `handle` has not
            // been returned, so `slice` is the unique writable view for the
            // duration of `f`. The borrow ends before `drop(mmap)`.
            let slice = unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), size) };
            f(slice).map_err(|e| MemError::SystemCall {
                operation: "allocate_and_write",
                source: e,
            })?;
            drop(mmap);
            Ok(handle)
        }

        /// Size of the backing memory in bytes (page-aligned by construction).
        #[inline]
        pub const fn size(&self) -> crate::PageAlignedLen {
            self.size
        }

        /// Whether this handle supports writable shared mappings.
        ///
        /// Returns `false` for handles created via `from_file()` (read-only fd).
        /// `map_handle()` uses this to choose read-only vs read-write mapping.
        #[inline]
        pub const fn is_writable(&self) -> bool {
            self.writable
        }

        /// Borrow the underlying file descriptor.
        #[inline]
        pub fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }

        /// Return a shared `Arc` over the underlying fd.
        ///
        /// Used by [`crate::map_handle`] and other consumers that need to
        /// keep the kernel fd alive alongside the handle without inflating
        /// the process fd table.
        #[inline]
        pub fn fd_arc(&self) -> Arc<OwnedFd> {
            Arc::clone(&self.fd)
        }

        /// Create a read-only mapping of this handle with explicit length.
        ///
        /// Maps `len` bytes (may exceed file size — kernel zero-fills past EOF).
        /// Used for pmem image data where the mapping size is page-aligned.
        ///
        /// When the handle was created via [`from_fd_range`](Self::from_fd_range),
        /// the mapping starts at the stored `offset` within the fd (e.g. the
        /// location of an EROFS blob inside `/proc/self/exe`).
        pub fn read_only_mapping(&self, len: usize) -> Result<crate::MmapSlice> {
            if len != *self.size {
                return Err(MemError::SizeMismatch {
                    expected: *self.size,
                    actual: len,
                });
            }
            crate::MmapSlice::read_only_at_offset(Arc::clone(&self.fd), len, self.offset)
        }

        /// Consume the handle and return the shared fd `Arc`.
        ///
        /// Prefer [`fd_arc`](Self::fd_arc) when you want to keep the handle
        /// available; this variant is for call sites that want to drop the
        /// `MemHandle` state (size/backend) and keep only the raw fd arc.
        pub fn into_fd_arc(self) -> Arc<OwnedFd> {
            self.fd
        }

        /// Clone the handle.
        ///
        /// Shares the underlying kernel fd via `Arc` — no `dup(2)` syscall,
        /// no new fd-table entry. The `CowTree` backend is cloned structurally
        /// (its ref is already `Arc`-shared).
        pub fn try_clone(&self) -> Result<Self> {
            Ok(Self {
                fd: Arc::clone(&self.fd),
                size: self.size,
                offset: self.offset,
                backend: self.backend.clone(),
                writable: self.writable,
            })
        }

        /// Create a `CoW` branch of this handle.
        ///
        /// Uses the active backend:
        /// - `CowTree`: kernel ioctl (O(1), lazy `CoW`)
        /// - Eager copy: `SEEK_DATA`/`sendfile` (copies only populated pages)
        ///
        /// # Safety
        ///
        /// The caller must guarantee that no execution context can write to
        /// this handle's mappings while the branch is created. For cowtree
        /// backends, stale writable TLB entries or mappings that predate the
        /// branch must not be used after branching unless the caller has first
        /// invalidated or replaced them so parent writes cannot bypass `CoW`.
        pub unsafe fn branch(&self) -> Result<Self> {
            if self.offset != 0 {
                // from_fd_range handles point into a shared read-only fd
                // (typically /proc/self/exe). Branching would need offset-aware
                // sendfile and is out of scope — the embedded rootfs is
                // read-only by design.
                return Err(MemError::InvalidState {
                    expected: "zero-offset handle",
                    actual: "from_fd_range handle (embedded blob, read-only)",
                });
            }
            match &self.backend {
                Some(CowBackend::CowTree(ct)) => {
                    // SAFETY: Upheld by this function's safety contract.
                    let parent = unsafe { amla_cowtree::FrozenBranch::assume_frozen(ct.branch_id) };
                    let branch_fd = ct.tree.branch(parent).map_err(|e| MemError::SystemCall {
                        operation: "cowtree branch",
                        source: std::io::Error::other(e.to_string()),
                    })?;
                    let child_branch_id = branch_fd.id();
                    let child_fd = branch_fd.as_fd().try_clone_to_owned().map_err(|e| {
                        MemError::SystemCall {
                            operation: "dup cowtree branch fd",
                            source: e,
                        }
                    })?;
                    Ok(Self {
                        fd: Arc::new(child_fd),
                        size: self.size,
                        offset: 0,
                        backend: Some(CowBackend::CowTree(CowTreeRef {
                            tree: ct.tree.clone(),
                            branch_id: child_branch_id,
                            _branch_fd: Some(Arc::new(branch_fd)),
                        })),
                        writable: true,
                    })
                }
                None => {
                    // Eager copy: copy parent data to child fd.
                    let child_fd =
                        memfd_create(c"branch", MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING)
                            .map_err(MemError::sys("memfd_create branch"))?;
                    ftruncate(&child_fd, *self.size as u64)
                        .map_err(MemError::sys("ftruncate branch"))?;
                    eager_copy_fd(self.fd.as_fd(), child_fd.as_fd(), *self.size)?;
                    Ok(Self {
                        fd: Arc::new(child_fd),
                        size: self.size,
                        offset: 0,
                        backend: None,
                        writable: true,
                    })
                }
            }
        }

        /// Release pages back to the system (CoW-safe).
        ///
        /// Deallocates physical pages. Next read returns zeros (root) or
        /// parent data (branch).
        ///
        /// - `CowTree`: ioctl `punch_hole` (reverts to parent sharing).
        /// - Eager copy: `fallocate(PUNCH_HOLE)` on the memfd.
        ///
        /// Returns `InvalidState` for read-only handles (file-backed).
        /// Fails with EPERM if the memfd has been sealed with `F_SEAL_WRITE`.
        pub fn punch_hole(&self, offset: u64, len: u64) -> Result<()> {
            if !self.writable {
                return Err(MemError::InvalidState {
                    expected: "writable handle",
                    actual: "read-only handle (from_file)",
                });
            }
            let range = crate::PageRange::new(offset, len, self.size)?;
            match &self.backend {
                Some(CowBackend::CowTree(ct)) => {
                    let range = amla_cowtree::PageRange::new(
                        range.offset(),
                        range.len_bytes(),
                        ct.tree.size(),
                    )
                    .map_err(|e| MemError::SystemCall {
                        operation: "cowtree page_range",
                        source: std::io::Error::other(e.to_string()),
                    })?;
                    ct.tree
                        .punch_hole(ct.branch_id, range)
                        .map_err(|e| MemError::SystemCall {
                            operation: "cowtree punch_hole",
                            source: std::io::Error::other(e.to_string()),
                        })?;
                }
                None => {
                    rustix::fs::fallocate(
                        self.fd.as_fd(),
                        rustix::fs::FallocateFlags::PUNCH_HOLE
                            | rustix::fs::FallocateFlags::KEEP_SIZE,
                        range.offset(),
                        range.len_bytes(),
                    )
                    .map_err(MemError::sys("fallocate punch_hole"))?;
                }
            }
            Ok(())
        }
    }

    impl AsRawFd for MemHandle {
        #[inline]
        fn as_raw_fd(&self) -> RawFd {
            self.fd.as_raw_fd()
        }
    }

    impl AsFd for MemHandle {
        #[inline]
        fn as_fd(&self) -> BorrowedFd<'_> {
            self.fd.as_fd()
        }
    }

    impl std::fmt::Debug for MemHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemHandle")
                .field("size", &self.size)
                .finish_non_exhaustive()
        }
    }
}

// ============================================================================
// macOS
// ============================================================================

#[cfg(target_os = "macos")]
mod inner {
    use std::ffi::CStr;

    use super::{MemError, Result};

    /// Platform-specific memory handle (macOS: Mach memory entry).
    ///
    /// Stores a Mach memory entry port created via `mach_make_memory_entry_64`.
    /// The entry is mappable via `mach_vm_map` and transferable across
    /// processes via Mach port descriptors.
    ///
    /// For handles created by `allocate()`, the original anonymous VM region
    /// is kept alive (`backing_addr`) so the memory entry remains valid.
    /// For handles received from another process (`from_mach_port`), there
    /// is no local backing — the sending process keeps pages alive.
    pub struct MemHandle {
        /// Mach memory entry send right.
        entry: u32,
        size: crate::PageAlignedLen,
        /// If this handle owns the backing anonymous VM region, stores
        /// (addr, size) for cleanup in Drop. None for received handles.
        backing: Option<(u64, usize)>,
        /// Whether this handle supports writable shared mappings.
        /// `from_file()` creates read-only handles; `allocate()` and
        /// `branch()` create writable ones.
        writable: bool,
    }

    impl MemHandle {
        /// Allocate a new anonymous shared memory region.
        ///
        /// Allocates anonymous memory via `mach_vm_allocate`, creates a Mach
        /// memory entry from it, then deallocates the original region. The
        /// memory entry holds the pages alive and is transferable across
        /// processes via Mach port descriptors.
        #[allow(clippy::cast_possible_wrap)]
        pub fn allocate(_name: &CStr, size: usize) -> Result<Self> {
            let page_size = crate::PageAlignedLen::round_up(size)?;
            let aligned = *page_size;

            let addr = crate::platform::macos::vm_allocate(aligned)?;
            let (entry, _) = crate::platform::macos::make_memory_entry(addr, aligned)?;
            // Do NOT deallocate the backing region — the memory entry
            // (MAP_MEM_VM_SHARE) references the same physical pages.

            Ok(Self {
                entry,
                size: page_size,
                backing: Some((addr, aligned)),
                writable: true,
            })
        }

        /// Size of the backing memory in bytes (page-aligned by construction).
        #[inline]
        pub fn size(&self) -> crate::PageAlignedLen {
            self.size
        }

        /// Whether this handle supports writable shared mappings.
        ///
        /// Returns `false` for handles created via `from_file()` (read-only entry).
        /// `map_handle()` uses this to choose read-only vs read-write mapping.
        #[inline]
        pub fn is_writable(&self) -> bool {
            self.writable
        }

        /// Get the Mach memory entry port.
        #[inline]
        pub fn entry(&self) -> u32 {
            self.entry
        }

        /// Consume self and return the entry port without deallocating it.
        ///
        /// The backing VM region (if any) is released here: the Mach memory
        /// entry holds the physical pages alive via `MAP_MEM_VM_SHARE`, so
        /// unmapping the original VM range does not free them.
        ///
        /// Returns an error if releasing the backing region fails. In that
        /// case the port is also released so the caller does not need to
        /// clean up partial state.
        pub fn into_port(self) -> Result<u32> {
            let this = std::mem::ManuallyDrop::new(self);
            if let Some((addr, size)) = this.backing
                && let Err(e) = crate::platform::macos::vm_deallocate(addr, size)
            {
                crate::platform::macos::deallocate_port(this.entry);
                return Err(e);
            }
            Ok(this.entry)
        }

        /// Create from a raw Mach memory entry port (writable).
        ///
        /// # Safety
        ///
        /// The caller must ensure `port` is a valid memory entry port with
        /// `size` bytes of mappable memory. Ownership of the send right
        /// is transferred to this handle.
        pub unsafe fn from_mach_port(port: u32, size: usize) -> Result<Self> {
            let size = match crate::PageAlignedLen::from_page_aligned(size) {
                Ok(size) => size,
                Err(err) => {
                    crate::platform::macos::deallocate_port(port);
                    return Err(err);
                }
            };
            Ok(Self {
                entry: port,
                size,
                backing: None,
                writable: true,
            })
        }

        /// Create a read-only handle from a raw Mach memory entry port.
        ///
        /// Like [`from_mach_port`](Self::from_mach_port) but marks the handle
        /// as read-only. `map_handle()` will create a read-only mapping.
        /// Used when reconstructing file-backed handles received via IPC.
        ///
        /// # Safety
        ///
        /// The caller must ensure `port` is a valid memory entry port with
        /// `size` bytes of mappable memory. Ownership of the send right
        /// is transferred to this handle.
        pub unsafe fn from_mach_port_readonly(port: u32, size: usize) -> Result<Self> {
            let size = match crate::PageAlignedLen::from_page_aligned(size) {
                Ok(size) => size,
                Err(err) => {
                    crate::platform::macos::deallocate_port(port);
                    return Err(err);
                }
            };
            Ok(Self {
                entry: port,
                size,
                backing: None,
                writable: false,
            })
        }

        /// Allocate a region, map it, call `f` to write data, then unmap.
        /// The written data persists via the shared memory entry.
        pub fn allocate_and_write(
            name: &CStr,
            size: usize,
            f: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
        ) -> Result<Self> {
            let handle = Self::allocate(name, size)?;
            let mmap = crate::map_handle(&handle)?;
            // SAFETY: `mmap` is a freshly-made writable view of the Mach
            // memory entry created by `Self::allocate`, covering exactly
            // `size` bytes. `handle` is local and the Mach port has not yet
            // been cloned or returned to a caller, so `slice` is the unique
            // writable view for the lifetime of `f`. The borrow ends before
            // `drop(mmap)` unmaps it.
            let slice = unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), size) };
            f(slice).map_err(|e| MemError::SystemCall {
                operation: "allocate_and_write",
                source: e,
            })?;
            drop(mmap);
            Ok(handle)
        }

        /// Open a file and wrap it as a read-only `MemHandle`.
        ///
        /// Opens the file, mmaps it read-only, creates a `MAP_MEM_VM_SHARE`
        /// memory entry (RO), then unmaps the temporary mapping. The entry
        /// holds a reference to the file's VM object — pages are demand-paged
        /// from disk with no eager copy.
        ///
        /// The resulting handle has `is_writable() == false`. Use `branch()`
        /// to get a writable `CoW` copy.
        pub fn from_file(path: &std::path::Path) -> Result<Self> {
            use std::os::unix::io::IntoRawFd;

            let file = std::fs::File::open(path).map_err(|e| MemError::SystemCall {
                operation: "open",
                source: e,
            })?;
            #[allow(clippy::cast_possible_truncation)]
            let file_size = file
                .metadata()
                .map_err(|e| MemError::SystemCall {
                    operation: "fstat",
                    source: e,
                })?
                .len() as usize;
            if file_size == 0 {
                return Err(MemError::InvalidMemfd {
                    reason: "cannot create memory entry from zero-length file",
                });
            }

            let size = crate::PageAlignedLen::round_up(file_size)?;
            let fd = file.into_raw_fd();

            // mmap the file PROT_READ|PROT_WRITE + MAP_PRIVATE.
            //
            // The file fd is `O_RDONLY`, so the kernel never writes back to
            // disk regardless of mmap protection. PROT_WRITE on the mmap is
            // required only so that `mach_make_memory_entry_64` can issue
            // an entry whose `max_protection` includes VM_PROT_WRITE — the
            // entry is later mapped truly RO in the worker via
            // `map_entry_ro_anywhere` (cur=R, max=RW). HVF's `hv_vm_map`
            // checks the host vm_map_entry's `max_protection` and rejects
            // with `HV_ERROR (0xfae94001)` if VM_PROT_WRITE is absent,
            // even when the guest mapping is `HV_MEMORY_READ|HV_MEMORY_EXEC`.
            // SAFETY: null hint requests a kernel-chosen address; `fd` is a
            // valid raw fd from `file.into_raw_fd()`, `*size` is non-zero and
            // page-aligned. PROT_WRITE on MAP_PRIVATE is CoW-only and never
            // writes back to the O_RDONLY fd (see comment above).
            let map_ptr = unsafe {
                libc::mmap(
                    std::ptr::null_mut(),
                    *size,
                    libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_PRIVATE,
                    fd,
                    0,
                )
            };
            // Close the fd — the mmap holds a reference to the vnode.
            // SAFETY: `fd` was produced by `file.into_raw_fd()` and no other
            // owner exists; the mmap holds an independent vnode reference.
            unsafe { libc::close(fd) };

            if map_ptr == libc::MAP_FAILED {
                return Err(MemError::SystemCall {
                    operation: "mmap",
                    source: std::io::Error::last_os_error(),
                });
            }

            let map_addr = map_ptr as u64;

            // Create an RW VM_SHARE entry from the CoW-backed mapping.
            let result = crate::platform::macos::make_memory_entry(map_addr, *size);

            // Unmap the temporary mapping — the entry holds the VM object alive.
            // SAFETY: `map_ptr`/`*size` are the exact address/length returned
            // by the mmap above; the memory entry now holds the VM object.
            unsafe { libc::munmap(map_ptr, *size) };

            let (entry, _) = result?;

            Ok(Self {
                entry,
                size,
                backing: None,
                writable: false,
            })
        }

        /// Create a read-only mapping of this handle with explicit length.
        ///
        /// Maps `len` bytes from the memory entry (may exceed file size —
        /// kernel zero-fills past EOF within mapped pages). Used for pmem
        /// image data where the mapping size is page-aligned.
        pub fn read_only_mapping(&self, len: usize) -> Result<crate::MmapSlice> {
            let addr = crate::platform::macos::map_entry_ro_anywhere(self.entry, len)?;
            // SAFETY: `addr` was just returned by `map_entry_ro_anywhere`
            // (mach_vm_map) with exactly `len` bytes; ownership transfers
            // to MmapSlice which unmaps on drop.
            Ok(unsafe { crate::MmapSlice::from_raw(addr as *mut u8, len) })
        }

        /// Create a copy-on-write branch of this handle.
        ///
        /// Allocates a new VM region, populates it with `CoW` pages from the
        /// parent via `mach_vm_map(copy=TRUE)`, then creates a shared memory
        /// entry (`MAP_MEM_VM_SHARE`) from the new region. The resulting entry
        /// can be mapped shared by both parent and worker processes.
        ///
        /// No data is copied until the child writes to a shared page — the
        /// kernel handles `CoW` page faults transparently.
        ///
        /// # Safety
        ///
        /// The caller must guarantee that no execution context can write to
        /// this handle's mappings while the branch is created, otherwise the
        /// child snapshot may observe a torn or inconsistent parent state.
        pub unsafe fn branch(&self) -> Result<Self> {
            let parent_size = *self.size;

            // Allocate a fresh VM region for the child.
            let child_addr = crate::platform::macos::vm_allocate(parent_size)?;

            // Overwrite it with CoW pages from the parent entry.
            // mach_vm_map with copy=TRUE + VM_FLAGS_OVERWRITE populates the
            // child region with CoW references to the parent's pages.
            crate::platform::macos::map_entry_fixed(
                // SAFETY: child_addr is from vm_allocate, valid and aligned.
                unsafe { std::ptr::NonNull::new_unchecked(child_addr as *mut u8) },
                parent_size,
                self.entry,
            )?;

            // Create a shared entry from the child region so it can be
            // mapped by the worker process.
            let (child_entry, _) =
                crate::platform::macos::make_memory_entry(child_addr, parent_size)?;

            Ok(Self {
                entry: child_entry,
                size: self.size,
                backing: Some((child_addr, parent_size)),
                writable: true,
            })
        }

        /// Clone the handle by incrementing the Mach port reference count.
        pub fn try_clone(&self) -> Result<Self> {
            crate::platform::macos::clone_send_right(self.entry)?;
            Ok(Self {
                entry: self.entry,
                size: self.size,
                backing: None, // clone does not own the backing region
                writable: self.writable,
            })
        }
    }

    impl Drop for MemHandle {
        fn drop(&mut self) {
            crate::platform::macos::deallocate_port(self.entry);
            // Drop can't propagate; surface vm_deallocate failures (kernel
            // accounting drift, double-free, etc.) via the log so they don't
            // disappear silently. Callers that need to observe release errors
            // should use `into_port()` instead, which returns Result.
            if let Some((addr, size)) = self.backing
                && let Err(e) = crate::platform::macos::vm_deallocate(addr, size)
            {
                log::error!("MemHandle::drop: vm_deallocate({addr:#x}, {size}) failed: {e}");
            }
        }
    }

    // SAFETY: All fields are plain Copy types (u32, usize, bool, Option<(u64, usize)>)
    // with no interior mutability. Mach port operations called from &self methods
    // (mach_vm_map, mach_port_mod_refs) are kernel-serialized and thread-safe.
    unsafe impl Send for MemHandle {}
    // SAFETY: Same rationale as Send — no interior mutability and kernel-serialized
    // Mach operations from `&self`.
    unsafe impl Sync for MemHandle {}

    impl std::fmt::Debug for MemHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemHandle")
                .field("entry", &self.entry)
                .field("size", &self.size)
                .finish_non_exhaustive()
        }
    }
}

// ============================================================================
// Windows
// ============================================================================

#[cfg(windows)]
mod inner {
    use std::ffi::CStr;
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};

    use windows_sys::Win32::Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE};
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MapViewOfFile, PAGE_READONLY,
        PAGE_READWRITE, UnmapViewOfFile,
    };

    use super::{MemError, Result};

    /// Platform-specific memory handle (Windows: pagefile-backed section object).
    ///
    /// Uses `CreateFileMappingW(INVALID_HANDLE_VALUE, ...)` to create a
    /// pagefile-backed section (the Windows equivalent of Linux's memfd).
    /// The section can be mapped into any process via `MapViewOfFile`.
    ///
    /// # CoW branching
    ///
    /// `branch()` currently performs an **eager copy**: it allocates a new
    /// section the same size as the parent, maps both, and memcpy's the
    /// contents. Child writes never touch the parent, but the copy cost is
    /// paid up front regardless of how many pages the child mutates.
    ///
    /// Future optimization: switch to `FILE_MAP_COPY` so the parent is
    /// mapped copy-on-write and a private section is only materialized for
    /// pages the child actually writes. See `branch()` for the per-call
    /// details.
    pub struct MemHandle {
        /// Section object handle (pagefile-backed or file-backed).
        handle: OwnedHandle,
        size: crate::PageAlignedLen,
        /// Whether this handle supports writable shared mappings.
        writable: bool,
    }

    impl MemHandle {
        /// Allocate a new anonymous pagefile-backed section.
        ///
        /// Creates a section object with `PAGE_READWRITE` protection,
        /// backed by the system pagefile. This is the Windows equivalent
        /// of `memfd_create` + `ftruncate` on Linux.
        pub fn allocate(_name: &CStr, size: usize) -> Result<Self> {
            let page_size = crate::PageAlignedLen::round_up(size)?;
            let aligned = *page_size;

            let size_hi = amla_constants::num::hi32(aligned as u64);
            let size_lo = amla_constants::num::lo32(aligned as u64);

            // SAFETY: INVALID_HANDLE_VALUE requests a pagefile-backed section;
            // null SECURITY_ATTRIBUTES uses defaults; null name makes the
            // section anonymous. `aligned` is non-zero and split into the
            // required hi/lo DWORDs.
            let section = unsafe {
                CreateFileMappingW(
                    INVALID_HANDLE_VALUE,
                    std::ptr::null(),
                    PAGE_READWRITE,
                    size_hi,
                    size_lo,
                    std::ptr::null(),
                )
            };
            if section.is_null() {
                return Err(MemError::SystemCall {
                    operation: "CreateFileMappingW",
                    source: std::io::Error::last_os_error(),
                });
            }

            // SAFETY: `section` is a fresh non-null HANDLE from CreateFileMappingW
            // (checked above) with no other owners; OwnedHandle takes ownership
            // and closes it on drop.
            let handle = unsafe { OwnedHandle::from_raw_handle(section.cast()) };

            Ok(Self {
                handle,
                size: page_size,
                writable: true,
            })
        }

        /// Size of the backing memory in bytes (page-aligned by construction).
        #[inline]
        pub fn size(&self) -> crate::PageAlignedLen {
            self.size
        }

        /// Whether this handle supports writable shared mappings.
        ///
        /// Returns `false` for handles created via `from_file()` (read-only section).
        #[inline]
        pub fn is_writable(&self) -> bool {
            self.writable
        }

        /// Wrap an existing Windows section handle with a known size.
        pub fn from_handle(handle: OwnedHandle, size: usize) -> Result<Self> {
            Ok(Self {
                handle,
                size: crate::PageAlignedLen::from_page_aligned(size)?,
                writable: true,
            })
        }

        /// Wrap an existing Windows section handle as read-only.
        pub fn from_handle_readonly(handle: OwnedHandle, size: usize) -> Result<Self> {
            Ok(Self {
                handle,
                size: crate::PageAlignedLen::from_page_aligned(size)?,
                writable: false,
            })
        }

        /// Consume and return the underlying Windows handle.
        pub fn into_handle(self) -> OwnedHandle {
            self.handle
        }

        /// Borrow the underlying Windows handle.
        pub fn as_handle(&self) -> &OwnedHandle {
            &self.handle
        }

        /// Allocate a section, map it RW, call `f` to write data, unmap.
        ///
        /// The written data persists in the pagefile-backed section and is
        /// visible to all subsequent `MapViewOfFile` calls.
        pub fn allocate_and_write(
            name: &CStr,
            size: usize,
            f: impl FnOnce(&mut [u8]) -> std::io::Result<()>,
        ) -> Result<Self> {
            let handle = Self::allocate(name, size)?;

            // Map the section RW to write initial data.
            // SAFETY: `handle.handle` is the section just created by
            // `Self::allocate`, sized to `*handle.size`; offset 0 + that
            // size maps the whole section.
            let view = unsafe {
                MapViewOfFile(
                    handle.handle.as_raw_handle().cast(),
                    FILE_MAP_WRITE,
                    0,
                    0,
                    *handle.size,
                )
            };
            if view.Value.is_null() {
                return Err(MemError::SystemCall {
                    operation: "MapViewOfFile (allocate_and_write)",
                    source: std::io::Error::last_os_error(),
                });
            }

            // SAFETY: `MapViewOfFile` returned a non-null view (checked
            // above) of the section created by `Self::allocate`, covering
            // at least `size` bytes (section is sized to
            // `handle.size`, which is `size` page-rounded). `handle` has
            // not been returned to a caller, so `slice` is the unique
            // writable view for the lifetime of `f`; the borrow ends
            // before `UnmapViewOfFile`.
            let slice = unsafe { std::slice::from_raw_parts_mut(view.Value.cast::<u8>(), size) };
            let result = f(slice);

            // SAFETY: `view` was returned by the matching MapViewOfFile above
            // and has not been unmapped yet; the borrow from `slice` ended
            // before this call.
            let unmapped = unsafe { UnmapViewOfFile(view) };
            if unmapped == 0 {
                return Err(MemError::SystemCall {
                    operation: "UnmapViewOfFile (allocate_and_write)",
                    source: std::io::Error::last_os_error(),
                });
            }

            result.map_err(|e| MemError::SystemCall {
                operation: "allocate_and_write callback",
                source: e,
            })?;

            Ok(handle)
        }

        /// Open a file and wrap it as a read-only `MemHandle`.
        ///
        /// Creates a file-backed section object with `PAGE_READONLY`.
        /// The resulting handle has `is_writable() == false`.
        pub fn from_file(path: &std::path::Path) -> Result<Self> {
            use std::os::windows::ffi::OsStrExt;
            use windows_sys::Win32::Storage::FileSystem::{
                CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, OPEN_EXISTING,
            };

            let wide_path: Vec<u16> = path
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();

            // Open the file read-only.
            // SAFETY: `wide_path` is a null-terminated UTF-16 buffer owned
            // by this frame; null security/template handles use defaults.
            let file_handle = unsafe {
                CreateFileW(
                    wide_path.as_ptr(),
                    GENERIC_READ,
                    FILE_SHARE_READ,
                    std::ptr::null(),
                    OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL,
                    std::ptr::null_mut(),
                )
            };
            if file_handle == INVALID_HANDLE_VALUE {
                return Err(MemError::SystemCall {
                    operation: "CreateFileW",
                    source: std::io::Error::last_os_error(),
                });
            }

            // Get file size.
            let mut file_size: u64 = 0;
            // SAFETY: `file_handle` is a valid handle (checked above);
            // `&mut file_size` is a valid pointer to a u64 on this stack frame.
            let ok = unsafe {
                windows_sys::Win32::Storage::FileSystem::GetFileSizeEx(
                    file_handle,
                    &mut file_size as *mut u64 as *mut _,
                )
            };
            if ok == 0 {
                let err = std::io::Error::last_os_error();
                // SAFETY: `file_handle` is a valid handle from CreateFileW
                // (checked above) and has no other owners.
                unsafe { CloseHandle(file_handle) };
                return Err(MemError::SystemCall {
                    operation: "GetFileSizeEx",
                    source: err,
                });
            }
            #[allow(clippy::cast_possible_truncation)]
            let file_size = file_size as usize;
            if file_size == 0 {
                // SAFETY: `file_handle` is a valid handle from CreateFileW
                // (checked above) and has no other owners.
                unsafe { CloseHandle(file_handle) };
                return Err(MemError::InvalidMemfd {
                    reason: "cannot create section from zero-length file",
                });
            }

            // Create a read-only section backed by the file.
            // SAFETY: `file_handle` is valid (checked above); null security
            // and name use defaults; size 0 means "use the file size".
            let section = unsafe {
                CreateFileMappingW(
                    file_handle,
                    std::ptr::null(),
                    PAGE_READONLY,
                    0,
                    0, // Use file size
                    std::ptr::null(),
                )
            };
            // SAFETY: `file_handle` is a valid handle from CreateFileW; the
            // section (if created) holds an independent reference to the
            // underlying file object.
            unsafe { CloseHandle(file_handle) };

            if section.is_null() {
                return Err(MemError::SystemCall {
                    operation: "CreateFileMappingW (from_file)",
                    source: std::io::Error::last_os_error(),
                });
            }

            // SAFETY: `section` is a fresh non-null HANDLE from
            // CreateFileMappingW (checked above) with no other owners.
            let handle = unsafe { OwnedHandle::from_raw_handle(section.cast()) };

            Ok(Self {
                handle,
                size: crate::PageAlignedLen::round_up(file_size)?,
                writable: false,
            })
        }

        /// Create a read-only mapping of this handle with explicit length.
        pub fn read_only_mapping(&self, len: usize) -> Result<crate::MmapSlice> {
            if len == 0 {
                return Err(MemError::InvalidMemfd {
                    reason: "cannot map zero-length region",
                });
            }
            // SAFETY: `self.handle` is a valid section owned by `&self`;
            // offset 0 + `len` (non-zero, checked above) maps up to `len`
            // bytes starting at the section base.
            let view = unsafe {
                MapViewOfFile(self.handle.as_raw_handle().cast(), FILE_MAP_READ, 0, 0, len)
            };
            if view.Value.is_null() {
                return Err(MemError::SystemCall {
                    operation: "MapViewOfFile (read_only_mapping)",
                    source: std::io::Error::last_os_error(),
                });
            }
            // SAFETY: `view.Value` was just returned by MapViewOfFile (non-null
            // checked above) and covers `len` bytes; ownership transfers to
            // MmapSlice which unmaps on drop.
            Ok(unsafe { crate::MmapSlice::from_raw(view.Value.cast::<u8>(), len) })
        }

        /// Create a copy-on-write branch of this handle.
        ///
        /// Creates a new pagefile-backed section and copies the parent's
        /// data into it. On Windows, true lazy CoW requires memory-mapped
        /// file tricks; for now we do an eager copy via mapped views.
        ///
        /// # How it works
        ///
        /// 1. Create a new pagefile-backed section of the same size
        /// 2. Map the parent section as `FILE_MAP_READ`
        /// 3. Map the child section as `FILE_MAP_WRITE`
        /// 4. Copy parent → child
        /// 5. Unmap both views
        ///
        /// Future optimization: use `FILE_MAP_COPY` for lazy CoW semantics
        /// by mapping the parent with copy-on-write and deferring the
        /// creation of a new backing section until pages are actually
        /// written.
        ///
        /// # Safety
        ///
        /// The caller must guarantee that no execution context can write to
        /// this handle's mappings while the branch is created, otherwise the
        /// child snapshot may observe a torn or inconsistent parent state.
        #[allow(clippy::cast_possible_truncation)]
        pub unsafe fn branch(&self) -> Result<Self> {
            let size = *self.size;

            // Create child section.
            let child = Self::allocate(c"branch", size)?;

            // Map parent read-only.
            // SAFETY: `self.handle` is a valid section owned by `&self`;
            // offset 0 + `size` maps the whole section (sized to `size`).
            let parent_view = unsafe {
                MapViewOfFile(
                    self.handle.as_raw_handle().cast(),
                    FILE_MAP_READ,
                    0,
                    0,
                    size,
                )
            };
            if parent_view.Value.is_null() {
                return Err(MemError::SystemCall {
                    operation: "MapViewOfFile (branch parent)",
                    source: std::io::Error::last_os_error(),
                });
            }

            // Map child read-write.
            // SAFETY: `child.handle` is the section just created by
            // `Self::allocate`, sized to `size`.
            let child_view = unsafe {
                MapViewOfFile(
                    child.handle.as_raw_handle().cast(),
                    FILE_MAP_WRITE,
                    0,
                    0,
                    size,
                )
            };
            if child_view.Value.is_null() {
                let err = std::io::Error::last_os_error();
                // SAFETY: `parent_view` was returned by the MapViewOfFile call
                // above (non-null checked) and has not been unmapped yet.
                unsafe { UnmapViewOfFile(parent_view) };
                return Err(MemError::SystemCall {
                    operation: "MapViewOfFile (branch child)",
                    source: err,
                });
            }

            // Copy parent data to child.
            // SAFETY: both views are non-null (checked above), each backs
            // `size` bytes, and the two views are in disjoint allocations.
            unsafe {
                std::ptr::copy_nonoverlapping(
                    parent_view.Value.cast::<u8>(),
                    child_view.Value.cast::<u8>(),
                    size,
                );
            }

            // Unmap both views.
            // SAFETY: both views were returned by the MapViewOfFile calls
            // above (non-null checked) and have not been unmapped yet;
            // the copy_nonoverlapping borrow ended before this block.
            unsafe {
                UnmapViewOfFile(child_view);
                UnmapViewOfFile(parent_view);
            }

            Ok(child)
        }

        /// Release pages back to the system.
        ///
        /// On Windows, uses `DiscardVirtualMemory` on a temporary mapping
        /// to discard the pages. The next read returns zeros.
        ///
        /// Note: This is less efficient than Linux's `fallocate(PUNCH_HOLE)`
        /// because we need to map/unmap. For the common case (full-region
        /// discard on VM teardown), this is acceptable.
        pub fn punch_hole(&self, offset: u64, len: u64) -> Result<()> {
            if !self.writable {
                return Err(MemError::InvalidState {
                    expected: "writable handle",
                    actual: "read-only handle (from_file)",
                });
            }
            let range = crate::PageRange::new(offset, len, self.size)?;

            // Map the region, zero it, unmap. DiscardVirtualMemory only
            // works on VirtualAlloc'd memory, not MapViewOfFile views.
            // For section-backed memory, we zero the pages explicitly.
            // SAFETY: `self.handle` is a valid writable section owned by
            // `&self`; `range.offset()` is split into the required hi/lo
            // DWORDs and `range.len_usize()` authorizes the mapped span.
            let view = unsafe {
                MapViewOfFile(
                    self.handle.as_raw_handle().cast(),
                    FILE_MAP_WRITE,
                    amla_constants::num::hi32(range.offset()),
                    amla_constants::num::lo32(range.offset()),
                    range.len_usize(),
                )
            };
            if view.Value.is_null() {
                return Err(MemError::SystemCall {
                    operation: "MapViewOfFile (punch_hole)",
                    source: std::io::Error::last_os_error(),
                });
            }

            // Zero the region.
            // SAFETY: `view.Value` is non-null (checked above) and backs
            // `range.len_usize()` writable bytes; no other view aliases this range.
            unsafe {
                std::ptr::write_bytes(view.Value.cast::<u8>(), 0, range.len_usize());
            }

            // SAFETY: `view` was returned by the MapViewOfFile call above
            // (non-null checked) and has not been unmapped yet; the write
            // borrow ended before this call.
            let unmapped = unsafe { UnmapViewOfFile(view) };
            if unmapped == 0 {
                return Err(MemError::SystemCall {
                    operation: "UnmapViewOfFile (punch_hole)",
                    source: std::io::Error::last_os_error(),
                });
            }

            Ok(())
        }

        /// Clone the handle via `DuplicateHandle`.
        pub fn try_clone(&self) -> Result<Self> {
            let handle = self
                .handle
                .try_clone()
                .map_err(MemError::sys("DuplicateHandle"))?;
            Ok(Self {
                handle,
                size: self.size,
                writable: self.writable,
            })
        }
    }

    impl std::fmt::Debug for MemHandle {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MemHandle")
                .field("size", &self.size)
                .field("writable", &self.writable)
                .finish_non_exhaustive()
        }
    }

    // SAFETY: OwnedHandle is Send+Sync. Section object handles are
    // process-wide kernel objects safe to use from any thread.
    unsafe impl Send for MemHandle {}
    // SAFETY: Same rationale as Send — the handle is a kernel object with
    // no interior mutability from `&self`.
    unsafe impl Sync for MemHandle {}
}

pub use inner::MemHandle;

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use std::io::Write;
    use std::os::fd::AsRawFd;
    use std::os::fd::OwnedFd;

    use super::*;

    fn read_only_temp_fd(data: &[u8]) -> OwnedFd {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(data).unwrap();
        file.flush().unwrap();
        std::fs::File::open(file.path()).unwrap().into()
    }

    #[test]
    fn allocate_creates_valid_handle() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        assert_eq!(*h.size(), 4096);
        assert!(h.as_raw_fd() >= 0);
    }

    #[test]
    fn from_fd_wraps_existing() {
        let h1 = MemHandle::allocate(c"test", 8192).unwrap();
        let raw = h1.as_raw_fd();
        let fd_arc = h1.into_fd_arc();
        assert_eq!(fd_arc.as_raw_fd(), raw);

        let h2 = MemHandle::from_fd_arc(fd_arc, 8192).unwrap();
        assert_eq!(*h2.size(), 8192);
    }

    #[test]
    fn from_fd_validated_happy() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        let fd = std::sync::Arc::try_unwrap(h.into_fd_arc()).expect("unique Arc");
        let h2 = MemHandle::from_fd_validated(fd, 4096).unwrap();
        assert_eq!(*h2.size(), 4096);
    }

    #[test]
    fn from_fd_validated_size_mismatch() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        let fd = std::sync::Arc::try_unwrap(h.into_fd_arc()).expect("unique Arc");
        let err = MemHandle::from_fd_validated(fd, 8192).unwrap_err();
        assert!(matches!(err, MemError::SizeMismatch { .. }));
    }

    #[test]
    fn from_fd_validated_not_page_aligned() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        let fd = std::sync::Arc::try_unwrap(h.into_fd_arc()).expect("unique Arc");
        let err = MemHandle::from_fd_validated(fd, 4097).unwrap_err();
        assert!(matches!(err, MemError::NotPageAligned { .. }));
    }

    #[test]
    fn from_fd_arc_rejects_size_mismatch() {
        let page = crate::page_size();
        let h = MemHandle::allocate(c"test", page).unwrap();
        let fd = h.into_fd_arc();
        let err = MemHandle::from_fd_arc(fd, page * 2).unwrap_err();
        assert!(matches!(err, MemError::SizeMismatch { .. }));
    }

    #[test]
    fn from_fd_arc_rejects_zero_size() {
        let page = crate::page_size();
        let h = MemHandle::allocate(c"test", page).unwrap();
        let fd = h.into_fd_arc();
        let err = MemHandle::from_fd_arc(fd, 0).unwrap_err();
        assert!(matches!(err, MemError::InvalidMemfd { .. }));
    }

    #[test]
    fn from_fd_arc_readonly_rejects_writable_fd() {
        let page = crate::page_size();
        let h = MemHandle::allocate(c"test", page).unwrap();
        let fd = h.into_fd_arc();
        let err = MemHandle::from_fd_arc_readonly(fd, page).unwrap_err();
        assert!(matches!(err, MemError::InvalidMemfd { .. }));
    }

    #[test]
    fn from_fd_arc_readonly_accepts_readonly_fd() {
        let page = crate::page_size();
        let fd = std::sync::Arc::new(read_only_temp_fd(&vec![0; page]));
        let handle = MemHandle::from_fd_arc_readonly(fd, page).unwrap();
        assert!(!handle.is_writable());
    }

    #[test]
    fn from_fd_range_requires_page_aligned_len() {
        let page = crate::page_size();
        let fd = read_only_temp_fd(&vec![0; page * 2]);
        let err = MemHandle::from_fd_range(fd, 0, page + 1).unwrap_err();
        assert!(matches!(err, MemError::NotPageAligned { .. }));
    }

    #[test]
    fn from_fd_range_rejects_past_eof() {
        let page = crate::page_size();
        let fd = read_only_temp_fd(&vec![0; page]);
        let err = MemHandle::from_fd_range(fd, u64::try_from(page).unwrap(), page).unwrap_err();
        assert!(matches!(err, MemError::InvalidMemfd { .. }));
    }

    #[test]
    fn from_fd_range_mapping_uses_stored_offset() {
        let page = crate::page_size();
        let mut data = vec![0; page * 2];
        data[..page].fill(0x11);
        data[page..].fill(0x22);

        let fd = read_only_temp_fd(&data);
        let handle = MemHandle::from_fd_range(fd, u64::try_from(page).unwrap(), page).unwrap();
        assert!(!handle.is_writable());

        let mmap = crate::backing::map_handle(&handle).unwrap();
        assert_eq!(mmap.len(), page);
        // SAFETY: read-only mapping in a single-threaded test.
        let bytes = unsafe { mmap.as_slice_unchecked() };
        assert!(bytes.iter().all(|&b| b == 0x22));
    }

    #[test]
    fn read_only_mapping_rejects_wrong_len() {
        let page = crate::page_size();
        let fd = read_only_temp_fd(&vec![0; page]);
        let handle = MemHandle::from_fd_range(fd, 0, page).unwrap();
        let err = handle.read_only_mapping(page / 2).unwrap_err();
        assert!(matches!(err, MemError::SizeMismatch { .. }));
    }

    #[test]
    fn try_clone_shares_fd_arc() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        let cloned = h.try_clone().unwrap();
        assert_eq!(h.size(), cloned.size());
        // Arc sharing means both handles report the same kernel fd.
        assert_eq!(h.as_raw_fd(), cloned.as_raw_fd());
    }

    #[test]
    fn debug_hides_fd() {
        let h = MemHandle::allocate(c"test", 4096).unwrap();
        let debug = format!("{h:?}");
        assert!(debug.contains("MemHandle"));
        assert!(debug.contains("4096"));
    }

    #[test]
    fn branch_creates_independent_handle() {
        let root = MemHandle::allocate(c"test", 4096).unwrap();
        // SAFETY: The test owns `root` and has no active mappings or writers.
        let child = unsafe { root.branch() }.unwrap();
        assert_eq!(*child.size(), 4096);
        assert_ne!(root.as_raw_fd(), child.as_raw_fd());
    }

    #[test]
    fn branch_preserves_parent_data() {
        let root = MemHandle::allocate(c"test", 4096).unwrap();

        // Write to root via mmap
        {
            let mmap = crate::backing::map_handle(&root).unwrap();
            // SAFETY: `mmap` is a shared RW mapping of 4096 bytes; this is
            // the only outstanding view of `root` in the test.
            let slice = unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), 4096) };
            slice[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        }

        // SAFETY: The temporary write mapping was dropped above, and the test
        // owns `root` with no other writers.
        let child = unsafe { root.branch() }.unwrap();

        // Child should see parent's data (eager copy or CowTree).
        let child_mmap = crate::backing::map_handle(&child).unwrap();
        // SAFETY: test-local child mapping has no concurrent writers.
        let child_bytes = unsafe { child_mmap.as_slice_unchecked() };
        let value = u32::from_le_bytes(child_bytes[0..4].try_into().unwrap());
        assert_eq!(value, 0xDEAD_BEEF);
    }

    #[test]
    fn branch_can_rebranch() {
        let root = MemHandle::allocate(c"test", 4096).unwrap();
        // SAFETY: The test owns `root` and has no active mappings or writers.
        let child = unsafe { root.branch() }.unwrap();
        // SAFETY: The test owns `child` and has no active mappings or writers.
        let grandchild = unsafe { child.branch() }.unwrap();
        assert_eq!(*grandchild.size(), 4096);
    }

    #[test]
    fn punch_hole_works() {
        let root = MemHandle::allocate(c"test", 4096).unwrap();
        // Write some data
        {
            let mmap = crate::backing::map_handle(&root).unwrap();
            // SAFETY: `mmap` is a shared RW mapping of 4096 bytes; this is
            // the only outstanding view of `root` in the test.
            let slice = unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), 4096) };
            slice[0] = 0xFF;
        }
        // Punch a hole — should not panic
        root.punch_hole(0, 4096).unwrap();
    }

    #[test]
    fn punch_hole_rejects_invalid_ranges() {
        let page = crate::page_size();
        let root = MemHandle::allocate(c"test", page * 2).unwrap();
        let page_u64 = u64::try_from(page).unwrap();

        for (offset, len) in [
            (0, 0),
            (1, page_u64),
            (0, page_u64 + 1),
            (page_u64, page_u64 * 2),
            (u64::MAX, page_u64),
        ] {
            let err = root.punch_hole(offset, len).unwrap_err();
            assert!(matches!(err, MemError::InvalidRange { .. }));
        }
    }
}
