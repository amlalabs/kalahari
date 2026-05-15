// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Rust bindings for the `cowtree` kernel module.
//!
//! `cowtree` provides branching copy-on-write memory, enabling efficient
//! hierarchical VM snapshots. Each branch shares pages with its parent
//! until written, at which point a private copy is made.
//!
//! ```text
//! Base (memfd with kernel image)
//!     ├── Branch 1 (running VM) - shares base pages, CoW on write
//!     │   └── Branch 3 (snapshot of VM 1)
//!     └── Branch 2 (running VM)
//! ```
//!
//! # Usage
//!
//! ```ignore
//! use amla_cowtree::CowTree;
//! use std::os::fd::AsFd;
//!
//! // Create a base memfd with kernel image
//! let base = memfd::MemfdOptions::default().create("base")?;
//! base.as_file().set_len(1 << 30)?; // 1GB
//! // ... write kernel image to base ...
//!
//! // Create a memory tree from the base
//! let mut tree = CowTree::from_base(base.as_fd(), 1 << 30)?;
//!
//! // Create branches (VMs) - each gets CoW access
//! let base = unsafe { FrozenBranch::assume_frozen(BranchId::BASE) };
//! let vm1_fd = tree.branch(base)?; // branch from base
//! let vm1_id = vm1_fd.id();
//! let vm2_fd = tree.branch(base)?;
//! let vm2_id = vm2_fd.id();
//!
//! // mmap the branch fd for CoW access
//! let vm1_mem = unsafe {
//!     libc::mmap(std::ptr::null_mut(), 1 << 30,
//!         libc::PROT_READ | libc::PROT_WRITE, libc::MAP_SHARED,
//!         vm1_fd.as_raw_fd(), 0)
//! };
//! // Reads return base pages, writes trigger CoW
//!
//! // Explicit destroy (retryable on failure)
//! tree.destroy()?;
//! // Or just drop — Drop impl handles cleanup automatically
//! ```
//!
//! # Kernel Module Required
//!
//! This crate requires the `cowtree` kernel module to be loaded:
//! ```bash
//! sudo insmod cowtree.ko
//! ```

// The ioctl encoding uses the asm-generic _IOC layout (NRSHIFT=0, TYPESHIFT=8,
// SIZESHIFT=16, DIRSHIFT=30), which is identical on x86_64 and arm64.
// All repr(C) structs use fixed-width types (__u64/__u32/__s32) with the same
// alignment on both architectures.
//
// On non-Linux targets this crate is empty — cowtree requires the Linux kernel module.

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd, RawFd};
#[cfg(target_os = "linux")]
use std::ptr::NonNull;
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
use rustix::mm::{MapFlags, ProtFlags, mmap, munmap};

#[cfg(target_os = "linux")]
mod ioctl;
#[cfg(target_os = "linux")]
pub use ioctl::{GlobalStats, Stats};

// =============================================================================
// Error Types
// =============================================================================

/// Errors from `cowtree` operations.
#[cfg(target_os = "linux")]
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Failed to open /dev/cowtree device.
    #[error("failed to open /dev/cowtree: {0} (is the kernel module loaded?)")]
    DeviceOpen(io::Error),

    /// ioctl failed.
    #[error("{operation} failed: {source}")]
    Ioctl {
        operation: &'static str,
        #[source]
        source: io::Error,
    },

    /// Branch or tree not found (ENOENT from kernel).
    ///
    /// The kernel returns ENOENT for both "tree not found" and "parent
    /// branch not found". Both IDs are included for debugging context.
    #[error("branch {parent_id} or tree {tree_id} not found (ENOENT)")]
    NotFound { tree_id: u64, parent_id: BranchId },

    /// mmap failed.
    #[error("mmap failed: {0}")]
    Mmap(io::Error),

    /// Tree has already been destroyed or disassembled via `into_parts()`.
    #[error("CowTree has been destroyed or disassembled")]
    Destroyed,

    /// Cannot disassemble a tree while branch handles still own cleanup authority.
    #[error("CowTree has active branch handles")]
    BranchesActive,

    /// Invalid size (not page-aligned or zero).
    #[error("invalid size {0}: must be non-zero and page-aligned")]
    InvalidSize(usize),

    /// Invalid page range.
    #[error("invalid range offset={offset} len={len} size={size}: {reason}")]
    InvalidRange {
        /// Range start in bytes.
        offset: u64,
        /// Range length in bytes.
        len: u64,
        /// Containing tree size in bytes.
        size: usize,
        /// Reason the range is invalid.
        reason: &'static str,
    },
}

#[cfg(target_os = "linux")]
pub type Result<T> = std::result::Result<T, Error>;

// =============================================================================
// Branch ID
// =============================================================================

/// Identifier for a branch within a memory tree.
///
/// Branch IDs are assigned by the kernel and are unique within a tree.
/// Use `0` to refer to the base/root (for branching from base).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct BranchId(u64);

#[cfg(target_os = "linux")]
impl BranchId {
    /// Branch from the base (`parent_id` = 0).
    pub const BASE: Self = Self(0);

    /// Create a branch ID from a raw value.
    #[inline]
    pub const fn new(id: u64) -> Self {
        Self(id)
    }

    /// Get the raw ID value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Display for BranchId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Branch({})", self.0)
    }
}

// =============================================================================
// Branch Freeze Proof
// =============================================================================

/// Proof that a branch is frozen for snapshot branching.
///
/// The cowtree kernel freezes the parent for new write faults when creating a
/// child branch, but it does not flush existing writable PTEs. Safe branching
/// therefore requires an external proof that no CPU can keep writing through
/// already-valid parent mappings while the snapshot is taken.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FrozenBranch {
    id: BranchId,
}

#[cfg(target_os = "linux")]
impl FrozenBranch {
    /// Assert that `id` is frozen and safe to branch from.
    ///
    /// # Safety
    ///
    /// The caller must guarantee that all execution contexts that can write to
    /// mappings of this branch are stopped before this token is created and
    /// remain unable to write for the duration of the branch operation. Before
    /// any such context resumes, the caller must also ensure stale writable TLB
    /// entries or mappings that predate the branch operation can no longer be
    /// used to mutate pages shared with the child snapshot.
    ///
    /// Violating this contract can break snapshot isolation: writes through
    /// stale parent mappings may bypass cowtree's freeze checks.
    #[inline]
    pub const unsafe fn assume_frozen(id: BranchId) -> Self {
        Self { id }
    }

    /// Return the frozen branch ID.
    #[inline]
    pub const fn branch_id(self) -> BranchId {
        self.id
    }
}

// =============================================================================
// Page Range
// =============================================================================

/// A non-empty, page-aligned byte range checked against a cowtree size.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PageRange {
    offset: u64,
    len: u64,
    tree_size: usize,
}

#[cfg(target_os = "linux")]
impl PageRange {
    /// Validate a raw byte range against a containing cowtree size.
    ///
    /// Rejects zero length, non-page-aligned start or length, arithmetic
    /// overflow, and ranges that extend past `tree_size`.
    #[inline]
    pub fn new(offset: u64, len: u64, tree_size: usize) -> Result<Self> {
        let page_size =
            u64::try_from(rustix::param::page_size()).map_err(|_| Error::InvalidRange {
                offset,
                len,
                size: tree_size,
                reason: "page size does not fit in u64",
            })?;

        if len == 0 {
            return Err(Error::InvalidRange {
                offset,
                len,
                size: tree_size,
                reason: "range length must be non-zero",
            });
        }
        if !offset.is_multiple_of(page_size) {
            return Err(Error::InvalidRange {
                offset,
                len,
                size: tree_size,
                reason: "range offset is not page-aligned",
            });
        }
        if !len.is_multiple_of(page_size) {
            return Err(Error::InvalidRange {
                offset,
                len,
                size: tree_size,
                reason: "range length is not page-aligned",
            });
        }

        let end = offset.checked_add(len).ok_or(Error::InvalidRange {
            offset,
            len,
            size: tree_size,
            reason: "range end overflows",
        })?;
        let tree_size_u64 = u64::try_from(tree_size).map_err(|_| Error::InvalidRange {
            offset,
            len,
            size: tree_size,
            reason: "tree size does not fit in u64",
        })?;
        if end > tree_size_u64 {
            return Err(Error::InvalidRange {
                offset,
                len,
                size: tree_size,
                reason: "range extends past tree size",
            });
        }

        Ok(Self {
            offset,
            len,
            tree_size,
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
        self.len
    }

    /// Tree size this range was checked against.
    #[inline]
    pub const fn tree_size(self) -> usize {
        self.tree_size
    }
}

// =============================================================================
// Memory Tree
// =============================================================================

#[cfg(target_os = "linux")]
struct CowTreeInner {
    /// File descriptor for /dev/cowtree control device.
    /// `None` after `into_parts()` has been called or `destroy()` succeeded.
    ctl_fd: Mutex<Option<OwnedFd>>,
    /// Tree ID returned by `CREATE_TREE`
    tree_id: u64,
    /// Size of the memory region
    size: usize,
}

#[cfg(target_os = "linux")]
impl CowTreeInner {
    const fn new(ctl_fd: OwnedFd, tree_id: u64, size: usize) -> Self {
        Self {
            ctl_fd: Mutex::new(Some(ctl_fd)),
            tree_id,
            size,
        }
    }

    // The `&OwnedFd` borrow handed to `f` lives for the duration of
    // `guard`; dropping the guard early (as `significant_drop_tightening`
    // would otherwise suggest) makes the borrow dangle. The lock IS the
    // critical section here — we hold it across the ioctl on purpose so
    // that a concurrent `destroy()` can't pull the fd out from under us.
    #[allow(clippy::significant_drop_tightening)]
    fn with_ctl_fd<T>(&self, f: impl FnOnce(&OwnedFd) -> Result<T>) -> Result<T> {
        let guard = self
            .ctl_fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let ctl_fd = guard.as_ref().ok_or(Error::Destroyed)?;
        f(ctl_fd)
    }

    fn destroy(&self) -> Result<()> {
        let mut guard = self
            .ctl_fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(ctl_fd) = guard.as_ref() else {
            return Ok(());
        };
        let result = ioctl::destroy_tree(ctl_fd, self.tree_id);
        if result.is_ok() {
            guard.take();
        }
        result
    }

    fn is_alive(&self) -> bool {
        self.ctl_fd
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_some()
    }

    fn into_parts(mut self) -> Result<(OwnedFd, u64, usize)> {
        let ctl_fd = self
            .ctl_fd
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner())
            .take()
            .ok_or(Error::Destroyed)?;
        Ok((ctl_fd, self.tree_id, self.size))
    }
}

#[cfg(target_os = "linux")]
impl Drop for CowTreeInner {
    fn drop(&mut self) {
        let Some(ctl_fd) = self
            .ctl_fd
            .get_mut()
            .unwrap_or_else(|poison| poison.into_inner())
            .as_ref()
        else {
            return;
        };

        match ioctl::destroy_tree(ctl_fd, self.tree_id) {
            Ok(()) => {}
            Err(e) => {
                let errno = match &e {
                    Error::Ioctl { source, .. } => source.raw_os_error(),
                    _ => None,
                };
                match errno {
                    Some(libc::ENOENT) => {
                        log::debug!("CowTree::drop: tree {} already destroyed", self.tree_id);
                    }
                    Some(libc::EBUSY) => {
                        log::error!(
                            "CowTree::drop: tree {} still has active kernel users \
                             after Rust branch handles dropped: {e}",
                            self.tree_id
                        );
                    }
                    _ => {
                        log::error!(
                            "CowTree::drop: failed to destroy tree {}: {e} \
                             (kernel resources may be leaked)",
                            self.tree_id
                        );
                    }
                }
            }
        }
    }
}

/// A memory tree providing branching copy-on-write memory.
///
/// `CowTree` manages a hierarchy of memory branches backed by a base memfd.
/// Each [`BranchFd`] shares a cleanup handle with the tree, so branch fds and
/// branch mappings keep the kernel destroy authority alive until they are gone.
/// `CowTree` is `Send + Sync`; the kernel handles synchronization.
#[cfg(target_os = "linux")]
pub struct CowTree {
    inner: Option<Arc<CowTreeInner>>,
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for CowTree {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CowTree")
            .field("tree_id", &self.tree_id())
            .field("size", &self.size())
            .field(
                "alive",
                &self.inner.as_ref().is_some_and(|inner| inner.is_alive()),
            )
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl CowTree {
    /// Device path for cowtree.
    pub const DEVICE_PATH: &'static str = "/dev/cowtree";

    /// Get the shared inner handle, returning `Err(Destroyed)` after `destroy()`.
    fn inner(&self) -> Result<&Arc<CowTreeInner>> {
        self.inner.as_ref().ok_or(Error::Destroyed)
    }

    /// Create a new memory tree from a base memfd.
    ///
    /// The base memfd provides the initial content for all branches.
    /// Branches share base pages via copy-on-write - reads return base pages,
    /// writes allocate private copies.
    ///
    /// # Arguments
    ///
    /// * `base_fd` - Borrowed file descriptor to memfd/shmem with base content
    /// * `size` - Size of the memory region (must match base)
    ///
    /// # Errors
    ///
    /// - `DeviceOpen`: /dev/cowtree not available (module not loaded?)
    /// - `InvalidSize`: Size is zero or not page-aligned
    /// - `Ioctl`: Kernel rejected the create request
    pub fn from_base(base_fd: BorrowedFd<'_>, size: usize) -> Result<Self> {
        let page_size = rustix::param::page_size();
        if size == 0 || !size.is_multiple_of(page_size) {
            return Err(Error::InvalidSize(size));
        }

        // Open the control device
        let ctl_fd = OpenOptions::new()
            .read(true)
            .write(true)
            .open(Self::DEVICE_PATH)
            .map_err(Error::DeviceOpen)?;

        let ctl_fd = OwnedFd::from(ctl_fd);

        // Create the tree
        let tree_id = ioctl::create_tree(&ctl_fd, base_fd.as_raw_fd(), size as u64)?;

        Ok(Self {
            inner: Some(Arc::new(CowTreeInner::new(ctl_fd, tree_id, size))),
        })
    }

    /// Create a new branch from a parent.
    ///
    /// Returns a branch fd wrapper that can be mmap'd for copy-on-write access.
    ///
    /// The returned [`BranchFd`] keeps the tree cleanup authority alive, so
    /// dropping `CowTree` before branch fds or mappings cannot leak the kernel
    /// tree. Use [`BranchFd::id`] to get the branch ID.
    ///
    /// Use a frozen `BranchId::BASE` proof to branch from the base.
    ///
    /// # Side Effects
    ///
    /// Creating a child branch freezes the parent for new write faults, but
    /// existing writable PTEs remain valid because the kernel does not flush
    /// TLBs. The [`FrozenBranch`] token makes that external synchronization
    /// requirement explicit.
    ///
    /// # Errors
    ///
    /// - `NotFound`: Parent branch or tree doesn't exist
    /// - `Ioctl`: Kernel rejected the request
    pub fn branch(&self, parent: FrozenBranch) -> Result<BranchFd> {
        let inner = self.inner()?;
        let (fd, id) = inner.with_ctl_fd(|fd| {
            ioctl::create_branch(fd, inner.tree_id, parent.branch_id().as_u64())
        })?;
        Ok(BranchFd {
            fd,
            id,
            tree: Arc::clone(inner),
        })
    }

    /// Get statistics for the entire tree.
    pub fn stats(&self) -> Result<Stats> {
        let inner = self.inner()?;
        inner.with_ctl_fd(|fd| ioctl::get_stats(fd, inner.tree_id, 0))
    }

    /// Get statistics for a specific branch.
    pub fn branch_stats(&self, branch_id: BranchId) -> Result<Stats> {
        let inner = self.inner()?;
        inner.with_ctl_fd(|fd| ioctl::get_stats(fd, inner.tree_id, branch_id.as_u64()))
    }

    /// Get global allocation statistics.
    ///
    /// Returns counters for all active allocations across all trees.
    /// Useful for leak detection and debugging.
    pub fn global_stats(&self) -> Result<GlobalStats> {
        let inner = self.inner()?;
        inner.with_ctl_fd(ioctl::get_global_stats)
    }

    /// Set a per-branch page limit for host-side memory enforcement.
    ///
    /// When the branch reaches this many copy-on-write pages, further write faults
    /// will receive SIGBUS. A limit of 0 means unlimited (default).
    ///
    /// This is a soft limit: concurrent faults may overshoot by up to #CPUs
    /// pages, which is acceptable for the host-side enforcement use case.
    pub fn set_page_limit(&self, branch_id: BranchId, max_pages: u64) -> Result<()> {
        let inner = self.inner()?;
        inner.with_ctl_fd(|fd| ioctl::set_limit(fd, inner.tree_id, branch_id.as_u64(), max_pages))
    }

    /// Punch a hole in a branch's page cache (reclaim copy-on-write pages).
    ///
    /// Evicts copy-on-write pages for the given byte range, restoring sharing
    /// with parent/base. The next read fault returns parent content; the next
    /// write fault triggers a new copy-on-write.
    ///
    /// This is the host-side mechanism for virtio-balloon free page reporting.
    pub fn punch_hole(&self, branch_id: BranchId, range: PageRange) -> Result<()> {
        let inner = self.inner()?;
        if range.tree_size() != inner.size {
            return Err(Error::InvalidRange {
                offset: range.offset(),
                len: range.len_bytes(),
                size: inner.size,
                reason: "range was checked against a different tree size",
            });
        }
        inner.with_ctl_fd(|fd| {
            ioctl::punch_hole(
                fd,
                inner.tree_id,
                branch_id.as_u64(),
                range.offset(),
                range.len_bytes(),
            )
        })
    }

    /// Get current page usage and limit for a branch.
    ///
    /// Returns `(current_cow_pages, max_cow_pages)` where max is 0 for unlimited.
    pub fn page_usage(&self, branch_id: BranchId) -> Result<(u64, u64)> {
        let stats = self.branch_stats(branch_id)?;
        Ok((stats.cow_pages, stats.max_cow_pages))
    }

    /// Destroy this tree and release kernel resources.
    ///
    /// The tree must have no active branches (all branch fds must be
    /// closed). Returns `EBUSY` if branches still exist.
    ///
    /// On success, this `CowTree` is disarmed and Drop will not attempt
    /// to destroy the tree again.
    ///
    /// On failure, the `CowTree` remains valid and the caller can retry
    /// after closing branches, or simply drop it (Drop will attempt
    /// cleanup).
    pub fn destroy(&mut self) -> Result<()> {
        let Some(inner) = self.inner.as_ref() else {
            return Ok(());
        };
        let result = inner.destroy();
        if result.is_ok() {
            self.inner.take();
        }
        result
    }

    /// Get the tree ID.
    #[inline]
    pub fn tree_id(&self) -> u64 {
        self.inner.as_ref().map_or(0, |inner| inner.tree_id)
    }

    /// Get the memory region size.
    #[inline]
    pub fn size(&self) -> usize {
        self.inner.as_ref().map_or(0, |inner| inner.size)
    }

    /// Reconstruct a `CowTree` from its constituent parts.
    ///
    /// The control fd must be a valid `/dev/cowtree` fd that owns the tree.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `ctl_fd` is a valid `/dev/cowtree` file descriptor
    /// - `tree_id` refers to a live tree that was created on this `ctl_fd`
    /// - `size` matches the original tree's memory region size
    ///
    /// Violating these invariants may cause the Drop impl to destroy
    /// an unrelated tree, or ioctls to operate on the wrong tree.
    pub unsafe fn from_parts(ctl_fd: OwnedFd, tree_id: u64, size: usize) -> Self {
        debug_assert!(size != 0, "from_parts: size must be non-zero");
        debug_assert!(
            size.is_multiple_of(rustix::param::page_size()),
            "from_parts: size must be page-aligned"
        );
        Self {
            inner: Some(Arc::new(CowTreeInner::new(ctl_fd, tree_id, size))),
        }
    }

    /// Decompose into parts.
    ///
    /// Returns `(ctl_fd, tree_id, size)` which can be reconstructed
    /// with `from_parts()`.
    ///
    /// This disarms the `Drop` impl — the caller takes ownership of the
    /// kernel tree and is responsible for destroying it.
    ///
    /// # Errors
    ///
    /// Returns `Error::Destroyed` if `destroy()` was already called or if
    /// `into_parts()` was already called (both leave `ctl_fd` as `None`).
    pub fn into_parts(mut self) -> Result<(OwnedFd, u64, usize)> {
        let inner = self.inner.take().ok_or(Error::Destroyed)?;
        match Arc::try_unwrap(inner) {
            Ok(inner) => inner.into_parts(),
            Err(inner) => {
                self.inner = Some(inner);
                Err(Error::BranchesActive)
            }
        }
    }

    /// Create a branch and map it into memory.
    ///
    /// Convenience method that combines `branch()` with mmap.
    pub fn branch_mapped(&self, parent: FrozenBranch) -> Result<BranchMapping> {
        let branch = self.branch(parent)?;
        BranchMapping::new(branch, self.size())
    }
}

// =============================================================================
// Branch FD
// =============================================================================

/// Owned file descriptor for a cowtree branch.
///
/// `BranchFd` intentionally wraps the raw branch [`OwnedFd`] together with the
/// tree cleanup handle. Keeping this type alive guarantees the kernel tree
/// destroy authority remains alive until the branch fd is closed.
#[cfg(target_os = "linux")]
pub struct BranchFd {
    /// Branch file descriptor.
    fd: OwnedFd,
    /// Branch ID.
    id: BranchId,
    /// Shared tree cleanup authority.
    tree: Arc<CowTreeInner>,
}

#[cfg(target_os = "linux")]
impl BranchFd {
    /// Get the branch ID.
    #[inline]
    pub const fn id(&self) -> BranchId {
        self.id
    }

    /// Get the kernel tree handle this branch belongs to.
    #[inline]
    pub fn tree_id(&self) -> u64 {
        self.tree.tree_id
    }

    /// Get the memory region size for this branch.
    #[inline]
    pub fn size(&self) -> usize {
        self.tree.size
    }
}

#[cfg(target_os = "linux")]
impl std::fmt::Debug for BranchFd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchFd")
            .field("id", &self.id)
            .field("tree_id", &self.tree.tree_id)
            .field("fd", &self.fd.as_raw_fd())
            .finish()
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for BranchFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl AsFd for BranchFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

// =============================================================================
// Branch Mapping
// =============================================================================

/// A memory mapping of a branch.
///
/// Provides direct access to a branch's memory via mmap.
/// Reads return shared pages from base/parent, writes trigger copy-on-write.
///
/// Dropping the mapping unmaps the memory.
#[cfg(target_os = "linux")]
pub struct BranchMapping {
    /// Branch file descriptor
    branch: BranchFd,
    /// Mapped memory region
    ptr: NonNull<u8>,
    /// Size of the mapping
    size: usize,
}

#[cfg(target_os = "linux")]
impl BranchMapping {
    /// Create a new mapping from a branch fd.
    fn new(branch: BranchFd, size: usize) -> Result<Self> {
        let prot = ProtFlags::READ | ProtFlags::WRITE;

        // Use MAP_SHARED so writes trigger CoW in the kernel
        // SAFETY: We pass a valid open file descriptor (`fd`), a non-zero `size`,
        // and a null hint address (letting the kernel choose). The returned pointer
        // is checked for errors by the `nix` wrapper and for null below.
        let raw_ptr = unsafe {
            mmap(
                std::ptr::null_mut(),
                size,
                prot,
                MapFlags::SHARED,
                &branch,
                0,
            )
        }
        .map_err(|e| Error::Mmap(e.into()))?;

        let Some(ptr) = NonNull::new(raw_ptr.cast()) else {
            // mmap succeeded but returned address 0. This is
            // theoretically possible (though practically impossible
            // without MAP_FIXED at address 0). We must munmap to
            // avoid leaking the mapping before returning an error.
            // SAFETY: `raw_ptr` was just returned by a successful `mmap` call
            // with the given `size`, so it is a valid mapping to unmap.
            if let Err(e) = unsafe { munmap(raw_ptr, size) } {
                log::error!("munmap failed while unwinding null-pointer mmap: {e}");
            }
            return Err(Error::Mmap(io::Error::other("mmap returned null pointer")));
        };

        Ok(Self { branch, ptr, size })
    }

    /// Get the branch ID.
    #[inline]
    pub const fn id(&self) -> BranchId {
        self.branch.id()
    }

    /// Get a pointer to the mapped memory.
    #[inline]
    pub const fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    /// Get a mutable pointer to the mapped memory.
    #[inline]
    pub const fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }

    /// Get the size of the mapping.
    #[inline]
    pub const fn size(&self) -> usize {
        self.size
    }

    /// Get a slice view of the mapped memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no other process, thread, or mapping is
    /// concurrently writing to any page covered by this mapping. Concurrent
    /// external writes while a `&[u8]` reference exists constitute undefined
    /// behavior under Rust's aliasing rules.
    #[inline]
    pub const unsafe fn as_slice(&self) -> &[u8] {
        // SAFETY: `self.ptr` is a `NonNull<u8>` obtained from a successful `mmap`
        // that allocated `self.size` bytes. The mapping is valid for the lifetime
        // of this `BranchMapping`. The caller upholds the no-concurrent-write
        // requirement per the function's safety contract.
        unsafe { std::slice::from_raw_parts(self.ptr.as_ptr(), self.size) }
    }

    /// Get a mutable slice view of the mapped memory.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no other process, thread, or mapping is
    /// concurrently reading from or writing to any page covered by this
    /// mapping. Concurrent external access while a `&mut [u8]` reference
    /// exists constitutes undefined behavior under Rust's aliasing rules.
    #[inline]
    pub const unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        // SAFETY: `self.ptr` is a `NonNull<u8>` obtained from a successful `mmap`
        // that allocated `self.size` bytes. The mapping is valid for the lifetime
        // of this `BranchMapping`. `&mut self` ensures no aliasing references exist,
        // and the caller upholds the no-concurrent-access requirement per the
        // function's safety contract.
        unsafe { std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.size) }
    }
}

#[cfg(target_os = "linux")]
impl Drop for BranchMapping {
    fn drop(&mut self) {
        // SAFETY: `self.ptr` and `self.size` were set by a successful `mmap` in
        // `BranchMapping::new`. The mapping has not been unmapped elsewhere because
        // this is the only `munmap` call outside of the null-pointer error path in
        // `new`, which returns early without constructing a `BranchMapping`.
        if let Err(e) = unsafe { munmap(self.ptr.as_ptr().cast(), self.size) } {
            log::error!("munmap failed in BranchMapping::drop: {e}");
        }
    }
}

#[cfg(target_os = "linux")]
impl AsRawFd for BranchMapping {
    fn as_raw_fd(&self) -> RawFd {
        self.branch.as_raw_fd()
    }
}

#[cfg(target_os = "linux")]
impl AsFd for BranchMapping {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.branch.as_fd()
    }
}

// SAFETY for Send: BranchMapping can be sent between threads because:
// 1. OwnedFd is Send - file descriptors are safe to transfer between threads
// 2. NonNull<u8> points to mmap'd memory that remains valid regardless of thread
// 3. The mapping lifetime is tied to this struct's lifetime, not any thread
// 4. BranchId and size are Copy types with no thread affinity
//
// SAFETY for Sync: &BranchMapping can be shared between threads because:
// 1. Read operations via as_slice() are safe - the kernel ensures page-level
//    atomicity for CoW mappings (concurrent reads see consistent data)
// 2. Write operations via as_mut_slice() require &mut self, preventing data races
// 3. The underlying cowtree kernel module handles concurrent access from multiple
//    processes/threads by triggering CoW faults atomically
//
// INVARIANT: Callers must not create overlapping mutable slices from the same
// BranchMapping. The as_mut_slice() method enforces this via &mut self.
// SAFETY: BranchMapping's raw `*mut u8` points into a kernel-managed CoW
// mapping; transferring ownership across threads is sound because the
// underlying mapping is process-wide and not tied to any single thread.
#[cfg(target_os = "linux")]
unsafe impl Send for BranchMapping {}
// SAFETY: See invariants above — reads go through `as_slice` (kernel
// provides page-level atomicity for CoW reads), writes require `&mut self`
// so no two mutable views can coexist across threads.
#[cfg(target_os = "linux")]
unsafe impl Sync for BranchMapping {}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::collections::HashSet;

    // =========================================================================
    // BranchId
    // =========================================================================

    #[test]
    fn branch_id_base_is_zero() {
        assert_eq!(BranchId::BASE.as_u64(), 0);
        assert_eq!(BranchId::BASE, BranchId::new(0));
    }

    #[test]
    fn branch_id_new_and_as_u64_roundtrip() {
        for val in [0, 1, 42, u64::MAX] {
            assert_eq!(BranchId::new(val).as_u64(), val);
        }
    }

    #[test]
    fn branch_id_display() {
        assert_eq!(format!("{}", BranchId::BASE), "Branch(0)");
        assert_eq!(format!("{}", BranchId::new(5)), "Branch(5)");
        assert_eq!(
            format!("{}", BranchId::new(u64::MAX)),
            format!("Branch({})", u64::MAX)
        );
    }

    #[test]
    fn branch_id_debug() {
        let id = BranchId::new(42);
        let dbg = format!("{id:?}");
        assert!(dbg.contains("42"), "Debug should show inner value");
    }

    #[test]
    fn branch_id_equality() {
        assert_eq!(BranchId::new(1), BranchId::new(1));
        assert_ne!(BranchId::new(1), BranchId::new(2));
        assert_ne!(BranchId::BASE, BranchId::new(1));
    }

    #[test]
    fn branch_id_clone_and_copy() {
        let id = BranchId::new(99);
        let cloned = id;
        assert_eq!(id, cloned);
        // Verify Copy semantics — original still usable after "move"
        assert_eq!(id.as_u64(), 99);
    }

    #[test]
    fn branch_id_hash() {
        let mut set = HashSet::new();
        set.insert(BranchId::new(1));
        set.insert(BranchId::new(2));
        set.insert(BranchId::new(1)); // duplicate
        assert_eq!(set.len(), 2);
        assert!(set.contains(&BranchId::new(1)));
        assert!(set.contains(&BranchId::new(2)));
        assert!(!set.contains(&BranchId::new(3)));
    }

    // =========================================================================
    // Error types — Display for all variants
    // =========================================================================

    #[test]
    fn error_display_device_open() {
        let err = Error::DeviceOpen(io::Error::new(io::ErrorKind::NotFound, "no such device"));
        let msg = err.to_string();
        assert!(msg.contains("/dev/cowtree"), "should mention device path");
        assert!(msg.contains("kernel module"), "should hint about module");
    }

    #[test]
    fn error_display_ioctl() {
        let err = Error::Ioctl {
            operation: "COWTREE_CREATE_TREE",
            source: io::Error::from_raw_os_error(libc::EINVAL),
        };
        let msg = err.to_string();
        assert!(
            msg.contains("COWTREE_CREATE_TREE"),
            "should name the operation"
        );
    }

    #[test]
    fn error_display_not_found() {
        let err = Error::NotFound {
            tree_id: 42,
            parent_id: BranchId::new(7),
        };
        let msg = err.to_string();
        assert!(msg.contains("42"), "should contain tree_id");
        assert!(msg.contains("Branch(7)"), "should contain parent_id");
        assert!(msg.contains("ENOENT"), "should mention ENOENT");
    }

    #[test]
    fn error_display_mmap() {
        let err = Error::Mmap(io::Error::other("mmap failed"));
        let msg = err.to_string();
        assert!(msg.contains("mmap"), "should mention mmap");
    }

    #[test]
    fn error_display_destroyed() {
        let err = Error::Destroyed;
        let msg = err.to_string();
        assert!(msg.contains("destroyed") || msg.contains("disassembled"));
    }

    #[test]
    fn error_display_branches_active() {
        let err = Error::BranchesActive;
        let msg = err.to_string();
        assert!(msg.contains("branch"));
    }

    #[test]
    fn error_display_invalid_size() {
        let err = Error::InvalidSize(4097);
        let msg = err.to_string();
        assert!(msg.contains("4097"), "should show the invalid size");
        assert!(
            msg.contains("page-aligned"),
            "should mention alignment requirement"
        );
    }

    #[test]
    fn error_display_invalid_size_zero() {
        let err = Error::InvalidSize(0);
        let msg = err.to_string();
        assert!(msg.contains('0'), "should show zero");
        assert!(
            msg.contains("non-zero"),
            "should mention non-zero requirement"
        );
    }

    #[test]
    fn error_source_chain() {
        let inner = io::Error::from_raw_os_error(libc::EBUSY);
        let err = Error::Ioctl {
            operation: "test",
            source: inner,
        };
        // std::error::Error::source() should return the inner io::Error
        let source = std::error::Error::source(&err);
        assert!(source.is_some(), "Ioctl error should have a source");
    }

    #[test]
    fn error_debug_all_variants() {
        // Verify Debug doesn't panic on any variant
        let variants: Vec<Error> = vec![
            Error::DeviceOpen(io::Error::new(io::ErrorKind::NotFound, "test")),
            Error::Ioctl {
                operation: "TEST",
                source: io::Error::from_raw_os_error(libc::EINVAL),
            },
            Error::NotFound {
                tree_id: 1,
                parent_id: BranchId::BASE,
            },
            Error::Mmap(io::Error::other("test")),
            Error::Destroyed,
            Error::BranchesActive,
            Error::InvalidSize(0),
            Error::InvalidRange {
                offset: 0,
                len: 0,
                size: 4096,
                reason: "test",
            },
        ];
        for err in &variants {
            // Smoke-test the Debug/Display impls — we just want to prove
            // they don't panic, so bind to a named `_` (the `!is_empty()`
            // assertion this replaces documented the wrong invariant).
            let _dbg = format!("{err:?}");
            let _dsp = format!("{err}");
        }
    }

    // =========================================================================
    // FrozenBranch
    // =========================================================================

    #[test]
    fn frozen_branch_exposes_branch_id() {
        // SAFETY: This test only checks token construction and does not issue
        // a branch ioctl or expose any writable mapping.
        let frozen = unsafe { FrozenBranch::assume_frozen(BranchId::new(9)) };
        assert_eq!(frozen.branch_id(), BranchId::new(9));
    }

    // =========================================================================
    // PageRange
    // =========================================================================

    #[test]
    fn page_range_accepts_aligned_in_range() {
        let page_size = rustix::param::page_size();
        let page_size_u64 = u64::try_from(page_size).unwrap();
        let range = PageRange::new(page_size_u64, page_size_u64, page_size * 2).unwrap();
        assert_eq!(range.offset(), page_size_u64);
        assert_eq!(range.len_bytes(), page_size_u64);
        assert_eq!(range.tree_size(), page_size * 2);
    }

    #[test]
    fn page_range_rejects_invalid_ranges() {
        let page_size = rustix::param::page_size();
        let page_size_u64 = u64::try_from(page_size).unwrap();

        assert!(matches!(
            PageRange::new(0, 0, page_size),
            Err(Error::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(1, page_size_u64, page_size),
            Err(Error::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(0, page_size_u64 + 1, page_size * 2),
            Err(Error::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(page_size_u64, page_size_u64 * 2, page_size * 2),
            Err(Error::InvalidRange { .. })
        ));
        assert!(matches!(
            PageRange::new(u64::MAX, page_size_u64, page_size * 2),
            Err(Error::InvalidRange { .. })
        ));
    }

    // =========================================================================
    // Size validation (from_base rejects bad sizes before touching the device)
    // =========================================================================

    #[test]
    fn from_base_rejects_zero_size() {
        // Create a dummy fd — the size check runs before the device open
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_fd();
        let err = CowTree::from_base(fd, 0).expect_err("expected error");
        assert!(
            matches!(err, Error::InvalidSize(0)),
            "zero size should be rejected, got: {err}"
        );
    }

    #[test]
    fn from_base_rejects_non_page_aligned() {
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_fd();
        let err = CowTree::from_base(fd, 4097).expect_err("expected error");
        assert!(
            matches!(err, Error::InvalidSize(4097)),
            "non-page-aligned size should be rejected, got: {err}"
        );
    }

    #[test]
    fn from_base_rejects_size_one() {
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_fd();
        let err = CowTree::from_base(fd, 1).expect_err("expected error");
        assert!(
            matches!(err, Error::InvalidSize(1)),
            "size 1 should be rejected, got: {err}"
        );
    }

    #[test]
    fn from_base_page_aligned_passes_validation() {
        // A page-aligned size should pass validation (no InvalidSize error).
        // It will then either open the device (module loaded) or fail at DeviceOpen.
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_fd();
        let page_size = rustix::param::page_size();
        let result = CowTree::from_base(fd, page_size);
        // Whether it succeeds or fails, it must NOT be InvalidSize
        if let Err(err) = result {
            assert!(
                !matches!(err, Error::InvalidSize(_)),
                "page-aligned size should not fail validation, got: {err}"
            );
        }
    }

    #[test]
    fn from_base_large_page_aligned_passes_validation() {
        let f = tempfile::tempfile().unwrap();
        let fd = f.as_fd();
        let result = CowTree::from_base(fd, 1 << 30); // 1 GiB
        if let Err(err) = result {
            assert!(
                !matches!(err, Error::InvalidSize(_)),
                "1 GiB should not fail validation, got: {err}"
            );
        }
    }

    // =========================================================================
    // CowTree accessors and constants
    // =========================================================================

    #[test]
    fn device_path_constant() {
        assert_eq!(CowTree::DEVICE_PATH, "/dev/cowtree");
    }

    // =========================================================================
    // from_parts / into_parts (unsafe construction)
    // =========================================================================

    #[test]
    fn from_parts_into_parts_roundtrip() {
        // Create a dummy OwnedFd from a tempfile for the test
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        let tree_id = 42u64;
        let size = 4096usize;

        // SAFETY: fd is a valid /dev/cowtree fd; tree_id and size match the created tree.
        let tree = unsafe { CowTree::from_parts(fd, tree_id, size) };
        assert_eq!(tree.tree_id(), 42);
        assert_eq!(tree.size(), 4096);

        // into_parts() consumes self — compiler prevents use after this
        let (got_fd, got_tree_id, got_size) = tree.into_parts().unwrap();
        assert_eq!(got_tree_id, 42);
        assert_eq!(got_size, 4096);
        // fd should still be valid (not closed)
        assert!(got_fd.as_raw_fd() >= 0);
    }

    #[test]
    fn into_parts_on_destroyed_returns_error() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let mut tree = unsafe { CowTree::from_parts(fd, 1, 4096) };
        tree.inner.take(); // simulate destroyed
        assert!(matches!(tree.into_parts(), Err(Error::Destroyed)));
    }

    #[test]
    fn debug_impl_shows_tree_info() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let tree = unsafe { CowTree::from_parts(fd, 42, 4096) };
        let debug = format!("{tree:?}");
        assert!(debug.contains("tree_id: 42"));
        assert!(debug.contains("size: 4096"));
        assert!(debug.contains("alive: true"));
    }

    // =========================================================================
    // Drop safety
    // =========================================================================

    #[test]
    fn into_parts_consumes_tree() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let tree = unsafe { CowTree::from_parts(fd, 1, 4096) };
        // into_parts() consumes self — Drop runs with ctl_fd=None, no panic
        let _parts = tree.into_parts().unwrap();
        // tree is moved — compiler prevents further use
    }

    #[test]
    fn drop_with_invalid_tree_id_is_graceful() {
        // Create a CowTree with a fake fd — Drop should handle the ioctl failure gracefully
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let tree = unsafe { CowTree::from_parts(fd, u64::MAX, 4096) };
        // This will call drop, which calls destroy_tree on a tempfile fd.
        // The ioctl will fail (ENOTTY or similar), which should be logged but not panic.
        drop(tree);
    }

    // =========================================================================
    // page_usage helper
    // =========================================================================

    #[test]
    fn page_usage_delegates_to_branch_stats() {
        // Can't test without the kernel module, but we verify the method exists
        // and has the right signature: (u64, u64) return type
        let _: fn(&CowTree, BranchId) -> Result<(u64, u64)> = CowTree::page_usage;
    }

    // =========================================================================
    // BranchMapping (using tempfile as mmap-compatible fd)
    // =========================================================================

    /// Create a `BranchMapping` backed by a tempfile for testing.
    /// The tempfile is ftruncated to `size` bytes so `mmap(MAP_SHARED)` works.
    fn test_branch_fd(id: BranchId, size: usize) -> BranchFd {
        use rustix::fs::ftruncate;
        let branch_file = tempfile::tempfile().unwrap();
        ftruncate(&branch_file, size as u64).unwrap();
        let fd: OwnedFd = branch_file.into();

        let ctl_file = tempfile::tempfile().unwrap();
        let ctl_fd: OwnedFd = ctl_file.into();
        BranchFd {
            fd,
            id,
            tree: Arc::new(CowTreeInner::new(ctl_fd, 42, size)),
        }
    }

    /// Create a `BranchMapping` backed by a tempfile for testing.
    /// The tempfile is ftruncated to `size` bytes so `mmap(MAP_SHARED)` works.
    fn test_branch_mapping(size: usize) -> BranchMapping {
        let branch = test_branch_fd(BranchId::new(7), size);
        BranchMapping::new(branch, size).unwrap()
    }

    #[test]
    fn branch_fd_accessors_and_fd_traits() {
        let page_size = rustix::param::page_size();
        let branch = test_branch_fd(BranchId::new(11), page_size);
        assert_eq!(branch.id(), BranchId::new(11));
        assert_eq!(branch.tree_id(), 42);
        assert_eq!(branch.size(), page_size);
        assert!(branch.as_raw_fd() >= 0);
        let _borrowed: BorrowedFd<'_> = branch.as_fd();
    }

    #[test]
    fn branch_mapping_new_and_accessors() {
        let page_size = rustix::param::page_size();
        let mapping = test_branch_mapping(page_size);
        assert_eq!(mapping.id(), BranchId::new(7));
        assert_eq!(mapping.size(), page_size);
        assert!(!mapping.as_ptr().is_null());
    }

    #[test]
    fn branch_mapping_as_mut_ptr() {
        let page_size = rustix::param::page_size();
        let mut mapping = test_branch_mapping(page_size);
        let ptr = mapping.as_mut_ptr();
        assert!(!ptr.is_null());
        assert_eq!(ptr, mapping.as_ptr().cast_mut());
    }

    #[test]
    fn branch_mapping_slice_read_write() {
        let page_size = rustix::param::page_size();
        let mut mapping = test_branch_mapping(page_size);

        // Write a pattern via as_mut_slice
        // SAFETY: No concurrent access — test owns the sole mapping.
        unsafe {
            let slice = mapping.as_mut_slice();
            assert_eq!(slice.len(), page_size);
            slice[0] = 0xAB;
            slice[1] = 0xCD;
            slice[page_size - 1] = 0xEF;
        }

        // Read back via as_slice
        // SAFETY: No concurrent access.
        unsafe {
            let slice = mapping.as_slice();
            assert_eq!(slice[0], 0xAB);
            assert_eq!(slice[1], 0xCD);
            assert_eq!(slice[page_size - 1], 0xEF);
            // Remaining bytes should still be zero (tempfile is zero-filled)
            assert_eq!(slice[2], 0);
        }
    }

    #[test]
    fn branch_mapping_as_fd_traits() {
        let page_size = rustix::param::page_size();
        let mapping = test_branch_mapping(page_size);
        // AsRawFd and AsFd should return valid fds
        let raw = mapping.as_raw_fd();
        assert!(raw >= 0);
        let _borrowed: BorrowedFd<'_> = mapping.as_fd();
    }

    #[test]
    fn branch_mapping_drop_unmaps() {
        let page_size = rustix::param::page_size();
        let mapping = test_branch_mapping(page_size);
        let ptr = mapping.as_ptr();
        drop(mapping);
        // After drop, the pointer is dangling — we can't dereference it,
        // but we verified Drop ran without panic. The munmap is tested
        // implicitly by not leaking the mapping.
        let _ = ptr; // suppress unused warning
    }

    #[test]
    fn branch_mapping_zero_size_fails() {
        use rustix::fs::ftruncate;
        let f = tempfile::tempfile().unwrap();
        ftruncate(&f, 0).unwrap();
        let fd: OwnedFd = f.into();
        let ctl_file = tempfile::tempfile().unwrap();
        let ctl_fd: OwnedFd = ctl_file.into();
        let branch = BranchFd {
            fd,
            id: BranchId::BASE,
            tree: Arc::new(CowTreeInner::new(ctl_fd, 42, 0)),
        };
        // mmap with size=0 should fail
        let result = BranchMapping::new(branch, 0);
        assert!(result.is_err(), "zero-size mapping should fail");
    }

    // =========================================================================
    // MEDIUM-1: branch() takes FrozenBranch (signature test)
    // =========================================================================

    #[test]
    fn branch_takes_frozen_branch() {
        let _: fn(&CowTree, FrozenBranch) -> Result<BranchFd> = CowTree::branch;
    }

    #[test]
    fn branch_return_type_is_not_bare_owned_fd() {
        let _: fn(&CowTree, FrozenBranch) -> Result<BranchFd> = CowTree::branch;
        assert!(
            std::mem::size_of::<BranchFd>() > std::mem::size_of::<OwnedFd>(),
            "BranchFd must carry cleanup ownership, not just a bare fd"
        );
    }

    #[test]
    fn branch_mapping_keeps_tree_cleanup_owner_alive() {
        use rustix::fs::ftruncate;

        let ctl_file = tempfile::tempfile().unwrap();
        let ctl_fd: OwnedFd = ctl_file.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let tree = unsafe { CowTree::from_parts(ctl_fd, 42, 4096) };
        let inner = Arc::clone(tree.inner.as_ref().unwrap());
        let weak = Arc::downgrade(&inner);

        let branch_file = tempfile::tempfile().unwrap();
        ftruncate(&branch_file, 4096).unwrap();
        let branch = BranchFd {
            fd: branch_file.into(),
            id: BranchId::new(7),
            tree: inner,
        };
        let mapping = BranchMapping::new(branch, 4096).unwrap();

        drop(tree);
        assert!(
            weak.upgrade().is_some(),
            "mapping must keep tree cleanup authority alive after CowTree drops"
        );

        drop(mapping);
        assert!(
            weak.upgrade().is_none(),
            "cleanup authority should release after the mapping drops"
        );
    }

    // =========================================================================
    // LOW-7: branch_mapped() signature test
    // =========================================================================

    #[test]
    fn branch_mapped_takes_frozen_branch() {
        let _: fn(&CowTree, FrozenBranch) -> Result<BranchMapping> = CowTree::branch_mapped;
    }

    // =========================================================================
    // MEDIUM-3: destroy() is idempotent
    // =========================================================================

    #[test]
    fn destroy_twice_returns_ok() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let mut tree = unsafe { CowTree::from_parts(fd, 1, 4096) };
        // First destroy will fail (not a real cowtree fd) but that's fine for
        // this test — we're checking that a SECOND call returns Ok.
        // Force inner to None to simulate a successful first destroy.
        tree.inner.take();
        assert!(tree.destroy().is_ok(), "second destroy must return Ok(())");
    }

    #[test]
    fn methods_return_destroyed_after_destroy() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let mut tree = unsafe { CowTree::from_parts(fd, 1, 4096) };
        tree.inner.take(); // simulate successful destroy
        // SAFETY: This test only checks destroyed-state short-circuiting.
        let frozen_base = unsafe { FrozenBranch::assume_frozen(BranchId::BASE) };
        assert!(matches!(tree.branch(frozen_base), Err(Error::Destroyed)));
        assert!(matches!(tree.stats(), Err(Error::Destroyed)));
        assert!(matches!(
            tree.branch_stats(BranchId::BASE),
            Err(Error::Destroyed)
        ));
        assert!(matches!(tree.global_stats(), Err(Error::Destroyed)));
        assert!(matches!(
            tree.set_page_limit(BranchId::BASE, 100),
            Err(Error::Destroyed)
        ));
        let range = PageRange::new(0, 4096, 4096).unwrap();
        assert!(matches!(
            tree.punch_hole(BranchId::BASE, range),
            Err(Error::Destroyed)
        ));
    }

    #[test]
    fn punch_hole_rejects_range_for_different_tree_size() {
        let f = tempfile::tempfile().unwrap();
        let fd: OwnedFd = f.into();
        // SAFETY: fd is a valid file descriptor; tree_id and size are test values.
        let tree = unsafe { CowTree::from_parts(fd, 1, 4096) };
        let range = PageRange::new(0, 4096, 8192).unwrap();
        assert!(matches!(
            tree.punch_hole(BranchId::BASE, range),
            Err(Error::InvalidRange { .. })
        ));
    }
}
