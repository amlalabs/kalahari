// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! [`MountedFsBackend`] wraps a filesystem under a directory prefix.
//!
//! Given an inner backend and a mount path like `".git"`, the wrapper creates
//! wrapper directories so the inner backend's tree appears at `.git/` instead
//! of at the root.
//!
//! Inode layout for `MountedFsBackend(".git", inner)`:
//! - Inode 1 (root): directory with single child `.git`
//! - Inode 2 (`.git`): maps to inner's root — inner root's children become `.git`'s children
//! - Inodes 3..N: inner's non-root inodes, shifted by 1

use amla_fuse::fs_types::{
    ATTR_VALID_SECS, DT_DIR, ENTRY_VALID_SECS, FUSE_ROOT_ID, S_IFDIR, try_rewrite_readdir_inodes,
    try_rewrite_readdirplus_inodes,
};
use amla_fuse::fuse::{
    FixedFsBackend, FsBackend, FuseAttr, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseOpenOut,
    FuseStatfsOut, pack_dirent, pack_direntplus,
};
use amla_fuse::fuse_abi::FuseError;
use std::fmt;
use std::num::NonZeroU64;

/// Error returned by [`MountedFsBackend::new`] for an unusable mount prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidMountPrefix {
    prefix: String,
    reason: &'static str,
}

impl fmt::Display for InvalidMountPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid mount prefix {:?}: {}", self.prefix, self.reason)
    }
}

impl std::error::Error for InvalidMountPrefix {}

/// Error returned when a mounted filesystem cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidMount {
    /// The mount prefix is not a valid relative path.
    Prefix(InvalidMountPrefix),
    /// The inner fixed backend exposes an unusable inode namespace.
    Layout(&'static str),
}

impl fmt::Display for InvalidMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Prefix(prefix) => prefix.fmt(f),
            Self::Layout(reason) => write!(f, "invalid mounted filesystem layout: {reason}"),
        }
    }
}

impl std::error::Error for InvalidMount {}

impl From<InvalidMountPrefix> for InvalidMount {
    fn from(value: InvalidMountPrefix) -> Self {
        Self::Prefix(value)
    }
}

fn validate_mount_prefix(prefix: &str) -> Result<Vec<Vec<u8>>, InvalidMountPrefix> {
    let make_err = |reason: &'static str| InvalidMountPrefix {
        prefix: prefix.to_string(),
        reason,
    };
    if prefix.is_empty() {
        return Err(make_err("empty"));
    }
    if prefix.starts_with('/') {
        return Err(make_err("absolute (leading '/')"));
    }
    if prefix.contains('\0') {
        return Err(make_err("contains NUL byte"));
    }
    let segments: Vec<Vec<u8>> = prefix.split('/').map(|s| s.as_bytes().to_vec()).collect();
    for seg in &segments {
        if seg.is_empty() {
            return Err(make_err("empty path component"));
        }
        if seg.as_slice() == b"." || seg.as_slice() == b".." {
            return Err(make_err("'.' or '..' component"));
        }
    }
    Ok(segments)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GuestInode(NonZeroU64);

impl GuestInode {
    fn from_guest(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or_else(FuseError::invalid)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InnerInode(NonZeroU64);

impl InnerInode {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::io)
    }

    const fn root() -> Self {
        Self(NonZeroU64::MIN)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InodeCount(NonZeroU64);

impl InodeCount {
    fn from_backend(raw: u64) -> Result<Self, InvalidMount> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or(InvalidMount::Layout("inner inode_count is zero"))
    }

    fn from_wrapper_segments(raw: usize) -> Result<Self, InvalidMount> {
        let raw = raw as u64;
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or(InvalidMount::Layout("mount prefix has no wrapper inodes"))
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct MountedLayout {
    wrapper_count: InodeCount,
    inner_count: InodeCount,
    total: InodeCount,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MountedOwner {
    Wrapper(GuestInode),
    Inner(InnerInode),
}

impl MountedLayout {
    fn new(wrapper_segments: usize, inner_inode_count: u64) -> Result<Self, InvalidMount> {
        let wrapper_count = InodeCount::from_wrapper_segments(wrapper_segments)?;
        let inner_count = InodeCount::from_backend(inner_inode_count)?;
        let total = wrapper_count
            .get()
            .checked_add(inner_count.get())
            .and_then(NonZeroU64::new)
            .map(InodeCount)
            .ok_or(InvalidMount::Layout("mounted inode namespace overflows"))?;

        Ok(Self {
            wrapper_count,
            inner_count,
            total,
        })
    }

    const fn total(self) -> u64 {
        self.total.get()
    }

    const fn mount_point(self) -> u64 {
        self.wrapper_count.get() + FUSE_ROOT_ID
    }

    fn classify(self, raw: u64) -> Result<MountedOwner, FuseError> {
        let global = GuestInode::from_guest(raw)?;
        if global.get() <= self.wrapper_count.get() {
            return Ok(MountedOwner::Wrapper(global));
        }
        self.global_to_inner(global)
            .map(MountedOwner::Inner)
            .ok_or_else(FuseError::not_found)
    }

    fn global_to_inner(self, global: GuestInode) -> Option<InnerInode> {
        if global.get() <= self.wrapper_count.get() || global.get() > self.total.get() {
            return None;
        }
        let local = global.get() - self.wrapper_count.get();
        NonZeroU64::new(local).map(InnerInode)
    }

    fn inner_to_global(self, inner: InnerInode) -> Result<GuestInode, FuseError> {
        if inner.get() > self.inner_count.get() {
            return Err(FuseError::io());
        }
        let raw = self
            .wrapper_count
            .get()
            .checked_add(inner.get())
            .ok_or_else(FuseError::range)?;
        GuestInode::from_guest(raw).map_err(|_| FuseError::io())
    }
}

/// Wraps a [`FixedFsBackend`] under a directory prefix.
///
/// The inner backend's root becomes a subdirectory of the wrapper's root.
/// For multi-segment paths like `"a/b/c"`, intermediate directories are created.
pub struct MountedFsBackend<F> {
    inner: F,
    layout: MountedLayout,
    /// Path segments for the wrapper directories.
    segments: Vec<Vec<u8>>,
    /// Unix mode for wrapper directories.
    dir_mode: u32,
    /// UID/GID for wrapper directories.
    uid: u32,
    gid: u32,
}

impl<F: FixedFsBackend> MountedFsBackend<F> {
    /// Create a new mounted filesystem.
    ///
    /// `prefix` is a slash-separated path like `".git"` or `"a/b/c"`.
    /// `dir_mode` is the unix permission bits for all wrapper directories (e.g. `0o755`).
    ///
    /// Rejects prefixes that are empty, absolute, contain a NUL byte, or
    /// contain any `.`, `..`, or empty component — mirroring the rules
    /// enforced by `SynthesizedFsBuilder::validate_path`.
    pub fn new(inner: F, prefix: &str, dir_mode: u32) -> Result<Self, InvalidMount> {
        let segments = validate_mount_prefix(prefix)?;
        // Inode layout:
        // - Global 1: wrapper root (NOT inner's root)
        // - For ".git": 1→".git"(2=inner root). Inner inode I → global I+1.
        // - For "a/b": 1→"a"(2)→"b"(3=inner root). Inner inode I → global I+2.
        let layout = MountedLayout::new(segments.len(), inner.inode_count())?;

        Ok(Self {
            inner,
            layout,
            segments,
            dir_mode,
            uid: 0,
            gid: 0,
        })
    }

    /// Set UID/GID for wrapper directories.
    #[must_use]
    pub const fn with_uid_gid(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    fn classify(&self, global: u64) -> Result<MountedOwner, FuseError> {
        self.layout.classify(global)
    }

    fn global_to_inner(&self, raw: u64) -> Option<InnerInode> {
        GuestInode::from_guest(raw)
            .ok()
            .and_then(|global| self.layout.global_to_inner(global))
    }

    fn inner_to_global(&self, inner: u64) -> Result<u64, FuseError> {
        Ok(self
            .layout
            .inner_to_global(InnerInode::from_backend(inner)?)?
            .get())
    }

    fn inner_entry_to_global(&self, mut entry: FuseEntryOut) -> Result<FuseEntryOut, FuseError> {
        entry.nodeid = self.inner_to_global(entry.nodeid)?;
        entry.attr.ino = self.inner_to_global(entry.attr.ino)?;
        Ok(entry)
    }

    /// Get the wrapper dir mode attribute for a given global inode.
    const fn wrapper_attr(&self, global: u64) -> FuseAttr {
        FuseAttr {
            ino: global,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: S_IFDIR | self.dir_mode,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    const fn wrapper_entry_out(&self, global: u64) -> FuseEntryOut {
        FuseEntryOut {
            nodeid: global,
            generation: 0,
            entry_valid: ENTRY_VALID_SECS,
            attr_valid: ATTR_VALID_SECS,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: self.wrapper_attr(global),
        }
    }

    const fn wrapper_attr_out(&self, global: u64) -> FuseAttrOut {
        FuseAttrOut {
            attr_valid: ATTR_VALID_SECS,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: self.wrapper_attr(global),
        }
    }

    /// Rewrite inodes in a readdir buffer from inner to global space.
    fn rewrite_readdir_buf(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdir_inodes(buf, |ino| self.inner_to_global(ino))
    }

    /// Rewrite inodes in a readdirplus buffer from inner to global space.
    fn rewrite_readdirplus_buf(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdirplus_inodes(buf, |ino| self.inner_to_global(ino))
    }

    /// Readdir for a wrapper directory (root or intermediate).
    /// These have exactly one child: the next segment.
    fn readdir_wrapper(&self, global: u64, offset: u64, size: u32) -> Vec<u8> {
        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        // "."
        if index >= offset && pack_dirent(&mut buf, max_size, global, b".", index + 1, DT_DIR) == 0
        {
            return buf;
        }
        index += 1;

        // ".."
        if index >= offset {
            let parent = if global == 1 { 1 } else { global - 1 };
            if pack_dirent(&mut buf, max_size, parent, b"..", index + 1, DT_DIR) == 0 {
                return buf;
            }
        }
        index += 1;

        // Single child: next segment.
        if index >= offset {
            let seg_idx = (global - 1) as usize;
            if seg_idx < self.segments.len() {
                let name = &self.segments[seg_idx];
                let child_global = global + 1;
                // Last entry: if it doesn't fit, the kernel sees a short
                // readdir reply and reissues with the next offset.
                let _written =
                    pack_dirent(&mut buf, max_size, child_global, name, index + 1, DT_DIR);
            }
        }

        buf
    }

    /// Readdirplus for a wrapper directory (root or intermediate).
    /// Same layout as `readdir_wrapper` but includes `FuseEntryOut` per entry.
    fn readdirplus_wrapper(&self, global: u64, offset: u64, size: u32) -> Vec<u8> {
        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        // "."
        if index >= offset {
            let entry = self.wrapper_entry_out(global);
            if pack_direntplus(&mut buf, max_size, &entry, b".", index + 1, DT_DIR) == 0 {
                return buf;
            }
        }
        index += 1;

        // ".."
        if index >= offset {
            let parent = if global == 1 { 1 } else { global - 1 };
            let entry = self.wrapper_entry_out(parent);
            if pack_direntplus(&mut buf, max_size, &entry, b"..", index + 1, DT_DIR) == 0 {
                return buf;
            }
        }
        index += 1;

        // Single child: next segment.
        if index >= offset {
            let seg_idx = (global - 1) as usize;
            if seg_idx < self.segments.len() {
                let name = &self.segments[seg_idx];
                let child_global = global + 1;
                let entry = self.wrapper_entry_out(child_global);
                // Last entry: if it doesn't fit, the kernel sees a short
                // readdirplus reply and reissues with the next offset.
                let _written = pack_direntplus(&mut buf, max_size, &entry, name, index + 1, DT_DIR);
            }
        }

        buf
    }
}

impl<F: FixedFsBackend> FixedFsBackend for MountedFsBackend<F> {
    fn inode_count(&self) -> u64 {
        self.layout.total()
    }
}

impl<F: FixedFsBackend> FsBackend for MountedFsBackend<F> {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        self.inner.init().await
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        match self.classify(parent)? {
            MountedOwner::Wrapper(parent) => {
                let parent = parent.get();
                let seg_idx = (parent - FUSE_ROOT_ID) as usize;
                if seg_idx >= self.segments.len() || name != self.segments[seg_idx].as_slice() {
                    return Err(FuseError::not_found());
                }

                let child_global = parent + FUSE_ROOT_ID;
                if child_global == self.layout.mount_point() {
                    let mut entry = self.inner.getattr(InnerInode::root().get()).await?;
                    entry.attr.ino = self.inner_to_global(entry.attr.ino)?;
                    return Ok(FuseEntryOut {
                        nodeid: child_global,
                        generation: 0,
                        entry_valid: ENTRY_VALID_SECS,
                        attr_valid: entry.attr_valid,
                        entry_valid_nsec: 0,
                        attr_valid_nsec: entry.attr_valid_nsec,
                        attr: entry.attr,
                    });
                }

                Ok(self.wrapper_entry_out(child_global))
            }
            MountedOwner::Inner(inner_parent) => {
                let result = self.inner.lookup(inner_parent.get(), name).await?;
                self.inner_entry_to_global(result)
            }
        }
    }

    async fn forget(&self, nodeid: u64, nlookup: u64) {
        if let Some(inner) = self.global_to_inner(nodeid) {
            self.inner.forget(inner.get(), nlookup).await;
        }
    }

    async fn batch_forget(&self, forgets: &[(u64, u64)]) {
        let inner_forgets: Vec<(u64, u64)> = forgets
            .iter()
            .filter_map(|&(nodeid, nlookup)| {
                self.global_to_inner(nodeid)
                    .map(|inner| (inner.get(), nlookup))
            })
            .collect();
        if !inner_forgets.is_empty() {
            self.inner.batch_forget(&inner_forgets).await;
        }
    }

    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(wrapper) => Ok(self.wrapper_attr_out(wrapper.get())),
            MountedOwner::Inner(inner) => {
                let mut result = self.inner.getattr(inner.get()).await?;
                result.attr.ino = self.inner_to_global(result.attr.ino)?;
                Ok(result)
            }
        }
    }

    async fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Err(FuseError::invalid()),
            MountedOwner::Inner(inner) => self.inner.readlink(inner.get()).await,
        }
    }

    async fn open(&self, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Err(FuseError::is_dir()),
            MountedOwner::Inner(inner) => self.inner.open(inner.get(), flags).await,
        }
    }

    async fn read(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Err(FuseError::is_dir()),
            MountedOwner::Inner(inner) => self.inner.read(inner.get(), fh, offset, size).await,
        }
    }

    async fn release(&self, nodeid: u64, fh: u64) {
        if let Some(inner) = self.global_to_inner(nodeid) {
            self.inner.release(inner.get(), fh).await;
        }
    }

    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Ok(FuseOpenOut {
                fh: 0,
                open_flags: 0,
                padding: 0,
            }),
            MountedOwner::Inner(inner) => self.inner.opendir(inner.get()).await,
        }
    }

    async fn readdir(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(wrapper) => Ok(self.readdir_wrapper(wrapper.get(), offset, size)),
            MountedOwner::Inner(inner) => {
                let mut buf = self.inner.readdir(inner.get(), fh, offset, size).await?;
                self.rewrite_readdir_buf(&mut buf)?;
                Ok(buf)
            }
        }
    }

    async fn readdirplus(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(wrapper) => {
                Ok(self.readdirplus_wrapper(wrapper.get(), offset, size))
            }
            MountedOwner::Inner(inner) => {
                let mut buf = self
                    .inner
                    .readdirplus(inner.get(), fh, offset, size)
                    .await?;
                self.rewrite_readdirplus_buf(&mut buf)?;
                Ok(buf)
            }
        }
    }

    async fn releasedir(&self, nodeid: u64, fh: u64) {
        if let Some(inner) = self.global_to_inner(nodeid) {
            self.inner.releasedir(inner.get(), fh).await;
        }
    }

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        self.inner.statfs().await
    }

    async fn access(&self, nodeid: u64, mask: u32) -> Result<(), FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Ok(()),
            MountedOwner::Inner(inner) => self.inner.access(inner.get(), mask).await,
        }
    }

    async fn getxattr(&self, nodeid: u64, name: &[u8], size: u32) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Err(FuseError::not_supported()),
            MountedOwner::Inner(inner) => self.inner.getxattr(inner.get(), name, size).await,
        }
    }

    async fn listxattr(&self, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            MountedOwner::Wrapper(_) => Err(FuseError::not_supported()),
            MountedOwner::Inner(inner) => self.inner.listxattr(inner.get(), size).await,
        }
    }

    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        let global = GuestInode::from_guest(nodeid)?;
        if global.get() == FUSE_ROOT_ID {
            // Root's parent is itself.
            Ok(FuseEntryOut::new(
                FUSE_ROOT_ID,
                self.wrapper_attr(FUSE_ROOT_ID),
            ))
        } else if global.get() <= self.layout.mount_point() {
            // Wrapper directories: parent is the previous wrapper dir.
            let parent = global.get() - FUSE_ROOT_ID;
            Ok(FuseEntryOut::new(parent, self.wrapper_attr(parent)))
        } else {
            // Inner inode: delegate to inner backend, translate result.
            let inner = self
                .layout
                .global_to_inner(global)
                .ok_or_else(FuseError::not_found)?;
            let entry = self.inner.get_parent(inner.get()).await?;
            self.inner_entry_to_global(entry)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use amla_fuse::fs_types::{DT_REG, S_IFREG};
    use amla_fuse::fuse::{FuseContext, FuseDirent};
    use amla_synthesized_fs::SynthesizedFs;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicU64, Ordering};

    const ROOT_CTX: FuseContext = FuseContext { uid: 0, gid: 0 };

    fn make_inner() -> SynthesizedFs<'static> {
        SynthesizedFs::builder()
            .file("HEAD", b"abc123\n", 0o444)
            .unwrap()
            .file("config", b"[core]\n", 0o444)
            .unwrap()
            .build()
    }

    struct FhRecordingFs {
        inner: SynthesizedFs<'static>,
        readdir_fh: Arc<AtomicU64>,
        readdirplus_fh: Arc<AtomicU64>,
        inode_count_override: Option<u64>,
        lookup_entry: Option<(u64, u64)>,
        readdir_ino: Option<u64>,
        readdirplus_entry: Option<(u64, u64)>,
    }

    impl FhRecordingFs {
        fn new() -> Self {
            Self {
                inner: make_inner(),
                readdir_fh: Arc::new(AtomicU64::new(u64::MAX)),
                readdirplus_fh: Arc::new(AtomicU64::new(u64::MAX)),
                inode_count_override: None,
                lookup_entry: None,
                readdir_ino: None,
                readdirplus_entry: None,
            }
        }

        fn with_recorders() -> (Self, Arc<AtomicU64>, Arc<AtomicU64>) {
            let readdir_fh = Arc::new(AtomicU64::new(u64::MAX));
            let readdirplus_fh = Arc::new(AtomicU64::new(u64::MAX));
            (
                Self {
                    inner: make_inner(),
                    readdir_fh: Arc::clone(&readdir_fh),
                    readdirplus_fh: Arc::clone(&readdirplus_fh),
                    inode_count_override: None,
                    lookup_entry: None,
                    readdir_ino: None,
                    readdirplus_entry: None,
                },
                readdir_fh,
                readdirplus_fh,
            )
        }

        fn with_inode_count(count: u64) -> Self {
            Self {
                inode_count_override: Some(count),
                ..Self::new()
            }
        }

        fn with_lookup_entry(nodeid: u64, attr_ino: u64) -> Self {
            Self {
                lookup_entry: Some((nodeid, attr_ino)),
                ..Self::new()
            }
        }

        fn with_readdir_ino(ino: u64) -> Self {
            Self {
                readdir_ino: Some(ino),
                ..Self::new()
            }
        }

        fn with_readdirplus_entry(nodeid: u64, attr_ino: u64) -> Self {
            Self {
                readdirplus_entry: Some((nodeid, attr_ino)),
                ..Self::new()
            }
        }

        fn entry(nodeid: u64, attr_ino: u64) -> FuseEntryOut {
            FuseEntryOut::new(
                nodeid,
                FuseAttr {
                    ino: attr_ino,
                    mode: S_IFREG | 0o444,
                    nlink: 1,
                    blksize: 512,
                    ..FuseAttr::default()
                },
            )
        }
    }

    impl FixedFsBackend for FhRecordingFs {
        fn inode_count(&self) -> u64 {
            self.inode_count_override
                .unwrap_or_else(|| self.inner.inode_count())
        }
    }

    impl FsBackend for FhRecordingFs {
        async fn init(&self) -> Result<FuseInitOut, FuseError> {
            self.inner.init().await
        }

        async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
            if parent == FUSE_ROOT_ID
                && name == b"bad"
                && let Some((nodeid, attr_ino)) = self.lookup_entry
            {
                return Ok(Self::entry(nodeid, attr_ino));
            }
            self.inner.lookup(parent, name).await
        }

        async fn forget(&self, nodeid: u64, nlookup: u64) {
            self.inner.forget(nodeid, nlookup).await;
        }

        async fn batch_forget(&self, forgets: &[(u64, u64)]) {
            self.inner.batch_forget(forgets).await;
        }

        async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
            self.inner.getattr(nodeid).await
        }

        async fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, FuseError> {
            self.inner.readlink(nodeid).await
        }

        async fn open(&self, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
            self.inner.open(nodeid, flags).await
        }

        async fn read(
            &self,
            nodeid: u64,
            fh: u64,
            offset: u64,
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            self.inner.read(nodeid, fh, offset, size).await
        }

        async fn release(&self, nodeid: u64, fh: u64) {
            self.inner.release(nodeid, fh).await;
        }

        async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
            self.inner.opendir(nodeid).await
        }

        async fn readdir(
            &self,
            nodeid: u64,
            fh: u64,
            offset: u64,
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            self.readdir_fh.store(fh, Ordering::Relaxed);
            if nodeid == FUSE_ROOT_ID
                && let Some(ino) = self.readdir_ino
            {
                let mut buf = Vec::with_capacity(size as usize);
                let _written = pack_dirent(&mut buf, size as usize, ino, b"bad", 3, DT_REG);
                return Ok(buf);
            }
            self.inner.readdir(nodeid, fh, offset, size).await
        }

        async fn readdirplus(
            &self,
            nodeid: u64,
            fh: u64,
            offset: u64,
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            self.readdirplus_fh.store(fh, Ordering::Relaxed);
            if nodeid == FUSE_ROOT_ID
                && let Some((nodeid, attr_ino)) = self.readdirplus_entry
            {
                let mut buf = Vec::with_capacity(size as usize);
                let entry = Self::entry(nodeid, attr_ino);
                let _written = pack_direntplus(&mut buf, size as usize, &entry, b"bad", 3, DT_REG);
                return Ok(buf);
            }
            self.inner.readdirplus(nodeid, fh, offset, size).await
        }

        async fn releasedir(&self, nodeid: u64, fh: u64) {
            self.inner.releasedir(nodeid, fh).await;
        }

        async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
            self.inner.statfs().await
        }

        async fn access(&self, nodeid: u64, mask: u32) -> Result<(), FuseError> {
            self.inner.access(nodeid, mask).await
        }

        async fn getxattr(
            &self,
            nodeid: u64,
            name: &[u8],
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            self.inner.getxattr(nodeid, name, size).await
        }

        async fn listxattr(&self, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError> {
            self.inner.listxattr(nodeid, size).await
        }

        async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
            self.inner.get_parent(nodeid).await
        }
    }

    #[test]
    fn inode_count() {
        let inner = make_inner();
        // inner: root(1) + HEAD(2) + config(3) = 3
        assert_eq!(inner.inode_count(), 3);
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        // 1 wrapper dir + 3 inner = 4
        assert_eq!(mounted.inode_count(), 4);
    }

    #[test]
    fn inode_count_multi_segment() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, "a/b/c", 0o755).unwrap();
        // 3 wrapper dirs + 3 inner = 6
        assert_eq!(mounted.inode_count(), 6);
    }

    #[test]
    fn new_rejects_invalid_inner_inode_count() {
        assert!(matches!(
            MountedFsBackend::new(FhRecordingFs::with_inode_count(0), ".git", 0o755),
            Err(InvalidMount::Layout("inner inode_count is zero"))
        ));
        assert!(matches!(
            MountedFsBackend::new(FhRecordingFs::with_inode_count(u64::MAX), ".git", 0o755),
            Err(InvalidMount::Layout("mounted inode namespace overflows"))
        ));
    }

    #[tokio::test]
    async fn lookup_single_segment() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();

        // Root has child ".git"
        let git = mounted.lookup(1, b".git").await.unwrap();
        assert_eq!(git.nodeid, 2); // mount point = inner root

        // ".git" has inner root's children
        let head = mounted.lookup(2, b"HEAD").await.unwrap();
        assert_eq!(head.nodeid, 3); // inner inode 2 → global 3

        let config = mounted.lookup(2, b"config").await.unwrap();
        assert_eq!(config.nodeid, 4); // inner inode 3 → global 4
    }

    #[tokio::test]
    async fn lookup_nonexistent() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.lookup(1, b"nope").await.is_err());
    }

    #[tokio::test]
    async fn lookup_rejects_backend_zero_inode() {
        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_lookup_entry(0, 2), ".git", 0o755).unwrap();
        assert_eq!(
            mounted.lookup(2, b"bad").await.unwrap_err(),
            FuseError::io()
        );

        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_lookup_entry(2, 0), ".git", 0o755).unwrap();
        assert_eq!(
            mounted.lookup(2, b"bad").await.unwrap_err(),
            FuseError::io()
        );
    }

    #[tokio::test]
    async fn lookup_rejects_backend_inode_past_count() {
        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_lookup_entry(4, 4), ".git", 0o755).unwrap();
        assert_eq!(
            mounted.lookup(2, b"bad").await.unwrap_err(),
            FuseError::io()
        );
    }

    #[tokio::test]
    async fn readdir_rejects_backend_zero_or_past_count_inode() {
        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_readdir_ino(0), ".git", 0o755).unwrap();
        assert_eq!(
            mounted.readdir(2, 0, 0, 4096).await.unwrap_err(),
            FuseError::io()
        );

        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_readdir_ino(4), ".git", 0o755).unwrap();
        assert_eq!(
            mounted.readdir(2, 0, 0, 4096).await.unwrap_err(),
            FuseError::io()
        );
    }

    #[tokio::test]
    async fn readdirplus_rejects_backend_zero_or_past_count_inode() {
        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_readdirplus_entry(0, 2), ".git", 0o755)
                .unwrap();
        assert_eq!(
            mounted.readdirplus(2, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );

        let mounted =
            MountedFsBackend::new(FhRecordingFs::with_readdirplus_entry(2, 4), ".git", 0o755)
                .unwrap();
        assert_eq!(
            mounted.readdirplus(2, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );
    }

    #[tokio::test]
    async fn nodeid_zero_is_rejected() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let invalid = FuseError::invalid().raw();

        assert_eq!(mounted.lookup(0, b".git").await.unwrap_err().raw(), invalid);
        assert_eq!(mounted.getattr(0).await.unwrap_err().raw(), invalid);
        assert_eq!(mounted.open(0, 0).await.unwrap_err().raw(), invalid);
        assert_eq!(
            mounted.read(0, 0, 0, 1024).await.unwrap_err().raw(),
            invalid
        );
        assert_eq!(mounted.opendir(0).await.unwrap_err().raw(), invalid);
        assert_eq!(
            mounted.readdir(0, 0, 0, 4096).await.unwrap_err().raw(),
            invalid
        );
        assert_eq!(
            mounted.readdirplus(0, 0, 0, 8192).await.unwrap_err().raw(),
            invalid
        );
        assert_eq!(mounted.access(0, 0).await.unwrap_err().raw(), invalid);
        assert_eq!(
            mounted
                .getxattr(0, b"user.test", 0)
                .await
                .unwrap_err()
                .raw(),
            invalid
        );
        assert_eq!(mounted.listxattr(0, 0).await.unwrap_err().raw(), invalid);
        assert_eq!(mounted.get_parent(0).await.unwrap_err().raw(), invalid);
    }

    #[tokio::test]
    async fn getattr_wrapper_dir() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let attr = mounted.getattr(1).await.unwrap();
        assert_eq!(attr.attr.ino, 1);
        assert_eq!(attr.attr.mode & 0o040_000, 0o040_000);
    }

    #[tokio::test]
    async fn getattr_mount_point() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let attr = mounted.getattr(2).await.unwrap();
        // Should have inner root's attributes but with global inode.
        assert_eq!(attr.attr.ino, 2);
        assert_eq!(attr.attr.mode & 0o040_000, 0o040_000);
    }

    #[tokio::test]
    async fn getattr_inner_file() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let attr = mounted.getattr(3).await.unwrap(); // HEAD
        assert_eq!(attr.attr.ino, 3);
        assert_eq!(attr.attr.size, 7);
    }

    #[tokio::test]
    async fn read_inner_file() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let data = mounted.read(3, 0, 0, 1024).await.unwrap(); // HEAD
        assert_eq!(&data, b"abc123\n");
    }

    #[tokio::test]
    async fn readdir_wrapper_root() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let buf = mounted.readdir(1, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&buf);
        assert!(names.contains(&b"."[..].to_vec()));
        assert!(names.contains(&b".."[..].to_vec()));
        assert!(names.contains(&b".git"[..].to_vec()));
    }

    #[tokio::test]
    async fn readdir_mount_point() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let buf = mounted.readdir(2, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&buf);
        assert!(names.contains(&b"HEAD"[..].to_vec()));
        assert!(names.contains(&b"config"[..].to_vec()));
    }

    #[tokio::test]
    async fn readdir_mount_point_forwards_fh() {
        let (inner, seen_fh, _) = FhRecordingFs::with_recorders();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let fh = 0xfeed_beef;

        let _buf = mounted.readdir(2, fh, 0, 4096).await.unwrap();

        assert_eq!(seen_fh.load(Ordering::Relaxed), fh);
    }

    fn parse_dirent_names(data: &[u8]) -> Vec<Vec<u8>> {
        let mut names = Vec::new();
        let mut pos = 0;
        let dirent_size = std::mem::size_of::<FuseDirent>();
        while pos + dirent_size <= data.len() {
            let dirent: &FuseDirent = bytemuck::from_bytes(&data[pos..pos + dirent_size]);
            let name_start = pos + dirent_size;
            let name_end = name_start + dirent.namelen as usize;
            if name_end > data.len() {
                break;
            }
            names.push(data[name_start..name_end].to_vec());
            let entry_size = (dirent_size + dirent.namelen as usize + 7) & !7;
            pos += entry_size;
        }
        names
    }

    #[tokio::test]
    async fn readdirplus_wrapper_root() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        // readdirplus on wrapper root (inode 1) should succeed, not ENOSYS.
        let buf = mounted.readdirplus(1, 0, 0, 8192).await.unwrap();
        // Parse the readdirplus entries to verify structure.
        let entry_out_size = std::mem::size_of::<FuseEntryOut>();
        let dirent_size = std::mem::size_of::<FuseDirent>();
        let mut names = Vec::new();
        let mut pos = 0;
        while pos + entry_out_size + dirent_size <= buf.len() {
            let entry_out: &FuseEntryOut = bytemuck::from_bytes(&buf[pos..pos + entry_out_size]);
            let dp = pos + entry_out_size;
            let dirent: &FuseDirent = bytemuck::from_bytes(&buf[dp..dp + dirent_size]);
            let name_start = dp + dirent_size;
            let name_end = name_start + dirent.namelen as usize;
            names.push(buf[name_start..name_end].to_vec());
            // Entry out should have valid nodeid and attr.
            assert_ne!(entry_out.nodeid, 0);
            let entry_size = (entry_out_size + dirent_size + dirent.namelen as usize + 7) & !7;
            pos += entry_size;
        }
        assert!(names.contains(&b"."[..].to_vec()));
        assert!(names.contains(&b".."[..].to_vec()));
        assert!(names.contains(&b".git"[..].to_vec()));
    }

    #[tokio::test]
    async fn readdirplus_mount_point_forwards_fh() {
        let (inner, _, seen_fh) = FhRecordingFs::with_recorders();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let fh = 0xfeed_cafe;

        let _buf = mounted.readdirplus(2, fh, 0, 8192).await.unwrap();

        assert_eq!(seen_fh.load(Ordering::Relaxed), fh);
    }

    // ─── Multi-segment path tests ───────────────────────────────────────

    #[tokio::test]
    async fn lookup_multi_segment() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, "a/b/c", 0o755).unwrap();

        // Root → a → b → c → inner children.
        let a = mounted.lookup(1, b"a").await.unwrap();
        assert_eq!(a.nodeid, 2);
        let b = mounted.lookup(2, b"b").await.unwrap();
        assert_eq!(b.nodeid, 3);
        let c = mounted.lookup(3, b"c").await.unwrap();
        assert_eq!(c.nodeid, 4); // mount point = inner root

        let head = mounted.lookup(4, b"HEAD").await.unwrap();
        assert_eq!(head.nodeid, 5); // inner inode 2 → global 5

        let data = mounted.read(5, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"abc123\n");
    }

    #[tokio::test]
    async fn lookup_wrong_segment_returns_error() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, "a/b", 0o755).unwrap();
        // Wrapper dir 1 only has child "a", not "b".
        assert!(mounted.lookup(1, b"b").await.is_err());
        assert!(mounted.lookup(1, b"nope").await.is_err());
        // Wrapper dir 2 only has child "b".
        assert!(mounted.lookup(2, b"a").await.is_err());
    }

    // ─── Write operations on wrapper dirs ───────────────────────────────

    #[tokio::test]
    async fn write_returns_erofs_on_all_inodes() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();

        // Write to wrapper dir.
        assert!(mounted.write(1, 0, 0, b"x", 0).await.is_err());
        // Write to mount point.
        assert!(mounted.write(2, 0, 0, b"x", 0).await.is_err());
        // Write to inner file.
        assert!(mounted.write(3, 0, 0, b"x", 0).await.is_err());
    }

    #[tokio::test]
    async fn mkdir_returns_erofs() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.mkdir(1, b"newdir", 0o755, ROOT_CTX).await.is_err());
        assert!(mounted.mkdir(2, b"newdir", 0o755, ROOT_CTX).await.is_err());
    }

    #[tokio::test]
    async fn unlink_returns_erofs() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.unlink(2, b"HEAD").await.is_err());
    }

    #[tokio::test]
    async fn create_returns_erofs() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(
            mounted
                .create(2, b"newfile", 0o644, 0, ROOT_CTX)
                .await
                .is_err()
        );
    }

    // ─── Getattr for all wrapper dirs ───────────────────────────────────

    #[tokio::test]
    async fn getattr_all_multi_segment_wrappers() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, "a/b/c", 0o755).unwrap();

        for inode in 1..=3 {
            let attr = mounted.getattr(inode).await.unwrap();
            assert_eq!(attr.attr.ino, inode);
            assert_eq!(
                attr.attr.mode & 0o040_000,
                0o040_000,
                "inode {inode} should be dir"
            );
            assert_eq!(attr.attr.mode & 0o777, 0o755);
        }
    }

    // ─── Getattr for invalid inode ──────────────────────────────────────

    #[tokio::test]
    async fn getattr_invalid_inode() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.getattr(999).await.is_err());
    }

    // ─── Readdir multi-segment wrapper dirs ─────────────────────────────

    #[tokio::test]
    async fn readdir_multi_segment_wrappers() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, "a/b", 0o755).unwrap();

        // Root has only "a".
        let buf = mounted.readdir(1, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&buf);
        assert!(names.contains(&b"a"[..].to_vec()));
        assert!(!names.contains(&b"b"[..].to_vec()));

        // "a" has only "b".
        let buf = mounted.readdir(2, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&buf);
        assert!(names.contains(&b"b"[..].to_vec()));
        assert!(!names.contains(&b"HEAD"[..].to_vec()));
    }

    // ─── Open/opendir on wrapper dirs ───────────────────────────────────

    #[tokio::test]
    async fn open_wrapper_dir_returns_eisdir() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.open(1, 0).await.is_err()); // wrapper root
    }

    #[tokio::test]
    async fn opendir_wrapper_dir_succeeds() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.opendir(1).await.is_ok());
    }

    #[tokio::test]
    async fn opendir_mount_point_succeeds() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.opendir(2).await.is_ok());
    }

    // ─── Read wrapper dir returns error ─────────────────────────────────

    #[tokio::test]
    async fn read_wrapper_dir_returns_error() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.read(1, 0, 0, 1024).await.is_err());
    }

    // ─── Access ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn access_all_inodes() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        assert!(mounted.access(1, 0).await.is_ok()); // wrapper root
        assert!(mounted.access(2, 0).await.is_ok()); // mount point
        assert!(mounted.access(3, 0).await.is_ok()); // inner file
    }

    // ─── Forget ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn forget_does_not_panic() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        mounted.forget(1, 1).await;
        mounted.forget(2, 1).await;
        mounted.forget(3, 1).await;
    }

    // ─── Statfs ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn statfs_returns_values() {
        let inner = make_inner();
        let mounted = MountedFsBackend::new(inner, ".git", 0o755).unwrap();
        let st = mounted.statfs().await.unwrap();
        assert!(st.st.bsize > 0);
        assert!(st.st.namelen > 0);
    }

    // ─── Prefix validation ──────────────────────────────────────────────

    #[test]
    fn new_rejects_empty_prefix() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "", 0o755).is_err());
    }

    #[test]
    fn new_rejects_absolute_prefix() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "/a", 0o755).is_err());
    }

    #[test]
    fn new_rejects_dot_component() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "a/./b", 0o755).is_err());
    }

    #[test]
    fn new_rejects_dotdot_component() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "a/../b", 0o755).is_err());
    }

    #[test]
    fn new_rejects_nul_byte() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "a\0b", 0o755).is_err());
    }

    #[test]
    fn new_rejects_double_slash() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "a//b", 0o755).is_err());
    }

    #[test]
    fn new_rejects_trailing_slash() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, "a/", 0o755).is_err());
    }

    #[test]
    fn new_rejects_bare_dot() {
        let inner = make_inner();
        assert!(MountedFsBackend::new(inner, ".", 0o755).is_err());
    }
}
