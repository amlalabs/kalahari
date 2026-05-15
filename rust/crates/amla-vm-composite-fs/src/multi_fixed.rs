// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! [`MultiFixedFsBackend`] merges N [`FixedFsBackend`]s into one namespace.
//!
//! Inode scheme:
//! - Inode 1 = composite root (virtual, merges all backends' root dirs)
//! - Backend 0 non-root inodes: `[2, N0]`
//! - Backend 1 non-root inodes: `[N0+1, N0+N1-1]`
//! - Backend k non-root inodes: `[base_k+1, base_k+Nk-1]`
//!
//! Where `base_k = 1 + sum(Ni - 1 for i in 0..k)` and Ni = backend i's `inode_count`.
//!
//! Backends are carried as an [`HList`](crate::hlist) so their concrete types
//! are preserved through composition — indexed dispatch goes through
//! [`FixedList`] methods that the compiler unrolls into direct calls, with no
//! vtable or heap-allocated futures.

use amla_fuse::fs_types::{
    ATTR_VALID_SECS, DT_DIR, FUSE_ROOT_ID, S_IFDIR, try_rewrite_readdir_inodes,
    try_rewrite_readdirplus_inodes,
};
use amla_fuse::fuse::{
    FixedFsBackend, FsBackend, FuseAttr, FuseAttrOut, FuseDirent, FuseEntryOut, FuseInitOut,
    FuseOpenOut, FuseStatfsOut, pack_dirent, pack_direntplus,
};
use amla_fuse::fuse_abi::FuseError;
use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;

use crate::hlist::FixedList;

/// Which backend owns a given inode.
struct Owner {
    /// Index into the backends list.
    idx: usize,
    /// The inode number in the backend's local space.
    local: LocalInode,
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
struct LocalInode(NonZeroU64);

impl LocalInode {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::io)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackendInodeCount(NonZeroU64);

impl BackendInodeCount {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or_else(FuseError::invalid)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BackendRange {
    base: u64,
    count: BackendInodeCount,
}

impl BackendRange {
    const fn contains(self, global: GuestInode) -> bool {
        if global.get() == FUSE_ROOT_ID {
            return false;
        }
        let Some(local) = global.get().checked_sub(self.base) else {
            return false;
        };
        local >= 2 && local <= self.count.get()
    }

    fn global_to_local(self, global: GuestInode) -> Result<LocalInode, FuseError> {
        let local = global
            .get()
            .checked_sub(self.base)
            .ok_or_else(FuseError::io)?;
        LocalInode::from_backend(local)
    }

    fn local_to_global(self, local: LocalInode) -> Result<GuestInode, FuseError> {
        if local.get() == FUSE_ROOT_ID {
            return Ok(GuestInode(NonZeroU64::MIN));
        }
        if local.get() > self.count.get() {
            return Err(FuseError::io());
        }
        let raw = self
            .base
            .checked_add(local.get())
            .ok_or_else(FuseError::range)?;
        GuestInode::from_guest(raw).map_err(|_| FuseError::io())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct MultiFixedLayout {
    ranges: Vec<BackendRange>,
    total: BackendInodeCount,
}

impl MultiFixedLayout {
    fn from_counts(counts: impl IntoIterator<Item = u64>) -> Result<Self, FuseError> {
        let mut ranges = Vec::new();
        let mut cumulative = 0u64;

        for raw_count in counts {
            let count = BackendInodeCount::from_backend(raw_count)?;
            ranges.push(BackendRange {
                base: cumulative,
                count,
            });
            let contribution = count
                .get()
                .checked_sub(FUSE_ROOT_ID)
                .ok_or_else(FuseError::invalid)?;
            cumulative = cumulative
                .checked_add(contribution)
                .ok_or_else(FuseError::range)?;
        }

        if ranges.is_empty() {
            return Err(FuseError::invalid());
        }

        let total = cumulative
            .checked_add(FUSE_ROOT_ID)
            .and_then(NonZeroU64::new)
            .map(BackendInodeCount)
            .ok_or_else(FuseError::range)?;
        Ok(Self { ranges, total })
    }

    const fn total(&self) -> u64 {
        self.total.get()
    }

    fn classify(&self, raw: u64) -> Result<Option<Owner>, FuseError> {
        let global = GuestInode::from_guest(raw)?;
        if global.get() == FUSE_ROOT_ID {
            return Ok(None);
        }
        if global.get() > self.total() {
            return Ok(None);
        }
        for (idx, range) in self.ranges.iter().enumerate().rev() {
            if range.contains(global) {
                return Ok(Some(Owner {
                    idx,
                    local: range.global_to_local(global)?,
                }));
            }
        }
        Ok(None)
    }

    fn local_to_global(&self, idx: usize, local: u64) -> Result<u64, FuseError> {
        let range = self.ranges.get(idx).ok_or_else(FuseError::invalid)?;
        Ok(range
            .local_to_global(LocalInode::from_backend(local)?)?
            .get())
    }
}

/// Merges N [`FixedFsBackend`]s into a single [`FixedFsBackend`].
///
/// Each backend's non-root inodes occupy a contiguous range in global inode
/// space. The composite root merges all backends' root directories.
///
/// `L` is an `HList` (see [`mod@crate::hlist`]) carrying the concrete backend
/// types — construct via [`hlist!`](crate::hlist!).
pub struct MultiFixedFsBackend<L: FixedList> {
    backends: L,
    layout: MultiFixedLayout,
    uid: u32,
    gid: u32,
}

/// Error returned when a multi-fixed filesystem cannot be constructed.
pub struct InvalidMultiFixedLayout<L> {
    error: FuseError,
    backends: L,
}

impl<L> InvalidMultiFixedLayout<L> {
    /// The layout validation error.
    pub const fn error(&self) -> FuseError {
        self.error
    }

    /// Recover the rejected backend list.
    pub fn into_parts(self) -> (FuseError, L) {
        (self.error, self.backends)
    }
}

impl<L> fmt::Debug for InvalidMultiFixedLayout<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("InvalidMultiFixedLayout")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl<L> fmt::Display for InvalidMultiFixedLayout<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid multi-fixed filesystem layout: {}", self.error)
    }
}

impl<L> std::error::Error for InvalidMultiFixedLayout<L> {}

impl<L: FixedList> MultiFixedFsBackend<L> {
    /// Create from an `HList` of fixed backends.
    ///
    pub fn new(backends: L) -> Result<Self, InvalidMultiFixedLayout<L>> {
        let n = backends.len();
        let layout = match MultiFixedLayout::from_counts((0..n).map(|i| backends.inode_count_at(i)))
        {
            Ok(layout) => layout,
            Err(error) => return Err(InvalidMultiFixedLayout { error, backends }),
        };

        Ok(Self {
            backends,
            layout,
            uid: 0,
            gid: 0,
        })
    }

    /// Set UID/GID for the composite root directory.
    #[must_use]
    pub const fn with_uid_gid(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Classify a global inode to its owning backend and local inode.
    fn classify(&self, global: u64) -> Result<Option<Owner>, FuseError> {
        self.layout.classify(global)
    }

    /// Convert a backend's local inode to global.
    fn to_global(&self, idx: usize, local: u64) -> Result<u64, FuseError> {
        self.layout.local_to_global(idx, local)
    }

    fn entry_to_global(
        &self,
        idx: usize,
        mut entry: FuseEntryOut,
    ) -> Result<FuseEntryOut, FuseError> {
        entry.nodeid = self.to_global(idx, entry.nodeid)?;
        entry.attr.ino = self.to_global(idx, entry.attr.ino)?;
        Ok(entry)
    }

    fn owner(&self, nodeid: u64) -> Result<Owner, FuseError> {
        self.classify(nodeid)?.ok_or_else(FuseError::not_found)
    }

    const fn composite_root_attr(&self) -> FuseAttr {
        FuseAttr {
            ino: 1,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: S_IFDIR | 0o755,
            nlink: 2,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        }
    }

    // Readdir at the composite root (nodeid = 1).
    //
    // The composite root is the union of every sub-backend's own root listing,
    // so we synthesize `.` and `..` ourselves and filter out the sub-backends'
    // copies. Entries are numbered monotonically — `.` is #1, `..` is #2,
    // backend 0's real entries start at #3, backend 1's follow, and so on.
    // The readdir `offset` is that monotonic count: on resume we replay from
    // the start of the logical stream and skip the first `offset` entries.
    // Replaying per call is O(N) in entries walked; dirs we care about are
    // small enough that this is well under any hot path.
    async fn readdir_root(&self, offset: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        let max = size as usize;
        let mut buf = Vec::with_capacity(max);
        let mut emitted: u64 = 0;

        emitted += 1;
        if emitted > offset && pack_dirent(&mut buf, max, 1, b".", emitted, DT_DIR) == 0 {
            return Ok(buf);
        }
        emitted += 1;
        if emitted > offset && pack_dirent(&mut buf, max, 1, b"..", emitted, DT_DIR) == 0 {
            return Ok(buf);
        }

        let dirent_size = core::mem::size_of::<FuseDirent>();
        let n = self.backends.len();
        let mut full = false;
        let mut seen = BTreeSet::new();
        for bidx in 0..n {
            if full {
                break;
            }
            let open = self.backends.opendir_at(bidx, 1).await?;
            let mut local: u64 = 0;
            'chunks: loop {
                let remaining = max.saturating_sub(buf.len());
                if remaining == 0 {
                    full = true;
                    break 'chunks;
                }
                let part = self
                    .backends
                    .readdir_at(bidx, 1, open.fh, local, remaining as u32)
                    .await?;
                if part.is_empty() {
                    break 'chunks;
                }
                let mut pos = 0;
                while pos + dirent_size <= part.len() {
                    let dirent: &FuseDirent = bytemuck::from_bytes(&part[pos..pos + dirent_size]);
                    let namelen = dirent.namelen as usize;
                    if namelen == 0 {
                        self.backends.releasedir_at(bidx, 1, open.fh).await;
                        return Err(FuseError::io());
                    }
                    let entry_size = (dirent_size + namelen + 7) & !7;
                    if pos + entry_size > part.len() {
                        self.backends.releasedir_at(bidx, 1, open.fh).await;
                        return Err(FuseError::io());
                    }
                    let name = &part[pos + dirent_size..pos + dirent_size + namelen];
                    // Advance the backend cursor even for `./..` we drop, so
                    // the next chunk request resumes past them.
                    local = local.max(dirent.off);
                    if name != b"." && name != b".." {
                        if !seen.insert(name.to_vec()) {
                            self.backends.releasedir_at(bidx, 1, open.fh).await;
                            return Err(FuseError::exists());
                        }
                        emitted += 1;
                        let ino = self.to_global(bidx, dirent.ino)?;
                        if emitted > offset
                            && pack_dirent(&mut buf, max, ino, name, emitted, dirent.typ) == 0
                        {
                            full = true;
                            break 'chunks;
                        }
                    }
                    pos += entry_size;
                }
                if pos != part.len() {
                    self.backends.releasedir_at(bidx, 1, open.fh).await;
                    return Err(FuseError::io());
                }
            }
            self.backends.releasedir_at(bidx, 1, open.fh).await;
        }
        Ok(buf)
    }

    async fn readdirplus_root(&self, offset: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        let max = size as usize;
        let mut buf = Vec::with_capacity(max);
        let mut emitted: u64 = 0;

        // Composite root is its own parent (see get_parent), so both `.` and
        // `..` point at the composite root itself.
        let root_entry = FuseEntryOut::new(1, self.composite_root_attr());
        emitted += 1;
        if emitted > offset
            && pack_direntplus(&mut buf, max, &root_entry, b".", emitted, DT_DIR) == 0
        {
            return Ok(buf);
        }
        emitted += 1;
        if emitted > offset
            && pack_direntplus(&mut buf, max, &root_entry, b"..", emitted, DT_DIR) == 0
        {
            return Ok(buf);
        }

        let entry_out_size = core::mem::size_of::<FuseEntryOut>();
        let dirent_size = core::mem::size_of::<FuseDirent>();
        let n = self.backends.len();
        let mut full = false;
        let mut seen = BTreeSet::new();
        for bidx in 0..n {
            if full {
                break;
            }
            let open = self.backends.opendir_at(bidx, 1).await?;
            let mut local: u64 = 0;
            'chunks: loop {
                let remaining = max.saturating_sub(buf.len());
                if remaining == 0 {
                    full = true;
                    break 'chunks;
                }
                let part = self
                    .backends
                    .readdirplus_at(bidx, 1, open.fh, local, remaining as u32)
                    .await?;
                if part.is_empty() {
                    break 'chunks;
                }
                let mut pos = 0;
                while pos + entry_out_size + dirent_size <= part.len() {
                    let dp = pos + entry_out_size;
                    let dirent: &FuseDirent = bytemuck::from_bytes(&part[dp..dp + dirent_size]);
                    let namelen = dirent.namelen as usize;
                    if namelen == 0 {
                        self.backends.releasedir_at(bidx, 1, open.fh).await;
                        return Err(FuseError::io());
                    }
                    let entry_size = (entry_out_size + dirent_size + namelen + 7) & !7;
                    if pos + entry_size > part.len() {
                        self.backends.releasedir_at(bidx, 1, open.fh).await;
                        return Err(FuseError::io());
                    }
                    let name = &part[dp + dirent_size..dp + dirent_size + namelen];
                    local = local.max(dirent.off);
                    if name != b"." && name != b".." {
                        if !seen.insert(name.to_vec()) {
                            self.backends.releasedir_at(bidx, 1, open.fh).await;
                            return Err(FuseError::exists());
                        }
                        emitted += 1;
                        if emitted > offset {
                            let entry: &FuseEntryOut =
                                bytemuck::from_bytes(&part[pos..pos + entry_out_size]);
                            let mut translated = *entry;
                            translated.nodeid = self.to_global(bidx, translated.nodeid)?;
                            translated.attr.ino = self.to_global(bidx, translated.attr.ino)?;
                            if pack_direntplus(
                                &mut buf,
                                max,
                                &translated,
                                name,
                                emitted,
                                dirent.typ,
                            ) == 0
                            {
                                full = true;
                                break 'chunks;
                            }
                        }
                    }
                    pos += entry_size;
                }
                if pos != part.len() {
                    self.backends.releasedir_at(bidx, 1, open.fh).await;
                    return Err(FuseError::io());
                }
            }
            self.backends.releasedir_at(bidx, 1, open.fh).await;
        }
        Ok(buf)
    }
}

impl<L: FixedList> FixedFsBackend for MultiFixedFsBackend<L> {
    fn inode_count(&self) -> u64 {
        self.layout.total()
    }
}

impl<L: FixedList> FsBackend for MultiFixedFsBackend<L> {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        let out = self.backends.init_at(0).await?;
        for i in 1..self.backends.len() {
            self.backends.init_at(i).await?;
        }
        // Arbitrary choice of which backend's FuseInitOut to surface —
        // OverlayFsBackend uses the dynamic backend's init anyway.
        Ok(out)
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        if parent == 1 {
            // Composite root: every backend must agree that the name is
            // either absent or uniquely present. Returning the first hit
            // would hide later backend EIO/corruption and make duplicate root
            // children depend on backend order.
            let n = self.backends.len();
            let mut found = None;
            for i in 0..n {
                match self.backends.lookup_at(i, 1, name).await {
                    Ok(entry) => {
                        if found.is_some() {
                            return Err(FuseError::exists());
                        }
                        found = Some(self.entry_to_global(i, entry)?);
                    }
                    Err(e) if e == FuseError::not_found() => {}
                    Err(e) => return Err(e),
                }
            }
            return found.ok_or_else(FuseError::not_found);
        }

        let owner = self.owner(parent)?;
        let result = self
            .backends
            .lookup_at(owner.idx, owner.local.get(), name)
            .await?;
        self.entry_to_global(owner.idx, result)
    }

    async fn forget(&self, nodeid: u64, nlookup: u64) {
        if let Some(owner) = self.classify(nodeid).ok().flatten() {
            self.backends
                .forget_at(owner.idx, owner.local.get(), nlookup)
                .await;
        }
    }

    async fn batch_forget(&self, forgets: &[(u64, u64)]) {
        // Group by backend.
        let n = self.backends.len();
        let mut per_backend: Vec<Vec<(u64, u64)>> = vec![Vec::new(); n];
        for &(nodeid, nlookup) in forgets {
            if let Some(owner) = self.classify(nodeid).ok().flatten() {
                per_backend[owner.idx].push((owner.local.get(), nlookup));
            }
        }
        for (i, batch) in per_backend.into_iter().enumerate() {
            if !batch.is_empty() {
                self.backends.batch_forget_at(i, &batch).await;
            }
        }
    }

    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        if nodeid == 1 {
            return Ok(FuseAttrOut {
                attr_valid: ATTR_VALID_SECS,
                attr_valid_nsec: 0,
                dummy: 0,
                attr: self.composite_root_attr(),
            });
        }
        let owner = self.owner(nodeid)?;
        let mut result = self
            .backends
            .getattr_at(owner.idx, owner.local.get())
            .await?;
        result.attr.ino = self.to_global(owner.idx, result.attr.ino)?;
        Ok(result)
    }

    async fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, FuseError> {
        let owner = self.classify(nodeid)?.ok_or_else(FuseError::invalid)?;
        self.backends
            .readlink_at(owner.idx, owner.local.get())
            .await
    }

    async fn open(&self, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
        if nodeid == 1 {
            return Err(FuseError::is_dir());
        }
        let owner = self.owner(nodeid)?;
        self.backends
            .open_at(owner.idx, owner.local.get(), flags)
            .await
    }

    async fn read(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let owner = self.owner(nodeid)?;
        self.backends
            .read_at(owner.idx, owner.local.get(), fh, offset, size)
            .await
    }

    async fn release(&self, nodeid: u64, fh: u64) {
        if let Some(owner) = self.classify(nodeid).ok().flatten() {
            self.backends
                .release_at(owner.idx, owner.local.get(), fh)
                .await;
        }
    }

    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        if nodeid == 1 {
            return Ok(FuseOpenOut {
                fh: 0,
                open_flags: 0,
                padding: 0,
            });
        }
        let owner = self.owner(nodeid)?;
        self.backends.opendir_at(owner.idx, owner.local.get()).await
    }

    async fn readdir(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if nodeid == 1 {
            return self.readdir_root(offset, size).await;
        }
        let owner = self.owner(nodeid)?;
        let idx = owner.idx;
        let mut buf = self
            .backends
            .readdir_at(idx, owner.local.get(), fh, offset, size)
            .await?;
        try_rewrite_readdir_inodes(&mut buf, |ino| self.to_global(idx, ino))?;
        Ok(buf)
    }

    async fn readdirplus(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if nodeid == 1 {
            return self.readdirplus_root(offset, size).await;
        }
        let owner = self.owner(nodeid)?;
        let idx = owner.idx;
        let mut buf = self
            .backends
            .readdirplus_at(idx, owner.local.get(), fh, offset, size)
            .await?;
        try_rewrite_readdirplus_inodes(&mut buf, |ino| self.to_global(idx, ino))?;
        Ok(buf)
    }

    async fn releasedir(&self, nodeid: u64, fh: u64) {
        if let Some(owner) = self.classify(nodeid).ok().flatten() {
            self.backends
                .releasedir_at(owner.idx, owner.local.get(), fh)
                .await;
        }
    }

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        self.backends.statfs_at(0).await
    }

    async fn access(&self, nodeid: u64, mask: u32) -> Result<(), FuseError> {
        if nodeid == 1 {
            return Ok(());
        }
        let owner = self.owner(nodeid)?;
        self.backends
            .access_at(owner.idx, owner.local.get(), mask)
            .await
    }

    async fn getxattr(&self, nodeid: u64, name: &[u8], size: u32) -> Result<Vec<u8>, FuseError> {
        let owner = self.owner(nodeid)?;
        self.backends
            .getxattr_at(owner.idx, owner.local.get(), name, size)
            .await
    }

    async fn listxattr(&self, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        let owner = self.owner(nodeid)?;
        self.backends
            .listxattr_at(owner.idx, owner.local.get(), size)
            .await
    }

    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        if nodeid == 1 {
            // Composite root's parent is itself.
            Ok(FuseEntryOut::new(1, self.composite_root_attr()))
        } else {
            let owner = self.owner(nodeid)?;
            let entry = self
                .backends
                .get_parent_at(owner.idx, owner.local.get())
                .await?;
            self.entry_to_global(owner.idx, entry)
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::hlist;
    use amla_fuse::fs_types::{DT_REG, S_IFREG};
    use amla_synthesized_fs::SynthesizedFs;

    fn make_backend_a() -> SynthesizedFs<'static> {
        SynthesizedFs::builder()
            .file("HEAD", b"abc123\n", 0o444)
            .unwrap()
            .file("config", b"[core]\n", 0o444)
            .unwrap()
            .build()
    }

    fn make_backend_b() -> SynthesizedFs<'static> {
        SynthesizedFs::builder()
            .file("README", b"hello\n", 0o444)
            .unwrap()
            .build()
    }

    fn make_backend_duplicate_head() -> SynthesizedFs<'static> {
        SynthesizedFs::builder()
            .file("HEAD", b"duplicate\n", 0o444)
            .unwrap()
            .build()
    }

    struct TestFixed {
        inner: SynthesizedFs<'static>,
        inode_count_override: Option<u64>,
        lookup_entry: Option<(u64, u64)>,
        readdir_ino: Option<u64>,
        readdirplus_entry: Option<(u64, u64)>,
    }

    impl TestFixed {
        fn new() -> Self {
            Self {
                inner: make_backend_a(),
                inode_count_override: None,
                lookup_entry: None,
                readdir_ino: None,
                readdirplus_entry: None,
            }
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

    impl FixedFsBackend for TestFixed {
        fn inode_count(&self) -> u64 {
            self.inode_count_override
                .unwrap_or_else(|| self.inner.inode_count())
        }
    }

    impl FsBackend for TestFixed {
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
            _fh: u64,
            _offset: u64,
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            if nodeid == FUSE_ROOT_ID
                && let Some(ino) = self.readdir_ino
            {
                let mut buf = Vec::with_capacity(size as usize);
                let _written = pack_dirent(&mut buf, size as usize, ino, b"bad", 3, DT_REG);
                return Ok(buf);
            }
            self.inner.readdir(nodeid, 0, 0, size).await
        }

        async fn readdirplus(
            &self,
            nodeid: u64,
            _fh: u64,
            _offset: u64,
            size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            if nodeid == FUSE_ROOT_ID
                && let Some((nodeid, attr_ino)) = self.readdirplus_entry
            {
                let mut buf = Vec::with_capacity(size as usize);
                let entry = Self::entry(nodeid, attr_ino);
                let _written = pack_direntplus(&mut buf, size as usize, &entry, b"bad", 3, DT_REG);
                return Ok(buf);
            }
            self.inner.readdirplus(nodeid, 0, 0, size).await
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
    fn inode_count_single() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a()]).unwrap();
        // Backend A: root(1) + HEAD(2) + config(3) = 3 inodes.
        // Multi: 1 (composite root) + 2 non-root = 3.
        assert_eq!(multi.inode_count(), 3);
    }

    #[test]
    fn inode_count_two() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_b()]).unwrap();
        // A: 3 inodes (2 non-root), B: 2 inodes (1 non-root).
        // Multi: 1 + 2 + 1 = 4.
        assert_eq!(multi.inode_count(), 4);
    }

    #[test]
    fn new_rejects_invalid_backend_counts() {
        assert!(matches!(
            MultiFixedFsBackend::new(hlist![TestFixed::with_inode_count(0)]),
            Err(error) if error.error() == FuseError::invalid()
        ));
        assert!(matches!(
            MultiFixedFsBackend::new(hlist![
                TestFixed::with_inode_count(u64::MAX),
                TestFixed::with_inode_count(2)
            ]),
            Err(error) if error.error() == FuseError::range()
        ));
    }

    #[tokio::test]
    async fn lookup_from_first_backend() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_b()]).unwrap();
        let entry = multi.lookup(1, b"HEAD").await.unwrap();
        assert_eq!(entry.nodeid, 2); // A's inode 2 → global 2
    }

    #[tokio::test]
    async fn lookup_from_second_backend() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_b()]).unwrap();
        let entry = multi.lookup(1, b"README").await.unwrap();
        // B's inode 2 → global bases[1]+2 = 2+2 = 4.
        assert_eq!(entry.nodeid, 4);
    }

    #[tokio::test]
    async fn lookup_duplicate_root_name_errors() {
        let multi =
            MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_duplicate_head()])
                .unwrap();
        let err = multi.lookup(1, b"HEAD").await.unwrap_err();
        assert_eq!(err, FuseError::exists());
    }

    #[tokio::test]
    async fn lookup_not_found() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a()]).unwrap();
        assert!(multi.lookup(1, b"nope").await.is_err());
    }

    #[tokio::test]
    async fn lookup_rejects_backend_zero_or_past_count_inode() {
        let multi = MultiFixedFsBackend::new(hlist![TestFixed::with_lookup_entry(0, 2)]).unwrap();
        assert_eq!(multi.lookup(1, b"bad").await.unwrap_err(), FuseError::io());

        let multi = MultiFixedFsBackend::new(hlist![TestFixed::with_lookup_entry(2, 0)]).unwrap();
        assert_eq!(multi.lookup(1, b"bad").await.unwrap_err(), FuseError::io());

        let multi = MultiFixedFsBackend::new(hlist![TestFixed::with_lookup_entry(4, 4)]).unwrap();
        assert_eq!(multi.lookup(1, b"bad").await.unwrap_err(), FuseError::io());
    }

    #[tokio::test]
    async fn getattr_composite_root() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a()]).unwrap();
        let attr = multi.getattr(1).await.unwrap();
        assert_eq!(attr.attr.ino, 1);
        assert_eq!(attr.attr.mode & 0o040_000, 0o040_000);
    }

    #[tokio::test]
    async fn getattr_inner_file() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a()]).unwrap();
        let attr = multi.getattr(2).await.unwrap();
        assert_eq!(attr.attr.ino, 2);
        assert_eq!(attr.attr.size, 7); // "abc123\n"
    }

    #[tokio::test]
    async fn read_from_second_backend() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_b()]).unwrap();
        // README is in B, global inode 4.
        let entry = multi.lookup(1, b"README").await.unwrap();
        let data = multi.read(entry.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"hello\n");
    }

    #[tokio::test]
    async fn readdir_root_merges_backends() {
        let multi = MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_b()]).unwrap();
        let buf = multi.readdir(1, 0, 0, 8192).await.unwrap();
        let names = parse_dirent_names(&buf);
        assert!(names.contains(&b"HEAD"[..].to_vec()));
        assert!(names.contains(&b"config"[..].to_vec()));
        assert!(names.contains(&b"README"[..].to_vec()));
    }

    #[tokio::test]
    async fn readdir_duplicate_root_name_errors() {
        let multi =
            MultiFixedFsBackend::new(hlist![make_backend_a(), make_backend_duplicate_head()])
                .unwrap();
        let err = multi.readdir(1, 0, 0, 8192).await.unwrap_err();
        assert_eq!(err, FuseError::exists());
    }

    #[tokio::test]
    async fn readdir_rejects_backend_zero_or_past_count_inode() {
        let multi = MultiFixedFsBackend::new(hlist![TestFixed::with_readdir_ino(0)]).unwrap();
        assert_eq!(
            multi.readdir(1, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );

        let multi = MultiFixedFsBackend::new(hlist![TestFixed::with_readdir_ino(4)]).unwrap();
        assert_eq!(
            multi.readdir(1, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );
    }

    #[tokio::test]
    async fn readdirplus_rejects_backend_zero_or_past_count_inode() {
        let multi =
            MultiFixedFsBackend::new(hlist![TestFixed::with_readdirplus_entry(0, 2)]).unwrap();
        assert_eq!(
            multi.readdirplus(1, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );

        let multi =
            MultiFixedFsBackend::new(hlist![TestFixed::with_readdirplus_entry(2, 4)]).unwrap();
        assert_eq!(
            multi.readdirplus(1, 0, 0, 8192).await.unwrap_err(),
            FuseError::io()
        );
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
}
