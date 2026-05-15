// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! [`OverlayFsBackend`] merges a dynamic and fixed backend into one namespace.
//!
//! Inode scheme (fixed LOW, dynamic HIGH):
//! - Inode 1 = composite root (virtual, merges both backends' roots)
//! - Inodes [2, N] = fixed backend's non-root inodes (local = global)
//! - Inodes [N+1, ...] = dynamic backend's non-root inodes (local = global - N + 1)
//!
//! Where N = `fixed_backend.inode_count()`.
//!
//! Name collisions at the composite root use overlay semantics: the dynamic
//! upper layer wins and fixed lower-layer duplicates are suppressed.

use std::collections::{HashMap, HashSet};
use std::num::NonZeroU64;
use std::sync::{Mutex, MutexGuard};

use amla_fuse::fs_types::{
    ATTR_VALID_SECS, DT_DIR, FUSE_ROOT_ID, S_IFDIR, mode_to_dtype, try_rewrite_readdir_inodes,
    try_rewrite_readdirplus_inodes,
};
use amla_fuse::fuse::{
    DynamicFsBackend, FixedFsBackend, FsBackend, FuseAttr, FuseAttrOut, FuseContext, FuseDirent,
    FuseEntryOut, FuseInitOut, FuseKstatfs, FuseOpenOut, FuseStatfsOut, pack_dirent,
    pack_direntplus,
};
use amla_fuse::fuse_abi::FuseError;

const ROOT_READDIR_PAGE_SIZE: u32 = 64 * 1024;

type DirOffset = u64;
type Name = Vec<u8>;

/// Which backend owns a given inode.
enum Owner {
    /// Composite root (inode 1) — handled specially.
    CompositeRoot,
    /// Fixed backend. Inner inode is the same as global.
    Fixed(FixedLocalInode),
    /// Dynamic backend. Inner inode translated from global.
    Dynamic(DynamicLocalInode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct GlobalInode(NonZeroU64);

impl GlobalInode {
    const ROOT: Self = Self(NonZeroU64::MIN);

    fn from_guest(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw)
            .map(Self)
            .ok_or_else(FuseError::invalid)
    }

    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::io)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedLocalInode(NonZeroU64);

impl FixedLocalInode {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::io)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DynamicLocalInode(NonZeroU64);

impl DynamicLocalInode {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::io)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FixedInodeCount(NonZeroU64);

impl FixedInodeCount {
    fn from_backend(raw: u64) -> Result<Self, FuseError> {
        let value = NonZeroU64::new(raw).ok_or_else(FuseError::invalid)?;
        if raw == u64::MAX {
            return Err(FuseError::range());
        }
        Ok(Self(value))
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InodePartition {
    fixed_count: FixedInodeCount,
}

impl InodePartition {
    fn from_fixed_count(raw: u64) -> Result<Self, FuseError> {
        Ok(Self {
            fixed_count: FixedInodeCount::from_backend(raw)?,
        })
    }

    fn classify(self, global: GlobalInode) -> Owner {
        let raw = global.get();
        if raw == FUSE_ROOT_ID {
            Owner::CompositeRoot
        } else if raw <= self.fixed_count.get() {
            Owner::Fixed(FixedLocalInode(global.0))
        } else {
            let local = raw - self.fixed_count.get() + FUSE_ROOT_ID;
            let Some(local) = NonZeroU64::new(local) else {
                unreachable!("dynamic local inode is nonzero after global partition check");
            };
            Owner::Dynamic(DynamicLocalInode(local))
        }
    }

    fn dynamic_to_global(self, local: DynamicLocalInode) -> Result<GlobalInode, FuseError> {
        if local.get() == FUSE_ROOT_ID {
            return Ok(GlobalInode::ROOT);
        }

        let offset = local
            .get()
            .checked_sub(FUSE_ROOT_ID)
            .ok_or_else(FuseError::io)?;
        let raw = self
            .fixed_count
            .get()
            .checked_add(offset)
            .ok_or_else(FuseError::range)?;
        GlobalInode::from_backend(raw)
    }

    const fn fixed_to_global(self, local: FixedLocalInode) -> Result<GlobalInode, FuseError> {
        if local.get() > self.fixed_count.get() {
            return Err(FuseError::io());
        }
        if local.get() == FUSE_ROOT_ID {
            Ok(GlobalInode::ROOT)
        } else {
            Ok(GlobalInode(local.0))
        }
    }
}

#[derive(Clone, Copy)]
enum LayerId {
    Dynamic,
    Fixed,
}

struct MergedDirCursor {
    layer: LayerId,
    offset: DirOffset,
    emitted: HashSet<Name>,
}

impl MergedDirCursor {
    fn new(layer: LayerId) -> Self {
        Self {
            layer,
            offset: 2,
            emitted: HashSet::new(),
        }
    }

    const fn move_to(&mut self, layer: LayerId) {
        self.layer = layer;
        self.offset = 2;
    }
}

struct ParsedDirent {
    name: Name,
    ino: u64,
    off: DirOffset,
    typ: u32,
}

#[derive(Clone)]
struct MergedDirEntry {
    name: Name,
    ino: u64,
    typ: u32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct RootDirFh(NonZeroU64);

impl RootDirFh {
    fn from_raw(raw: u64) -> Result<Self, FuseError> {
        NonZeroU64::new(raw).map(Self).ok_or_else(FuseError::bad_fd)
    }

    const fn get(self) -> u64 {
        self.0.get()
    }
}

struct RootDirHandles {
    next_fh: NonZeroU64,
    open: HashMap<RootDirFh, Vec<MergedDirEntry>>,
}

impl Default for RootDirHandles {
    fn default() -> Self {
        Self {
            next_fh: NonZeroU64::MIN,
            open: HashMap::new(),
        }
    }
}

impl RootDirHandles {
    fn insert(&mut self, entries: Vec<MergedDirEntry>) -> RootDirFh {
        let fh = loop {
            let fh = RootDirFh(self.next_fh);
            self.next_fh =
                NonZeroU64::new(self.next_fh.get().wrapping_add(1)).unwrap_or(NonZeroU64::MIN);
            if !self.open.contains_key(&fh) {
                break fh;
            }
        };
        self.open.insert(fh, entries);
        fh
    }

    fn get(&self, fh: RootDirFh) -> Result<Vec<MergedDirEntry>, FuseError> {
        self.open.get(&fh).cloned().ok_or_else(FuseError::bad_fd)
    }

    fn remove(&mut self, fh: RootDirFh) {
        self.open.remove(&fh);
    }
}

/// Overlay filesystem composing one [`DynamicFsBackend`] and one [`FixedFsBackend`].
///
/// Implements only [`FsBackend`] (not Fixed or Dynamic), preventing nesting.
pub struct OverlayFsBackend<D, F> {
    dynamic: D,
    fixed: F,
    partition: InodePartition,
    /// UID/GID for the composite root directory.
    uid: u32,
    gid: u32,
    root_dirs: Mutex<RootDirHandles>,
}

impl<D: DynamicFsBackend, F: FixedFsBackend> OverlayFsBackend<D, F> {
    /// Create a new overlay.
    ///
    /// `dynamic` occupies the upper inode range, `fixed` the lower.
    pub fn new(dynamic: D, fixed: F) -> Result<Self, FuseError> {
        let partition = InodePartition::from_fixed_count(fixed.inode_count())?;
        Ok(Self {
            dynamic,
            fixed,
            partition,
            uid: 0,
            gid: 0,
            root_dirs: Mutex::new(RootDirHandles::default()),
        })
    }

    /// Set UID/GID for the composite root directory.
    #[must_use]
    pub const fn with_uid_gid(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    fn classify(&self, global: u64) -> Result<Owner, FuseError> {
        Ok(self.partition.classify(GlobalInode::from_guest(global)?))
    }

    fn dynamic_to_global(&self, local: u64) -> Result<u64, FuseError> {
        Ok(self
            .partition
            .dynamic_to_global(DynamicLocalInode::from_backend(local)?)?
            .get())
    }

    fn fixed_to_global(&self, local: u64) -> Result<u64, FuseError> {
        Ok(self
            .partition
            .fixed_to_global(FixedLocalInode::from_backend(local)?)?
            .get())
    }

    fn root_dirs(&self) -> Result<MutexGuard<'_, RootDirHandles>, FuseError> {
        self.root_dirs.lock().map_err(|_| FuseError::io())
    }

    fn dynamic_parent_local(&self, parent: u64) -> Result<u64, FuseError> {
        match self.classify(parent)? {
            Owner::CompositeRoot => Ok(FUSE_ROOT_ID),
            Owner::Dynamic(local) => Ok(local.get()),
            Owner::Fixed(_) => Err(FuseError::read_only()),
        }
    }

    fn dynamic_node_local(&self, nodeid: u64) -> Result<u64, FuseError> {
        match self.classify(nodeid)? {
            Owner::Dynamic(local) => Ok(local.get()),
            Owner::CompositeRoot | Owner::Fixed(_) => Err(FuseError::read_only()),
        }
    }

    fn dynamic_entry_to_global(&self, mut entry: FuseEntryOut) -> Result<FuseEntryOut, FuseError> {
        entry.nodeid = self.dynamic_to_global(entry.nodeid)?;
        entry.attr.ino = self.dynamic_to_global(entry.attr.ino)?;
        Ok(entry)
    }

    fn fixed_entry_to_global(&self, mut entry: FuseEntryOut) -> Result<FuseEntryOut, FuseError> {
        entry.nodeid = self.fixed_to_global(entry.nodeid)?;
        entry.attr.ino = self.fixed_to_global(entry.attr.ino)?;
        Ok(entry)
    }

    /// Rewrite inodes in a readdir buffer from dynamic-local to global space.
    fn rewrite_dynamic_readdir(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdir_inodes(buf, |ino| self.dynamic_to_global(ino))
    }

    /// Rewrite inodes in a readdirplus buffer from dynamic-local to global space.
    fn rewrite_dynamic_readdirplus(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdirplus_inodes(buf, |ino| self.dynamic_to_global(ino))
    }

    /// Rewrite inodes in a readdir buffer from fixed-local to global space.
    fn rewrite_fixed_readdir(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdir_inodes(buf, |ino| self.fixed_to_global(ino))
    }

    /// Rewrite inodes in a readdirplus buffer from fixed-local to global space.
    fn rewrite_fixed_readdirplus(&self, buf: &mut [u8]) -> Result<(), FuseError> {
        try_rewrite_readdirplus_inodes(buf, |ino| self.fixed_to_global(ino))
    }

    fn parse_readdir_entries(buf: &[u8]) -> Result<Vec<ParsedDirent>, FuseError> {
        let mut entries = Vec::new();
        let dirent_size = std::mem::size_of::<FuseDirent>();
        let mut pos = 0;
        while pos + dirent_size <= buf.len() {
            let dirent: &FuseDirent = bytemuck::from_bytes(&buf[pos..pos + dirent_size]);
            let namelen = dirent.namelen as usize;
            if namelen == 0 {
                return Err(FuseError::io());
            }

            let Some(name_start) = pos.checked_add(dirent_size) else {
                return Err(FuseError::io());
            };
            let Some(name_end) = name_start.checked_add(namelen) else {
                return Err(FuseError::io());
            };
            let Some(entry_size) = dirent_size
                .checked_add(namelen)
                .and_then(|size| size.checked_add(7))
                .map(|size| size & !7)
            else {
                return Err(FuseError::io());
            };
            let Some(entry_end) = pos.checked_add(entry_size) else {
                return Err(FuseError::io());
            };
            if name_end > buf.len() || entry_end > buf.len() {
                return Err(FuseError::io());
            }

            entries.push(ParsedDirent {
                name: buf[name_start..name_end].to_vec(),
                ino: dirent.ino,
                off: dirent.off,
                typ: dirent.typ,
            });
            pos = entry_end;
        }

        Ok(entries)
    }

    async fn collect_root_layer_entries(
        &self,
        cursor: &mut MergedDirCursor,
        fh: u64,
        entries: &mut Vec<MergedDirEntry>,
    ) -> Result<(), FuseError> {
        loop {
            let mut buf = match cursor.layer {
                LayerId::Dynamic => {
                    self.dynamic
                        .readdir(1, fh, cursor.offset, ROOT_READDIR_PAGE_SIZE)
                        .await?
                }
                LayerId::Fixed => {
                    self.fixed
                        .readdir(1, fh, cursor.offset, ROOT_READDIR_PAGE_SIZE)
                        .await?
                }
            };

            match cursor.layer {
                LayerId::Dynamic => self.rewrite_dynamic_readdir(&mut buf)?,
                LayerId::Fixed => self.rewrite_fixed_readdir(&mut buf)?,
            }

            let parsed = Self::parse_readdir_entries(&buf)?;
            if parsed.is_empty() {
                break;
            }

            let mut next_offset = cursor.offset;
            for dirent in parsed {
                next_offset = dirent.off;
                if dirent.name == b"." || dirent.name == b".." {
                    continue;
                }
                if cursor.emitted.insert(dirent.name.clone()) {
                    entries.push(MergedDirEntry {
                        name: dirent.name,
                        ino: dirent.ino,
                        typ: dirent.typ,
                    });
                }
            }

            if next_offset <= cursor.offset {
                return Err(FuseError::io());
            }
            cursor.offset = next_offset;
        }

        Ok(())
    }

    async fn collect_merged_root_entries(
        &self,
        dynamic_fh: u64,
        fixed_fh: u64,
    ) -> Result<Vec<MergedDirEntry>, FuseError> {
        let mut entries = Vec::new();
        let mut cursor = MergedDirCursor::new(LayerId::Dynamic);

        self.collect_root_layer_entries(&mut cursor, dynamic_fh, &mut entries)
            .await?;

        cursor.move_to(LayerId::Fixed);
        self.collect_root_layer_entries(&mut cursor, fixed_fh, &mut entries)
            .await?;

        Ok(entries)
    }

    async fn snapshot_merged_root_entries(&self) -> Result<Vec<MergedDirEntry>, FuseError> {
        let dynamic_fh = self.dynamic.opendir(1).await?.fh;
        let fixed_fh = match self.fixed.opendir(1).await {
            Ok(open) => open.fh,
            Err(error) => {
                self.dynamic.releasedir(1, dynamic_fh).await;
                return Err(error);
            }
        };

        let result = self.collect_merged_root_entries(dynamic_fh, fixed_fh).await;
        self.fixed.releasedir(1, fixed_fh).await;
        self.dynamic.releasedir(1, dynamic_fh).await;
        result
    }

    fn insert_root_dir(&self, entries: Vec<MergedDirEntry>) -> Result<RootDirFh, FuseError> {
        Ok(self.root_dirs()?.insert(entries))
    }

    fn root_entries_for_fh(&self, fh: u64) -> Result<Vec<MergedDirEntry>, FuseError> {
        self.root_dirs()?.get(RootDirFh::from_raw(fh)?)
    }

    fn remove_root_dir(&self, fh: u64) -> Result<(), FuseError> {
        self.root_dirs()?.remove(RootDirFh::from_raw(fh)?);
        Ok(())
    }

    fn pack_merged_root_readdir(entries: &[MergedDirEntry], offset: u64, size: u32) -> Vec<u8> {
        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        if index >= offset && pack_dirent(&mut buf, max_size, 1, b".", index + 1, DT_DIR) == 0 {
            return buf;
        }
        index += 1;

        if index >= offset && pack_dirent(&mut buf, max_size, 1, b"..", index + 1, DT_DIR) == 0 {
            return buf;
        }
        index += 1;

        for entry in entries {
            if index >= offset
                && pack_dirent(
                    &mut buf,
                    max_size,
                    entry.ino,
                    &entry.name,
                    index + 1,
                    entry.typ,
                ) == 0
            {
                break;
            }
            index += 1;
        }

        buf
    }

    async fn pack_merged_root_readdirplus(
        &self,
        entries: &[MergedDirEntry],
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let max_size = size as usize;
        let mut result = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        let root = FuseEntryOut::new(1, self.composite_root_attr());
        if index >= offset
            && pack_direntplus(&mut result, max_size, &root, b".", index + 1, DT_DIR) == 0
        {
            return Ok(result);
        }
        index += 1;

        if index >= offset
            && pack_direntplus(&mut result, max_size, &root, b"..", index + 1, DT_DIR) == 0
        {
            return Ok(result);
        }
        index += 1;

        let mut live_entries = Vec::with_capacity(entries.len());
        for merged in entries {
            match self.lookup(1, &merged.name).await {
                Ok(entry) => live_entries.push((merged.name.as_slice(), entry)),
                Err(e) if e == FuseError::not_found() => {}
                Err(e) => return Err(e),
            }
        }

        for (name, entry) in live_entries {
            if index >= offset
                && pack_direntplus(
                    &mut result,
                    max_size,
                    &entry,
                    name,
                    index + 1,
                    mode_to_dtype(entry.attr.mode),
                ) == 0
            {
                break;
            }
            index += 1;
        }

        Ok(result)
    }

    /// Attributes for the synthetic composite root directory.
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
}

impl<D: DynamicFsBackend, F: FixedFsBackend> FsBackend for OverlayFsBackend<D, F> {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        // Initialize both backends; return dynamic's init (primary).
        let _ = self.fixed.init().await?;
        self.dynamic.init().await
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        match self.classify(parent)? {
            Owner::CompositeRoot => {
                // The dynamic layer is the writable upper layer. It wins root
                // name collisions; fixed lower-layer entries are fallback only.
                match self.dynamic.lookup(FUSE_ROOT_ID, name).await {
                    Ok(entry) => self.dynamic_entry_to_global(entry),
                    Err(e) if e == FuseError::not_found() => {
                        let entry = self.fixed.lookup(FUSE_ROOT_ID, name).await?;
                        self.fixed_entry_to_global(entry)
                    }
                    Err(e) => Err(e),
                }
            }
            Owner::Fixed(local) => {
                let entry = self.fixed.lookup(local.get(), name).await?;
                self.fixed_entry_to_global(entry)
            }
            Owner::Dynamic(local) => {
                let entry = self.dynamic.lookup(local.get(), name).await?;
                self.dynamic_entry_to_global(entry)
            }
        }
    }

    async fn forget(&self, nodeid: u64, nlookup: u64) {
        match self.classify(nodeid).ok() {
            Some(Owner::CompositeRoot) | None => {} // no-op
            Some(Owner::Fixed(local)) => self.fixed.forget(local.get(), nlookup).await,
            Some(Owner::Dynamic(local)) => self.dynamic.forget(local.get(), nlookup).await,
        }
    }

    async fn batch_forget(&self, forgets: &[(u64, u64)]) {
        let mut fixed_forgets = Vec::new();
        let mut dynamic_forgets = Vec::new();
        for &(nodeid, nlookup) in forgets {
            match self.classify(nodeid).ok() {
                Some(Owner::CompositeRoot) | None => {}
                Some(Owner::Fixed(local)) => fixed_forgets.push((local.get(), nlookup)),
                Some(Owner::Dynamic(local)) => dynamic_forgets.push((local.get(), nlookup)),
            }
        }
        if !fixed_forgets.is_empty() {
            self.fixed.batch_forget(&fixed_forgets).await;
        }
        if !dynamic_forgets.is_empty() {
            self.dynamic.batch_forget(&dynamic_forgets).await;
        }
    }

    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Ok(FuseAttrOut {
                attr_valid: ATTR_VALID_SECS,
                attr_valid_nsec: 0,
                dummy: 0,
                attr: self.composite_root_attr(),
            }),
            Owner::Fixed(local) => {
                let mut result = self.fixed.getattr(local.get()).await?;
                result.attr.ino = self.fixed_to_global(result.attr.ino)?;
                Ok(result)
            }
            Owner::Dynamic(local) => {
                let mut result = self.dynamic.getattr(local.get()).await?;
                result.attr.ino = self.dynamic_to_global(result.attr.ino)?;
                Ok(result)
            }
        }
    }

    async fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Err(FuseError::invalid()),
            Owner::Fixed(local) => self.fixed.readlink(local.get()).await,
            Owner::Dynamic(local) => self.dynamic.readlink(local.get()).await,
        }
    }

    async fn open(&self, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Err(FuseError::is_dir()),
            Owner::Fixed(local) => self.fixed.open(local.get(), flags).await,
            Owner::Dynamic(local) => self.dynamic.open(local.get(), flags).await,
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
            Owner::CompositeRoot => Err(FuseError::is_dir()),
            Owner::Fixed(local) => self.fixed.read(local.get(), fh, offset, size).await,
            Owner::Dynamic(local) => self.dynamic.read(local.get(), fh, offset, size).await,
        }
    }

    async fn release(&self, nodeid: u64, fh: u64) {
        match self.classify(nodeid).ok() {
            Some(Owner::CompositeRoot) | None => {}
            Some(Owner::Fixed(local)) => self.fixed.release(local.get(), fh).await,
            Some(Owner::Dynamic(local)) => self.dynamic.release(local.get(), fh).await,
        }
    }

    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => {
                let entries = self.snapshot_merged_root_entries().await?;
                let fh = self.insert_root_dir(entries)?;
                Ok(FuseOpenOut {
                    fh: fh.get(),
                    open_flags: 0,
                    padding: 0,
                })
            }
            Owner::Fixed(local) => self.fixed.opendir(local.get()).await,
            Owner::Dynamic(local) => self.dynamic.opendir(local.get()).await,
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn readdir(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => {
                let entries = self.root_entries_for_fh(fh)?;
                Ok(Self::pack_merged_root_readdir(&entries, offset, size))
            }
            Owner::Fixed(local) => {
                let mut buf = self.fixed.readdir(local.get(), fh, offset, size).await?;
                self.rewrite_fixed_readdir(&mut buf)?;
                Ok(buf)
            }
            Owner::Dynamic(local) => {
                let mut buf = self.dynamic.readdir(local.get(), fh, offset, size).await?;
                self.rewrite_dynamic_readdir(&mut buf)?;
                Ok(buf)
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn readdirplus(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => {
                let entries = self.root_entries_for_fh(fh)?;
                self.pack_merged_root_readdirplus(&entries, offset, size)
                    .await
            }
            Owner::Fixed(local) => {
                let mut buf = self
                    .fixed
                    .readdirplus(local.get(), fh, offset, size)
                    .await?;
                self.rewrite_fixed_readdirplus(&mut buf)?;
                Ok(buf)
            }
            Owner::Dynamic(local) => {
                let mut buf = self
                    .dynamic
                    .readdirplus(local.get(), fh, offset, size)
                    .await?;
                self.rewrite_dynamic_readdirplus(&mut buf)?;
                Ok(buf)
            }
        }
    }

    async fn releasedir(&self, nodeid: u64, fh: u64) {
        match self.classify(nodeid).ok() {
            Some(Owner::CompositeRoot) => {
                let _ignored = self.remove_root_dir(fh);
            }
            Some(Owner::Fixed(local)) => self.fixed.releasedir(local.get(), fh).await,
            Some(Owner::Dynamic(local)) => self.dynamic.releasedir(local.get(), fh).await,
            None => {}
        }
    }

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        // Merge statfs from both.
        let fixed_st = self.fixed.statfs().await?;
        let dynamic_st = self.dynamic.statfs().await?;
        Ok(FuseStatfsOut {
            st: FuseKstatfs {
                blocks: fixed_st.st.blocks.saturating_add(dynamic_st.st.blocks),
                bfree: fixed_st.st.bfree.saturating_add(dynamic_st.st.bfree),
                bavail: fixed_st.st.bavail.saturating_add(dynamic_st.st.bavail),
                files: fixed_st.st.files.saturating_add(dynamic_st.st.files),
                ffree: fixed_st.st.ffree.saturating_add(dynamic_st.st.ffree),
                bsize: dynamic_st.st.bsize,
                namelen: dynamic_st.st.namelen,
                frsize: dynamic_st.st.frsize,
                padding: 0,
                spare: [0; 6],
            },
        })
    }

    async fn access(&self, nodeid: u64, mask: u32) -> Result<(), FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Ok(()),
            Owner::Fixed(local) => self.fixed.access(local.get(), mask).await,
            Owner::Dynamic(local) => self.dynamic.access(local.get(), mask).await,
        }
    }

    async fn getxattr(&self, nodeid: u64, name: &[u8], size: u32) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Err(FuseError::not_supported()),
            Owner::Fixed(local) => self.fixed.getxattr(local.get(), name, size).await,
            Owner::Dynamic(local) => self.dynamic.getxattr(local.get(), name, size).await,
        }
    }

    async fn listxattr(&self, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Err(FuseError::not_supported()),
            Owner::Fixed(local) => self.fixed.listxattr(local.get(), size).await,
            Owner::Dynamic(local) => self.dynamic.listxattr(local.get(), size).await,
        }
    }

    // Write operations — route to the correct backend.
    async fn write(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        write_flags: u32,
    ) -> Result<u32, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot | Owner::Fixed(_) => Err(FuseError::read_only()),
            Owner::Dynamic(local) => {
                self.dynamic
                    .write(local.get(), fh, offset, data, write_flags)
                    .await
            }
        }
    }

    async fn create(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let (entry, open) = self
            .dynamic
            .create(local_parent, name, mode, flags, ctx)
            .await?;
        Ok((self.dynamic_entry_to_global(entry)?, open))
    }

    async fn mkdir(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let entry = self.dynamic.mkdir(local_parent, name, mode, ctx).await?;
        self.dynamic_entry_to_global(entry)
    }

    async fn unlink(&self, parent: u64, name: &[u8]) -> Result<(), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        self.dynamic.unlink(local_parent, name).await
    }

    async fn rmdir(&self, parent: u64, name: &[u8]) -> Result<(), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        self.dynamic.rmdir(local_parent, name).await
    }

    async fn setattr(
        &self,
        nodeid: u64,
        args: &amla_fuse::fuse::FuseSetattrIn,
    ) -> Result<FuseAttrOut, FuseError> {
        match self.classify(nodeid)? {
            Owner::Fixed(_) => Err(FuseError::read_only()),
            Owner::CompositeRoot => {
                let mut result = self.dynamic.setattr(FUSE_ROOT_ID, args).await?;
                result.attr.ino = self.dynamic_to_global(result.attr.ino)?;
                Ok(result)
            }
            Owner::Dynamic(local) => {
                let mut result = self.dynamic.setattr(local.get(), args).await?;
                result.attr.ino = self.dynamic_to_global(result.attr.ino)?;
                Ok(result)
            }
        }
    }

    async fn rename(
        &self,
        parent: u64,
        name: &[u8],
        newparent: u64,
        newname: &[u8],
    ) -> Result<(), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let local_newparent = self.dynamic_parent_local(newparent)?;
        self.dynamic
            .rename(local_parent, name, local_newparent, newname)
            .await
    }

    async fn rename_whiteout(
        &self,
        parent: u64,
        name: &[u8],
        newparent: u64,
        newname: &[u8],
    ) -> Result<(), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let local_newparent = self.dynamic_parent_local(newparent)?;
        self.dynamic
            .rename_whiteout(local_parent, name, local_newparent, newname)
            .await
    }

    async fn mknod(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let entry = self
            .dynamic
            .mknod(local_parent, name, mode, rdev, ctx)
            .await?;
        self.dynamic_entry_to_global(entry)
    }

    async fn symlink(
        &self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let entry = self
            .dynamic
            .symlink(local_parent, name, target, ctx)
            .await?;
        self.dynamic_entry_to_global(entry)
    }

    async fn link(
        &self,
        nodeid: u64,
        newparent: u64,
        newname: &[u8],
    ) -> Result<FuseEntryOut, FuseError> {
        let local_node = self.dynamic_node_local(nodeid)?;
        let local_parent = self.dynamic_parent_local(newparent)?;
        let entry = self.dynamic.link(local_node, local_parent, newname).await?;
        self.dynamic_entry_to_global(entry)
    }

    async fn setxattr(
        &self,
        nodeid: u64,
        name: &[u8],
        value: &[u8],
        flags: u32,
    ) -> Result<(), FuseError> {
        match self.classify(nodeid)? {
            Owner::Dynamic(local) => self.dynamic.setxattr(local.get(), name, value, flags).await,
            _ => Err(FuseError::read_only()),
        }
    }

    async fn removexattr(&self, nodeid: u64, name: &[u8]) -> Result<(), FuseError> {
        match self.classify(nodeid)? {
            Owner::Dynamic(local) => self.dynamic.removexattr(local.get(), name).await,
            _ => Err(FuseError::read_only()),
        }
    }

    async fn tmpfile(
        &self,
        parent: u64,
        mode: u32,
        flags: u32,
        ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        let local_parent = self.dynamic_parent_local(parent)?;
        let (entry, open) = self.dynamic.tmpfile(local_parent, mode, flags, ctx).await?;
        Ok((self.dynamic_entry_to_global(entry)?, open))
    }

    async fn fsync(&self, nodeid: u64, fh: u64, datasync: bool) -> Result<(), FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => Ok(()),
            Owner::Fixed(local) => self.fixed.fsync(local.get(), fh, datasync).await,
            Owner::Dynamic(local) => self.dynamic.fsync(local.get(), fh, datasync).await,
        }
    }

    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        match self.classify(nodeid)? {
            Owner::CompositeRoot => {
                // Root's parent is itself.
                Ok(FuseEntryOut::new(FUSE_ROOT_ID, self.composite_root_attr()))
            }
            Owner::Fixed(local) => {
                let entry = self.fixed.get_parent(local.get()).await?;
                self.fixed_entry_to_global(entry)
            }
            Owner::Dynamic(local) => {
                let entry = self.dynamic.get_parent(local.get()).await?;
                self.dynamic_entry_to_global(entry)
            }
        }
    }

    fn max_write(&self) -> u32 {
        self.dynamic.max_write()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::MountedFsBackend;
    use amla_fuse::fs_types::{DT_REG, S_IFREG};
    use amla_synthesized_fs::SynthesizedFs;
    use std::sync::{Arc, Mutex};

    const ROOT_CTX: FuseContext = FuseContext { uid: 0, gid: 0 };

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum RecordedOp {
        Create(u64),
        Mkdir(u64),
        Unlink(u64),
        Rmdir(u64),
        Rename(u64, u64),
        RenameWhiteout(u64, u64),
        Mknod(u64),
        Symlink(u64),
        Link { nodeid: u64, parent: u64 },
        Tmpfile(u64),
    }

    /// Minimal dynamic backend for testing — wraps a `SynthesizedFs`.
    struct FakeDynamic {
        inner: SynthesizedFs<'static>,
        recorded_ops: Option<Arc<Mutex<Vec<RecordedOp>>>>,
        overflow_lookup: bool,
        overflow_readdir: bool,
    }

    impl FakeDynamic {
        fn new() -> Self {
            Self {
                inner: SynthesizedFs::builder()
                    .file("README.md", b"# Hello\n", 0o644)
                    .unwrap()
                    .file("src/main.rs", b"fn main() {}\n", 0o644)
                    .unwrap()
                    .build(),
                recorded_ops: None,
                overflow_lookup: false,
                overflow_readdir: false,
            }
        }

        fn from_files(files: &[(String, &'static [u8])]) -> Self {
            Self {
                inner: synthesized_from_root_files(files),
                recorded_ops: None,
                overflow_lookup: false,
                overflow_readdir: false,
            }
        }

        fn overflowing_lookup() -> Self {
            Self {
                overflow_lookup: true,
                ..Self::new()
            }
        }

        fn overflowing_readdir() -> Self {
            Self {
                overflow_readdir: true,
                ..Self::new()
            }
        }

        fn recording() -> (Self, Arc<Mutex<Vec<RecordedOp>>>) {
            let recorded_ops = Arc::new(Mutex::new(Vec::new()));
            (
                Self {
                    inner: SynthesizedFs::builder()
                        .file("README.md", b"# Hello\n", 0o644)
                        .unwrap()
                        .build(),
                    recorded_ops: Some(Arc::clone(&recorded_ops)),
                    overflow_lookup: false,
                    overflow_readdir: false,
                },
                recorded_ops,
            )
        }

        fn record(&self, op: RecordedOp) -> Result<(), FuseError> {
            let Some(recorded_ops) = &self.recorded_ops else {
                return Err(FuseError::read_only());
            };
            recorded_ops.lock().unwrap().push(op);
            Ok(())
        }

        fn synthetic_entry(local_nodeid: u64, mode: u32) -> FuseEntryOut {
            FuseEntryOut::new(
                local_nodeid,
                FuseAttr {
                    ino: local_nodeid,
                    mode,
                    nlink: 1,
                    blksize: 512,
                    ..FuseAttr::default()
                },
            )
        }
    }

    impl DynamicFsBackend for FakeDynamic {}

    impl FsBackend for FakeDynamic {
        async fn init(&self) -> Result<FuseInitOut, FuseError> {
            self.inner.init().await
        }
        async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
            if self.overflow_lookup && parent == FUSE_ROOT_ID && name == b"overflow" {
                return Ok(Self::synthetic_entry(u64::MAX, S_IFREG | 0o644));
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
            if self.overflow_readdir && nodeid == FUSE_ROOT_ID {
                let mut buf = Vec::with_capacity(size as usize);
                let _written =
                    pack_dirent(&mut buf, size as usize, u64::MAX, b"overflow", 3, DT_REG);
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
        async fn create(
            &self,
            parent: u64,
            _name: &[u8],
            _mode: u32,
            _flags: u32,
            _ctx: FuseContext,
        ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
            self.record(RecordedOp::Create(parent))?;
            Ok((
                Self::synthetic_entry(10, S_IFREG | 0o644),
                FuseOpenOut::default(),
            ))
        }
        async fn mkdir(
            &self,
            parent: u64,
            _name: &[u8],
            _mode: u32,
            _ctx: FuseContext,
        ) -> Result<FuseEntryOut, FuseError> {
            self.record(RecordedOp::Mkdir(parent))?;
            Ok(Self::synthetic_entry(11, S_IFDIR | 0o755))
        }
        async fn mknod(
            &self,
            parent: u64,
            _name: &[u8],
            _mode: u32,
            _rdev: u32,
            _ctx: FuseContext,
        ) -> Result<FuseEntryOut, FuseError> {
            self.record(RecordedOp::Mknod(parent))?;
            Ok(Self::synthetic_entry(12, S_IFREG | 0o644))
        }
        async fn unlink(&self, parent: u64, _name: &[u8]) -> Result<(), FuseError> {
            self.record(RecordedOp::Unlink(parent))
        }
        async fn rmdir(&self, parent: u64, _name: &[u8]) -> Result<(), FuseError> {
            self.record(RecordedOp::Rmdir(parent))
        }
        async fn rename(
            &self,
            parent: u64,
            _name: &[u8],
            newparent: u64,
            _newname: &[u8],
        ) -> Result<(), FuseError> {
            self.record(RecordedOp::Rename(parent, newparent))
        }
        async fn rename_whiteout(
            &self,
            parent: u64,
            _name: &[u8],
            newparent: u64,
            _newname: &[u8],
        ) -> Result<(), FuseError> {
            self.record(RecordedOp::RenameWhiteout(parent, newparent))
        }
        async fn symlink(
            &self,
            parent: u64,
            _name: &[u8],
            _target: &[u8],
            _ctx: FuseContext,
        ) -> Result<FuseEntryOut, FuseError> {
            self.record(RecordedOp::Symlink(parent))?;
            Ok(Self::synthetic_entry(13, S_IFREG | 0o777))
        }
        async fn link(
            &self,
            nodeid: u64,
            newparent: u64,
            _newname: &[u8],
        ) -> Result<FuseEntryOut, FuseError> {
            self.record(RecordedOp::Link {
                nodeid,
                parent: newparent,
            })?;
            Ok(Self::synthetic_entry(nodeid, S_IFREG | 0o644))
        }
        async fn tmpfile(
            &self,
            parent: u64,
            _mode: u32,
            _flags: u32,
            _ctx: FuseContext,
        ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
            self.record(RecordedOp::Tmpfile(parent))?;
            Ok((
                Self::synthetic_entry(14, S_IFREG | 0o600),
                FuseOpenOut::default(),
            ))
        }
    }

    fn synthesized_from_root_files(files: &[(String, &'static [u8])]) -> SynthesizedFs<'static> {
        let mut builder = SynthesizedFs::builder();
        for (name, content) in files {
            builder = builder.file(name, content, 0o644).unwrap();
        }
        builder.build()
    }

    fn make_fixed() -> MountedFsBackend<SynthesizedFs<'static>> {
        let synth = SynthesizedFs::builder()
            .file("HEAD", b"abc123\n", 0o444)
            .unwrap()
            .file("config", b"[core]\n", 0o444)
            .unwrap()
            .build();
        MountedFsBackend::new(synth, ".git", 0o755).unwrap()
    }

    fn make_colliding_fixed() -> MountedFsBackend<SynthesizedFs<'static>> {
        let synth = SynthesizedFs::builder()
            .file("shadow", b"fixed\n", 0o444)
            .unwrap()
            .build();
        MountedFsBackend::new(synth, "README.md", 0o755).unwrap()
    }

    struct FixedCountOnly(u64);

    impl FixedFsBackend for FixedCountOnly {
        fn inode_count(&self) -> u64 {
            self.0
        }
    }

    impl FsBackend for FixedCountOnly {
        async fn init(&self) -> Result<FuseInitOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn lookup(&self, _parent: u64, _name: &[u8]) -> Result<FuseEntryOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn forget(&self, _nodeid: u64, _nlookup: u64) {}

        async fn batch_forget(&self, _forgets: &[(u64, u64)]) {}

        async fn getattr(&self, _nodeid: u64) -> Result<FuseAttrOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn open(&self, _nodeid: u64, _flags: u32) -> Result<FuseOpenOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn read(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn release(&self, _nodeid: u64, _fh: u64) {}

        async fn opendir(&self, _nodeid: u64) -> Result<FuseOpenOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readdir(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readdirplus(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn releasedir(&self, _nodeid: u64, _fh: u64) {}

        async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn access(&self, _nodeid: u64, _mask: u32) -> Result<(), FuseError> {
            Err(FuseError::no_sys())
        }

        async fn getxattr(
            &self,
            _nodeid: u64,
            _name: &[u8],
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn listxattr(&self, _nodeid: u64, _size: u32) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn get_parent(&self, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
            Err(FuseError::no_sys())
        }
    }

    #[test]
    fn overlay_rejects_invalid_fixed_inode_counts() {
        assert_eq!(
            OverlayFsBackend::new(FakeDynamic::new(), FixedCountOnly(0)).err(),
            Some(FuseError::invalid())
        );
        assert_eq!(
            OverlayFsBackend::new(FakeDynamic::new(), FixedCountOnly(u64::MAX)).err(),
            Some(FuseError::range())
        );
    }

    #[test]
    fn inode_partition_maps_boundaries() {
        let one_fixed = InodePartition::from_fixed_count(1).unwrap();
        assert_eq!(
            one_fixed
                .dynamic_to_global(DynamicLocalInode::from_backend(2).unwrap())
                .unwrap()
                .get(),
            2
        );
        assert!(matches!(
            one_fixed.classify(GlobalInode::from_guest(2).unwrap()),
            Owner::Dynamic(local) if local.get() == 2
        ));

        let normal = InodePartition::from_fixed_count(4).unwrap();
        assert!(matches!(
            normal.classify(GlobalInode::from_guest(4).unwrap()),
            Owner::Fixed(local) if local.get() == 4
        ));
        assert!(matches!(
            normal.classify(GlobalInode::from_guest(5).unwrap()),
            Owner::Dynamic(local) if local.get() == 2
        ));
    }

    #[tokio::test]
    async fn overlay_lookup_fixed() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Composite root → ".git" (from fixed)
        let git = overlay.lookup(1, b".git").await.unwrap();
        assert!(git.nodeid > 0);

        // ".git" → "HEAD" (from fixed's inner)
        let head = overlay.lookup(git.nodeid, b"HEAD").await.unwrap();
        let data = overlay.read(head.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"abc123\n");
    }

    #[tokio::test]
    async fn overlay_lookup_dynamic() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Composite root → "README.md" (from dynamic)
        let readme = overlay.lookup(1, b"README.md").await.unwrap();
        let data = overlay.read(readme.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"# Hello\n");
    }

    #[tokio::test]
    async fn overlay_root_lookup_dynamic_shadows_fixed_collision() {
        let dynamic = FakeDynamic::new();
        let fixed = make_colliding_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let readme = overlay.lookup(1, b"README.md").await.unwrap();
        let data = overlay.read(readme.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"# Hello\n");
    }

    #[tokio::test]
    async fn overlay_root_readdir_dynamic_shadows_fixed_collision() {
        let dynamic = FakeDynamic::new();
        let fixed = make_colliding_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let buf = root_readdir(&overlay, 0, 8192).await.unwrap();
        let names = parse_dirent_names(&buf);
        let readme_count = names
            .iter()
            .filter(|n| n.as_slice() == b"README.md")
            .count();
        assert_eq!(readme_count, 1);
    }

    #[tokio::test]
    async fn overlay_readdir_root() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let buf = root_readdir(&overlay, 0, 8192).await.unwrap();
        let names = parse_dirent_names(&buf);
        // Should contain entries from both backends.
        assert!(names.contains(&b"."[..].to_vec()));
        assert!(names.contains(&b".."[..].to_vec()));
        assert!(names.contains(&b".git"[..].to_vec())); // from fixed
        assert!(names.contains(&b"README.md"[..].to_vec())); // from dynamic
        assert!(names.contains(&b"src"[..].to_vec())); // from dynamic
    }

    #[tokio::test]
    async fn overlay_root_readdir_requires_open_root_handle() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let err = overlay.readdir(1, 0, 0, 8192).await.unwrap_err();
        assert_eq!(err, FuseError::bad_fd());
    }

    #[tokio::test]
    async fn overlay_rejects_zero_guest_inode() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        assert_eq!(overlay.getattr(0).await.unwrap_err(), FuseError::invalid());
        assert_eq!(
            overlay.read(0, 0, 0, 1024).await.unwrap_err(),
            FuseError::invalid()
        );
        assert_eq!(
            overlay.readdir(0, 0, 0, 1024).await.unwrap_err(),
            FuseError::invalid()
        );

        overlay.forget(0, 1).await;
        overlay.batch_forget(&[(0, 1)]).await;
        overlay.release(0, 0).await;
        overlay.releasedir(0, 0).await;
    }

    #[tokio::test]
    async fn overlay_rejects_overflowing_dynamic_lookup_inode() {
        let dynamic = FakeDynamic::overflowing_lookup();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        assert_eq!(
            overlay.lookup(1, b"overflow").await.unwrap_err(),
            FuseError::range()
        );
    }

    #[tokio::test]
    async fn overlay_rejects_overflowing_dynamic_readdir_inode() {
        let dynamic = FakeDynamic::overflowing_readdir();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        assert_eq!(overlay.opendir(1).await.unwrap_err(), FuseError::range());
    }

    #[tokio::test]
    async fn overlay_getattr_composite_root() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let attr = overlay.getattr(1).await.unwrap();
        assert_eq!(attr.attr.ino, 1);
        assert_eq!(attr.attr.mode & S_IFDIR, S_IFDIR);
    }

    #[tokio::test]
    async fn overlay_nested_dynamic() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Navigate: root → src → main.rs
        let src = overlay.lookup(1, b"src").await.unwrap();
        let main = overlay.lookup(src.nodeid, b"main.rs").await.unwrap();
        let data = overlay.read(main.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"fn main() {}\n");
    }

    #[tokio::test]
    async fn overlay_write_returns_erofs_for_fixed() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let head = overlay.lookup(1, b".git").await.unwrap();
        let head_file = overlay.lookup(head.nodeid, b"HEAD").await.unwrap();
        let result = overlay.write(head_file.nodeid, 0, 0, b"x", 0).await;
        assert!(result.is_err());
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

    /// Parse (ino, name) pairs from a readdir buffer for inode verification.
    fn parse_dirent_entries(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let dirent_size = std::mem::size_of::<FuseDirent>();
        while pos + dirent_size <= data.len() {
            let dirent: &FuseDirent = bytemuck::from_bytes(&data[pos..pos + dirent_size]);
            let name_start = pos + dirent_size;
            let name_end = name_start + dirent.namelen as usize;
            if name_end > data.len() {
                break;
            }
            entries.push((dirent.ino, data[name_start..name_end].to_vec()));
            let entry_size = (dirent_size + dirent.namelen as usize + 7) & !7;
            pos += entry_size;
        }
        entries
    }

    /// Parse (ino, off, name) triples from a readdir buffer.
    fn parse_dirent_entries_with_offsets(data: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
        let mut entries = Vec::new();
        let mut pos = 0;
        let dirent_size = std::mem::size_of::<FuseDirent>();
        while pos + dirent_size <= data.len() {
            let dirent: &FuseDirent = bytemuck::from_bytes(&data[pos..pos + dirent_size]);
            let name_start = pos + dirent_size;
            let name_end = name_start + dirent.namelen as usize;
            if name_end > data.len() {
                break;
            }
            entries.push((dirent.ino, dirent.off, data[name_start..name_end].to_vec()));
            let entry_size = (dirent_size + dirent.namelen as usize + 7) & !7;
            pos += entry_size;
        }
        entries
    }

    async fn root_readdir<D, F>(
        overlay: &OverlayFsBackend<D, F>,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>
    where
        D: DynamicFsBackend,
        F: FixedFsBackend,
    {
        let open = overlay.opendir(1).await?;
        let result = overlay.readdir(1, open.fh, offset, size).await;
        overlay.releasedir(1, open.fh).await;
        result
    }

    async fn root_readdirplus<D, F>(
        overlay: &OverlayFsBackend<D, F>,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>
    where
        D: DynamicFsBackend,
        F: FixedFsBackend,
    {
        let open = overlay.opendir(1).await?;
        let result = overlay.readdirplus(1, open.fh, offset, size).await;
        overlay.releasedir(1, open.fh).await;
        result
    }

    /// Parse (nodeid, ino, name) from a readdirplus buffer.
    fn parse_readdirplus_entries(data: &[u8]) -> Vec<(u64, u64, Vec<u8>)> {
        let mut entries = Vec::new();
        let entry_out_size = std::mem::size_of::<FuseEntryOut>();
        let dirent_size = std::mem::size_of::<FuseDirent>();
        let mut pos = 0;
        while pos + entry_out_size + dirent_size <= data.len() {
            let entry_out: &FuseEntryOut = bytemuck::from_bytes(&data[pos..pos + entry_out_size]);
            let dp = pos + entry_out_size;
            let dirent: &FuseDirent = bytemuck::from_bytes(&data[dp..dp + dirent_size]);
            let nl = dirent.namelen as usize;
            let name_start = dp + dirent_size;
            if name_start + nl <= data.len() {
                entries.push((
                    entry_out.nodeid,
                    dirent.ino,
                    data[name_start..name_start + nl].to_vec(),
                ));
            }
            let es = (entry_out_size + dirent_size + nl + 7) & !7;
            pos += es;
        }
        entries
    }

    async fn drain_root_readdir_pages<D, F>(
        overlay: &OverlayFsBackend<D, F>,
        size: u32,
    ) -> Vec<(u64, u64, Vec<u8>)>
    where
        D: DynamicFsBackend,
        F: FixedFsBackend,
    {
        let mut offset = 0;
        let mut entries = Vec::new();
        let mut iterations = 0;
        let open = overlay.opendir(1).await.unwrap();
        loop {
            assert!(iterations < 128);
            iterations += 1;

            let buf = overlay.readdir(1, open.fh, offset, size).await.unwrap();
            if buf.is_empty() {
                break;
            }

            let page = parse_dirent_entries_with_offsets(&buf);
            assert!(!page.is_empty());
            let next_offset = page.last().unwrap().1;
            assert!(next_offset > offset);
            offset = next_offset;
            entries.extend(page);
        }
        overlay.releasedir(1, open.fh).await;
        entries
    }

    // ─── Readdirplus tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn overlay_readdirplus_root_contains_both_backends() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let buf = root_readdirplus(&overlay, 0, 16384).await.unwrap();
        let entries = parse_readdirplus_entries(&buf);
        let names: Vec<&[u8]> = entries.iter().map(|(_, _, n)| n.as_slice()).collect();

        assert!(names.contains(&&b"."[..]));
        assert!(names.contains(&&b".."[..]));
        assert!(names.contains(&&b".git"[..])); // from fixed
        assert!(names.contains(&&b"README.md"[..])); // from dynamic
        assert!(names.contains(&&b"src"[..])); // from dynamic
    }

    #[tokio::test]
    async fn overlay_readdirplus_inodes_match_lookup() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let buf = root_readdirplus(&overlay, 0, 16384).await.unwrap();
        let entries = parse_readdirplus_entries(&buf);

        // For each real entry (not . or ..), verify inode matches lookup.
        for (nodeid, ino, name) in &entries {
            if name == b"." || name == b".." {
                assert_eq!(*nodeid, 1);
                assert_eq!(*ino, 1);
                continue;
            }
            let entry = overlay.lookup(1, name).await.unwrap();
            assert_eq!(
                *nodeid,
                entry.nodeid,
                "readdirplus nodeid mismatch for {:?}",
                String::from_utf8_lossy(name)
            );
            assert_eq!(
                *ino,
                entry.nodeid,
                "readdirplus dirent.ino mismatch for {:?}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[tokio::test]
    async fn overlay_readdirplus_fixed_subdir() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Navigate to .git and readdirplus there.
        let git = overlay.lookup(1, b".git").await.unwrap();
        let buf = overlay.readdirplus(git.nodeid, 0, 0, 16384).await.unwrap();
        let entries = parse_readdirplus_entries(&buf);
        let names: Vec<&[u8]> = entries.iter().map(|(_, _, n)| n.as_slice()).collect();
        assert!(names.contains(&&b"HEAD"[..]));
        assert!(names.contains(&&b"config"[..]));
    }

    #[tokio::test]
    async fn overlay_readdirplus_dynamic_subdir() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let src = overlay.lookup(1, b"src").await.unwrap();
        let buf = overlay.readdirplus(src.nodeid, 0, 0, 16384).await.unwrap();
        let entries = parse_readdirplus_entries(&buf);
        assert!(entries.iter().any(|(_, _, n)| n.as_slice() == b"main.rs"));
    }

    // ─── Inode consistency tests ────────────────────────────────────────

    #[tokio::test]
    async fn overlay_readdir_inodes_match_lookup() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let buf = root_readdir(&overlay, 0, 8192).await.unwrap();
        let entries = parse_dirent_entries(&buf);

        for (ino, name) in &entries {
            if name == b"." || name == b".." {
                assert_eq!(*ino, 1);
                continue;
            }
            let entry = overlay.lookup(1, name).await.unwrap();
            assert_eq!(
                *ino,
                entry.nodeid,
                "readdir ino mismatch for {:?}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[tokio::test]
    async fn overlay_getattr_inodes_consistent() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Every lookup inode's getattr should return the same inode.
        for name in &[b"README.md" as &[u8], b"src", b".git"] {
            let entry = overlay.lookup(1, name).await.unwrap();
            let attr = overlay.getattr(entry.nodeid).await.unwrap();
            assert_eq!(
                attr.attr.ino,
                entry.nodeid,
                "getattr ino mismatch for {:?}",
                String::from_utf8_lossy(name)
            );
        }
    }

    // ─── Statfs test ────────────────────────────────────────────────────

    #[tokio::test]
    async fn overlay_statfs_merges() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let st = overlay.statfs().await.unwrap();
        assert!(st.st.bsize > 0);
        assert!(st.st.namelen > 0);

        // Verify it merges: files count should be >= sum of both backends' files.
        let fixed2 = make_fixed();
        let fst = fixed2.statfs().await.unwrap();
        let dyn2 = FakeDynamic::new();
        let dst = dyn2.statfs().await.unwrap();
        assert_eq!(st.st.files, fst.st.files + dst.st.files);
    }

    // ─── Error routing tests ────────────────────────────────────────────

    #[tokio::test]
    async fn overlay_readlink_composite_root_returns_invalid() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        assert!(overlay.readlink(1).await.is_err());
    }

    #[tokio::test]
    async fn overlay_open_composite_root_returns_eisdir() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        assert!(overlay.open(1, 0).await.is_err());
    }

    #[tokio::test]
    async fn overlay_read_composite_root_returns_eisdir() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        assert!(overlay.read(1, 0, 0, 1024).await.is_err());
    }

    #[tokio::test]
    async fn overlay_xattr_composite_root_returns_not_supported() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        assert!(overlay.getxattr(1, b"user.test", 256).await.is_err());
        assert!(overlay.listxattr(1, 256).await.is_err());
    }

    // ─── Write operation routing tests ──────────────────────────────────

    #[tokio::test]
    async fn overlay_write_ops_reject_fixed_inodes() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Get a fixed inode (the .git dir).
        let git = overlay.lookup(1, b".git").await.unwrap();

        // mkdir in fixed dir should fail.
        assert!(
            overlay
                .mkdir(git.nodeid, b"newdir", 0o755, ROOT_CTX)
                .await
                .is_err()
        );
        // unlink in fixed dir should fail.
        assert!(overlay.unlink(git.nodeid, b"HEAD").await.is_err());
        // rmdir in fixed dir should fail.
        assert!(overlay.rmdir(git.nodeid, b"subdir").await.is_err());
        // create in fixed dir should fail.
        assert!(
            overlay
                .create(git.nodeid, b"newfile", 0o644, 0, ROOT_CTX)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn overlay_write_ops_reject_composite_root() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        assert!(overlay.mkdir(1, b"newdir", 0o755, ROOT_CTX).await.is_err());
        assert!(overlay.unlink(1, b"file").await.is_err());
        assert!(overlay.rmdir(1, b"dir").await.is_err());
        assert!(
            overlay
                .create(1, b"file", 0o644, 0, ROOT_CTX)
                .await
                .is_err()
        );
        assert!(overlay.write(1, 0, 0, b"data", 0).await.is_err());
    }

    #[tokio::test]
    async fn overlay_root_parent_mutations_route_to_dynamic_root() {
        let (dynamic, recorded_ops) = FakeDynamic::recording();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        overlay
            .create(1, b"file", 0o644, 0, ROOT_CTX)
            .await
            .unwrap();
        overlay.mkdir(1, b"dir", 0o755, ROOT_CTX).await.unwrap();
        overlay.unlink(1, b"old-file").await.unwrap();
        overlay.rmdir(1, b"old-dir").await.unwrap();
        overlay.rename(1, b"from", 1, b"to").await.unwrap();
        overlay
            .rename_whiteout(1, b"from-whiteout", 1, b"to-whiteout")
            .await
            .unwrap();
        overlay
            .mknod(1, b"dev", S_IFREG | 0o644, 0, ROOT_CTX)
            .await
            .unwrap();
        overlay
            .symlink(1, b"link", b"target", ROOT_CTX)
            .await
            .unwrap();
        let readme = overlay.lookup(1, b"README.md").await.unwrap();
        overlay.link(readme.nodeid, 1, b"hard-link").await.unwrap();
        overlay.tmpfile(1, 0o600, 0, ROOT_CTX).await.unwrap();

        assert_eq!(
            *recorded_ops.lock().unwrap(),
            vec![
                RecordedOp::Create(1),
                RecordedOp::Mkdir(1),
                RecordedOp::Unlink(1),
                RecordedOp::Rmdir(1),
                RecordedOp::Rename(1, 1),
                RecordedOp::RenameWhiteout(1, 1),
                RecordedOp::Mknod(1),
                RecordedOp::Symlink(1),
                RecordedOp::Link {
                    nodeid: 2,
                    parent: 1
                },
                RecordedOp::Tmpfile(1),
            ]
        );
    }

    #[tokio::test]
    async fn overlay_rename_rejects_cross_backend() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let git = overlay.lookup(1, b".git").await.unwrap();
        let src = overlay.lookup(1, b"src").await.unwrap();
        // Rename from dynamic to fixed should fail.
        assert!(
            overlay
                .rename(src.nodeid, b"main.rs", git.nodeid, b"x")
                .await
                .is_err()
        );
        // Rename from fixed to dynamic should fail.
        assert!(
            overlay
                .rename(git.nodeid, b"HEAD", src.nodeid, b"x")
                .await
                .is_err()
        );
        // Whiteout rename follows the same backend ownership rule.
        assert!(
            overlay
                .rename_whiteout(src.nodeid, b"main.rs", git.nodeid, b"x")
                .await
                .is_err()
        );
        assert!(
            overlay
                .rename_whiteout(git.nodeid, b"HEAD", src.nodeid, b"x")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn overlay_setxattr_rejects_fixed() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let git = overlay.lookup(1, b".git").await.unwrap();
        let head = overlay.lookup(git.nodeid, b"HEAD").await.unwrap();
        assert!(
            overlay
                .setxattr(head.nodeid, b"user.test", b"val", 0)
                .await
                .is_err()
        );
        assert!(
            overlay
                .removexattr(head.nodeid, b"user.test")
                .await
                .is_err()
        );
    }

    // ─── Forget/batch_forget tests ──────────────────────────────────────

    #[tokio::test]
    async fn overlay_forget_composite_root_is_noop() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        // Should not panic.
        overlay.forget(1, 1).await;
    }

    #[tokio::test]
    async fn overlay_batch_forget_routes_correctly() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let git = overlay.lookup(1, b".git").await.unwrap();
        let readme = overlay.lookup(1, b"README.md").await.unwrap();
        // Should not panic — routes to respective backends.
        overlay
            .batch_forget(&[(1, 1), (git.nodeid, 1), (readme.nodeid, 1)])
            .await;
    }

    // ─── Readdir offset/pagination tests ────────────────────────────────

    #[tokio::test]
    async fn overlay_readdir_with_offset_skips_entries() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Full readdir.
        let full = root_readdir(&overlay, 0, 8192).await.unwrap();
        let full_names = parse_dirent_names(&full);

        // Readdir with offset=2 should skip . and ..
        let partial = root_readdir(&overlay, 2, 8192).await.unwrap();
        let partial_names = parse_dirent_names(&partial);
        assert!(!partial_names.contains(&b"."[..].to_vec()));
        assert!(!partial_names.contains(&b".."[..].to_vec()));
        assert_eq!(partial_names.len(), full_names.len() - 2);
    }

    #[tokio::test]
    async fn overlay_readdir_small_buffer_paginates() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Use a buffer barely big enough for one entry (dirent is 24 bytes + name + padding).
        let dirent_size = std::mem::size_of::<FuseDirent>();
        let one_entry_size = (dirent_size + 1 + 7) & !7; // "." = 1 byte name

        let buf = root_readdir(&overlay, 0, one_entry_size as u32)
            .await
            .unwrap();
        let names = parse_dirent_names(&buf);
        // Should get at most 1 entry since buffer is tiny.
        assert_eq!(names.len(), 1);
    }

    #[tokio::test]
    async fn overlay_readdir_root_pagination_suppresses_late_lower_duplicate() {
        let mut dynamic_files: Vec<(String, &'static [u8])> =
            vec![("shared".to_string(), b"upper" as &'static [u8])];
        for i in 0..12 {
            dynamic_files.push((format!("upper_{i:02}"), b"u"));
        }

        let mut fixed_files: Vec<(String, &'static [u8])> = Vec::new();
        for i in 0..12 {
            fixed_files.push((format!("lower_{i:02}"), b"l"));
        }
        fixed_files.push(("shared".to_string(), b"lower"));
        fixed_files.push(("lower_tail".to_string(), b"l"));

        let dynamic = FakeDynamic::from_files(&dynamic_files);
        let fixed = synthesized_from_root_files(&fixed_files);
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        let dirent_size = std::mem::size_of::<FuseDirent>();
        let page_size = ((dirent_size + "lower_tail".len() + 7) & !7) as u32;
        let entries = drain_root_readdir_pages(&overlay, page_size).await;
        let names: Vec<Vec<u8>> = entries.iter().map(|(_, _, name)| name.clone()).collect();

        assert_eq!(names.first(), Some(&b"."[..].to_vec()));
        assert_eq!(names.get(1), Some(&b".."[..].to_vec()));
        assert_eq!(names.len(), 2 + dynamic_files.len() + fixed_files.len() - 1);

        let mut unique_names = names.clone();
        unique_names.sort();
        unique_names.dedup();
        assert_eq!(unique_names.len(), names.len());
        assert_eq!(
            names
                .iter()
                .filter(|name| name.as_slice() == b"shared")
                .count(),
            1
        );

        for i in 0..12 {
            assert!(names.contains(&format!("upper_{i:02}").into_bytes()));
            assert!(names.contains(&format!("lower_{i:02}").into_bytes()));
        }
        assert!(names.contains(&b"lower_tail"[..].to_vec()));

        let lookup = overlay.lookup(1, b"shared").await.unwrap();
        let data = overlay.read(lookup.nodeid, 0, 0, 16).await.unwrap();
        assert_eq!(&data, b"upper");

        let shared_dirent = entries
            .iter()
            .find(|(_, _, name)| name.as_slice() == b"shared")
            .unwrap();
        assert_eq!(shared_dirent.0, lookup.nodeid);

        let plus = root_readdirplus(&overlay, 0, 16_384).await.unwrap();
        let plus_entries = parse_readdirplus_entries(&plus);
        let shared_plus: Vec<_> = plus_entries
            .iter()
            .filter(|(_, _, name)| name.as_slice() == b"shared")
            .collect();
        assert_eq!(shared_plus.len(), 1);
        assert_eq!(shared_plus[0].0, lookup.nodeid);
        assert_eq!(shared_plus[0].1, lookup.nodeid);
    }

    // ─── Fsync test ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn overlay_fsync_composite_root_is_noop() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();
        assert!(overlay.fsync(1, 0, false).await.is_ok());
    }

    // ─── Access test ────────────────────────────────────────────────────

    #[tokio::test]
    async fn overlay_access_all_backends() {
        let dynamic = FakeDynamic::new();
        let fixed = make_fixed();
        let overlay = OverlayFsBackend::new(dynamic, fixed).unwrap();

        // Composite root.
        assert!(overlay.access(1, 0).await.is_ok());

        // Fixed inode.
        let git = overlay.lookup(1, b".git").await.unwrap();
        assert!(overlay.access(git.nodeid, 0).await.is_ok());

        // Dynamic inode.
        let readme = overlay.lookup(1, b"README.md").await.unwrap();
        assert!(overlay.access(readme.nodeid, 0).await.is_ok());
    }
}
