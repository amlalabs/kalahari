// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![allow(clippy::cast_possible_truncation)]
//! Writable FUSE filesystem backed by a redb database.
//!
//! Implements [`DynamicFsBackend`] for use as a virtiofs mount — typically
//! the overlayfs upperdir inside a guest VM.  All inodes, directory entries,
//! file data (in 128 KiB chunks), and xattrs live in a single `.db` file.
//!
//! ## Transaction model
//!
//! Read-only FUSE ops (`lookup`, `getattr`, `readlink`, `access`, `read`,
//! `readdir`, `readdirplus`, `getxattr`, `listxattr`, `get_parent`) use
//! `begin_read()`, which does not take the write lock.  Write ops use
//! `begin_write()` with `Durability::None` — commit just releases the lock,
//! no fsync.  `fsync` is the only path that does a durable commit; POSIX
//! `close()` (`FUSE_FLUSH`) is a no-op.
//!
//! [`to_erofs`](RedbFs::to_erofs) streams the contents into an EROFS image.

use std::collections::{BTreeSet, HashMap};
use std::io::{Seek, Write};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use amla_fuse::fs_types::{DT_DIR, FUSE_ROOT_ID, S_IFDIR, S_IFLNK, S_IFREG, mode_to_dtype};
#[cfg(unix)]
use amla_fuse::fuse::FuseKstatfs;
use amla_fuse::fuse::{
    DynamicFsBackend, FATTR_GID, FATTR_MODE, FATTR_MTIME, FATTR_SIZE, FATTR_UID, FUSE_ASYNC_READ,
    FUSE_DO_READDIRPLUS, FUSE_FLOCK_LOCKS, FUSE_POSIX_LOCKS, FsBackend, FuseAttr, FuseAttrOut,
    FuseContext, FuseEntryOut, FuseInitOut, FuseOpenOut, FuseSetattrIn, FuseStatfsOut, pack_dirent,
    pack_direntplus,
};
use amla_fuse::fuse_abi::{
    FuseError, O_ACCMODE, O_RDONLY, O_RDWR, O_WRONLY, XATTR_CREATE, XATTR_REPLACE,
};
use redb::{Durability, ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

const INODES: redb::TableDefinition<u64, &[u8]> = redb::TableDefinition::new("i");
const TREE: redb::TableDefinition<(u64, &[u8]), u64> = redb::TableDefinition::new("t");
const DATA: redb::TableDefinition<(u64, u64), &[u8]> = redb::TableDefinition::new("d");
const XATTRS: redb::TableDefinition<(u64, &[u8]), &[u8]> = redb::TableDefinition::new("x");

const CHUNK: u64 = 128 * 1024;
/// Highest logical file size accepted by redbfs.
///
/// This is the first size whose last byte would have required chunk index
/// `u32::MAX + 1` in the original DATA-key format. Keeping an explicit cap
/// at that security boundary rejects historical alias inputs instead of
/// silently creating enormous sparse files.
const MAX_FILE_SIZE: u64 = (u32::MAX as u64 + 1) * CHUNK;
const S_IFMT: u32 = 0o170_000;
const S_IFCHR: u32 = 0o020_000;
const S_IFBLK: u32 = 0o060_000;
const S_IFIFO: u32 = 0o010_000;
const S_IFSOCK: u32 = 0o140_000;

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors returned by [`RedbFs::open`] / [`RedbFs::open_with_quota`].
///
/// `Corrupted` is the one callers usually care to match on: it means the
/// on-disk inode bytes failed postcard decode, so the `.db` is structurally
/// broken and the caller should refuse to mount (and likely quarantine the
/// file) rather than retry. All other variants are redb / IO errors that
/// may be transient.
#[derive(Debug, thiserror::Error)]
pub enum RedbFsError {
    #[error(transparent)]
    Database(#[from] redb::DatabaseError),
    #[error(transparent)]
    Transaction(#[from] redb::TransactionError),
    #[error(transparent)]
    Table(#[from] redb::TableError),
    #[error(transparent)]
    Storage(#[from] redb::StorageError),
    #[error(transparent)]
    Commit(#[from] redb::CommitError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("corrupt inode #{ino} in stored bytes: {source}")]
    Corrupted {
        ino: u64,
        #[source]
        source: postcard::Error,
    },
    #[error("accounting invariant violation: {message}")]
    AccountingInvariant { message: &'static str },
}

/// Upper bound on the initial `Vec::with_capacity` used when materializing
/// a file body during `to_erofs`. The Vec grows naturally beyond this if
/// the actual on-disk chunks are larger, but a corrupt or crafted inode
/// with `size = u64::MAX` can't trigger a `usize::MAX` allocation.
const MAX_FILE_PREALLOC: usize = 1 << 30; // 1 GiB

// ── Quota ────────────────────────────────────────────────────────────────

/// Resource limits enforced by [`RedbFs`].
///
/// `u64::MAX` on any field disables that limit; the [`Default`] impl is
/// "unlimited on every dimension" so callers that don't explicitly opt in
/// to a quota get the historical "no-ceiling" behavior. Callers that need
/// enforcement (e.g. the `amla-container --max-disk-usage` flag) set the
/// relevant fields and leave the rest at `u64::MAX`.
#[derive(Debug, Clone, Copy)]
pub struct RedbFsQuota {
    /// Maximum number of live inodes (files + dirs + symlinks + special).
    /// Hit → `ENOSPC` on any creating op (create/mkdir/mknod/symlink/tmpfile).
    pub max_inodes: u64,

    /// Maximum total file-data bytes across all regular files.
    /// Hit → `ENOSPC` on `write` / `setattr(SIZE)` growth.
    ///
    /// This is logical size (sum of inode.size), not on-disk redb bytes —
    /// the redb file is typically larger due to B-tree overhead and chunk
    /// padding, but user-visible `df` numbers track logical size.
    pub max_data_bytes: u64,

    /// Maximum xattrs per inode. Hit → `ENOSPC` on `setxattr`.
    pub max_xattrs_per_inode: u64,

    /// Maximum bytes per xattr *value*. Hit → `E2BIG`.
    pub max_xattr_value_bytes: u64,

    /// Maximum bytes per symlink target. Hit → `ENAMETOOLONG`.
    pub max_symlink_bytes: u64,
}

impl RedbFsQuota {
    /// No limits — every dimension set to `u64::MAX`.
    pub const fn unlimited() -> Self {
        Self {
            max_inodes: u64::MAX,
            max_data_bytes: u64::MAX,
            max_xattrs_per_inode: u64::MAX,
            max_xattr_value_bytes: u64::MAX,
            max_symlink_bytes: u64::MAX,
        }
    }
}

impl Default for RedbFsQuota {
    fn default() -> Self {
        Self::unlimited()
    }
}

/// RAII reservation against the filesystem's quota.
///
/// A reservation is *pending* until the caller's redb transaction commits —
/// i.e. the caller knows the new inode / new bytes are durably on disk and
/// should now count toward the live total. Call [`commit`](Self::commit)
/// after `txn.commit()` succeeds; on drop without commit, the reservation
/// returns to the budget.
///
/// The `#[must_use]` is the real fix here: every `reserve_*` call site has
/// several `.map_err(io)?` points between reservation and commit, and
/// previously any of them would leak the reserved budget permanently.
#[must_use = "a dropped QuotaReservation releases its reservation; bind it to \
              a variable that outlives the redb transaction, then call \
              .commit() after txn.commit() succeeds"]
struct QuotaReservation<'a> {
    fs: &'a RedbFs,
    debit: Option<QuotaDebit>,
}

impl QuotaReservation<'_> {
    /// Durability-commit the reservation: the caller has finished their
    /// redb transaction and the reserved budget is now part of the live
    /// total. Consumes the guard so it can't be accidentally released.
    fn commit(mut self) {
        self.debit = None;
    }
}

impl Drop for QuotaReservation<'_> {
    fn drop(&mut self) {
        if let Some(debit) = self.debit.take()
            && let Err(err) = self.fs.release_debit(debit)
        {
            log::error!("quota reservation rollback failed: {err}");
        }
    }
}

#[derive(Clone, Copy)]
enum QuotaDebitKind {
    Inode,
    DataBytes,
}

#[derive(Clone, Copy)]
struct QuotaDebit {
    kind: QuotaDebitKind,
    amount: NonZeroU64,
}

impl QuotaDebit {
    const fn inode() -> Self {
        Self {
            kind: QuotaDebitKind::Inode,
            amount: NonZeroU64::MIN,
        }
    }

    fn data_bytes(bytes: u64) -> Option<Self> {
        Some(Self {
            kind: QuotaDebitKind::DataBytes,
            amount: NonZeroU64::new(bytes)?,
        })
    }
}

#[derive(Clone, Copy)]
enum CleanupPolicy {
    RequiredUnlinked,
    IfUnlinked,
}

/// Pre-grow the database by this many bytes so that early writes don't
/// keep triggering host-side file growth (ftruncate).
#[cfg(not(test))]
const PREGROW_BYTES: usize = 32 * 1024 * 1024;

#[cfg(not(test))]
const PREGROW_TABLE: redb::TableDefinition<u32, &[u8]> = redb::TableDefinition::new("_pregrow");

fn io<T>(_: T) -> FuseError {
    FuseError::io()
}

fn accounting_invariant(message: &'static str) -> FuseError {
    log::error!("redbfs accounting invariant violation: {message}");
    FuseError::io()
}

fn checked_inc_nlink(n: &mut Inode, context: &'static str) -> Result<(), FuseError> {
    n.nlink = n
        .nlink
        .checked_add(1)
        .ok_or_else(|| accounting_invariant(context))?;
    Ok(())
}

fn checked_dec_nlink(n: &mut Inode, context: &'static str) -> Result<(), FuseError> {
    n.nlink = n
        .nlink
        .checked_sub(1)
        .ok_or_else(|| accounting_invariant(context))?;
    Ok(())
}

fn checked_dec_parent_dir_nlink(n: &mut Inode, context: &'static str) -> Result<(), FuseError> {
    let next = n
        .nlink
        .checked_sub(1)
        .ok_or_else(|| accounting_invariant(context))?;
    if next < 2 {
        return Err(accounting_invariant(context));
    }
    n.nlink = next;
    Ok(())
}

fn checked_remove_empty_dir_nlink(n: &mut Inode, context: &'static str) -> Result<(), FuseError> {
    ensure_directory(n)?;
    if n.nlink != 2 {
        return Err(accounting_invariant(context));
    }
    n.nlink = 0;
    Ok(())
}

#[derive(Clone, Copy)]
struct FileSize(u64);

impl FileSize {
    const fn new(size: u64) -> Result<Self, FuseError> {
        if size > MAX_FILE_SIZE {
            return Err(FuseError::file_too_big());
        }
        Ok(Self(size))
    }

    const fn get(self) -> u64 {
        self.0
    }
}

// ── Inode ────────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct Inode {
    mode: u32,
    uid: u32,
    gid: u32,
    nlink: u32,
    size: u64,
    mtime: u64,
    mtime_nsec: u32,
    rdev: u32,
    parent: u64,
    symlink: Vec<u8>,
}

impl Inode {
    const fn new(mode: u32, nlink: u32, parent: u64, uid: u32, gid: u32) -> Self {
        Self {
            mode,
            uid,
            gid,
            nlink,
            size: 0,
            mtime: 0,
            mtime_nsec: 0,
            rdev: 0,
            parent,
            symlink: Vec::new(),
        }
    }
    #[allow(clippy::expect_used)]
    fn enc(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("Inode is always serializable")
    }
    fn dec(b: &[u8]) -> Result<Self, postcard::Error> {
        postcard::from_bytes(b)
    }
    const fn is_dir(&self) -> bool {
        self.mode & S_IFMT == S_IFDIR
    }
    const fn is_regular(&self) -> bool {
        self.mode & S_IFMT == S_IFREG
    }
    const fn attr(&self, ino: u64) -> FuseAttr {
        FuseAttr {
            ino,
            size: self.size,
            blocks: self.size.div_ceil(512),
            atime: self.mtime,
            mtime: self.mtime,
            ctime: self.mtime,
            atimensec: self.mtime_nsec,
            mtimensec: self.mtime_nsec,
            ctimensec: self.mtime_nsec,
            mode: self.mode,
            nlink: self.nlink,
            uid: self.uid,
            gid: self.gid,
            rdev: self.rdev,
            blksize: 4096,
            flags: 0,
        }
    }
    const fn entry(&self, ino: u64) -> FuseEntryOut {
        FuseEntryOut::new(ino, self.attr(ino))
    }
}

fn iget<T: ReadableTable<u64, &'static [u8]>>(t: &T, ino: u64) -> Result<Inode, FuseError> {
    let g = t.get(ino).map_err(io)?.ok_or_else(FuseError::not_found)?;
    Inode::dec(g.value()).map_err(|e| {
        // open_with_quota validates every row, so post-open decode failure
        // means redb storage corrupted mid-run. Fail the op with EIO and
        // keep the mount up so the broken inode stays isolated.
        log::error!("iget: corrupt inode #{ino}: {e}");
        FuseError::io()
    })
}

fn iget_referenced<T: ReadableTable<u64, &'static [u8]>>(
    t: &T,
    ino: u64,
    context: &str,
) -> Result<Inode, FuseError> {
    let Some(g) = t.get(ino).map_err(io)? else {
        log::error!("{context}: missing referenced inode #{ino}");
        return Err(FuseError::io());
    };
    Inode::dec(g.value()).map_err(|e| {
        log::error!("{context}: corrupt referenced inode #{ino}: {e}");
        FuseError::io()
    })
}

fn iput(t: &mut redb::Table<u64, &[u8]>, ino: u64, n: &Inode) -> Result<(), FuseError> {
    t.insert(ino, n.enc().as_slice()).map_err(io)?;
    Ok(())
}

fn tree_has_children<T>(t: &T, ino: u64) -> Result<bool, FuseError>
where
    T: ReadableTable<(u64, &'static [u8]), u64>,
{
    Ok(t.range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
        .map_err(io)?
        .next()
        .is_some())
}

const fn ensure_directory(n: &Inode) -> Result<(), FuseError> {
    if n.is_dir() {
        Ok(())
    } else {
        Err(FuseError::not_dir())
    }
}

const fn ensure_not_directory(n: &Inode) -> Result<(), FuseError> {
    if n.is_dir() {
        Err(FuseError::is_dir())
    } else {
        Ok(())
    }
}

fn ensure_live(n: &Inode, ino: u64, context: &str) -> Result<(), FuseError> {
    if n.nlink == 0 {
        log::error!("{context}: inode #{ino} is not live");
        Err(FuseError::io())
    } else {
        Ok(())
    }
}

fn load_live_inode<T: ReadableTable<u64, &'static [u8]>>(
    t: &T,
    ino: u64,
    context: &str,
) -> Result<Inode, FuseError> {
    let n = iget(t, ino)?;
    ensure_live(&n, ino, context)?;
    Ok(n)
}

fn load_referenced_live_inode<T: ReadableTable<u64, &'static [u8]>>(
    t: &T,
    ino: u64,
    context: &str,
) -> Result<Inode, FuseError> {
    let n = iget_referenced(t, ino, context)?;
    ensure_live(&n, ino, context)?;
    Ok(n)
}

fn load_live_dir<T: ReadableTable<u64, &'static [u8]>>(
    t: &T,
    ino: u64,
    context: &str,
) -> Result<Inode, FuseError> {
    let n = load_live_inode(t, ino, context)?;
    ensure_directory(&n)?;
    Ok(n)
}

fn load_live_regular<T: ReadableTable<u64, &'static [u8]>>(
    t: &T,
    ino: u64,
    context: &str,
) -> Result<Inode, FuseError> {
    let n = iget(t, ino)?;
    if n.is_regular() {
        Ok(n)
    } else if n.is_dir() {
        Err(FuseError::is_dir())
    } else {
        log::error!(
            "{context}: expected regular inode #{ino}, found mode {:#o}",
            n.mode & S_IFMT
        );
        Err(FuseError::invalid())
    }
}

fn erofs_body_from_inode<DT>(
    dt: &DT,
    ino: u64,
    path: &str,
    n: &Inode,
) -> anyhow::Result<amla_erofs::Body>
where
    DT: ReadableTable<(u64, u64), &'static [u8]>,
{
    use amla_erofs::{Body, DeviceKind};

    match n.mode & S_IFMT {
        S_IFDIR => Ok(Body::Directory),
        S_IFLNK => {
            let target = String::from_utf8(n.symlink.clone()).map_err(|e| {
                anyhow::anyhow!("symlink inode {ino} at {path} has non-UTF-8 target: {e}")
            })?;
            Ok(Body::Symlink(target))
        }
        S_IFREG => {
            if n.size > MAX_FILE_PREALLOC as u64 {
                anyhow::bail!("file ino {ino} size {} exceeds export limit", n.size);
            }
            let size_usz = n.size as usize;
            let mut d = vec![0u8; size_usz];
            let n_chunks = n.size.div_ceil(CHUNK);
            for ci in 0..n_chunks {
                if let Some(c) = dt.get((ino, ci))? {
                    let val = c.value();
                    let off = (ci as usize) * CHUNK as usize;
                    let take = val.len().min(size_usz - off);
                    d[off..off + take].copy_from_slice(&val[..take]);
                }
            }
            Ok(Body::RegularFile(d))
        }
        S_IFCHR => Ok(Body::DeviceNode {
            kind: DeviceKind::Character,
            rdev: n.rdev,
        }),
        S_IFBLK => Ok(Body::DeviceNode {
            kind: DeviceKind::Block,
            rdev: n.rdev,
        }),
        S_IFIFO => Ok(Body::Fifo),
        S_IFSOCK => Ok(Body::Socket),
        other => anyhow::bail!("inode {ino} at {path} has unsupported file type mode {other:#o}"),
    }
}

fn is_descendant_of<T>(it: &T, ancestor: u64, mut node: u64) -> Result<bool, FuseError>
where
    T: ReadableTable<u64, &'static [u8]>,
{
    let mut seen = BTreeSet::new();
    while node != 0 {
        if node == ancestor {
            return Ok(true);
        }
        if node == FUSE_ROOT_ID {
            return Ok(false);
        }
        if !seen.insert(node) {
            log::error!("rename: cycle in parent chain at inode #{node}");
            return Err(FuseError::io());
        }
        node = iget_referenced(it, node, "rename parent chain")?.parent;
    }
    Ok(false)
}

/// Validate a directory-entry name component received from the guest.
///
/// A guest-supplied name is a *single* path component, not a path. Reject
/// anything the POSIX / FUSE layer would treat specially so a malicious or
/// buggy guest cannot smuggle path traversal into the on-disk tree:
///
/// - empty name
/// - "." or ".."  (reserved; readdir synthesizes these)
/// - name containing '/'  (would pack multiple components into one)
/// - name containing NUL  (terminates C strings; confuses host tools)
fn validate_name(name: &[u8]) -> Result<(), FuseError> {
    if name.is_empty() || name == b"." || name == b".." {
        return Err(FuseError::invalid());
    }
    if name.iter().any(|&b| b == b'/' || b == 0) {
        return Err(FuseError::invalid());
    }
    // EROFS `nameoff` is u16 and Linux's erofs driver enforces NAME_MAX=255;
    // reject before the name ever reaches the on-disk export.
    if name.len() > 255 {
        return Err(FuseError::name_too_long());
    }
    Ok(())
}

/// Validate an xattr name. Xattrs use a separate namespace (`user.`,
/// `security.`, ...), so `.` / `..` / `/` are legal, but empty and NUL
/// are still protocol errors.
fn validate_xattr_name(name: &[u8]) -> Result<(), FuseError> {
    if name.is_empty() || name.contains(&0) {
        return Err(FuseError::invalid());
    }
    Ok(())
}

struct RenameTarget {
    ino: u64,
    inode: Inode,
}

struct ValidatedRename {
    source_ino: u64,
    source: Inode,
    displaced: Option<RenameTarget>,
}

impl ValidatedRename {
    fn displaced_frees_slot(&self) -> bool {
        self.displaced
            .as_ref()
            .is_some_and(|target| target.inode.is_dir() || target.inode.nlink == 1)
    }
}

struct RenameOutcome {
    unlinked_ino: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum OpenKind {
    File,
    Dir,
}

#[derive(Clone, Copy)]
struct OpenAccess {
    read: bool,
    write: bool,
}

impl OpenAccess {
    const fn from_flags(flags: u32) -> Result<Self, FuseError> {
        match flags & O_ACCMODE {
            O_RDONLY => Ok(Self {
                read: true,
                write: false,
            }),
            O_WRONLY => Ok(Self {
                read: false,
                write: true,
            }),
            O_RDWR => Ok(Self {
                read: true,
                write: true,
            }),
            _ => Err(FuseError::invalid()),
        }
    }

    const fn read_only() -> Self {
        Self {
            read: true,
            write: false,
        }
    }
}

struct OpenHandle {
    ino: u64,
    access: OpenAccess,
    kind: OpenKind,
}

#[derive(Default)]
struct OpenHandleState {
    handles: HashMap<u64, OpenHandle>,
    inode_open_counts: HashMap<u64, u64>,
}

impl OpenHandleState {
    fn insert(&mut self, fh: u64, handle: OpenHandle) -> Result<(), FuseError> {
        if self.handles.contains_key(&fh) {
            return Err(accounting_invariant(
                "file handle id reused while still open",
            ));
        }
        let count = self.inode_open_counts.entry(handle.ino).or_insert(0);
        *count = count
            .checked_add(1)
            .ok_or_else(|| accounting_invariant("inode open count overflow"))?;
        self.handles.insert(fh, handle);
        Ok(())
    }

    fn get(&self, fh: u64) -> Option<&OpenHandle> {
        self.handles.get(&fh)
    }

    fn open_count(&self, ino: u64) -> u64 {
        self.inode_open_counts.get(&ino).copied().unwrap_or(0)
    }

    fn remove(&mut self, fh: u64) -> Result<(OpenHandle, u64), FuseError> {
        let handle = self.handles.remove(&fh).ok_or_else(FuseError::bad_fd)?;
        let count = self
            .inode_open_counts
            .get_mut(&handle.ino)
            .ok_or_else(|| accounting_invariant("open handle missing inode open count"))?;
        *count = count
            .checked_sub(1)
            .ok_or_else(|| accounting_invariant("inode open count underflow"))?;
        let remaining = *count;
        if remaining == 0 {
            self.inode_open_counts.remove(&handle.ino);
        }
        Ok((handle, remaining))
    }
}

#[derive(Clone, Copy)]
struct RenamePaths<'a> {
    parent: u64,
    name: &'a [u8],
    new_parent: u64,
    new_name: &'a [u8],
}

fn validate_rename<TT, IT>(
    tt: &TT,
    it: &IT,
    paths: RenamePaths<'_>,
    whiteout: bool,
) -> Result<Option<ValidatedRename>, FuseError>
where
    TT: ReadableTable<(u64, &'static [u8]), u64>,
    IT: ReadableTable<u64, &'static [u8]>,
{
    load_live_dir(it, paths.parent, "rename source parent")?;
    load_live_dir(it, paths.new_parent, "rename target parent")?;

    let source_ino = tt
        .get((paths.parent, paths.name))
        .map_err(io)?
        .ok_or_else(FuseError::not_found)?
        .value();
    let source = load_referenced_live_inode(it, source_ino, "rename source")?;
    if source.is_dir() && is_descendant_of(it, source_ino, paths.new_parent)? {
        return Err(FuseError::invalid());
    }

    let displaced_ino = tt
        .get((paths.new_parent, paths.new_name))
        .map_err(io)?
        .map(|v| v.value());
    if displaced_ino == Some(source_ino) {
        return if whiteout {
            Err(FuseError::invalid())
        } else {
            Ok(None)
        };
    }

    let displaced = if let Some(ino) = displaced_ino {
        let inode = load_referenced_live_inode(it, ino, "rename target")?;
        if source.is_dir() {
            ensure_directory(&inode)?;
            if tree_has_children(tt, ino)? {
                return Err(FuseError::not_empty());
            }
        } else {
            ensure_not_directory(&inode)?;
        }
        Some(RenameTarget { ino, inode })
    } else {
        None
    };

    Ok(Some(ValidatedRename {
        source_ino,
        source,
        displaced,
    }))
}

fn apply_validated_rename(
    tt: &mut redb::Table<(u64, &[u8]), u64>,
    it: &mut redb::Table<u64, &[u8]>,
    paths: RenamePaths<'_>,
    mut rename: ValidatedRename,
    whiteout_ino: Option<u64>,
) -> Result<RenameOutcome, FuseError> {
    let displaced_dir = rename
        .displaced
        .as_ref()
        .is_some_and(|target| target.inode.is_dir());
    let unlinked_ino = rename
        .displaced
        .as_ref()
        .filter(|target| target.inode.is_dir() || target.inode.nlink == 1)
        .map(|target| target.ino);

    tt.remove((paths.parent, paths.name))
        .map_err(io)?
        .ok_or_else(FuseError::not_found)?;
    if rename.displaced.is_some() {
        tt.remove((paths.new_parent, paths.new_name)).map_err(io)?;
    }

    if rename.source.is_dir() || displaced_dir {
        let mut old_parent = load_live_dir(it, paths.parent, "rename source parent")?;
        let mut new_parent_inode = if paths.parent == paths.new_parent {
            None
        } else {
            Some(load_live_dir(it, paths.new_parent, "rename target parent")?)
        };
        if rename.source.is_dir() && paths.parent != paths.new_parent {
            checked_dec_parent_dir_nlink(
                &mut old_parent,
                "rename source parent directory nlink underflow",
            )?;
            if let Some(p) = &mut new_parent_inode {
                checked_inc_nlink(p, "rename target parent directory nlink overflow")?;
            }
        }
        if displaced_dir {
            if let Some(p) = &mut new_parent_inode {
                checked_dec_parent_dir_nlink(
                    p,
                    "rename displaced directory parent nlink underflow",
                )?;
            } else {
                checked_dec_parent_dir_nlink(
                    &mut old_parent,
                    "rename displaced directory parent nlink underflow",
                )?;
            }
        }
        iput(it, paths.parent, &old_parent)?;
        if let Some(p) = new_parent_inode {
            iput(it, paths.new_parent, &p)?;
        }
    }

    if let Some(target) = rename.displaced {
        let mut n = target.inode;
        if n.is_dir() {
            checked_remove_empty_dir_nlink(&mut n, "rename displaced empty directory nlink drift")?;
        } else {
            checked_dec_nlink(&mut n, "rename displaced inode nlink underflow")?;
        }
        iput(it, target.ino, &n)?;
    }

    tt.insert((paths.new_parent, paths.new_name), rename.source_ino)
        .map_err(io)?;
    if let Some(ino) = whiteout_ino {
        iput(it, ino, &Inode::new(S_IFCHR, 1, paths.parent, 0, 0))?;
        tt.insert((paths.parent, paths.name), ino).map_err(io)?;
    }
    if paths.parent != paths.new_parent {
        rename.source.parent = paths.new_parent;
        iput(it, rename.source_ino, &rename.source)?;
    }

    Ok(RenameOutcome { unlinked_ino })
}

// ── RedbFs ────────────────────────────────────────────────────────────────

pub struct RedbFs {
    db: redb::Database,
    /// Backing file path — retained so `statfs` can ask the host kernel for
    /// real capacity/free-space numbers of the underlying filesystem. Without
    /// this, `df` / `systemd` / `apt` capacity checks in the guest see
    /// fabricated values and make wrong decisions.
    #[cfg_attr(not(unix), allow(dead_code))]
    db_path: PathBuf,
    next_ino: AtomicU64,
    next_fh: AtomicU64,
    quota: RedbFsQuota,
    /// Live inode count. Derived from `next_ino` on open (minus root), then
    /// maintained incrementally with checked arithmetic.
    live_inodes: AtomicU64,
    /// Total file-data bytes. Computed from `sum(inode.size where S_IFREG)`
    /// on open, maintained incrementally on write/setattr/unlink.
    live_data_bytes: AtomicU64,
    /// Set after an invariant failure on a path whose FUSE signature cannot
    /// return an error. Once set, mutating operations and `statfs` fail fast
    /// instead of continuing with suspect quota mirrors.
    accounting_poisoned: AtomicBool,
    /// Open file/directory handles. A FUSE `fh` is a capability minted by
    /// this map, not an ambient inode id supplied by the guest.
    open_handles: Mutex<OpenHandleState>,
}

impl RedbFs {
    pub fn create(path: &Path) -> anyhow::Result<Self> {
        Self::create_with_quota(path, RedbFsQuota::default())
    }

    pub fn create_with_quota(path: &Path, quota: RedbFsQuota) -> anyhow::Result<Self> {
        let mut builder = redb::Builder::new();
        builder.set_cache_size(64 * 1024 * 1024);
        let db = builder.create(path)?;

        // Initialize tables + root inode.
        let txn = db.begin_write()?;
        txn.open_table(INODES)?.insert(
            FUSE_ROOT_ID,
            Inode::new(S_IFDIR | 0o755, 2, 0, 0, 0).enc().as_slice(),
        )?;
        txn.open_table(TREE)?;
        txn.open_table(DATA)?;
        txn.open_table(XATTRS)?;
        txn.commit()?;

        #[cfg(not(test))]
        Self::pregrow(&db, PREGROW_BYTES)?;

        Ok(Self {
            db,
            db_path: path.to_path_buf(),
            next_ino: AtomicU64::new(2),
            next_fh: AtomicU64::new(1),
            quota,
            live_inodes: AtomicU64::new(1), // root
            live_data_bytes: AtomicU64::new(0),
            accounting_poisoned: AtomicBool::new(false),
            open_handles: Mutex::new(OpenHandleState::default()),
        })
    }

    pub fn open(path: &Path) -> Result<Self, RedbFsError> {
        Self::open_with_quota(path, RedbFsQuota::default())
    }

    pub fn open_with_quota(path: &Path, quota: RedbFsQuota) -> Result<Self, RedbFsError> {
        let mut builder = redb::Builder::new();
        builder.set_cache_size(64 * 1024 * 1024);
        let db = builder.open(path)?;

        // Walk the INODES table once on open to seed the live counters AND
        // validate every stored inode decodes. Any postcard failure here
        // means the .db is structurally broken — return `Corrupted` so the
        // caller can quarantine the file instead of mounting a broken FS.
        let (max_ino, live_inodes, live_data_bytes) = {
            let txn = db.begin_read()?;
            txn.open_table(DATA)?;
            let t = txn.open_table(INODES)?;
            let mut max_ino = 1u64;
            let mut live_inodes = 0u64;
            let mut live_data_bytes = 0u64;
            for r in t.iter()? {
                let (k, v) = r?;
                let ino_id = k.value();
                max_ino = max_ino.max(ino_id);
                let n = Inode::dec(v.value()).map_err(|source| RedbFsError::Corrupted {
                    ino: ino_id,
                    source,
                })?;
                if n.nlink == 0 {
                    continue;
                }
                live_inodes =
                    live_inodes
                        .checked_add(1)
                        .ok_or(RedbFsError::AccountingInvariant {
                            message: "live inode count overflow while opening redbfs",
                        })?;
                if n.mode & S_IFMT == S_IFREG {
                    live_data_bytes = live_data_bytes.checked_add(n.size).ok_or(
                        RedbFsError::AccountingInvariant {
                            message: "live data byte count overflow while opening redbfs",
                        },
                    )?;
                }
            }
            (max_ino, live_inodes, live_data_bytes)
        };

        Ok(Self {
            db,
            db_path: path.to_path_buf(),
            next_ino: AtomicU64::new(max_ino.checked_add(1).ok_or(
                RedbFsError::AccountingInvariant {
                    message: "next inode id overflow while opening redbfs",
                },
            )?),
            next_fh: AtomicU64::new(1),
            quota,
            live_inodes: AtomicU64::new(live_inodes),
            live_data_bytes: AtomicU64::new(live_data_bytes),
            accounting_poisoned: AtomicBool::new(false),
            open_handles: Mutex::new(OpenHandleState::default()),
        })
    }

    fn mark_accounting_poisoned(&self, context: &'static str) {
        self.accounting_poisoned.store(true, Ordering::Release);
        log::error!("redbfs accounting poisoned: {context}");
    }

    fn ensure_accounting_healthy(&self) -> Result<(), FuseError> {
        if self.accounting_poisoned.load(Ordering::Acquire) {
            Err(accounting_invariant(
                "redbfs accounting was poisoned by an earlier invariant failure",
            ))
        } else {
            Ok(())
        }
    }

    /// Reserve one inode slot, returning an RAII guard that auto-releases
    /// on drop unless [`QuotaReservation::commit`] is called.
    ///
    /// Use this at the start of every inode-creating op: the guard holds
    /// the budget through the redb write transaction, and if any fallible
    /// step (`begin`, `open_table`, `insert`, `commit`) returns `Err`, the guard's
    /// destructor puts the budget back. Before this existed, a crashed or
    /// failed transaction leaked one inode slot per failure, ratcheting the
    /// filesystem toward ENOSPC under disk pressure.
    fn reserve_inode_guard(&self) -> Result<QuotaReservation<'_>, FuseError> {
        self.reserve_inode()?;
        Ok(QuotaReservation {
            fs: self,
            debit: Some(QuotaDebit::inode()),
        })
    }

    /// Reserve `bytes` of data-budget, returning an RAII guard that
    /// auto-releases on drop unless [`QuotaReservation::commit`] is called.
    /// Zero-byte reservations return an already-inert guard.
    fn reserve_bytes_guard(&self, bytes: u64) -> Result<QuotaReservation<'_>, FuseError> {
        self.reserve_bytes(bytes)?;
        Ok(QuotaReservation {
            fs: self,
            debit: QuotaDebit::data_bytes(bytes),
        })
    }

    /// Reserve one inode slot against the quota. Returns ENOSPC if over.
    ///
    /// Pairs with [`alloc_ino`] — call this *before* `alloc_ino` so a
    /// refusal doesn't leak the inode number.
    fn reserve_inode(&self) -> Result<(), FuseError> {
        self.ensure_accounting_healthy()?;
        // Compare-and-swap loop: bump live_inodes only if we're under limit.
        let mut cur = self.live_inodes.load(Ordering::Relaxed);
        loop {
            if cur >= self.quota.max_inodes {
                return Err(FuseError::no_space());
            }
            match self.live_inodes.compare_exchange_weak(
                cur,
                cur + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    /// Reserve `bytes` new data bytes against the quota. Returns ENOSPC if over.
    fn reserve_bytes(&self, bytes: u64) -> Result<(), FuseError> {
        self.ensure_accounting_healthy()?;
        if bytes == 0 {
            return Ok(());
        }
        let mut cur = self.live_data_bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(bytes) else {
                log::error!(
                    "redbfs quota counter overflow while reserving {bytes} data bytes from {cur}"
                );
                return Err(FuseError::no_space());
            };
            if next > self.quota.max_data_bytes {
                return Err(FuseError::no_space());
            }
            match self.live_data_bytes.compare_exchange_weak(
                cur,
                next,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    fn release_debit(&self, debit: QuotaDebit) -> Result<(), FuseError> {
        let result = match debit.kind {
            QuotaDebitKind::Inode => Self::release_counter(
                &self.live_inodes,
                debit.amount.get(),
                "inode quota release underflow",
            ),
            QuotaDebitKind::DataBytes => Self::release_counter(
                &self.live_data_bytes,
                debit.amount.get(),
                "data byte quota release underflow",
            ),
        };
        if result.is_err() {
            self.mark_accounting_poisoned("quota release underflow");
        }
        result
    }

    fn release_counter(
        counter: &AtomicU64,
        amount: u64,
        context: &'static str,
    ) -> Result<(), FuseError> {
        match counter.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |cur| {
            cur.checked_sub(amount)
        }) {
            Ok(_) => Ok(()),
            Err(cur) => {
                log::error!(
                    "redbfs accounting invariant violation: {context}: tried to release {amount} from {cur}"
                );
                Err(FuseError::io())
            }
        }
    }

    /// Return `bytes` to the data budget on truncate/unlink.
    fn release_bytes(&self, bytes: u64) -> Result<(), FuseError> {
        if let Some(debit) = QuotaDebit::data_bytes(bytes) {
            self.release_debit(debit)?;
        }
        Ok(())
    }

    /// Return one inode slot to the quota on unlink/rmdir/reservation-drop.
    fn release_inode(&self) -> Result<(), FuseError> {
        self.release_debit(QuotaDebit::inode())
    }

    #[cfg(not(test))]
    fn pregrow(db: &redb::Database, bytes: usize) -> anyhow::Result<()> {
        let chunk = vec![0u8; CHUNK as usize];
        let n_chunks = (bytes / CHUNK as usize).max(1) as u32;
        let txn = db.begin_write()?;
        {
            let mut t = txn.open_table(PREGROW_TABLE)?;
            for i in 0..n_chunks {
                t.insert(i, chunk.as_slice())?;
            }
        }
        txn.commit()?;
        let txn = db.begin_write()?;
        {
            let mut t = txn.open_table(PREGROW_TABLE)?;
            for i in 0..n_chunks {
                t.remove(i)?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Start a write transaction with `Durability::None`.
    fn begin(&self) -> Result<redb::WriteTransaction, FuseError> {
        self.ensure_accounting_healthy()?;
        let mut txn = self.db.begin_write().map_err(io)?;
        txn.set_durability(Durability::None).map_err(io)?;
        Ok(txn)
    }

    /// Start a read transaction.  Does not take the write lock; multiple
    /// reads can run concurrently with each other and with in-flight writes.
    fn read_txn(&self) -> Result<redb::ReadTransaction, FuseError> {
        self.db.begin_read().map_err(io)
    }

    fn alloc_ino(&self) -> u64 {
        self.next_ino.fetch_add(1, Ordering::Relaxed)
    }

    fn alloc_fh(&self) -> Result<u64, FuseError> {
        self.next_fh
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |fh| {
                fh.checked_add(1).filter(|_| fh != 0)
            })
            .map_err(|_| accounting_invariant("file handle id overflow"))
    }

    const fn open_out(fh: u64) -> FuseOpenOut {
        FuseOpenOut {
            fh,
            open_flags: 0,
            padding: 0,
        }
    }

    fn open_handles(&self) -> MutexGuard<'_, OpenHandleState> {
        self.open_handles
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn validate_handle(
        &self,
        ino: u64,
        fh: u64,
        kind: OpenKind,
        needs_read: bool,
        needs_write: bool,
        context: &'static str,
    ) -> Result<(), FuseError> {
        let handles = self.open_handles();
        let snapshot = handles.get(fh).map(|h| (h.ino, h.kind, h.access));
        drop(handles);
        let Some((handle_ino, handle_kind, handle_access)) = snapshot else {
            log::error!("{context}: unknown file handle {fh}");
            return Err(FuseError::bad_fd());
        };
        if handle_ino != ino || handle_kind != kind {
            log::error!("{context}: file handle {fh} is for inode #{handle_ino}, not inode #{ino}");
            return Err(FuseError::bad_fd());
        }
        if needs_read && !handle_access.read {
            return Err(FuseError::bad_fd());
        }
        if needs_write && !handle_access.write {
            return Err(FuseError::bad_fd());
        }
        Ok(())
    }

    // Reason: validation reads through `handle` then mutates the same map
    // via `handles.remove`. The handle borrow ties the guard to the body;
    // dropping it early would force a second lock acquisition and a second
    // lookup. Lock scope here is exactly the critical section.
    #[allow(clippy::significant_drop_tightening)]
    fn release_handle(
        &self,
        ino: u64,
        fh: u64,
        kind: OpenKind,
        context: &'static str,
    ) -> Result<Option<u64>, FuseError> {
        let mut handles = self.open_handles();
        let Some(handle) = handles.get(fh) else {
            log::error!("{context}: unknown file handle {fh}");
            return Err(FuseError::bad_fd());
        };
        if handle.ino != ino || handle.kind != kind {
            log::error!(
                "{context}: file handle {fh} is for inode #{}, not inode #{ino}",
                handle.ino
            );
            return Err(FuseError::bad_fd());
        }
        let (_, remaining) = handles.remove(fh)?;
        Ok((remaining == 0).then_some(ino))
    }

    fn cleanup_required_unlinked_inode(&self, ino: u64) -> Result<(), FuseError> {
        self.cleanup_unlinked_inode_accounting(ino, true, CleanupPolicy::RequiredUnlinked)
    }

    fn cleanup_required_unlinked_inode_accounting(
        &self,
        ino: u64,
        release_inode_slot: bool,
    ) -> Result<(), FuseError> {
        self.cleanup_unlinked_inode_accounting(
            ino,
            release_inode_slot,
            CleanupPolicy::RequiredUnlinked,
        )
    }

    fn cleanup_last_handle_inode(&self, ino: u64) -> Result<(), FuseError> {
        self.cleanup_unlinked_inode_accounting(ino, true, CleanupPolicy::IfUnlinked)
    }

    fn cleanup_unlinked_inode_accounting(
        &self,
        ino: u64,
        release_inode_slot: bool,
        policy: CleanupPolicy,
    ) -> Result<(), FuseError> {
        let txn = self.begin()?;
        let freed_bytes = {
            let mut it = txn.open_table(INODES).map_err(io)?;
            let n = {
                let Some(raw) = it.get(ino).map_err(io)? else {
                    log::error!("cleanup: missing inode #{ino}");
                    return Err(FuseError::io());
                };
                Inode::dec(raw.value()).map_err(|e| {
                    log::error!("release: corrupt inode #{ino}: {e}");
                    FuseError::io()
                })?
            };
            if n.nlink != 0 {
                return match policy {
                    CleanupPolicy::RequiredUnlinked => {
                        log::error!(
                            "cleanup: expected inode #{ino} to be unlinked, found nlink {}",
                            n.nlink
                        );
                        Err(FuseError::io())
                    }
                    CleanupPolicy::IfUnlinked => Ok(()),
                };
            }

            let mut dt = txn.open_table(DATA).map_err(io)?;
            let data_keys = dt
                .range((ino, 0)..(ino + 1, 0))
                .map_err(io)?
                .map(|r| r.map(|(k, _)| k.value().1))
                .collect::<Result<Vec<_>, _>>()
                .map_err(io)?;
            for chunk in data_keys {
                dt.remove((ino, chunk)).map_err(io)?;
            }

            let mut xt = txn.open_table(XATTRS).map_err(io)?;
            let xattr_keys = xt
                .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
                .map_err(io)?
                .map(|r| r.map(|(k, _)| k.value().1.to_vec()))
                .collect::<Result<Vec<_>, _>>()
                .map_err(io)?;
            for name in xattr_keys {
                xt.remove((ino, name.as_slice())).map_err(io)?;
            }

            it.remove(ino).map_err(io)?;
            if n.is_regular() { n.size } else { 0 }
        };
        txn.commit().map_err(io)?;
        if release_inode_slot {
            self.release_inode()?;
        }
        self.release_bytes(freed_bytes)?;
        Ok(())
    }

    /// Write the filesystem as an EROFS image.
    pub fn to_erofs(&self, w: &mut (impl Write + Seek)) -> anyhow::Result<amla_erofs::ImageStats> {
        self.to_erofs_from(FUSE_ROOT_ID, w)
    }

    /// Write a subtree as an EROFS image, using `subdir` as the new root.
    pub fn to_erofs_subtree(
        &self,
        subdir: &str,
        w: &mut (impl Write + Seek),
    ) -> anyhow::Result<amla_erofs::ImageStats> {
        let txn = self.db.begin_read()?;
        let tt = txn.open_table(TREE)?;
        let root_ino = tt
            .get((FUSE_ROOT_ID, subdir.as_bytes()))?
            .ok_or_else(|| anyhow::anyhow!("subtree {subdir:?} not found"))?
            .value();
        drop(tt);
        drop(txn);
        self.to_erofs_from(root_ino, w)
    }

    fn to_erofs_from(
        &self,
        root_ino: u64,
        w: &mut (impl Write + Seek),
    ) -> anyhow::Result<amla_erofs::ImageStats> {
        use amla_erofs::{Entry, ErofsWriter, Metadata, Permissions, Xattr};
        // Use a write transaction for type-inference compatibility with
        // our table helper functions.  No actual mutations happen.
        let mut txn = self.db.begin_write()?;
        txn.set_durability(Durability::None)?;
        let it = txn.open_table(INODES)?;
        let tt = txn.open_table(TREE)?;
        let dt = txn.open_table(DATA)?;
        let xt = txn.open_table(XATTRS)?;

        let mut erofs = ErofsWriter::new(w);
        let mut stack = vec![(root_ino, "/".to_string())];

        while let Some((ino, path)) = stack.pop() {
            let n = match it.get(ino)? {
                Some(g) => Inode::dec(g.value())
                    .map_err(|e| anyhow::anyhow!("corrupt inode {ino} at {path}: {e}"))?,
                None => anyhow::bail!("export references missing inode {ino} at {path}"),
            };
            let mut xattrs = Vec::new();
            for r in xt.range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))? {
                let (k, v) = r?;
                xattrs.push(Xattr {
                    key: k.value().1.to_vec(),
                    value: v.value().to_vec(),
                });
            }
            #[allow(clippy::cast_possible_truncation)]
            let meta = Metadata {
                permissions: Permissions::try_from((n.mode & 0o7777) as u16)?,
                uid: n.uid,
                gid: n.gid,
                mtime: n.mtime,
                mtime_nsec: n.mtime_nsec,
                xattrs,
            };
            let body = erofs_body_from_inode(&dt, ino, &path, &n)?;
            erofs.push(Entry {
                path: path.clone(),
                metadata: meta,
                body,
            })?;
            if n.is_dir() {
                let mut ch: Vec<(Vec<u8>, u64)> = tt
                    .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))?
                    .map(|r| r.map(|(k, v)| (k.value().1.to_vec(), v.value())))
                    .collect::<Result<_, _>>()?;
                ch.reverse();
                for (name, cino) in ch {
                    let s = String::from_utf8_lossy(&name);
                    stack.push((
                        cino,
                        if path == "/" {
                            format!("/{s}")
                        } else {
                            format!("{path}/{s}")
                        },
                    ));
                }
            }
        }
        drop(it);
        drop(tt);
        drop(dt);
        drop(xt);
        txn.commit()?;
        let (_, stats) = erofs.finish()?;
        Ok(stats)
    }
}

// ── FsBackend ─────────────────────────────────────────────────────────────

impl DynamicFsBackend for RedbFs {}

impl FsBackend for RedbFs {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        Ok(FuseInitOut {
            major: 7,
            minor: 31,
            max_readahead: 128 * 1024,
            flags: FUSE_ASYNC_READ | FUSE_POSIX_LOCKS | FUSE_FLOCK_LOCKS | FUSE_DO_READDIRPLUS,
            ..FuseInitOut::default()
        })
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        validate_name(name)?;
        let txn = self.read_txn()?;
        let it = txn.open_table(INODES).map_err(io)?;
        load_live_dir(&it, parent, "lookup parent")?;
        let ino = txn
            .open_table(TREE)
            .map_err(io)?
            .get((parent, name))
            .map_err(io)?
            .ok_or_else(FuseError::not_found)?
            .value();
        let n = iget_referenced(&it, ino, "lookup")?;
        Ok(n.entry(ino))
    }

    async fn forget(&self, _: u64, _: u64) {}
    async fn batch_forget(&self, _: &[(u64, u64)]) {}

    async fn getattr(&self, ino: u64) -> Result<FuseAttrOut, FuseError> {
        let txn = self.read_txn()?;
        let n = iget(&txn.open_table(INODES).map_err(io)?, ino)?;
        Ok(FuseAttrOut::new(n.attr(ino)))
    }

    async fn readlink(&self, ino: u64) -> Result<Vec<u8>, FuseError> {
        let txn = self.read_txn()?;
        let n = iget(&txn.open_table(INODES).map_err(io)?, ino)?;
        if n.symlink.is_empty() {
            return Err(FuseError::invalid());
        }
        Ok(n.symlink)
    }

    async fn access(&self, ino: u64, _: u32) -> Result<(), FuseError> {
        let txn = self.read_txn()?;
        txn.open_table(INODES)
            .map_err(io)?
            .get(ino)
            .map_err(io)?
            .ok_or_else(FuseError::not_found)?;
        Ok(())
    }

    async fn open(&self, ino: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
        let access = OpenAccess::from_flags(flags)?;
        let txn = self.read_txn()?;
        let it = txn.open_table(INODES).map_err(io)?;
        let n = load_live_inode(&it, ino, "open")?;
        if n.is_dir() {
            return Err(FuseError::is_dir());
        }
        if !n.is_regular() {
            log::error!(
                "open: expected regular inode #{ino}, found mode {:#o}",
                n.mode
            );
            return Err(FuseError::invalid());
        }
        let fh = self.alloc_fh()?;
        self.open_handles().insert(
            fh,
            OpenHandle {
                ino,
                access,
                kind: OpenKind::File,
            },
        )?;
        Ok(Self::open_out(fh))
    }
    async fn opendir(&self, ino: u64) -> Result<FuseOpenOut, FuseError> {
        let txn = self.read_txn()?;
        load_live_dir(&txn.open_table(INODES).map_err(io)?, ino, "opendir")?;
        let fh = self.alloc_fh()?;
        self.open_handles().insert(
            fh,
            OpenHandle {
                ino,
                access: OpenAccess::read_only(),
                kind: OpenKind::Dir,
            },
        )?;
        Ok(Self::open_out(fh))
    }

    async fn release(&self, ino: u64, fh: u64) {
        match self.release_handle(ino, fh, OpenKind::File, "release") {
            Ok(Some(cleanup_ino)) => {
                if let Err(e) = self.cleanup_last_handle_inode(cleanup_ino) {
                    log::error!("release cleanup for inode #{cleanup_ino} failed: {e}");
                    self.mark_accounting_poisoned("release cleanup failed");
                }
            }
            Ok(None) => {}
            Err(e) => log::error!("release rejected for inode #{ino}, fh {fh}: {e}"),
        }
    }
    async fn releasedir(&self, ino: u64, fh: u64) {
        match self.release_handle(ino, fh, OpenKind::Dir, "releasedir") {
            Ok(Some(cleanup_ino)) => {
                if let Err(e) = self.cleanup_last_handle_inode(cleanup_ino) {
                    log::error!("releasedir cleanup for inode #{cleanup_ino} failed: {e}");
                    self.mark_accounting_poisoned("releasedir cleanup failed");
                }
            }
            Ok(None) => {}
            Err(e) => log::error!("releasedir rejected for inode #{ino}, fh {fh}: {e}"),
        }
    }

    async fn read(&self, ino: u64, fh: u64, offset: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        self.validate_handle(ino, fh, OpenKind::File, true, false, "read")?;
        let txn = self.read_txn()?;
        let file_size = FileSize::new(
            load_live_regular(&txn.open_table(INODES).map_err(io)?, ino, "read")?.size,
        )?
        .get();
        if offset >= file_size {
            return Ok(Vec::new());
        }
        // `offset + size` can overflow u64 if the caller crafts offset near
        // u64::MAX. Saturating + min(file_size) preserves POSIX read-past-EOF
        // semantics (short read) without wrapping into an underflow on
        // `end - offset`.
        let end = offset.saturating_add(u64::from(size)).min(file_size);
        let dt = txn.open_table(DATA).map_err(io)?;
        let mut buf = Vec::with_capacity((end - offset) as usize);
        let mut pos = offset;
        while pos < end {
            let ci = pos / CHUNK;
            let co = (pos % CHUNK) as usize;
            let need = (end - pos) as usize;
            // A stored chunk whose length is <= co is a sparse tail within the
            // chunk: fall through to the zero-fill branch alongside a missing
            // chunk, preserving POSIX hole semantics.
            if let Some(c) = dt.get((ino, ci)).map_err(io)?
                && let val = c.value()
                && co < val.len()
            {
                let take = (val.len() - co).min(need);
                buf.extend_from_slice(&val[co..co + take]);
                pos += take as u64;
            } else {
                let fill = need.min(CHUNK as usize - co);
                buf.resize(buf.len() + fill, 0);
                pos += fill as u64;
            }
        }
        Ok(buf)
    }

    #[allow(clippy::many_single_char_names)]
    async fn readdir(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        self.validate_handle(ino, fh, OpenKind::Dir, true, false, "readdir")?;
        let txn = self.read_txn()?;
        let it = txn.open_table(INODES).map_err(io)?;
        let tt = txn.open_table(TREE).map_err(io)?;
        let n = load_live_dir(&it, ino, "readdir")?;
        let pino = if n.parent == 0 { ino } else { n.parent };
        let max = size as usize;
        let mut buf = Vec::with_capacity(max);
        let mut i = 0u64;
        i += 1;
        if i > offset && pack_dirent(&mut buf, max, ino, b".", i, DT_DIR) == 0 {
            return Ok(buf);
        }
        i += 1;
        if i > offset && pack_dirent(&mut buf, max, pino, b"..", i, DT_DIR) == 0 {
            return Ok(buf);
        }
        for r in tt
            .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
            .map_err(io)?
        {
            let (k, v) = r.map_err(io)?;
            i += 1;
            if i <= offset {
                continue;
            }
            let cino = v.value();
            let c = iget_referenced(&it, cino, "readdir")?;
            if pack_dirent(&mut buf, max, cino, k.value().1, i, mode_to_dtype(c.mode)) == 0 {
                break;
            }
        }
        Ok(buf)
    }

    #[allow(clippy::many_single_char_names)]
    async fn readdirplus(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        self.validate_handle(ino, fh, OpenKind::Dir, true, false, "readdirplus")?;
        let txn = self.read_txn()?;
        let it = txn.open_table(INODES).map_err(io)?;
        let tt = txn.open_table(TREE).map_err(io)?;
        let n = load_live_dir(&it, ino, "readdirplus")?;
        let pino = if n.parent == 0 { ino } else { n.parent };
        let max = size as usize;
        let mut buf = Vec::with_capacity(max);
        let mut i = 0u64;
        i += 1;
        if i > offset && pack_direntplus(&mut buf, max, &n.entry(ino), b".", i, DT_DIR) == 0 {
            return Ok(buf);
        }
        i += 1;
        if i > offset {
            let pe = if pino == ino {
                n.entry(ino)
            } else {
                iget(&it, pino)?.entry(pino)
            };
            if pack_direntplus(&mut buf, max, &pe, b"..", i, DT_DIR) == 0 {
                return Ok(buf);
            }
        }
        for r in tt
            .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
            .map_err(io)?
        {
            let (k, v) = r.map_err(io)?;
            i += 1;
            if i <= offset {
                continue;
            }
            let cino = v.value();
            let c = iget_referenced(&it, cino, "readdirplus")?;
            if pack_direntplus(
                &mut buf,
                max,
                &c.entry(cino),
                k.value().1,
                i,
                mode_to_dtype(c.mode),
            ) == 0
            {
                break;
            }
        }
        Ok(buf)
    }

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        self.ensure_accounting_healthy()?;
        // Start from the host backing filesystem's real capacity — `apt`,
        // `dpkg`, and `systemd` make install/boot decisions based on these
        // numbers, and fabricating them causes "not enough space" failures
        // even when the host disk has room.
        //
        // Then clamp the guest-facing display by any quota that's actually
        // set, so guest tooling plans against the container's limit too.
        // This is presentation only: authoritative quota counters are seeded
        // and mutated with checked arithmetic above, while `statfs` must still
        // report zero free space if an existing image is reopened under a
        // tighter quota than its current usage.
        // Each dimension is only clamped when its quota ≠ u64::MAX
        // (the `unlimited` marker), so the historical "report host reality"
        // behavior is preserved when no quota is set.
        #[cfg(unix)]
        {
            let vfs =
                rustix::fs::statvfs(&self.db_path).map_err(|e| io(std::io::Error::from(e)))?;
            let bsize = u32::try_from(vfs.f_bsize).unwrap_or(4096);
            let namelen = u32::try_from(vfs.f_namemax).unwrap_or(255);
            let frsize = u32::try_from(vfs.f_frsize).unwrap_or(4096);
            let block_unit = u64::from(frsize).max(1);

            let mut blocks = vfs.f_blocks;
            let mut bfree = vfs.f_bfree;
            let mut bavail = vfs.f_bavail;
            let mut files = vfs.f_files;
            let mut ffree = vfs.f_ffree;

            if self.quota.max_data_bytes != u64::MAX {
                let used = self.live_data_bytes.load(Ordering::Relaxed);
                let quota_blocks = self.quota.max_data_bytes / block_unit;
                let remaining_blocks = self.quota.max_data_bytes.saturating_sub(used) / block_unit;
                blocks = blocks.min(quota_blocks);
                bfree = bfree.min(remaining_blocks);
                bavail = bavail.min(remaining_blocks);
            }
            if self.quota.max_inodes != u64::MAX {
                let live = self.live_inodes.load(Ordering::Relaxed);
                files = files.min(self.quota.max_inodes);
                ffree = ffree.min(self.quota.max_inodes.saturating_sub(live));
            }

            Ok(FuseStatfsOut {
                st: FuseKstatfs {
                    blocks,
                    bfree,
                    bavail,
                    files,
                    ffree,
                    bsize,
                    namelen,
                    frsize,
                    padding: 0,
                    spare: [0; 6],
                },
            })
        }
        #[cfg(not(unix))]
        {
            // FUSE doesn't run on Windows; compile-only stub for cross-build.
            Err(FuseError::no_data())
        }
    }

    async fn getxattr(&self, ino: u64, name: &[u8], size: u32) -> Result<Vec<u8>, FuseError> {
        validate_xattr_name(name)?;
        let txn = self.read_txn()?;
        let val = txn
            .open_table(XATTRS)
            .map_err(io)?
            .get((ino, name))
            .map_err(io)?
            .ok_or_else(FuseError::no_data)?
            .value()
            .to_vec();
        // size=0 is a probe — return the full value so the FUSE server
        // can measure .len() and report the correct size to the kernel.
        if size != 0 && val.len() > size as usize {
            return Err(FuseError::range());
        }
        Ok(val)
    }

    async fn listxattr(&self, ino: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        let txn = self.read_txn()?;
        let mut names = Vec::new();
        for r in txn
            .open_table(XATTRS)
            .map_err(io)?
            .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
            .map_err(io)?
        {
            let (k, _) = r.map_err(io)?;
            names.extend_from_slice(k.value().1);
            names.push(0);
        }
        if size != 0 && names.len() > size as usize {
            return Err(FuseError::range());
        }
        Ok(names)
    }

    // ── Writes ────────────────────────────────────────────────────────

    async fn setattr(&self, ino: u64, a: &FuseSetattrIn) -> Result<FuseAttrOut, FuseError> {
        let requested_size = if a.valid & FATTR_SIZE != 0 {
            Some(FileSize::new(a.size)?.get())
        } else {
            None
        };
        let txn = self.begin()?;

        // Read the current size *inside* the write-txn so the delta we
        // reserve matches the delta we commit. Reading from a separate
        // read-txn first would let another writer grow the file between the
        // read and the reservation, leaving `live_data_bytes` short by that
        // concurrent writer's delta. Under adversarial workloads this could
        // push the mirror counter arbitrarily high and freeze the FS early.
        let old_size = {
            let it = txn.open_table(INODES).map_err(io)?;
            if a.valid & FATTR_SIZE != 0 {
                load_live_regular(&it, ino, "setattr size")?.size
            } else {
                iget(&it, ino)?.size
            }
        };

        // Grow-truncates allocate (implicitly zeroed) bytes that count
        // against the byte quota just like a write. RAII guard — any `?`
        // between here and commit rolls the reservation back.
        let grow_res = if let Some(new_size) = requested_size
            && new_size > old_size
        {
            Some(self.reserve_bytes_guard(new_size - old_size)?)
        } else {
            None
        };

        if let Some(new_size) = requested_size {
            let mut dt = txn.open_table(DATA).map_err(io)?;
            // Preserve only bytes that were visible both before and after the
            // resize. This handles shrink and also sanitizes old DBs where a
            // prior shrink left stale bytes hidden past EOF; a later grow must
            // expose zeros, not that hidden tail.
            let keep_size = old_size.min(new_size);
            let first_gone = keep_size.div_ceil(CHUNK);
            if keep_size % CHUNK != 0 {
                let tail_len = (keep_size % CHUNK) as usize;
                let tail_key = (ino, first_gone - 1);
                let truncated_tail = dt.get(tail_key).map_err(io)?.and_then(|c| {
                    let val = c.value();
                    (val.len() > tail_len).then(|| val[..tail_len].to_vec())
                });
                if let Some(tail) = truncated_tail {
                    dt.insert(tail_key, tail.as_slice()).map_err(io)?;
                }
            }
            // Drop every chunk at or after the first byte that should become
            // logically zero/absent.
            dt.retain_in((ino, first_gone)..(ino + 1, 0), |_, _| false)
                .map_err(io)?;
        }
        let mut it = txn.open_table(INODES).map_err(io)?;
        let mut n = if requested_size.is_some() {
            load_live_regular(&it, ino, "setattr size")?
        } else {
            iget(&it, ino)?
        };
        let old_size_for_release = n.size;
        if a.valid & FATTR_MODE != 0 {
            n.mode = (n.mode & S_IFMT) | (a.mode & 0o7777);
        }
        if a.valid & FATTR_UID != 0 {
            n.uid = a.uid;
        }
        if a.valid & FATTR_GID != 0 {
            n.gid = a.gid;
        }
        if let Some(new_size) = requested_size {
            n.size = new_size;
        }
        if a.valid & FATTR_MTIME != 0 {
            n.mtime = a.mtime;
            n.mtime_nsec = a.mtimensec;
        }
        iput(&mut it, ino, &n)?;
        drop(it);
        txn.commit().map_err(io)?;
        if let Some(res) = grow_res {
            res.commit();
        }
        // Post-commit: if we shrank the file, credit the freed bytes back
        // to the byte budget. Grow-truncates were reserved above.
        if let Some(new_size) = requested_size
            && new_size < old_size_for_release
        {
            self.release_bytes(old_size_for_release - new_size)?;
        }
        Ok(FuseAttrOut::new(n.attr(ino)))
    }

    async fn write(
        &self,
        ino: u64,
        fh: u64,
        offset: u64,
        data: &[u8],
        _: u32,
    ) -> Result<u32, FuseError> {
        self.validate_handle(ino, fh, OpenKind::File, false, true, "write")?;
        // Reject writes that would overflow the u64 file-size field before we
        // touch any state. If we let this wrap, the reservation path saturates
        // (under-reserves) while the commit path wrapped silently, leaving
        // data in the DATA table but gating it out of reads via a tiny `n.size`
        // — silent data loss plus a leaked quota reservation.
        let new_end = offset
            .checked_add(data.len() as u64)
            .ok_or_else(FuseError::file_too_big)?;
        let new_end = FileSize::new(new_end)?.get();
        // Upfront byte reservation: read the current inode size inside the
        // write-txn so the delta we reserve matches the delta we'll commit.
        // A separate read-txn here would let another writer extend the file
        // between the read and this txn's commit, under-reserving for this
        // write and drifting the mirror counter above the true live total.
        let txn = self.begin()?;
        let delta = {
            let it = txn.open_table(INODES).map_err(io)?;
            let n = load_live_regular(&it, ino, "write")?;
            match new_end.cmp(&n.size) {
                std::cmp::Ordering::Greater => new_end - n.size,
                std::cmp::Ordering::Equal | std::cmp::Ordering::Less => 0,
            }
        };
        let byte_res = self.reserve_bytes_guard(delta)?;

        {
            let mut dt = txn.open_table(DATA).map_err(io)?;
            let mut pos = 0usize;
            let mut foff = offset;
            while pos < data.len() {
                let ci = foff / CHUNK;
                let co = (foff % CHUNK) as usize;
                let wlen = (CHUNK as usize - co).min(data.len() - pos);
                let src = &data[pos..pos + wlen];

                // Full-chunk aligned write: new bytes replace the whole chunk.
                // This is the dominant case for bulk sequential writes (package
                // install, file copy, image unpack) because `max_write = CHUNK`.
                if co == 0 && wlen == CHUNK as usize {
                    dt.insert((ino, ci), src).map_err(io)?;
                } else {
                    let existing: Option<Vec<u8>> =
                        dt.get((ino, ci)).map_err(io)?.map(|v| v.value().to_vec());
                    // No prior chunk and aligned start: skip the zero-pad.
                    if co == 0 && existing.is_none() {
                        dt.insert((ino, ci), src).map_err(io)?;
                    } else {
                        // Partial overlay: read existing, patch, write back.
                        let mut chunk = existing.unwrap_or_default();
                        if chunk.len() < co + wlen {
                            chunk.resize(co + wlen, 0);
                        }
                        chunk[co..co + wlen].copy_from_slice(src);
                        dt.insert((ino, ci), chunk.as_slice()).map_err(io)?;
                    }
                }
                pos += wlen;
                foff += wlen as u64;
            }
        }
        {
            let mut it = txn.open_table(INODES).map_err(io)?;
            let mut n = load_live_regular(&it, ino, "write")?;
            if new_end > n.size {
                n.size = new_end;
                iput(&mut it, ino, &n)?;
            }
        }
        txn.commit().map_err(io)?;
        byte_res.commit();
        #[allow(clippy::cast_possible_truncation)]
        Ok(data.len() as u32)
    }

    async fn create(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        flags: u32,
        ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        validate_name(name)?;
        let access = OpenAccess::from_flags(flags)?;
        let fh = self.alloc_fh()?;
        let res = self.reserve_inode_guard()?;
        let ino = self.alloc_ino();
        let n = Inode::new(S_IFREG | (mode & 0o7777), 1, parent, ctx.uid, ctx.gid);
        let txn = self.begin()?;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, parent, "create parent")?;
            if tt.get((parent, name)).map_err(io)?.is_some() {
                return Err(FuseError::exists());
            }
            iput(&mut it, ino, &n)?;
            tt.insert((parent, name), ino).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        res.commit();
        self.open_handles().insert(
            fh,
            OpenHandle {
                ino,
                access,
                kind: OpenKind::File,
            },
        )?;
        Ok((n.entry(ino), Self::open_out(fh)))
    }

    async fn mkdir(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        validate_name(name)?;
        let res = self.reserve_inode_guard()?;
        let ino = self.alloc_ino();
        let n = Inode::new(S_IFDIR | (mode & 0o7777), 2, parent, ctx.uid, ctx.gid);
        let txn = self.begin()?;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            let mut p = load_live_dir(&it, parent, "mkdir parent")?;
            if tt.get((parent, name)).map_err(io)?.is_some() {
                return Err(FuseError::exists());
            }
            iput(&mut it, ino, &n)?;
            checked_inc_nlink(&mut p, "mkdir parent directory nlink overflow")?;
            iput(&mut it, parent, &p)?;
            tt.insert((parent, name), ino).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        res.commit();
        Ok(n.entry(ino))
    }

    async fn mknod(
        &self,
        parent: u64,
        name: &[u8],
        mode: u32,
        rdev: u32,
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        validate_name(name)?;
        // Reject S_IFREG/S_IFDIR/S_IFLNK and garbage type fields — mknod is
        // only for char/block/fifo/socket nodes. Without this, a guest could
        // store an inode whose S_IFMT disagrees with how it's laid out
        // (e.g. S_IFREG but no data chunks), corrupting unlink's
        // live_data_bytes accounting and readdir's dtype translation.
        match mode & S_IFMT {
            S_IFCHR | S_IFBLK | S_IFIFO | S_IFSOCK => {}
            _ => return Err(FuseError::invalid()),
        }
        // Preserve setuid/setgid/sticky (the 0o7000 bits inside 0o7777) —
        // stripping them would break sudo, passwd, mount, and other setuid
        // binaries in guest rootfs images. Defense-in-depth against a
        // malicious guest creating setuid nodes is the consumer's job via
        // `mount -o nosuid`, not this FUSE daemon's.
        let type_bits = mode & S_IFMT;
        let perm_bits = mode & 0o7777;
        let res = self.reserve_inode_guard()?;
        let ino = self.alloc_ino();
        let mut n = Inode::new(type_bits | perm_bits, 1, parent, ctx.uid, ctx.gid);
        n.rdev = rdev;
        let txn = self.begin()?;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, parent, "mknod parent")?;
            if tt.get((parent, name)).map_err(io)?.is_some() {
                return Err(FuseError::exists());
            }
            iput(&mut it, ino, &n)?;
            tt.insert((parent, name), ino).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        res.commit();
        Ok(n.entry(ino))
    }

    async fn unlink(&self, parent: u64, name: &[u8]) -> Result<(), FuseError> {
        validate_name(name)?;
        let handles = self.open_handles();
        let txn = self.begin()?;
        let unlinked_ino = {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, parent, "unlink parent")?;
            let ino = tt
                .remove((parent, name))
                .map_err(io)?
                .ok_or_else(FuseError::not_found)?
                .value();
            let mut n = load_referenced_live_inode(&it, ino, "unlink")?;
            ensure_not_directory(&n)?;
            let unlinked_ino = (n.nlink == 1).then_some(ino);
            checked_dec_nlink(&mut n, "unlink inode nlink underflow")?;
            iput(&mut it, ino, &n)?;
            unlinked_ino
        };
        txn.commit().map_err(io)?;
        if let Some(ino) = unlinked_ino
            && handles.open_count(ino) == 0
        {
            drop(handles);
            self.cleanup_required_unlinked_inode(ino)?;
        }
        Ok(())
    }

    async fn rmdir(&self, parent: u64, name: &[u8]) -> Result<(), FuseError> {
        validate_name(name)?;
        let handles = self.open_handles();
        let txn = self.begin()?;
        let removed_ino;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            let mut p = load_live_dir(&it, parent, "rmdir parent")?;
            removed_ino = tt
                .get((parent, name))
                .map_err(io)?
                .ok_or_else(FuseError::not_found)?
                .value();
            let mut n = load_referenced_live_inode(&it, removed_ino, "rmdir")?;
            ensure_directory(&n)?;
            if tree_has_children(&tt, removed_ino)? {
                return Err(FuseError::not_empty());
            }
            tt.remove((parent, name)).map_err(io)?;
            checked_dec_parent_dir_nlink(&mut p, "rmdir parent directory nlink underflow")?;
            iput(&mut it, parent, &p)?;
            checked_remove_empty_dir_nlink(&mut n, "rmdir empty directory nlink drift")?;
            iput(&mut it, removed_ino, &n)?;
        }
        txn.commit().map_err(io)?;
        if handles.open_count(removed_ino) == 0 {
            drop(handles);
            self.cleanup_required_unlinked_inode(removed_ino)?;
        }
        Ok(())
    }

    async fn rename(&self, parent: u64, name: &[u8], np: u64, nn: &[u8]) -> Result<(), FuseError> {
        validate_name(name)?;
        validate_name(nn)?;
        let paths = RenamePaths {
            parent,
            name,
            new_parent: np,
            new_name: nn,
        };
        let handles = self.open_handles();
        let txn = self.begin()?;
        let outcome;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            let Some(validated) = validate_rename(&tt, &it, paths, false)? else {
                return Ok(());
            };
            outcome = apply_validated_rename(&mut tt, &mut it, paths, validated, None)?;
        }
        txn.commit().map_err(io)?;
        if let Some(ino) = outcome.unlinked_ino
            && handles.open_count(ino) == 0
        {
            drop(handles);
            self.cleanup_required_unlinked_inode(ino)?;
        }
        Ok(())
    }

    async fn rename_whiteout(
        &self,
        parent: u64,
        name: &[u8],
        np: u64,
        nn: &[u8],
    ) -> Result<(), FuseError> {
        validate_name(name)?;
        validate_name(nn)?;
        let paths = RenamePaths {
            parent,
            name,
            new_parent: np,
            new_name: nn,
        };
        let handles = self.open_handles();
        let mut inode_res = None;
        let reused_displaced_slot;
        let txn = self.begin()?;
        let outcome;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            let Some(validated) = validate_rename(&tt, &it, paths, true)? else {
                return Ok(());
            };
            reused_displaced_slot = validated.displaced_frees_slot()
                && validated
                    .displaced
                    .as_ref()
                    .is_some_and(|target| handles.open_count(target.ino) == 0);
            if !reused_displaced_slot {
                inode_res = Some(self.reserve_inode_guard()?);
            }
            let wo_ino = self.alloc_ino();
            outcome = apply_validated_rename(&mut tt, &mut it, paths, validated, Some(wo_ino))?;
        }
        txn.commit().map_err(io)?;
        if let Some(res) = inode_res {
            res.commit();
        }
        if let Some(ino) = outcome.unlinked_ino
            && handles.open_count(ino) == 0
        {
            drop(handles);
            self.cleanup_required_unlinked_inode_accounting(ino, !reused_displaced_slot)?;
        }
        Ok(())
    }

    async fn symlink(
        &self,
        parent: u64,
        name: &[u8],
        target: &[u8],
        ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        validate_name(name)?;
        if target.len() as u64 > self.quota.max_symlink_bytes {
            return Err(FuseError::name_too_long());
        }
        let res = self.reserve_inode_guard()?;
        let ino = self.alloc_ino();
        let mut n = Inode::new(S_IFLNK | 0o777, 1, parent, ctx.uid, ctx.gid);
        n.symlink = target.to_vec();
        n.size = target.len() as u64;
        let txn = self.begin()?;
        {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, parent, "symlink parent")?;
            if tt.get((parent, name)).map_err(io)?.is_some() {
                return Err(FuseError::exists());
            }
            iput(&mut it, ino, &n)?;
            tt.insert((parent, name), ino).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        res.commit();
        Ok(n.entry(ino))
    }

    async fn tmpfile(
        &self,
        parent: u64,
        mode: u32,
        flags: u32,
        ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        let access = OpenAccess::from_flags(flags)?;
        let fh = self.alloc_fh()?;
        let res = self.reserve_inode_guard()?;
        let ino = self.alloc_ino();
        let n = Inode::new(S_IFREG | (mode & 0o7777), 0, 0, ctx.uid, ctx.gid);
        let txn = self.begin()?;
        {
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, parent, "tmpfile parent")?;
            iput(&mut it, ino, &n)?;
        }
        txn.commit().map_err(io)?;
        res.commit();
        self.open_handles().insert(
            fh,
            OpenHandle {
                ino,
                access,
                kind: OpenKind::File,
            },
        )?;
        Ok((n.entry(ino), Self::open_out(fh)))
    }

    async fn link(&self, nodeid: u64, np: u64, nn: &[u8]) -> Result<FuseEntryOut, FuseError> {
        validate_name(nn)?;
        let txn = self.begin()?;
        let n = {
            let mut tt = txn.open_table(TREE).map_err(io)?;
            let mut it = txn.open_table(INODES).map_err(io)?;
            load_live_dir(&it, np, "link parent")?;
            if tt.get((np, nn)).map_err(io)?.is_some() {
                return Err(FuseError::exists());
            }
            let n = {
                let mut n = iget(&it, nodeid)?;
                ensure_not_directory(&n)?;
                if n.nlink == 0 {
                    return Err(FuseError::not_found());
                }
                checked_inc_nlink(&mut n, "link inode nlink overflow")?;
                iput(&mut it, nodeid, &n)?;
                n
            };
            tt.insert((np, nn), nodeid).map_err(io)?;
            n
        };
        txn.commit().map_err(io)?;
        Ok(n.entry(nodeid))
    }

    async fn setxattr(
        &self,
        ino: u64,
        name: &[u8],
        val: &[u8],
        flags: u32,
    ) -> Result<(), FuseError> {
        validate_xattr_name(name)?;
        if flags & !(XATTR_CREATE | XATTR_REPLACE) != 0 || flags == (XATTR_CREATE | XATTR_REPLACE) {
            return Err(FuseError::invalid());
        }
        if val.len() as u64 > self.quota.max_xattr_value_bytes {
            return Err(FuseError::too_big());
        }
        let txn = self.begin()?;
        {
            iget(&txn.open_table(INODES).map_err(io)?, ino)?;
            let mut xt = txn.open_table(XATTRS).map_err(io)?;
            let exists = xt.get((ino, name)).map_err(io)?.is_some();
            if flags & XATTR_CREATE != 0 && exists {
                return Err(FuseError::exists());
            }
            if flags & XATTR_REPLACE != 0 && !exists {
                return Err(FuseError::no_data());
            }
            // Count xattrs already on this inode. Cheap because xattrs are
            // keyed by (ino, name) and redb supports range queries.
            if !exists {
                let mut count = 0u64;
                for r in xt
                    .range((ino, &[] as &[u8])..(ino + 1, &[] as &[u8]))
                    .map_err(io)?
                {
                    r.map_err(io)?;
                    count += 1;
                    if count >= self.quota.max_xattrs_per_inode {
                        return Err(FuseError::no_space());
                    }
                }
            }
            xt.insert((ino, name), val).map_err(io)?;
        }
        txn.commit().map_err(io)?;
        Ok(())
    }

    async fn removexattr(&self, ino: u64, name: &[u8]) -> Result<(), FuseError> {
        validate_xattr_name(name)?;
        let txn = self.begin()?;
        iget(&txn.open_table(INODES).map_err(io)?, ino)?;
        let removed = txn
            .open_table(XATTRS)
            .map_err(io)?
            .remove((ino, name))
            .map_err(io)?
            .is_some();
        if !removed {
            return Err(FuseError::no_data());
        }
        txn.commit().map_err(io)?;
        Ok(())
    }

    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        let txn = self.read_txn()?;
        let it = txn.open_table(INODES).map_err(io)?;
        let n = iget(&it, nodeid)?;
        let parent_ino = if n.parent == 0 { nodeid } else { n.parent };
        let p = iget(&it, parent_ino)?;
        Ok(p.entry(parent_ino))
    }

    async fn fsync(&self, ino: u64, fh: u64, _: bool) -> Result<(), FuseError> {
        self.validate_handle(ino, fh, OpenKind::File, false, false, "fsync")?;
        // Durable commit — forces data to disk.
        let txn = self.db.begin_write().map_err(io)?;
        txn.commit().map_err(io)?;
        Ok(())
    }

    async fn flush(&self, ino: u64, fh: u64) -> Result<(), FuseError> {
        self.validate_handle(ino, fh, OpenKind::File, false, false, "flush")
    }

    fn max_write(&self) -> u32 {
        128 * 1024
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::unreadable_literal,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use amla_fuse::fuse::FsBackend;

    fn ctx() -> FuseContext {
        FuseContext { uid: 0, gid: 0 }
    }

    fn ctx_user(uid: u32, gid: u32) -> FuseContext {
        FuseContext { uid, gid }
    }

    fn make_fs() -> (RedbFs, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let fs = RedbFs::create_with_quota(&dir.path().join("test.redb"), RedbFsQuota::unlimited())
            .unwrap();
        (fs, dir)
    }

    fn make_fs_quota(quota: RedbFsQuota) -> (RedbFs, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let fs = RedbFs::create_with_quota(&dir.path().join("test.redb"), quota).unwrap();
        (fs, dir)
    }

    async fn create_rw(fs: &RedbFs, parent: u64, name: &[u8]) -> (FuseEntryOut, FuseOpenOut) {
        fs.create(parent, name, 0o644, O_RDWR, ctx()).await.unwrap()
    }

    async fn create_file(fs: &RedbFs, parent: u64, name: &[u8]) -> FuseEntryOut {
        let (entry, open) = create_rw(fs, parent, name).await;
        fs.release(entry.nodeid, open.fh).await;
        entry
    }

    async fn write_file(fs: &RedbFs, ino: u64, offset: u64, data: &[u8]) -> Result<u32, FuseError> {
        let open = fs.open(ino, O_RDWR).await?;
        let result = fs.write(ino, open.fh, offset, data, 0).await;
        fs.release(ino, open.fh).await;
        result
    }

    fn set_inode_nlink(fs: &RedbFs, ino: u64, nlink: u32) {
        let txn = fs.begin().unwrap();
        {
            let mut it = txn.open_table(INODES).unwrap();
            let mut inode = iget(&it, ino).unwrap();
            inode.nlink = nlink;
            iput(&mut it, ino, &inode).unwrap();
        }
        txn.commit().unwrap();
    }

    async fn read_file(
        fs: &RedbFs,
        ino: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let open = fs.open(ino, O_RDONLY).await?;
        let result = fs.read(ino, open.fh, offset, size).await;
        fs.release(ino, open.fh).await;
        result
    }

    #[tokio::test]
    async fn quota_max_inodes_rejects_create() {
        let quota = RedbFsQuota {
            max_inodes: 3, // root + 2 user-visible
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);

        create_file(&fs, FUSE_ROOT_ID, b"a").await;
        create_file(&fs, FUSE_ROOT_ID, b"b").await;
        // Third create would take us to live_inodes=4 > cap 3.
        assert!(
            fs.create(FUSE_ROOT_ID, b"c", 0o644, 0, ctx())
                .await
                .is_err()
        );
    }

    /// Regression: before the RAII quota guards and unlink-releases, a guest
    /// could hit `max_inodes` once and the FS was permanently ENOSPC — even
    /// after deleting every file. The dpkg-install-then-uninstall pattern
    /// broke on cycle 2. This test walks several install/uninstall cycles
    /// against a tight quota and asserts every cycle succeeds.
    #[tokio::test]
    async fn quota_inodes_recycled_across_unlink() {
        let quota = RedbFsQuota {
            max_inodes: 3, // root + 2 user-visible at a time
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);

        for _ in 0..5 {
            create_file(&fs, FUSE_ROOT_ID, b"a").await;
            create_file(&fs, FUSE_ROOT_ID, b"b").await;
            fs.unlink(FUSE_ROOT_ID, b"a").await.unwrap();
            fs.unlink(FUSE_ROOT_ID, b"b").await.unwrap();
        }
    }

    #[tokio::test]
    async fn quota_reopen_ignores_unlinked_inodes() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            ..RedbFsQuota::unlimited()
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        {
            let fs = RedbFs::create_with_quota(&path, quota).unwrap();
            create_file(&fs, FUSE_ROOT_ID, b"a").await;
            fs.unlink(FUSE_ROOT_ID, b"a").await.unwrap();
        }

        let fs = RedbFs::open_with_quota(&path, quota).unwrap();
        create_file(&fs, FUSE_ROOT_ID, b"b").await;
    }

    #[tokio::test]
    async fn open_reports_live_data_accounting_overflow() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        {
            let fs = RedbFs::create_with_quota(&path, RedbFsQuota::unlimited()).unwrap();
            let txn = fs.begin().unwrap();
            {
                let mut it = txn.open_table(INODES).unwrap();
                let mut huge = Inode::new(S_IFREG | 0o644, 1, FUSE_ROOT_ID, 0, 0);
                huge.size = u64::MAX;
                iput(&mut it, 2, &huge).unwrap();
                let mut one = Inode::new(S_IFREG | 0o644, 1, FUSE_ROOT_ID, 0, 0);
                one.size = 1;
                iput(&mut it, 3, &one).unwrap();
            }
            txn.commit().unwrap();
        }

        assert!(matches!(
            RedbFs::open_with_quota(&path, RedbFsQuota::unlimited()),
            Err(RedbFsError::AccountingInvariant { .. })
        ));
    }

    /// Regression: same pattern for bytes. A 1 KiB budget, repeatedly
    /// written and unlinked, must not monotonically shrink.
    #[tokio::test]
    async fn quota_bytes_recycled_across_unlink() {
        let quota = RedbFsQuota {
            max_data_bytes: 1024,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        for _ in 0..5 {
            let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
            write_file(&fs, entry.nodeid, 0, &[0u8; 1024])
                .await
                .unwrap();
            fs.unlink(FUSE_ROOT_ID, b"f").await.unwrap();
        }
    }

    #[tokio::test]
    async fn quota_rename_overwrite_releases_displaced_inode_and_bytes() {
        let quota = RedbFsQuota {
            max_inodes: 3,
            max_data_bytes: 4,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let a = create_file(&fs, FUSE_ROOT_ID, b"a").await;
        let b = create_file(&fs, FUSE_ROOT_ID, b"b").await;
        write_file(&fs, a.nodeid, 0, b"aa").await.unwrap();
        write_file(&fs, b.nodeid, 0, b"bb").await.unwrap();

        fs.rename(FUSE_ROOT_ID, b"a", FUSE_ROOT_ID, b"b")
            .await
            .unwrap();
        let c = create_file(&fs, FUSE_ROOT_ID, b"c").await;
        write_file(&fs, c.nodeid, 0, b"cc").await.unwrap();
    }

    /// Regression: rmdir reclaims the directory's inode slot.
    #[tokio::test]
    async fn quota_rmdir_releases_inode() {
        let quota = RedbFsQuota {
            max_inodes: 3,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        for _ in 0..5 {
            fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
            fs.rmdir(FUSE_ROOT_ID, b"d").await.unwrap();
        }
    }

    #[tokio::test]
    async fn rmdir_parent_nlink_drift_fails_without_clamping() {
        let (fs, _td) = make_fs();
        fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        set_inode_nlink(&fs, FUSE_ROOT_ID, 1);

        let err = fs.rmdir(FUSE_ROOT_ID, b"d").await.unwrap_err();
        assert_eq!(err, FuseError::io());
        let txn = fs.read_txn().unwrap();
        let root = iget(&txn.open_table(INODES).unwrap(), FUSE_ROOT_ID).unwrap();
        assert_eq!(root.nlink, 1);
        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_ok());
    }

    #[tokio::test]
    async fn rmdir_removed_dir_nlink_drift_fails_without_clamping() {
        let (fs, _td) = make_fs();
        let dir = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        set_inode_nlink(&fs, dir.nodeid, 3);

        let err = fs.rmdir(FUSE_ROOT_ID, b"d").await.unwrap_err();
        assert_eq!(err, FuseError::io());

        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_ok());
        let txn = fs.read_txn().unwrap();
        let inode = iget(&txn.open_table(INODES).unwrap(), dir.nodeid).unwrap();
        assert_eq!(inode.nlink, 3);
    }

    #[tokio::test]
    async fn rename_over_empty_dir_nlink_drift_fails_without_clamping() {
        let (fs, _td) = make_fs();
        fs.mkdir(FUSE_ROOT_ID, b"src", 0o755, ctx()).await.unwrap();
        let dst = fs.mkdir(FUSE_ROOT_ID, b"dst", 0o755, ctx()).await.unwrap();
        set_inode_nlink(&fs, dst.nodeid, 3);

        let err = fs
            .rename(FUSE_ROOT_ID, b"src", FUSE_ROOT_ID, b"dst")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::io());

        assert!(fs.lookup(FUSE_ROOT_ID, b"src").await.is_ok());
        assert!(fs.lookup(FUSE_ROOT_ID, b"dst").await.is_ok());
        let txn = fs.read_txn().unwrap();
        let inode = iget(&txn.open_table(INODES).unwrap(), dst.nodeid).unwrap();
        assert_eq!(inode.nlink, 3);
    }

    #[tokio::test]
    async fn required_cleanup_rejects_missing_inode() {
        let (fs, _td) = make_fs();
        let err = fs.cleanup_required_unlinked_inode(999).unwrap_err();
        assert_eq!(err, FuseError::io());
    }

    #[tokio::test]
    async fn required_cleanup_rejects_still_linked_inode() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let err = fs
            .cleanup_required_unlinked_inode(entry.nodeid)
            .unwrap_err();
        assert_eq!(err, FuseError::io());
        assert!(fs.lookup(FUSE_ROOT_ID, b"f").await.is_ok());
    }

    /// Quota release drift is an invariant violation. A stray extra release
    /// used to saturate at zero, hiding double-release bugs and letting the
    /// in-memory counter diverge from the inode table.
    #[tokio::test]
    async fn release_bytes_reports_accounting_drift() {
        let (fs, _td) = make_fs();
        let err = fs.release_bytes(1_000_000).unwrap_err();
        assert_eq!(err, FuseError::io());
        assert_eq!(fs.live_data_bytes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn release_inode_reports_accounting_drift() {
        let (fs, _td) = make_fs();
        fs.live_inodes.store(0, Ordering::Relaxed);

        let err = fs.release_inode().unwrap_err();
        assert_eq!(err, FuseError::io());
        assert_eq!(fs.live_inodes.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn release_cleanup_accounting_drift_poisons_future_mutation() {
        let (fs, _td) = make_fs();
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"f").await;
        fs.write(entry.nodeid, open.fh, 0, b"data", 0)
            .await
            .unwrap();
        fs.unlink(FUSE_ROOT_ID, b"f").await.unwrap();

        fs.live_data_bytes.store(0, Ordering::Relaxed);
        fs.release(entry.nodeid, open.fh).await;

        assert_eq!(fs.statfs().await.unwrap_err(), FuseError::io());
        let err = fs
            .create(FUSE_ROOT_ID, b"blocked", 0o644, O_RDWR, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::io());
    }

    #[tokio::test]
    async fn quota_max_bytes_rejects_write() {
        let quota = RedbFsQuota {
            max_data_bytes: 1024,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        // First 1 KiB fits.
        let ok = write_file(&fs, entry.nodeid, 0, &[0u8; 1024])
            .await
            .unwrap();
        assert_eq!(ok, 1024);
        // One more byte would exceed the budget.
        assert!(
            write_file(&fs, entry.nodeid, 1024, &[0u8; 1])
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn quota_xattr_value_size_rejected() {
        let quota = RedbFsQuota {
            max_xattr_value_bytes: 8,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        assert!(
            fs.setxattr(entry.nodeid, b"user.ok", &[0u8; 8], 0)
                .await
                .is_ok()
        );
        assert!(
            fs.setxattr(entry.nodeid, b"user.big", &[0u8; 9], 0)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn quota_symlink_length_rejected() {
        let quota = RedbFsQuota {
            max_symlink_bytes: 4,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        assert!(
            fs.symlink(FUSE_ROOT_ID, b"ok", b"tgt!", ctx())
                .await
                .is_ok()
        );
        assert!(
            fs.symlink(FUSE_ROOT_ID, b"bad", b"toolong!", ctx())
                .await
                .is_err()
        );
    }

    // ── Basic file operations ─────────────────────────────────────────

    #[tokio::test]
    async fn create_and_lookup() {
        let (fs, _td) = make_fs();
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"hello").await;
        assert!(entry.nodeid >= 2);
        assert!(open.fh >= 1);
        fs.release(entry.nodeid, open.fh).await;

        let looked = fs.lookup(FUSE_ROOT_ID, b"hello").await.unwrap();
        assert_eq!(looked.nodeid, entry.nodeid);
        assert_eq!(looked.attr.mode, S_IFREG | 0o644);
    }

    #[tokio::test]
    async fn lookup_nonexistent_returns_not_found() {
        let (fs, _td) = make_fs();
        let err = fs.lookup(FUSE_ROOT_ID, b"nope").await;
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn write_and_read_small() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        let data = b"hello world";
        let written = write_file(&fs, ino, 0, data).await.unwrap();
        assert_eq!(written, data.len() as u32);

        let read_back = read_file(&fs, ino, 0, 64).await.unwrap();
        assert_eq!(&read_back, data);

        let attr = fs.getattr(ino).await.unwrap();
        assert_eq!(attr.attr.size, data.len() as u64);
    }

    #[tokio::test]
    async fn write_and_read_multi_chunk() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"big").await;
        let ino = entry.nodeid;

        let data = vec![0xABu8; 300 * 1024];
        write_file(&fs, ino, 0, &data).await.unwrap();

        let read_back = read_file(&fs, ino, 0, 300 * 1024).await.unwrap();
        assert_eq!(read_back.len(), 300 * 1024);
        assert_eq!(read_back, data);
    }

    #[tokio::test]
    async fn write_partial_chunk_read_modify_write() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        write_file(&fs, ino, 0, b"AAAA").await.unwrap();
        write_file(&fs, ino, 1, b"BB").await.unwrap();

        let got = read_file(&fs, ino, 0, 10).await.unwrap();
        assert_eq!(&got, b"ABBA");
    }

    #[tokio::test]
    async fn read_past_eof_returns_empty() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;
        write_file(&fs, ino, 0, b"hi").await.unwrap();

        let got = read_file(&fs, ino, 100, 10).await.unwrap();
        assert!(got.is_empty());
    }

    #[tokio::test]
    async fn sparse_file_reads_zeros() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        // Write at offset 256K (skipping chunks 0 and 1).
        write_file(&fs, ino, 256 * 1024, b"data").await.unwrap();

        let gap = read_file(&fs, ino, 0, 16).await.unwrap();
        assert_eq!(gap, vec![0u8; 16]);
    }

    /// Regression: reading the sparse tail of a partially-written chunk must
    /// return zeros instead of panicking (underflow) or hanging (infinite loop).
    ///
    /// Setup: chunk 0 stores only a few bytes at its head. File size is grown
    /// past that via a second write so the sparse tail is addressable.
    ///
    /// This exercises both failure modes of the pre-fix code:
    ///   - underflow: read with `offset` strictly greater than the stored
    ///     bytes but within the same chunk.
    ///   - infinite loop: read a range that starts inside the stored bytes
    ///     and extends past them (so the loop hits `co == val.len()` on a
    ///     subsequent iteration).
    /// Assert the returned buffer has the right length and the hole bytes
    /// are zero.
    #[tokio::test]
    async fn sparse_tail_within_chunk_reads_zeros() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        write_file(&fs, ino, 0, b"abc").await.unwrap();
        write_file(&fs, ino, CHUNK, b"x").await.unwrap();

        // Old code computed `val.len() - co` with co > val.len().
        let underflow = read_file(&fs, ino, 8, 4).await.unwrap();
        assert_eq!(underflow, vec![0u8; 4]);

        // Old code consumed `c`, then made no progress once co == val.len().
        let crosses_tail = read_file(&fs, ino, 2, 4).await.unwrap();
        assert_eq!(crosses_tail, vec![b'c', 0, 0, 0]);
    }

    #[tokio::test]
    async fn huge_write_and_truncate_reject_before_chunk_zero_alias() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        write_file(&fs, ino, 0, b"safe").await.unwrap();

        let err = write_file(&fs, ino, MAX_FILE_SIZE, b"X").await.unwrap_err();
        assert_eq!(err, FuseError::file_too_big());
        assert_eq!(read_file(&fs, ino, 0, 8).await.unwrap(), b"safe".to_vec());

        let args = FuseSetattrIn {
            valid: FATTR_SIZE,
            size: MAX_FILE_SIZE + 1,
            ..FuseSetattrIn::default()
        };
        let err = fs.setattr(ino, &args).await.unwrap_err();
        assert_eq!(err, FuseError::file_too_big());

        let attr = fs.getattr(ino).await.unwrap();
        assert_eq!(attr.attr.size, 4);
        assert_eq!(read_file(&fs, ino, 0, 8).await.unwrap(), b"safe".to_vec());
    }

    #[tokio::test]
    async fn regular_file_io_rejects_directories() {
        let (fs, _td) = make_fs();
        let dir = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();

        let err = fs.read(dir.nodeid, 0, 0, 64).await.unwrap_err();
        assert_eq!(err, FuseError::bad_fd());

        let err = fs.write(dir.nodeid, 0, 0, b"x", 0).await.unwrap_err();
        assert_eq!(err, FuseError::bad_fd());

        let args = FuseSetattrIn {
            valid: FATTR_SIZE,
            size: 1,
            ..FuseSetattrIn::default()
        };
        let err = fs.setattr(dir.nodeid, &args).await.unwrap_err();
        assert_eq!(err, FuseError::is_dir());
    }

    // ── Directory operations ──────────────────────────────────────────

    #[tokio::test]
    async fn mkdir_and_readdir() {
        let (fs, _td) = make_fs();
        let dir = fs
            .mkdir(FUSE_ROOT_ID, b"subdir", 0o755, ctx())
            .await
            .unwrap();
        assert_eq!(dir.attr.mode, S_IFDIR | 0o755);
        assert_eq!(dir.attr.nlink, 2);

        let root_attr = fs.getattr(FUSE_ROOT_ID).await.unwrap();
        assert_eq!(root_attr.attr.nlink, 3);

        let root = fs.opendir(FUSE_ROOT_ID).await.unwrap();
        let buf = fs.readdir(FUSE_ROOT_ID, root.fh, 0, 4096).await.unwrap();
        fs.releasedir(FUSE_ROOT_ID, root.fh).await;
        assert!(!buf.is_empty());
    }

    #[tokio::test]
    async fn namespace_creators_reject_non_directory_parent() {
        let (fs, _td) = make_fs();
        let file = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let err = fs
            .create(file.nodeid, b"child", 0o644, 0, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());

        let err = fs
            .mkdir(file.nodeid, b"child", 0o755, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());

        let err = fs
            .mknod(file.nodeid, b"child", S_IFCHR | 0o666, 0, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());

        let err = fs
            .symlink(file.nodeid, b"child", b"target", ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());

        let err = fs.tmpfile(file.nodeid, 0o644, 0, ctx()).await.unwrap_err();
        assert_eq!(err, FuseError::not_dir());
    }

    #[tokio::test]
    async fn rmdir_empty() {
        let (fs, _td) = make_fs();
        fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        fs.rmdir(FUSE_ROOT_ID, b"d").await.unwrap();

        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_err());
        let attr = fs.getattr(FUSE_ROOT_ID).await.unwrap();
        assert_eq!(attr.attr.nlink, 2);
    }

    #[tokio::test]
    async fn rmdir_nonempty_fails() {
        let (fs, _td) = make_fs();
        let d = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        create_file(&fs, d.nodeid, b"f").await;

        assert!(fs.rmdir(FUSE_ROOT_ID, b"d").await.is_err());
    }

    #[tokio::test]
    async fn unlink_rejects_directory() {
        let (fs, _td) = make_fs();
        fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();

        let err = fs.unlink(FUSE_ROOT_ID, b"d").await.unwrap_err();
        assert_eq!(err, FuseError::is_dir());
        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_ok());
    }

    #[tokio::test]
    async fn rmdir_rejects_non_directory() {
        let (fs, _td) = make_fs();
        create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let err = fs.rmdir(FUSE_ROOT_ID, b"f").await.unwrap_err();
        assert_eq!(err, FuseError::not_dir());
        assert!(fs.lookup(FUSE_ROOT_ID, b"f").await.is_ok());
    }

    // ── Inode lifecycle (ESTALE prevention) ───────────────────────────

    #[tokio::test]
    async fn unlinked_inode_remains_accessible() {
        let (fs, _td) = make_fs();

        let (entry, old_open) = create_rw(&fs, FUSE_ROOT_ID, b"status").await;
        let old_ino = entry.nodeid;
        fs.write(old_ino, old_open.fh, 0, b"old content", 0)
            .await
            .unwrap();

        let (entry2, new_open) = create_rw(&fs, FUSE_ROOT_ID, b"status-new").await;
        let new_ino = entry2.nodeid;
        fs.write(new_ino, new_open.fh, 0, b"new content", 0)
            .await
            .unwrap();
        fs.release(new_ino, new_open.fh).await;

        fs.rename(FUSE_ROOT_ID, b"status-new", FUSE_ROOT_ID, b"status")
            .await
            .unwrap();

        let looked = fs.lookup(FUSE_ROOT_ID, b"status").await.unwrap();
        assert_eq!(looked.nodeid, new_ino);

        let attr = fs.getattr(old_ino).await;
        assert!(attr.is_ok(), "getattr on displaced inode must not ENOENT");
        assert_eq!(attr.unwrap().attr.size, 11);

        let data = fs.read(old_ino, old_open.fh, 0, 64).await.unwrap();
        assert_eq!(&data, b"old content");
        fs.release(old_ino, old_open.fh).await;
    }

    #[tokio::test]
    async fn unlink_preserves_inode_for_open_fd() {
        let (fs, _td) = make_fs();

        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"tmp").await;
        let ino = entry.nodeid;
        fs.write(ino, open.fh, 0, b"keep me", 0).await.unwrap();

        fs.unlink(FUSE_ROOT_ID, b"tmp").await.unwrap();
        assert!(fs.lookup(FUSE_ROOT_ID, b"tmp").await.is_err());

        let attr = fs.getattr(ino).await;
        assert!(attr.is_ok(), "getattr after unlink must succeed");
        let data = fs.read(ino, open.fh, 0, 64).await.unwrap();
        assert_eq!(&data, b"keep me");
        fs.release(ino, open.fh).await;
    }

    #[tokio::test]
    async fn release_after_unlink_does_not_double_release_inode_quota() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"tmp").await;

        fs.unlink(FUSE_ROOT_ID, b"tmp").await.unwrap();
        assert!(
            fs.create(FUSE_ROOT_ID, b"blocked", 0o644, O_RDWR, ctx())
                .await
                .is_err()
        );

        fs.release(entry.nodeid, open.fh).await;
        create_file(&fs, FUSE_ROOT_ID, b"next").await;
        let err = fs
            .create(FUSE_ROOT_ID, b"extra", 0o644, O_RDWR, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_space());
    }

    #[tokio::test]
    async fn forged_and_stale_file_handles_are_rejected() {
        let (fs, _td) = make_fs();
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"cap").await;

        assert_eq!(
            fs.read(entry.nodeid, open.fh + 1, 0, 1).await.unwrap_err(),
            FuseError::bad_fd()
        );
        assert_eq!(
            fs.write(entry.nodeid, open.fh + 1, 0, b"x", 0)
                .await
                .unwrap_err(),
            FuseError::bad_fd()
        );

        fs.release(entry.nodeid, open.fh).await;
        assert_eq!(
            fs.read(entry.nodeid, open.fh, 0, 1).await.unwrap_err(),
            FuseError::bad_fd()
        );
    }

    #[tokio::test]
    async fn unlink_while_open_keeps_quota_and_valid_handle_access() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            max_data_bytes: 4,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"tmp").await;
        fs.write(entry.nodeid, open.fh, 0, b"data", 0)
            .await
            .unwrap();

        fs.unlink(FUSE_ROOT_ID, b"tmp").await.unwrap();
        assert_eq!(fs.live_inodes.load(Ordering::Relaxed), 2);
        assert_eq!(fs.live_data_bytes.load(Ordering::Relaxed), 4);
        assert_eq!(
            fs.create(FUSE_ROOT_ID, b"blocked", 0o644, O_RDWR, ctx())
                .await
                .unwrap_err(),
            FuseError::no_space()
        );
        assert_eq!(
            fs.read(entry.nodeid, open.fh, 0, 8).await.unwrap(),
            b"data".to_vec()
        );
    }

    #[tokio::test]
    async fn final_release_cleans_unlinked_inode_and_accounting() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            max_data_bytes: 4,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"tmp").await;
        fs.write(entry.nodeid, open.fh, 0, b"data", 0)
            .await
            .unwrap();
        fs.unlink(FUSE_ROOT_ID, b"tmp").await.unwrap();

        fs.release(entry.nodeid, open.fh).await;
        assert_eq!(
            fs.getattr(entry.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
        assert_eq!(fs.live_inodes.load(Ordering::Relaxed), 1);
        assert_eq!(fs.live_data_bytes.load(Ordering::Relaxed), 0);

        let next = create_file(&fs, FUSE_ROOT_ID, b"next").await;
        write_file(&fs, next.nodeid, 0, b"data").await.unwrap();
    }

    #[tokio::test]
    async fn multiple_open_handles_do_not_double_release() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let (entry, first) = create_rw(&fs, FUSE_ROOT_ID, b"tmp").await;
        let second = fs.open(entry.nodeid, O_RDWR).await.unwrap();

        fs.unlink(FUSE_ROOT_ID, b"tmp").await.unwrap();
        fs.release(entry.nodeid, first.fh).await;
        fs.release(entry.nodeid, first.fh).await;
        assert_eq!(fs.live_inodes.load(Ordering::Relaxed), 2);
        assert_eq!(
            fs.create(FUSE_ROOT_ID, b"blocked", 0o644, O_RDWR, ctx())
                .await
                .unwrap_err(),
            FuseError::no_space()
        );

        fs.release(entry.nodeid, second.fh).await;
        assert_eq!(fs.live_inodes.load(Ordering::Relaxed), 1);
        create_file(&fs, FUSE_ROOT_ID, b"next").await;
    }

    #[tokio::test]
    async fn rmdir_preserves_inode() {
        let (fs, _td) = make_fs();
        let d = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        fs.rmdir(FUSE_ROOT_ID, b"d").await.unwrap();
        assert_eq!(
            fs.getattr(d.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
    }

    // ── xattr (overlayfs compatibility) ──────────────────────────────

    #[tokio::test]
    async fn getxattr_size_probe_returns_full_value() {
        let (fs, _td) = make_fs();

        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        let origin = vec![0xAB; 20];
        fs.setxattr(ino, b"trusted.overlay.origin", &origin, 0)
            .await
            .unwrap();

        let probe = fs
            .getxattr(ino, b"trusted.overlay.origin", 0)
            .await
            .unwrap();
        assert_eq!(probe.len(), 20);

        let got = fs
            .getxattr(ino, b"trusted.overlay.origin", 20)
            .await
            .unwrap();
        assert_eq!(got, origin);

        assert!(
            fs.getxattr(ino, b"trusted.overlay.origin", 4)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn listxattr_size_probe() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        fs.setxattr(ino, b"user.a", b"val1", 0).await.unwrap();
        fs.setxattr(ino, b"user.b", b"val2", 0).await.unwrap();

        let list = fs.listxattr(ino, 0).await.unwrap();
        assert!(!list.is_empty());
        assert!(list.contains(&0));

        let exact = fs.listxattr(ino, list.len() as u32).await.unwrap();
        assert_eq!(exact.len(), list.len());

        assert!(fs.listxattr(ino, 1).await.is_err());
    }

    #[tokio::test]
    async fn getxattr_nonexistent_returns_no_data() {
        let (fs, _td) = make_fs();
        let err = fs
            .getxattr(FUSE_ROOT_ID, b"user.nope", 0)
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_data());
    }

    #[tokio::test]
    async fn setxattr_flags_follow_create_replace_semantics() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        let err = fs
            .setxattr(ino, b"user.key", b"missing", XATTR_REPLACE)
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_data());

        fs.setxattr(ino, b"user.key", b"one", XATTR_CREATE)
            .await
            .unwrap();

        let err = fs
            .setxattr(ino, b"user.key", b"again", XATTR_CREATE)
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::exists());

        fs.setxattr(ino, b"user.key", b"two", XATTR_REPLACE)
            .await
            .unwrap();
        let got = fs.getxattr(ino, b"user.key", 3).await.unwrap();
        assert_eq!(got, b"two".to_vec());

        let err = fs
            .setxattr(ino, b"user.key", b"bad", XATTR_CREATE | XATTR_REPLACE)
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::invalid());
    }

    #[tokio::test]
    async fn removexattr_works() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        fs.setxattr(ino, b"user.key", b"val", 0).await.unwrap();
        fs.removexattr(ino, b"user.key").await.unwrap();
        let err = fs.getxattr(ino, b"user.key", 0).await.unwrap_err();
        assert_eq!(err, FuseError::no_data());
    }

    #[tokio::test]
    async fn removexattr_missing_returns_no_data() {
        let (fs, _td) = make_fs();
        let err = fs
            .removexattr(FUSE_ROOT_ID, b"user.nope")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_data());
    }

    // ── Rename ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn rename_simple() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"old").await;
        let ino = entry.nodeid;

        fs.rename(FUSE_ROOT_ID, b"old", FUSE_ROOT_ID, b"new")
            .await
            .unwrap();

        assert!(fs.lookup(FUSE_ROOT_ID, b"old").await.is_err());
        assert_eq!(fs.lookup(FUSE_ROOT_ID, b"new").await.unwrap().nodeid, ino);
    }

    #[tokio::test]
    async fn rename_across_directories() {
        let (fs, _td) = make_fs();
        let d1 = fs.mkdir(FUSE_ROOT_ID, b"d1", 0o755, ctx()).await.unwrap();
        let d2 = fs.mkdir(FUSE_ROOT_ID, b"d2", 0o755, ctx()).await.unwrap();
        let entry = create_file(&fs, d1.nodeid, b"f").await;

        fs.rename(d1.nodeid, b"f", d2.nodeid, b"f").await.unwrap();

        assert!(fs.lookup(d1.nodeid, b"f").await.is_err());
        assert_eq!(
            fs.lookup(d2.nodeid, b"f").await.unwrap().nodeid,
            entry.nodeid
        );
    }

    #[tokio::test]
    async fn rename_overwrite_existing() {
        let (fs, _td) = make_fs();
        let e1 = create_file(&fs, FUSE_ROOT_ID, b"a").await;
        let e2 = create_file(&fs, FUSE_ROOT_ID, b"b").await;

        fs.rename(FUSE_ROOT_ID, b"a", FUSE_ROOT_ID, b"b")
            .await
            .unwrap();

        assert_eq!(
            fs.lookup(FUSE_ROOT_ID, b"b").await.unwrap().nodeid,
            e1.nodeid
        );
        assert_eq!(
            fs.getattr(e2.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
    }

    #[tokio::test]
    async fn rename_overwrite_nonempty_dir_fails() {
        let (fs, _td) = make_fs();
        fs.mkdir(FUSE_ROOT_ID, b"d1", 0o755, ctx()).await.unwrap();
        let d2 = fs.mkdir(FUSE_ROOT_ID, b"d2", 0o755, ctx()).await.unwrap();
        create_file(&fs, d2.nodeid, b"child").await;

        assert!(
            fs.rename(FUSE_ROOT_ID, b"d1", FUSE_ROOT_ID, b"d2")
                .await
                .is_err()
        );
        assert!(fs.lookup(FUSE_ROOT_ID, b"d1").await.is_ok());
        assert!(fs.lookup(FUSE_ROOT_ID, b"d2").await.is_ok());
    }

    #[tokio::test]
    async fn rename_rejects_file_directory_type_mismatch() {
        let (fs, _td) = make_fs();
        create_file(&fs, FUSE_ROOT_ID, b"f").await;
        fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();

        let err = fs
            .rename(FUSE_ROOT_ID, b"f", FUSE_ROOT_ID, b"d")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::is_dir());

        let err = fs
            .rename(FUSE_ROOT_ID, b"d", FUSE_ROOT_ID, b"f")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());
    }

    #[tokio::test]
    async fn rename_directory_across_parents_updates_link_counts() {
        let (fs, _td) = make_fs();
        let d1 = fs.mkdir(FUSE_ROOT_ID, b"d1", 0o755, ctx()).await.unwrap();
        let d2 = fs.mkdir(FUSE_ROOT_ID, b"d2", 0o755, ctx()).await.unwrap();
        let child = fs.mkdir(d1.nodeid, b"child", 0o755, ctx()).await.unwrap();

        fs.rename(d1.nodeid, b"child", d2.nodeid, b"child")
            .await
            .unwrap();

        assert_eq!(fs.getattr(d1.nodeid).await.unwrap().attr.nlink, 2);
        assert_eq!(fs.getattr(d2.nodeid).await.unwrap().attr.nlink, 3);
        assert_eq!(
            fs.lookup(d2.nodeid, b"child").await.unwrap().nodeid,
            child.nodeid
        );
    }

    #[tokio::test]
    async fn rename_overwrite_empty_dir_releases_inode_quota() {
        let quota = RedbFsQuota {
            max_inodes: 3,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        fs.mkdir(FUSE_ROOT_ID, b"a", 0o755, ctx()).await.unwrap();
        fs.mkdir(FUSE_ROOT_ID, b"b", 0o755, ctx()).await.unwrap();

        fs.rename(FUSE_ROOT_ID, b"a", FUSE_ROOT_ID, b"b")
            .await
            .unwrap();
        fs.mkdir(FUSE_ROOT_ID, b"c", 0o755, ctx()).await.unwrap();
    }

    #[tokio::test]
    async fn rename_rejects_directory_into_descendant() {
        let (fs, _td) = make_fs();
        let d = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        let child = fs.mkdir(d.nodeid, b"child", 0o755, ctx()).await.unwrap();

        let err = fs
            .rename(FUSE_ROOT_ID, b"d", child.nodeid, b"moved")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::invalid());
        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_ok());
    }

    // ── Rename whiteout (overlayfs) ──────────────────────────────────

    #[tokio::test]
    async fn rename_whiteout_creates_chardev() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        fs.rename_whiteout(FUSE_ROOT_ID, b"f", FUSE_ROOT_ID, b"f_moved")
            .await
            .unwrap();

        assert_eq!(
            fs.lookup(FUSE_ROOT_ID, b"f_moved").await.unwrap().nodeid,
            entry.nodeid
        );

        let wo = fs.lookup(FUSE_ROOT_ID, b"f").await.unwrap();
        assert_ne!(wo.nodeid, entry.nodeid);
        assert_eq!(wo.attr.mode & S_IFMT, S_IFCHR);
        assert_eq!(wo.attr.rdev, 0);
    }

    #[tokio::test]
    async fn rename_whiteout_rejects_file_directory_type_mismatch() {
        let (fs, _td) = make_fs();
        create_file(&fs, FUSE_ROOT_ID, b"f").await;
        fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();

        let err = fs
            .rename_whiteout(FUSE_ROOT_ID, b"f", FUSE_ROOT_ID, b"d")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::is_dir());

        let err = fs
            .rename_whiteout(FUSE_ROOT_ID, b"d", FUSE_ROOT_ID, b"f")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());
    }

    #[tokio::test]
    async fn rename_whiteout_rejects_directory_into_descendant() {
        let (fs, _td) = make_fs();
        let d = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        let child = fs.mkdir(d.nodeid, b"child", 0o755, ctx()).await.unwrap();

        let err = fs
            .rename_whiteout(FUSE_ROOT_ID, b"d", child.nodeid, b"moved")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::invalid());
        assert!(fs.lookup(FUSE_ROOT_ID, b"d").await.is_ok());
    }

    #[tokio::test]
    async fn rename_whiteout_rejects_non_directory_parents() {
        let (fs, _td) = make_fs();
        let file = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        create_file(&fs, FUSE_ROOT_ID, b"source").await;

        let err = fs
            .rename_whiteout(file.nodeid, b"source", FUSE_ROOT_ID, b"dest")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());

        let err = fs
            .rename_whiteout(FUSE_ROOT_ID, b"source", file.nodeid, b"dest")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::not_dir());
        assert!(fs.lookup(FUSE_ROOT_ID, b"source").await.is_ok());
    }

    // ── Symlinks ─────────────────────────────────────────────────────

    #[tokio::test]
    async fn symlink_and_readlink() {
        let (fs, _td) = make_fs();
        let entry = fs
            .symlink(FUSE_ROOT_ID, b"link", b"/target/path", ctx())
            .await
            .unwrap();
        assert_eq!(entry.attr.mode & S_IFMT, S_IFLNK);
        assert_eq!(entry.attr.size, 12);

        let target = fs.readlink(entry.nodeid).await.unwrap();
        assert_eq!(&target, b"/target/path");
    }

    #[tokio::test]
    async fn readlink_on_non_symlink_fails() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        assert!(fs.readlink(entry.nodeid).await.is_err());
    }

    // ── Hardlinks ────────────────────────────────────────────────────

    #[tokio::test]
    async fn hardlink() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"orig").await;
        write_file(&fs, entry.nodeid, 0, b"shared data")
            .await
            .unwrap();

        let linked = fs.link(entry.nodeid, FUSE_ROOT_ID, b"alias").await.unwrap();
        assert_eq!(linked.nodeid, entry.nodeid);
        assert_eq!(linked.attr.nlink, 2);

        assert_eq!(
            fs.lookup(FUSE_ROOT_ID, b"orig").await.unwrap().nodeid,
            fs.lookup(FUSE_ROOT_ID, b"alias").await.unwrap().nodeid
        );
    }

    #[tokio::test]
    async fn hardlink_rejects_directory() {
        let (fs, _td) = make_fs();
        let dir = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();

        let err = fs
            .link(dir.nodeid, FUSE_ROOT_ID, b"alias")
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::is_dir());
    }

    // ── mknod ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mknod_chardev() {
        let (fs, _td) = make_fs();
        let entry = fs
            .mknod(FUSE_ROOT_ID, b"null", S_IFCHR | 0o666, 259, ctx())
            .await
            .unwrap();
        assert_eq!(entry.attr.mode, S_IFCHR | 0o666);
        assert_eq!(entry.attr.rdev, 259);
    }

    // ── tmpfile (O_TMPFILE) ──────────────────────────────────────────

    #[tokio::test]
    async fn tmpfile_no_name_in_tree() {
        let (fs, _td) = make_fs();
        let (entry, open) = fs
            .tmpfile(FUSE_ROOT_ID, 0o644, O_RDWR, ctx())
            .await
            .unwrap();
        assert!(open.fh >= 1);

        fs.write(entry.nodeid, open.fh, 0, b"anon data", 0)
            .await
            .unwrap();
        let data = fs.read(entry.nodeid, open.fh, 0, 64).await.unwrap();
        assert_eq!(&data, b"anon data");
        fs.release(entry.nodeid, open.fh).await;
    }

    #[tokio::test]
    async fn tmpfile_release_removes_anonymous_inode_and_releases_quota() {
        let quota = RedbFsQuota {
            max_inodes: 2,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);
        let (entry, open) = fs
            .tmpfile(FUSE_ROOT_ID, 0o644, O_RDWR, ctx())
            .await
            .unwrap();
        fs.write(entry.nodeid, open.fh, 0, b"anon", 0)
            .await
            .unwrap();

        let err = fs
            .create(FUSE_ROOT_ID, b"blocked", 0o644, 0, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_space());

        fs.release(entry.nodeid, open.fh).await;
        assert_eq!(
            fs.getattr(entry.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
        create_file(&fs, FUSE_ROOT_ID, b"ok").await;
    }

    // ── setattr ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn setattr_chmod() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let mut args = FuseSetattrIn::default();
        args.valid = FATTR_MODE;
        args.mode = 0o755;
        let result = fs.setattr(entry.nodeid, &args).await.unwrap();
        assert_eq!(result.attr.mode, S_IFREG | 0o755);
    }

    #[tokio::test]
    async fn setattr_chown() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let mut args = FuseSetattrIn::default();
        args.valid = FATTR_UID | FATTR_GID;
        args.uid = 1000;
        args.gid = 1000;
        let result = fs.setattr(entry.nodeid, &args).await.unwrap();
        assert_eq!(result.attr.uid, 1000);
        assert_eq!(result.attr.gid, 1000);
    }

    #[tokio::test]
    async fn setattr_truncate() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        write_file(&fs, ino, 0, &vec![0xAB; 256 * 1024])
            .await
            .unwrap();

        let mut args = FuseSetattrIn::default();
        args.valid = FATTR_SIZE;
        args.size = 10;
        fs.setattr(ino, &args).await.unwrap();

        let attr = fs.getattr(ino).await.unwrap();
        assert_eq!(attr.attr.size, 10);

        let data = read_file(&fs, ino, 0, 64).await.unwrap();
        assert_eq!(data.len(), 10);
        assert_eq!(data[0], 0xAB);
    }

    #[tokio::test]
    async fn setattr_truncate_zeros_retained_chunk_tail() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;
        let ino = entry.nodeid;

        write_file(&fs, ino, 0, b"abcdefghij").await.unwrap();
        let mut args = FuseSetattrIn {
            valid: FATTR_SIZE,
            size: 4,
            ..FuseSetattrIn::default()
        };
        fs.setattr(ino, &args).await.unwrap();

        write_file(&fs, ino, 6, b"Z").await.unwrap();
        let data = read_file(&fs, ino, 0, 16).await.unwrap();
        assert_eq!(&data, b"abcd\0\0Z");

        args.size = 10;
        fs.setattr(ino, &args).await.unwrap();
        let grown = read_file(&fs, ino, 0, 16).await.unwrap();
        assert_eq!(&grown, b"abcd\0\0Z\0\0\0");
    }

    #[tokio::test]
    async fn setattr_mtime() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"f").await;

        let mut args = FuseSetattrIn::default();
        args.valid = FATTR_MTIME;
        args.mtime = 1700000000;
        args.mtimensec = 123456789;
        let result = fs.setattr(entry.nodeid, &args).await.unwrap();
        assert_eq!(result.attr.mtime, 1700000000);
        assert_eq!(result.attr.mtimensec, 123456789);
    }

    // ── uid/gid propagation ──────────────────────────────────────────

    #[tokio::test]
    async fn create_preserves_uid_gid() {
        let (fs, _td) = make_fs();
        let (entry, open) = fs
            .create(FUSE_ROOT_ID, b"f", 0o644, O_RDWR, ctx_user(1000, 1000))
            .await
            .unwrap();
        fs.release(entry.nodeid, open.fh).await;
        assert_eq!(entry.attr.uid, 1000);
        assert_eq!(entry.attr.gid, 1000);
    }

    // ── access ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn access_existing_succeeds() {
        let (fs, _td) = make_fs();
        assert!(fs.access(FUSE_ROOT_ID, 0).await.is_ok());
    }

    #[tokio::test]
    async fn access_nonexistent_fails() {
        let (fs, _td) = make_fs();
        assert!(fs.access(999999, 0).await.is_err());
    }

    // ── statfs ────────────────────────────────────────────────────────

    #[tokio::test]
    async fn statfs_returns_reasonable_values() {
        let (fs, _td) = make_fs();
        let st = fs.statfs().await.unwrap();
        assert!(st.st.blocks > 0);
        assert!(st.st.bsize > 0);
        assert!(st.st.frsize > 0);
    }

    #[tokio::test]
    async fn statfs_advertises_max_disk_usage_quota() {
        // 1 MiB quota should show through as both total size and available
        // bytes. After using half, bavail shrinks to match — this is what
        // the guest's `df` and apt's pre-install checks read.
        let quota = RedbFsQuota {
            max_data_bytes: 1024 * 1024,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);

        let before = fs.statfs().await.unwrap().st;
        let frsize = u64::from(before.frsize).max(1);
        let expected_total = 1024 * 1024 / frsize;
        assert_eq!(before.blocks, expected_total);
        assert_eq!(before.bavail, expected_total);

        // Write half the quota. bavail must reflect the consumption.
        let entry = create_file(&fs, FUSE_ROOT_ID, b"big").await;
        write_file(&fs, entry.nodeid, 0, &vec![0u8; 512 * 1024])
            .await
            .unwrap();

        let after = fs.statfs().await.unwrap().st;
        assert_eq!(after.blocks, expected_total, "total size is fixed");
        assert_eq!(after.bavail, (1024 * 1024 - 512 * 1024) / frsize);
        assert!(after.bavail < before.bavail);
    }

    #[tokio::test]
    async fn statfs_unlimited_quota_surfaces_host_values() {
        // With no quota set, statfs must still report the host backing fs's
        // real capacity so `apt` / `systemd` don't see fabricated numbers.
        let (fs, _td) = make_fs(); // unlimited quota in tests
        let st = fs.statfs().await.unwrap().st;
        // Unlimited → blocks is whatever the host tempdir has, not a small
        // fabricated number. No dev host has a <100-block /tmp.
        assert!(st.blocks > 100);
    }

    // ── fsync ─────────────────────────────────────────────────────────

    #[tokio::test]
    async fn fsync_succeeds() {
        let (fs, _td) = make_fs();
        let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"f").await;
        fs.write(entry.nodeid, open.fh, 0, b"data", 0)
            .await
            .unwrap();
        assert!(fs.fsync(entry.nodeid, open.fh, false).await.is_ok());
        fs.release(entry.nodeid, open.fh).await;
    }

    // ── open/close persistence ────────────────────────────────────────

    #[tokio::test]
    async fn open_rejects_missing_and_non_regular_inodes() {
        let (fs, _td) = make_fs();
        assert_eq!(fs.open(999, 0).await.unwrap_err(), FuseError::not_found());

        let dir = fs.mkdir(FUSE_ROOT_ID, b"d", 0o755, ctx()).await.unwrap();
        assert_eq!(
            fs.open(dir.nodeid, 0).await.unwrap_err(),
            FuseError::is_dir()
        );

        let node = fs
            .mknod(FUSE_ROOT_ID, b"chr", S_IFCHR | 0o666, 0, ctx())
            .await
            .unwrap();
        assert_eq!(
            fs.open(node.nodeid, 0).await.unwrap_err(),
            FuseError::invalid()
        );
    }

    #[tokio::test]
    async fn open_close_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        {
            let fs = RedbFs::create(&path).unwrap();
            let (entry, open) = create_rw(&fs, FUSE_ROOT_ID, b"persist").await;
            fs.write(entry.nodeid, open.fh, 0, b"durable", 0)
                .await
                .unwrap();
            fs.fsync(entry.nodeid, open.fh, false).await.unwrap();
            fs.release(entry.nodeid, open.fh).await;
        }
        let fs = RedbFs::open(&path).unwrap();
        let looked = fs.lookup(FUSE_ROOT_ID, b"persist").await.unwrap();
        let data = read_file(&fs, looked.nodeid, 0, 64).await.unwrap();
        assert_eq!(&data, b"durable");
    }

    // ── readdirplus ───────────────────────────────────────────────────

    #[tokio::test]
    async fn readdirplus_returns_entries() {
        let (fs, _td) = make_fs();
        create_file(&fs, FUSE_ROOT_ID, b"a").await;
        create_file(&fs, FUSE_ROOT_ID, b"b").await;
        fs.mkdir(FUSE_ROOT_ID, b"c", 0o755, ctx()).await.unwrap();

        let root = fs.opendir(FUSE_ROOT_ID).await.unwrap();
        let buf = fs
            .readdirplus(FUSE_ROOT_ID, root.fh, 0, 8192)
            .await
            .unwrap();
        fs.releasedir(FUSE_ROOT_ID, root.fh).await;
        assert!(buf.len() > 100);
    }

    // ── EROFS export ─────────────────────────────────────────────────

    #[tokio::test]
    async fn to_erofs_basic() {
        let (fs, _td) = make_fs();
        create_file(&fs, FUSE_ROOT_ID, b"file").await;
        fs.mkdir(FUSE_ROOT_ID, b"dir", 0o755, ctx()).await.unwrap();

        let mut buf = std::io::Cursor::new(Vec::new());
        let stats = fs.to_erofs(&mut buf).unwrap();
        assert!(stats.inode_count >= 3);
    }

    #[tokio::test]
    async fn to_erofs_subtree() {
        let (fs, _td) = make_fs();
        let upper = fs
            .mkdir(FUSE_ROOT_ID, b"upper", 0o755, ctx())
            .await
            .unwrap();
        create_file(&fs, upper.nodeid, b"f").await;

        let mut buf = std::io::Cursor::new(Vec::new());
        let stats = fs.to_erofs_subtree("upper", &mut buf).unwrap();
        assert!(stats.inode_count >= 2);
    }

    // ── dpkg simulation ──────────────────────────────────────────────

    #[tokio::test]
    async fn dpkg_rename_simulation() {
        let (fs, _td) = make_fs();

        let e1 = create_file(&fs, FUSE_ROOT_ID, b"status").await;
        write_file(&fs, e1.nodeid, 0, b"Package: old\nStatus: installed\n")
            .await
            .unwrap();

        let e2 = create_file(&fs, FUSE_ROOT_ID, b"status-new").await;
        write_file(&fs, e2.nodeid, 0, b"Package: new\nStatus: installed\n")
            .await
            .unwrap();

        fs.rename(FUSE_ROOT_ID, b"status-new", FUSE_ROOT_ID, b"status")
            .await
            .unwrap();

        let looked = fs.lookup(FUSE_ROOT_ID, b"status").await.unwrap();
        assert_eq!(looked.nodeid, e2.nodeid);
        let data = read_file(&fs, e2.nodeid, 0, 100).await.unwrap();
        assert!(data.starts_with(b"Package: new"));

        assert_eq!(
            fs.getattr(e1.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
        assert!(fs.lookup(FUSE_ROOT_ID, b"status-new").await.is_err());
    }

    #[tokio::test]
    async fn dpkg_rename_whiteout_simulation() {
        let (fs, _td) = make_fs();

        let e1 = create_file(&fs, FUSE_ROOT_ID, b"status").await;
        write_file(&fs, e1.nodeid, 0, b"old").await.unwrap();

        let e2 = create_file(&fs, FUSE_ROOT_ID, b"status-new").await;
        write_file(&fs, e2.nodeid, 0, b"new").await.unwrap();

        fs.rename_whiteout(FUSE_ROOT_ID, b"status-new", FUSE_ROOT_ID, b"status")
            .await
            .unwrap();

        assert_eq!(
            fs.lookup(FUSE_ROOT_ID, b"status").await.unwrap().nodeid,
            e2.nodeid
        );

        let wo = fs.lookup(FUSE_ROOT_ID, b"status-new").await.unwrap();
        assert_eq!(wo.attr.mode & S_IFMT, S_IFCHR);

        assert_eq!(
            fs.getattr(e1.nodeid).await.unwrap_err(),
            FuseError::not_found()
        );
    }

    #[tokio::test]
    async fn rename_whiteout_counts_new_whiteout_against_inode_quota() {
        let quota = RedbFsQuota {
            max_inodes: 3,
            ..RedbFsQuota::unlimited()
        };
        let (fs, _td) = make_fs_quota(quota);

        create_file(&fs, FUSE_ROOT_ID, b"source").await;
        fs.rename_whiteout(FUSE_ROOT_ID, b"source", FUSE_ROOT_ID, b"dest")
            .await
            .unwrap();

        let err = fs
            .create(FUSE_ROOT_ID, b"extra", 0o644, O_RDWR, ctx())
            .await
            .unwrap_err();
        assert_eq!(err, FuseError::no_space());
    }

    #[tokio::test]
    async fn lookup_tree_reference_to_missing_inode_returns_eio() {
        let (fs, _td) = make_fs();
        let entry = create_file(&fs, FUSE_ROOT_ID, b"broken").await;

        let txn = fs.db.begin_write().unwrap();
        txn.open_table(INODES)
            .unwrap()
            .remove(entry.nodeid)
            .unwrap();
        txn.commit().unwrap();

        let err = fs.lookup(FUSE_ROOT_ID, b"broken").await.unwrap_err();
        assert_eq!(err, FuseError::io());
    }

    #[tokio::test]
    async fn to_erofs_exports_special_files() {
        let (fs, _td) = make_fs();
        fs.mknod(FUSE_ROOT_ID, b"fifo", S_IFIFO | 0o644, 0, ctx())
            .await
            .unwrap();

        let mut buf = std::io::Cursor::new(Vec::new());
        let stats = fs.to_erofs(&mut buf).unwrap();
        assert_eq!(stats.inode_count, 2);
    }

    // ── Stress / many files ──────────────────────────────────────────

    #[tokio::test]
    async fn many_files_in_one_dir() {
        let (fs, _td) = make_fs();
        for i in 0..200u64 {
            let name = format!("f_{i:04}").into_bytes();
            create_file(&fs, FUSE_ROOT_ID, &name).await;
        }

        for i in 0..200u64 {
            let name = format!("f_{i:04}").into_bytes();
            assert!(fs.lookup(FUSE_ROOT_ID, &name).await.is_ok());
        }

        let root = fs.opendir(FUSE_ROOT_ID).await.unwrap();
        let buf = fs.readdir(FUSE_ROOT_ID, root.fh, 0, 65536).await.unwrap();
        fs.releasedir(FUSE_ROOT_ID, root.fh).await;
        assert!(buf.len() > 1000);
    }

    #[tokio::test]
    async fn deep_directory_tree() {
        let (fs, _td) = make_fs();
        let mut parent = FUSE_ROOT_ID;
        let mut dirs = Vec::new();
        for i in 0..20u64 {
            let name = format!("d{i}").into_bytes();
            let entry = fs.mkdir(parent, &name, 0o755, ctx()).await.unwrap();
            dirs.push((parent, name));
            parent = entry.nodeid;
        }

        for (p, name) in &dirs {
            assert!(fs.lookup(*p, name).await.is_ok());
        }
    }

    // ── readdir offset/pagination ────────────────────────────────────

    #[tokio::test]
    async fn readdir_with_offset() {
        let (fs, _td) = make_fs();
        for i in 0..5u64 {
            let name = format!("f{i}").into_bytes();
            create_file(&fs, FUSE_ROOT_ID, &name).await;
        }

        let root = fs.opendir(FUSE_ROOT_ID).await.unwrap();
        let buf1 = fs.readdir(FUSE_ROOT_ID, root.fh, 0, 4096).await.unwrap();
        assert!(!buf1.is_empty());

        let buf2 = fs.readdir(FUSE_ROOT_ID, root.fh, 100, 4096).await.unwrap();
        fs.releasedir(FUSE_ROOT_ID, root.fh).await;
        assert!(buf2.is_empty());
    }
}
