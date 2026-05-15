// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! FUSE protocol types and request dispatch for virtio-fs.
//!
//! Implements the FUSE wire protocol used between the guest kernel (client) and
//! our VMM (server). Each virtqueue entry contains a FUSE request in readable
//! descriptors and space for the response in writable descriptors.
//!
//! Wire format per request:
//! ```text
//! Readable:  [FuseInHeader (40 bytes)] [opcode-specific args] [optional data]
//! Writable:  [FuseOutHeader (16 bytes)] [opcode-specific response] [optional data]
//! ```
//!
//! # Compatibility
//!
//! The `repr(C)` structs in this module match the negotiated Linux FUSE 7.x
//! UAPI subset used by the guest kernel. Amla-specific dispatch behavior,
//! backend trait expectations, and helper buffer formats are same-version only;
//! this module does not define an additional cross-version Amla ABI.

use amla_core::VmmError;
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{ReadableDescriptor, SplitDescriptorChain};

use crate::fs_types::{ATTR_VALID_SECS, ENTRY_VALID_SECS};
use crate::fuse_abi;
use crate::fuse_abi::FuseError;

/// Maximum size for a single FUSE data allocation (1 MiB).
/// Guards against guest-controlled OOM via oversized descriptor lengths.
pub const MAX_FUSE_DATA_SIZE: usize = 1 << 20;
const MAX_FUSE_DATA_SIZE_U32: u32 = 1 << 20;

/// Maximum copied FUSE request payload size.
///
/// Virtio-fs must own request bytes before awaiting the backend. This bound
/// covers the largest data payload plus headers/names while preventing a
/// guest-controlled readable descriptor chain from driving unbounded host
/// allocation.
pub const MAX_FUSE_REQUEST_SIZE: usize = MAX_FUSE_DATA_SIZE + (64 * 1024);

/// Maximum size for a FUSE name/path allocation (4 KiB = `PATH_MAX`).
const MAX_FUSE_NAME_SIZE: usize = 4096;

// FUSE protocol constants — guest ABI values (always Linux), not host libc.
// Defined explicitly so this module compiles on non-Unix hosts.
const fn fuse_opcode_name(opcode: u32) -> &'static str {
    match opcode {
        FUSE_LOOKUP => "LOOKUP",
        FUSE_FORGET => "FORGET",
        FUSE_GETATTR => "GETATTR",
        FUSE_SETATTR => "SETATTR",
        FUSE_READLINK => "READLINK",
        FUSE_SYMLINK => "SYMLINK",
        FUSE_MKNOD => "MKNOD",
        FUSE_MKDIR => "MKDIR",
        FUSE_UNLINK => "UNLINK",
        FUSE_RMDIR => "RMDIR",
        FUSE_RENAME => "RENAME",
        FUSE_LINK => "LINK",
        FUSE_OPEN => "OPEN",
        FUSE_READ => "READ",
        FUSE_WRITE => "WRITE",
        FUSE_STATFS => "STATFS",
        FUSE_RELEASE => "RELEASE",
        FUSE_FSYNC => "FSYNC",
        FUSE_SETXATTR => "SETXATTR",
        FUSE_GETXATTR => "GETXATTR",
        FUSE_LISTXATTR => "LISTXATTR",
        FUSE_REMOVEXATTR => "REMOVEXATTR",
        FUSE_FLUSH => "FLUSH",
        FUSE_INIT => "INIT",
        FUSE_OPENDIR => "OPENDIR",
        FUSE_READDIR => "READDIR",
        FUSE_RELEASEDIR => "RELEASEDIR",
        FUSE_FSYNCDIR => "FSYNCDIR",
        FUSE_ACCESS => "ACCESS",
        FUSE_CREATE => "CREATE",
        FUSE_DESTROY => "DESTROY",
        FUSE_BATCH_FORGET => "BATCH_FORGET",
        FUSE_READDIRPLUS => "READDIRPLUS",
        FUSE_RENAME2 => "RENAME2",
        FUSE_POLL => "POLL",
        FUSE_IOCTL => "IOCTL",
        FUSE_TMPFILE => "TMPFILE",
        FUSE_INTERRUPT => "INTERRUPT",
        FUSE_GETLK => "GETLK",
        FUSE_SETLK => "SETLK",
        FUSE_SETLKW => "SETLKW",
        _ => "UNKNOWN",
    }
}

// =============================================================================
// FUSE Opcodes
// =============================================================================

pub const FUSE_LOOKUP: u32 = 1;
pub const FUSE_FORGET: u32 = 2;
pub const FUSE_GETATTR: u32 = 3;
pub const FUSE_READLINK: u32 = 5;
pub const FUSE_OPEN: u32 = 14;
pub const FUSE_READ: u32 = 15;
pub const FUSE_STATFS: u32 = 17;
pub const FUSE_RELEASE: u32 = 18;
pub const FUSE_FSYNC: u32 = 20;
pub const FUSE_SETXATTR: u32 = 21;
pub const FUSE_GETXATTR: u32 = 22;
pub const FUSE_LISTXATTR: u32 = 23;
pub const FUSE_FLUSH: u32 = 25;
pub const FUSE_INIT: u32 = 26;
pub const FUSE_OPENDIR: u32 = 27;
pub const FUSE_READDIR: u32 = 28;
pub const FUSE_RELEASEDIR: u32 = 29;
pub const FUSE_FSYNCDIR: u32 = 30;
pub const FUSE_ACCESS: u32 = 34;
pub const FUSE_DESTROY: u32 = 38;
pub const FUSE_IOCTL: u32 = 39;
pub const FUSE_POLL: u32 = 40;
pub const FUSE_BATCH_FORGET: u32 = 42;
/// Maximum number of entries to process in a single `BATCH_FORGET` request,
/// preventing guest-controlled OOM via `Vec::with_capacity`.
const MAX_BATCH_FORGET: usize = 8192;
pub const FUSE_READDIRPLUS: u32 = 44;

// Write-support opcodes
pub const FUSE_SETATTR: u32 = 4;
pub const FUSE_SYMLINK: u32 = 6;
pub const FUSE_MKNOD: u32 = 8;
pub const FUSE_MKDIR: u32 = 9;
pub const FUSE_UNLINK: u32 = 10;
pub const FUSE_RMDIR: u32 = 11;
pub const FUSE_RENAME: u32 = 12;
pub const FUSE_LINK: u32 = 13;
pub const FUSE_WRITE: u32 = 16;
pub const FUSE_CREATE: u32 = 35;
pub const FUSE_RENAME2: u32 = 45;
pub const FUSE_TMPFILE: u32 = 51;
pub const FUSE_REMOVEXATTR: u32 = 24;
pub const FUSE_INTERRUPT: u32 = 36;

// Locking opcodes
pub const FUSE_GETLK: u32 = 31;
pub const FUSE_SETLK: u32 = 32;
pub const FUSE_SETLKW: u32 = 33;

/// `renameat2(2)` flag: atomically replace source with a whiteout.
const RENAME_WHITEOUT: u32 = 4;

// =============================================================================
// FUSE Init Feature Flags
// =============================================================================

pub const FUSE_ASYNC_READ: u32 = 1 << 0;
pub const FUSE_POSIX_LOCKS: u32 = 1 << 1;
pub const FUSE_ATOMIC_O_TRUNC: u32 = 1 << 3;
/// Filesystem handles lookups of "." and ".." — enables kernel exportfs
/// support (file handle encode/decode). Required for overlayfs upper.
pub const FUSE_EXPORT_SUPPORT: u32 = 1 << 4;
pub const FUSE_FLOCK_LOCKS: u32 = 1 << 10;
pub const FUSE_DO_READDIRPLUS: u32 = 1 << 13;
pub const FUSE_READDIRPLUS_AUTO: u32 = 1 << 14;
pub const FUSE_WRITEBACK_CACHE: u32 = 1 << 16;

// FUSE_WRITE write_flags bits
pub const FUSE_WRITE_CACHE: u32 = 1 << 0;
pub const FUSE_WRITE_LOCKOWNER: u32 = 1 << 1;
pub const FUSE_WRITE_KILL_SUIDGID: u32 = 1 << 2;

// =============================================================================
// FUSE Protocol Structs (wire format, must match Linux include/uapi/linux/fuse.h)
// =============================================================================

/// FUSE request header — first 40 bytes of every request.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseInHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub padding: u32,
}

/// FUSE response header — first 16 bytes of every response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseOutHeader {
    pub len: u32,
    pub error: i32,
    pub unique: u64,
}

/// File attributes — matches `struct fuse_attr` in the kernel.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseAttr {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub rdev: u32,
    pub blksize: u32,
    pub flags: u32,
}

/// `FUSE_INIT` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseInitIn {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
}

/// `FUSE_INIT` response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseInitOut {
    pub major: u32,
    pub minor: u32,
    pub max_readahead: u32,
    pub flags: u32,
    pub max_background: u16,
    pub congestion_threshold: u16,
    pub max_write: u32,
    pub time_gran: u32,
    pub max_pages: u16,
    pub map_alignment: u16,
    pub flags2: u32,
    pub unused: [u32; 7],
}

/// `FUSE_GETATTR` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseGetattrIn {
    pub getattr_flags: u32,
    pub dummy: u32,
    pub fh: u64,
}

/// `FUSE_GETATTR` response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseAttrOut {
    pub attr_valid: u64,
    pub attr_valid_nsec: u32,
    pub dummy: u32,
    pub attr: FuseAttr,
}

impl FuseAttrOut {
    #[must_use]
    pub const fn new(attr: FuseAttr) -> Self {
        Self {
            attr_valid: ATTR_VALID_SECS,
            attr_valid_nsec: 0,
            dummy: 0,
            attr,
        }
    }
}

/// `FUSE_LOOKUP` response (same as `FUSE_ENTRY_OUT`).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseEntryOut {
    pub nodeid: u64,
    pub generation: u64,
    pub entry_valid: u64,
    pub attr_valid: u64,
    pub entry_valid_nsec: u32,
    pub attr_valid_nsec: u32,
    pub attr: FuseAttr,
}

impl FuseEntryOut {
    #[must_use]
    pub const fn new(nodeid: u64, attr: FuseAttr) -> Self {
        Self {
            nodeid,
            generation: 0,
            entry_valid: ENTRY_VALID_SECS,
            attr_valid: ATTR_VALID_SECS,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr,
        }
    }
}

/// `FUSE_OPEN` / `FUSE_OPENDIR` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseOpenIn {
    pub flags: u32,
    pub open_flags: u32,
}

/// `FUSE_OPEN` / `FUSE_OPENDIR` response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseOpenOut {
    pub fh: u64,
    pub open_flags: u32,
    pub padding: u32,
}

/// `FUSE_READ` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseReadIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub read_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `FUSE_RELEASE` / `FUSE_RELEASEDIR` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseReleaseIn {
    pub fh: u64,
    pub flags: u32,
    pub release_flags: u32,
    pub lock_owner: u64,
}

/// `FUSE_FORGET` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseForgetIn {
    pub nlookup: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
struct FuseInterruptIn {
    unique: u64,
}

/// `FUSE_BATCH_FORGET` request args (header).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseBatchForgetIn {
    pub count: u32,
    pub dummy: u32,
}

/// Single entry in `FUSE_BATCH_FORGET`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseForgetOne {
    pub nodeid: u64,
    pub nlookup: u64,
}

/// `FUSE_ACCESS` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseAccessIn {
    pub mask: u32,
    pub padding: u32,
}

/// `FUSE_GETXATTR` / `FUSE_LISTXATTR` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseGetxattrIn {
    pub size: u32,
    pub padding: u32,
}

/// `FUSE_GETXATTR` / `FUSE_LISTXATTR` response (size query).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseGetxattrOut {
    pub size: u32,
    pub padding: u32,
}

/// `FUSE_STATFS` response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseStatfsOut {
    pub st: FuseKstatfs,
}

/// Filesystem stats — matches `struct fuse_kstatfs`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseKstatfs {
    pub blocks: u64,
    pub bfree: u64,
    pub bavail: u64,
    pub files: u64,
    pub ffree: u64,
    pub bsize: u32,
    pub namelen: u32,
    pub frsize: u32,
    pub padding: u32,
    pub spare: [u32; 6],
}

/// `FUSE_FSYNC` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseFsyncIn {
    pub fh: u64,
    pub fsync_flags: u32,
    pub padding: u32,
}

/// `FUSE_FLUSH` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseFlushIn {
    pub fh: u64,
    pub unused: u32,
    pub padding: u32,
    pub lock_owner: u64,
}

// =============================================================================
// Write-support FUSE Protocol Structs
// =============================================================================

/// `FUSE_SETATTR` request args (88 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseSetattrIn {
    pub valid: u32,
    pub padding: u32,
    pub fh: u64,
    pub size: u64,
    pub lock_owner: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub atimensec: u32,
    pub mtimensec: u32,
    pub ctimensec: u32,
    pub mode: u32,
    pub unused4: u32,
    pub uid: u32,
    pub gid: u32,
    pub unused5: u32,
}

/// `FUSE_WRITE` request args (40 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseWriteIn {
    pub fh: u64,
    pub offset: u64,
    pub size: u32,
    pub write_flags: u32,
    pub lock_owner: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `FUSE_WRITE` response (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseWriteOut {
    pub size: u32,
    pub padding: u32,
}

/// `FUSE_CREATE` request args (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseCreateIn {
    pub flags: u32,
    pub mode: u32,
    pub umask: u32,
    pub open_flags: u32,
}

/// `FUSE_MKDIR` request args (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseMkdirIn {
    pub mode: u32,
    pub umask: u32,
}

/// `FUSE_MKNOD` request args (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseMknodIn {
    pub mode: u32,
    pub rdev: u32,
    pub umask: u32,
    pub padding: u32,
}

/// `FUSE_RENAME` request args (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseRenameIn {
    pub newdir: u64,
}

/// `FUSE_RENAME2` request args (16 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseRename2In {
    pub newdir: u64,
    pub flags: u32,
    pub padding: u32,
}

/// `FUSE_LINK` request args (8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseLinkIn {
    pub oldnodeid: u64,
}

/// FUSE file lock structure (shared between request and response).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseFileLock {
    pub start: u64,
    pub end: u64,
    pub typ: u32,
    pub pid: u32,
}

/// `FUSE_GETLK` / `FUSE_SETLK` / `FUSE_SETLKW` request args.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseLkIn {
    pub fh: u64,
    pub owner: u64,
    pub lk: FuseFileLock,
    pub lk_flags: u32,
    pub padding: u32,
}

/// `FUSE_GETLK` response.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseLkOut {
    pub lk: FuseFileLock,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
struct FusePollIn {
    fh: u64,
    kh: u64,
    flags: u32,
    events: u32,
}

/// `FUSE_SETXATTR` request args (8 bytes — FUSE 7.31 wire format).
///
/// The extended 16-byte version with `setxattr_flags` requires FUSE >= 7.33.
/// Since we negotiate 7.31, the kernel sends this 8-byte layout.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseSetxattrIn {
    pub size: u32,
    pub flags: u32,
}

// FUSE_SETATTR valid flags
pub const FATTR_MODE: u32 = 1 << 0;
pub const FATTR_UID: u32 = 1 << 1;
pub const FATTR_GID: u32 = 1 << 2;
pub const FATTR_SIZE: u32 = 1 << 3;
pub const FATTR_ATIME: u32 = 1 << 4;
pub const FATTR_MTIME: u32 = 1 << 5;
pub const FATTR_FH: u32 = 1 << 6;
pub const FATTR_ATIME_NOW: u32 = 1 << 7;
pub const FATTR_MTIME_NOW: u32 = 1 << 8;
pub const FATTR_LOCKOWNER: u32 = 1 << 9;
pub const FATTR_CTIME: u32 = 1 << 10;

/// Single entry in READDIRPLUS response.
/// This must be 8-byte aligned in the output buffer.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseDirentplus {
    pub entry_out: FuseEntryOut,
    pub dirent: FuseDirent,
}

/// Directory entry — variable-length (name follows inline, padded to 8 bytes).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, bytemuck::Pod, bytemuck::Zeroable)]
pub struct FuseDirent {
    pub ino: u64,
    pub off: u64,
    pub namelen: u32,
    pub typ: u32,
    // name bytes follow (not part of the fixed struct)
}

// =============================================================================
// FsBackend trait
// =============================================================================

/// Caller identity from the FUSE request header.
///
/// Passed to inode-creating operations so backends can set correct ownership.
#[derive(Clone, Copy, Debug)]
pub struct FuseContext {
    /// User ID of the process that issued the request.
    pub uid: u32,
    /// Group ID of the process that issued the request.
    pub gid: u32,
}

/// Backend interface for filesystem operations.
///
/// Each method corresponds to a FUSE opcode. Errors are returned as
/// [`FuseError`] (typed wrapper around positive errno values).
/// `FuseServer::write_error` negates them when writing FUSE error
/// responses. Consumers ([`FuseServer<F>`], `FsDevice<F>`) are generic
/// over a concrete `F: FsBackend` — the FUSE dispatch path monomorphizes
/// with no vtable lookups.
///
/// Sync backends simply use `async fn` with synchronous bodies.
//
// `#[trait_variant::make(Send)]` rewrites this trait so every `async fn`'s
// returned future is `Send`. Impls write `async fn` naturally; callers like
// the daemon's agent-spawn path that cross `tokio::spawn` get Send futures
// without each method signature having to spell out `impl Future + Send`.
#[trait_variant::make(Send)]
pub trait FsBackend: Sync {
    /// Initialize the backend and return `FUSE_INIT` response fields.
    ///
    /// **Note:** `max_write` in the returned [`FuseInitOut`] is ignored —
    /// [`FuseServer`] always overwrites it with [`max_write()`](FsBackend::max_write).
    /// Backends should set it to `0`.
    async fn init(&self) -> Result<FuseInitOut, FuseError>;
    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError>;
    async fn forget(&self, nodeid: u64, nlookup: u64);
    async fn batch_forget(&self, forgets: &[(u64, u64)]);
    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError>;
    async fn readlink(&self, nodeid: u64) -> Result<Vec<u8>, FuseError>;
    async fn open(&self, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError>;
    async fn read(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;
    async fn release(&self, nodeid: u64, fh: u64);
    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError>;
    async fn readdir(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;
    async fn readdirplus(
        &self,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;
    async fn releasedir(&self, nodeid: u64, fh: u64);
    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError>;
    async fn access(&self, nodeid: u64, mask: u32) -> Result<(), FuseError>;
    async fn getxattr(&self, nodeid: u64, name: &[u8], size: u32) -> Result<Vec<u8>, FuseError>;
    async fn listxattr(&self, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError>;

    // Write operations — default to EROFS so read-only backends are unchanged.
    // `trait_variant::make(Send)` rewrites the signatures but leaves bodies
    // unwrapped, so each default body is itself an `async { ... }` block that
    // produces the required future.

    async fn setattr(&self, _nodeid: u64, _args: &FuseSetattrIn) -> Result<FuseAttrOut, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn write(
        &self,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _data: &[u8],
        _write_flags: u32,
    ) -> Result<u32, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn create(
        &self,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _flags: u32,
        _ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn mkdir(
        &self,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn mknod(
        &self,
        _parent: u64,
        _name: &[u8],
        _mode: u32,
        _rdev: u32,
        _ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn unlink(&self, _parent: u64, _name: &[u8]) -> Result<(), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn rmdir(&self, _parent: u64, _name: &[u8]) -> Result<(), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn rename(
        &self,
        _parent: u64,
        _name: &[u8],
        _newparent: u64,
        _newname: &[u8],
    ) -> Result<(), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn symlink(
        &self,
        _parent: u64,
        _name: &[u8],
        _target: &[u8],
        _ctx: FuseContext,
    ) -> Result<FuseEntryOut, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn link(
        &self,
        _nodeid: u64,
        _newparent: u64,
        _newname: &[u8],
    ) -> Result<FuseEntryOut, FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn setxattr(
        &self,
        _nodeid: u64,
        _name: &[u8],
        _value: &[u8],
        _flags: u32,
    ) -> Result<(), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn removexattr(&self, _nodeid: u64, _name: &[u8]) -> Result<(), FuseError> {
        async { Err(FuseError::read_only()) }
    }
    async fn fsync(&self, _nodeid: u64, _fh: u64, _datasync: bool) -> Result<(), FuseError> {
        async { Ok(()) }
    }
    /// Called on `FUSE_FLUSH`, which the kernel issues per `close()`.
    ///
    /// POSIX `close()` does not durably persist — it only evicts dirty pages
    /// to the filesystem — so the default is a no-op.  Backends that need
    /// per-close cleanup (e.g., file-handle bookkeeping) can override.
    /// Durability only happens on explicit `fsync()` / `fdatasync()`.
    async fn flush(&self, _nodeid: u64, _fh: u64) -> Result<(), FuseError> {
        async { Ok(()) }
    }
    /// Rename with `RENAME_WHITEOUT`: move source → dest, then create a
    /// whiteout (char device 0,0) at the source path.
    async fn rename_whiteout(
        &self,
        _parent: u64,
        _name: &[u8],
        _newparent: u64,
        _newname: &[u8],
    ) -> Result<(), FuseError> {
        async { Err(FuseError::no_sys()) }
    }
    /// Create an anonymous temporary file in a directory (`O_TMPFILE`).
    /// Returns entry + open handle, like `create` but without a name.
    async fn tmpfile(
        &self,
        _parent: u64,
        _mode: u32,
        _flags: u32,
        _ctx: FuseContext,
    ) -> Result<(FuseEntryOut, FuseOpenOut), FuseError> {
        async { Err(FuseError::no_sys()) }
    }

    /// Return the parent directory entry for `nodeid` (LOOKUP "..").
    /// Required for `FUSE_EXPORT_SUPPORT`.
    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError>;

    /// Maximum bytes per `FUSE_WRITE` (0 = read-only, no writes accepted).
    fn max_write(&self) -> u32 {
        0
    }
}

// =============================================================================
// FsBackend sub-traits for composable filesystem primitives
// =============================================================================

/// A filesystem backend with a fixed, known inode count.
///
/// Backends that implement this trait allocate all inodes at construction time.
/// The inode count never changes after construction, which enables composition:
/// `OverlayFsBackend` uses the fixed count to partition the inode namespace
/// between fixed (low) and dynamic (high) backends.
///
/// Inodes are numbered `[1, inode_count()]` where 1 is the root.
pub trait FixedFsBackend: FsBackend {
    /// Total number of inodes in this backend, including the root (inode 1).
    fn inode_count(&self) -> u64;
}

/// A filesystem backend with dynamic inode allocation.
///
/// Backends that implement this trait allocate inodes on demand (e.g., lazily
/// resolving git tree entries). The total inode count is unknown at construction
/// time.
///
/// When composed via `OverlayFsBackend`, dynamic backends occupy the upper
/// inode range (above the fixed backend's count).
pub trait DynamicFsBackend: FsBackend {}

// =============================================================================
// FuseServer — request parsing and dispatch
// =============================================================================

/// Readable scatter-gather regions from a single FUSE descriptor chain.
///
/// `readable` carries only the request (header + args + optional data).
/// Writable response regions stay owned by the virtio queue runner as an
/// opaque deferred completion token, so async FUSE dispatch cannot write guest
/// memory before queue-generation and used-ring validation.
pub struct DescriptorRegions<'brand, 'm, M: GuestMemory> {
    pub readable: Vec<ReadableDescriptor<'brand, 'm, M>>,
}

/// Host-owned FUSE request bytes.
///
/// The guest descriptor chain is copied into one bounded contiguous buffer
/// before the async backend await. Descriptor boundaries are deliberately not
/// retained: FUSE parsing is defined over the byte stream
/// `[FuseInHeader][args][payload]`, not over virtqueue scatter-gather shape.
#[derive(Debug)]
pub struct OwnedFuseRequest {
    bytes: Vec<u8>,
}

impl OwnedFuseRequest {
    /// Create an empty owned request with bounded byte capacity.
    #[must_use]
    pub fn with_capacity(bytes: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(bytes),
        }
    }

    /// Append one zero-initialized descriptor and return its byte region.
    pub fn push_zeroed(&mut self, len: usize) -> &mut [u8] {
        let start = self.bytes.len();
        self.bytes.resize(start + len, 0);
        &mut self.bytes[start..start + len]
    }

    /// Contiguous request bytes copied from readable descriptors.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// True when no readable descriptor was supplied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Approximate heap bytes reserved by this owned request.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.bytes.capacity()
    }
}

/// Canonical FUSE request byte stream.
///
/// FUSE parsing is defined over `[FuseInHeader][args][payload]`, independent of
/// the virtqueue descriptor boundaries used to carry those bytes.
pub trait FuseRequest {
    /// Length of the contiguous FUSE request byte stream.
    #[must_use]
    fn stream_len(&self) -> usize;

    /// Read from the contiguous FUSE request byte stream.
    fn read_stream_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, VmmError>;
}

impl FuseRequest for OwnedFuseRequest {
    fn stream_len(&self) -> usize {
        self.bytes.len()
    }

    fn read_stream_at(&self, offset: usize, dst: &mut [u8]) -> Result<usize, VmmError> {
        let Some(src) = self.bytes.get(offset..) else {
            return Ok(0);
        };
        let n = src.len().min(dst.len());
        dst[..n].copy_from_slice(&src[..n]);
        Ok(n)
    }
}

/// Validated destination for committing a FUSE reply.
///
/// Implementations are responsible for writing the prepared response header
/// and body fragments into a destination that has already been validated by
/// the virtio transport owner. Async request dispatch only produces a
/// [`FuseReply`]; it does not receive a writer.
pub trait FuseReplyWriter {
    /// Write a complete FUSE response and return the used-ring byte count.
    fn write_reply(
        &mut self,
        out_header: &FuseOutHeader,
        body_fragments: &[&[u8]],
    ) -> Result<u32, VmmError>;
}

/// Collect descriptor regions from a chain into owned vectors.
///
/// Separates readable (request) and writable (response) regions from a chain
/// that has already been structurally validated by
/// [`SplitDescriptorChain`]. Malformed chains never reach this function.
pub fn collect_regions<'brand, 'm, M: GuestMemory>(
    chain: &SplitDescriptorChain<'brand, 'm, M>,
) -> DescriptorRegions<'brand, 'm, M> {
    for slice in chain.readable() {
        log::trace!("  desc: len={} (R)", slice.len());
    }
    for slice in chain.writable() {
        log::trace!("  desc: len={} (W)", slice.len());
    }
    DescriptorRegions {
        readable: chain.readable().to_vec(),
    }
}

/// Owned FUSE response produced by async request dispatch.
///
/// The reply contains only host-owned response data. It deliberately does not
/// contain writable guest descriptors, so backend futures cannot write into
/// guest memory after a queue reset and before the VMM completion validation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug)]
pub enum FuseReply {
    /// Request has FUSE no-reply semantics.
    NoReply,
    /// Error response with a negative errno on the wire.
    Error {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Positive Linux errno.
        errno: FuseError,
    },
    /// Header-only successful response.
    Empty {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
    },
    /// `FUSE_INIT` response.
    Init {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseInitOut,
    },
    /// Entry response used by lookup and inode-creating operations.
    Entry {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseEntryOut,
    },
    /// Attribute response.
    Attr {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseAttrOut,
    },
    /// Open response.
    Open {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseOpenOut,
    },
    /// Write response.
    Write {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseWriteOut,
    },
    /// Extended-attribute size response.
    Getxattr {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseGetxattrOut,
    },
    /// Filesystem stats response.
    Statfs {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseStatfsOut,
    },
    /// File-lock query response.
    Lk {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: FuseLkOut,
    },
    /// Poll response (`revents`, `padding`).
    Poll {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Typed response body.
        body: [u32; 2],
    },
    /// Create/tmpfile response: entry followed by open handle.
    Create {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Entry response fragment.
        entry: FuseEntryOut,
        /// Open response fragment.
        open: FuseOpenOut,
    },
    /// Variable-sized byte response already owned by the backend.
    Bytes {
        /// Request header used for the response unique ID.
        header: FuseInHeader,
        /// Response body bytes.
        data: Vec<u8>,
    },
}

impl FuseReply {
    /// Return the number of bytes this reply will write to a FUSE response buffer.
    pub fn encoded_len(&self) -> Result<u32, VmmError> {
        match self {
            Self::NoReply => Ok(0),
            Self::Error { .. } | Self::Empty { .. } => encoded_response_len(&[]),
            Self::Init { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Entry { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Attr { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Open { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Write { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Getxattr { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Statfs { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Lk { body, .. } => encoded_response_len(&[bytemuck::bytes_of(body)]),
            Self::Poll { body, .. } => encoded_response_len(&[bytemuck::cast_slice(body)]),
            Self::Create { entry, open, .. } => {
                encoded_response_len(&[bytemuck::bytes_of(entry), bytemuck::bytes_of(open)])
            }
            Self::Bytes { data, .. } => encoded_response_len(&[data.as_slice()]),
        }
    }

    /// Encode this reply into a host-owned FUSE response frame.
    ///
    /// Async virtio-fs request handling uses this before reacquiring the queue
    /// lock. The queue layer later validates the destination descriptors and
    /// publishes the used entry in one operation.
    pub fn encode(&self) -> Result<Vec<u8>, VmmError> {
        let expected = self.encoded_len()?;
        let expected_usize = usize::try_from(expected).map_err(|_| {
            VmmError::DeviceConfig(format!("FUSE response length overflow: {expected}"))
        })?;
        let mut writer = OwnedFuseReplyWriter {
            bytes: Vec::with_capacity(expected_usize),
        };
        let written = self.commit(&mut writer)?;
        if written != expected {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE reply encoder wrote {written} bytes, expected {expected}",
            )));
        }
        if writer.bytes.len() != expected_usize {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE reply encoder produced {} bytes, expected {expected_usize}",
                writer.bytes.len(),
            )));
        }
        Ok(writer.bytes)
    }

    /// Commit this reply into the validated writable descriptor chain.
    pub fn commit<W: FuseReplyWriter + ?Sized>(&self, writer: &mut W) -> Result<u32, VmmError> {
        match self {
            Self::NoReply => Ok(0),
            Self::Error { header, errno } => {
                commit_response(writer, header, errno.to_wire_error(), &[])
            }
            Self::Empty { header } => commit_response(writer, header, 0, &[]),
            Self::Init { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Entry { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Attr { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Open { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Write { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Getxattr { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Statfs { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Lk { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::bytes_of(body)])
            }
            Self::Poll { header, body } => {
                commit_response(writer, header, 0, &[bytemuck::cast_slice(body)])
            }
            Self::Create {
                header,
                entry,
                open,
            } => commit_response(
                writer,
                header,
                0,
                &[bytemuck::bytes_of(entry), bytemuck::bytes_of(open)],
            ),
            Self::Bytes { header, data } => commit_response(writer, header, 0, &[data.as_slice()]),
        }
    }
}

struct OwnedFuseReplyWriter {
    bytes: Vec<u8>,
}

impl FuseReplyWriter for OwnedFuseReplyWriter {
    fn write_reply(
        &mut self,
        out_header: &FuseOutHeader,
        body_fragments: &[&[u8]],
    ) -> Result<u32, VmmError> {
        let header_bytes = bytemuck::bytes_of(out_header);
        let body_len = body_fragments
            .iter()
            .try_fold(0usize, |acc, fragment| acc.checked_add(fragment.len()))
            .ok_or_else(|| VmmError::DeviceConfig("FUSE response body length overflow".into()))?;
        let total = header_bytes
            .len()
            .checked_add(body_len)
            .ok_or_else(|| VmmError::DeviceConfig("FUSE response length overflow".into()))?;
        if out_header.len as usize != total {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE response header length {} did not match body length {total}",
                out_header.len
            )));
        }

        self.bytes.extend_from_slice(header_bytes);
        for fragment in body_fragments {
            self.bytes.extend_from_slice(fragment);
        }
        u32::try_from(total)
            .map_err(|_| VmmError::DeviceConfig(format!("FUSE response too large: {total}")))
    }
}

fn commit_response<W: FuseReplyWriter + ?Sized>(
    writer: &mut W,
    in_header: &FuseInHeader,
    error: i32,
    body_fragments: &[&[u8]],
) -> Result<u32, VmmError> {
    if error != 0 {
        let errno = -error;
        // ENOENT, ENOTTY, ENODATA, ENOTSUP, ENOSYS
        // are normal (missing files, no ioctl, no xattrs, unsupported ops).
        if errno == fuse_abi::ENOENT
            || errno == fuse_abi::ENOTTY
            || errno == fuse_abi::ENODATA
            || errno == fuse_abi::ENOTSUP
            || errno == fuse_abi::ENOSYS
        {
            log::debug!(
                "FUSE: {} nodeid={} -> errno={errno}",
                fuse_opcode_name(in_header.opcode),
                in_header.nodeid,
            );
        } else {
            log::warn!(
                "FUSE error: {} nodeid={} -> errno={errno} (unique={})",
                fuse_opcode_name(in_header.opcode),
                in_header.nodeid,
                in_header.unique,
            );
        }
    }

    let total_u32 = encoded_response_len(body_fragments)?;
    let out_header = FuseOutHeader {
        len: total_u32,
        error,
        unique: in_header.unique,
    };

    writer.write_reply(&out_header, body_fragments)
}

fn encoded_response_len(body_fragments: &[&[u8]]) -> Result<u32, VmmError> {
    let hdr_size = std::mem::size_of::<FuseOutHeader>();
    let body_len = body_fragments
        .iter()
        .try_fold(0usize, |acc, fragment| acc.checked_add(fragment.len()))
        .ok_or_else(|| VmmError::DeviceConfig("FUSE response body length overflow".into()))?;
    let total = hdr_size
        .checked_add(body_len)
        .ok_or_else(|| VmmError::DeviceConfig("FUSE response length overflow".into()))?;

    u32::try_from(total)
        .map_err(|_| VmmError::DeviceConfig(format!("FUSE response too large: {total}")))
}

/// FUSE protocol request handler.
///
/// Dispatches FUSE requests to an `FsBackend`.
///
/// The server parses readable request descriptors and returns owned replies.
/// Virtio transport code is responsible for validating the queue lifecycle
/// before committing a reply to writable descriptors.
pub struct FuseServer<'a, F: FsBackend> {
    backend: &'a F,
}

// Reason: every dispatch/handler fn here takes `&R` or `&Q` where the
// trait bound (FuseRequest / consumer-supplied generic) has no Sync
// bound, so the resulting future is `!Send` purely from the captured
// reference. Adding Sync to the trait would propagate through every
// FUSE consumer for no runtime benefit; this is single-threaded
// host-side request dispatch.
#[allow(clippy::future_not_send)]
impl<'a, F: FsBackend> FuseServer<'a, F> {
    pub const fn new(backend: &'a F) -> Self {
        Self { backend }
    }

    /// Dispatch a host-owned FUSE request and return an owned reply.
    pub async fn dispatch_owned_request(
        &self,
        request: &OwnedFuseRequest,
    ) -> Result<FuseReply, VmmError> {
        self.dispatch_request(request).await
    }

    #[allow(clippy::too_many_lines)]
    async fn dispatch_request<R: FuseRequest + ?Sized>(
        &self,
        readable: &R,
    ) -> Result<FuseReply, VmmError> {
        let header = Self::read_header(readable)?;

        log::debug!(
            "FUSE >> {} nodeid={} uid={} unique={}",
            fuse_opcode_name(header.opcode),
            header.nodeid,
            header.uid,
            header.unique,
        );

        let reply = match header.opcode {
            FUSE_INIT => self.handle_init(&header, readable).await,
            FUSE_DESTROY => Self::validate_empty_request(&header, "FUSE_DESTROY")
                .map(|()| FuseReply::Empty { header }),
            FUSE_FLUSH => self.handle_flush(&header, readable).await,
            FUSE_LOOKUP => self.handle_lookup(&header, readable).await,
            FUSE_FORGET => self
                .handle_forget(&header, readable)
                .await
                .map(|()| FuseReply::NoReply),
            FUSE_BATCH_FORGET => self
                .handle_batch_forget(&header, readable)
                .await
                .map(|()| FuseReply::NoReply),
            FUSE_INTERRUPT => {
                Self::handle_interrupt(&header, readable).map(|()| FuseReply::NoReply)
            }
            FUSE_GETATTR => self.handle_getattr(&header, readable).await,
            FUSE_READLINK => self.handle_readlink(&header, readable).await,
            FUSE_OPEN => self.handle_open(&header, readable).await,
            FUSE_READ => self.handle_read(&header, readable).await,
            FUSE_RELEASE => self.handle_release(&header, readable).await,
            FUSE_OPENDIR => self.handle_opendir(&header, readable).await,
            FUSE_READDIR => self.handle_readdir(&header, readable).await,
            FUSE_READDIRPLUS => self.handle_readdirplus(&header, readable).await,
            FUSE_RELEASEDIR => self.handle_releasedir(&header, readable).await,
            FUSE_STATFS => self.handle_statfs(&header, readable).await,
            FUSE_ACCESS => self.handle_access(&header, readable).await,
            FUSE_GETXATTR => self.handle_getxattr(&header, readable).await,
            FUSE_LISTXATTR => self.handle_listxattr(&header, readable).await,
            FUSE_FSYNC | FUSE_FSYNCDIR => self.handle_fsync(&header, readable).await,
            FUSE_SETATTR => self.handle_setattr(&header, readable).await,
            FUSE_WRITE => self.handle_write(&header, readable).await,
            FUSE_CREATE => self.handle_create(&header, readable).await,
            FUSE_MKDIR => self.handle_mkdir(&header, readable).await,
            FUSE_MKNOD => self.handle_mknod(&header, readable).await,
            FUSE_UNLINK => self.handle_unlink(&header, readable).await,
            FUSE_RMDIR => self.handle_rmdir(&header, readable).await,
            FUSE_RENAME => self.handle_rename(&header, readable).await,
            FUSE_RENAME2 => self.handle_rename2(&header, readable).await,
            FUSE_SYMLINK => self.handle_symlink(&header, readable).await,
            FUSE_LINK => self.handle_link(&header, readable).await,
            FUSE_SETXATTR => self.handle_setxattr(&header, readable).await,
            FUSE_REMOVEXATTR => self.handle_removexattr(&header, readable).await,
            FUSE_TMPFILE => self.handle_tmpfile(&header, readable).await,
            FUSE_GETLK => {
                Self::read_exact_args::<FuseLkIn, R>(&header, readable, "FUSE_GETLK").map(|_args| {
                    // Return "no conflicting lock" — the kernel VFS handles lock
                    // arbitration locally for single-guest virtiofs.
                    let out = FuseLkOut {
                        lk: FuseFileLock {
                            typ: 2, // F_UNLCK
                            ..FuseFileLock::default()
                        },
                    };
                    FuseReply::Lk { header, body: out }
                })
            }
            FUSE_SETLK | FUSE_SETLKW => {
                Self::read_exact_args::<FuseLkIn, R>(&header, readable, "FUSE_SETLK").map(|_args| {
                    // Accept all lock/unlock requests — the kernel VFS tracks
                    // lock state locally between guest processes.
                    FuseReply::Empty { header }
                })
            }
            FUSE_POLL => {
                Self::read_exact_args::<FusePollIn, R>(&header, readable, "FUSE_POLL").map(
                    |_args| {
                        // Return "no events ready" — overlay only needs POLL to not ENOSYS.
                        let out = [0u32, 0u32]; // revents=0, padding=0
                        FuseReply::Poll { header, body: out }
                    },
                )
            }
            FUSE_IOCTL => {
                // No ioctls are supported. Overlay falls back gracefully.
                Ok(Self::error_reply(&header, FuseError::not_tty()))
            }
            other => {
                log::warn!(
                    "FUSE: unhandled opcode {other} nodeid={} → ENOSYS",
                    header.nodeid
                );
                Ok(Self::error_reply(&header, FuseError::no_sys()))
            }
        };

        match reply {
            Ok(reply) => Ok(reply),
            Err(error) => Ok(Self::malformed_request_reply(&header, &error)),
        }
    }

    // =========================================================================
    // Descriptor I/O helpers
    // =========================================================================

    fn error_reply(in_header: &FuseInHeader, errno: FuseError) -> FuseReply {
        log::debug!(
            "FUSE << {} nodeid={} ERROR={}",
            fuse_opcode_name(in_header.opcode),
            in_header.nodeid,
            errno.raw(),
        );
        FuseReply::Error {
            header: *in_header,
            errno,
        }
    }

    fn malformed_request_reply(in_header: &FuseInHeader, error: &VmmError) -> FuseReply {
        log::warn!(
            "FUSE: malformed {} request unique={} nodeid={}: {error}",
            fuse_opcode_name(in_header.opcode),
            in_header.unique,
            in_header.nodeid,
        );
        match in_header.opcode {
            FUSE_FORGET | FUSE_BATCH_FORGET | FUSE_INTERRUPT => FuseReply::NoReply,
            _ => Self::error_reply(in_header, FuseError::invalid()),
        }
    }

    /// Read and validate the FUSE `in_header` from the contiguous byte stream.
    fn read_header<Q: FuseRequest + ?Sized>(readable: &Q) -> Result<FuseInHeader, VmmError> {
        let header = Self::read_pod_from_stream::<FuseInHeader, Q>(
            readable,
            0,
            std::mem::size_of::<FuseInHeader>(),
        )?;
        let declared_len = header.len as usize;
        let header_size = std::mem::size_of::<FuseInHeader>();
        if declared_len < header_size {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request length {declared_len} smaller than header"
            )));
        }
        if declared_len > MAX_FUSE_REQUEST_SIZE {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request length {declared_len} exceeds cap {MAX_FUSE_REQUEST_SIZE}"
            )));
        }
        if declared_len > readable.stream_len() {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request truncated: got {}, declared {declared_len}",
                readable.stream_len()
            )));
        }
        Ok(header)
    }

    /// Read opcode-specific args from the contiguous byte stream.
    fn read_args<T: Copy + bytemuck::Pod, Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<T, VmmError> {
        Self::read_pod_from_stream::<T, Q>(
            readable,
            std::mem::size_of::<FuseInHeader>(),
            header.len as usize,
        )
    }

    /// Read fixed-size opcode args and reject missing or trailing body bytes.
    fn read_exact_args<T: Copy + bytemuck::Pod, Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
        context: &'static str,
    ) -> Result<T, VmmError> {
        Self::validate_fixed_request::<T>(header, context)?;
        Self::read_args::<T, Q>(header, readable)
    }

    /// Read opcode-specific args while permitting versioned trailing fields.
    fn read_prefix_args<T: Copy + bytemuck::Pod, Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
        context: &'static str,
    ) -> Result<T, VmmError> {
        Self::validate_min_request::<T>(header, context)?;
        Self::read_args::<T, Q>(header, readable)
    }

    fn validate_fixed_request<T>(
        header: &FuseInHeader,
        context: &'static str,
    ) -> Result<(), VmmError> {
        let expected = std::mem::size_of::<FuseInHeader>()
            .checked_add(std::mem::size_of::<T>())
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: length overflow")))?;
        Self::validate_request_len(header, expected, context)
    }

    fn validate_min_request<T>(
        header: &FuseInHeader,
        context: &'static str,
    ) -> Result<(), VmmError> {
        let min = std::mem::size_of::<FuseInHeader>()
            .checked_add(std::mem::size_of::<T>())
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: length overflow")))?;
        let actual = header.len as usize;
        if actual < min {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: request length {actual} smaller than minimum {min}"
            )));
        }
        Ok(())
    }

    fn validate_empty_request(
        header: &FuseInHeader,
        context: &'static str,
    ) -> Result<(), VmmError> {
        Self::validate_request_len(header, std::mem::size_of::<FuseInHeader>(), context)
    }

    fn validate_request_len(
        header: &FuseInHeader,
        expected: usize,
        context: &'static str,
    ) -> Result<(), VmmError> {
        let actual = header.len as usize;
        if actual != expected {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: request length {actual} does not match expected {expected}"
            )));
        }
        Ok(())
    }

    fn max_component_payload_len() -> Result<usize, VmmError> {
        MAX_FUSE_NAME_SIZE
            .checked_add(1)
            .ok_or_else(|| VmmError::DeviceConfig("FUSE name payload length overflow".into()))
    }

    fn validate_component_name(name: &[u8], context: &'static str) -> Result<(), VmmError> {
        if name.is_empty() {
            return Err(VmmError::DeviceConfig(format!("{context}: empty name")));
        }
        if name.len() > MAX_FUSE_NAME_SIZE {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: name exceeds maximum size"
            )));
        }
        if name.contains(&b'/') {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: name contains slash"
            )));
        }
        Ok(())
    }

    fn validate_path_name(name: &[u8], context: &'static str) -> Result<(), VmmError> {
        if name.len() > MAX_FUSE_NAME_SIZE {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: name exceeds maximum size"
            )));
        }
        Ok(())
    }

    /// Return bytes before the only required FUSE component-name terminator.
    fn nul_terminated_component_name(
        buf: &[u8],
        context: &'static str,
    ) -> Result<Vec<u8>, VmmError> {
        let null_pos = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: missing NUL terminator")))?;
        if null_pos + 1 != buf.len() {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: trailing bytes after name"
            )));
        }
        let name = &buf[..null_pos];
        Self::validate_component_name(name, context)?;
        Ok(name.to_vec())
    }

    fn nul_terminated_path_name(buf: &[u8], context: &'static str) -> Result<Vec<u8>, VmmError> {
        let null_pos = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: missing NUL terminator")))?;
        if null_pos + 1 != buf.len() {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: trailing bytes after path"
            )));
        }
        let name = &buf[..null_pos];
        Self::validate_path_name(name, context)?;
        Ok(name.to_vec())
    }

    fn split_two_nul_terminated_components(
        buf: &[u8],
        context: &'static str,
    ) -> Result<(Vec<u8>, Vec<u8>), VmmError> {
        let first_null = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: first name missing NUL")))?;

        let rest = &buf[first_null + 1..];
        let second_null = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: second name missing NUL")))?;
        if first_null + 1 + second_null + 1 != buf.len() {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: trailing bytes after second name"
            )));
        }

        let first = &buf[..first_null];
        let second = &rest[..second_null];
        Self::validate_component_name(first, context)?;
        Self::validate_component_name(second, context)?;

        Ok((first.to_vec(), second.to_vec()))
    }

    fn split_symlink_payload(
        buf: &[u8],
        context: &'static str,
    ) -> Result<(Vec<u8>, Vec<u8>), VmmError> {
        let first_null = buf
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: name missing NUL")))?;

        let rest = &buf[first_null + 1..];
        let second_null = rest
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| VmmError::DeviceConfig(format!("{context}: target missing NUL")))?;
        if first_null + 1 + second_null + 1 != buf.len() {
            return Err(VmmError::DeviceConfig(format!(
                "{context}: trailing bytes after target"
            )));
        }

        let name = &buf[..first_null];
        let target = &rest[..second_null];
        Self::validate_component_name(name, context)?;
        Self::validate_path_name(target, context)?;

        Ok((name.to_vec(), target.to_vec()))
    }

    fn expected_request_len(arg_size: usize, payload_size: usize) -> Option<usize> {
        std::mem::size_of::<FuseInHeader>()
            .checked_add(arg_size)?
            .checked_add(payload_size)
    }

    fn capped_reply_size(size: u32) -> u32 {
        size.min(MAX_FUSE_DATA_SIZE_U32)
    }

    fn capped_backend_max_write(size: u32) -> u32 {
        size.min(MAX_FUSE_DATA_SIZE_U32)
    }

    fn bytes_reply_with_limit(header: &FuseInHeader, data: Vec<u8>, limit: usize) -> FuseReply {
        let limit = limit.min(MAX_FUSE_DATA_SIZE);
        if data.len() > limit {
            return Self::error_reply(header, FuseError::range());
        }
        FuseReply::Bytes {
            header: *header,
            data,
        }
    }

    fn read_exact_from_stream<Q: FuseRequest + ?Sized>(
        readable: &Q,
        offset: usize,
        len: usize,
        frame_len: usize,
    ) -> Result<Vec<u8>, VmmError> {
        let end = offset
            .checked_add(len)
            .ok_or(VmmError::AddressOverflow { addr: 0, size: len })?;
        if end > frame_len {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request range {offset}..{end} exceeds frame length {frame_len}"
            )));
        }
        let mut out = vec![0u8; len];
        let n = readable.read_stream_at(offset, &mut out)?;
        if n != len {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request short read at offset {offset}: {n}/{len}"
            )));
        }
        Ok(out)
    }

    fn read_pod_from_stream<T: bytemuck::Pod, Q: FuseRequest + ?Sized>(
        readable: &Q,
        offset: usize,
        frame_len: usize,
    ) -> Result<T, VmmError> {
        let bytes =
            Self::read_exact_from_stream(readable, offset, std::mem::size_of::<T>(), frame_len)?;
        Ok(bytemuck::pod_read_unaligned(&bytes))
    }

    fn read_tail_from_stream<Q: FuseRequest + ?Sized>(
        readable: &Q,
        offset: usize,
        cap: usize,
        frame_len: usize,
    ) -> Result<Vec<u8>, VmmError> {
        if offset > frame_len {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request offset {offset} exceeds frame length {frame_len}"
            )));
        }
        let len = frame_len - offset;
        if len > cap {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request tail length {len} exceeds cap {cap}"
            )));
        }
        Self::read_exact_from_stream(readable, offset, len, frame_len)
    }

    fn offset_after_args<T>() -> Result<usize, VmmError> {
        std::mem::size_of::<FuseInHeader>()
            .checked_add(std::mem::size_of::<T>())
            .ok_or_else(|| VmmError::DeviceConfig("FUSE args offset overflow".into()))
    }

    /// Read a null-terminated name immediately after the FUSE header.
    fn read_name<Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<Vec<u8>, VmmError> {
        Self::read_name_at_offset(header, readable, std::mem::size_of::<FuseInHeader>())
    }

    /// Read a null-terminated name that follows a fixed-size args struct.
    fn read_name_after_args<T, Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<Vec<u8>, VmmError> {
        Self::read_name_at_offset(header, readable, Self::offset_after_args::<T>()?)
    }

    /// Read two null-terminated names after a fixed-size args struct.
    ///
    /// Used by `FUSE_RENAME`/`RENAME2` where: args + oldname\0 + newname\0
    /// is parsed from the byte stream, independent of descriptor boundaries.
    fn read_two_names_after_args<T, Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<(Vec<u8>, Vec<u8>), VmmError> {
        let max = Self::max_component_payload_len()?
            .checked_mul(2)
            .ok_or_else(|| VmmError::DeviceConfig("FUSE two-name length overflow".into()))?;
        let all_data = Self::read_tail_from_stream(
            readable,
            Self::offset_after_args::<T>()?,
            max,
            header.len as usize,
        )?;
        Self::split_two_nul_terminated_components(&all_data, "FUSE two-name payload")
    }

    /// Read a null-terminated name from a byte-stream offset.
    ///
    /// Capped at `MAX_FUSE_NAME_SIZE` (4 KiB) instead of the 1 MiB data limit
    /// to prevent a guest from forcing large host allocations for path names.
    fn read_name_at_offset<Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
        offset: usize,
    ) -> Result<Vec<u8>, VmmError> {
        let buf = Self::read_tail_from_stream(
            readable,
            offset,
            Self::max_component_payload_len()?,
            header.len as usize,
        )?;
        Self::nul_terminated_component_name(&buf, "FUSE name")
    }

    // =========================================================================
    // Opcode handlers
    // =========================================================================

    async fn handle_init<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let init_in = Self::read_prefix_args::<FuseInitIn, Q>(header, readable, "FUSE_INIT")?;

        match self.backend.init().await {
            Ok(mut init_out) => {
                init_out.max_write = Self::capped_backend_max_write(self.backend.max_write());
                // Only advertise capabilities the kernel also supports.
                init_out.flags &= init_in.flags;
                // Negotiate protocol version: servers speak 7.x. When the
                // guest advertises major 7 we cap the minor at the backend's
                // offer; otherwise let the guest parse our defaults and
                // decide whether it wants to retry.
                if init_in.major == 7 {
                    init_out.major = 7;
                    init_out.minor = init_out.minor.min(init_in.minor);
                }
                Ok(FuseReply::Init {
                    header: *header,
                    body: init_out,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_lookup<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let name = Self::read_name(header, readable)?;
        log::debug!(
            "FUSE    LOOKUP parent={} name={:?}",
            header.nodeid,
            String::from_utf8_lossy(&name),
        );
        // Handle "." and ".." — needed for FUSE_EXPORT_SUPPORT (exportfs).
        let result = if name == b"." {
            self.backend
                .getattr(header.nodeid)
                .await
                .map(|a| FuseEntryOut::new(header.nodeid, a.attr))
        } else if name == b".." {
            self.backend.get_parent(header.nodeid).await
        } else {
            self.backend.lookup(header.nodeid, &name).await
        };
        match result {
            Ok(entry) => {
                log::debug!(
                    "FUSE << LOOKUP -> ino={} mode={:#o} nlink={} size={}",
                    entry.nodeid,
                    entry.attr.mode,
                    entry.attr.nlink,
                    entry.attr.size,
                );
                Ok(FuseReply::Entry {
                    header: *header,
                    body: entry,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_forget<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<(), VmmError> {
        let args = Self::read_exact_args::<FuseForgetIn, Q>(header, readable, "FUSE_FORGET")?;
        self.backend.forget(header.nodeid, args.nlookup).await;
        Ok(())
    }

    fn handle_interrupt<Q: FuseRequest + ?Sized>(
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<(), VmmError> {
        let args = Self::read_exact_args::<FuseInterruptIn, Q>(header, readable, "FUSE_INTERRUPT")?;
        log::trace!(
            "FUSE INTERRUPT unique={} target_unique={} — no reply",
            header.unique,
            args.unique,
        );
        Ok(())
    }

    async fn handle_batch_forget<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader, // nodeid unused — entries carry their own
        readable: &Q,
    ) -> Result<(), VmmError> {
        let args = Self::read_args::<FuseBatchForgetIn, Q>(header, readable)?;
        let arg_size = std::mem::size_of::<FuseBatchForgetIn>();
        let entry_size = std::mem::size_of::<FuseForgetOne>();
        let count = args.count as usize;
        if count > MAX_BATCH_FORGET {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE BATCH_FORGET count {count} exceeds cap {MAX_BATCH_FORGET}"
            )));
        }
        let expected_entry_bytes = count.checked_mul(entry_size).ok_or_else(|| {
            VmmError::DeviceConfig("FUSE BATCH_FORGET entry byte length overflow".into())
        })?;
        let expected_len = std::mem::size_of::<FuseInHeader>()
            .checked_add(arg_size)
            .and_then(|len| len.checked_add(expected_entry_bytes))
            .ok_or_else(|| VmmError::DeviceConfig("FUSE BATCH_FORGET length overflow".into()))?;
        if header.len as usize != expected_len {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE BATCH_FORGET length {} does not match count {count} expected {expected_len}",
                header.len
            )));
        }
        let entry_offset = Self::offset_after_args::<FuseBatchForgetIn>()?;
        let entry_bytes = Self::read_exact_from_stream(
            readable,
            entry_offset,
            expected_entry_bytes,
            header.len as usize,
        )?;

        let mut forgets = Vec::with_capacity(count);
        for chunk in entry_bytes.chunks_exact(entry_size) {
            let entry = bytemuck::pod_read_unaligned::<FuseForgetOne>(chunk);
            forgets.push((entry.nodeid, entry.nlookup));
        }
        self.backend.batch_forget(&forgets).await;
        Ok(())
    }

    async fn handle_getattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let _args = Self::read_exact_args::<FuseGetattrIn, Q>(header, readable, "FUSE_GETATTR")?;
        match self.backend.getattr(header.nodeid).await {
            Ok(attr_out) => {
                log::debug!(
                    "FUSE << GETATTR ino={} mode={:#o} nlink={} size={}",
                    header.nodeid,
                    attr_out.attr.mode,
                    attr_out.attr.nlink,
                    attr_out.attr.size,
                );
                Ok(FuseReply::Attr {
                    header: *header,
                    body: attr_out,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_readlink<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        Self::validate_empty_request(header, "FUSE_READLINK")?;
        let _ = readable;
        match self.backend.readlink(header.nodeid).await {
            Ok(data) => Ok(Self::bytes_reply_with_limit(
                header,
                data,
                MAX_FUSE_NAME_SIZE,
            )),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_open<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseOpenIn, Q>(header, readable, "FUSE_OPEN")?;
        match self.backend.open(header.nodeid, args.flags).await {
            Ok(open_out) => Ok(FuseReply::Open {
                header: *header,
                body: open_out,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_read<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseReadIn, Q>(header, readable, "FUSE_READ")?;
        let size = Self::capped_reply_size(args.size);
        match self
            .backend
            .read(header.nodeid, args.fh, args.offset, size)
            .await
        {
            Ok(data) => Ok(Self::bytes_reply_with_limit(header, data, size as usize)),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_release<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseReleaseIn, Q>(header, readable, "FUSE_RELEASE")?;
        self.backend.release(header.nodeid, args.fh).await;
        Ok(FuseReply::Empty { header: *header })
    }

    async fn handle_opendir<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let _args = Self::read_exact_args::<FuseOpenIn, Q>(header, readable, "FUSE_OPENDIR")?;
        match self.backend.opendir(header.nodeid).await {
            Ok(open_out) => Ok(FuseReply::Open {
                header: *header,
                body: open_out,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_readdir<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseReadIn, Q>(header, readable, "FUSE_READDIR")?;
        let size = Self::capped_reply_size(args.size);
        match self
            .backend
            .readdir(header.nodeid, args.fh, args.offset, size)
            .await
        {
            Ok(data) => Ok(Self::bytes_reply_with_limit(header, data, size as usize)),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_readdirplus<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseReadIn, Q>(header, readable, "FUSE_READDIRPLUS")?;
        let size = Self::capped_reply_size(args.size);
        match self
            .backend
            .readdirplus(header.nodeid, args.fh, args.offset, size)
            .await
        {
            Ok(data) => Ok(Self::bytes_reply_with_limit(header, data, size as usize)),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_releasedir<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseReleaseIn, Q>(header, readable, "FUSE_RELEASEDIR")?;
        self.backend.releasedir(header.nodeid, args.fh).await;
        Ok(FuseReply::Empty { header: *header })
    }

    async fn handle_statfs<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        Self::validate_empty_request(header, "FUSE_STATFS")?;
        let _ = readable;
        match self.backend.statfs().await {
            Ok(statfs_out) => Ok(FuseReply::Statfs {
                header: *header,
                body: statfs_out,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_access<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseAccessIn, Q>(header, readable, "FUSE_ACCESS")?;
        match self.backend.access(header.nodeid, args.mask).await {
            Ok(()) => Ok(FuseReply::Empty { header: *header }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_getxattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseGetxattrIn, Q>(header, readable)?;
        let name = Self::read_name_after_args::<FuseGetxattrIn, Q>(header, readable)?;
        log::debug!(
            "FUSE    GETXATTR ino={} name={:?} size={}",
            header.nodeid,
            String::from_utf8_lossy(&name),
            args.size,
        );
        let size = Self::capped_reply_size(args.size);
        match self.backend.getxattr(header.nodeid, &name, size).await {
            Ok(data) => {
                if data.len() > MAX_FUSE_DATA_SIZE {
                    return Ok(Self::error_reply(header, FuseError::range()));
                }
                if args.size == 0 {
                    let data_size = u32::try_from(data.len()).map_err(|_| {
                        VmmError::DeviceConfig(format!("xattr value too large: {}", data.len()))
                    })?;
                    let size_out = FuseGetxattrOut {
                        size: data_size,
                        padding: 0,
                    };
                    Ok(FuseReply::Getxattr {
                        header: *header,
                        body: size_out,
                    })
                } else if data.len() > size as usize {
                    Ok(Self::error_reply(header, FuseError::range()))
                } else {
                    Ok(FuseReply::Bytes {
                        header: *header,
                        data,
                    })
                }
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_listxattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseGetxattrIn, Q>(header, readable, "FUSE_LISTXATTR")?;
        let size = Self::capped_reply_size(args.size);
        match self.backend.listxattr(header.nodeid, size).await {
            Ok(data) => {
                if data.len() > MAX_FUSE_DATA_SIZE {
                    return Ok(Self::error_reply(header, FuseError::range()));
                }
                if args.size == 0 {
                    let data_size = u32::try_from(data.len()).map_err(|_| {
                        VmmError::DeviceConfig(format!(
                            "listxattr result too large: {}",
                            data.len()
                        ))
                    })?;
                    let size_out = FuseGetxattrOut {
                        size: data_size,
                        padding: 0,
                    };
                    Ok(FuseReply::Getxattr {
                        header: *header,
                        body: size_out,
                    })
                } else if data.len() > size as usize {
                    Ok(Self::error_reply(header, FuseError::range()))
                } else {
                    Ok(FuseReply::Bytes {
                        header: *header,
                        data,
                    })
                }
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    // =========================================================================
    // Write-support handlers
    // =========================================================================

    async fn handle_fsync<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseFsyncIn, Q>(header, readable, "FUSE_FSYNC")?;
        let datasync = args.fsync_flags & 1 != 0;
        match self.backend.fsync(header.nodeid, args.fh, datasync).await {
            Ok(()) => Ok(FuseReply::Empty { header: *header }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_flush<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseFlushIn, Q>(header, readable, "FUSE_FLUSH")?;
        // FLUSH corresponds to close().  POSIX close() does not durably
        // persist — it only flushes dirty pages to the filesystem — so we
        // do not fsync here.  Applications that need durability must call
        // fsync() explicitly (which routes to `FsBackend::fsync`).
        match self.backend.flush(header.nodeid, args.fh).await {
            Ok(()) => Ok(FuseReply::Empty { header: *header }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_setattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_exact_args::<FuseSetattrIn, Q>(header, readable, "FUSE_SETATTR")?;
        log::debug!(
            "FUSE    SETATTR ino={} valid={:#x} size={} mode={:#o} uid={} gid={}",
            header.nodeid,
            args.valid,
            args.size,
            args.mode,
            args.uid,
            args.gid,
        );
        match self.backend.setattr(header.nodeid, &args).await {
            Ok(attr_out) => {
                log::debug!(
                    "FUSE << SETATTR -> mode={:#o} nlink={} size={}",
                    attr_out.attr.mode,
                    attr_out.attr.nlink,
                    attr_out.attr.size,
                );
                Ok(FuseReply::Attr {
                    header: *header,
                    body: attr_out,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_write<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseWriteIn, Q>(header, readable)?;
        let arg_size = std::mem::size_of::<FuseWriteIn>();
        let declared = args.size as usize;
        if declared > MAX_FUSE_DATA_SIZE {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }
        let max_write = Self::capped_backend_max_write(self.backend.max_write());
        if max_write == 0 {
            return Ok(Self::error_reply(header, FuseError::read_only()));
        }
        if declared > max_write as usize {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }
        if Self::expected_request_len(arg_size, declared) != Some(header.len as usize) {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }

        let data = Self::read_exact_from_stream(
            readable,
            Self::offset_after_args::<FuseWriteIn>()?,
            declared,
            header.len as usize,
        )?;
        match self
            .backend
            .write(header.nodeid, args.fh, args.offset, &data, args.write_flags)
            .await
        {
            Ok(written) => {
                if written > args.size {
                    return Ok(Self::error_reply(header, FuseError::range()));
                }
                let out = FuseWriteOut {
                    size: written,
                    padding: 0,
                };
                Ok(FuseReply::Write {
                    header: *header,
                    body: out,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_create<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseCreateIn, Q>(header, readable)?;
        let name = Self::read_name_after_args::<FuseCreateIn, Q>(header, readable)?;
        let ctx = FuseContext {
            uid: header.uid,
            gid: header.gid,
        };
        log::debug!(
            "FUSE    CREATE parent={} name={:?} mode={:#o}",
            header.nodeid,
            String::from_utf8_lossy(&name),
            args.mode,
        );
        match self
            .backend
            .create(header.nodeid, &name, args.mode, args.flags, ctx)
            .await
        {
            Ok((entry, open)) => {
                log::debug!("FUSE << CREATE -> ino={} fh={}", entry.nodeid, open.fh);
                Ok(FuseReply::Create {
                    header: *header,
                    entry,
                    open,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_tmpfile<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        // Linux sends the create args plus a version-dependent name-like tail.
        // The backend operation remains anonymous, but we still parse and
        // validate the tail instead of making descriptor boundaries matter.
        let args = Self::read_prefix_args::<FuseCreateIn, Q>(header, readable, "FUSE_TMPFILE")?;
        let tail_offset = Self::offset_after_args::<FuseCreateIn>()?;
        if header.len as usize > tail_offset {
            let tail = Self::read_tail_from_stream(
                readable,
                tail_offset,
                Self::max_component_payload_len()?,
                header.len as usize,
            )?;
            let _name = Self::nul_terminated_path_name(&tail, "FUSE_TMPFILE name")?;
        }
        log::debug!(
            "FUSE    TMPFILE parent={} mode={:#o}",
            header.nodeid,
            args.mode,
        );
        let ctx = FuseContext {
            uid: header.uid,
            gid: header.gid,
        };
        match self
            .backend
            .tmpfile(header.nodeid, args.mode, args.flags, ctx)
            .await
        {
            Ok((entry, open)) => {
                log::debug!("FUSE << TMPFILE -> ino={} fh={}", entry.nodeid, open.fh);
                Ok(FuseReply::Create {
                    header: *header,
                    entry,
                    open,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_mkdir<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseMkdirIn, Q>(header, readable)?;
        let name = Self::read_name_after_args::<FuseMkdirIn, Q>(header, readable)?;
        let ctx = FuseContext {
            uid: header.uid,
            gid: header.gid,
        };
        match self
            .backend
            .mkdir(header.nodeid, &name, args.mode, ctx)
            .await
        {
            Ok(entry) => Ok(FuseReply::Entry {
                header: *header,
                body: entry,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_mknod<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseMknodIn, Q>(header, readable)?;
        let name = Self::read_name_after_args::<FuseMknodIn, Q>(header, readable)?;
        let ctx = FuseContext {
            uid: header.uid,
            gid: header.gid,
        };
        match self
            .backend
            .mknod(header.nodeid, &name, args.mode, args.rdev, ctx)
            .await
        {
            Ok(entry) => Ok(FuseReply::Entry {
                header: *header,
                body: entry,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_unlink<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let name = Self::read_name(header, readable)?;
        log::debug!(
            "FUSE    UNLINK parent={} name={:?}",
            header.nodeid,
            String::from_utf8_lossy(&name),
        );
        match self.backend.unlink(header.nodeid, &name).await {
            Ok(()) => {
                log::debug!("FUSE << UNLINK -> ok");
                Ok(FuseReply::Empty { header: *header })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_rmdir<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let name = Self::read_name(header, readable)?;
        log::debug!(
            "FUSE    RMDIR parent={} name={:?}",
            header.nodeid,
            String::from_utf8_lossy(&name),
        );
        match self.backend.rmdir(header.nodeid, &name).await {
            Ok(()) => Ok(FuseReply::Empty { header: *header }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_rename<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseRenameIn, Q>(header, readable)?;
        let (oldname, newname) =
            Self::read_two_names_after_args::<FuseRenameIn, Q>(header, readable)?;
        log::debug!(
            "FUSE    RENAME parent={} {:?} -> newparent={} {:?}",
            header.nodeid,
            String::from_utf8_lossy(&oldname),
            args.newdir,
            String::from_utf8_lossy(&newname),
        );
        match self
            .backend
            .rename(header.nodeid, &oldname, args.newdir, &newname)
            .await
        {
            Ok(()) => {
                log::debug!("FUSE << RENAME -> ok");
                Ok(FuseReply::Empty { header: *header })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_rename2<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseRename2In, Q>(header, readable)?;
        let (oldname, newname) =
            Self::read_two_names_after_args::<FuseRename2In, Q>(header, readable)?;
        log::debug!(
            "FUSE    RENAME2 parent={} {:?} -> newparent={} {:?} flags={:#x}",
            header.nodeid,
            String::from_utf8_lossy(&oldname),
            args.newdir,
            String::from_utf8_lossy(&newname),
            args.flags,
        );

        let result = if args.flags == RENAME_WHITEOUT {
            // Rename source → dest, then create a whiteout at source.
            self.backend
                .rename_whiteout(header.nodeid, &oldname, args.newdir, &newname)
                .await
        } else if args.flags == 0 {
            self.backend
                .rename(header.nodeid, &oldname, args.newdir, &newname)
                .await
        } else {
            // RENAME_EXCHANGE, RENAME_NOREPLACE — not yet supported.
            Err(FuseError::invalid())
        };

        match result {
            Ok(()) => {
                log::debug!("FUSE << RENAME2 -> ok");
                Ok(FuseReply::Empty { header: *header })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_symlink<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        // FUSE_SYMLINK: name\0target\0 immediately follows the header.
        let data = Self::read_tail_from_stream(
            readable,
            std::mem::size_of::<FuseInHeader>(),
            Self::max_component_payload_len()?
                .checked_mul(2)
                .ok_or_else(|| VmmError::DeviceConfig("FUSE symlink length overflow".into()))?,
            header.len as usize,
        )?;
        let (name, target) = Self::split_symlink_payload(&data, "FUSE symlink payload")?;
        let ctx = FuseContext {
            uid: header.uid,
            gid: header.gid,
        };
        match self
            .backend
            .symlink(header.nodeid, &name, &target, ctx)
            .await
        {
            Ok(entry) => Ok(FuseReply::Entry {
                header: *header,
                body: entry,
            }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_link<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseLinkIn, Q>(header, readable)?;
        let newname = Self::read_name_after_args::<FuseLinkIn, Q>(header, readable)?;
        log::debug!(
            "FUSE    LINK oldino={} newparent={} newname={:?}",
            args.oldnodeid,
            header.nodeid,
            String::from_utf8_lossy(&newname),
        );
        match self
            .backend
            .link(args.oldnodeid, header.nodeid, &newname)
            .await
        {
            Ok(entry) => {
                log::debug!(
                    "FUSE << LINK -> ino={} nlink={}",
                    entry.nodeid,
                    entry.attr.nlink
                );
                Ok(FuseReply::Entry {
                    header: *header,
                    body: entry,
                })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_setxattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let args = Self::read_args::<FuseSetxattrIn, Q>(header, readable)?;
        let arg_size = std::mem::size_of::<FuseSetxattrIn>();
        let declared = args.size as usize;
        if declared > MAX_FUSE_DATA_SIZE {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }
        let fixed = std::mem::size_of::<FuseInHeader>() + arg_size;
        let Some(tail_len) = (header.len as usize).checked_sub(fixed) else {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        };
        let max_tail = MAX_FUSE_NAME_SIZE
            .checked_add(1)
            .and_then(|n| n.checked_add(declared))
            .ok_or_else(|| VmmError::DeviceConfig("FUSE setxattr length overflow".into()))?;
        if tail_len > max_tail {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }

        // Layout: [header][setxattr_in][name\0][value]. The value length is
        // protocol-declared; reject malformed requests instead of truncating.
        let tail = Self::read_exact_from_stream(readable, fixed, tail_len, header.len as usize)?;
        let Some(null_pos) = tail.iter().position(|&b| b == 0) else {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        };
        if null_pos > MAX_FUSE_NAME_SIZE || tail.len() - null_pos - 1 != declared {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }
        let name = tail[..null_pos].to_vec();
        if Self::validate_component_name(&name, "FUSE setxattr name").is_err() {
            return Ok(Self::error_reply(header, FuseError::invalid()));
        }
        let value = tail[null_pos + 1..].to_vec();
        log::debug!(
            "FUSE    SETXATTR ino={} name={:?} value_len={}",
            header.nodeid,
            String::from_utf8_lossy(&name),
            value.len(),
        );
        match self
            .backend
            .setxattr(header.nodeid, &name, &value, args.flags)
            .await
        {
            Ok(()) => {
                log::debug!("FUSE << SETXATTR -> ok");
                Ok(FuseReply::Empty { header: *header })
            }
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }

    async fn handle_removexattr<Q: FuseRequest + ?Sized>(
        &self,
        header: &FuseInHeader,
        readable: &Q,
    ) -> Result<FuseReply, VmmError> {
        let name = Self::read_name(header, readable)?;
        match self.backend.removexattr(header.nodeid, &name).await {
            Ok(()) => Ok(FuseReply::Empty { header: *header }),
            Err(e) => Ok(Self::error_reply(header, e)),
        }
    }
}

// =============================================================================
// READDIRPLUS entry packing helper
// =============================================================================

/// Pack a READDIR entry (`FuseDirent` + name) into a buffer.
///
/// Returns the number of bytes written, or 0 if the entry doesn't fit.
/// Entries are padded to 8-byte alignment.
#[must_use]
pub fn pack_dirent(
    buf: &mut Vec<u8>,
    max_size: usize,
    ino: u64,
    name: &[u8],
    dir_offset: u64,
    file_type: u32,
) -> usize {
    let Ok(namelen) = u32::try_from(name.len()) else {
        return 0;
    };
    let dirent = FuseDirent {
        ino,
        off: dir_offset,
        namelen,
        typ: file_type,
    };

    let fixed_size = std::mem::size_of::<FuseDirent>();
    let entry_size = fixed_size.saturating_add(name.len());
    let padded_size = (entry_size + 7) & !7; // 8-byte alignment

    if buf.len().saturating_add(padded_size) > max_size {
        return 0;
    }

    buf.extend_from_slice(bytemuck::bytes_of(&dirent));
    buf.extend_from_slice(name);
    // Pad to 8-byte alignment
    let padding = padded_size - entry_size;
    buf.extend(std::iter::repeat_n(0u8, padding));

    padded_size
}

/// Pack a READDIRPLUS entry (`FuseEntryOut` + `FuseDirent` + name) into a buffer.
///
/// Returns the number of bytes written, or 0 if the entry doesn't fit.
/// Entries are padded to 8-byte alignment.
#[must_use]
pub fn pack_direntplus(
    buf: &mut Vec<u8>,
    max_size: usize,
    entry: &FuseEntryOut,
    name: &[u8],
    dir_offset: u64,
    file_type: u32,
) -> usize {
    let Ok(namelen) = u32::try_from(name.len()) else {
        return 0;
    };
    let dirent = FuseDirent {
        ino: entry.attr.ino,
        off: dir_offset,
        namelen,
        typ: file_type,
    };

    let fixed_size = std::mem::size_of::<FuseEntryOut>() + std::mem::size_of::<FuseDirent>();
    let entry_size = fixed_size.saturating_add(name.len());
    let padded_size = (entry_size + 7) & !7; // 8-byte alignment

    if buf.len().saturating_add(padded_size) > max_size {
        return 0;
    }

    buf.extend_from_slice(bytemuck::bytes_of(entry));
    buf.extend_from_slice(bytemuck::bytes_of(&dirent));
    buf.extend_from_slice(name);
    // Pad to 8-byte alignment
    let padding = padded_size - entry_size;
    buf.extend(std::iter::repeat_n(0u8, padding));

    padded_size
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NullFsBackend;
    use std::future::Future;
    use std::sync::{
        Mutex,
        atomic::{AtomicBool, Ordering},
    };

    fn request_with_descriptors(descriptors: &[&[u8]]) -> OwnedFuseRequest {
        let bytes = descriptors.iter().map(|d| d.len()).sum();
        let mut request = OwnedFuseRequest::with_capacity(bytes);
        for descriptor in descriptors {
            request
                .push_zeroed(descriptor.len())
                .copy_from_slice(descriptor);
        }
        request
    }

    fn request_with_header(header: &FuseInHeader, descriptors: &[&[u8]]) -> OwnedFuseRequest {
        let bytes = std::mem::size_of::<FuseInHeader>()
            + descriptors.iter().map(|d| d.len()).sum::<usize>();
        let mut request = OwnedFuseRequest::with_capacity(bytes);
        request
            .push_zeroed(std::mem::size_of::<FuseInHeader>())
            .copy_from_slice(bytemuck::bytes_of(header));
        for descriptor in descriptors {
            request
                .push_zeroed(descriptor.len())
                .copy_from_slice(descriptor);
        }
        request
    }

    fn block_on_ready<F: Future>(future: F) -> F::Output {
        let waker = std::task::Waker::noop();
        let mut context = std::task::Context::from_waker(waker);
        let mut future = std::pin::pin!(future);
        match future.as_mut().poll(&mut context) {
            std::task::Poll::Ready(output) => output,
            std::task::Poll::Pending => panic!("test future unexpectedly pending"),
        }
    }

    fn header(opcode: u32, body_len: usize) -> FuseInHeader {
        FuseInHeader {
            len: u32::try_from(std::mem::size_of::<FuseInHeader>() + body_len).unwrap(),
            opcode,
            unique: 42,
            nodeid: 1,
            ..Default::default()
        }
    }

    fn assert_error_reply(reply: FuseReply, expected: FuseError) {
        match reply {
            FuseReply::Error { errno, .. } => assert_eq!(errno, expected),
            other => panic!("expected error {expected}, got {other:?}"),
        }
    }

    struct BoundedReplyBackend {
        bytes_len: usize,
        max_write: u32,
        write_return: u32,
        write_called: AtomicBool,
        forget_called: AtomicBool,
        rename_called: AtomicBool,
        rename_whiteout_called: AtomicBool,
        batch_forget_calls: Mutex<Vec<Vec<(u64, u64)>>>,
        lookup_names: Mutex<Vec<Vec<u8>>>,
    }

    impl BoundedReplyBackend {
        fn new(bytes_len: usize) -> Self {
            Self {
                bytes_len,
                max_write: MAX_FUSE_DATA_SIZE_U32,
                write_return: 0,
                write_called: AtomicBool::new(false),
                forget_called: AtomicBool::new(false),
                rename_called: AtomicBool::new(false),
                rename_whiteout_called: AtomicBool::new(false),
                batch_forget_calls: Mutex::new(Vec::new()),
                lookup_names: Mutex::new(Vec::new()),
            }
        }

        fn with_max_write(mut self, max_write: u32) -> Self {
            self.max_write = max_write;
            self
        }

        fn with_write_return(mut self, write_return: u32) -> Self {
            self.write_return = write_return;
            self
        }

        fn bytes(&self) -> Vec<u8> {
            vec![0x55; self.bytes_len]
        }

        fn batch_forget_calls(&self) -> Vec<Vec<(u64, u64)>> {
            self.batch_forget_calls.lock().unwrap().clone()
        }

        fn lookup_names(&self) -> Vec<Vec<u8>> {
            self.lookup_names.lock().unwrap().clone()
        }
    }

    impl FsBackend for BoundedReplyBackend {
        async fn init(&self) -> Result<FuseInitOut, FuseError> {
            Ok(FuseInitOut {
                major: 7,
                minor: 31,
                ..Default::default()
            })
        }

        async fn lookup(&self, _parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
            self.lookup_names.lock().unwrap().push(name.to_vec());
            Ok(FuseEntryOut::new(2, FuseAttr::default()))
        }

        async fn forget(&self, _nodeid: u64, _nlookup: u64) {
            self.forget_called.store(true, Ordering::SeqCst);
        }

        async fn batch_forget(&self, forgets: &[(u64, u64)]) {
            self.batch_forget_calls
                .lock()
                .unwrap()
                .push(forgets.to_vec());
        }

        async fn getattr(&self, _nodeid: u64) -> Result<FuseAttrOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
            Ok(self.bytes())
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
            Ok(self.bytes())
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
            Ok(self.bytes())
        }

        async fn readdirplus(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Ok(self.bytes())
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

        async fn write(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _data: &[u8],
            _write_flags: u32,
        ) -> Result<u32, FuseError> {
            self.write_called.store(true, Ordering::SeqCst);
            Ok(self.write_return)
        }

        async fn rename(
            &self,
            _parent: u64,
            _name: &[u8],
            _newparent: u64,
            _newname: &[u8],
        ) -> Result<(), FuseError> {
            self.rename_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn rename_whiteout(
            &self,
            _parent: u64,
            _name: &[u8],
            _newparent: u64,
            _newname: &[u8],
        ) -> Result<(), FuseError> {
            self.rename_whiteout_called.store(true, Ordering::SeqCst);
            Ok(())
        }

        async fn get_parent(&self, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
            Err(FuseError::no_sys())
        }

        fn max_write(&self) -> u32 {
            self.max_write
        }
    }

    #[test]
    fn test_fuse_in_header_size() {
        assert_eq!(std::mem::size_of::<FuseInHeader>(), 40);
    }

    #[test]
    fn test_fuse_out_header_size() {
        assert_eq!(std::mem::size_of::<FuseOutHeader>(), 16);
    }

    #[test]
    fn test_fuse_attr_size() {
        assert_eq!(std::mem::size_of::<FuseAttr>(), 88);
    }

    #[test]
    fn test_fuse_entry_out_size() {
        assert_eq!(std::mem::size_of::<FuseEntryOut>(), 128);
    }

    #[test]
    fn test_fuse_init_in_size() {
        assert_eq!(std::mem::size_of::<FuseInitIn>(), 16);
    }

    #[test]
    fn test_fuse_init_out_size() {
        assert_eq!(std::mem::size_of::<FuseInitOut>(), 64);
    }

    #[test]
    fn test_fuse_attr_out_size() {
        assert_eq!(std::mem::size_of::<FuseAttrOut>(), 104);
    }

    #[test]
    fn test_fuse_open_in_size() {
        assert_eq!(std::mem::size_of::<FuseOpenIn>(), 8);
    }

    #[test]
    fn test_fuse_open_out_size() {
        assert_eq!(std::mem::size_of::<FuseOpenOut>(), 16);
    }

    #[test]
    fn test_fuse_read_in_size() {
        assert_eq!(std::mem::size_of::<FuseReadIn>(), 40);
    }

    #[test]
    fn test_fuse_dirent_size() {
        assert_eq!(std::mem::size_of::<FuseDirent>(), 24);
    }

    #[test]
    fn test_fuse_statfs_out_size() {
        assert_eq!(std::mem::size_of::<FuseStatfsOut>(), 80);
    }

    #[test]
    fn test_fuse_forget_in_size() {
        assert_eq!(std::mem::size_of::<FuseForgetIn>(), 8);
    }

    #[test]
    fn test_fuse_forget_one_size() {
        assert_eq!(std::mem::size_of::<FuseForgetOne>(), 16);
    }

    #[test]
    fn test_fuse_setattr_in_size() {
        assert_eq!(std::mem::size_of::<FuseSetattrIn>(), 88);
    }

    #[test]
    fn test_fuse_write_in_size() {
        assert_eq!(std::mem::size_of::<FuseWriteIn>(), 40);
    }

    #[test]
    fn test_fuse_write_out_size() {
        assert_eq!(std::mem::size_of::<FuseWriteOut>(), 8);
    }

    #[test]
    fn read_reply_larger_than_requested_is_rejected() {
        let backend = BoundedReplyBackend::new(9);
        let server = FuseServer::new(&backend);
        let args = FuseReadIn {
            size: 8,
            ..Default::default()
        };
        let header = header(FUSE_READ, std::mem::size_of::<FuseReadIn>());
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args)]);

        let reply = block_on_ready(server.handle_read(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::range());
    }

    #[test]
    fn readlink_reply_uses_path_sized_cap() {
        let backend = BoundedReplyBackend::new(MAX_FUSE_NAME_SIZE + 1);
        let server = FuseServer::new(&backend);
        let header = header(FUSE_READLINK, 0);
        let request = request_with_header(&header, &[]);

        let reply = block_on_ready(server.handle_readlink(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::range());
    }

    #[test]
    fn init_caps_backend_max_write_to_server_limit() {
        let backend = BoundedReplyBackend::new(0).with_max_write(u32::MAX);
        let server = FuseServer::new(&backend);
        let args = FuseInitIn {
            major: 7,
            minor: 31,
            ..Default::default()
        };
        let header = header(FUSE_INIT, std::mem::size_of::<FuseInitIn>());
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args)]);

        let reply = block_on_ready(server.handle_init(&header, &request)).unwrap();

        match reply {
            FuseReply::Init { body, .. } => assert_eq!(body.max_write, MAX_FUSE_DATA_SIZE_U32),
            other => panic!("expected FUSE_INIT reply, got {other:?}"),
        }
    }

    #[test]
    fn write_larger_than_backend_max_write_is_rejected_before_copy() {
        let backend = BoundedReplyBackend::new(0).with_max_write(4);
        let server = FuseServer::new(&backend);
        let args = FuseWriteIn {
            size: 5,
            ..Default::default()
        };
        let header = header(
            FUSE_WRITE,
            std::mem::size_of::<FuseWriteIn>() + args.size as usize,
        );
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args)]);

        let reply = block_on_ready(server.handle_write(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::invalid());
        assert!(!backend.write_called.load(Ordering::SeqCst));
    }

    #[test]
    fn zero_max_write_rejects_writes_as_read_only() {
        let backend = BoundedReplyBackend::new(0).with_max_write(0);
        let server = FuseServer::new(&backend);
        let args = FuseWriteIn {
            size: 1,
            ..Default::default()
        };
        let header = header(
            FUSE_WRITE,
            std::mem::size_of::<FuseWriteIn>() + args.size as usize,
        );
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args)]);

        let reply = block_on_ready(server.handle_write(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::read_only());
        assert!(!backend.write_called.load(Ordering::SeqCst));
    }

    #[test]
    fn batch_forget_exact_request_calls_backend_once() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseBatchForgetIn { count: 2, dummy: 0 };
        let entries = [
            FuseForgetOne {
                nodeid: 11,
                nlookup: 3,
            },
            FuseForgetOne {
                nodeid: 12,
                nlookup: 4,
            },
        ];
        let mut payload = Vec::new();
        payload.extend_from_slice(bytemuck::bytes_of(&args));
        for entry in entries {
            payload.extend_from_slice(bytemuck::bytes_of(&entry));
        }
        let header = header(FUSE_BATCH_FORGET, payload.len());
        let request = request_with_header(&header, &[&payload]);

        block_on_ready(server.handle_batch_forget(&header, &request)).unwrap();

        assert_eq!(backend.batch_forget_calls(), vec![vec![(11, 3), (12, 4)]]);
    }

    #[test]
    fn batch_forget_rejects_oversized_count_before_backend() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseBatchForgetIn {
            count: u32::try_from(MAX_BATCH_FORGET).unwrap() + 1,
            dummy: 0,
        };
        let payload = bytemuck::bytes_of(&args);
        let header = header(FUSE_BATCH_FORGET, payload.len());
        let request = request_with_header(&header, &[payload]);

        let err = block_on_ready(server.handle_batch_forget(&header, &request)).unwrap_err();

        assert!(
            format!("{err}").contains("exceeds cap"),
            "unexpected error: {err}"
        );
        assert!(backend.batch_forget_calls().is_empty());
    }

    #[test]
    fn batch_forget_rejects_truncated_entries_before_backend() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseBatchForgetIn { count: 2, dummy: 0 };
        let entry = FuseForgetOne {
            nodeid: 11,
            nlookup: 3,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(bytemuck::bytes_of(&args));
        payload.extend_from_slice(bytemuck::bytes_of(&entry));
        let header = header(
            FUSE_BATCH_FORGET,
            std::mem::size_of::<FuseBatchForgetIn>() + 2 * std::mem::size_of::<FuseForgetOne>(),
        );
        let request = request_with_header(&header, &[&payload]);

        let err = block_on_ready(server.handle_batch_forget(&header, &request)).unwrap_err();

        assert!(
            format!("{err}").contains("short read"),
            "unexpected error: {err}"
        );
        assert!(backend.batch_forget_calls().is_empty());
    }

    #[test]
    fn descriptor_boundaries_do_not_change_lookup_parsing() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let name = b"file.txt\0";
        let header = header(FUSE_LOOKUP, name.len());

        let split_at_header = request_with_header(&header, &[name]);
        let mut stream = Vec::new();
        stream.extend_from_slice(bytemuck::bytes_of(&header));
        stream.extend_from_slice(name);
        let split_inside_header_and_name =
            request_with_descriptors(&[&stream[..7], &stream[7..43], &stream[43..]]);

        let reply_a = block_on_ready(server.dispatch_owned_request(&split_at_header)).unwrap();
        let reply_b =
            block_on_ready(server.dispatch_owned_request(&split_inside_header_and_name)).unwrap();

        assert!(matches!(reply_a, FuseReply::Entry { .. }));
        assert!(matches!(reply_b, FuseReply::Entry { .. }));
        assert_eq!(
            backend.lookup_names(),
            vec![b"file.txt".to_vec(), b"file.txt".to_vec()]
        );
    }

    #[test]
    fn lookup_malformed_name_returns_einval_before_backend() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let payload = b"file.txt\0junk";
        let header = header(FUSE_LOOKUP, payload.len());
        let request = request_with_header(&header, &[payload]);

        let reply = block_on_ready(server.dispatch_owned_request(&request)).unwrap();

        assert_error_reply(reply, FuseError::invalid());
        assert!(backend.lookup_names().is_empty());
    }

    #[test]
    fn fixed_size_requests_return_einval_for_trailing_body_bytes() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseOpenIn::default();
        let extra = [0x99];
        let header = header(FUSE_OPEN, std::mem::size_of::<FuseOpenIn>() + extra.len());
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args), &extra]);

        let reply = block_on_ready(server.dispatch_owned_request(&request)).unwrap();

        assert_error_reply(reply, FuseError::invalid());
    }

    #[test]
    fn malformed_forget_keeps_no_reply_semantics_before_backend() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseForgetIn { nlookup: 1 };
        let extra = [0x55];
        let header = header(
            FUSE_FORGET,
            std::mem::size_of::<FuseForgetIn>() + extra.len(),
        );
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args), &extra]);

        let reply = block_on_ready(server.dispatch_owned_request(&request)).unwrap();

        assert!(matches!(reply, FuseReply::NoReply));
        assert!(!backend.forget_called.load(Ordering::SeqCst));
    }

    #[test]
    fn malformed_interrupt_keeps_no_reply_semantics() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let header = header(FUSE_INTERRUPT, 0);
        let request = request_with_header(&header, &[]);

        let reply = block_on_ready(server.dispatch_owned_request(&request)).unwrap();

        assert!(matches!(reply, FuseReply::NoReply));
    }

    #[test]
    fn unaligned_owned_descriptor_boundary_does_not_panic() {
        let backend = BoundedReplyBackend::new(0).with_max_write(16);
        let server = FuseServer::new(&backend);
        let args = FuseWriteIn {
            size: 4,
            ..Default::default()
        };
        let payload = [0x33; 4];
        let header = header(
            FUSE_WRITE,
            std::mem::size_of::<FuseWriteIn>() + payload.len(),
        );
        let mut stream = Vec::new();
        stream.extend_from_slice(bytemuck::bytes_of(&header));
        stream.extend_from_slice(bytemuck::bytes_of(&args));
        stream.extend_from_slice(&payload);
        let request = request_with_descriptors(&[&stream[..41], &stream[41..]]);

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            block_on_ready(server.dispatch_owned_request(&request))
        }));

        assert!(result.is_ok(), "owned request parsing panicked");
    }

    #[test]
    fn backend_write_cannot_ack_more_than_guest_sent() {
        let backend = BoundedReplyBackend::new(0)
            .with_max_write(16)
            .with_write_return(5);
        let server = FuseServer::new(&backend);
        let args = FuseWriteIn {
            size: 4,
            ..Default::default()
        };
        let payload = vec![0x11; args.size as usize];
        let header = header(
            FUSE_WRITE,
            std::mem::size_of::<FuseWriteIn>() + payload.len(),
        );
        let request = request_with_header(&header, &[bytemuck::bytes_of(&args), &payload]);

        let reply = block_on_ready(server.handle_write(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::range());
        assert!(backend.write_called.load(Ordering::SeqCst));
    }

    #[test]
    fn test_fuse_create_in_size() {
        assert_eq!(std::mem::size_of::<FuseCreateIn>(), 16);
    }

    #[test]
    fn test_fuse_mkdir_in_size() {
        assert_eq!(std::mem::size_of::<FuseMkdirIn>(), 8);
    }

    #[test]
    fn test_fuse_mknod_in_size() {
        assert_eq!(std::mem::size_of::<FuseMknodIn>(), 16);
    }

    #[test]
    fn test_fuse_rename_in_size() {
        assert_eq!(std::mem::size_of::<FuseRenameIn>(), 8);
    }

    #[test]
    fn test_fuse_rename2_in_size() {
        assert_eq!(std::mem::size_of::<FuseRename2In>(), 16);
    }

    #[test]
    fn test_fuse_link_in_size() {
        assert_eq!(std::mem::size_of::<FuseLinkIn>(), 8);
    }

    #[test]
    fn test_fuse_setxattr_in_size() {
        assert_eq!(std::mem::size_of::<FuseSetxattrIn>(), 8);
    }

    #[test]
    fn test_pack_direntplus_basic() {
        let entry = FuseEntryOut {
            nodeid: 2,
            generation: 0,
            entry_valid: 1,
            attr_valid: 1,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: FuseAttr {
                ino: 2,
                mode: 0o04_0755, // directory
                ..Default::default()
            },
        };
        let name = b"testdir";
        let mut buf = Vec::new();

        let written = pack_direntplus(&mut buf, 4096, &entry, name, 1, 4);
        assert!(written > 0);
        // Should be 8-byte aligned
        assert_eq!(written % 8, 0);
        // FuseEntryOut(128) + FuseDirent(24) + name(7) = 159, padded to 160
        assert_eq!(written, 160);
    }

    #[test]
    fn test_pack_direntplus_doesnt_fit() {
        let entry = FuseEntryOut::default();
        let name = b"test";
        let mut buf = Vec::new();

        // Buffer max too small
        let written = pack_direntplus(&mut buf, 10, &entry, name, 1, 4);
        assert_eq!(written, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn read_name_requires_nul_terminator() {
        let header = header(FUSE_LOOKUP, b"unterminated".len());
        let request = request_with_header(&header, &[b"unterminated"]);
        let err = FuseServer::<NullFsBackend>::read_name(&header, &request).unwrap_err();
        assert!(format!("{err}").contains("missing NUL"), "got: {err}");
    }

    #[test]
    fn read_name_rejects_empty_component() {
        let header = header(FUSE_LOOKUP, b"\0".len());
        let request = request_with_header(&header, &[b"\0"]);

        let err = FuseServer::<NullFsBackend>::read_name(&header, &request).unwrap_err();

        assert!(format!("{err}").contains("empty name"), "got: {err}");
    }

    #[test]
    fn read_name_rejects_component_with_slash() {
        let header = header(FUSE_LOOKUP, b"dir/file\0".len());
        let request = request_with_header(&header, &[b"dir/file\0"]);

        let err = FuseServer::<NullFsBackend>::read_name(&header, &request).unwrap_err();

        assert!(format!("{err}").contains("contains slash"), "got: {err}");
    }

    #[test]
    fn read_name_accepts_max_sized_component() {
        let mut payload = vec![b'a'; MAX_FUSE_NAME_SIZE];
        payload.push(0);
        let header = header(FUSE_LOOKUP, payload.len());
        let request = request_with_header(&header, &[&payload]);

        let name = FuseServer::<NullFsBackend>::read_name(&header, &request).unwrap();

        assert_eq!(name, vec![b'a'; MAX_FUSE_NAME_SIZE]);
    }

    #[test]
    fn read_name_rejects_component_larger_than_max() {
        let mut payload = vec![b'a'; MAX_FUSE_NAME_SIZE + 1];
        payload.push(0);
        let header = header(FUSE_LOOKUP, payload.len());
        let request = request_with_header(&header, &[&payload]);

        let err = FuseServer::<NullFsBackend>::read_name(&header, &request).unwrap_err();

        assert!(format!("{err}").contains("exceeds cap"), "got: {err}");
    }

    #[test]
    fn read_name_after_args_requires_nul_terminator() {
        let mut arg_and_name = vec![0u8; std::mem::size_of::<FuseMkdirIn>()];
        arg_and_name.extend_from_slice(b"dirname");
        let header = header(FUSE_MKDIR, arg_and_name.len());
        let request = request_with_header(&header, &[&arg_and_name]);

        let err =
            FuseServer::<NullFsBackend>::read_name_after_args::<FuseMkdirIn, _>(&header, &request)
                .unwrap_err();
        assert!(format!("{err}").contains("missing NUL"), "got: {err}");
    }

    #[test]
    fn read_two_names_requires_both_nul_terminators() {
        let mut arg_and_names = vec![0u8; std::mem::size_of::<FuseRenameIn>()];
        arg_and_names.extend_from_slice(b"old\0new");
        let header = header(FUSE_RENAME, arg_and_names.len());
        let request = request_with_header(&header, &[&arg_and_names]);

        let err = FuseServer::<NullFsBackend>::read_two_names_after_args::<FuseRenameIn, _>(
            &header, &request,
        )
        .unwrap_err();
        assert!(
            format!("{err}").contains("second name missing NUL"),
            "got: {err}"
        );
    }

    #[test]
    fn read_two_names_rejects_trailing_bytes() {
        let mut arg_and_names = vec![0u8; std::mem::size_of::<FuseRenameIn>()];
        arg_and_names.extend_from_slice(b"old\0new\0junk");
        let header = header(FUSE_RENAME, arg_and_names.len());
        let request = request_with_header(&header, &[&arg_and_names]);

        let err = FuseServer::<NullFsBackend>::read_two_names_after_args::<FuseRenameIn, _>(
            &header, &request,
        )
        .unwrap_err();

        assert!(
            format!("{err}").contains("trailing bytes after second name"),
            "got: {err}"
        );
    }

    #[test]
    fn read_two_names_accepts_terminated_payload() {
        let mut arg_and_names = vec![0u8; std::mem::size_of::<FuseRenameIn>()];
        arg_and_names.extend_from_slice(b"old\0new\0");
        let header = header(FUSE_RENAME, arg_and_names.len());
        let request = request_with_header(&header, &[&arg_and_names]);

        let (old, new) = FuseServer::<NullFsBackend>::read_two_names_after_args::<FuseRenameIn, _>(
            &header, &request,
        )
        .unwrap();
        assert_eq!(old, b"old");
        assert_eq!(new, b"new");
    }

    #[test]
    fn rename2_rejects_flags_combined_with_whiteout() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseRename2In {
            newdir: 2,
            flags: RENAME_WHITEOUT | 1,
            padding: 0,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(bytemuck::bytes_of(&args));
        payload.extend_from_slice(b"old\0new\0");
        let header = header(FUSE_RENAME2, payload.len());
        let request = request_with_header(&header, &[&payload]);

        let reply = block_on_ready(server.handle_rename2(&header, &request)).unwrap();

        assert_error_reply(reply, FuseError::invalid());
        assert!(!backend.rename_called.load(Ordering::SeqCst));
        assert!(!backend.rename_whiteout_called.load(Ordering::SeqCst));
    }

    #[test]
    fn rename2_accepts_exact_whiteout_flag() {
        let backend = BoundedReplyBackend::new(0);
        let server = FuseServer::new(&backend);
        let args = FuseRename2In {
            newdir: 2,
            flags: RENAME_WHITEOUT,
            padding: 0,
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(bytemuck::bytes_of(&args));
        payload.extend_from_slice(b"old\0new\0");
        let header = header(FUSE_RENAME2, payload.len());
        let request = request_with_header(&header, &[&payload]);

        let reply = block_on_ready(server.handle_rename2(&header, &request)).unwrap();

        assert!(matches!(reply, FuseReply::Empty { .. }));
        assert!(!backend.rename_called.load(Ordering::SeqCst));
        assert!(backend.rename_whiteout_called.load(Ordering::SeqCst));
    }

    // -------------------------------------------------------------------------
    // Wire struct field layout tests (verify offsets match kernel ABI)
    // -------------------------------------------------------------------------

    #[test]
    fn test_setattr_in_field_offsets() {
        let sa = FuseSetattrIn {
            valid: 0x1111,
            padding: 0,
            fh: 0x2222,
            size: 0x3333,
            lock_owner: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: 0o755,
            unused4: 0,
            uid: 1000,
            gid: 2000,
            unused5: 0,
        };
        let bytes = bytemuck::bytes_of(&sa);
        // valid at offset 0 (u32)
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 0x1111);
        // fh at offset 8 (u64)
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 0x2222);
        // size at offset 16 (u64)
        assert_eq!(
            u64::from_ne_bytes(bytes[16..24].try_into().unwrap()),
            0x3333
        );
        // mode at offset 68 (u32)
        assert_eq!(u32::from_ne_bytes(bytes[68..72].try_into().unwrap()), 0o755);
        // uid at offset 76 (u32)
        assert_eq!(u32::from_ne_bytes(bytes[76..80].try_into().unwrap()), 1000);
        // gid at offset 80 (u32)
        assert_eq!(u32::from_ne_bytes(bytes[80..84].try_into().unwrap()), 2000);
    }

    #[test]
    fn test_write_in_field_offsets() {
        let wi = FuseWriteIn {
            fh: 0xAABB,
            offset: 0xCCDD,
            size: 4096,
            write_flags: 0,
            lock_owner: 0,
            flags: 0,
            padding: 0,
        };
        let bytes = bytemuck::bytes_of(&wi);
        // fh at offset 0 (u64)
        assert_eq!(u64::from_ne_bytes(bytes[0..8].try_into().unwrap()), 0xAABB);
        // offset at 8 (u64)
        assert_eq!(u64::from_ne_bytes(bytes[8..16].try_into().unwrap()), 0xCCDD);
        // size at 16 (u32)
        assert_eq!(u32::from_ne_bytes(bytes[16..20].try_into().unwrap()), 4096);
    }

    #[test]
    fn test_create_in_field_offsets() {
        let ci = FuseCreateIn {
            flags: 0x42,
            mode: 0o644,
            umask: 0o022,
            open_flags: 0,
        };
        let bytes = bytemuck::bytes_of(&ci);
        assert_eq!(u32::from_ne_bytes(bytes[0..4].try_into().unwrap()), 0x42);
        assert_eq!(u32::from_ne_bytes(bytes[4..8].try_into().unwrap()), 0o644);
    }

    #[test]
    fn test_rename2_in_field_offsets() {
        let r2 = FuseRename2In {
            newdir: 42,
            flags: 0x01,
            padding: 0,
        };
        let bytes = bytemuck::bytes_of(&r2);
        assert_eq!(u64::from_ne_bytes(bytes[0..8].try_into().unwrap()), 42);
        assert_eq!(u32::from_ne_bytes(bytes[8..12].try_into().unwrap()), 0x01);
    }

    // -------------------------------------------------------------------------
    // FATTR flag constants test
    // -------------------------------------------------------------------------

    #[test]
    fn test_fattr_constants_are_powers_of_two() {
        assert_eq!(FATTR_MODE, 1 << 0);
        assert_eq!(FATTR_UID, 1 << 1);
        assert_eq!(FATTR_GID, 1 << 2);
        assert_eq!(FATTR_SIZE, 1 << 3);
        assert_eq!(FATTR_ATIME, 1 << 4);
        assert_eq!(FATTR_MTIME, 1 << 5);
        assert_eq!(FATTR_FH, 1 << 6);
        assert_eq!(FATTR_ATIME_NOW, 1 << 7);
        assert_eq!(FATTR_MTIME_NOW, 1 << 8);
        assert_eq!(FATTR_LOCKOWNER, 1 << 9);
        assert_eq!(FATTR_CTIME, 1 << 10);
    }

    // -------------------------------------------------------------------------
    // Opcode constants match FUSE spec
    // -------------------------------------------------------------------------

    #[test]
    fn test_opcode_values_match_fuse_spec() {
        assert_eq!(FUSE_LOOKUP, 1);
        assert_eq!(FUSE_FORGET, 2);
        assert_eq!(FUSE_GETATTR, 3);
        assert_eq!(FUSE_SETATTR, 4);
        assert_eq!(FUSE_READLINK, 5);
        assert_eq!(FUSE_SYMLINK, 6);
        assert_eq!(FUSE_MKNOD, 8);
        assert_eq!(FUSE_MKDIR, 9);
        assert_eq!(FUSE_UNLINK, 10);
        assert_eq!(FUSE_RMDIR, 11);
        assert_eq!(FUSE_RENAME, 12);
        assert_eq!(FUSE_LINK, 13);
        assert_eq!(FUSE_OPEN, 14);
        assert_eq!(FUSE_READ, 15);
        assert_eq!(FUSE_WRITE, 16);
        assert_eq!(FUSE_STATFS, 17);
        assert_eq!(FUSE_RELEASE, 18);
        assert_eq!(FUSE_FSYNC, 20);
        assert_eq!(FUSE_SETXATTR, 21);
        assert_eq!(FUSE_GETXATTR, 22);
        assert_eq!(FUSE_LISTXATTR, 23);
        assert_eq!(FUSE_REMOVEXATTR, 24);
        assert_eq!(FUSE_FLUSH, 25);
        assert_eq!(FUSE_INIT, 26);
        assert_eq!(FUSE_OPENDIR, 27);
        assert_eq!(FUSE_READDIR, 28);
        assert_eq!(FUSE_RELEASEDIR, 29);
        assert_eq!(FUSE_ACCESS, 34);
        assert_eq!(FUSE_CREATE, 35);
        assert_eq!(FUSE_DESTROY, 38);
        assert_eq!(FUSE_BATCH_FORGET, 42);
        assert_eq!(FUSE_READDIRPLUS, 44);
        assert_eq!(FUSE_RENAME2, 45);
    }

    // -------------------------------------------------------------------------
    // pack_dirent tests
    // -------------------------------------------------------------------------

    #[test]
    fn test_pack_dirent_basic() {
        let mut buf = Vec::new();
        let written = pack_dirent(&mut buf, 4096, 42, b"hello", 1, 8);
        assert!(written > 0);
        assert_eq!(written % 8, 0);
        // FuseDirent(24) + name(5) = 29, padded to 32
        assert_eq!(written, 32);
        assert_eq!(buf.len(), 32);
    }

    #[test]
    fn test_pack_dirent_doesnt_fit() {
        let mut buf = Vec::new();
        let written = pack_dirent(&mut buf, 10, 1, b"test", 1, 4);
        assert_eq!(written, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_pack_dirent_empty_name() {
        let mut buf = Vec::new();
        let written = pack_dirent(&mut buf, 4096, 1, b"", 1, 4);
        assert!(written > 0);
        // FuseDirent(24) + name(0) = 24, already 8-byte aligned
        assert_eq!(written, 24);
    }

    #[test]
    fn test_pack_dirent_alignment() {
        // Name of exactly 8 bytes → no padding needed
        let mut buf = Vec::new();
        let written = pack_dirent(&mut buf, 4096, 1, b"12345678", 1, 4);
        // FuseDirent(24) + name(8) = 32, already aligned
        assert_eq!(written, 32);

        // Name of 1 byte → needs 7 bytes padding
        let mut buf2 = Vec::new();
        let written2 = pack_dirent(&mut buf2, 4096, 1, b"a", 1, 4);
        // FuseDirent(24) + name(1) = 25, padded to 32
        assert_eq!(written2, 32);
    }

    // -------------------------------------------------------------------------
    // fuse_opcode_name uses constants
    // -------------------------------------------------------------------------

    #[test]
    fn test_fuse_attr_out_new_sets_validity() {
        let attr = FuseAttr {
            ino: 42,
            mode: 0o10_0644,
            size: 1024,
            ..Default::default()
        };
        let out = FuseAttrOut::new(attr);
        assert_eq!(out.attr_valid, ATTR_VALID_SECS);
        assert_eq!(out.attr_valid_nsec, 0);
        assert_eq!(out.dummy, 0);
        assert_eq!(out.attr.ino, 42);
        assert_eq!(out.attr.mode, 0o10_0644);
        assert_eq!(out.attr.size, 1024);
    }

    #[test]
    fn test_fuse_entry_out_new_sets_validity() {
        let attr = FuseAttr {
            ino: 7,
            mode: 0o04_0755,
            nlink: 2,
            ..Default::default()
        };
        let out = FuseEntryOut::new(99, attr);
        assert_eq!(out.nodeid, 99);
        assert_eq!(out.generation, 0);
        assert_eq!(out.entry_valid, ENTRY_VALID_SECS);
        assert_eq!(out.attr_valid, ATTR_VALID_SECS);
        assert_eq!(out.entry_valid_nsec, 0);
        assert_eq!(out.attr_valid_nsec, 0);
        assert_eq!(out.attr.ino, 7);
        assert_eq!(out.attr.mode, 0o04_0755);
        assert_eq!(out.attr.nlink, 2);
    }

    #[test]
    fn test_fuse_opcode_name_uses_constants() {
        assert_eq!(fuse_opcode_name(FUSE_LOOKUP), "LOOKUP");
        assert_eq!(fuse_opcode_name(FUSE_INIT), "INIT");
        assert_eq!(fuse_opcode_name(FUSE_WRITE), "WRITE");
        assert_eq!(fuse_opcode_name(FUSE_RENAME2), "RENAME2");
        assert_eq!(fuse_opcode_name(9999), "UNKNOWN");
    }
}
