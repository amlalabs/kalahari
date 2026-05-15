// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)] // Inodes are u64 but always fit in usize on 64-bit.

//! Read-only FUSE filesystem built from in-memory slices and host files.
//!
//! [`SynthesizedFs`] implements [`FixedFsBackend`] — all inodes are allocated
//! at construction time via a builder API. File content comes from either
//! borrowed byte slices (`&'a [u8]`) or owned snapshots of host files.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-synthesized-fs requires a 64-bit target");

use std::collections::HashMap;
use std::fmt;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use amla_fuse::fs_types::{
    ATTR_VALID_SECS, DT_DIR, DT_REG, ENTRY_VALID_SECS, FUSE_ROOT_ID, S_IFDIR, S_IFREG,
};
use amla_fuse::fuse::{
    self, FixedFsBackend, FsBackend, FuseAttr, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseKstatfs,
    FuseOpenOut, FuseStatfsOut,
};
use amla_fuse::fuse_abi::FuseError;

// ─── Constants ──────────────────────────────────────────────────────────

const BLOCK_SIZE: u32 = 4096;
const MAX_READ_SIZE: usize = 128 * 1024;

#[cfg(unix)]
fn open_regular_host_file(path: &Path) -> std::io::Result<(std::fs::File, u64)> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    let len = regular_file_len(&file)?;
    Ok((file, len))
}

#[cfg(not(unix))]
fn open_regular_host_file(path: &Path) -> std::io::Result<(std::fs::File, u64)> {
    let file = std::fs::File::open(path)?;
    let len = regular_file_len(&file)?;
    Ok((file, len))
}

fn regular_file_len(file: &std::fs::File) -> std::io::Result<u64> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "host path is not a regular file",
        ));
    }
    Ok(metadata.len())
}

fn read_host_file_snapshot(path: &Path) -> Result<Box<[u8]>, SynthesizedFsError> {
    let (file, len) = open_regular_host_file(path)?;
    let capacity = usize::try_from(len)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "host file too large"))?;

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(capacity)
        .map_err(std::io::Error::other)?;

    let mut limited = file.take(len);
    limited.read_to_end(&mut bytes)?;
    Ok(bytes.into_boxed_slice())
}

fn read_bytes(data: &[u8], offset: u64, size: u32) -> Vec<u8> {
    let Ok(start) = usize::try_from(offset) else {
        return Vec::new();
    };
    if start >= data.len() {
        return Vec::new();
    }
    let len = (size as usize).min(MAX_READ_SIZE).min(data.len() - start);
    data[start..start + len].to_vec()
}

// ─── Content sources ────────────────────────────────────────────────────

/// Where a file's content comes from.
enum ContentSource<'a> {
    /// In-memory content borrowed from the caller.
    Borrowed(&'a [u8]),
    /// Owned snapshot captured from a host file at build time.
    Owned(Box<[u8]>),
}

/// A regular file in the synthesized tree.
struct FileEntry<'a> {
    content: ContentSource<'a>,
    size: u64,
    mode: u32,
}

/// A directory in the synthesized tree.
struct DirEntry {
    mode: u32,
    /// Child name → inode.
    children: Vec<(Vec<u8>, u64)>,
}

/// An inode in the synthesized tree.
enum InodeEntry<'a> {
    Dir(DirEntry),
    File(FileEntry<'a>),
}

impl InodeEntry<'_> {
    const fn is_dir(&self) -> bool {
        matches!(self, Self::Dir(_))
    }
}

// ─── SynthesizedFs ──────────────────────────────────────────────────────

/// A read-only FUSE filesystem with content known at construction time.
///
/// Files can borrow `&'a [u8]` for zero-copy in-memory content, or own bytes
/// captured from host files at build time. The directory tree is fully built by
/// the [`SynthesizedFsBuilder`].
pub struct SynthesizedFs<'a> {
    /// Inodes indexed by inode number (1-based; index 0 is unused).
    inodes: Vec<Option<InodeEntry<'a>>>,
    /// Parent inode for each inode (root's parent is itself).
    parents: Vec<u64>,
    /// Timestamp for all files/dirs (seconds since epoch).
    mtime: u64,
    /// UID/GID for all files and directories.
    uid: u32,
    gid: u32,
}

impl<'a> SynthesizedFs<'a> {
    /// Create a builder for constructing a synthesized filesystem.
    pub fn builder() -> SynthesizedFsBuilder<'a> {
        SynthesizedFsBuilder::new()
    }

    fn get_inode(&self, nodeid: u64) -> Result<&InodeEntry<'a>, FuseError> {
        self.inodes
            .get(nodeid as usize)
            .and_then(|e| e.as_ref())
            .ok_or(FuseError::not_found())
    }

    const fn make_attr(&self, nodeid: u64, entry: &InodeEntry<'_>) -> FuseAttr {
        match entry {
            InodeEntry::Dir(dir) => FuseAttr {
                ino: nodeid,
                size: 0,
                blocks: 0,
                atime: self.mtime,
                mtime: self.mtime,
                ctime: self.mtime,
                atimensec: 0,
                mtimensec: 0,
                ctimensec: 0,
                mode: S_IFDIR | dir.mode,
                nlink: 2,
                uid: self.uid,
                gid: self.gid,
                rdev: 0,
                blksize: BLOCK_SIZE,
                flags: 0,
            },
            InodeEntry::File(file) => FuseAttr {
                ino: nodeid,
                size: file.size,
                blocks: file.size.div_ceil(512),
                atime: self.mtime,
                mtime: self.mtime,
                ctime: self.mtime,
                atimensec: 0,
                mtimensec: 0,
                ctimensec: 0,
                mode: S_IFREG | file.mode,
                nlink: 1,
                uid: self.uid,
                gid: self.gid,
                rdev: 0,
                blksize: BLOCK_SIZE,
                flags: 0,
            },
        }
    }

    const fn make_entry_out(&self, nodeid: u64, entry: &InodeEntry<'_>) -> FuseEntryOut {
        FuseEntryOut {
            nodeid,
            generation: 0,
            entry_valid: ENTRY_VALID_SECS,
            attr_valid: ATTR_VALID_SECS,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: self.make_attr(nodeid, entry),
        }
    }

    const fn make_attr_out(&self, nodeid: u64, entry: &InodeEntry<'_>) -> FuseAttrOut {
        FuseAttrOut {
            attr_valid: ATTR_VALID_SECS,
            attr_valid_nsec: 0,
            dummy: 0,
            attr: self.make_attr(nodeid, entry),
        }
    }

    fn read_content(source: &ContentSource<'_>, offset: u64, size: u32) -> Vec<u8> {
        match source {
            ContentSource::Borrowed(data) => read_bytes(data, offset, size),
            ContentSource::Owned(data) => read_bytes(data, offset, size),
        }
    }
}

impl FixedFsBackend for SynthesizedFs<'_> {
    fn inode_count(&self) -> u64 {
        // inodes[0] is unused, so count is len - 1.
        //
        // We emit raw dense inodes (1..=N) to the guest via `FuseAttr::ino`.
        // A past audit flagged this as leaking the inode count, but the
        // guest can recover the same number by walking the tree with
        // `readdir` — nothing in this FS is hidden from enumeration. Adding
        // a keyed permutation would buy obfuscation the guest can defeat
        // in one pass, so we keep the simple dense scheme.
        (self.inodes.len() - 1) as u64
    }
}

impl FsBackend for SynthesizedFs<'_> {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        Ok(FuseInitOut {
            major: 7,
            minor: 31,
            max_readahead: 128 * 1024,
            flags: fuse::FUSE_ASYNC_READ | fuse::FUSE_DO_READDIRPLUS,
            max_write: 0,
            ..FuseInitOut::default()
        })
    }

    async fn lookup(&self, parent: u64, name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        let parent_entry = self.get_inode(parent)?;
        let dir = match parent_entry {
            InodeEntry::Dir(d) => d,
            InodeEntry::File(_) => return Err(FuseError::not_dir()),
        };
        for (child_name, child_ino) in &dir.children {
            if child_name == name {
                let child = self.get_inode(*child_ino)?;
                return Ok(self.make_entry_out(*child_ino, child));
            }
        }
        Err(FuseError::not_found())
    }

    async fn forget(&self, _nodeid: u64, _nlookup: u64) {
        // Static filesystem — nothing to clean up.
    }

    async fn batch_forget(&self, _forgets: &[(u64, u64)]) {
        // Static filesystem — nothing to clean up.
    }

    async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        let entry = self.get_inode(nodeid)?;
        Ok(self.make_attr_out(nodeid, entry))
    }

    async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::invalid())
    }

    async fn open(&self, nodeid: u64, _flags: u32) -> Result<FuseOpenOut, FuseError> {
        let entry = self.get_inode(nodeid)?;
        match entry {
            InodeEntry::File(_) => Ok(FuseOpenOut {
                fh: 0,
                open_flags: 0,
                padding: 0,
            }),
            InodeEntry::Dir(_) => Err(FuseError::is_dir()),
        }
    }

    async fn read(
        &self,
        nodeid: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let entry = self.get_inode(nodeid)?;
        match entry {
            InodeEntry::File(f) => Ok(Self::read_content(&f.content, offset, size)),
            InodeEntry::Dir(_) => Err(FuseError::is_dir()),
        }
    }

    async fn release(&self, _nodeid: u64, _fh: u64) {}

    async fn opendir(&self, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        let entry = self.get_inode(nodeid)?;
        match entry {
            InodeEntry::Dir(_) => Ok(FuseOpenOut {
                fh: 0,
                open_flags: 0,
                padding: 0,
            }),
            InodeEntry::File(_) => Err(FuseError::not_dir()),
        }
    }

    async fn readdir(
        &self,
        nodeid: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let entry = self.get_inode(nodeid)?;
        let dir = match entry {
            InodeEntry::Dir(d) => d,
            InodeEntry::File(_) => return Err(FuseError::not_dir()),
        };

        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        // Entry 0: "."
        if index >= offset
            && fuse::pack_dirent(&mut buf, max_size, nodeid, b".", index + 1, DT_DIR) == 0
        {
            return Ok(buf);
        }
        index += 1;

        // Entry 1: ".."
        if index >= offset {
            let parent_ino = self.parents[nodeid as usize];
            if fuse::pack_dirent(&mut buf, max_size, parent_ino, b"..", index + 1, DT_DIR) == 0 {
                return Ok(buf);
            }
        }
        index += 1;

        // Real children.
        for (name, child_ino) in &dir.children {
            if index >= offset {
                let child = self.get_inode(*child_ino)?;
                let typ = if child.is_dir() { DT_DIR } else { DT_REG };
                if fuse::pack_dirent(&mut buf, max_size, *child_ino, name, index + 1, typ) == 0 {
                    return Ok(buf);
                }
            }
            index += 1;
        }

        Ok(buf)
    }

    async fn readdirplus(
        &self,
        nodeid: u64,
        _fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        let entry = self.get_inode(nodeid)?;
        let dir = match entry {
            InodeEntry::Dir(d) => d,
            InodeEntry::File(_) => return Err(FuseError::not_dir()),
        };

        let max_size = size as usize;
        let mut buf = Vec::with_capacity(max_size.min(4096));
        let mut index = 0u64;

        // Entry 0: "."
        if index >= offset {
            let self_entry = self.get_inode(nodeid)?;
            let entry_out = self.make_entry_out(nodeid, self_entry);
            if fuse::pack_direntplus(&mut buf, max_size, &entry_out, b".", index + 1, DT_DIR) == 0 {
                return Ok(buf);
            }
        }
        index += 1;

        // Entry 1: ".."
        if index >= offset {
            let parent_ino = self.parents[nodeid as usize];
            let parent_entry = self.get_inode(parent_ino)?;
            let entry_out = self.make_entry_out(parent_ino, parent_entry);
            if fuse::pack_direntplus(&mut buf, max_size, &entry_out, b"..", index + 1, DT_DIR) == 0
            {
                return Ok(buf);
            }
        }
        index += 1;

        // Real children.
        for (name, child_ino) in &dir.children {
            if index >= offset {
                let child = self.get_inode(*child_ino)?;
                let typ = if child.is_dir() { DT_DIR } else { DT_REG };
                let entry_out = self.make_entry_out(*child_ino, child);
                if fuse::pack_direntplus(&mut buf, max_size, &entry_out, name, index + 1, typ) == 0
                {
                    return Ok(buf);
                }
            }
            index += 1;
        }

        Ok(buf)
    }

    async fn releasedir(&self, _nodeid: u64, _fh: u64) {}

    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        Ok(FuseStatfsOut {
            st: FuseKstatfs {
                blocks: self.inode_count(),
                bfree: 0,
                bavail: 0,
                files: self.inode_count(),
                ffree: 0,
                bsize: BLOCK_SIZE,
                namelen: 255,
                frsize: BLOCK_SIZE,
                padding: 0,
                spare: [0; 6],
            },
        })
    }

    async fn access(&self, nodeid: u64, _mask: u32) -> Result<(), FuseError> {
        let _ = self.get_inode(nodeid)?;
        Ok(())
    }

    async fn getxattr(&self, _nodeid: u64, _name: &[u8], _size: u32) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::not_supported())
    }

    async fn listxattr(&self, _nodeid: u64, _size: u32) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::not_supported())
    }

    async fn get_parent(&self, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        let parent_ino = *self
            .parents
            .get(nodeid as usize)
            .ok_or_else(FuseError::not_found)?;
        let entry = self.get_inode(parent_ino)?;
        Ok(self.make_entry_out(parent_ino, entry))
    }
}

// ─── Errors ─────────────────────────────────────────────────────────────

/// Error returned by [`SynthesizedFsBuilder`] methods.
#[non_exhaustive]
#[derive(Debug)]
pub enum SynthesizedFsError {
    /// Path is empty, absolute, contains NUL, or contains a `.` / `..` / empty
    /// component. Rejected to prevent traversal when paths come from untrusted
    /// sources (git trees, OCI layer tarballs, user-supplied manifests).
    InvalidPath(String),
    /// A directory already contains an entry with this name, or a file was
    /// used where a parent directory was required.
    DuplicateName(String),
    /// I/O error while reading host content.
    Io(std::io::Error),
}

impl fmt::Display for SynthesizedFsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath(msg) => write!(f, "invalid path: {msg}"),
            Self::DuplicateName(name) => write!(f, "duplicate synthesized-fs name: {name}"),
            Self::Io(e) => write!(f, "io: {e}"),
        }
    }
}

impl std::error::Error for SynthesizedFsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidPath(_) | Self::DuplicateName(_) => None,
            Self::Io(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for SynthesizedFsError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<SynthesizedFsError> for std::io::Error {
    fn from(e: SynthesizedFsError) -> Self {
        match e {
            SynthesizedFsError::Io(io) => io,
            SynthesizedFsError::InvalidPath(_) => {
                Self::new(std::io::ErrorKind::InvalidInput, e.to_string())
            }
            SynthesizedFsError::DuplicateName(_) => {
                Self::new(std::io::ErrorKind::AlreadyExists, e.to_string())
            }
        }
    }
}

/// Validate that `path` is a non-empty, relative, traversal-free path.
///
/// Mirrors `amla-vm-erofs`'s `validate_path` but for the relative-path
/// convention used by [`SynthesizedFsBuilder`]. Rejects:
/// - Empty paths and paths ending in `/`.
/// - Absolute paths (leading `/`).
/// - Paths containing NUL bytes.
/// - Any component that is empty (e.g. `foo//bar`), `.`, or `..`.
fn validate_path(path: &str) -> Result<(), SynthesizedFsError> {
    if path.is_empty() {
        return Err(SynthesizedFsError::InvalidPath("empty path".to_string()));
    }
    if path.starts_with('/') {
        return Err(SynthesizedFsError::InvalidPath(format!(
            "absolute path not allowed: {path:?}"
        )));
    }
    if path.ends_with('/') {
        return Err(SynthesizedFsError::InvalidPath(format!(
            "path ends in slash: {path:?}"
        )));
    }
    if path.contains('\0') {
        return Err(SynthesizedFsError::InvalidPath(format!(
            "path contains NUL byte: {path:?}"
        )));
    }
    for component in path.split('/') {
        if component.is_empty() || component == "." || component == ".." {
            return Err(SynthesizedFsError::InvalidPath(format!(
                "reserved or empty component in path: {path:?}"
            )));
        }
    }
    Ok(())
}

// ─── Builder ────────────────────────────────────────────────────────────

/// Builder for constructing a [`SynthesizedFs`].
///
/// Paths are relative to the root (e.g. `"HEAD"`, `"objects/pack/foo.pack"`).
/// Intermediate directories are created automatically.
pub struct SynthesizedFsBuilder<'a> {
    /// Next inode number to allocate.
    next_inode: u64,
    /// All inodes. Index 0 is unused, index 1 is root.
    inodes: Vec<Option<InodeEntry<'a>>>,
    /// Parent inode for each inode.
    parents: Vec<u64>,
    /// Maps (`parent_inode`, name) → `child_inode` for uniqueness checks.
    dir_map: HashMap<(u64, Vec<u8>), u64>,
    /// UID/GID for all files and directories.
    uid: u32,
    gid: u32,
}

impl<'a> SynthesizedFsBuilder<'a> {
    fn new() -> Self {
        // Allocate root at inode 1 (index 1). Index 0 is unused.
        let root = InodeEntry::Dir(DirEntry {
            mode: 0o755,
            children: Vec::new(),
        });
        Self {
            next_inode: 2,
            inodes: vec![None, Some(root)],
            parents: vec![0, FUSE_ROOT_ID], // root's parent is itself
            dir_map: HashMap::new(),
            uid: 0,
            gid: 0,
        }
    }

    const fn alloc_inode(&mut self) -> u64 {
        let ino = self.next_inode;
        self.next_inode += 1;
        ino
    }

    /// Ensure all directories along `path` exist, returning the parent inode
    /// of the final component.
    fn ensure_parents(
        &mut self,
        path: &str,
        dir_mode: u32,
    ) -> Result<(u64, Vec<u8>), SynthesizedFsError> {
        let components: Vec<&str> = path.split('/').collect();
        let (dirs, name) = components.split_at(components.len() - 1);

        let mut current = FUSE_ROOT_ID;
        for &component in dirs {
            let name_bytes = component.as_bytes().to_vec();
            let key = (current, name_bytes.clone());
            if let Some(&existing) = self.dir_map.get(&key) {
                let Some(entry) = self.inodes.get(existing as usize).and_then(Option::as_ref)
                else {
                    return Err(SynthesizedFsError::DuplicateName(component.to_string()));
                };
                if !entry.is_dir() {
                    return Err(SynthesizedFsError::DuplicateName(component.to_string()));
                }
                current = existing;
            } else {
                let ino = self.alloc_inode();
                let dir = InodeEntry::Dir(DirEntry {
                    mode: dir_mode,
                    children: Vec::new(),
                });
                while self.inodes.len() <= ino as usize {
                    self.inodes.push(None);
                    self.parents.push(0);
                }
                self.inodes[ino as usize] = Some(dir);
                self.parents[ino as usize] = current;

                if let Some(InodeEntry::Dir(parent_dir)) = &mut self.inodes[current as usize] {
                    parent_dir.children.push((name_bytes, ino));
                }
                self.dir_map.insert(key, ino);
                current = ino;
            }
        }

        Ok((current, name[0].as_bytes().to_vec()))
    }

    fn insert_file(
        &mut self,
        parent_ino: u64,
        name: Vec<u8>,
        file: InodeEntry<'a>,
    ) -> Result<(), SynthesizedFsError> {
        let key = (parent_ino, name.clone());
        if self.dir_map.contains_key(&key) {
            return Err(SynthesizedFsError::DuplicateName(
                String::from_utf8_lossy(&name).into_owned(),
            ));
        }
        let ino = self.alloc_inode();
        while self.inodes.len() <= ino as usize {
            self.inodes.push(None);
            self.parents.push(0);
        }
        self.inodes[ino as usize] = Some(file);
        self.parents[ino as usize] = parent_ino;

        if let Some(InodeEntry::Dir(dir)) = &mut self.inodes[parent_ino as usize] {
            dir.children.push((name, ino));
        } else {
            return Err(SynthesizedFsError::DuplicateName(
                String::from_utf8_lossy(&key.1).into_owned(),
            ));
        }
        self.dir_map.insert(key, ino);
        Ok(())
    }

    /// Add a file with borrowed in-memory content.
    ///
    /// Returns [`SynthesizedFsError::InvalidPath`] if `path` is empty,
    /// absolute, ends in `/`, contains a NUL byte, or contains any `.`,
    /// `..`, or empty component.
    pub fn file(
        mut self,
        path: &str,
        content: &'a [u8],
        mode: u32,
    ) -> Result<Self, SynthesizedFsError> {
        validate_path(path)?;
        let (parent_ino, name) = self.ensure_parents(path, 0o755)?;
        let file = InodeEntry::File(FileEntry {
            content: ContentSource::Borrowed(content),
            size: content.len() as u64,
            mode,
        });
        self.insert_file(parent_ino, name, file)?;
        Ok(self)
    }

    /// Add a file backed by a host filesystem path.
    ///
    /// The host file is opened, validated as a regular file, and copied into an
    /// owned snapshot immediately. Later guest reads never reopen the path.
    ///
    /// Returns [`SynthesizedFsError::InvalidPath`] on invalid `path`; see
    /// [`file()`](Self::file) for the rules.
    pub fn host_file(
        mut self,
        path: &str,
        host_path: &Path,
        mode: u32,
    ) -> Result<Self, SynthesizedFsError> {
        validate_path(path)?;
        let content = read_host_file_snapshot(host_path)?;
        let size = content.len() as u64;
        let (parent_ino, name) = self.ensure_parents(path, 0o755)?;
        let file = InodeEntry::File(FileEntry {
            content: ContentSource::Owned(content),
            size,
            mode,
        });
        self.insert_file(parent_ino, name, file)?;
        Ok(self)
    }

    /// Add an explicit directory entry (usually not needed — directories are
    /// created automatically by [`file()`](Self::file) and
    /// [`host_file()`](Self::host_file)).
    ///
    /// Returns [`SynthesizedFsError::InvalidPath`] on invalid `path`; see
    /// [`file()`](Self::file) for the rules.
    pub fn dir(mut self, path: &str, mode: u32) -> Result<Self, SynthesizedFsError> {
        validate_path(path)?;
        let components: Vec<&str> = path.split('/').collect();
        let mut current = FUSE_ROOT_ID;
        for component in components {
            let name_bytes = component.as_bytes().to_vec();
            let key = (current, name_bytes.clone());
            if let Some(&ino) = self.dir_map.get(&key) {
                let Some(entry) = self.inodes.get(ino as usize).and_then(Option::as_ref) else {
                    return Err(SynthesizedFsError::DuplicateName(component.to_string()));
                };
                if !entry.is_dir() {
                    return Err(SynthesizedFsError::DuplicateName(component.to_string()));
                }
                current = ino;
            } else {
                let ino = self.alloc_inode();
                let dir = InodeEntry::Dir(DirEntry {
                    mode,
                    children: Vec::new(),
                });
                while self.inodes.len() <= ino as usize {
                    self.inodes.push(None);
                    self.parents.push(0);
                }
                self.inodes[ino as usize] = Some(dir);
                self.parents[ino as usize] = current;
                if let Some(InodeEntry::Dir(parent_dir)) = &mut self.inodes[current as usize] {
                    parent_dir.children.push((name_bytes, ino));
                }
                self.dir_map.insert(key, ino);
                current = ino;
            }
        }
        if let Some(InodeEntry::Dir(dir)) = &mut self.inodes[current as usize] {
            dir.mode = mode;
        }
        Ok(self)
    }

    /// Recursively add all files from a host directory tree.
    ///
    /// Walks `host_dir` and adds each regular file as an owned snapshot under
    /// `prefix`. Directories are created automatically.
    ///
    /// `prefix` may be empty (to add into the root); otherwise it is subject
    /// to the same validation as [`file()`](Self::file).
    pub fn host_dir(
        mut self,
        prefix: &str,
        host_dir: &Path,
        mode: u32,
    ) -> Result<Self, SynthesizedFsError> {
        if !prefix.is_empty() {
            validate_path(prefix)?;
        }
        self = self.walk_host_dir(prefix, host_dir, mode)?;
        Ok(self)
    }

    fn walk_host_dir(
        mut self,
        prefix: &str,
        host_dir: &Path,
        mode: u32,
    ) -> Result<Self, SynthesizedFsError> {
        let entries = std::fs::read_dir(host_dir)?;
        for entry in entries {
            let entry = entry?;
            let file_type = entry.file_type()?;
            let name = entry.file_name();
            // Reject non-UTF-8 filenames rather than using to_string_lossy —
            // that would replace invalid bytes with U+FFFD and smuggle a
            // mangled path past validate_path, desynchronizing what we register
            // from what exists on the host.
            let Some(name_str) = name.to_str() else {
                return Err(SynthesizedFsError::InvalidPath(format!(
                    "non-UTF-8 filename under {}: {}",
                    host_dir.display(),
                    name.to_string_lossy()
                )));
            };
            let child_path = if prefix.is_empty() {
                name_str.to_string()
            } else {
                format!("{prefix}/{name_str}")
            };

            if file_type.is_dir() {
                self = self.walk_host_dir(&child_path, &entry.path(), mode)?;
            } else if file_type.is_file() {
                self = self.host_file(&child_path, &entry.path(), mode)?;
            }
            // Skip symlinks and other file types.
        }
        Ok(self)
    }

    /// Set the UID/GID for all files and directories.
    #[must_use]
    pub const fn uid_gid(mut self, uid: u32, gid: u32) -> Self {
        self.uid = uid;
        self.gid = gid;
        self
    }

    /// Build the final filesystem.
    pub fn build(self) -> SynthesizedFs<'a> {
        // duration_since can only fail if the system clock is before 1970.
        #[allow(clippy::expect_used)]
        let mtime = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system clock before UNIX epoch")
            .as_secs();

        SynthesizedFs {
            inodes: self.inodes,
            parents: self.parents,
            mtime,
            uid: self.uid,
            gid: self.gid,
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use amla_fuse::fuse::{FuseContext, FuseDirent};

    const ROOT_CTX: FuseContext = FuseContext { uid: 0, gid: 0 };

    fn make_simple_fs() -> SynthesizedFs<'static> {
        let head = b"abc123\n";
        let config = b"[core]\n\tbare = false\n";

        SynthesizedFs::builder()
            .file("HEAD", head, 0o444)
            .unwrap()
            .file("config", config, 0o444)
            .unwrap()
            .dir("objects", 0o755)
            .unwrap()
            .build()
    }

    #[test]
    fn inode_count() {
        let fs = make_simple_fs();
        // root(1) + HEAD(2) + config(3) + objects(4) = 4
        assert_eq!(fs.inode_count(), 4);
    }

    #[tokio::test]
    async fn lookup_root_entries() {
        let fs = make_simple_fs();
        let head = fs.lookup(FUSE_ROOT_ID, b"HEAD").await;
        assert!(head.is_ok());
        let entry = head.unwrap();
        assert_eq!(entry.nodeid, 2);

        let config = fs.lookup(FUSE_ROOT_ID, b"config").await;
        assert!(config.is_ok());
        assert_eq!(config.unwrap().nodeid, 3);

        let objects = fs.lookup(FUSE_ROOT_ID, b"objects").await;
        assert!(objects.is_ok());
        assert_eq!(objects.unwrap().nodeid, 4);
    }

    #[tokio::test]
    async fn lookup_nonexistent() {
        let fs = make_simple_fs();
        let result = fs.lookup(FUSE_ROOT_ID, b"nope").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn getattr_root() {
        let fs = make_simple_fs();
        let attr = fs.getattr(FUSE_ROOT_ID).await.unwrap();
        assert_eq!(attr.attr.ino, FUSE_ROOT_ID);
        assert_eq!(attr.attr.mode & S_IFDIR, S_IFDIR);
        assert_eq!(attr.attr.nlink, 2);
    }

    #[tokio::test]
    async fn getattr_file() {
        let fs = make_simple_fs();
        let attr = fs.getattr(2).await.unwrap(); // HEAD
        assert_eq!(attr.attr.ino, 2);
        assert_eq!(attr.attr.mode & S_IFREG, S_IFREG);
        assert_eq!(attr.attr.mode & 0o777, 0o444);
        assert_eq!(attr.attr.size, 7); // "abc123\n"
    }

    #[tokio::test]
    async fn read_borrowed() {
        let fs = make_simple_fs();
        let data = fs.read(2, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"abc123\n");
    }

    #[tokio::test]
    async fn read_partial() {
        let fs = make_simple_fs();
        let data = fs.read(2, 0, 3, 2).await.unwrap();
        assert_eq!(&data, b"12");
    }

    #[tokio::test]
    async fn read_past_eof() {
        let fs = make_simple_fs();
        let data = fs.read(2, 0, 100, 1024).await.unwrap();
        assert!(data.is_empty());
    }

    #[tokio::test]
    async fn read_dir_returns_error() {
        let fs = make_simple_fs();
        let result = fs.read(FUSE_ROOT_ID, 0, 0, 1024).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn readdir_root() {
        let fs = make_simple_fs();
        let data = fs.readdir(FUSE_ROOT_ID, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&data);
        assert!(names.contains(&b"."[..].to_vec()));
        assert!(names.contains(&b".."[..].to_vec()));
        assert!(names.contains(&b"HEAD"[..].to_vec()));
        assert!(names.contains(&b"config"[..].to_vec()));
        assert!(names.contains(&b"objects"[..].to_vec()));
    }

    #[tokio::test]
    async fn readdir_offset_skips_entries() {
        let fs = make_simple_fs();
        // offset=2 should skip "." and ".."
        let data = fs.readdir(FUSE_ROOT_ID, 0, 2, 4096).await.unwrap();
        let names = parse_dirent_names(&data);
        assert!(!names.contains(&b"."[..].to_vec()));
        assert!(!names.contains(&b".."[..].to_vec()));
        assert_eq!(names.len(), 3); // HEAD, config, objects
    }

    #[tokio::test]
    async fn write_returns_erofs() {
        let fs = make_simple_fs();
        let result = fs.write(2, 0, 0, b"data", 0).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn nested_directories() {
        let data = b"packfile";
        let fs = SynthesizedFs::builder()
            .file("objects/pack/foo.pack", data, 0o444)
            .unwrap()
            .build();

        // root(1) + objects(2) + pack(3) + foo.pack(4) = 4
        assert_eq!(fs.inode_count(), 4);

        let objects = fs.lookup(FUSE_ROOT_ID, b"objects").await.unwrap();
        assert_eq!(objects.attr.mode & S_IFDIR, S_IFDIR);

        let pack = fs.lookup(objects.nodeid, b"pack").await.unwrap();
        assert_eq!(pack.attr.mode & S_IFDIR, S_IFDIR);

        let foo = fs.lookup(pack.nodeid, b"foo.pack").await.unwrap();
        assert_eq!(foo.attr.mode & S_IFREG, S_IFREG);
        assert_eq!(foo.attr.size, 8);
    }

    #[tokio::test]
    async fn host_file_read() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"host content here").unwrap();

        let fs = SynthesizedFs::builder()
            .host_file("test.txt", &file_path, 0o444)
            .unwrap()
            .build();

        assert_eq!(fs.inode_count(), 2); // root + file

        let data = fs.read(2, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"host content here");

        // Partial read.
        let data = fs.read(2, 0, 5, 7).await.unwrap();
        assert_eq!(&data, b"content");
    }

    #[tokio::test]
    async fn host_file_is_snapshotted_at_build() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        std::fs::write(&file_path, b"original").unwrap();

        let fs = SynthesizedFs::builder()
            .host_file("test.txt", &file_path, 0o444)
            .unwrap()
            .build();

        std::fs::write(&file_path, b"mutated and longer").unwrap();

        let attr = fs.getattr(2).await.unwrap();
        assert_eq!(attr.attr.size, 8);

        let data = fs.read(2, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"original");

        let data = fs.read(2, 0, 8, 1024).await.unwrap();
        assert!(data.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn host_file_rejects_symlink() {
        let dir = tempfile::tempdir().unwrap();
        let real_path = dir.path().join("real.txt");
        let link_path = dir.path().join("link.txt");
        std::fs::write(&real_path, b"real").unwrap();
        std::os::unix::fs::symlink(&real_path, &link_path).unwrap();

        let result = SynthesizedFs::builder().host_file("link.txt", &link_path, 0o444);
        assert!(matches!(result, Err(SynthesizedFsError::Io(_))));
    }

    #[tokio::test]
    async fn readdirplus_entries() {
        let fs = make_simple_fs();
        let data = fs.readdirplus(FUSE_ROOT_ID, 0, 0, 8192).await.unwrap();
        assert!(!data.is_empty());
    }

    #[tokio::test]
    async fn statfs_values() {
        let fs = make_simple_fs();
        let st = fs.statfs().await.unwrap();
        assert_eq!(st.st.bsize, BLOCK_SIZE);
        assert_eq!(st.st.namelen, 255);
    }

    #[tokio::test]
    async fn access_valid_inode() {
        let fs = make_simple_fs();
        assert!(fs.access(FUSE_ROOT_ID, 0).await.is_ok());
        assert!(fs.access(2, 0).await.is_ok());
    }

    #[tokio::test]
    async fn access_invalid_inode() {
        let fs = make_simple_fs();
        assert!(fs.access(999, 0).await.is_err());
    }

    #[tokio::test]
    async fn host_dir_walk() {
        let dir = tempfile::tempdir().unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir_all(&sub).unwrap();
        std::fs::write(dir.path().join("a.txt"), b"aaa").unwrap();
        std::fs::write(sub.join("b.txt"), b"bbb").unwrap();

        let fs = SynthesizedFs::builder()
            .host_dir("data", dir.path(), 0o444)
            .unwrap()
            .build();

        // root(1) + data(2) + a.txt(3) + sub(4) + b.txt(5) = 5
        assert_eq!(fs.inode_count(), 5);

        let data_dir = fs.lookup(FUSE_ROOT_ID, b"data").await.unwrap();
        let a = fs.lookup(data_dir.nodeid, b"a.txt").await.unwrap();
        let content = fs.read(a.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&content, b"aaa");

        let sub_dir = fs.lookup(data_dir.nodeid, b"sub").await.unwrap();
        let b = fs.lookup(sub_dir.nodeid, b"b.txt").await.unwrap();
        let content = fs.read(b.nodeid, 0, 0, 1024).await.unwrap();
        assert_eq!(&content, b"bbb");
    }

    /// Parse dirent names from a readdir buffer.
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

    /// Parse (nodeid, name) tuples from a readdirplus buffer.
    fn parse_readdirplus_entries(data: &[u8]) -> Vec<(u64, Vec<u8>)> {
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
                entries.push((entry_out.nodeid, data[name_start..name_start + nl].to_vec()));
            }
            let es = (entry_out_size + dirent_size + nl + 7) & !7;
            pos += es;
        }
        entries
    }

    // ─── Forget / batch_forget ──────────────────────────────────────────

    #[tokio::test]
    async fn forget_is_noop() {
        let fs = make_simple_fs();
        // Should not panic — SynthesizedFs is static.
        fs.forget(2, 1).await;
        fs.forget(FUSE_ROOT_ID, 1).await;
        // Inode is still accessible afterward.
        assert!(fs.getattr(2).await.is_ok());
    }

    #[tokio::test]
    async fn batch_forget_is_noop() {
        let fs = make_simple_fs();
        fs.batch_forget(&[(2, 1), (3, 1), (FUSE_ROOT_ID, 5)]).await;
        // All inodes still accessible.
        assert!(fs.getattr(2).await.is_ok());
        assert!(fs.getattr(3).await.is_ok());
    }

    // ─── Readlink ───────────────────────────────────────────────────────

    #[tokio::test]
    async fn readlink_returns_error() {
        let fs = make_simple_fs();
        // No symlinks in SynthesizedFs.
        assert!(fs.readlink(2).await.is_err());
        assert!(fs.readlink(FUSE_ROOT_ID).await.is_err());
    }

    // ─── Opendir / releasedir ───────────────────────────────────────────

    #[tokio::test]
    async fn opendir_file_returns_error() {
        let fs = make_simple_fs();
        assert!(fs.opendir(2).await.is_err()); // HEAD is a file
    }

    #[tokio::test]
    async fn opendir_dir_succeeds() {
        let fs = make_simple_fs();
        let result = fs.opendir(FUSE_ROOT_ID).await;
        assert!(result.is_ok());
        let result = fs.opendir(4).await; // objects dir
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn releasedir_does_not_panic() {
        let fs = make_simple_fs();
        fs.releasedir(FUSE_ROOT_ID, 0).await;
    }

    // ─── Open / release ─────────────────────────────────────────────────

    #[tokio::test]
    async fn open_file_succeeds() {
        let fs = make_simple_fs();
        let result = fs.open(2, 0).await; // HEAD
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn open_dir_returns_eisdir() {
        let fs = make_simple_fs();
        assert!(fs.open(FUSE_ROOT_ID, 0).await.is_err());
    }

    #[tokio::test]
    async fn release_does_not_panic() {
        let fs = make_simple_fs();
        fs.release(2, 0).await;
    }

    // ─── Getxattr / listxattr ───────────────────────────────────────────

    #[tokio::test]
    async fn getxattr_returns_no_data() {
        let fs = make_simple_fs();
        let result = fs.getxattr(2, b"user.test", 256).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn listxattr_returns_empty_or_error() {
        let fs = make_simple_fs();
        let result = fs.listxattr(2, 256).await;
        // Either empty list or ENOTSUP is acceptable.
        if let Ok(data) = result {
            assert!(data.is_empty());
        }
    }

    // ─── Inode boundary checks ──────────────────────────────────────────

    #[tokio::test]
    async fn getattr_invalid_inode_zero() {
        let fs = make_simple_fs();
        assert!(fs.getattr(0).await.is_err());
    }

    #[tokio::test]
    async fn getattr_invalid_inode_past_end() {
        let fs = make_simple_fs();
        // 4 inodes, so 5 is out of range.
        assert!(fs.getattr(5).await.is_err());
        assert!(fs.getattr(u64::MAX).await.is_err());
    }

    #[tokio::test]
    async fn lookup_in_file_returns_error() {
        let fs = make_simple_fs();
        // Inode 2 is HEAD (a file), not a directory.
        assert!(fs.lookup(2, b"child").await.is_err());
    }

    #[tokio::test]
    async fn read_invalid_inode() {
        let fs = make_simple_fs();
        assert!(fs.read(0, 0, 0, 1024).await.is_err());
        assert!(fs.read(999, 0, 0, 1024).await.is_err());
    }

    // ─── Readdirplus content verification ───────────────────────────────

    #[tokio::test]
    async fn readdirplus_root_has_all_entries() {
        let fs = make_simple_fs();
        let data = fs.readdirplus(FUSE_ROOT_ID, 0, 0, 8192).await.unwrap();
        let entries = parse_readdirplus_entries(&data);
        let names: Vec<&[u8]> = entries.iter().map(|(_, n)| n.as_slice()).collect();
        assert!(names.contains(&&b"."[..]));
        assert!(names.contains(&&b".."[..]));
        assert!(names.contains(&&b"HEAD"[..]));
        assert!(names.contains(&&b"config"[..]));
        assert!(names.contains(&&b"objects"[..]));
    }

    #[tokio::test]
    async fn readdirplus_nodeids_match_lookup() {
        let fs = make_simple_fs();
        let data = fs.readdirplus(FUSE_ROOT_ID, 0, 0, 8192).await.unwrap();
        let entries = parse_readdirplus_entries(&data);
        for (nodeid, name) in &entries {
            if name == b"." || name == b".." {
                continue;
            }
            let entry = fs.lookup(FUSE_ROOT_ID, name).await.unwrap();
            assert_eq!(
                *nodeid,
                entry.nodeid,
                "readdirplus nodeid mismatch for {:?}",
                String::from_utf8_lossy(name)
            );
        }
    }

    #[tokio::test]
    async fn readdirplus_file_returns_error() {
        let fs = make_simple_fs();
        assert!(fs.readdirplus(2, 0, 0, 8192).await.is_err());
    }

    // ─── Write operations return EROFS ──────────────────────────────────

    #[tokio::test]
    async fn mkdir_returns_erofs() {
        let fs = make_simple_fs();
        assert!(
            fs.mkdir(FUSE_ROOT_ID, b"newdir", 0o755, ROOT_CTX)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn create_returns_erofs() {
        let fs = make_simple_fs();
        assert!(
            fs.create(FUSE_ROOT_ID, b"file", 0o644, 0, ROOT_CTX)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn unlink_returns_erofs() {
        let fs = make_simple_fs();
        assert!(fs.unlink(FUSE_ROOT_ID, b"HEAD").await.is_err());
    }

    #[tokio::test]
    async fn rmdir_returns_erofs() {
        let fs = make_simple_fs();
        assert!(fs.rmdir(FUSE_ROOT_ID, b"objects").await.is_err());
    }

    #[tokio::test]
    async fn symlink_returns_erofs() {
        let fs = make_simple_fs();
        assert!(
            fs.symlink(FUSE_ROOT_ID, b"link", b"target", ROOT_CTX)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn rename_returns_erofs() {
        let fs = make_simple_fs();
        assert!(
            fs.rename(FUSE_ROOT_ID, b"HEAD", FUSE_ROOT_ID, b"HEAD2")
                .await
                .is_err()
        );
    }

    // ─── Parent pointer validation ──────────────────────────────────────

    #[tokio::test]
    async fn readdir_dotdot_points_to_parent() {
        let fs = SynthesizedFs::builder()
            .file("a/b.txt", b"data", 0o644)
            .unwrap()
            .build();
        // root(1) + a(2) + b.txt(3)
        let a = fs.lookup(FUSE_ROOT_ID, b"a").await.unwrap();
        assert_eq!(a.nodeid, 2);

        // readdir of "a" dir — ".." should have root inode (1).
        let buf = fs.readdir(2, 0, 0, 4096).await.unwrap();
        let dirent_size = std::mem::size_of::<FuseDirent>();
        let mut pos = 0;
        while pos + dirent_size <= buf.len() {
            let dirent: &FuseDirent = bytemuck::from_bytes(&buf[pos..pos + dirent_size]);
            let name_start = pos + dirent_size;
            let name_end = name_start + dirent.namelen as usize;
            if name_end > buf.len() {
                break;
            }
            let name = &buf[name_start..name_end];
            if name == b".." {
                assert_eq!(dirent.ino, FUSE_ROOT_ID, ".. should point to parent");
            }
            pos += (dirent_size + dirent.namelen as usize + 7) & !7;
        }
    }

    // ─── Empty directory readdir ────────────────────────────────────────

    #[tokio::test]
    async fn readdir_empty_dir() {
        let fs = SynthesizedFs::builder()
            .dir("empty", 0o755)
            .unwrap()
            .build();
        let empty = fs.lookup(FUSE_ROOT_ID, b"empty").await.unwrap();
        let buf = fs.readdir(empty.nodeid, 0, 0, 4096).await.unwrap();
        let names = parse_dirent_names(&buf);
        // Should only have . and ..
        assert_eq!(names.len(), 2);
        assert!(names.contains(&b"."[..].to_vec()));
        assert!(names.contains(&b".."[..].to_vec()));
    }

    // ─── Dedup on repeated paths ────────────────────────────────────────

    #[test]
    fn builder_dedup_shared_parents() {
        let fs = SynthesizedFs::builder()
            .file("a/x.txt", b"x", 0o444)
            .unwrap()
            .file("a/y.txt", b"y", 0o444)
            .unwrap()
            .build();
        // root(1) + a(2) + x.txt(3) + y.txt(4) = 4
        assert_eq!(fs.inode_count(), 4);
    }

    #[track_caller]
    fn assert_duplicate_name<T>(result: Result<T, SynthesizedFsError>) {
        match result {
            Err(SynthesizedFsError::DuplicateName(_)) => {}
            Err(other) => panic!("expected DuplicateName, got {other:?}"),
            Ok(_) => panic!("expected DuplicateName error, got Ok"),
        }
    }

    #[test]
    fn builder_rejects_duplicate_file_name() {
        let result = SynthesizedFs::builder()
            .file("dup.txt", b"first", 0o444)
            .unwrap()
            .file("dup.txt", b"second", 0o444);
        assert_duplicate_name(result);
    }

    #[test]
    fn builder_rejects_file_as_parent_dir() {
        let result = SynthesizedFs::builder()
            .file("a", b"file", 0o444)
            .unwrap()
            .file("a/b", b"child", 0o444);
        assert_duplicate_name(result);
    }

    #[test]
    fn builder_rejects_file_over_existing_dir() {
        let result = SynthesizedFs::builder()
            .dir("a", 0o755)
            .unwrap()
            .file("a", b"file", 0o444);
        assert_duplicate_name(result);
    }

    // ─── Path validation ────────────────────────────────────────────────

    /// Assert that a builder result is an [`SynthesizedFsError::InvalidPath`].
    #[track_caller]
    fn assert_invalid_path<T>(result: Result<T, SynthesizedFsError>) {
        match result {
            Err(SynthesizedFsError::InvalidPath(_)) => {}
            Err(other) => panic!("expected InvalidPath, got {other:?}"),
            Ok(_) => panic!("expected InvalidPath error, got Ok"),
        }
    }

    #[test]
    fn reject_dotdot_component() {
        assert_invalid_path(SynthesizedFs::builder().file("foo/../bar", b"x", 0o444));
    }

    #[test]
    fn reject_dot_component() {
        assert_invalid_path(SynthesizedFs::builder().file("foo/./bar", b"x", 0o444));
    }

    #[test]
    fn reject_absolute_path() {
        assert_invalid_path(SynthesizedFs::builder().file("/abs/path", b"x", 0o444));
    }

    #[test]
    fn reject_double_slash() {
        assert_invalid_path(SynthesizedFs::builder().file("foo//bar", b"x", 0o444));
    }

    #[test]
    fn reject_empty_path() {
        assert_invalid_path(SynthesizedFs::builder().file("", b"x", 0o444));
    }

    #[test]
    fn reject_trailing_slash() {
        assert_invalid_path(SynthesizedFs::builder().file("foo/", b"x", 0o444));
    }

    #[test]
    fn reject_nul_byte() {
        assert_invalid_path(SynthesizedFs::builder().file("foo\0bar", b"x", 0o444));
    }

    #[test]
    fn reject_leading_dotdot() {
        assert_invalid_path(SynthesizedFs::builder().file("../escape", b"x", 0o444));
    }

    #[test]
    fn dir_rejects_traversal() {
        assert_invalid_path(SynthesizedFs::builder().dir("foo/..", 0o755));
    }

    #[test]
    fn host_file_rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("t.txt");
        std::fs::write(&file_path, b"x").unwrap();
        assert_invalid_path(SynthesizedFs::builder().host_file("foo/../bar", &file_path, 0o444));
    }

    #[test]
    fn valid_simple_and_nested_paths_accepted() {
        // Sanity check — well-formed paths still work.
        assert!(validate_path("HEAD").is_ok());
        assert!(validate_path("objects/pack/foo.pack").is_ok());
        assert!(validate_path("a.b.c/d").is_ok());
        assert!(validate_path("..foo").is_ok()); // leading-dot filename ok
        assert!(validate_path("foo..").is_ok()); // trailing-dot filename ok
        assert!(validate_path("...").is_ok()); // triple-dot is not ".."
    }

    // ─── Host file partial read at boundary ─────────────────────────────

    #[tokio::test]
    async fn host_file_read_exact_size() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("exact.bin");
        std::fs::write(&file_path, b"12345").unwrap();

        let fs = SynthesizedFs::builder()
            .host_file("exact.bin", &file_path, 0o444)
            .unwrap()
            .build();

        // Read exactly the file size.
        let data = fs.read(2, 0, 0, 5).await.unwrap();
        assert_eq!(&data, b"12345");

        // Read with larger buffer.
        let data = fs.read(2, 0, 0, 1024).await.unwrap();
        assert_eq!(&data, b"12345");

        // Read at the very end — should be empty.
        let data = fs.read(2, 0, 5, 1024).await.unwrap();
        assert!(data.is_empty());
    }
}
