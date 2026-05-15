// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Streaming EROFS image builder.
//!
//! Builds EROFS images with O(metadata) memory usage using a **data-first**
//! on-disk layout: large file data blocks are written to the output during
//! [`push`](ErofsWriter::push) / [`push_file`](ErofsWriter::push_file),
//! and metadata is written afterward during [`finish`](ErofsWriter::finish).
//!
//! ```text
//! Block 0:       [boot sector + superblock (patched last)]
//! Blocks 1..D:   [file data blocks — written during push()]
//! Blocks D..M:   [metadata area — inodes + inline data]
//! Blocks M..T:   [deferred data — large dirs, edge-case files]
//! ```
//!
//! The EROFS format allows this because `meta_blkaddr` in the superblock
//! can point to any block, and each inode's `raw_blkaddr` independently
//! locates its data blocks.

use std::collections::BTreeMap;
use std::io::{Cursor, Read, Seek, SeekFrom, Write};

use sha2::{Digest, Sha256};

use crate::entry::{
    self, Body, DeviceKind, Entry, ImageStats, Metadata, Permissions, Xattr,
    serialize_inline_xattrs,
};
use crate::error::ErofsError;
use crate::ondisk::{
    Dirent, EROFS_FT_BLKDEV, EROFS_FT_CHRDEV, EROFS_FT_DIR, EROFS_FT_FIFO, EROFS_FT_REG_FILE,
    EROFS_FT_SOCK, EROFS_FT_SYMLINK, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN,
    EROFS_INODE_SLOT_SIZE, InodeCompact, InodeExtended, SuperBlock,
};
use crate::{BLOCK_SIZE, SUPERBLOCK_OFFSET};

// ── Constants ───────────────────────────────────────────────────────────

const ZEROS: [u8; BLOCK_SIZE as usize] = [0u8; BLOCK_SIZE as usize];

/// Files larger than this are definitely `FLAT_PLAIN` (can never be inlined).
/// Uses the smallest possible inode (compact, 32 bytes) to get the maximum
/// possible inline capacity.
const MAX_POSSIBLE_INLINE: usize = BLOCK_SIZE as usize - 32;

// ── Internal types ──────────────────────────────────────────────────────

/// Tracks where file data lives during the build.
enum DataRef {
    /// Small data kept in memory (may be tail-packed inline).
    Mem(Vec<u8>),
    /// Data already written to the output at the given block address.
    Written {
        block_addr: u32,
        len: u64,
        digest: [u8; 32],
    },
}

impl DataRef {
    #[allow(clippy::cast_possible_truncation)] // 32-bit targets won't build multi-GiB images
    const fn len(&self) -> usize {
        match self {
            Self::Mem(v) => v.len(),
            Self::Written { len, .. } => *len as usize,
        }
    }
}

/// Body variant using [`DataRef`] instead of owned `Vec<u8>`.
enum StreamBody {
    Directory,
    RegularFile(DataRef),
    Symlink(String),
    Hardlink(String),
    DeviceNode { kind: DeviceKind, rdev: u32 },
    Fifo,
    Socket,
}

/// Computed inode layout — no data stored, just layout decisions.
struct InodeLayout {
    layout: u16,
    data_blocks: u32,
    slots: u64,
}

/// Per-inode metadata pre-computed during `push()`.
struct InodeMeta {
    /// Index into `entries` for this inode.
    entry_idx: usize,
    /// Compact (32) or extended (64) inode on-disk size.
    inode_size: usize,
    /// Whether this inode uses the extended format.
    needs_extended: bool,
    /// Serialized inline xattr blob (empty if no xattrs).
    xattr_blob: Vec<u8>,
    /// `i_xattr_icount` value for the inode header.
    xattr_icount: u16,
    /// Number of extra hard links pointing to this inode.
    extra_nlinks: u32,
}

/// Internal entry — large file data has already been flushed to output.
struct StreamEntry {
    path: String,
    metadata: Metadata,
    body: StreamBody,
}

// ── Checked conversion helpers ──────────────────────────────────────────

#[allow(clippy::needless_pass_by_value)] // used with map_err which passes by value
fn map_io(e: std::io::Error) -> ErofsError {
    ErofsError::Io(e.to_string())
}

fn to_u32(val: u64, what: &str) -> Result<u32, ErofsError> {
    u32::try_from(val).map_err(|_| ErofsError::Overflow(format!("{what}: {val} exceeds u32::MAX")))
}

fn to_usize(val: u64, what: &str) -> Result<usize, ErofsError> {
    usize::try_from(val)
        .map_err(|_| ErofsError::Overflow(format!("{what}: {val} exceeds usize::MAX")))
}

fn to_u16(val: usize, what: &str) -> Result<u16, ErofsError> {
    u16::try_from(val).map_err(|_| ErofsError::Overflow(format!("{what}: {val} exceeds u16::MAX")))
}

// ── Path helpers ────────────────────────────────────────────────────────

fn validate_path(path: &str) -> Result<(), ErofsError> {
    if path.is_empty() || (path != "/" && !path.starts_with('/')) {
        return Err(ErofsError::InvalidPath(path.to_string()));
    }
    if path != "/" && path.ends_with('/') {
        return Err(ErofsError::InvalidPath(path.to_string()));
    }
    if path.contains('\0') {
        return Err(ErofsError::InvalidPath(format!(
            "path contains NUL byte: {path:?}"
        )));
    }
    if path != "/" {
        for component in path[1..].split('/') {
            if component == "." || component == ".." {
                return Err(ErofsError::InvalidPath(format!(
                    "reserved component in path: {path:?}"
                )));
            }
        }
    }
    Ok(())
}

fn parent_of(path: &str) -> &str {
    if path == "/" {
        return "/";
    }
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(pos) => &path[..pos],
    }
}

fn basename(path: &str) -> &str {
    if path == "/" {
        return ".";
    }
    path.rfind('/').map_or(path, |pos| &path[pos + 1..])
}

// ── Layout computation ─────────────────────────────────────────────────

/// Decide layout for an inode given its overhead (inode + xattr size)
/// and data length. No data is stored — just the layout decision.
fn compute_layout(overhead: usize, data_len: usize) -> Result<InodeLayout, ErofsError> {
    let max_inline = (BLOCK_SIZE as usize).saturating_sub(overhead);

    if data_len == 0 {
        Ok(InodeLayout {
            layout: EROFS_INODE_FLAT_PLAIN,
            data_blocks: 0,
            slots: (overhead as u64).div_ceil(EROFS_INODE_SLOT_SIZE).max(1),
        })
    } else if data_len <= max_inline {
        let total_bytes = overhead as u64 + data_len as u64;
        Ok(InodeLayout {
            layout: EROFS_INODE_FLAT_INLINE,
            data_blocks: 0,
            slots: total_bytes.div_ceil(EROFS_INODE_SLOT_SIZE),
        })
    } else {
        let blocks = to_u32(
            (data_len as u64).div_ceil(u64::from(BLOCK_SIZE)),
            "data blocks",
        )?;
        Ok(InodeLayout {
            layout: EROFS_INODE_FLAT_PLAIN,
            data_blocks: blocks,
            slots: (overhead as u64).div_ceil(EROFS_INODE_SLOT_SIZE).max(1),
        })
    }
}

/// Assign NID offsets (slot indices) from layouts.
///
/// `FLAT_INLINE` inodes must not cross a block boundary (kernel returns
/// EFSCORRUPTED). If one would straddle, we skip to the next block.
fn assign_nids(layouts: &[InodeLayout]) -> (Vec<u64>, u64) {
    const SLOTS_PER_BLOCK: u64 = BLOCK_SIZE as u64 / EROFS_INODE_SLOT_SIZE;

    let mut nid_offsets = Vec::with_capacity(layouts.len());
    let mut current_slot: u64 = 0;
    for layout in layouts {
        if layout.slots > 1 && layout.layout == EROFS_INODE_FLAT_INLINE {
            let block_start = current_slot / SLOTS_PER_BLOCK;
            let block_end = (current_slot + layout.slots - 1) / SLOTS_PER_BLOCK;
            if block_start != block_end {
                current_slot = (block_start + 1) * SLOTS_PER_BLOCK;
            }
        }
        nid_offsets.push(current_slot);
        current_slot += layout.slots;
    }
    (nid_offsets, current_slot)
}

// ── Directory entry serialization ───────────────────────────────────────

/// Serialize directory entries into EROFS directory block format.
fn serialize_dir_entries(entries: &[(u64, u8, &[u8])]) -> Result<Vec<u8>, ErofsError> {
    let max_inline_size: usize = BLOCK_SIZE as usize - core::mem::size_of::<InodeCompact>();
    let block_size = BLOCK_SIZE as usize;
    let dirent_size = core::mem::size_of::<Dirent>();
    let mut result = Vec::new();

    let mut i = 0;
    while i < entries.len() {
        let mut count = 0;
        let mut total_size = 0;
        for entry in &entries[i..] {
            let entry_size = dirent_size + entry.2.len();
            if total_size + entry_size > block_size {
                break;
            }
            total_size += entry_size;
            count += 1;
        }
        if count == 0 {
            let name = entries[i].2;
            return Err(ErofsError::NameTooLong {
                name_len: name.len(),
                max_len: block_size - dirent_size,
            });
        }

        let headers_size = count * dirent_size;
        let mut block = vec![0u8; block_size];
        let mut name_offset = headers_size;

        for k in 0..count {
            let (nid, ft, name) = &entries[i + k];
            let nameoff = to_u16(name_offset, "dirent nameoff")?;
            let dirent = Dirent::new(*nid, nameoff, *ft);
            let hdr_off = k * dirent_size;
            block[hdr_off..hdr_off + dirent_size].copy_from_slice(dirent.as_bytes());
            block[name_offset..name_offset + name.len()].copy_from_slice(name);
            name_offset += name.len();
        }

        result.extend_from_slice(&block);
        i += count;
    }

    let used_bytes: usize = entries
        .iter()
        .map(|(_, _, name)| dirent_size + name.len())
        .sum();
    if used_bytes <= max_inline_size {
        result.truncate(used_bytes);
    }
    Ok(result)
}

// ── Block writing helper ────────────────────────────────────────────────

/// Write data at the given block address, padding to block boundary.
/// Returns the number of blocks written.
fn write_padded_blocks(
    writer: &mut (impl Write + Seek),
    block_addr: u32,
    data: &[u8],
) -> Result<u32, ErofsError> {
    let block_offset = u64::from(block_addr) * u64::from(BLOCK_SIZE);
    writer.seek(SeekFrom::Start(block_offset)).map_err(map_io)?;
    writer.write_all(data).map_err(map_io)?;
    let pad = (BLOCK_SIZE as usize - (data.len() % BLOCK_SIZE as usize)) % BLOCK_SIZE as usize;
    if pad > 0 {
        writer.write_all(&ZEROS[..pad]).map_err(map_io)?;
    }
    to_u32(
        (data.len() as u64).div_ceil(u64::from(BLOCK_SIZE)),
        "file data blocks",
    )
}

// ── UUID hashing ────────────────────────────────────────────────────────

fn hash_meta(hasher: &mut Sha256, path: &str, meta: &Metadata, mode_type: u16) {
    hasher.update(path.as_bytes());
    hasher.update((mode_type | meta.permissions.bits()).to_le_bytes());
    hasher.update(meta.uid.to_le_bytes());
    hasher.update(meta.gid.to_le_bytes());
    hasher.update(meta.mtime.to_le_bytes());
    hasher.update(meta.mtime_nsec.to_le_bytes());
}

fn hash_xattrs(hasher: &mut Sha256, meta: &Metadata) {
    for xattr in &meta.xattrs {
        hasher.update(&xattr.key);
        hasher.update(&xattr.value);
    }
}

fn hash_stream_body(hasher: &mut Sha256, body: &StreamBody) {
    match body {
        StreamBody::RegularFile(DataRef::Mem(data)) => hasher.update(data),
        StreamBody::RegularFile(DataRef::Written { digest, .. }) => {
            hasher.update(b"sha256:");
            hasher.update(digest);
        }
        StreamBody::Symlink(t) | StreamBody::Hardlink(t) => hasher.update(t.as_bytes()),
        StreamBody::DeviceNode { kind, rdev } => {
            hasher.update([u8::from(matches!(kind, DeviceKind::Block))]);
            hasher.update(rdev.to_le_bytes());
        }
        StreamBody::Directory | StreamBody::Fifo | StreamBody::Socket => {}
    }
}

fn content_uuid(entries: &[StreamEntry]) -> [u8; 16] {
    let mut hasher = Sha256::new();
    for entry in entries {
        hash_meta(
            &mut hasher,
            &entry.path,
            &entry.metadata,
            stream_body_mode_type(&entry.body),
        );
        hash_stream_body(&mut hasher, &entry.body);
        hash_xattrs(&mut hasher, &entry.metadata);
    }
    finalize_uuid(hasher)
}

fn finalize_uuid(hasher: Sha256) -> [u8; 16] {
    let hash = hasher.finalize();
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&hash[..16]);
    uuid
}

// ── `StreamBody` helpers ────────────────────────────────────────────────

const fn device_mode_type(kind: DeviceKind) -> u16 {
    match kind {
        DeviceKind::Character => 0o020_000,
        DeviceKind::Block => 0o060_000,
    }
}

const fn stream_body_mode_type(body: &StreamBody) -> u16 {
    match body {
        StreamBody::Directory => 0o040_000,
        StreamBody::RegularFile(_) => 0o100_000,
        StreamBody::Symlink(_) => 0o120_000,
        StreamBody::DeviceNode { kind, .. } => device_mode_type(*kind),
        StreamBody::Fifo => 0o010_000,
        StreamBody::Socket => 0o140_000,
        StreamBody::Hardlink(_) => 0,
    }
}

const fn stream_body_mode(body: &StreamBody, permissions: Permissions) -> u16 {
    stream_body_mode_type(body) | permissions.bits()
}

const fn stream_body_to_file_type(body: &StreamBody) -> u8 {
    match body {
        StreamBody::Directory => EROFS_FT_DIR,
        StreamBody::RegularFile(_) => EROFS_FT_REG_FILE,
        StreamBody::Symlink(_) => EROFS_FT_SYMLINK,
        StreamBody::DeviceNode {
            kind: DeviceKind::Character,
            ..
        } => EROFS_FT_CHRDEV,
        StreamBody::DeviceNode {
            kind: DeviceKind::Block,
            ..
        } => EROFS_FT_BLKDEV,
        StreamBody::Fifo => EROFS_FT_FIFO,
        StreamBody::Socket => EROFS_FT_SOCK,
        StreamBody::Hardlink(_) => 0,
    }
}

/// Data length for the extended-format check (push-time).
/// Only `RegularFile` contributes — dir data isn't computed yet.
const fn file_data_size(body: &StreamBody) -> u64 {
    match body {
        StreamBody::RegularFile(r) => r.len() as u64,
        _ => 0,
    }
}

fn build_inode_meta(
    entry_idx: usize,
    metadata: &Metadata,
    body: &StreamBody,
    extra_nlinks: u32,
) -> Result<InodeMeta, ErofsError> {
    let (xattr_blob, xattr_icount) = serialize_inline_xattrs(&metadata.xattrs)?;
    let data_size = file_data_size(body);
    let needs_extended = metadata.uid > u32::from(u16::MAX)
        || metadata.gid > u32::from(u16::MAX)
        || metadata.mtime > 0
        || metadata.mtime_nsec > 0
        || !metadata.xattrs.is_empty()
        || data_size > u64::from(u32::MAX);
    let inode_size = if needs_extended { 64 } else { 32 };

    Ok(InodeMeta {
        entry_idx,
        inode_size,
        needs_extended,
        xattr_blob,
        xattr_icount,
        extra_nlinks,
    })
}

/// Data length including directory data (for layout computation).
fn data_len_with_dirs(
    body: &StreamBody,
    dir_data: &BTreeMap<usize, Vec<u8>>,
    inode_idx: usize,
) -> usize {
    match body {
        StreamBody::Directory => dir_data.get(&inode_idx).map_or(0, Vec::len),
        StreamBody::RegularFile(r) => r.len(),
        StreamBody::Symlink(target) => target.len(),
        _ => 0,
    }
}

// ── Streaming EROFS builder ─────────────────────────────────────────────

/// Streaming EROFS image builder.
///
/// Takes a seekable writer at construction. Large file data is written to
/// the output immediately during [`push`](Self::push), keeping memory
/// usage proportional to metadata size. Call [`finish`](Self::finish) to
/// write metadata and patch the superblock.
///
/// Work is pipelined: path validation, xattr serialization, inode format
/// decisions, and parent-child tracking all happen during `push()`, so
/// `finish()` only does the irreducible minimum (NID assignment, directory
/// serialization, metadata write, superblock patch).
pub struct ErofsWriter<W> {
    writer: W,
    entries: Vec<StreamEntry>,
    /// Pre-computed per-inode metadata (one per non-hardlink entry).
    inode_metas: Vec<InodeMeta>,
    /// Maps path → inode index (for hardlink resolution + parent lookup).
    path_to_inode: BTreeMap<String, usize>,
    /// Maps inode index → sorted child entry indices.
    children: BTreeMap<usize, Vec<usize>>,
    /// Maps entry index → inode index (hardlinks share their target's inode).
    entry_to_inode: Vec<usize>,
    /// Next available block for data (starts at 1, block 0 = superblock).
    next_data_block: u32,
    /// Set after any push error because output writes are not rollbackable.
    poisoned: bool,
}

impl<W: Write + Seek> ErofsWriter<W> {
    /// Create a new streaming EROFS builder writing to `writer`.
    #[must_use]
    pub const fn new(writer: W) -> Self {
        Self {
            writer,
            entries: Vec::new(),
            inode_metas: Vec::new(),
            path_to_inode: BTreeMap::new(),
            children: BTreeMap::new(),
            entry_to_inode: Vec::new(),
            next_data_block: 1,
            poisoned: false,
        }
    }

    /// Push a complete entry. For `RegularFile` entries larger than ~4 KiB,
    /// data is written to the output immediately and the `Vec<u8>` freed.
    pub fn push(&mut self, entry: Entry) -> Result<(), ErofsError> {
        self.ensure_not_poisoned()?;
        let result = self.push_inner(entry);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn push_inner(&mut self, entry: Entry) -> Result<(), ErofsError> {
        validate_path(&entry.path)?;

        // Convert body — may write data blocks to output
        let body = match entry.body {
            Body::Directory => StreamBody::Directory,
            Body::RegularFile(data) => {
                if data.len() > MAX_POSSIBLE_INLINE {
                    let block_addr = self.next_data_block;
                    let len = data.len() as u64;
                    let digest = Sha256::digest(&data).into();
                    let blocks = write_padded_blocks(&mut self.writer, block_addr, &data)?;
                    self.next_data_block = self
                        .next_data_block
                        .checked_add(blocks)
                        .ok_or_else(|| ErofsError::Overflow("next_data_block".to_string()))?;
                    StreamBody::RegularFile(DataRef::Written {
                        block_addr,
                        len,
                        digest,
                    })
                } else {
                    StreamBody::RegularFile(DataRef::Mem(data))
                }
            }
            Body::Symlink(t) => StreamBody::Symlink(t),
            Body::Hardlink(t) => StreamBody::Hardlink(t),
            Body::DeviceNode { kind, rdev } => StreamBody::DeviceNode { kind, rdev },
            Body::Fifo => StreamBody::Fifo,
            Body::Socket => StreamBody::Socket,
        };

        self.register_entry(entry.path, entry.metadata, body)
    }

    /// Stream a regular file's data directly from a reader to the output.
    ///
    /// For files larger than ~4 KiB, data flows `reader → hasher → writer`
    /// with a 64 KiB buffer — zero heap allocation. For smaller files,
    /// data is buffered in memory for potential inline packing.
    ///
    /// `size` is the exact byte count to read from `reader`.
    pub fn push_file(
        &mut self,
        path: String,
        metadata: Metadata,
        size: u64,
        reader: &mut impl Read,
    ) -> Result<(), ErofsError> {
        self.ensure_not_poisoned()?;
        let result = self.push_file_inner(path, metadata, size, reader);
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn push_file_inner(
        &mut self,
        path: String,
        metadata: Metadata,
        size: u64,
        reader: &mut impl Read,
    ) -> Result<(), ErofsError> {
        validate_path(&path)?;

        let data_ref = if size <= MAX_POSSIBLE_INLINE as u64 {
            // size ≤ MAX_POSSIBLE_INLINE ≤ 4064, always fits in usize on 64-bit host.
            let size_usz = to_usize(size, "inline data size")?;
            let mut data = vec![0u8; size_usz];
            reader.read_exact(&mut data).map_err(map_io)?;
            DataRef::Mem(data)
        } else {
            let block_addr = self.next_data_block;
            let block_offset = u64::from(block_addr) * u64::from(BLOCK_SIZE);
            self.writer
                .seek(SeekFrom::Start(block_offset))
                .map_err(map_io)?;

            let mut buf = vec![0u8; 65536];
            let mut file_hasher = Sha256::new();
            let mut remaining = size;
            while remaining > 0 {
                let remaining_usz = to_usize(remaining, "remaining data bytes")?;
                let to_read = buf.len().min(remaining_usz);
                reader.read_exact(&mut buf[..to_read]).map_err(map_io)?;
                file_hasher.update(&buf[..to_read]);
                self.writer.write_all(&buf[..to_read]).map_err(map_io)?;
                remaining -= to_read as u64;
            }
            let bs = u64::from(BLOCK_SIZE);
            let pad = (bs - (size % bs)) % bs;
            if pad > 0 {
                let pad_usz = to_usize(pad, "block padding bytes")?;
                self.writer.write_all(&ZEROS[..pad_usz]).map_err(map_io)?;
            }
            let blocks = to_u32(size.div_ceil(u64::from(BLOCK_SIZE)), "file data blocks")?;
            self.next_data_block = self
                .next_data_block
                .checked_add(blocks)
                .ok_or_else(|| ErofsError::Overflow("next_data_block".to_string()))?;
            DataRef::Written {
                block_addr,
                len: size,
                digest: file_hasher.finalize().into(),
            }
        };

        self.register_entry(path, metadata, StreamBody::RegularFile(data_ref))
    }

    const fn ensure_not_poisoned(&self) -> Result<(), ErofsError> {
        if self.poisoned {
            return Err(ErofsError::BuilderPoisoned);
        }
        Ok(())
    }

    fn parent_inode_for(&self, path: &str) -> Result<Option<usize>, ErofsError> {
        if path == "/" {
            return Ok(None);
        }

        let parent_path = parent_of(path);
        let parent_inode = *self
            .path_to_inode
            .get(parent_path)
            .ok_or_else(|| ErofsError::ParentNotFound(path.to_string()))?;
        let parent_entry_idx = self.inode_metas[parent_inode].entry_idx;
        if !matches!(self.entries[parent_entry_idx].body, StreamBody::Directory) {
            return Err(ErofsError::ParentNotDirectory(parent_path.to_string()));
        }

        Ok(Some(parent_inode))
    }

    /// Set or replace an inline xattr on an entry that has already been
    /// registered with the builder.
    pub fn set_xattr(&mut self, path: &str, xattr: Xattr) -> Result<(), ErofsError> {
        self.ensure_not_poisoned()?;
        validate_path(path)?;
        let inode_idx = *self
            .path_to_inode
            .get(path)
            .ok_or_else(|| ErofsError::PathNotFound(path.to_string()))?;
        let entry_idx = self.inode_metas[inode_idx].entry_idx;
        let mut metadata = self.entries[entry_idx].metadata.clone();
        let Xattr { key, value } = xattr;

        if let Some(idx) = metadata
            .xattrs
            .iter()
            .position(|existing| existing.key == key)
        {
            metadata.xattrs[idx].value = value;
        } else {
            metadata.xattrs.push(Xattr { key, value });
        }

        let extra_nlinks = self.inode_metas[inode_idx].extra_nlinks;
        let inode_meta = build_inode_meta(
            entry_idx,
            &metadata,
            &self.entries[entry_idx].body,
            extra_nlinks,
        )?;
        self.entries[entry_idx].metadata = metadata;
        self.inode_metas[inode_idx] = inode_meta;
        Ok(())
    }

    /// Common registration: validate structure, resolve hardlinks, track
    /// parent-child relationships, pre-compute inode metadata. Called by
    /// both `push()` and `push_file()`.
    fn register_entry(
        &mut self,
        path: String,
        metadata: Metadata,
        body: StreamBody,
    ) -> Result<(), ErofsError> {
        let orig_idx = self.entries.len();

        // Root must be first
        if orig_idx == 0 && path != "/" {
            return Err(ErofsError::InvalidPath(
                "root directory \"/\" must be first entry".to_string(),
            ));
        }
        if orig_idx == 0 && !matches!(body, StreamBody::Directory) {
            return Err(ErofsError::InvalidPath(
                "root entry must be a directory".to_string(),
            ));
        }

        // Duplicate check
        if self.path_to_inode.contains_key(&path) {
            return Err(ErofsError::DuplicatePath(path));
        }

        // Hardlink resolution
        if let StreamBody::Hardlink(ref target) = body {
            let target_inode = *self
                .path_to_inode
                .get(target.as_str())
                .ok_or_else(|| ErofsError::HardlinkTargetNotFound(target.clone()))?;
            let target_entry_idx = self.inode_metas[target_inode].entry_idx;
            if matches!(self.entries[target_entry_idx].body, StreamBody::Directory) {
                return Err(ErofsError::InvalidPath(format!(
                    "hard link target is a directory: {target:?}"
                )));
            }
            let parent_inode = self.parent_inode_for(&path)?;
            let extra_nlinks = self.inode_metas[target_inode]
                .extra_nlinks
                .checked_add(1)
                .ok_or_else(|| ErofsError::Overflow("hard link count".to_string()))?;

            self.path_to_inode.insert(path.clone(), target_inode);
            self.entry_to_inode.push(target_inode);
            self.inode_metas[target_inode].extra_nlinks = extra_nlinks;

            // Add as child of parent directory
            if let Some(parent_inode) = parent_inode {
                self.children
                    .entry(parent_inode)
                    .or_default()
                    .push(orig_idx);
            }

            self.entries.push(StreamEntry {
                path,
                metadata,
                body,
            });
            return Ok(());
        }

        // New inode
        let parent_inode = self.parent_inode_for(&path)?;
        let inode_idx = self.inode_metas.len();
        let inode_meta = build_inode_meta(orig_idx, &metadata, &body, 0)?;
        self.path_to_inode.insert(path.clone(), inode_idx);
        self.entry_to_inode.push(inode_idx);
        self.inode_metas.push(inode_meta);

        // Parent-child tracking
        if path == "/" {
            self.children.entry(0).or_default();
        } else if let Some(parent_inode) = parent_inode {
            self.children
                .entry(parent_inode)
                .or_default()
                .push(orig_idx);

            if matches!(body, StreamBody::Directory) {
                self.children.entry(inode_idx).or_default();
            }
        }

        self.entries.push(StreamEntry {
            path,
            metadata,
            body,
        });
        Ok(())
    }

    /// Write metadata area, deferred data blocks, and patch superblock.
    ///
    /// All structural work (path validation, hardlink resolution,
    /// parent-child tracking, xattr serialization) was done during
    /// `push()`. This only does the irreducible: NID assignment (requires
    /// all entries), directory serialization, and the final writes.
    #[allow(clippy::too_many_lines)]
    pub fn finish(self) -> Result<(W, ImageStats), ErofsError> {
        let Self {
            mut writer,
            entries,
            inode_metas,
            path_to_inode,
            mut children,
            entry_to_inode,
            next_data_block,
            poisoned,
        } = self;

        if poisoned {
            return Err(ErofsError::BuilderPoisoned);
        }

        if entries.is_empty() {
            return Err(ErofsError::InvalidPath("no entries provided".to_string()));
        }

        let num_inodes = inode_metas.len();

        // Sort children by name (deferred from push to avoid re-sorting)
        for kids in children.values_mut() {
            kids.sort_by(|&a, &b| basename(&entries[a].path).cmp(basename(&entries[b].path)));
        }

        // ── Compute inode layouts ────────────────────────────────────────
        let dir_data_initial = build_dir_data(
            &entries,
            &inode_metas,
            &children,
            &entry_to_inode,
            &path_to_inode,
            &[0u64; 0],
            true,
        )?;

        let mut layouts = compute_layouts(&entries, &inode_metas, &dir_data_initial)?;

        // ── Assign NIDs, fix directory data ──────────────────────────────
        let (mut nid_offsets, _) = assign_nids(&layouts);

        for _ in 0..3 {
            let dir_data = build_dir_data(
                &entries,
                &inode_metas,
                &children,
                &entry_to_inode,
                &path_to_inode,
                &nid_offsets,
                false,
            )?;
            update_dir_layouts(&entries, &inode_metas, &dir_data, &mut layouts)?;
            nid_offsets = assign_nids(&layouts).0;
        }

        let dir_data = build_dir_data(
            &entries,
            &inode_metas,
            &children,
            &entry_to_inode,
            &path_to_inode,
            &nid_offsets,
            false,
        )?;
        update_dir_layouts(&entries, &inode_metas, &dir_data, &mut layouts)?;
        let (nid_offsets, total_meta_slots) = assign_nids(&layouts);

        // ── Compute addresses ────────────────────────────────────────────
        let meta_blkaddr = next_data_block;
        let meta_start_byte = u64::from(meta_blkaddr) * u64::from(BLOCK_SIZE);

        let meta_total_bytes = total_meta_slots
            .checked_mul(EROFS_INODE_SLOT_SIZE)
            .ok_or_else(|| ErofsError::Overflow("meta total bytes".to_string()))?;
        let meta_end_byte = meta_start_byte
            .checked_add(meta_total_bytes)
            .ok_or_else(|| ErofsError::Overflow("meta end byte".to_string()))?;
        let meta_end_block = to_u32(
            meta_end_byte.div_ceil(u64::from(BLOCK_SIZE)),
            "meta end block",
        )?;

        let mut data_block_addrs = vec![0u32; num_inodes];
        let mut current_deferred_block = meta_end_block;
        for (k, layout) in layouts.iter().enumerate() {
            if layout.data_blocks == 0 {
                continue;
            }
            let entry = &entries[inode_metas[k].entry_idx];
            if let StreamBody::RegularFile(DataRef::Written { block_addr, .. }) = &entry.body {
                data_block_addrs[k] = *block_addr;
            } else {
                data_block_addrs[k] = current_deferred_block;
                current_deferred_block = current_deferred_block
                    .checked_add(layout.data_blocks)
                    .ok_or_else(|| ErofsError::Overflow("deferred block address".to_string()))?;
            }
        }

        let total_blocks = current_deferred_block;
        let image_size = u64::from(total_blocks) * u64::from(BLOCK_SIZE);
        let root_nid = u16::try_from(nid_offsets[0])
            .map_err(|_| ErofsError::Overflow("root NID".to_string()))?;

        // ── Write block 0 (boot sector) ──────────────────────────────────
        writer.seek(SeekFrom::Start(0)).map_err(map_io)?;
        writer.write_all(&ZEROS).map_err(map_io)?;

        // ── Zero-fill metadata area ──────────────────────────────────────
        writer
            .seek(SeekFrom::Start(meta_start_byte))
            .map_err(map_io)?;
        let meta_blocks = meta_end_block.saturating_sub(meta_blkaddr);
        for _ in 0..meta_blocks {
            writer.write_all(&ZEROS).map_err(map_io)?;
        }

        // ── Write inodes ─────────────────────────────────────────────────
        for (k, imeta) in inode_metas.iter().enumerate() {
            let entry = &entries[imeta.entry_idx];
            let inode_byte_offset = meta_start_byte + nid_offsets[k] * EROFS_INODE_SLOT_SIZE;
            writer
                .seek(SeekFrom::Start(inode_byte_offset))
                .map_err(map_io)?;

            let data_size = data_len_with_dirs(&entry.body, &dir_data, k) as u64;

            let base_nlink: u32 = match &entry.body {
                StreamBody::Directory => {
                    let subdirs_count = children.get(&k).map_or(0usize, |kids| {
                        kids.iter()
                            .filter(|&&orig| matches!(entries[orig].body, StreamBody::Directory))
                            .count()
                    });
                    let subdirs = u32::try_from(subdirs_count).map_err(|_| {
                        ErofsError::Overflow(format!(
                            "subdirs count {subdirs_count} exceeds u32::MAX"
                        ))
                    })?;
                    2 + subdirs
                }
                _ => 1,
            };
            let nlink = base_nlink + imeta.extra_nlinks;
            let mode = stream_body_mode(&entry.body, entry.metadata.permissions);

            if imeta.needs_extended {
                let mut inode = InodeExtended::new(
                    mode,
                    data_size,
                    nlink,
                    entry.metadata.uid,
                    entry.metadata.gid,
                    layouts[k].layout,
                    entry.metadata.mtime,
                    entry.metadata.mtime_nsec,
                );
                inode.i_xattr_icount = imeta.xattr_icount;
                if let StreamBody::DeviceNode { rdev, .. } = &entry.body {
                    inode.set_raw_blkaddr(*rdev);
                } else if layouts[k].data_blocks > 0 {
                    inode.set_raw_blkaddr(data_block_addrs[k]);
                }
                inode.i_ino = u32::try_from(k).map_err(|_| {
                    ErofsError::Overflow(format!("inode index {k} exceeds u32::MAX"))
                })?;
                writer.write_all(inode.as_bytes()).map_err(map_io)?;
            } else {
                let data_size_u32 = to_u32(data_size, "compact inode data size")?;
                let nlink_u16 =
                    u16::try_from(nlink).map_err(|_| ErofsError::Overflow("nlink".to_string()))?;
                let uid = u16::try_from(entry.metadata.uid).map_err(|_| {
                    ErofsError::Overflow(format!(
                        "uid {} exceeds u16::MAX (extended inode required)",
                        entry.metadata.uid
                    ))
                })?;
                let gid = u16::try_from(entry.metadata.gid).map_err(|_| {
                    ErofsError::Overflow(format!(
                        "gid {} exceeds u16::MAX (extended inode required)",
                        entry.metadata.gid
                    ))
                })?;

                let mut inode =
                    InodeCompact::new(mode, data_size_u32, nlink_u16, uid, gid, layouts[k].layout);
                inode.i_xattr_icount = imeta.xattr_icount;
                if let StreamBody::DeviceNode { rdev, .. } = &entry.body {
                    inode.set_raw_blkaddr(*rdev);
                } else if layouts[k].data_blocks > 0 {
                    inode.set_raw_blkaddr(data_block_addrs[k]);
                }
                inode.i_ino = u32::try_from(k).map_err(|_| {
                    ErofsError::Overflow(format!("inode index {k} exceeds u32::MAX"))
                })?;
                writer.write_all(inode.as_bytes()).map_err(map_io)?;
            }

            if !imeta.xattr_blob.is_empty() {
                writer.write_all(&imeta.xattr_blob).map_err(map_io)?;
            }

            if layouts[k].layout == EROFS_INODE_FLAT_INLINE {
                let data_size_usz = to_usize(data_size, "inline body data size")?;
                write_body_data(&entry.body, &dir_data, k, data_size_usz, &mut writer)?;
            }
        }

        // ── Write deferred data blocks ───────────────────────────────────
        for (k, layout) in layouts.iter().enumerate() {
            if layout.data_blocks == 0 {
                continue;
            }
            let entry = &entries[inode_metas[k].entry_idx];
            if matches!(
                &entry.body,
                StreamBody::RegularFile(DataRef::Written { .. })
            ) {
                continue;
            }

            let block_offset = u64::from(data_block_addrs[k]) * u64::from(BLOCK_SIZE);
            writer.seek(SeekFrom::Start(block_offset)).map_err(map_io)?;

            let data_size = data_len_with_dirs(&entry.body, &dir_data, k);
            write_body_data(&entry.body, &dir_data, k, data_size, &mut writer)?;

            let pad =
                (BLOCK_SIZE as usize - (data_size % BLOCK_SIZE as usize)) % BLOCK_SIZE as usize;
            if pad > 0 {
                writer.write_all(&ZEROS[..pad]).map_err(map_io)?;
            }
        }

        // ── Patch superblock ─────────────────────────────────────────────
        let uuid = content_uuid(&entries);
        let num_inodes_u64 = u64::try_from(num_inodes)
            .map_err(|_| ErofsError::Overflow("num_inodes".to_string()))?;
        let mut sb = SuperBlock::new(root_nid, num_inodes_u64, total_blocks, meta_blkaddr);
        sb.uuid = uuid;
        writer
            .seek(SeekFrom::Start(SUPERBLOCK_OFFSET as u64))
            .map_err(map_io)?;
        writer.write_all(sb.as_bytes()).map_err(map_io)?;
        writer.flush().map_err(map_io)?;

        Ok((
            writer,
            ImageStats {
                image_size,
                inode_count: num_inodes_u64,
                block_count: total_blocks,
            },
        ))
    }
}

impl ErofsWriter<Cursor<Vec<u8>>> {
    /// Build the EROFS image and return it as a byte buffer.
    pub fn finish_to_vec(self) -> Result<entry::BuiltImage, ErofsError> {
        let (cursor, stats) = self.finish()?;
        Ok(entry::BuiltImage::new(cursor.into_inner(), stats))
    }
}

// ── Directory data construction ─────────────────────────────────────────

fn build_dir_data(
    entries: &[StreamEntry],
    inode_metas: &[InodeMeta],
    children: &BTreeMap<usize, Vec<usize>>,
    entry_to_inode: &[usize],
    path_to_inode: &BTreeMap<String, usize>,
    nid_offsets: &[u64],
    placeholder_nids: bool,
) -> Result<BTreeMap<usize, Vec<u8>>, ErofsError> {
    let mut dir_data = BTreeMap::new();

    for (&dir_inode_idx, kids) in children {
        let entry = &entries[inode_metas[dir_inode_idx].entry_idx];
        if !matches!(entry.body, StreamBody::Directory) {
            continue;
        }

        let (dot_nid, dotdot_nid) = if placeholder_nids {
            (0, 0)
        } else {
            let dot = nid_offsets[dir_inode_idx];
            let dotdot = if dir_inode_idx == 0 {
                dot
            } else {
                let parent_path = parent_of(&entry.path);
                let &parent_inode = path_to_inode
                    .get(parent_path)
                    .ok_or_else(|| ErofsError::ParentNotFound(parent_path.to_string()))?;
                nid_offsets[parent_inode]
            };
            (dot, dotdot)
        };

        let mut tuples: Vec<(u64, u8, &[u8])> = Vec::with_capacity(kids.len() + 2);
        tuples.push((dot_nid, EROFS_FT_DIR, b"."));
        tuples.push((dotdot_nid, EROFS_FT_DIR, b".."));

        for &orig_idx in kids {
            let child = &entries[orig_idx];
            let name = basename(&child.path).as_bytes();
            let child_inode = entry_to_inode[orig_idx];
            let ft = if matches!(child.body, StreamBody::Hardlink(_)) {
                let target = &entries[inode_metas[child_inode].entry_idx];
                stream_body_to_file_type(&target.body)
            } else {
                stream_body_to_file_type(&child.body)
            };
            let nid = if placeholder_nids {
                child_inode as u64
            } else {
                nid_offsets[child_inode]
            };
            tuples.push((nid, ft, name));
        }

        let data = serialize_dir_entries(&tuples)?;
        dir_data.insert(dir_inode_idx, data);
    }

    Ok(dir_data)
}

// ── Layout helpers ──────────────────────────────────────────────────────

fn compute_layouts(
    entries: &[StreamEntry],
    inode_metas: &[InodeMeta],
    dir_data: &BTreeMap<usize, Vec<u8>>,
) -> Result<Vec<InodeLayout>, ErofsError> {
    let mut layouts = Vec::with_capacity(inode_metas.len());
    for (k, imeta) in inode_metas.iter().enumerate() {
        let overhead = imeta.inode_size + imeta.xattr_blob.len();
        let dlen = data_len_with_dirs(&entries[imeta.entry_idx].body, dir_data, k);
        layouts.push(compute_layout(overhead, dlen)?);
    }
    Ok(layouts)
}

fn update_dir_layouts(
    entries: &[StreamEntry],
    inode_metas: &[InodeMeta],
    dir_data: &BTreeMap<usize, Vec<u8>>,
    layouts: &mut [InodeLayout],
) -> Result<(), ErofsError> {
    for (k, imeta) in inode_metas.iter().enumerate() {
        if !matches!(entries[imeta.entry_idx].body, StreamBody::Directory) {
            continue;
        }
        let overhead = imeta.inode_size + imeta.xattr_blob.len();
        let dlen = dir_data.get(&k).map_or(0, Vec::len);
        layouts[k] = compute_layout(overhead, dlen)?;
    }
    Ok(())
}

// ── Data writing helpers ────────────────────────────────────────────────

fn write_body_data(
    body: &StreamBody,
    dir_data: &BTreeMap<usize, Vec<u8>>,
    inode_idx: usize,
    len: usize,
    writer: &mut impl Write,
) -> Result<(), ErofsError> {
    if len == 0 {
        return Ok(());
    }
    match body {
        StreamBody::Directory => {
            if let Some(data) = dir_data.get(&inode_idx) {
                writer.write_all(&data[..len]).map_err(map_io)?;
            }
        }
        StreamBody::RegularFile(DataRef::Mem(data)) => {
            writer.write_all(&data[..len]).map_err(map_io)?;
        }
        StreamBody::RegularFile(DataRef::Written { .. }) => {
            return Err(ErofsError::Io(
                "internal error: Written data reached inline write path".into(),
            ));
        }
        StreamBody::Symlink(target) => {
            writer
                .write_all(&target.as_bytes()[..len])
                .map_err(map_io)?;
        }
        _ => {}
    }
    Ok(())
}

// ── Convenience free functions ──────────────────────────────────────────

/// Build an EROFS image from entries, writing to a seekable stream.
///
/// Each entry's data is written to the output as it is consumed from the
/// iterator — large file data flows through immediately via
/// [`ErofsWriter::push`]. For streaming file data from a reader (avoiding
/// the `Vec<u8>` in [`Body::RegularFile`]), use [`ErofsWriter::push_file`]
/// directly.
pub fn build_erofs(
    entries: impl IntoIterator<Item = Entry>,
    writer: impl Write + Seek,
) -> Result<ImageStats, ErofsError> {
    let mut ew = ErofsWriter::new(writer);
    for entry in entries {
        ew.push(entry)?;
    }
    let (_, stats) = ew.finish()?;
    Ok(stats)
}

/// Build an EROFS image from entries and return it as a byte buffer.
pub fn build_to_vec(
    entries: impl IntoIterator<Item = Entry>,
) -> Result<entry::BuiltImage, ErofsError> {
    let mut ew = ErofsWriter::new(Cursor::new(Vec::new()));
    for entry in entries {
        ew.push(entry)?;
    }
    ew.finish_to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::{Dirent, EROFS_FT_DIR, EROFS_FT_REG_FILE};

    #[test]
    fn parent_of_cases() {
        assert_eq!(parent_of("/"), "/");
        assert_eq!(parent_of("/bin"), "/");
        assert_eq!(parent_of("/etc"), "/");
        assert_eq!(parent_of("/usr/bin"), "/usr");
        assert_eq!(parent_of("/a/b/c/d"), "/a/b/c");
    }

    #[test]
    fn basename_cases() {
        assert_eq!(basename("/"), ".");
        assert_eq!(basename("/bin"), "bin");
        assert_eq!(basename("/usr/bin/sh"), "sh");
        assert_eq!(basename("file.txt"), "file.txt");
    }

    #[test]
    fn validate_path_cases() {
        assert!(validate_path("").is_err());
        assert!(validate_path("relative").is_err());
        assert!(validate_path("/bin/").is_err());
        assert!(validate_path("/").is_ok());
        assert!(validate_path("/bin").is_ok());
        assert!(validate_path("/usr/bin/sh").is_ok());
    }

    #[test]
    fn serialize_dir_entries_empty() {
        let data = serialize_dir_entries(&[]).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn serialize_dir_entries_single() {
        let entries: Vec<(u64, u8, &[u8])> = vec![(1, EROFS_FT_REG_FILE, b"hello")];
        let data = serialize_dir_entries(&entries).unwrap();
        let ds = core::mem::size_of::<Dirent>();

        assert_eq!(data.len(), ds + 5);
        let de = Dirent::from_bytes(&data).unwrap();
        // Copy packed fields to locals to avoid unaligned references.
        let (nid, ft, nameoff) = (de.nid, de.file_type, de.nameoff);
        assert_eq!(nid, 1);
        assert_eq!(ft, EROFS_FT_REG_FILE);
        assert_eq!(nameoff as usize, ds);
        assert_eq!(&data[ds..ds + 5], b"hello");
    }

    #[test]
    fn serialize_dir_entries_dot_dotdot() {
        let entries: Vec<(u64, u8, &[u8])> =
            vec![(0, EROFS_FT_DIR, b"."), (0, EROFS_FT_DIR, b"..")];
        let data = serialize_dir_entries(&entries).unwrap();
        let ds = core::mem::size_of::<Dirent>();

        assert_eq!(data.len(), 2 * ds + 1 + 2);
        let off0 = Dirent::from_bytes(&data).unwrap().nameoff as usize;
        let off1 = Dirent::from_bytes(&data[ds..]).unwrap().nameoff as usize;
        assert_eq!(&data[off0..][..1], b".");
        assert_eq!(&data[off1..][..2], b"..");
    }

    #[test]
    fn serialize_dir_entries_multi_block() {
        let entries: Vec<(u64, u8, &[u8])> = (0..200)
            .map(|i| (i, EROFS_FT_REG_FILE, b"abcdefghij".as_slice()))
            .collect();
        let data = serialize_dir_entries(&entries).unwrap();
        assert_eq!(data.len() % BLOCK_SIZE as usize, 0);
        assert!(data.len() >= BLOCK_SIZE as usize);
    }

    #[test]
    fn push_file_matches_push() {
        use crate::{Body, Entry, Metadata, Permissions};

        fn m(mode: u16) -> Metadata {
            Metadata {
                permissions: Permissions::try_from(mode & Permissions::MASK).unwrap(),
                uid: 0,
                gid: 0,
                mtime: 0,
                mtime_nsec: 0,
                xattrs: vec![],
            }
        }
        fn root() -> Entry {
            Entry {
                path: "/".into(),
                metadata: m(0o040_755),
                body: Body::Directory,
            }
        }

        let data = vec![42u8; 8192];

        let mut ew1 = ErofsWriter::new(Cursor::new(Vec::new()));
        ew1.push(root()).unwrap();
        ew1.push(Entry {
            path: "/file".into(),
            metadata: m(0o100_644),
            body: Body::RegularFile(data.clone()),
        })
        .unwrap();
        let (c1, _) = ew1.finish().unwrap();

        let mut ew2 = ErofsWriter::new(Cursor::new(Vec::new()));
        ew2.push(root()).unwrap();
        ew2.push_file(
            "/file".into(),
            m(0o100_644),
            data.len() as u64,
            &mut data.as_slice(),
        )
        .unwrap();
        let (c2, _) = ew2.finish().unwrap();

        assert_eq!(c1.into_inner(), c2.into_inner());
    }
}
