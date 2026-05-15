// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! EROFS image reader.
//!
//! Parses a byte slice as an EROFS image and provides lookup, readdir,
//! `read_file`, and readlink operations.

use crate::error::ErofsError;
use crate::ondisk::{
    Dirent, EROFS_INODE_FLAT_INLINE, EROFS_INODE_FLAT_PLAIN, EROFS_INODE_SLOT_SIZE, InodeCompact,
    InodeExtended, SuperBlock,
};
use crate::{BLOCK_SIZE, EROFS_MAGIC, SUPERBLOCK_OFFSET};

/// Parsed inode information returned by `inode()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InodeInfo {
    pub mode: u16,
    pub nlink: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    /// Block address (`FLAT_PLAIN`) or rdev (device nodes).
    pub raw_blkaddr: u32,
    /// Data layout (`FLAT_PLAIN` or `FLAT_INLINE`).
    pub data_layout: u16,
    /// Inline xattr area size encoded as EROFS 4-byte units.
    pub xattr_icount: u16,
    /// Byte offset of this inode within the image.
    pub inode_offset: u64,
    /// On-disk inode struct size in bytes (32 for compact, 64 for extended).
    pub inode_size: usize,
}

impl InodeInfo {
    /// Extract `S_IFMT` bits (file type portion of mode).
    const fn file_type_bits(&self) -> u16 {
        self.mode & 0o170_000
    }

    fn inline_xattr_size(&self) -> Option<usize> {
        if self.xattr_icount == 0 {
            Some(0)
        } else {
            usize::from(self.xattr_icount)
                .checked_mul(4)?
                .checked_add(8)
        }
    }

    #[must_use]
    pub const fn is_dir(&self) -> bool {
        self.file_type_bits() == 0o040_000
    }

    #[must_use]
    pub const fn is_reg(&self) -> bool {
        self.file_type_bits() == 0o100_000
    }

    #[must_use]
    pub const fn is_symlink(&self) -> bool {
        self.file_type_bits() == 0o120_000
    }

    #[must_use]
    pub const fn is_chrdev(&self) -> bool {
        self.file_type_bits() == 0o020_000
    }

    #[must_use]
    pub const fn is_blkdev(&self) -> bool {
        self.file_type_bits() == 0o060_000
    }

    #[must_use]
    pub const fn is_fifo(&self) -> bool {
        self.file_type_bits() == 0o010_000
    }

    #[must_use]
    pub const fn is_socket(&self) -> bool {
        self.file_type_bits() == 0o140_000
    }

    /// For device nodes, decode major number from rdev.
    #[must_use]
    pub const fn rdev_major(&self) -> u32 {
        // Linux encodes rdev as (major << 8) | minor for old-style,
        // or use the new MKDEV macro. We use the simple encoding.
        (self.raw_blkaddr >> 8) & 0xff
    }

    /// For device nodes, decode minor number from rdev.
    #[must_use]
    pub const fn rdev_minor(&self) -> u32 {
        self.raw_blkaddr & 0xff
    }
}

/// A directory entry returned by `readdir()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub nid: u64,
    pub name: Vec<u8>,
    pub file_type: u8,
}

impl DirEntry {
    /// Return the entry name as a UTF-8 string, if valid.
    #[must_use]
    pub fn name_str(&self) -> Option<&str> {
        core::str::from_utf8(&self.name).ok()
    }
}

/// Read-only view into an EROFS image.
pub struct ErofsImage<'a> {
    data: &'a [u8],
    root_nid: u64,
    meta_blkaddr: u32,
}

impl core::fmt::Debug for ErofsImage<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ErofsImage")
            .field("data_len", &self.data.len())
            .field("root_nid", &self.root_nid)
            .field("meta_blkaddr", &self.meta_blkaddr)
            .finish()
    }
}

impl<'a> ErofsImage<'a> {
    /// Parse an EROFS image from a byte slice.
    pub fn new(data: &'a [u8]) -> Result<Self, ErofsError> {
        let min_size = SUPERBLOCK_OFFSET + core::mem::size_of::<SuperBlock>();
        if data.len() < min_size {
            return Err(ErofsError::TooSmall {
                expected: min_size,
                actual: data.len(),
            });
        }

        let sb =
            SuperBlock::from_bytes(&data[SUPERBLOCK_OFFSET..]).ok_or(ErofsError::TooSmall {
                expected: min_size,
                actual: data.len(),
            })?;

        let magic = sb.magic;
        if magic != EROFS_MAGIC {
            return Err(ErofsError::BadMagic(magic));
        }

        let blkszbits = sb.blkszbits;
        if blkszbits != 12 {
            return Err(ErofsError::UnsupportedBlockSize(blkszbits));
        }

        let feature_incompat = sb.feature_incompat;
        if feature_incompat != 0 {
            return Err(ErofsError::UnsupportedFeature(feature_incompat));
        }

        validate_superblock_fields(sb)?;

        let blocks = sb.blocks;
        let image_len_u64 = u64::from(blocks)
            .checked_mul(u64::from(BLOCK_SIZE))
            .ok_or_else(|| ErofsError::Overflow("superblock block count".to_string()))?;
        let image_len = usize::try_from(image_len_u64)
            .map_err(|_| ErofsError::Overflow("superblock image size".to_string()))?;
        if image_len < min_size {
            return Err(ErofsError::MalformedSuperblock(
                "declared block count is too small",
            ));
        }
        if data.len() < image_len {
            return Err(ErofsError::TooSmall {
                expected: image_len,
                actual: data.len(),
            });
        }

        let root_nid = u64::from(sb.root_nid);
        let image = Self {
            data: &data[..image_len],
            root_nid,
            meta_blkaddr: sb.meta_blkaddr,
        };

        let meta_start = image.meta_start();
        if meta_start < u64::from(BLOCK_SIZE) || meta_start >= image_len_u64 {
            return Err(ErofsError::MalformedSuperblock(
                "metadata block address is outside the image",
            ));
        }

        let root = image.inode(root_nid)?;
        if !root.is_dir() {
            return Err(ErofsError::NotADirectory(root_nid));
        }

        Ok(image)
    }

    /// NID of the root directory inode.
    #[must_use]
    pub const fn root_nid(&self) -> u64 {
        self.root_nid
    }

    /// Byte offset in the image where inode metadata begins.
    fn meta_start(&self) -> u64 {
        u64::from(self.meta_blkaddr) * u64::from(BLOCK_SIZE)
    }

    /// Byte offset in the image for a given NID.
    fn nid_offset(&self, nid: u64) -> Option<u64> {
        nid.checked_mul(EROFS_INODE_SLOT_SIZE)?
            .checked_add(self.meta_start())
    }

    /// Read inode metadata for a given NID.
    ///
    /// Supports both compact (32-byte) and extended (64-byte) on-disk inodes.
    pub fn inode(&self, nid: u64) -> Result<InodeInfo, ErofsError> {
        let offset = self
            .nid_offset(nid)
            .and_then(|o| usize::try_from(o).ok())
            .ok_or(ErofsError::InvalidNid(nid))?;

        // We need at least 2 bytes to read i_format and determine the inode type.
        // Read the compact struct first (it's smaller); bit 0 tells us which format.
        let end_compact = offset
            .checked_add(core::mem::size_of::<InodeCompact>())
            .ok_or(ErofsError::InvalidNid(nid))?;
        if end_compact > self.data.len() {
            return Err(ErofsError::InvalidNid(nid));
        }

        let raw_compact =
            InodeCompact::from_bytes(&self.data[offset..]).ok_or(ErofsError::InvalidNid(nid))?;

        let i_format = raw_compact.i_format;
        let is_extended = i_format & 1 != 0;

        if is_extended {
            // Extended inode — 64 bytes with u32 uid/gid and u64 size.
            let end_ext = offset
                .checked_add(core::mem::size_of::<InodeExtended>())
                .ok_or(ErofsError::InvalidNid(nid))?;
            if end_ext > self.data.len() {
                return Err(ErofsError::InvalidNid(nid));
            }
            let raw = InodeExtended::from_bytes(&self.data[offset..])
                .ok_or(ErofsError::InvalidNid(nid))?;
            Ok(InodeInfo {
                mode: raw.i_mode,
                nlink: raw.i_nlink,
                size: raw.i_size,
                uid: raw.i_uid,
                gid: raw.i_gid,
                raw_blkaddr: raw.raw_blkaddr(),
                data_layout: raw.data_layout(),
                xattr_icount: raw.i_xattr_icount,
                inode_offset: u64::try_from(offset).map_err(|_| ErofsError::InvalidNid(nid))?,
                inode_size: core::mem::size_of::<InodeExtended>(),
            })
        } else {
            // Compact inode — 32 bytes with u16 uid/gid and u32 size.
            Ok(InodeInfo {
                mode: raw_compact.i_mode,
                nlink: u32::from(raw_compact.i_nlink),
                size: u64::from(raw_compact.i_size),
                uid: u32::from(raw_compact.i_uid),
                gid: u32::from(raw_compact.i_gid),
                raw_blkaddr: raw_compact.raw_blkaddr(),
                data_layout: raw_compact.data_layout(),
                xattr_icount: raw_compact.i_xattr_icount,
                inode_offset: u64::try_from(offset).map_err(|_| ErofsError::InvalidNid(nid))?,
                inode_size: core::mem::size_of::<InodeCompact>(),
            })
        }
    }

    /// Read file data at the given offset and length (allocating).
    ///
    /// For regular files, directories, and symlinks. Returns up to `len` bytes
    /// (fewer if the read extends past EOF).
    pub fn read_file(&self, nid: u64, offset: u64, len: usize) -> Result<Vec<u8>, ErofsError> {
        self.data_slice(nid, offset, len).map(<[u8]>::to_vec)
    }

    /// Read file data as a borrowed slice (zero-copy).
    ///
    /// Like `read_file()` but returns a reference into the image data instead
    /// of allocating. Only works for uncompressed flat layouts.
    pub fn read_file_slice(&self, nid: u64, offset: u64, len: usize) -> Result<&[u8], ErofsError> {
        self.data_slice(nid, offset, len)
    }

    /// Common implementation for `read_file` and `read_file_slice`.
    fn data_slice(&self, nid: u64, offset: u64, len: usize) -> Result<&[u8], ErofsError> {
        let info = self.inode(nid)?;

        if offset >= info.size {
            return Ok(&[]);
        }

        let oor = || ErofsError::OffsetOutOfRange {
            offset,
            size: info.size,
        };

        let available = usize::try_from(info.size - offset).map_err(|_| oor())?;
        let read_len = len.min(available);

        match info.data_layout {
            EROFS_INODE_FLAT_INLINE => {
                let xattr_size = info.inline_xattr_size().ok_or_else(oor)?;
                let inline_start = usize::try_from(info.inode_offset)
                    .ok()
                    .and_then(|o| o.checked_add(info.inode_size))
                    .and_then(|o| o.checked_add(xattr_size))
                    .ok_or_else(oor)?;
                let start = usize::try_from(offset)
                    .ok()
                    .and_then(|o| inline_start.checked_add(o))
                    .ok_or_else(oor)?;
                let end = start.checked_add(read_len).ok_or_else(oor)?;
                if end > self.data.len() {
                    return Err(oor());
                }
                Ok(&self.data[start..end])
            }
            EROFS_INODE_FLAT_PLAIN => {
                let block_start = u64::from(info.raw_blkaddr)
                    .checked_mul(u64::from(BLOCK_SIZE))
                    .ok_or_else(oor)?;
                let abs = block_start.checked_add(offset).ok_or_else(oor)?;
                let start = usize::try_from(abs).map_err(|_| oor())?;
                let end = start.checked_add(read_len).ok_or_else(oor)?;
                if end > self.data.len() {
                    return Err(oor());
                }
                Ok(&self.data[start..end])
            }
            other => Err(ErofsError::UnsupportedLayout(other)),
        }
    }

    /// List directory entries for a directory inode.
    pub fn readdir(&self, nid: u64) -> Result<Vec<DirEntry>, ErofsError> {
        let info = self.inode(nid)?;
        if !info.is_dir() {
            return Err(ErofsError::NotADirectory(nid));
        }

        if info.size == 0 {
            return Ok(Vec::new());
        }

        let size = usize::try_from(info.size).map_err(|_| ErofsError::OffsetOutOfRange {
            offset: 0,
            size: info.size,
        })?;
        let dir_data = self.read_file(nid, 0, size)?;
        parse_dir_block(&dir_data, size)
    }

    /// Read symlink target.
    pub fn readlink(&self, nid: u64) -> Result<Vec<u8>, ErofsError> {
        let info = self.inode(nid)?;
        if !info.is_symlink() {
            return Err(ErofsError::NotASymlink(nid));
        }
        let size = usize::try_from(info.size).map_err(|_| ErofsError::OffsetOutOfRange {
            offset: 0,
            size: info.size,
        })?;
        self.read_file(nid, 0, size)
    }

    /// Read symlink target as a borrowed slice (zero-copy).
    pub fn readlink_slice(&self, nid: u64) -> Result<&[u8], ErofsError> {
        let info = self.inode(nid)?;
        if !info.is_symlink() {
            return Err(ErofsError::NotASymlink(nid));
        }
        let size = usize::try_from(info.size).map_err(|_| ErofsError::OffsetOutOfRange {
            offset: 0,
            size: info.size,
        })?;
        self.data_slice(nid, 0, size)
    }

    /// Look up a child entry by name in a directory.
    pub fn lookup(&self, dir_nid: u64, name: &[u8]) -> Result<Option<DirEntry>, ErofsError> {
        let entries = self.readdir(dir_nid)?;
        Ok(entries.into_iter().find(|e| e.name == name))
    }

    /// Resolve an absolute path from the root. Returns the NID of the final component.
    pub fn resolve(&self, path: &str) -> Result<u64, ErofsError> {
        if path.is_empty() {
            return Err(ErofsError::InvalidPath("empty path".to_string()));
        }
        if !path.starts_with('/') {
            return Err(ErofsError::InvalidPath(format!(
                "path must be absolute: {path:?}"
            )));
        }
        if path == "/" {
            return Ok(self.root_nid);
        }

        let path = &path[1..]; // strip leading '/'
        let mut current_nid = self.root_nid;

        for component in path.split('/') {
            if component.is_empty() {
                continue;
            }
            // Reject traversal components — a crafted image could contain a
            // directory entry literally named "." or ".." that would otherwise
            // let the caller escape the intended subtree.
            if component == "." || component == ".." {
                return Err(ErofsError::InvalidPath(format!(
                    "reserved component in path: {component:?}"
                )));
            }
            match self.lookup(current_nid, component.as_bytes())? {
                Some(entry) => current_nid = entry.nid,
                None => {
                    return Err(ErofsError::InvalidPath(format!(
                        "component {component:?} not found"
                    )));
                }
            }
        }

        Ok(current_nid)
    }
}

fn validate_superblock_fields(sb: &SuperBlock) -> Result<(), ErofsError> {
    if sb.checksum != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("checksum"));
    }
    if sb.feature_compat != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("feature_compat"));
    }
    if sb.sb_extslots != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("sb_extslots"));
    }
    if sb.inos == 0 {
        return Err(ErofsError::MalformedSuperblock("inode count is zero"));
    }
    if sb.build_time_nsec >= 1_000_000_000 {
        return Err(ErofsError::MalformedSuperblock(
            "build_time_nsec is not normalized",
        ));
    }
    if sb.xattr_blkaddr != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("xattr_blkaddr"));
    }
    if sb.u1 != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("u1"));
    }
    if sb.extra_devices != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("extra_devices"));
    }
    if sb.devt_slotoff != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("devt_slotoff"));
    }
    if sb.dirblkbits != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("dirblkbits"));
    }
    if sb.xattr_prefix_count != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("xattr_prefix_count"));
    }
    if sb.xattr_prefix_start != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("xattr_prefix_start"));
    }
    if sb.packed_nid != 0 {
        return Err(ErofsError::UnsupportedSuperblockField("packed_nid"));
    }
    let reserved2 = sb.reserved2;
    if reserved2 != [0; 24] {
        return Err(ErofsError::UnsupportedSuperblockField("reserved2"));
    }
    Ok(())
}

/// Parse EROFS directory data (potentially spanning multiple blocks) into entries.
fn parse_dir_block(data: &[u8], dir_size: usize) -> Result<Vec<DirEntry>, ErofsError> {
    let dirent_size = core::mem::size_of::<Dirent>();
    let block_size = BLOCK_SIZE as usize;
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < dir_size {
        // Determine the extent of this block (or remaining data)
        let block_end = if dir_size - pos >= block_size {
            pos + block_size
        } else {
            dir_size
        };

        let block_data = &data[pos..data.len().min(block_end)];

        if block_data.len() < dirent_size {
            return Err(ErofsError::CorruptedDirectory(
                "block too small for dirent header".to_string(),
            ));
        }

        let first = Dirent::from_bytes(block_data).ok_or_else(|| {
            ErofsError::CorruptedDirectory("cannot parse first dirent".to_string())
        })?;
        let first_nameoff = first.nameoff as usize;
        if first_nameoff < dirent_size || first_nameoff > block_data.len() {
            return Err(ErofsError::CorruptedDirectory(format!(
                "invalid first nameoff: {first_nameoff}"
            )));
        }
        if !first_nameoff.is_multiple_of(dirent_size) {
            return Err(ErofsError::CorruptedDirectory(format!(
                "first nameoff {first_nameoff} not aligned to dirent size {dirent_size}"
            )));
        }

        let num_entries = first_nameoff / dirent_size;

        let mut name_offsets = Vec::with_capacity(num_entries);
        let mut prev_nameoff = first_nameoff;
        for k in 0..num_entries {
            let hdr_off = k * dirent_size;
            if hdr_off + dirent_size > block_data.len() {
                return Err(ErofsError::CorruptedDirectory(format!(
                    "dirent header {k} extends past block"
                )));
            }
            let dirent = Dirent::from_bytes(&block_data[hdr_off..]).ok_or_else(|| {
                ErofsError::CorruptedDirectory(format!("cannot parse dirent {k}"))
            })?;
            let name_start = dirent.nameoff as usize;
            if name_start < first_nameoff || name_start >= block_data.len() {
                return Err(ErofsError::CorruptedDirectory(format!(
                    "dirent {k} nameoff {name_start} outside name area"
                )));
            }
            if name_start < prev_nameoff {
                return Err(ErofsError::CorruptedDirectory(format!(
                    "dirent {k} nameoff {name_start} before previous nameoff {prev_nameoff}"
                )));
            }
            prev_nameoff = name_start;
            name_offsets.push(name_start);
        }

        for k in 0..num_entries {
            let hdr_off = k * dirent_size;
            let dirent = Dirent::from_bytes(&block_data[hdr_off..]).ok_or_else(|| {
                ErofsError::CorruptedDirectory(format!("cannot parse dirent {k}"))
            })?;
            let name_start = name_offsets[k];

            // Name end: either the nameoff of the next entry, or scan for
            // the end of the name (first zero byte or block end)
            let name_end = if k + 1 < num_entries {
                name_offsets[k + 1]
            } else {
                // Last entry: name extends to end of used portion of block.
                // Scan for first zero byte.
                let mut end = name_start;
                while end < block_data.len() && block_data[end] != 0 {
                    end += 1;
                }
                end
            };

            if name_end < name_start {
                return Err(ErofsError::CorruptedDirectory(format!(
                    "name_end {name_end} before name_start {name_start}"
                )));
            }
            let name = &block_data[name_start..name_end];

            entries.push(DirEntry {
                nid: dirent.nid,
                name: name.to_vec(),
                file_type: dirent.file_type,
            });
        }

        // Advance to next block boundary
        pos += block_size;
    }

    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ondisk::{Dirent, EROFS_FT_DIR, EROFS_FT_REG_FILE, EROFS_FT_SYMLINK};

    // --- InodeInfo type checks ---

    #[test]
    fn inode_info_type_detection() {
        let dir = InodeInfo {
            mode: 0o040_755,
            nlink: 2,
            size: 0,
            uid: 0,
            gid: 0,
            raw_blkaddr: 0,
            data_layout: 0,
            xattr_icount: 0,
            inode_offset: 0,
            inode_size: 32,
        };
        assert!(dir.is_dir());
        assert!(!dir.is_reg());
        assert!(!dir.is_symlink());
        assert!(!dir.is_chrdev());
        assert!(!dir.is_blkdev());

        let reg = InodeInfo {
            mode: 0o100_644,
            ..dir
        };
        assert!(reg.is_reg());
        assert!(!reg.is_dir());

        let sym = InodeInfo {
            mode: 0o120_777,
            ..dir
        };
        assert!(sym.is_symlink());

        let chr = InodeInfo {
            mode: 0o020_666,
            ..dir
        };
        assert!(chr.is_chrdev());

        let blk = InodeInfo {
            mode: 0o060_660,
            ..dir
        };
        assert!(blk.is_blkdev());
    }

    #[test]
    fn inode_info_rdev_decode() {
        let dev = InodeInfo {
            mode: 0o020_666,
            nlink: 1,
            size: 0,
            uid: 0,
            gid: 0,
            raw_blkaddr: (1 << 8) | 3, // major=1, minor=3 (/dev/null)
            data_layout: 0,
            xattr_icount: 0,
            inode_offset: 0,
            inode_size: 32,
        };
        assert_eq!(dev.rdev_major(), 1);
        assert_eq!(dev.rdev_minor(), 3);
    }

    #[test]
    fn inode_info_rdev_zero() {
        let dev = InodeInfo {
            mode: 0o020_666,
            nlink: 1,
            size: 0,
            uid: 0,
            gid: 0,
            raw_blkaddr: 0,
            data_layout: 0,
            xattr_icount: 0,
            inode_offset: 0,
            inode_size: 32,
        };
        assert_eq!(dev.rdev_major(), 0);
        assert_eq!(dev.rdev_minor(), 0);
    }

    // --- parse_dir_block ---

    fn make_dir_block(entries: &[(u64, u8, &[u8])]) -> Vec<u8> {
        let dirent_size = core::mem::size_of::<Dirent>();
        let headers_size = entries.len() * dirent_size;
        let names_size: usize = entries.iter().map(|(_, _, n)| n.len()).sum();
        let total = headers_size + names_size;
        let mut buf = vec![0u8; total.max(BLOCK_SIZE as usize)];

        let mut name_offset = headers_size;
        for (i, (nid, ft, name)) in entries.iter().enumerate() {
            let de = Dirent::new(*nid, u16::try_from(name_offset).unwrap(), *ft);
            let hdr_off = i * dirent_size;
            buf[hdr_off..hdr_off + dirent_size].copy_from_slice(de.as_bytes());
            buf[name_offset..name_offset + name.len()].copy_from_slice(name);
            name_offset += name.len();
        }
        buf
    }

    #[test]
    fn parse_dir_block_basic() {
        let raw_entries = vec![
            (0u64, EROFS_FT_DIR, b".".as_slice()),
            (0, EROFS_FT_DIR, b".."),
            (1, EROFS_FT_REG_FILE, b"hello"),
        ];
        let buf = make_dir_block(&raw_entries);
        let dirent_size = core::mem::size_of::<Dirent>();
        let dir_size = 3 * dirent_size + 1 + 2 + 5; // headers + names

        let entries = parse_dir_block(&buf, dir_size).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].name, b".");
        assert_eq!(entries[0].file_type, EROFS_FT_DIR);
        assert_eq!(entries[1].name, b"..");
        assert_eq!(entries[2].name, b"hello");
        assert_eq!(entries[2].nid, 1);
        assert_eq!(entries[2].file_type, EROFS_FT_REG_FILE);
    }

    #[test]
    fn parse_dir_block_empty() {
        let entries = parse_dir_block(&[], 0).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn parse_dir_block_too_small_for_dirent() {
        let buf = vec![0u8; 8]; // smaller than one Dirent (12 bytes)
        let err = parse_dir_block(&buf, 8).unwrap_err();
        assert!(matches!(err, ErofsError::CorruptedDirectory(_)));
    }

    #[test]
    fn parse_dir_block_invalid_first_nameoff() {
        // First dirent with nameoff=0 (before the dirent header itself)
        let mut buf = vec![0u8; BLOCK_SIZE as usize];
        let de = Dirent::new(0, 0, EROFS_FT_DIR);
        buf[..12].copy_from_slice(de.as_bytes());
        let err = parse_dir_block(&buf, BLOCK_SIZE as usize).unwrap_err();
        assert!(matches!(err, ErofsError::CorruptedDirectory(_)));
    }

    #[test]
    fn parse_dir_block_rejects_decreasing_nameoff() {
        let raw_entries = vec![
            (0u64, EROFS_FT_DIR, b".".as_slice()),
            (1, EROFS_FT_REG_FILE, b"one"),
            (2, EROFS_FT_REG_FILE, b"two"),
        ];
        let mut buf = make_dir_block(&raw_entries);
        let dirent_size = core::mem::size_of::<Dirent>();
        let first_nameoff = Dirent::from_bytes(&buf).unwrap().nameoff;
        let second_nameoff = first_nameoff + 1;
        let second = Dirent::new(1, second_nameoff, EROFS_FT_REG_FILE);
        buf[dirent_size..dirent_size * 2].copy_from_slice(second.as_bytes());
        let bad_third = Dirent::new(2, first_nameoff, EROFS_FT_REG_FILE);
        buf[dirent_size * 2..dirent_size * 3].copy_from_slice(bad_third.as_bytes());

        let dir_size = 3 * dirent_size + 1 + 3 + 3;
        let err = parse_dir_block(&buf, dir_size).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("before previous nameoff"), "got: {msg}");
    }

    #[test]
    fn parse_dir_block_rejects_nameoff_past_block() {
        let raw_entries = vec![
            (0u64, EROFS_FT_DIR, b".".as_slice()),
            (1, EROFS_FT_REG_FILE, b"file"),
        ];
        let mut buf = make_dir_block(&raw_entries);
        let dirent_size = core::mem::size_of::<Dirent>();
        let bad_nameoff = u16::try_from(BLOCK_SIZE + 1).unwrap();
        let bad = Dirent::new(1, bad_nameoff, EROFS_FT_REG_FILE);
        buf[dirent_size..dirent_size * 2].copy_from_slice(bad.as_bytes());

        let dir_size = 2 * dirent_size + 1 + 4;
        let err = parse_dir_block(&buf, dir_size).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("outside name area"), "got: {msg}");
    }

    #[test]
    fn parse_dir_block_rejects_nameoff_at_block_end() {
        let raw_entries = vec![
            (0u64, EROFS_FT_DIR, b".".as_slice()),
            (1, EROFS_FT_REG_FILE, b"file"),
        ];
        let mut buf = make_dir_block(&raw_entries);
        let dirent_size = core::mem::size_of::<Dirent>();
        let dir_size = 2 * dirent_size + 1 + 4;
        let bad_nameoff = u16::try_from(dir_size).unwrap();
        let bad = Dirent::new(1, bad_nameoff, EROFS_FT_REG_FILE);
        buf[dirent_size..dirent_size * 2].copy_from_slice(bad.as_bytes());

        let err = parse_dir_block(&buf, dir_size).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("outside name area"), "got: {msg}");
    }

    #[test]
    fn parse_dir_block_symlink_entry() {
        let raw_entries = vec![
            (0u64, EROFS_FT_DIR, b".".as_slice()),
            (0, EROFS_FT_DIR, b".."),
            (5, EROFS_FT_SYMLINK, b"link"),
        ];
        let buf = make_dir_block(&raw_entries);
        let dirent_size = core::mem::size_of::<Dirent>();
        let dir_size = 3 * dirent_size + 1 + 2 + 4;

        let entries = parse_dir_block(&buf, dir_size).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[2].name, b"link");
        assert_eq!(entries[2].file_type, EROFS_FT_SYMLINK);
        assert_eq!(entries[2].nid, 5);
    }

    // --- ErofsImage construction ---

    #[test]
    fn erofs_image_rejects_small_data() {
        let data = vec![0u8; 100];
        assert!(ErofsImage::new(&data).is_err());
    }

    #[test]
    fn erofs_image_rejects_bad_magic() {
        let mut data = vec![0u8; 4096];
        data[SUPERBLOCK_OFFSET..SUPERBLOCK_OFFSET + 4].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF]);
        assert!(ErofsImage::new(&data).is_err());
    }

    // --- Full roundtrip via builder ---

    use crate::entry::{Body, Entry, Metadata, Permissions, Xattr};

    fn meta(mode: u16) -> Metadata {
        Metadata {
            permissions: Permissions::try_from(mode & Permissions::MASK).unwrap(),
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
            xattrs: vec![],
        }
    }

    fn meta_with_xattr(mode: u16) -> Metadata {
        Metadata {
            xattrs: vec![Xattr {
                key: b"user.test".to_vec(),
                value: b"metadata".to_vec(),
            }],
            ..meta(mode)
        }
    }

    fn dir_entry(path: &str, mode: u16) -> Entry {
        Entry {
            path: path.to_string(),
            metadata: meta(mode),
            body: Body::Directory,
        }
    }

    fn file_entry(path: &str, data: &[u8], mode: u16) -> Entry {
        Entry {
            path: path.to_string(),
            metadata: meta(mode),
            body: Body::RegularFile(data.to_vec()),
        }
    }

    /// Build an EROFS image from entries and return its bytes.
    fn build_image(entries: Vec<Entry>) -> Vec<u8> {
        crate::builder::build_to_vec(entries).unwrap().into_vec()
    }

    #[test]
    fn resolve_root_returns_root_nid() {
        let image = build_image(vec![dir_entry("/", 0o40755)]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/").unwrap();
        assert_eq!(nid, fs.root_nid());
    }

    #[test]
    fn resolve_handles_empty_components() {
        let image = build_image(vec![dir_entry("/", 0o40755), dir_entry("/a", 0o40755)]);

        let fs = ErofsImage::new(&image).unwrap();
        // Double slash and trailing slash should work
        let nid1 = fs.resolve("/a").unwrap();
        let nid2 = fs.resolve("/a/").unwrap();
        let nid3 = fs.resolve("//a").unwrap();
        assert_eq!(nid1, nid2);
        assert_eq!(nid1, nid3);
    }

    #[test]
    fn lookup_returns_none_for_missing() {
        let image = build_image(vec![dir_entry("/", 0o40755)]);

        let fs = ErofsImage::new(&image).unwrap();
        let result = fs.lookup(fs.root_nid(), b"nonexistent").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn readdir_on_file_errors() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"data", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        assert!(fs.readdir(nid).is_err());
    }

    #[test]
    fn readlink_on_dir_errors() {
        let image = build_image(vec![dir_entry("/", 0o40755)]);

        let fs = ErofsImage::new(&image).unwrap();
        assert!(fs.readlink(fs.root_nid()).is_err());
    }

    #[test]
    fn read_file_past_eof_returns_empty() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"hello", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let data = fs.read_file(nid, 100, 10).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn read_file_clamps_to_available() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"hello", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let data = fs.read_file(nid, 3, 1000).unwrap();
        assert_eq!(data, b"lo");
    }

    // --- read_file_slice (zero-copy) ---

    #[test]
    fn read_file_slice_full() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"hello", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let slice = fs.read_file_slice(nid, 0, 100).unwrap();
        assert_eq!(slice, b"hello");
    }

    #[test]
    fn read_inline_file_skips_inline_xattrs() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            Entry {
                path: "/f".to_string(),
                metadata: meta_with_xattr(0o100_644),
                body: Body::RegularFile(b"payload".to_vec()),
            },
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let info = fs.inode(nid).unwrap();
        assert_eq!(info.data_layout, EROFS_INODE_FLAT_INLINE);
        assert!(info.xattr_icount > 0);

        assert_eq!(fs.read_file(nid, 0, 100).unwrap(), b"payload");
        assert_eq!(fs.read_file_slice(nid, 1, 3).unwrap(), b"ayl");
    }

    #[test]
    fn read_inline_symlink_skips_inline_xattrs() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            Entry {
                path: "/link".to_string(),
                metadata: meta_with_xattr(0o120_777),
                body: Body::Symlink("target".to_string()),
            },
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/link").unwrap();
        let info = fs.inode(nid).unwrap();
        assert_eq!(info.data_layout, EROFS_INODE_FLAT_INLINE);
        assert!(info.xattr_icount > 0);

        assert_eq!(fs.readlink(nid).unwrap(), b"target");
        assert_eq!(fs.readlink_slice(nid).unwrap(), b"target");
    }

    #[test]
    fn read_file_slice_past_eof() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"hello", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let slice = fs.read_file_slice(nid, 100, 10).unwrap();
        assert!(slice.is_empty());
    }

    #[test]
    fn read_file_slice_partial() {
        let image = build_image(vec![
            dir_entry("/", 0o40755),
            file_entry("/f", b"hello", 0o100_644),
        ]);

        let fs = ErofsImage::new(&image).unwrap();
        let nid = fs.resolve("/f").unwrap();
        let slice = fs.read_file_slice(nid, 3, 1000).unwrap();
        assert_eq!(slice, b"lo");
    }

    // resolve("") test is in tests/roundtrip.rs

    // --- BUG-1: blkszbits validation ---

    #[test]
    fn rejects_non_4k_blkszbits() {
        let mut image = build_image(vec![dir_entry("/", 0o40755)]);

        // blkszbits is at SUPERBLOCK_OFFSET + 12
        image[crate::SUPERBLOCK_OFFSET + 12] = 13; // 8 KiB — unsupported

        let err = ErofsImage::new(&image).unwrap_err();
        assert!(matches!(err, ErofsError::UnsupportedBlockSize(13)));
    }

    // --- BUG-4: feature_incompat validation ---

    #[test]
    fn rejects_nonzero_feature_incompat() {
        let mut image = build_image(vec![dir_entry("/", 0o40755)]);

        // feature_incompat is at byte offset 80 within SuperBlock
        // SuperBlock starts at SUPERBLOCK_OFFSET (1024)
        let off = crate::SUPERBLOCK_OFFSET + 80;
        image[off] = 1; // set a feature flag

        let err = ErofsImage::new(&image).unwrap_err();
        assert!(matches!(err, ErofsError::UnsupportedFeature(_)));
    }

    // Extended inodes are now supported — see tests/roundtrip.rs for coverage.

    // --- BUG-3: reject relative paths in resolve() ---

    #[test]
    fn resolve_rejects_relative_path() {
        let image = build_image(vec![dir_entry("/", 0o40755), dir_entry("/bin", 0o40755)]);

        let fs = ErofsImage::new(&image).unwrap();
        let err = fs.resolve("bin").unwrap_err();
        assert!(matches!(err, ErofsError::InvalidPath(_)));
    }
}
