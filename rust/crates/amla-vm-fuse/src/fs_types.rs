// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Shared types, constants, and helpers for filesystem backends.

use crate::fuse::{FuseDirent, FuseEntryOut};
use crate::fuse_abi::FuseError;

// =============================================================================
// FUSE-specific constants
// =============================================================================

/// FUSE root inode number — always 1.
pub const FUSE_ROOT_ID: u64 = 1;

/// Cache validity for attributes (seconds).
pub const ATTR_VALID_SECS: u64 = 86400;

/// Cache validity for entries (seconds).
pub const ENTRY_VALID_SECS: u64 = 86400;

// =============================================================================
// POSIX mode / dirent type constants
// =============================================================================

/// `S_IFDIR` — directory file type in `st_mode`.
pub const S_IFDIR: u32 = 0o040_000;

/// `S_IFREG` — regular file type in `st_mode`.
pub const S_IFREG: u32 = 0o100_000;

/// `S_IFLNK` — symbolic link file type in `st_mode`.
pub const S_IFLNK: u32 = 0o120_000;

/// `DT_DIR` — directory type for `d_type`.
pub const DT_DIR: u32 = 4;

/// `DT_REG` — regular file type for `d_type`.
pub const DT_REG: u32 = 8;

/// `DT_LNK` — symbolic link type for `d_type`.
pub const DT_LNK: u32 = 10;

// =============================================================================
// Utility functions
// =============================================================================

/// Convert a POSIX `mode` to a directory entry type (`d_type`).
pub const fn mode_to_dtype(mode: u32) -> u32 {
    (mode >> 12) & 0xF
}

fn read_wire<T: bytemuck::Pod>(buf: &[u8], pos: usize) -> Result<T, FuseError> {
    let size = core::mem::size_of::<T>();
    let end = pos.checked_add(size).ok_or_else(FuseError::io)?;
    let bytes = buf.get(pos..end).ok_or_else(FuseError::io)?;
    Ok(bytemuck::pod_read_unaligned(bytes))
}

fn write_wire<T: bytemuck::Pod>(buf: &mut [u8], pos: usize, value: &T) -> Result<(), FuseError> {
    let size = core::mem::size_of::<T>();
    let end = pos.checked_add(size).ok_or_else(FuseError::io)?;
    let dst = buf.get_mut(pos..end).ok_or_else(FuseError::io)?;
    dst.copy_from_slice(bytemuck::bytes_of(value));
    Ok(())
}

// =============================================================================
// Readdir inode rewriting
// =============================================================================

/// Rewrite inode numbers in a FUSE readdir buffer.
///
/// Walks the wire-format `FuseDirent` entries in `buf` and applies `translate`
/// to each `ino` field in-place. Used by composite filesystem backends to map
/// inner inode numbers to global inode space.
///
/// Returns `Err(FuseError::io())` if a sub-backend produced a malformed
/// entry (zero `namelen`, or a declared entry size that overruns the
/// buffer). Callers should treat a malformed buffer as a backend bug and
/// surface EIO to the guest — forwarding half-rewritten bytes risks
/// corrupting the guest's view of the directory.
pub fn rewrite_readdir_inodes(
    buf: &mut [u8],
    mut translate: impl FnMut(u64) -> u64,
) -> Result<(), FuseError> {
    try_rewrite_readdir_inodes(buf, |ino| Ok(translate(ino)))
}

/// Rewrite inode numbers in a FUSE readdir buffer with a fallible mapper.
///
/// This is the checked variant of [`rewrite_readdir_inodes`]. It returns the
/// mapper's error when an inner inode cannot be represented in the caller's
/// inode namespace.
pub fn try_rewrite_readdir_inodes(
    buf: &mut [u8],
    mut translate: impl FnMut(u64) -> Result<u64, FuseError>,
) -> Result<(), FuseError> {
    let dirent_size = core::mem::size_of::<FuseDirent>();
    let mut pos = 0;
    while pos + dirent_size <= buf.len() {
        let mut dirent: FuseDirent = read_wire(buf, pos)?;
        dirent.ino = translate(dirent.ino)?;
        let namelen = dirent.namelen as usize;
        if namelen == 0 {
            return Err(FuseError::io());
        }
        let entry_size = (dirent_size + namelen + 7) & !7;
        if pos + entry_size > buf.len() {
            return Err(FuseError::io());
        }
        write_wire(buf, pos, &dirent)?;
        pos += entry_size;
    }
    Ok(())
}

/// Rewrite inode numbers in a FUSE readdirplus buffer.
///
/// Walks the wire-format `FuseEntryOut` + `FuseDirent` pairs in `buf` and
/// applies `translate` to the `nodeid`, `attr.ino`, and dirent `ino` fields
/// in-place. See [`rewrite_readdir_inodes`] for error semantics.
pub fn rewrite_readdirplus_inodes(
    buf: &mut [u8],
    mut translate: impl FnMut(u64) -> u64,
) -> Result<(), FuseError> {
    try_rewrite_readdirplus_inodes(buf, |ino| Ok(translate(ino)))
}

/// Rewrite inode numbers in a FUSE readdirplus buffer with a fallible mapper.
///
/// This is the checked variant of [`rewrite_readdirplus_inodes`]. It returns
/// the mapper's error when an inner inode cannot be represented in the caller's
/// inode namespace.
pub fn try_rewrite_readdirplus_inodes(
    buf: &mut [u8],
    mut translate: impl FnMut(u64) -> Result<u64, FuseError>,
) -> Result<(), FuseError> {
    let entry_out_size = core::mem::size_of::<FuseEntryOut>();
    let dirent_size = core::mem::size_of::<FuseDirent>();
    let mut pos = 0;
    while pos + entry_out_size + dirent_size <= buf.len() {
        let mut entry_out: FuseEntryOut = read_wire(buf, pos)?;
        entry_out.nodeid = translate(entry_out.nodeid)?;
        entry_out.attr.ino = translate(entry_out.attr.ino)?;

        let dp = pos + entry_out_size;
        let mut dirent: FuseDirent = read_wire(buf, dp)?;
        dirent.ino = translate(dirent.ino)?;

        let namelen = dirent.namelen as usize;
        if namelen == 0 {
            return Err(FuseError::io());
        }
        let entry_size = (entry_out_size + dirent_size + namelen + 7) & !7;
        if pos + entry_size > buf.len() {
            return Err(FuseError::io());
        }
        write_wire(buf, pos, &entry_out)?;
        write_wire(buf, dp, &dirent)?;
        pos += entry_size;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuse_root_id_is_one() {
        assert_eq!(FUSE_ROOT_ID, 1);
    }

    #[test]
    fn mode_to_dtype_values() {
        assert_eq!(mode_to_dtype(0o10_0644), 8); // regular file
        assert_eq!(mode_to_dtype(0o04_0755), 4); // directory
        assert_eq!(mode_to_dtype(0o12_0777), 10); // symlink
        assert_eq!(mode_to_dtype(0o06_0660), 6); // block device
        assert_eq!(mode_to_dtype(0o02_0666), 2); // character device
    }

    #[test]
    fn posix_constants_consistent_with_mode_to_dtype() {
        assert_eq!(mode_to_dtype(S_IFDIR | 0o755), DT_DIR);
        assert_eq!(mode_to_dtype(S_IFREG | 0o644), DT_REG);
        assert_eq!(mode_to_dtype(S_IFLNK | 0o777), DT_LNK);
    }

    #[test]
    fn rewrite_readdir_translates_inodes() {
        use crate::fuse::pack_dirent;
        let mut buf = Vec::with_capacity(256);
        let _n = pack_dirent(&mut buf, 256, 100, b"hello", 1, DT_REG);
        let _n = pack_dirent(&mut buf, 256, 200, b"world", 2, DT_DIR);

        rewrite_readdir_inodes(&mut buf, |ino| ino + 1000).unwrap();

        // Parse back and verify.
        let dirent_size = core::mem::size_of::<FuseDirent>();
        let d1: FuseDirent = bytemuck::pod_read_unaligned(&buf[..dirent_size]);
        assert_eq!(d1.ino, 1100);
        let step = (dirent_size + d1.namelen as usize + 7) & !7;
        let d2: FuseDirent = bytemuck::pod_read_unaligned(&buf[step..step + dirent_size]);
        assert_eq!(d2.ino, 1200);
    }

    #[test]
    fn try_rewrite_readdir_propagates_mapper_error() {
        use crate::fuse::pack_dirent;
        let mut buf = Vec::with_capacity(256);
        let _n = pack_dirent(&mut buf, 256, 100, b"hello", 1, DT_REG);

        let err = try_rewrite_readdir_inodes(&mut buf, |_ino| Err(FuseError::range()));
        assert_eq!(err, Err(FuseError::range()));
    }

    #[test]
    fn rewrite_readdirplus_translates_all_inode_fields() {
        use crate::fuse::{FuseAttr, pack_direntplus};

        let attr = |ino| FuseAttr {
            ino,
            size: 0,
            blocks: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
            atimensec: 0,
            mtimensec: 0,
            ctimensec: 0,
            mode: S_IFREG | 0o644,
            nlink: 1,
            uid: 0,
            gid: 0,
            rdev: 0,
            blksize: 4096,
            flags: 0,
        };
        let entry = |nodeid| FuseEntryOut {
            nodeid,
            generation: 0,
            entry_valid: ENTRY_VALID_SECS,
            attr_valid: ATTR_VALID_SECS,
            entry_valid_nsec: 0,
            attr_valid_nsec: 0,
            attr: attr(nodeid),
        };

        let mut buf = Vec::with_capacity(512);
        let _n = pack_direntplus(&mut buf, 512, &entry(10), b"a", 1, DT_REG);
        let _n = pack_direntplus(&mut buf, 512, &entry(20), b"b", 2, DT_REG);

        rewrite_readdirplus_inodes(&mut buf, |ino| ino + 500).unwrap();

        let entry_out_size = core::mem::size_of::<FuseEntryOut>();
        let dirent_size = core::mem::size_of::<FuseDirent>();

        let e1: FuseEntryOut = bytemuck::pod_read_unaligned(&buf[..entry_out_size]);
        assert_eq!(e1.nodeid, 510);
        assert_eq!(e1.attr.ino, 510);
        let d1: FuseDirent =
            bytemuck::pod_read_unaligned(&buf[entry_out_size..entry_out_size + dirent_size]);
        assert_eq!(d1.ino, 510);
    }

    #[test]
    fn try_rewrite_readdirplus_propagates_mapper_error() {
        use crate::fuse::{FuseAttr, pack_direntplus};

        let attr = FuseAttr {
            ino: 10,
            mode: S_IFREG | 0o644,
            nlink: 1,
            blksize: 4096,
            ..FuseAttr::default()
        };
        let entry = FuseEntryOut {
            nodeid: 10,
            attr,
            ..FuseEntryOut::default()
        };

        let mut buf = Vec::with_capacity(512);
        let _n = pack_direntplus(&mut buf, 512, &entry, b"a", 1, DT_REG);

        let err = try_rewrite_readdirplus_inodes(&mut buf, |_ino| Err(FuseError::range()));
        assert_eq!(err, Err(FuseError::range()));
    }

    #[test]
    fn rewrite_readdir_rejects_zero_namelen() {
        let dirent_size = core::mem::size_of::<FuseDirent>();
        let mut buf = vec![0u8; dirent_size];
        let d = FuseDirent {
            ino: 42,
            namelen: 0,
            typ: DT_REG,
            ..Default::default()
        };
        buf[..dirent_size].copy_from_slice(bytemuck::bytes_of(&d));
        assert!(rewrite_readdir_inodes(&mut buf, |ino| ino).is_err());
    }

    #[test]
    fn rewrite_readdir_rejects_entry_past_buffer() {
        let dirent_size = core::mem::size_of::<FuseDirent>();
        // Header-only buffer whose namelen claims bytes that aren't there.
        let mut buf = vec![0u8; dirent_size];
        let d = FuseDirent {
            namelen: 64,
            ..Default::default()
        };
        buf[..dirent_size].copy_from_slice(bytemuck::bytes_of(&d));
        assert!(rewrite_readdir_inodes(&mut buf, |ino| ino).is_err());
    }

    #[test]
    fn rewrite_readdir_handles_unaligned_buffer() {
        use crate::fuse::pack_dirent;

        let mut inner = Vec::new();
        let _n = pack_dirent(&mut inner, 256, 100, b"hello", 1, DT_REG);
        let mut buf = Vec::with_capacity(inner.len() + 1);
        buf.push(0xaa);
        buf.extend_from_slice(&inner);

        rewrite_readdir_inodes(&mut buf[1..], |ino| ino + 7).unwrap();

        let dirent_size = core::mem::size_of::<FuseDirent>();
        let d: FuseDirent = bytemuck::pod_read_unaligned(&buf[1..=dirent_size]);
        assert_eq!(d.ino, 107);
    }
}
