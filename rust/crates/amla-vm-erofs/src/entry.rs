// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Entry types for the streaming EROFS builder.
//!
//! These types represent filesystem entries in a format similar to tar
//! archives: each entry has a path, metadata, and a body describing its
//! type-specific content.

use crate::ErofsError;

/// POSIX permission and special bits, without `S_IFMT` file-type bits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Permissions(u16);

impl Permissions {
    /// Bits accepted in an input permissions value.
    pub const MASK: u16 = 0o7777;

    /// Create permissions from raw bits.
    ///
    /// Returns `None` when `bits` includes file-type bits or any other bit
    /// outside [`MASK`](Self::MASK).
    #[must_use]
    pub const fn new(bits: u16) -> Option<Self> {
        if bits & !Self::MASK == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// Create permissions by discarding file-type bits from a POSIX mode.
    #[must_use]
    pub const fn from_mode(mode: u16) -> Self {
        Self(mode & Self::MASK)
    }

    /// Return the raw permission bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }
}

impl TryFrom<u16> for Permissions {
    type Error = ErofsError;

    fn try_from(bits: u16) -> Result<Self, Self::Error> {
        Self::new(bits).ok_or(ErofsError::InvalidPermissions(bits))
    }
}

/// A filesystem entry to be written into an EROFS image.
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub metadata: Metadata,
    pub body: Body,
}

/// POSIX file metadata.
#[derive(Debug, Clone)]
pub struct Metadata {
    /// Permission and special bits only; file-type bits are derived from [`Body`].
    pub permissions: Permissions,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub xattrs: Vec<Xattr>,
}

impl Metadata {
    /// Construct metadata with zero ownership, timestamps, and xattrs.
    #[must_use]
    pub const fn new(permissions: Permissions) -> Self {
        Self {
            permissions,
            uid: 0,
            gid: 0,
            mtime: 0,
            mtime_nsec: 0,
            xattrs: Vec::new(),
        }
    }
}

/// An extended attribute (key-value pair).
#[derive(Debug, Clone)]
pub struct Xattr {
    pub key: Vec<u8>,
    pub value: Vec<u8>,
}

/// Device node kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceKind {
    /// Character device (`S_IFCHR`).
    Character,
    /// Block device (`S_IFBLK`).
    Block,
}

/// Entry body — what kind of filesystem object this is.
#[derive(Debug, Clone)]
pub enum Body {
    Directory,
    RegularFile(Vec<u8>),
    Symlink(String),
    /// Hard link to another path (target must appear earlier in the entry stream).
    Hardlink(String),
    DeviceNode {
        kind: DeviceKind,
        rdev: u32,
    },
    Fifo,
    Socket,
}

/// Statistics about a built EROFS image.
#[derive(Debug, Clone)]
pub struct ImageStats {
    pub image_size: u64,
    pub inode_count: u64,
    pub block_count: u32,
}

/// A built EROFS image as a byte buffer.
#[derive(Debug, Clone)]
pub struct BuiltImage {
    data: Vec<u8>,
    pub stats: ImageStats,
}

impl BuiltImage {
    pub(crate) const fn new(data: Vec<u8>, stats: ImageStats) -> Self {
        Self { data, stats }
    }

    /// Size of the EROFS image in bytes.
    #[must_use]
    pub const fn image_size(&self) -> usize {
        self.data.len()
    }

    /// Return the image bytes as a `Vec<u8>`.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }

    /// Borrow the image bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Write the image into a pre-allocated buffer.
    ///
    /// `buf` must be at least [`image_size()`](Self::image_size) bytes.
    pub fn write_to(&self, buf: &mut [u8]) -> Result<(), crate::ErofsError> {
        let needed = self.data.len();
        if buf.len() < needed {
            return Err(crate::ErofsError::BufferSizeMismatch {
                expected: needed,
                actual: buf.len(),
            });
        }
        buf[..needed].copy_from_slice(&self.data);
        Ok(())
    }
}

// ── Xattr serialization ──────────────────────────────────────────────────

// EROFS xattr prefix indices (from Linux include/uapi/linux/xattr.h)
const XATTR_INDEX_USER: u8 = 1;
const XATTR_INDEX_POSIX_ACL_ACCESS: u8 = 2;
const XATTR_INDEX_POSIX_ACL_DEFAULT: u8 = 3;
const XATTR_INDEX_SECURITY: u8 = 6;
const XATTR_INDEX_SYSTEM: u8 = 7;
const XATTR_INDEX_TRUSTED: u8 = 8;

/// Split an xattr key into (`prefix_index`, `name_suffix`).
fn split_xattr_prefix(key: &[u8]) -> (u8, &[u8]) {
    // Order matters: more specific prefixes first
    if let Some(suffix) = key.strip_prefix(b"security.") {
        return (XATTR_INDEX_SECURITY, suffix);
    }
    if let Some(suffix) = key.strip_prefix(b"trusted.") {
        return (XATTR_INDEX_TRUSTED, suffix);
    }
    if key == b"system.posix_acl_access" {
        return (XATTR_INDEX_POSIX_ACL_ACCESS, b"");
    }
    if key == b"system.posix_acl_default" {
        return (XATTR_INDEX_POSIX_ACL_DEFAULT, b"");
    }
    if let Some(suffix) = key.strip_prefix(b"system.") {
        return (XATTR_INDEX_SYSTEM, suffix);
    }
    if let Some(suffix) = key.strip_prefix(b"user.") {
        return (XATTR_INDEX_USER, suffix);
    }
    // Unknown prefix — store full key with index 0 (no prefix)
    (0, key)
}

/// Serialize xattrs into an inline xattr blob for an EROFS inode.
///
/// Returns the complete blob (12-byte header + entries + padding) to be
/// appended after the inode struct. Returns empty vec if no xattrs.
///
/// Also returns the `i_xattr_icount` value (blob size in 4-byte units).
pub(crate) fn serialize_inline_xattrs(xattrs: &[Xattr]) -> Result<(Vec<u8>, u16), ErofsError> {
    if xattrs.is_empty() {
        return Ok((Vec::new(), 0));
    }

    let mut buf = Vec::new();

    // 12-byte XattrInodeHeader (all zeros: no shared xattrs)
    buf.extend_from_slice(&[0u8; 12]);

    for xattr in xattrs {
        let (prefix_index, name_suffix) = split_xattr_prefix(&xattr.key);

        // 4-byte xattr entry header
        let name_len = u8::try_from(name_suffix.len()).map_err(|_| {
            ErofsError::Overflow(format!(
                "xattr name suffix len {} exceeds u8::MAX",
                name_suffix.len()
            ))
        })?;
        let value_size = u16::try_from(xattr.value.len()).map_err(|_| {
            ErofsError::Overflow(format!(
                "xattr value size {} exceeds u16::MAX",
                xattr.value.len()
            ))
        })?;

        buf.push(name_len);
        buf.push(prefix_index);
        buf.extend_from_slice(&value_size.to_le_bytes());

        // Name suffix
        buf.extend_from_slice(name_suffix);

        // Value
        buf.extend_from_slice(&xattr.value);

        // Pad to 4-byte alignment
        let pad = (4 - (buf.len() % 4)) % 4;
        buf.extend(std::iter::repeat_n(0u8, pad));
    }

    // Kernel computes xattr area size as: 12 + 4 * (icount - 1) = 4 * icount + 8
    // So: icount = (blob_len - 8) / 4
    let icount_usz = (buf.len() - 8) / 4;
    let icount = u16::try_from(icount_usz)
        .map_err(|_| ErofsError::Overflow(format!("xattr icount {icount_usz} exceeds u16::MAX")))?;

    Ok((buf, icount))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn split_xattr_prefix_security() {
        let (idx, suffix) = split_xattr_prefix(b"security.selinux");
        assert_eq!(idx, XATTR_INDEX_SECURITY);
        assert_eq!(suffix, b"selinux");
    }

    #[test]
    fn split_xattr_prefix_user() {
        let (idx, suffix) = split_xattr_prefix(b"user.myattr");
        assert_eq!(idx, XATTR_INDEX_USER);
        assert_eq!(suffix, b"myattr");
    }

    #[test]
    fn split_xattr_prefix_unknown() {
        let (idx, suffix) = split_xattr_prefix(b"custom.thing");
        assert_eq!(idx, 0);
        assert_eq!(suffix, b"custom.thing");
    }

    #[test]
    fn serialize_empty_xattrs() {
        let (blob, icount) = serialize_inline_xattrs(&[]).unwrap();
        assert!(blob.is_empty());
        assert_eq!(icount, 0);
    }

    #[test]
    fn serialize_xattr_alignment() {
        let xattrs = vec![Xattr {
            key: b"security.selinux".to_vec(),
            value: b"unconfined_u:unconfined_r:unconfined_t:s0".to_vec(),
        }];
        let (blob, icount) = serialize_inline_xattrs(&xattrs).unwrap();
        assert_eq!(blob.len() % 4, 0, "blob must be 4-byte aligned");
        // Kernel formula: xattr area = 12 + 4*(icount-1) = 4*icount + 8
        assert_eq!(4 * icount as usize + 8, blob.len());
        // Header (12) + entry header (4) + "selinux" (7) + value (41) = 64
        assert!(blob.len() >= 64);
    }
}
