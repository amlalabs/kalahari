// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum ErofsError {
    /// Image is too small or truncated
    TooSmall { expected: usize, actual: usize },
    /// Superblock magic mismatch
    BadMagic(u32),
    /// Invalid inode NID (out of range)
    InvalidNid(u64),
    /// Inode data layout is unsupported
    UnsupportedLayout(u16),
    /// Path is invalid (empty, missing leading slash, etc.)
    InvalidPath(String),
    /// Permissions contain file-type bits or other unsupported bits
    InvalidPermissions(u16),
    /// Duplicate path in builder
    DuplicatePath(String),
    /// Parent directory not found in builder
    ParentNotFound(String),
    /// Path not found in builder
    PathNotFound(String),
    /// Read offset is out of range
    OffsetOutOfRange { offset: u64, size: u64 },
    /// NID is not a directory
    NotADirectory(u64),
    /// NID is not a symlink
    NotASymlink(u64),
    /// Parent path exists but is not a directory
    ParentNotDirectory(String),
    /// Filename exceeds single-block limit
    NameTooLong { name_len: usize, max_len: usize },
    /// Numeric value overflows the target type during image construction
    Overflow(String),
    /// Block size is not 4 KiB (unsupported)
    UnsupportedBlockSize(u8),
    /// Image uses incompatible features this reader does not support
    UnsupportedFeature(u32),
    /// Superblock field is non-zero but unsupported by this reader
    UnsupportedSuperblockField(&'static str),
    /// Superblock is internally inconsistent
    MalformedSuperblock(&'static str),
    /// Inode uses extended format (not compact)
    UnsupportedInodeFormat(u16),
    /// Directory data is corrupted
    CorruptedDirectory(String),
    /// Buffer passed to `write_to` has the wrong size
    BufferSizeMismatch { expected: usize, actual: usize },
    /// I/O error during `write_to_writer`
    Io(String),
    /// Hard link target not found
    HardlinkTargetNotFound(String),
    /// Builder state is invalid after an earlier push error
    BuilderPoisoned,
}

impl fmt::Display for ErofsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooSmall { expected, actual } => {
                write!(f, "image too small: need {expected} bytes, got {actual}")
            }
            Self::BadMagic(m) => write!(f, "bad superblock magic: {m:#010x}"),
            Self::InvalidNid(n) => write!(f, "invalid inode NID: {n}"),
            Self::UnsupportedLayout(l) => write!(f, "unsupported inode layout: {l}"),
            Self::InvalidPath(p) => write!(f, "invalid path: {p:?}"),
            Self::InvalidPermissions(bits) => {
                write!(
                    f,
                    "invalid permissions: {bits:#06o} includes non-permission bits"
                )
            }
            Self::DuplicatePath(p) => write!(f, "duplicate path: {p:?}"),
            Self::ParentNotFound(p) => write!(f, "parent directory not found: {p:?}"),
            Self::PathNotFound(p) => write!(f, "path not found: {p:?}"),
            Self::OffsetOutOfRange { offset, size } => {
                write!(f, "offset {offset} out of range for size {size}")
            }
            Self::NotADirectory(n) => write!(f, "NID {n} is not a directory"),
            Self::NotASymlink(n) => write!(f, "NID {n} is not a symlink"),
            Self::ParentNotDirectory(p) => {
                write!(f, "parent is not a directory: {p:?}")
            }
            Self::NameTooLong { name_len, max_len } => {
                write!(f, "filename too long: {name_len} bytes (max {max_len})")
            }
            Self::Overflow(msg) => write!(f, "overflow: {msg}"),
            Self::UnsupportedBlockSize(bits) => {
                write!(f, "unsupported block size: blkszbits={bits} (expected 12)")
            }
            Self::UnsupportedFeature(flags) => {
                write!(f, "unsupported incompatible features: {flags:#010x}")
            }
            Self::UnsupportedSuperblockField(field) => {
                write!(f, "unsupported superblock field set: {field}")
            }
            Self::MalformedSuperblock(reason) => write!(f, "malformed superblock: {reason}"),
            Self::UnsupportedInodeFormat(fmt) => {
                write!(
                    f,
                    "unsupported inode format (extended): i_format={fmt:#06x}"
                )
            }
            Self::CorruptedDirectory(msg) => write!(f, "corrupted directory: {msg}"),
            Self::BufferSizeMismatch { expected, actual } => {
                write!(f, "buffer size mismatch: expected {expected}, got {actual}")
            }
            Self::Io(msg) => write!(f, "io: {msg}"),
            Self::HardlinkTargetNotFound(p) => {
                write!(f, "hard link target not found: {p:?}")
            }
            Self::BuilderPoisoned => write!(f, "builder is poisoned after an earlier error"),
        }
    }
}

impl std::error::Error for ErofsError {}
