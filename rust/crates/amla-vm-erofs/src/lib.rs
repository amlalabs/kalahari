// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Pure-Rust EROFS image builder and reader.
//!
//! EROFS is a compact read-only filesystem format; amla uses it for all
//! guest rootfs images exposed to VMs via virtio-pmem so pages can be
//! mapped directly (DAX) from host storage without a guest page-cache
//! copy. [`BLOCK_SIZE`] is pinned to the guest page size for that reason.
//!
//! - [`builder`] assembles an image from a tree of [`entry::Entry`] values.
//! - [`reader`] parses an existing image and resolves inodes/dir entries.
//!
//! See the crate README for usage examples.

pub mod builder;
pub mod entry;
pub mod error;
pub mod ondisk;
pub mod reader;

pub use builder::{ErofsWriter, build_erofs, build_to_vec};
pub use entry::{Body, BuiltImage, DeviceKind, Entry, ImageStats, Metadata, Permissions, Xattr};
pub use error::ErofsError;
pub use reader::{DirEntry, ErofsImage, InodeInfo};

/// EROFS superblock magic number.
pub const EROFS_MAGIC: u32 = 0xE0F5_E1E2;

/// EROFS block size — always matches the guest page size for DAX compatibility.
///
/// `GUEST_PAGE_SIZE` is u64; the truncation to u32 is safe because the
/// compile-time assert below guarantees the value round-trips.
#[allow(clippy::cast_possible_truncation)]
pub const BLOCK_SIZE: u32 = amla_constants::GUEST_PAGE_SIZE as u32;
const _: () = assert!(BLOCK_SIZE as u64 == amla_constants::GUEST_PAGE_SIZE);
const _: () = assert!(BLOCK_SIZE.is_power_of_two());

/// log2 of the block size.
#[allow(clippy::cast_possible_truncation)]
pub const BLOCK_SIZE_BITS: u8 = BLOCK_SIZE.trailing_zeros() as u8;
const _: () = assert!(1u32 << BLOCK_SIZE_BITS as u32 == BLOCK_SIZE);

/// Byte offset of the superblock within the image.
pub const SUPERBLOCK_OFFSET: usize = 1024;
