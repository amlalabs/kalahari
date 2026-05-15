// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 Linux Image header parsing.
//!
//! The ARM64 Image format has a 64-byte header at offset 0:
//!
//! ```text
//! Offset  Size  Field
//!  0       4    code0 (executable branch instruction)
//!  4       4    code1 (executable branch instruction)
//!  8       8    text_offset (offset from start of RAM to load kernel)
//! 16       8    image_size (effective image size, 0 = unknown)
//! 24       8    flags (bit 0: kernel endianness, bits 1-2: page size)
//! 32       8    res2 (reserved)
//! 40       8    res3 (reserved)
//! 48       8    res4 (reserved)
//! 56       4    magic ("ARM\x64")
//! 60       4    res5 (reserved / PE header offset)
//! ```

use crate::arm64::error::{BootError, Result};

/// Minimum ARM64 Image header size.
const HEADER_SIZE: usize = 64;

/// Magic bytes at offset 56: "ARM\x64".
const ARM64_MAGIC: [u8; 4] = [0x41, 0x52, 0x4d, 0x64];

/// Parsed ARM64 Image header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ImageHeader {
    /// Offset from start of RAM to load the kernel text.
    pub text_offset: u64,
    /// Effective size of the kernel image (0 = unknown pre-v3.17).
    pub image_size: u64,
    /// Flags (bit 0: BE=1/LE=0, bits 1-2: page size hint).
    pub flags: u64,
}

impl ImageHeader {
    /// Parse an ARM64 Image header from kernel bytes.
    ///
    /// # Errors
    ///
    /// Returns [`BootError`] if the image is too small, the magic bytes are
    /// wrong, or `text_offset` is not page-aligned.
    pub fn parse(kernel: &[u8]) -> Result<Self> {
        if kernel.len() < HEADER_SIZE {
            return Err(BootError::ImageTooSmall(kernel.len()));
        }

        // Verify magic at offset 56
        if kernel[56..60] != ARM64_MAGIC {
            return Err(BootError::InvalidMagic);
        }

        // Note: HEADER_SIZE check above guarantees all indices are in bounds.
        // The map_err is unreachable but avoids unwrap in a deny(unwrap_used) workspace.
        let text_offset = u64::from_le_bytes(
            kernel[8..16]
                .try_into()
                .map_err(|_| BootError::ImageTooSmall(kernel.len()))?,
        );
        let image_size = u64::from_le_bytes(
            kernel[16..24]
                .try_into()
                .map_err(|_| BootError::ImageTooSmall(kernel.len()))?,
        );
        let flags = u64::from_le_bytes(
            kernel[24..32]
                .try_into()
                .map_err(|_| BootError::ImageTooSmall(kernel.len()))?,
        );

        // text_offset should be page-aligned (typically 0x80000 = 512KB)
        if text_offset > 0 && !text_offset.is_multiple_of(0x1000) {
            return Err(BootError::InvalidTextOffset(text_offset));
        }

        Ok(Self {
            text_offset,
            image_size,
            flags,
        })
    }

    /// Whether the kernel is big-endian (flag bit 0 = 1 per ARM64 Image spec).
    #[must_use]
    pub const fn is_big_endian(self) -> bool {
        self.flags & 1 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_image(text_offset: u64, image_size: u64, flags: u64) -> Vec<u8> {
        let mut img = vec![0u8; 128];
        img[8..16].copy_from_slice(&text_offset.to_le_bytes());
        img[16..24].copy_from_slice(&image_size.to_le_bytes());
        img[24..32].copy_from_slice(&flags.to_le_bytes());
        img[56..60].copy_from_slice(&ARM64_MAGIC);
        img
    }

    #[test]
    fn parse_valid_header() {
        let img = make_image(0x8_0000, 0x100_0000, 0x01);
        let hdr = ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.text_offset, 0x8_0000);
        assert_eq!(hdr.image_size, 0x100_0000);
        assert!(hdr.is_big_endian()); // flags=1 → bit 0 set → big-endian
    }

    #[test]
    fn parse_too_small() {
        let img = vec![0u8; 32];
        assert!(matches!(
            ImageHeader::parse(&img),
            Err(BootError::ImageTooSmall(32))
        ));
    }

    #[test]
    fn parse_bad_magic() {
        let mut img = vec![0u8; 128];
        img[56..60].copy_from_slice(b"NOPE");
        assert!(matches!(
            ImageHeader::parse(&img),
            Err(BootError::InvalidMagic)
        ));
    }

    #[test]
    fn parse_unaligned_text_offset() {
        let img = make_image(0x8_0001, 0x100_0000, 0);
        assert!(matches!(
            ImageHeader::parse(&img),
            Err(BootError::InvalidTextOffset(_))
        ));
    }

    #[test]
    fn parse_zero_text_offset() {
        let img = make_image(0, 0x100_0000, 0);
        let hdr = ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.text_offset, 0);
    }

    #[test]
    fn parse_image_size_larger_than_file_is_valid() {
        // image_size includes BSS/alignment that isn't in the file — must be accepted
        let img = make_image(0x8_0000, 0x200_0000, 0);
        let hdr = ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.image_size, 0x200_0000);
    }

    #[test]
    fn parse_zero_image_size_is_valid() {
        let img = make_image(0x8_0000, 0, 0);
        let hdr = ImageHeader::parse(&img).unwrap();
        assert_eq!(hdr.image_size, 0);
    }

    #[test]
    fn big_endian_flag_clear_means_le() {
        let img = make_image(0x8_0000, 0x100_0000, 0x00);
        let hdr = ImageHeader::parse(&img).unwrap();
        assert!(!hdr.is_big_endian()); // flags=0 → bit 0 clear → little-endian
    }

    #[test]
    fn endianness_comprehensive() {
        // LE: flags=0 (pre-v3.17, no bits set)
        let hdr = ImageHeader::parse(&make_image(0x8_0000, 0x100_0000, 0)).unwrap();
        assert!(!hdr.is_big_endian());

        // LE: flags=0b010 (4K page size hint, bit 0 = 0)
        let hdr = ImageHeader::parse(&make_image(0x8_0000, 0x100_0000, 0b010)).unwrap();
        assert!(!hdr.is_big_endian());

        // BE: flags=1 (bit 0 = 1)
        let hdr = ImageHeader::parse(&make_image(0x8_0000, 0x100_0000, 1)).unwrap();
        assert!(hdr.is_big_endian());

        // BE: flags=0b011 (4K page + BE)
        let hdr = ImageHeader::parse(&make_image(0x8_0000, 0x100_0000, 0b011)).unwrap();
        assert!(hdr.is_big_endian());
    }
}
