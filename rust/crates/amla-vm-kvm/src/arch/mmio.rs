// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Shared MMIO exit helpers used by both `x86_64` and ARM64 exit handlers.
//!
//! KVM provides MMIO data in a fixed `[u8; 8]` array within the `kvm_run`
//! union. These helpers validate the access size and decode the data into
//! a native `u64`, avoiding duplicated match arms in each architecture.

/// Valid MMIO access sizes supported by KVM.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MmioSize {
    /// 1-byte access.
    One,
    /// 2-byte access.
    Two,
    /// 4-byte access.
    Four,
    /// 8-byte access.
    Eight,
}

impl MmioSize {
    /// Return the size in bytes.
    pub(crate) const fn bytes(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
            Self::Eight => 8,
        }
    }
}

/// Validate an MMIO access size.
///
/// Returns `None` for sizes that aren't 1, 2, 4, or 8 — callers should
/// log a warning and return `VcpuExit::Unknown` in that case.
#[inline]
pub const fn decode_mmio_size(len: u32) -> Option<MmioSize> {
    match len {
        1 => Some(MmioSize::One),
        2 => Some(MmioSize::Two),
        4 => Some(MmioSize::Four),
        8 => Some(MmioSize::Eight),
        _ => None,
    }
}

/// Decode MMIO write data from KVM's `mmio.data` array.
#[inline]
pub fn decode_mmio_write_data(data: [u8; 8], size: MmioSize) -> u64 {
    match size {
        MmioSize::One => u64::from(data[0]),
        MmioSize::Two => u64::from(u16::from_le_bytes([data[0], data[1]])),
        MmioSize::Four => u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        MmioSize::Eight => u64::from_le_bytes(data),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── decode_mmio_size ─────────────────────────────────────────

    #[test]
    fn valid_sizes() {
        assert_eq!(decode_mmio_size(1), Some(MmioSize::One));
        assert_eq!(decode_mmio_size(2), Some(MmioSize::Two));
        assert_eq!(decode_mmio_size(4), Some(MmioSize::Four));
        assert_eq!(decode_mmio_size(8), Some(MmioSize::Eight));
    }

    #[test]
    fn invalid_sizes() {
        for bad in [0, 3, 5, 16, u32::MAX] {
            assert_eq!(decode_mmio_size(bad), None, "len={bad} should be rejected");
        }
    }

    // ── decode_mmio_write_data ───────────────────────────────────

    #[test]
    fn write_1byte() {
        // Trailing bytes are 0xFF to verify only byte 0 is read.
        let data = [0xAB, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(decode_mmio_write_data(data, MmioSize::One), 0xAB);
    }

    #[test]
    fn write_2byte() {
        let data = [0xEF, 0xBE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(decode_mmio_write_data(data, MmioSize::Two), 0xBEEF);
    }

    #[test]
    fn write_4byte() {
        let data = [0xEF, 0xBE, 0xAD, 0xDE, 0xFF, 0xFF, 0xFF, 0xFF];
        assert_eq!(decode_mmio_write_data(data, MmioSize::Four), 0xDEAD_BEEF);
    }

    #[test]
    fn write_8byte() {
        let data = 0x0123_4567_89AB_CDEF_u64.to_le_bytes();
        assert_eq!(
            decode_mmio_write_data(data, MmioSize::Eight),
            0x0123_4567_89AB_CDEF
        );
    }
}
