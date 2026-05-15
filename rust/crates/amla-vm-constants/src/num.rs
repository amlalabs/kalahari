// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Intentional u64→u32 narrowing helpers.
//!
//! Call sites that split a `u64` into high/low `u32` halves use these helpers
//! instead of scattering `#[allow(clippy::cast_possible_truncation)]` across
//! the tree. The truncation is intentional and named by the function.
//!
//! For fallible narrowings (e.g. `slice.len() as u32`), prefer `u32::try_from`
//! directly with `?`-propagation; no helper needed.

/// Low 32 bits of a `u64`.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn lo32(x: u64) -> u32 {
    x as u32
}

/// High 32 bits of a `u64`.
#[inline]
#[must_use]
#[allow(clippy::cast_possible_truncation)]
pub const fn hi32(x: u64) -> u32 {
    (x >> 32) as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lo32_extracts_low_bits() {
        assert_eq!(lo32(0), 0);
        assert_eq!(lo32(0xFFFF_FFFF), 0xFFFF_FFFF);
        assert_eq!(lo32(0x1_0000_0000), 0);
        assert_eq!(lo32(0xDEAD_BEEF_CAFE_F00D), 0xCAFE_F00D);
        assert_eq!(lo32(u64::MAX), u32::MAX);
    }

    #[test]
    fn hi32_extracts_high_bits() {
        assert_eq!(hi32(0), 0);
        assert_eq!(hi32(0xFFFF_FFFF), 0);
        assert_eq!(hi32(0x1_0000_0000), 1);
        assert_eq!(hi32(0xDEAD_BEEF_CAFE_F00D), 0xDEAD_BEEF);
        assert_eq!(hi32(u64::MAX), u32::MAX);
    }

    #[test]
    fn halves_reconstruct_original() {
        let cases = [
            0u64,
            1,
            0xFFFF_FFFF,
            0x1_0000_0000,
            0xDEAD_BEEF_CAFE_F00D,
            u64::MAX,
        ];
        for &x in &cases {
            let rebuilt = (u64::from(hi32(x)) << 32) | u64::from(lo32(x));
            assert_eq!(rebuilt, x);
        }
    }
}
