// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! PFN superblock for virtio-pmem altmap (zero-RAM vmemmap).
//!
//! When a PMEM device has a valid PFN superblock at offset 4 KiB, the guest
//! kernel stores vmemmap (struct page array) inside the PMEM region itself
//! instead of consuming boot RAM. This eliminates OOM on large PMEM devices.
//!
//! The superblock format matches the kernel's `struct nd_pfn_sb` from
//! `drivers/nvdimm/pfn.h`. Key trick: virtio-pmem creates `namespace_io`
//! devices whose UUID is `uuid_null` (all zeros), so `parent_uuid = zeros`
//! passes the kernel's validation check without any kernel patches.

use super::{PFN_SB_DATAOFF, PFN_SB_NPFNS, PFN_SB_PAGE_SIZE, PFN_SB_SIZE, checked_section_align};

/// PFN superblock signature (16 bytes, null-terminated).
const PFN_SIG: &[u8; 16] = b"NVDIMM_PFN_INFO\0";

/// PFN mode: store vmemmap inside the PMEM region (altmap).
const PFN_MODE_PMEM: u32 = 2;

/// Maximum struct page size used by the kernel for vmemmap sizing.
/// From `drivers/nvdimm/nd.h`: `#define MAX_STRUCT_PAGE_SIZE 64`.
const MAX_STRUCT_PAGE_SIZE: u64 = 64;

/// Kernel info-block reserve: space for the PFN superblock metadata.
/// From `nd_info_block_reserve()` = `ALIGN(SZ_8K, PAGE_SIZE)`.
const SZ_8K: u64 = 8192;

/// Subsection alignment for dataoff (2 MiB on all architectures).
/// From `include/linux/mmzone.h`: `#define SUBSECTION_SHIFT 21`.
const SUBSECTION_SIZE: u64 = 2 << 20;

/// Guest page size — re-exported from `amla_constants` for convenience.
pub const GUEST_PAGE_SIZE: u64 = amla_constants::GUEST_PAGE_SIZE;

/// Pre-computed PMEM geometry for a single disk.
#[derive(Debug, Clone, Copy)]
pub struct PmemGeometry {
    /// Offset within the PMEM device where EROFS data begins (after
    /// the PFN superblock + vmemmap area). Always 2 MiB aligned.
    pub dataoff: u64,
    /// Actual PMEM device size: `dataoff + erofs_size`.
    pub total: u64,
}

impl PmemGeometry {
    /// Compute geometry for caller-provided image sizes.
    pub fn checked_compute(erofs_size: u64, page_size: u64) -> Option<Self> {
        let (dataoff, total) = pfn_overhead_checked(erofs_size, page_size)?;
        Some(Self { dataoff, total })
    }
}

/// Compute the PFN header overhead for an EROFS image.
///
/// Returns `(dataoff, total_pmem_size)` where:
/// - `dataoff` = size of the PFN header + vmemmap area (2 MiB aligned)
/// - `total_pmem_size` = `dataoff + erofs_size`
///
/// IMPORTANT: `dataoff` must be sized for the section-aligned total PMEM
/// device size, not just `dataoff + erofs_size`. The kernel uses
/// `resource_size()` (section-aligned) when computing vmemmap needs.
pub fn pfn_overhead_checked(erofs_size: u64, page_size: u64) -> Option<(u64, u64)> {
    if page_size == 0 || !page_size.is_power_of_two() {
        return None;
    }
    let mut section_total = checked_section_align(erofs_size)?;
    for _ in 0..10 {
        let dataoff = calculate_dataoff_checked(section_total, page_size)?;
        let total = dataoff.checked_add(erofs_size)?;
        let new_section_total = checked_section_align(total)?;
        if new_section_total == section_total {
            return Some((dataoff, total));
        }
        section_total = new_section_total;
    }
    let dataoff = calculate_dataoff_checked(section_total, page_size)?;
    Some((dataoff, dataoff.checked_add(erofs_size)?))
}

/// Calculate the dataoff for a given total PMEM size.
///
/// Mirrors the kernel's `nd_pfn_init()` calculation.
fn calculate_dataoff_checked(total_pmem_size: u64, page_size: u64) -> Option<u64> {
    let info_reserve = align_up_checked(SZ_8K, page_size)?;
    let npfns = total_pmem_size.saturating_sub(info_reserve) / page_size;
    let page_map_size = MAX_STRUCT_PAGE_SIZE.checked_mul(npfns)?;
    align_up_checked(info_reserve.checked_add(page_map_size)?, SUBSECTION_SIZE)
}

/// Build a 4096-byte PFN superblock.
///
/// The superblock is written at offset 4 KiB within the PMEM device.
/// `device_index` is used to generate a unique UUID per device.
#[allow(clippy::cast_possible_truncation)] // Kernel ABI constants fit in u32/u16
pub fn build_superblock(
    total_size: u64,
    dataoff: u64,
    page_size: u64,
    device_index: u32,
) -> Option<[u8; PFN_SB_SIZE]> {
    if page_size == 0 || !page_size.is_power_of_two() || dataoff > total_size {
        return None;
    }

    let mut sb = [0u8; PFN_SB_SIZE];

    // signature (offset 0x00, 16 bytes)
    sb[0x00..0x10].copy_from_slice(PFN_SIG);

    // uuid (offset 0x10, 16 bytes) — unique per device
    let mut uuid = [
        0x41, 0x4D, 0x4C, 0x41, // "AMLA"
        0x50, 0x46, 0x4E, 0x00, // "PFN\0"
        0x00, 0x00, 0x00, 0x00, // device index (LE)
        0x00, 0x00, 0x00, 0x01, // version
    ];
    uuid[8..12].copy_from_slice(&device_index.to_le_bytes());
    sb[0x10..0x20].copy_from_slice(&uuid);

    // parent_uuid (offset 0x20) — ALL ZEROS for namespace_io
    // flags (offset 0x30) — 0
    // Already zero.

    // version_major (offset 0x34, 2 bytes) — 1
    sb[0x34..0x36].copy_from_slice(&1u16.to_le_bytes());
    // version_minor (offset 0x36, 2 bytes) — 4
    sb[0x36..0x38].copy_from_slice(&4u16.to_le_bytes());

    // dataoff
    sb[PFN_SB_DATAOFF..PFN_SB_DATAOFF + 8].copy_from_slice(&dataoff.to_le_bytes());

    // npfns
    let npfns = (total_size - dataoff) / page_size;
    sb[PFN_SB_NPFNS..PFN_SB_NPFNS + 8].copy_from_slice(&npfns.to_le_bytes());

    // mode (offset 0x48, 4 bytes) — PFN_MODE_PMEM
    sb[0x48..0x4C].copy_from_slice(&PFN_MODE_PMEM.to_le_bytes());

    // align (offset 0x54, 4 bytes) — SUBSECTION_SIZE
    sb[0x54..0x58].copy_from_slice(&(SUBSECTION_SIZE as u32).to_le_bytes());

    // page_size
    sb[PFN_SB_PAGE_SIZE..PFN_SB_PAGE_SIZE + 4].copy_from_slice(&(page_size as u32).to_le_bytes());

    // page_struct_size (offset 0x5C, 2 bytes) — MAX_STRUCT_PAGE_SIZE
    sb[0x5C..0x5E].copy_from_slice(&(MAX_STRUCT_PAGE_SIZE as u16).to_le_bytes());

    // checksum (offset 0xFF8, 8 bytes) — fletcher64 with checksum field zeroed
    let checksum = fletcher64(&sb);
    sb[0xFF8..0x1000].copy_from_slice(&checksum.to_le_bytes());

    Some(sb)
}

/// Fletcher64 checksum matching the kernel's `nd_fletcher64()`.
fn fletcher64(data: &[u8]) -> u64 {
    assert!(
        data.len().is_multiple_of(4),
        "fletcher64: input length must be a multiple of 4"
    );
    let mut lo: u32 = 0;
    let mut hi: u64 = 0;
    for chunk in data.chunks_exact(4) {
        let word = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        lo = lo.wrapping_add(word);
        hi = hi.wrapping_add(u64::from(lo));
    }
    (hi << 32) | u64::from(lo)
}

fn align_up_checked(n: u64, align: u64) -> Option<u64> {
    if align == 0 || !align.is_power_of_two() {
        return None;
    }
    Some(n.checked_add(align - 1)? & !(align - 1))
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAGE_4K: u64 = GUEST_PAGE_SIZE;
    const MB: u64 = 1024 * 1024;
    const GB: u64 = 1024 * MB;

    // ─── fletcher64 ─────────────────────────────────────────────────────

    #[test]
    fn fletcher64_all_zeros() {
        let data = [0u8; 4096];
        assert_eq!(fletcher64(&data), 0);
    }

    #[test]
    fn fletcher64_single_word() {
        let mut data = [0u8; 4];
        data[0] = 1;
        assert_eq!(fletcher64(&data), (1u64 << 32) | 1);
    }

    #[test]
    fn fletcher64_two_words() {
        let mut data = [0u8; 8];
        data[0] = 1;
        data[4] = 2;
        assert_eq!(fletcher64(&data), (4u64 << 32) | 3);
    }

    #[test]
    fn fletcher64_wrapping() {
        let mut data = [0u8; 8];
        data[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(fletcher64(&data), 0xFFFF_FFFF_u64 << 32);
    }

    #[test]
    #[should_panic(expected = "multiple of 4")]
    fn fletcher64_rejects_unaligned() {
        fletcher64(&[0u8; 3]);
    }

    // ─── superblock ─────────────────────────────────────────────────────

    #[test]
    fn superblock_signature() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        assert_eq!(&sb[0..16], PFN_SIG);
    }

    #[test]
    fn superblock_parent_uuid_is_zero() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        assert_eq!(&sb[0x20..0x30], &[0u8; 16]);
    }

    #[test]
    fn superblock_mode_is_pmem() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        let mode = u32::from_le_bytes(sb[0x48..0x4C].try_into().unwrap());
        assert_eq!(mode, PFN_MODE_PMEM);
    }

    #[test]
    fn superblock_version() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        let major = u16::from_le_bytes(sb[0x34..0x36].try_into().unwrap());
        let minor = u16::from_le_bytes(sb[0x36..0x38].try_into().unwrap());
        assert_eq!(major, 1);
        assert_eq!(minor, 4);
    }

    #[test]
    fn superblock_checksum_valid() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        let stored = u64::from_le_bytes(sb[0xFF8..0x1000].try_into().unwrap());
        let mut sb_copy = sb;
        sb_copy[0xFF8..0x1000].fill(0);
        assert_eq!(fletcher64(&sb_copy), stored);
    }

    #[test]
    fn superblock_page_size() {
        let sb = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        let ps = u32::from_le_bytes(
            sb[PFN_SB_PAGE_SIZE..PFN_SB_PAGE_SIZE + 4]
                .try_into()
                .unwrap(),
        );
        assert_eq!(ps, 4096);
    }

    #[test]
    fn superblock_unique_uuid_per_device() {
        let sb0 = build_superblock(100 * MB, 2 * MB, PAGE_4K, 0).unwrap();
        let sb1 = build_superblock(100 * MB, 2 * MB, PAGE_4K, 1).unwrap();
        assert_ne!(&sb0[0x10..0x20], &sb1[0x10..0x20]);
    }

    #[test]
    fn superblock_npfns() {
        let total = 100 * MB;
        let dataoff = 2 * MB;
        let sb = build_superblock(total, dataoff, PAGE_4K, 0).unwrap();
        let npfns = u64::from_le_bytes(sb[PFN_SB_NPFNS..PFN_SB_NPFNS + 8].try_into().unwrap());
        assert_eq!(npfns, (total - dataoff) / PAGE_4K);
    }

    #[test]
    fn superblock_rejects_invalid_geometry() {
        assert!(build_superblock(100 * MB, 2 * MB, 0, 0).is_none());
        assert!(build_superblock(100 * MB, 2 * MB, 3000, 0).is_none());
        assert!(build_superblock(2 * MB, 100 * MB, PAGE_4K, 0).is_none());
    }

    // ─── dataoff ────────────────────────────────────────────────────────

    #[test]
    fn dataoff_is_subsection_aligned() {
        for &erofs_size in &[50 * MB, GB, 25 * GB] {
            let (dataoff, _) = pfn_overhead_checked(erofs_size, PAGE_4K).unwrap();
            assert_eq!(dataoff % SUBSECTION_SIZE, 0, "not aligned for {erofs_size}");
        }
    }

    #[test]
    fn dataoff_small_image() {
        let (dataoff, _) = pfn_overhead_checked(50 * MB, PAGE_4K).unwrap();
        #[cfg(target_arch = "x86_64")]
        assert_eq!(dataoff, 4 * MB);
        #[cfg(target_arch = "aarch64")]
        assert_eq!(dataoff, 10 * MB);
        assert_eq!(dataoff % (2 * MB), 0);
    }

    #[test]
    fn dataoff_large_image() {
        let (dataoff, total) = pfn_overhead_checked(25 * GB, PAGE_4K).unwrap();
        assert!(dataoff > 300 * MB, "25 GB should need >300 MB for vmemmap");
        assert!(dataoff < 500 * MB, "25 GB should need <500 MB for vmemmap");
        assert_eq!(total, dataoff + 25 * GB);
    }

    #[test]
    fn dataoff_convergence() {
        let (dataoff1, total1) = pfn_overhead_checked(10 * GB, PAGE_4K).unwrap();
        let (dataoff2, total2) = pfn_overhead_checked(10 * GB, PAGE_4K).unwrap();
        assert_eq!(dataoff1, dataoff2, "must be deterministic");
        assert_eq!(total1, total2);
        let section_total = checked_section_align(total1).unwrap();
        let needed_vmemmap = section_total / PAGE_4K * MAX_STRUCT_PAGE_SIZE;
        assert!(
            dataoff1 >= needed_vmemmap + SZ_8K,
            "dataoff must cover vmemmap for section-aligned total"
        );
    }

    #[test]
    fn dataoff_zero_image() {
        let (dataoff, total) = pfn_overhead_checked(0, PAGE_4K).unwrap();
        assert_eq!(dataoff % SUBSECTION_SIZE, 0);
        assert_eq!(total, dataoff);
    }

    #[test]
    fn dataoff_rejects_invalid_page_size() {
        assert!(pfn_overhead_checked(50 * MB, 0).is_none());
        assert!(pfn_overhead_checked(50 * MB, 3000).is_none());
    }

    #[test]
    fn dataoff_rejects_overflow() {
        assert!(pfn_overhead_checked(u64::MAX, PAGE_4K).is_none());
    }
}
