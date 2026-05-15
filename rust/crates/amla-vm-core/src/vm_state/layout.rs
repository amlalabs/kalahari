// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Layout constants used by the VM state file.

use super::header::PAGE_SIZE;

// =========================================================================
// PFN superblock — kernel ABI constants from drivers/nvdimm/pfn.h
// =========================================================================

/// Byte offset within a PMEM device where the PFN superblock is stored.
/// The kernel reads it via `nvdimm_read_bytes(ndns, SZ_4K, ...)`.
pub const PFN_SB_OFFSET: usize = 4096;

/// Byte offset of `dataoff` (u64 LE) within the PFN superblock struct.
pub const PFN_SB_DATAOFF: usize = 0x38;

/// Byte offset of `npfns` (u64 LE) within the PFN superblock struct.
pub const PFN_SB_NPFNS: usize = 0x40;

/// Byte offset of `page_size` (u32 LE) within the PFN superblock struct.
pub const PFN_SB_PAGE_SIZE: usize = 0x58;

/// Size of the PFN superblock struct (kernel ABI constant).
/// `BUILD_BUG_ON(sizeof(struct nd_pfn_sb) != SZ_4K)` in the kernel.
pub const PFN_SB_SIZE: usize = 4096;

// =========================================================================
// NVDIMM section alignment
// =========================================================================

/// Guest NVDIMM section alignment: 128 MiB on x86, 512 MiB on ARM64.
#[cfg(target_arch = "x86_64")]
pub const SECTION_SIZE: u64 = 128 << 20;
/// Guest NVDIMM section alignment: 128 MiB on x86, 512 MiB on ARM64.
#[cfg(target_arch = "aarch64")]
pub const SECTION_SIZE: u64 = 512 << 20;
/// Guest NVDIMM section alignment (fallback).
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const SECTION_SIZE: u64 = 128 << 20;

/// Round `size` up to the next `SECTION_SIZE` boundary.
pub const fn section_align(size: u64) -> u64 {
    (size + SECTION_SIZE - 1) & !(SECTION_SIZE - 1)
}

/// Checked variant of [`section_align`].
pub const fn checked_section_align(size: u64) -> Option<u64> {
    match size.checked_add(SECTION_SIZE - 1) {
        Some(v) => Some(v & !(SECTION_SIZE - 1)),
        None => None,
    }
}

/// Ring buffer total size (matches `HOST_GUEST_TOTAL_SIZE` in amla-ringbuf).
/// Layout: SharedHeader(64) + 2×RingHeader(64) + 2×64MiB data = 192 + 128MiB.
pub const RING_BUFFER_SIZE: usize = 192 + 2 * 64 * 1024 * 1024;

/// vCPU state section size per CPU.
///
/// 16 KiB per slot covers both x86 (~14 KiB) and ARM64 (~1 KiB).
pub const VCPU_SLOT_SIZE: usize = 16384;

// Compile-time check: slot must be page-aligned.
const _: () = assert!(VCPU_SLOT_SIZE.is_multiple_of(PAGE_SIZE));

/// Round `n` up to the next multiple of `PAGE_SIZE`.
pub const fn page_align(n: u64) -> u64 {
    let ps = PAGE_SIZE as u64;
    (n + ps - 1) & !(ps - 1)
}

/// Checked page alignment — returns `None` on overflow.
pub const fn checked_page_align(n: u64) -> Option<u64> {
    let ps = PAGE_SIZE as u64;
    match n.checked_add(ps - 1) {
        Some(v) => Some(v & !(ps - 1)),
        None => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::vm_state::header::{
        MAX_DEVICES, MAX_VCPUS, VM_STATE_MAGIC, VM_STATE_VERSION, VmStateHeader,
    };

    fn default_header() -> VmStateHeader {
        VmStateHeader::compute(
            1,
            8,
            256 * 1024 * 1024, // 256 MiB
            &[],
            &[],
        )
        .unwrap()
    }

    #[test]
    fn compute_succeeds_for_valid_config() {
        let h = default_header();
        assert!(h.total_size() > 0);
    }

    #[test]
    fn all_sections_page_aligned() {
        let h = default_header();
        assert!(h.is_page_aligned());
    }

    #[test]
    fn sections_do_not_overlap() {
        let h = default_header();

        // Each section starts after the previous one ends
        assert!(h.psci_offset >= page_align(core::mem::size_of::<VmStateHeader>() as u64));
        assert!(h.psci_offset + h.psci_size <= h.vcpu_offset);
        assert!(h.vcpu_offset + h.vcpu_size <= h.irqchip_offset);
        assert!(h.irqchip_offset + h.irqchip_size <= h.device_offset);
        assert!(h.device_offset + h.device_size <= h.device_meta_offset);
        assert!(h.device_meta_offset + h.device_meta_size <= h.ring_offset);
        assert!(h.ring_offset + h.ring_size <= h.pmem_offset);
        assert!(h.pmem_offset + h.pmem_size <= h.ram_desc_offset);
        assert!(h.ram_desc_offset + h.ram_desc_size <= h.ram_offset);
        assert!(h.ram_offset + h.ram_size <= h.total_size());
    }

    #[test]
    fn rejects_too_many_vcpus() {
        let r = VmStateHeader::compute(
            u32::try_from(MAX_VCPUS).unwrap() + 1,
            8,
            256 * 1024 * 1024,
            &[],
            &[],
        );
        assert!(r.is_none());
    }

    #[test]
    fn rejects_too_many_devices() {
        let r = VmStateHeader::compute(
            1,
            u32::try_from(MAX_DEVICES).unwrap() + 1,
            256 * 1024 * 1024,
            &[],
            &[],
        );
        assert!(r.is_none());
    }

    #[test]
    fn max_vcpus_accepted() {
        let h = VmStateHeader::compute(
            u32::try_from(MAX_VCPUS).unwrap(),
            8,
            256 * 1024 * 1024,
            &[],
            &[],
        )
        .unwrap();
        assert!(h.is_page_aligned());
        assert!(h.vcpu_size >= (MAX_VCPUS * VCPU_SLOT_SIZE) as u64);
    }

    #[test]
    fn header_fields_correct() {
        let h = default_header();
        assert_eq!(h.magic, VM_STATE_MAGIC);
        assert_eq!(h.version, VM_STATE_VERSION);
        assert_eq!(h.vcpu_count, 1);
        assert_eq!(h.device_count, 8);
    }

    #[test]
    fn ram_size_preserved() {
        let h = VmStateHeader::compute(1, 8, 512 * 1024 * 1024, &[], &[]).unwrap();
        assert_eq!(h.ram_size, 512 * 1024 * 1024);
    }

    #[test]
    fn rejects_ram_size_not_representable_by_descriptor_bitmap() {
        let r = VmStateHeader::compute(1, 8, 256 * 1024 * 1024 + 4096, &[], &[]);
        assert!(r.is_none());
    }

    #[test]
    fn zero_devices_accepted() {
        let h = VmStateHeader::compute(1, 0, 256 * 1024 * 1024, &[], &[]).unwrap();
        assert_eq!(h.device_size, 0);
        assert!(h.is_page_aligned());
    }

    #[test]
    fn no_pmem_has_zero_pmem_section() {
        let h = default_header();
        assert_eq!(h.pmem_size, 0);
        // pmem_offset should equal ram_desc_offset when no PMEM sections
        assert_eq!(h.pmem_offset + h.pmem_size, h.ram_desc_offset);
    }

    #[test]
    fn pmem_sections_are_page_aligned() {
        let h = VmStateHeader::compute(
            1,
            8,
            256 * 1024 * 1024,
            &[2 * 1024 * 1024, 400 * 1024 * 1024], // 2 MB + 400 MB
            &[1, 1],
        )
        .unwrap();
        assert!(h.is_page_aligned());
        assert!(h.pmem_size > 0);
        assert!(h.pmem_offset + h.pmem_size <= h.ram_desc_offset);
    }

    #[test]
    fn pmem_section_nonzero_and_aligned() {
        let h = VmStateHeader::compute(
            1,
            8,
            256 * 1024 * 1024,
            &[2 * 1024 * 1024], // 2 MB image
            &[1],
        )
        .unwrap();
        assert!(h.pmem_size > 0);
        assert!(h.is_page_aligned());
    }

    #[test]
    fn section_align_already_aligned() {
        assert_eq!(section_align(SECTION_SIZE), SECTION_SIZE);
        assert_eq!(section_align(2 * SECTION_SIZE), 2 * SECTION_SIZE);
    }

    #[test]
    fn section_align_rounds_up() {
        assert_eq!(section_align(1), SECTION_SIZE);
        assert_eq!(section_align(SECTION_SIZE - 1), SECTION_SIZE);
        assert_eq!(section_align(SECTION_SIZE + 1), 2 * SECTION_SIZE);
    }

    #[test]
    fn section_align_zero() {
        assert_eq!(section_align(0), 0);
    }
}
