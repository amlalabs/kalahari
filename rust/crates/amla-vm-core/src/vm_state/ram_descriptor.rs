// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! RAM descriptor: block bitmap for guest memory regions.
//!
//! The RAM descriptor section sits before guest RAM in the mmap. It contains a
//! header and a bitmap where each bit represents one `BLOCK_SIZE` (2 MiB) block.
//! For the base RAM node, a set bit means the block is a "hole" (backing released).
//! For hotplug nodes, a set bit means the block is "plugged" (virtio-mem).

use core::cell::UnsafeCell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, Ordering};

use bytemuck::{Pod, Zeroable};

use super::header::PAGE_SIZE;

/// Bitmap granularity — one bit per block.
///
/// Uses [`BLOCK_SIZE`](crate::BLOCK_SIZE) from the crate root so both the
/// RAM descriptor bitmap and virtio-mem share a single compile-time constant.
pub const BITMAP_BLOCK_SIZE: u64 = crate::BLOCK_SIZE;

/// RAM size represented exactly by a RAM descriptor bitmap.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct RamSize(u64);

impl RamSize {
    /// Validate a byte size as nonzero, block-aligned descriptor RAM.
    pub const fn new(bytes: u64) -> Result<Self, &'static str> {
        if bytes == 0 {
            return Err("RAM size is zero");
        }
        if !bytes.is_multiple_of(BITMAP_BLOCK_SIZE) {
            return Err("RAM size is not a descriptor block multiple");
        }
        if bytes / BITMAP_BLOCK_SIZE > u32::MAX as u64 {
            return Err("RAM descriptor block_count exceeds u32");
        }
        Ok(Self(bytes))
    }

    /// RAM size in bytes.
    #[must_use]
    pub const fn bytes(self) -> u64 {
        self.0
    }

    /// Number of descriptor blocks.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // `RamSize::new` proves the quotient fits in u32.
    pub const fn block_count(self) -> u32 {
        (self.0 / BITMAP_BLOCK_SIZE) as u32
    }

    /// Number of bytes needed for the bitmap (1 bit per block, rounded up).
    #[must_use]
    pub const fn bitmap_byte_len(self) -> u64 {
        (self.block_count() as u64).div_ceil(8)
    }

    /// Total size of the RAM descriptor section (header + bitmap), 16 KiB-aligned.
    #[must_use]
    pub const fn descriptor_section_size(self) -> u64 {
        let raw = core::mem::size_of::<RamDescriptorHeader>() as u64 + self.bitmap_byte_len();
        let ps = PAGE_SIZE as u64;
        (raw + ps - 1) & !(ps - 1)
    }
}

/// Header at the start of the RAM descriptor section.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct RamDescriptorHeader {
    /// Block size used by the bitmap ([`BITMAP_BLOCK_SIZE`]).
    pub block_size: u32,
    /// Number of blocks tracked by the bitmap (`ram_size / BITMAP_BLOCK_SIZE`).
    pub block_count: u32,
    /// Reserved for future use.
    pub reserved: [u64; 1],
}

// 16 bytes total.
const _: () = assert!(core::mem::size_of::<RamDescriptorHeader>() == 16);

/// Number of bytes needed for the bitmap (1 bit per block, rounded up).
pub const fn bitmap_byte_len(ram_size: RamSize) -> u64 {
    ram_size.bitmap_byte_len()
}

/// Total size of the RAM descriptor section (header + bitmap), 16 KiB-aligned.
pub const fn ram_desc_section_size(ram_size: RamSize) -> u64 {
    ram_size.descriptor_section_size()
}

/// Check if a page is entirely zero using wide loads.
///
/// `align_to::<u128>` reinterprets the byte slice as 128-bit chunks.
/// Pages from mmap are page-aligned, so prefix/suffix are empty and
/// the entire page becomes 256 × u128 comparisons. The compiler
/// auto-vectorizes this to AVX2 (32 bytes/iteration) on `x86_64`
/// or NEON on ARM64 — no manual SIMD intrinsics needed.
#[must_use]
pub fn is_zero(page: &[u8]) -> bool {
    // SAFETY: u128 has no invalid bit patterns; align_to handles alignment.
    let (prefix, chunks, suffix) = unsafe { page.align_to::<u128>() };
    prefix.iter().all(|&b| b == 0)
        && chunks.iter().all(|&c| c == 0)
        && suffix.iter().all(|&b| b == 0)
}

/// Runtime view over the RAM descriptor section in the mmap.
///
/// Provides bit-level access to the hole bitmap. All bit operations use atomic
/// loads/stores for thread safety (balloon reclaim runs on the device thread).
pub struct RamDescriptorView<'m> {
    bitmap: *mut u8,
    block_count: u32,
    _memory: PhantomData<&'m UnsafeCell<[u8]>>,
}

// SAFETY: The underlying memory is mmap'd VM state protected by higher-level
// synchronization (device mutex for balloon, single-threaded freeze scan).
unsafe impl Send for RamDescriptorView<'_> {}
// SAFETY: see `Send` impl above — the same higher-level synchronization
// ensures `&RamDescriptorView` is only shared across threads that cooperate
// via the balloon device mutex / freeze scan.
unsafe impl Sync for RamDescriptorView<'_> {}

impl<'m> RamDescriptorView<'m> {
    /// Validate an initialized RAM descriptor section and return its RAM size.
    ///
    /// This checks the guest-controlled descriptor header before any
    /// [`RamDescriptorView`] is constructed from the region.
    pub fn validate_initialized_region(region: &[u8]) -> Result<RamSize, &'static str> {
        if region.len() < core::mem::size_of::<RamDescriptorHeader>() {
            return Err("RAM descriptor region is smaller than header");
        }
        let hdr: RamDescriptorHeader =
            bytemuck::pod_read_unaligned(&region[..core::mem::size_of::<RamDescriptorHeader>()]);
        if u64::from(hdr.block_size) != BITMAP_BLOCK_SIZE {
            return Err("RAM descriptor block_size is invalid");
        }
        if hdr.block_count == 0 {
            return Err("RAM descriptor block_count is zero");
        }
        if hdr.reserved.iter().any(|&v| v != 0) {
            return Err("RAM descriptor reserved field is nonzero");
        }
        let bytes = u64::from(hdr.block_count)
            .checked_mul(BITMAP_BLOCK_SIZE)
            .ok_or("RAM descriptor ram_size overflow")?;
        let ram_size = RamSize::new(bytes)?;
        let section_size = ram_desc_section_size(ram_size);
        let section_size =
            usize::try_from(section_size).map_err(|_| "RAM descriptor section too large")?;
        if section_size > region.len() {
            return Err("RAM descriptor section extends past region");
        }
        Ok(ram_size)
    }

    /// Initialize the RAM descriptor header. The bitmap is already zeroed by the memfd.
    ///
    /// # Safety
    ///
    /// - `ptr` must point to a region of at least `ram_desc_section_size(ram_size)` bytes.
    /// - The caller must have exclusive setup-time access to the region.
    ///
    /// # Panics
    ///
    /// Panics if `ptr` is not aligned for `RamDescriptorHeader`.
    #[allow(clippy::cast_ptr_alignment, clippy::cast_possible_truncation)]
    pub(crate) unsafe fn init_region(ptr: *mut u8, ram_size: RamSize) {
        assert_eq!(
            ptr.align_offset(align_of::<RamDescriptorHeader>()),
            0,
            "RamDescriptorView::init_region: pointer misaligned for RamDescriptorHeader"
        );
        let hdr = RamDescriptorHeader {
            block_size: BITMAP_BLOCK_SIZE as u32,
            block_count: ram_size.block_count(),
            reserved: [0],
        };
        // SAFETY: caller guarantees setup-time exclusive access to a valid descriptor header.
        unsafe { ptr.cast::<RamDescriptorHeader>().write(hdr) };
    }

    /// Create a runtime bitmap view over the RAM descriptor section.
    ///
    /// # Safety
    ///
    /// - `ptr` must point to a region of at least `ram_desc_section_size(ram_size)` bytes.
    /// - The region must remain mapped for the lifetime of this view.
    ///
    /// # Panics
    ///
    /// Panics if `ptr` is not aligned for `RamDescriptorHeader`.
    #[allow(clippy::cast_ptr_alignment, clippy::cast_possible_truncation)] // align asserted below; block_count ≤ u32
    pub(crate) unsafe fn new(ptr: *mut u8, ram_size: RamSize, _owner: &'m impl ?Sized) -> Self {
        assert_eq!(
            ptr.align_offset(align_of::<RamDescriptorHeader>()),
            0,
            "RamDescriptorView::new: pointer misaligned for RamDescriptorHeader"
        );
        // SAFETY: bounds-checked above (caller guarantees `ptr` points to at least `ram_desc_section_size(ram_size)` bytes); result stays within the backing allocation.
        let bitmap = unsafe { ptr.add(core::mem::size_of::<RamDescriptorHeader>()) };
        let block_count = ram_size.block_count();
        Self {
            bitmap,
            block_count,
            _memory: PhantomData,
        }
    }

    /// Number of blocks tracked by this bitmap.
    #[inline]
    pub const fn block_count(&self) -> u32 {
        self.block_count
    }

    /// RAM size in bytes (`block_count * BITMAP_BLOCK_SIZE`).
    #[inline]
    pub fn ram_size(&self) -> u64 {
        u64::from(self.block_count) * BITMAP_BLOCK_SIZE
    }

    /// Check if a page is marked as a hole.
    #[inline]
    pub fn is_hole(&self, page_idx: u32) -> bool {
        if page_idx >= self.block_count {
            return false;
        }
        let byte_idx = (page_idx / 8) as usize;
        let bit = page_idx % 8;
        // SAFETY: bounds-checked above; result stays within the backing allocation.
        let byte_ptr = unsafe { self.bitmap.add(byte_idx) };
        // SAFETY: `byte_ptr` is within the descriptor's bitmap region (bounds asserted); AtomicU8 layout matches u8.
        let atom = unsafe { &*(byte_ptr as *const AtomicU8) };
        atom.load(Ordering::Relaxed) & (1 << bit) != 0
    }

    /// Mark a page as a hole (set the bit).
    #[inline]
    pub fn mark_hole(&self, page_idx: u32) {
        if page_idx >= self.block_count {
            return;
        }
        let byte_idx = (page_idx / 8) as usize;
        let bit = page_idx % 8;
        // SAFETY: bounds-checked above; result stays within the backing allocation.
        let byte_ptr = unsafe { self.bitmap.add(byte_idx) };
        // SAFETY: `byte_ptr` is within the descriptor's bitmap region (bounds asserted); AtomicU8 layout matches u8.
        let atom = unsafe { &*(byte_ptr as *const AtomicU8) };
        atom.fetch_or(1 << bit, Ordering::Relaxed);
    }

    /// Clear a hole marker (clear the bit).
    #[inline]
    pub fn clear_hole(&self, page_idx: u32) {
        if page_idx >= self.block_count {
            return;
        }
        let byte_idx = (page_idx / 8) as usize;
        let bit = page_idx % 8;
        // SAFETY: bounds-checked above; result stays within the backing allocation.
        let byte_ptr = unsafe { self.bitmap.add(byte_idx) };
        // SAFETY: `byte_ptr` is within the descriptor's bitmap region (bounds asserted); AtomicU8 layout matches u8.
        let atom = unsafe { &*(byte_ptr as *const AtomicU8) };
        atom.fetch_and(!(1 << bit), Ordering::Relaxed);
    }

    /// Iterate over all page indices that are marked as holes.
    #[allow(clippy::cast_possible_truncation)]
    pub fn holes(&self) -> impl Iterator<Item = u32> + '_ {
        let byte_count = self.block_count.div_ceil(8) as usize;
        (0..byte_count).flat_map(move |byte_idx| {
            // SAFETY: bounds-checked above (byte_idx < byte_count derived from block_count); result stays within the backing allocation.
            let byte_ptr = unsafe { self.bitmap.add(byte_idx) };
            // SAFETY: `byte_ptr` is within the descriptor's bitmap region (bounds asserted); AtomicU8 layout matches u8.
            let atom = unsafe { &*(byte_ptr as *const AtomicU8) };
            let byte_val = atom.load(Ordering::Relaxed);
            (0u8..8).filter_map(move |bit| {
                let page_idx = (byte_idx as u32) * 8 + u32::from(bit);
                if page_idx < self.block_count && byte_val & (1 << bit) != 0 {
                    Some(page_idx)
                } else {
                    None
                }
            })
        })
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    fn ram_size(bytes: u64) -> RamSize {
        RamSize::new(bytes).unwrap()
    }

    #[allow(clippy::cast_possible_truncation)]
    fn alloc_section(ram_size: RamSize) -> Vec<u8> {
        vec![0u8; ram_desc_section_size(ram_size) as usize]
    }

    #[test]
    fn header_size() {
        assert_eq!(core::mem::size_of::<RamDescriptorHeader>(), 16);
    }

    #[test]
    fn bitmap_byte_len_basic() {
        let bs = BITMAP_BLOCK_SIZE;
        // 1 block → 1 bit → 1 byte
        assert_eq!(bitmap_byte_len(ram_size(bs)), 1);
        // 8 blocks → 8 bits → 1 byte
        assert_eq!(bitmap_byte_len(ram_size(bs * 8)), 1);
        // 9 blocks → 9 bits → 2 bytes
        assert_eq!(bitmap_byte_len(ram_size(bs * 9)), 2);
        // 256 MB → 128 blocks (at 2M) → 16 bytes
        assert_eq!(
            bitmap_byte_len(ram_size(256 * 1024 * 1024)),
            256 * 1024 * 1024 / bs / 8
        );
    }

    #[test]
    fn section_size_is_page_aligned() {
        for &ram_mb in &[2, 4, 128, 256, 1024] {
            let bytes = ram_mb * 1024 * 1024;
            let section = ram_desc_section_size(ram_size(bytes));
            assert_eq!(section % PAGE_SIZE as u64, 0, "not aligned for {ram_mb}MB");
        }
    }

    #[test]
    fn ram_size_rejects_unrepresentable_descriptor_sizes() {
        assert_eq!(RamSize::new(0), Err("RAM size is zero"));
        assert_eq!(
            RamSize::new(BITMAP_BLOCK_SIZE + 4096),
            Err("RAM size is not a descriptor block multiple"),
        );
        assert_eq!(
            RamSize::new((u64::from(u32::MAX) + 1) * BITMAP_BLOCK_SIZE),
            Err("RAM descriptor block_count exceeds u32"),
        );
    }

    #[test]
    fn init_writes_header() {
        let bs = BITMAP_BLOCK_SIZE;
        let ram_size = ram_size(bs * 16); // 16 blocks
        let mut buf = alloc_section(ram_size);
        // SAFETY: `buf` points to a buffer of the size computed from
        // `ram_size`, and this test has exclusive setup-time access.
        unsafe { RamDescriptorView::init_region(buf.as_mut_ptr(), ram_size) };

        let hdr: RamDescriptorHeader =
            bytemuck::pod_read_unaligned(&buf[..core::mem::size_of::<RamDescriptorHeader>()]);
        assert_eq!(u64::from(hdr.block_size), bs);
        assert_eq!(hdr.block_count, 16);
    }

    #[test]
    fn mark_and_check() {
        let ram_size = ram_size(BITMAP_BLOCK_SIZE * 64); // 64 blocks
        let mut buf = alloc_section(ram_size);
        // SAFETY: `buf` points to a buffer of the size computed from `ram_size`; single exclusive view.
        let view = unsafe { RamDescriptorView::new(buf.as_mut_ptr(), ram_size, &buf) };

        assert!(!view.is_hole(0));
        assert!(!view.is_hole(63));

        view.mark_hole(0);
        view.mark_hole(7);
        view.mark_hole(8);
        view.mark_hole(63);

        assert!(view.is_hole(0));
        assert!(view.is_hole(7));
        assert!(view.is_hole(8));
        assert!(view.is_hole(63));
        assert!(!view.is_hole(1));
        assert!(!view.is_hole(62));
    }

    #[test]
    fn clear_hole() {
        let ram_size = ram_size(BITMAP_BLOCK_SIZE * 16);
        let mut buf = alloc_section(ram_size);
        // SAFETY: `buf` points to a buffer of the size computed from `ram_size`; single exclusive view.
        let view = unsafe { RamDescriptorView::new(buf.as_mut_ptr(), ram_size, &buf) };

        view.mark_hole(5);
        assert!(view.is_hole(5));

        view.clear_hole(5);
        assert!(!view.is_hole(5));
    }

    #[test]
    fn holes_iterator() {
        let ram_size = ram_size(BITMAP_BLOCK_SIZE * 32);
        let mut buf = alloc_section(ram_size);
        // SAFETY: `buf` points to a buffer of the size computed from `ram_size`; single exclusive view.
        let view = unsafe { RamDescriptorView::new(buf.as_mut_ptr(), ram_size, &buf) };

        view.mark_hole(1);
        view.mark_hole(10);
        view.mark_hole(31);

        let holes: Vec<u32> = view.holes().collect();
        assert_eq!(holes, vec![1, 10, 31]);
    }

    #[test]
    fn is_zero_all_zero() {
        let page = vec![0u8; 4096];
        assert!(is_zero(&page));
    }

    #[test]
    fn is_zero_first_byte_nonzero() {
        let mut page = vec![0u8; 4096];
        page[0] = 1;
        assert!(!is_zero(&page));
    }

    #[test]
    fn is_zero_last_byte_nonzero() {
        let mut page = vec![0u8; 4096];
        page[4095] = 0xFF;
        assert!(!is_zero(&page));
    }

    #[test]
    fn is_zero_middle_nonzero() {
        let mut page = vec![0u8; 4096];
        page[2048] = 42;
        assert!(!is_zero(&page));
    }

    #[test]
    fn block_count_accessor() {
        let ram_size = ram_size(BITMAP_BLOCK_SIZE * 100);
        let mut buf = alloc_section(ram_size);
        // SAFETY: `buf` points to a buffer of the size computed from `ram_size`; single exclusive view.
        let view = unsafe { RamDescriptorView::new(buf.as_mut_ptr(), ram_size, &buf) };
        assert_eq!(view.block_count(), 100);
    }

    #[test]
    fn validate_initialized_region_rejects_bad_header() {
        let mut buf = alloc_section(ram_size(BITMAP_BLOCK_SIZE));
        assert_eq!(
            RamDescriptorView::validate_initialized_region(&buf),
            Err("RAM descriptor block_size is invalid")
        );

        let hdr = RamDescriptorHeader {
            block_size: u32::try_from(BITMAP_BLOCK_SIZE).unwrap(),
            block_count: 1,
            reserved: [1],
        };
        buf[..core::mem::size_of::<RamDescriptorHeader>()]
            .copy_from_slice(bytemuck::bytes_of(&hdr));
        assert_eq!(
            RamDescriptorView::validate_initialized_region(&buf),
            Err("RAM descriptor reserved field is nonzero")
        );
    }

    #[test]
    fn validate_initialized_region_rejects_truncated_bitmap() {
        let mut buf = vec![0u8; core::mem::size_of::<RamDescriptorHeader>()];
        let hdr = RamDescriptorHeader {
            block_size: u32::try_from(BITMAP_BLOCK_SIZE).unwrap(),
            block_count: 1,
            reserved: [0],
        };
        buf.copy_from_slice(bytemuck::bytes_of(&hdr));
        assert_eq!(
            RamDescriptorView::validate_initialized_region(&buf),
            Err("RAM descriptor section extends past region")
        );
    }
}
