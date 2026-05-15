// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Guest memory mapping and GPA hole splitting.
//!
//! [`MemoryMapping`] describes how to project a host memory region into the
//! guest physical address space. [`MemoryHole`] defines reserved GPA ranges
//! (MMIO, PCI) that RAM must skip. [`MemoryMapping::split_holes`] takes a
//! set of mappings and splits them around holes — GPA jumps over the hole,
//! the backing memory stays contiguous (no wasted bytes).

use serde::{Deserialize, Serialize};

// =========================================================================
// MemoryMapping — how to map a host region into GPA space
// =========================================================================

/// Source of backing memory for a mapped region.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MapSource {
    /// Backed by a handle at the given index and byte offset.
    Handle {
        /// Index into the handles array passed to `map_memory`.
        index: u32,
        /// Byte offset within the handle.
        offset: u64,
    },
    /// Private anonymous zero-filled mapping.
    AnonymousZero,
}

/// Describes one GPA region to map into the VM.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryMapping {
    /// Where the backing memory comes from.
    pub source: MapSource,
    /// Size of the region in bytes.
    pub size: u64,
    /// Guest physical address to map at.
    pub gpa: u64,
    /// If true, map as read-only in the guest.
    pub readonly: bool,
}

/// Immutable facts about one host backing handle used to validate GPA mappings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingHandleInfo {
    len: usize,
    writable: bool,
}

impl MappingHandleInfo {
    /// Create handle metadata from a byte length and write capability.
    #[must_use]
    pub const fn new(len: usize, writable: bool) -> Self {
        Self { len, writable }
    }

    /// Backing handle length in bytes.
    #[must_use]
    pub const fn byte_len(self) -> usize {
        self.len
    }

    /// Whether writable guest mappings may use this handle.
    #[must_use]
    pub const fn is_writable(self) -> bool {
        self.writable
    }
}

impl From<&amla_mem::MemHandle> for MappingHandleInfo {
    fn from(handle: &amla_mem::MemHandle) -> Self {
        Self::new(handle.size().as_usize(), handle.is_writable())
    }
}

/// Validated source of one guest memory mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidatedMapSource {
    /// Backed by a checked handle index and checked byte offset.
    Handle {
        /// Index into the handle table.
        index: usize,
        /// Original byte offset within the handle.
        offset: u64,
        /// Offset converted to `usize` for host pointer arithmetic.
        offset_usize: usize,
    },
    /// Private anonymous zero-filled mapping.
    AnonymousZero,
}

/// One memory mapping whose GPA interval and host backing have been validated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ValidatedMemoryMapping {
    source: ValidatedMapSource,
    gpa: u64,
    end: u64,
    size: u64,
    size_usize: usize,
    readonly: bool,
}

impl ValidatedMemoryMapping {
    /// Validated backing source.
    #[must_use]
    pub const fn source(self) -> ValidatedMapSource {
        self.source
    }

    /// Guest physical start address.
    #[must_use]
    pub const fn gpa(self) -> u64 {
        self.gpa
    }

    /// Exclusive guest physical end address.
    #[must_use]
    pub const fn end(self) -> u64 {
        self.end
    }

    /// Mapping size in bytes.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    /// Mapping size converted to `usize` for host APIs.
    #[must_use]
    pub const fn size_usize(self) -> usize {
        self.size_usize
    }

    /// Whether the guest mapping must be read-only.
    #[must_use]
    pub const fn readonly(self) -> bool {
        self.readonly
    }
}

/// Proof that a batch of memory mappings is canonical for a handle table.
#[derive(Debug, Clone)]
pub struct ValidatedMemoryMappings<'a> {
    raw: &'a [MemoryMapping],
    entries: Vec<ValidatedMemoryMapping>,
}

impl<'a> ValidatedMemoryMappings<'a> {
    /// Validate guest GPA mappings against host backing handles.
    ///
    /// The token rejects zero-length mappings, unaligned GPA ranges, GPA
    /// overlap, invalid handle indices, unaligned backing offsets, integer
    /// conversion overflow, handle-range overflow, and writable mappings from
    /// read-only handles.
    ///
    /// # Errors
    ///
    /// Returns [`VmmError::DeviceConfig`](super::VmmError::DeviceConfig) or
    /// [`VmmError::AddressOverflow`](super::VmmError::AddressOverflow) when
    /// any mapping is not canonical for the supplied handle table.
    pub fn new(
        raw: &'a [MemoryMapping],
        handles: &[MappingHandleInfo],
    ) -> Result<Self, super::VmmError> {
        let mut entries = Vec::with_capacity(raw.len());
        for mapping in raw {
            entries.push(validate_memory_mapping(mapping, handles)?);
        }
        validate_memory_mapping_overlaps(&entries)?;
        Ok(Self { raw, entries })
    }

    /// Original raw mapping slice that this token validates.
    #[must_use]
    pub const fn raw(&self) -> &'a [MemoryMapping] {
        self.raw
    }

    /// Validated and resolved mapping entries.
    #[must_use]
    pub fn entries(&self) -> &[ValidatedMemoryMapping] {
        &self.entries
    }

    /// Number of validated mappings.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no mappings were supplied.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

impl MemoryMapping {
    /// Split mappings around memory holes.
    ///
    /// Any mapping that overlaps a hole is split into the part before the
    /// hole and the part after. The GPA jumps over the hole; the backing
    /// offset stays contiguous. Mappings that don't overlap any hole pass
    /// through unchanged.
    ///
    /// Returns an error if any mapping starts inside a hole (a caller bug).
    ///
    /// This function is **idempotent**: calling it again with the same
    /// holes produces an identical result (already-split mappings don't
    /// overlap holes, so they pass through unchanged).
    pub fn split_holes(
        mappings: &[Self],
        holes: MemoryHoles<'_>,
    ) -> Result<Vec<Self>, super::VmmError> {
        let mut result = Vec::with_capacity(mappings.len());
        for m in mappings {
            split_one(*m, holes.as_slice(), &mut result)?;
        }
        Ok(result)
    }
}

fn validate_memory_mapping(
    mapping: &MemoryMapping,
    handles: &[MappingHandleInfo],
) -> Result<ValidatedMemoryMapping, super::VmmError> {
    if mapping.size == 0 {
        return Err(super::VmmError::DeviceConfig(format!(
            "zero-sized memory mapping at GPA {:#x}",
            mapping.gpa
        )));
    }

    let page_size = crate::vm_state::pfn::GUEST_PAGE_SIZE;
    if !mapping.gpa.is_multiple_of(page_size) {
        return Err(super::VmmError::DeviceConfig(format!(
            "mapping GPA {:#x} is not guest-page-aligned",
            mapping.gpa
        )));
    }
    if !mapping.size.is_multiple_of(page_size) {
        return Err(super::VmmError::DeviceConfig(format!(
            "mapping size {:#x} at GPA {:#x} is not guest-page-aligned",
            mapping.size, mapping.gpa
        )));
    }

    let end = checked_interval_end(mapping.gpa, mapping.size)?;
    let size_usize = usize::try_from(mapping.size).map_err(|_| {
        super::VmmError::DeviceConfig(format!(
            "mapping size {:#x} exceeds usize at GPA {:#x}",
            mapping.size, mapping.gpa
        ))
    })?;

    let source = match mapping.source {
        MapSource::Handle { index, offset } => {
            let index = usize::try_from(index).map_err(|_| {
                super::VmmError::DeviceConfig(format!("handle index {index} exceeds usize"))
            })?;
            let handle = handles.get(index).ok_or_else(|| {
                super::VmmError::DeviceConfig(format!("handle index {index} out of range"))
            })?;
            if !offset.is_multiple_of(page_size) {
                return Err(super::VmmError::DeviceConfig(format!(
                    "handle offset {offset:#x} for GPA {:#x} is not guest-page-aligned",
                    mapping.gpa
                )));
            }
            if !mapping.readonly && !handle.is_writable() {
                return Err(super::VmmError::DeviceConfig(format!(
                    "mapping at GPA {:#x} is writable but handle {index} is read-only",
                    mapping.gpa
                )));
            }
            let offset_usize = usize::try_from(offset).map_err(|_| {
                super::VmmError::DeviceConfig(format!(
                    "handle offset {offset:#x} exceeds usize for mapping at GPA {:#x}",
                    mapping.gpa
                ))
            })?;
            let backing_end = offset_usize.checked_add(size_usize).ok_or_else(|| {
                super::VmmError::DeviceConfig(format!(
                    "handle offset + mapping size overflows at GPA {:#x}",
                    mapping.gpa
                ))
            })?;
            if backing_end > handle.byte_len() {
                return Err(super::VmmError::DeviceConfig(format!(
                    "mapping at GPA {:#x}: offset {offset:#x} + size {:#x} exceeds handle size {:#x}",
                    mapping.gpa,
                    mapping.size,
                    handle.byte_len()
                )));
            }
            ValidatedMapSource::Handle {
                index,
                offset,
                offset_usize,
            }
        }
        MapSource::AnonymousZero => ValidatedMapSource::AnonymousZero,
    };

    Ok(ValidatedMemoryMapping {
        source,
        gpa: mapping.gpa,
        end,
        size: mapping.size,
        size_usize,
        readonly: mapping.readonly,
    })
}

fn validate_memory_mapping_overlaps(
    entries: &[ValidatedMemoryMapping],
) -> Result<(), super::VmmError> {
    for (i, left) in entries.iter().enumerate() {
        for right in entries.iter().skip(i + 1) {
            if left.gpa() < right.end() && right.gpa() < left.end() {
                return Err(super::VmmError::DeviceConfig(format!(
                    "overlapping memory mappings at GPA {:#x}..{:#x} and {:#x}..{:#x}",
                    left.gpa(),
                    left.end(),
                    right.gpa(),
                    right.end()
                )));
            }
        }
    }
    Ok(())
}

/// Split a single mapping around all holes.
fn split_one(
    m: MemoryMapping,
    holes: &[MemoryHole],
    out: &mut Vec<MemoryMapping>,
) -> Result<(), super::VmmError> {
    let mut end = checked_interval_end(m.gpa, m.size)?;

    let MapSource::Handle {
        index,
        offset: base_offset,
    } = m.source
    else {
        // Anonymous mappings don't have a backing offset to stay contiguous
        // across a hole, so we refuse to split them. The caller must place
        // anonymous regions outside every hole.
        for hole in holes {
            let overlaps = hole.start < end && hole.end > m.gpa;
            if overlaps {
                return Err(super::VmmError::DeviceConfig(format!(
                    "anonymous mapping [{:#x}, {:#x}) overlaps hole [{:#x}, {:#x})",
                    m.gpa, end, hole.start, hole.end,
                )));
            }
        }
        out.push(m);
        return Ok(());
    };

    let mut gpa = m.gpa;
    let mut offset = base_offset;
    let mut remaining = m.size;

    for hole in holes {
        if remaining == 0 || hole.end <= gpa {
            continue;
        }
        end = checked_interval_end(gpa, remaining)?;
        if hole.start >= end {
            break;
        }

        // Reject mappings that start inside a hole.
        if gpa >= hole.start {
            return Err(super::VmmError::DeviceConfig(format!(
                "mapping at GPA {gpa:#x} starts inside hole [{:#x}, {:#x})",
                hole.start, hole.end,
            )));
        }

        // Emit the part before the hole.
        let before = (hole.start - gpa).min(remaining);
        out.push(MemoryMapping {
            source: MapSource::Handle { index, offset },
            size: before,
            gpa,
            readonly: m.readonly,
        });
        offset = offset.checked_add(before).ok_or_else(|| {
            super::VmmError::DeviceConfig(format!(
                "mapping backing offset overflow: {offset:#x} + {before:#x}"
            ))
        })?;
        remaining -= before;

        if remaining == 0 {
            break;
        }

        // GPA jumps over the hole; backing offset stays contiguous.
        gpa = hole.end;
    }

    if remaining > 0 {
        out.push(MemoryMapping {
            source: MapSource::Handle { index, offset },
            size: remaining,
            gpa,
            readonly: m.readonly,
        });
    }
    Ok(())
}

fn validate_hole(hole: MemoryHole) -> Result<(), super::VmmError> {
    if hole.start >= hole.end {
        return Err(super::VmmError::DeviceConfig(format!(
            "invalid memory hole [{:#x}, {:#x})",
            hole.start, hole.end,
        )));
    }
    Ok(())
}

fn checked_interval_end(gpa: u64, size: u64) -> Result<u64, super::VmmError> {
    let size_for_error = usize::try_from(size).unwrap_or(usize::MAX);
    gpa.checked_add(size)
        .ok_or(super::VmmError::AddressOverflow {
            addr: gpa,
            size: size_for_error,
        })
}

// =========================================================================
// MemoryHole — reserved GPA ranges
// =========================================================================

/// A reserved GPA range that guest RAM must not occupy.
///
/// When RAM mappings overlap a hole, [`MemoryMapping::split_holes`] splits
/// them: the GPA jumps over the hole, the backing memory stays contiguous.
#[derive(Debug, Clone, Copy)]
pub struct MemoryHole {
    /// Start of the reserved range (inclusive).
    pub start: u64,
    /// End of the reserved range (exclusive).
    pub end: u64,
    /// Whether to advertise this hole to the guest as `E820_TYPE_RESERVED`.
    ///
    /// - `true`: emit an e820 "reserved" entry (e.g. virtio-mmio device
    ///   range — tells the kernel not to treat these addresses as RAM).
    /// - `false`: omit from e820 entirely (e.g. the 32-bit PCI MMIO hole —
    ///   a "reserved" entry there prevents the kernel from allocating
    ///   PCI BARs in that range, triggering `Cannot find an available
    ///   gap in the 32-bit address range`. Leaving the range unadvertised
    ///   makes the kernel treat it as "not RAM, available for MMIO").
    pub advertise_reserved: bool,
}

/// Reserved GPA ranges validated for sorted, non-overlapping order.
#[derive(Debug, Clone, Copy)]
pub struct MemoryHoles<'a> {
    holes: &'a [MemoryHole],
}

impl<'a> MemoryHoles<'a> {
    /// No reserved GPA ranges.
    pub const EMPTY: Self = Self { holes: &[] };

    /// Validate reserved GPA ranges.
    ///
    /// # Errors
    ///
    /// Returns [`VmmError::DeviceConfig`](super::VmmError::DeviceConfig) when
    /// any hole is empty, inverted, unsorted, or overlaps the previous hole.
    pub fn new(holes: &'a [MemoryHole]) -> Result<Self, super::VmmError> {
        validate_holes(holes)?;
        Ok(Self { holes })
    }

    /// Create a hole proof for a statically audited table.
    ///
    /// # Safety
    ///
    /// `holes` must be sorted by `start`, contain only non-empty ranges, and
    /// have no overlapping ranges.
    pub const unsafe fn new_unchecked(holes: &'a [MemoryHole]) -> Self {
        Self { holes }
    }

    /// Return the validated holes as a slice.
    #[must_use]
    pub const fn as_slice(self) -> &'a [MemoryHole] {
        self.holes
    }
}

fn validate_holes(holes: &[MemoryHole]) -> Result<(), super::VmmError> {
    let mut previous_end = None;
    for &hole in holes {
        validate_hole(hole)?;
        if let Some(end) = previous_end
            && hole.start < end
        {
            return Err(super::VmmError::DeviceConfig(format!(
                "memory holes are not sorted and non-overlapping: previous end {end:#x}, next [{:#x}, {:#x})",
                hole.start, hole.end,
            )));
        }
        previous_end = Some(hole.end);
    }
    Ok(())
}

/// Per-architecture memory holes.
#[cfg(target_arch = "x86_64")]
const ARCH_MEMORY_HOLES: &[MemoryHole] = &[
    // virtio-mmio device range — guest must not use as RAM.
    MemoryHole {
        start: 0x0A00_0000,
        end: 0x0A00_8000,
        advertise_reserved: true,
    },
    // 32-bit PCI MMIO hole — reserved from RAM but intentionally *not*
    // marked in e820 so Linux can assign 32-bit PCI BARs here.
    MemoryHole {
        start: 0xE000_0000,
        end: 0x1_0000_0000,
        advertise_reserved: false,
    },
];

/// Per-architecture memory holes.
#[cfg(target_arch = "x86_64")]
// SAFETY: `ARCH_MEMORY_HOLES` is sorted, non-empty, and non-overlapping.
pub const MEMORY_HOLES: MemoryHoles<'static> =
    unsafe { MemoryHoles::new_unchecked(ARCH_MEMORY_HOLES) };

/// Per-architecture memory holes.
#[cfg(target_arch = "aarch64")]
pub const MEMORY_HOLES: MemoryHoles<'static> = MemoryHoles::EMPTY;

/// Per-architecture memory holes.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub const MEMORY_HOLES: MemoryHoles<'static> = MemoryHoles::EMPTY;

#[cfg(test)]
mod tests {
    use super::*;

    fn hole(start: u64, end: u64) -> MemoryHole {
        MemoryHole {
            start,
            end,
            advertise_reserved: true,
        }
    }

    fn handle_mapping(gpa: u64, size: u64, offset: u64) -> MemoryMapping {
        MemoryMapping {
            source: MapSource::Handle { index: 0, offset },
            size,
            gpa,
            readonly: false,
        }
    }

    fn memory_holes(holes: &[MemoryHole]) -> MemoryHoles<'_> {
        MemoryHoles::new(holes).unwrap()
    }

    fn writable_handle(len: usize) -> MappingHandleInfo {
        MappingHandleInfo::new(len, true)
    }

    fn readonly_handle(len: usize) -> MappingHandleInfo {
        MappingHandleInfo::new(len, false)
    }

    #[test]
    fn validated_mappings_resolve_handle_indices_and_sizes() {
        let mappings = [
            handle_mapping(0, 0x1000, 0),
            MemoryMapping {
                source: MapSource::AnonymousZero,
                size: 0x1000,
                gpa: 0x2000,
                readonly: false,
            },
        ];
        let handles = [writable_handle(0x4000)];
        let validated = ValidatedMemoryMappings::new(&mappings, &handles).unwrap();

        assert_eq!(validated.raw().len(), 2);
        assert_eq!(validated.len(), 2);
        assert_eq!(validated.entries()[0].gpa(), 0);
        assert_eq!(validated.entries()[0].end(), 0x1000);
        assert_eq!(validated.entries()[0].size_usize(), 0x1000);
        assert!(matches!(
            validated.entries()[0].source(),
            ValidatedMapSource::Handle {
                index: 0,
                offset: 0,
                offset_usize: 0
            }
        ));
        assert_eq!(
            validated.entries()[1].source(),
            ValidatedMapSource::AnonymousZero
        );
    }

    #[test]
    fn validated_mappings_reject_overlapping_gpa_ranges() {
        let mappings = [
            handle_mapping(0, 0x2000, 0),
            MemoryMapping {
                source: MapSource::AnonymousZero,
                size: 0x1000,
                gpa: 0x1000,
                readonly: false,
            },
        ];
        let err = ValidatedMemoryMappings::new(&mappings, &[writable_handle(0x4000)]).unwrap_err();
        assert!(format!("{err}").contains("overlapping"), "{err}");
    }

    #[test]
    fn validated_mappings_reject_writable_mapping_from_readonly_handle() {
        let mappings = [handle_mapping(0, 0x1000, 0)];
        let err = ValidatedMemoryMappings::new(&mappings, &[readonly_handle(0x4000)]).unwrap_err();
        assert!(format!("{err}").contains("read-only"), "{err}");
    }

    #[test]
    fn validated_mappings_reject_out_of_bounds_handle_range() {
        let mappings = [handle_mapping(0, 0x2000, 0x3000)];
        let err = ValidatedMemoryMappings::new(&mappings, &[writable_handle(0x4000)]).unwrap_err();
        assert!(format!("{err}").contains("exceeds handle size"), "{err}");
    }

    #[test]
    fn validated_mappings_reject_unaligned_backing_offset() {
        let mappings = [handle_mapping(0, 0x1000, 1)];
        let err = ValidatedMemoryMappings::new(&mappings, &[writable_handle(0x4000)]).unwrap_err();
        assert!(format!("{err}").contains("guest-page-aligned"), "{err}");
    }

    #[test]
    fn memory_holes_reject_unsorted_or_overlapping_ranges() {
        let unsorted = [hole(0x2000, 0x3000), hole(0x1000, 0x1800)];
        let err = MemoryHoles::new(&unsorted).unwrap_err();
        assert!(format!("{err}").contains("not sorted"), "{err}");

        let overlapping = [hole(0x1000, 0x3000), hole(0x2000, 0x4000)];
        let err = MemoryHoles::new(&overlapping).unwrap_err();
        assert!(format!("{err}").contains("not sorted"), "{err}");
    }

    #[test]
    fn memory_holes_reject_empty_ranges() {
        let err = MemoryHoles::new(&[hole(0x1000, 0x1000)]).unwrap_err();
        assert!(format!("{err}").contains("invalid memory hole"), "{err}");
    }

    #[test]
    fn no_holes_passthrough() {
        let m = handle_mapping(0, 0x1000, 0);
        let result = MemoryMapping::split_holes(&[m], MemoryHoles::EMPTY).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].gpa, 0);
        assert_eq!(result[0].size, 0x1000);
    }

    #[test]
    fn split_around_one_hole() {
        let m = handle_mapping(0, 0x2_0000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        assert_eq!(result.len(), 2);
        // Before hole: [0, 0x8000)
        assert_eq!(result[0].gpa, 0);
        assert_eq!(result[0].size, 0x8000);
        // After hole: GPA jumps to 0x1_0000, offset stays contiguous at 0x8000
        assert_eq!(result[1].gpa, 0x1_0000);
        assert_eq!(result[1].size, 0x2_0000 - 0x8000);
        let MapSource::Handle { offset, .. } = result[1].source else {
            unreachable!();
        };
        assert_eq!(offset, 0x8000);
    }

    #[test]
    fn mapping_before_hole_untouched() {
        let m = handle_mapping(0, 0x4000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].gpa, 0);
        assert_eq!(result[0].size, 0x4000);
    }

    #[test]
    fn mapping_after_hole_untouched() {
        let m = handle_mapping(0x2_0000, 0x1000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].gpa, 0x2_0000);
    }

    #[test]
    fn mapping_inside_hole_is_error() {
        let m = handle_mapping(0x9000, 0x1000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes));
        assert!(result.is_err());
        let msg = format!("{}", result.unwrap_err());
        assert!(msg.contains("starts inside hole"), "got: {msg}");
    }

    #[test]
    fn mapping_at_hole_start_is_error() {
        let m = handle_mapping(0x8000, 0x1000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes));
        assert!(result.is_err());
    }

    #[test]
    fn split_around_two_holes() {
        // 4 GiB mapping split by x86_64 holes
        let m = handle_mapping(0, 0x1_0000_0000, 0);
        let holes = [
            hole(0x0A00_0000, 0x0A00_8000),
            hole(0xE000_0000, 0x1_0000_0000),
        ];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        assert_eq!(result.len(), 3);
        // [0, 0x0A00_0000)
        assert_eq!(result[0].gpa, 0);
        assert_eq!(result[0].size, 0x0A00_0000);
        // [0x0A00_8000, 0xE000_0000) — GPA jumped over hole 1
        assert_eq!(result[1].gpa, 0x0A00_8000);
        // [0x1_0000_0000, ...) — GPA jumped over hole 2
        assert_eq!(result[2].gpa, 0x1_0000_0000);
        // Offsets are contiguous
        let offsets: Vec<u64> = result
            .iter()
            .map(|r| match r.source {
                MapSource::Handle { offset, .. } => offset,
                MapSource::AnonymousZero => 0,
            })
            .collect();
        assert_eq!(offsets[0], 0);
        assert_eq!(offsets[1], 0x0A00_0000);
        assert_eq!(offsets[2], offsets[1] + result[1].size);
    }

    #[test]
    fn anonymous_mapping_outside_holes_passes_through() {
        let m = MemoryMapping {
            source: MapSource::AnonymousZero,
            size: 0x1000,
            gpa: 0x2_0000, // clear of any hole
            readonly: false,
        };
        let holes = [hole(0x8000, 0x1_0000)];
        let result = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn anonymous_mapping_overlapping_hole_is_error() {
        let m = MemoryMapping {
            source: MapSource::AnonymousZero,
            size: 0x1000,
            gpa: 0x9000, // inside a hole
            readonly: false,
        };
        let holes = [hole(0x8000, 0x1_0000)];
        let err = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("anonymous mapping"), "got: {msg}");
    }

    #[test]
    fn mapping_end_overflow_is_error() {
        let m = handle_mapping(u64::MAX - 0xff, 0x200, 0);
        let err = MemoryMapping::split_holes(&[m], MemoryHoles::EMPTY).unwrap_err();
        assert!(matches!(
            err,
            super::super::VmmError::AddressOverflow { .. }
        ));
    }

    #[test]
    fn anonymous_mapping_end_overflow_is_error() {
        let m = MemoryMapping {
            source: MapSource::AnonymousZero,
            size: 0x200,
            gpa: u64::MAX - 0xff,
            readonly: false,
        };
        let err = MemoryMapping::split_holes(&[m], MemoryHoles::EMPTY).unwrap_err();
        assert!(matches!(
            err,
            super::super::VmmError::AddressOverflow { .. }
        ));
    }

    #[test]
    fn backing_offset_overflow_is_error() {
        let m = handle_mapping(0, 0x200, u64::MAX - 0x7f);
        let holes = [hole(0x100, 0x200)];
        let err = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("backing offset overflow"), "got: {msg}");
    }

    #[test]
    fn idempotent() {
        let m = handle_mapping(0, 0x2_0000, 0);
        let holes = [hole(0x8000, 0x1_0000)];
        let first = MemoryMapping::split_holes(&[m], memory_holes(&holes)).unwrap();
        let second = MemoryMapping::split_holes(&first, memory_holes(&holes)).unwrap();
        assert_eq!(first.len(), second.len());
        for (a, b) in first.iter().zip(second.iter()) {
            assert_eq!(a.gpa, b.gpa);
            assert_eq!(a.size, b.size);
        }
    }
}
