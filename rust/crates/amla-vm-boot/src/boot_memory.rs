// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Typed guest-memory layout and translated boot writes.

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-boot requires a 64-bit host");

#[cfg(any(target_arch = "aarch64", test))]
use std::marker::PhantomData;
#[cfg(any(target_arch = "aarch64", test))]
use std::ptr::NonNull;

use thiserror::Error;

const PAGE_4K: u64 = 4096;

/// Errors raised by architecture-neutral boot-memory validation and writes.
#[derive(Debug, Error)]
pub enum BootMemoryError {
    /// Boot setup attempted to write outside the mapped RAM backing.
    #[error("guest memory write at offset {offset:#x} len {len} exceeds memory size {mem_size:#x}")]
    GuestMemoryOutOfBounds {
        /// RAM backing offset of the attempted write.
        offset: u64,
        /// Number of bytes in the attempted write.
        len: usize,
        /// Total mapped RAM backing size.
        mem_size: usize,
    },

    /// Guest range construction overflowed.
    #[error("guest range at {start:#x} len {len} overflows")]
    GuestRangeOverflow {
        /// Start of the requested guest range.
        start: u64,
        /// Length of the requested range.
        len: usize,
    },

    /// Guest range is not backed by a single RAM segment.
    #[error("guest range [{start:#x}..+{len:#x}) is not mapped as contiguous RAM")]
    GuestRangeUnmapped {
        /// Start of the requested guest range.
        start: u64,
        /// Length of the requested range.
        len: usize,
    },

    /// Boot-memory validation failed.
    #[error("invalid boot memory: {reason}")]
    InvalidBootMemory {
        /// Validation failure details.
        reason: String,
    },

    /// A guest address does not fit in a boot-protocol field.
    #[error("boot address field {field} value {value:#x} exceeds limit {limit:#x}")]
    BootAddressTooLarge {
        /// Name of the boot protocol field.
        field: &'static str,
        /// Actual value.
        value: u64,
        /// Field limit.
        limit: u64,
    },

    /// Memory layout error from the VM-state mapping layer.
    #[error("memory layout: {0}")]
    MemoryLayout(#[from] amla_core::VmmError),
}

/// Result type for architecture-neutral boot-memory operations.
pub type Result<T> = std::result::Result<T, BootMemoryError>;

/// Guest physical address: the address space visible to Linux.
#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct GuestPhysAddr(u64);

impl GuestPhysAddr {
    /// Construct a guest physical address from a raw value.
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// Return the raw guest physical address value.
    #[must_use]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Build a checked guest range starting at this address.
    ///
    /// # Errors
    ///
    /// Returns `GuestRangeOverflow` if `self + len`
    /// overflows.
    pub fn range(self, len: usize) -> Result<GuestRange> {
        let len_u64 = u64::try_from(len)
            .map_err(|_| BootMemoryError::GuestRangeOverflow { start: self.0, len })?;
        self.0
            .checked_add(len_u64)
            .ok_or(BootMemoryError::GuestRangeOverflow { start: self.0, len })?;
        Ok(GuestRange { start: self, len })
    }

    /// Convert this address to a Linux boot-protocol `u32` field.
    ///
    /// # Errors
    ///
    /// Returns `BootAddressTooLarge` if the address does
    /// not fit.
    pub fn as_boot_u32(self, field: &'static str) -> Result<u32> {
        u32::try_from(self.0).map_err(|_| BootMemoryError::BootAddressTooLarge {
            field,
            value: self.0,
            limit: u64::from(u32::MAX),
        })
    }

    #[cfg(target_arch = "x86_64")]
    pub(crate) fn checked_add_u64(self, value: u64) -> Result<Self> {
        self.0
            .checked_add(value)
            .map(Self)
            .ok_or(BootMemoryError::GuestRangeOverflow {
                start: self.0,
                len: usize::MAX,
            })
    }
}

/// A checked range in guest physical address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestRange {
    start: GuestPhysAddr,
    len: usize,
}

impl GuestRange {
    /// Start GPA of this range.
    #[must_use]
    pub const fn start(self) -> GuestPhysAddr {
        self.start
    }

    /// Length of this range in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Return true if the range is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Exclusive end GPA of this range.
    ///
    /// # Errors
    ///
    /// Returns `GuestRangeOverflow` if `start + len`
    /// overflows.
    pub fn end(self) -> Result<GuestPhysAddr> {
        let len_u64 = u64::try_from(self.len).map_err(|_| BootMemoryError::GuestRangeOverflow {
            start: self.start.0,
            len: self.len,
        })?;
        self.start.0.checked_add(len_u64).map(GuestPhysAddr).ok_or(
            BootMemoryError::GuestRangeOverflow {
                start: self.start.0,
                len: self.len,
            },
        )
    }
}

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamBackingOffset(usize);

impl RamBackingOffset {
    #[cfg(test)]
    pub(crate) const fn new(value: usize) -> Self {
        Self(value)
    }

    pub(crate) const fn as_usize(self) -> usize {
        self.0
    }

    pub(crate) fn checked_add(self, len: usize) -> Result<Self> {
        self.0
            .checked_add(len)
            .map(Self)
            .ok_or(BootMemoryError::GuestMemoryOutOfBounds {
                offset: self.0 as u64,
                len,
                mem_size: usize::MAX,
            })
    }
}

/// A translated range in the contiguous RAM backing buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamBackingRange {
    offset: RamBackingOffset,
    len: usize,
}

impl RamBackingRange {
    #[cfg(all(test, target_arch = "x86_64"))]
    pub(crate) const fn new_for_test(offset: usize, len: usize) -> Self {
        Self {
            offset: RamBackingOffset(offset),
            len,
        }
    }

    pub(crate) const fn from_parts(offset: RamBackingOffset, len: usize) -> Self {
        Self { offset, len }
    }

    pub(crate) const fn offset(self) -> usize {
        self.offset.as_usize()
    }

    pub(crate) const fn len(self) -> usize {
        self.len
    }
}

/// One contiguous RAM span: guest GPA plus its offset in the RAM backing blob.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RamSegment {
    guest_start: GuestPhysAddr,
    backing_start: RamBackingOffset,
    len: usize,
}

impl RamSegment {
    pub(crate) const fn new(
        guest_start: GuestPhysAddr,
        backing_start: RamBackingOffset,
        len: usize,
    ) -> Self {
        Self {
            guest_start,
            backing_start,
            len,
        }
    }

    /// Guest physical start of this segment.
    #[must_use]
    pub const fn guest_start(self) -> GuestPhysAddr {
        self.guest_start
    }

    /// Segment length in bytes.
    #[must_use]
    pub const fn len(self) -> usize {
        self.len
    }

    /// Return true if the segment is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.len == 0
    }

    /// Exclusive guest physical end of this segment.
    ///
    /// # Errors
    ///
    /// Returns `GuestRangeOverflow` if the segment end
    /// overflows.
    pub fn guest_end(self) -> Result<GuestPhysAddr> {
        self.guest_start.range(self.len)?.end()
    }

    pub(crate) fn backing_end(self) -> Result<RamBackingOffset> {
        self.backing_start.checked_add(self.len)
    }
}

#[derive(Debug, Clone)]
struct MemoryHoleSet {
    holes: Vec<amla_core::MemoryHole>,
}

impl MemoryHoleSet {
    fn new(holes: amla_core::MemoryHoles<'_>) -> Result<Self> {
        for hole in holes.as_slice() {
            if !hole.start.is_multiple_of(PAGE_4K) || !hole.end.is_multiple_of(PAGE_4K) {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "memory hole [{:#x}..{:#x}) is not 4 KiB aligned",
                        hole.start, hole.end
                    ),
                });
            }
        }
        Ok(Self {
            holes: holes.as_slice().to_vec(),
        })
    }

    fn as_slice(&self) -> &[amla_core::MemoryHole] {
        &self.holes
    }

    fn as_memory_holes(&self) -> amla_core::MemoryHoles<'_> {
        // SAFETY: `MemoryHoleSet::new` only stores an already validated
        // `MemoryHoles` slice and preserves its order exactly.
        unsafe { amla_core::MemoryHoles::new_unchecked(&self.holes) }
    }
}

/// Validated RAM layout used by boot-memory writers.
#[derive(Debug, Clone)]
pub struct BootRamLayout {
    guest_base: GuestPhysAddr,
    backing_len: usize,
    segments: Vec<RamSegment>,
    holes: MemoryHoleSet,
}

impl BootRamLayout {
    /// Build a layout from contiguous RAM backing and architecture holes.
    ///
    /// # Errors
    ///
    /// Returns a layout error if hole splitting fails, or if the resulting
    /// layout does not describe one contiguous backing blob split only by the
    /// supplied holes.
    pub fn from_ram(
        guest_base: GuestPhysAddr,
        ram_size: usize,
        holes: amla_core::MemoryHoles<'_>,
    ) -> Result<Self> {
        let holes = MemoryHoleSet::new(holes)?;
        let size = u64::try_from(ram_size).map_err(|_| BootMemoryError::InvalidBootMemory {
            reason: format!("RAM size {ram_size:#x} does not fit u64"),
        })?;
        let ram = amla_core::MemoryMapping {
            source: amla_core::MapSource::Handle {
                index: 0,
                offset: 0,
            },
            size,
            gpa: guest_base.as_u64(),
            readonly: false,
        };
        let split = amla_core::MemoryMapping::split_holes(&[ram], holes.as_memory_holes())?;
        let mut segments = Vec::with_capacity(split.len());
        for mapping in split {
            let amla_core::MapSource::Handle { offset, .. } = mapping.source else {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: "RAM layout split produced anonymous backing".into(),
                });
            };
            let backing_start =
                usize::try_from(offset).map_err(|_| BootMemoryError::InvalidBootMemory {
                    reason: format!("RAM backing offset {offset:#x} does not fit usize"),
                })?;
            let len =
                usize::try_from(mapping.size).map_err(|_| BootMemoryError::InvalidBootMemory {
                    reason: format!("RAM segment size {:#x} does not fit usize", mapping.size),
                })?;
            if len == 0 {
                continue;
            }
            segments.push(RamSegment::new(
                GuestPhysAddr(mapping.gpa),
                RamBackingOffset(backing_start),
                len,
            ));
        }

        let layout = Self {
            guest_base,
            backing_len: ram_size,
            segments,
            holes,
        };
        layout.validate_segments()?;
        layout.validate_declared_holes_match_gaps()?;
        Ok(layout)
    }

    /// Build a boot RAM layout from the guest-memory mappings in `VmState`.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the `VmState` RAM mappings do not describe a
    /// contiguous RAM backing blob split only by the supplied architecture
    /// holes.
    pub fn from_vm_state(
        view: &amla_core::vm_state::VmState<'_>,
        holes: amla_core::MemoryHoles<'_>,
    ) -> Result<Self> {
        let header = view.header();
        let ram_offset = header.ram_offset;
        let ram_size =
            usize::try_from(header.ram_size).map_err(|_| BootMemoryError::InvalidBootMemory {
                reason: format!("ram_size {:#x} does not fit usize", header.ram_size),
            })?;
        let ram_end = ram_offset.checked_add(header.ram_size).ok_or_else(|| {
            BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "ram_offset {:#x} + ram_size {:#x} overflows",
                    header.ram_offset, header.ram_size
                ),
            }
        })?;
        let holes = MemoryHoleSet::new(holes)?;
        let mut segments = Vec::with_capacity(view.guest_region_count());

        for mapping in view.guest_memory_mappings() {
            let amla_core::MapSource::Handle { index, offset } = mapping.source else {
                continue;
            };
            let mapping_end = offset.checked_add(mapping.size).ok_or_else(|| {
                BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "guest memory mapping source [{offset:#x}..+{:#x}) overflows",
                        mapping.size
                    ),
                }
            })?;
            let overlaps_ram = offset < ram_end && mapping_end > ram_offset;
            if index != 0 || !overlaps_ram {
                continue;
            }
            if mapping.readonly {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: format!("RAM mapping at GPA {:#x} is read-only", mapping.gpa),
                });
            }
            if offset < ram_offset || mapping_end > ram_end {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "RAM mapping source [{offset:#x}..{mapping_end:#x}) is not contained in \
                         header RAM [{ram_offset:#x}..{ram_end:#x})",
                    ),
                });
            }

            let backing_start = usize::try_from(offset - ram_offset).map_err(|_| {
                BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "RAM mapping source offset {offset:#x} relative to {ram_offset:#x} \
                         does not fit usize",
                    ),
                }
            })?;
            let len =
                usize::try_from(mapping.size).map_err(|_| BootMemoryError::InvalidBootMemory {
                    reason: format!("RAM mapping size {:#x} does not fit usize", mapping.size),
                })?;
            if len == 0 {
                continue;
            }
            segments.push(RamSegment::new(
                GuestPhysAddr(mapping.gpa),
                RamBackingOffset(backing_start),
                len,
            ));
        }

        let guest_base = segments
            .first()
            .copied()
            .map_or(GuestPhysAddr(0), |segment| segment.guest_start);
        let layout = Self {
            guest_base,
            backing_len: ram_size,
            segments,
            holes,
        };
        layout.validate_segments()?;
        layout.validate_declared_holes_match_gaps()?;
        Ok(layout)
    }

    /// Translate a guest range to a contiguous RAM backing range.
    ///
    /// # Errors
    ///
    /// Returns `GuestRangeUnmapped` if the range is not
    /// fully contained in a single RAM segment.
    pub fn translate(&self, range: GuestRange) -> Result<RamBackingRange> {
        let start = range.start().as_u64();
        let end = range.end()?.as_u64();

        for seg in &self.segments {
            let seg_start = seg.guest_start.as_u64();
            let seg_end = seg.guest_end()?.as_u64();
            let contains_empty = range.is_empty() && start >= seg_start && start <= seg_end;
            let contains_nonempty = !range.is_empty() && start >= seg_start && end <= seg_end;
            if contains_empty || contains_nonempty {
                let delta_u64 = start - seg_start;
                let delta =
                    usize::try_from(delta_u64).map_err(|_| BootMemoryError::InvalidBootMemory {
                        reason: format!("guest delta {delta_u64:#x} does not fit usize"),
                    })?;
                return Ok(RamBackingRange::from_parts(
                    seg.backing_start.checked_add(delta)?,
                    range.len(),
                ));
            }
        }

        Err(BootMemoryError::GuestRangeUnmapped {
            start,
            len: range.len(),
        })
    }

    /// Translate a guest start/length pair to a contiguous RAM backing range.
    ///
    /// # Errors
    ///
    /// Returns a range construction or translation error.
    pub fn translate_contiguous(
        &self,
        start: GuestPhysAddr,
        len: usize,
    ) -> Result<RamBackingRange> {
        self.translate(start.range(len)?)
    }

    /// RAM segments in guest-visible order.
    #[must_use]
    pub fn ram_segments(&self) -> &[RamSegment] {
        &self.segments
    }

    /// Architecture holes used to validate this layout.
    #[must_use]
    #[cfg(target_arch = "x86_64")]
    pub(crate) fn holes(&self) -> &[amla_core::MemoryHole] {
        self.holes.as_slice()
    }

    /// Guest base address of the first RAM byte.
    #[must_use]
    #[cfg(any(target_arch = "aarch64", test))]
    pub const fn guest_base(&self) -> GuestPhysAddr {
        self.guest_base
    }

    /// Exclusive end of the last guest-visible RAM segment.
    ///
    /// Returns the base GPA for an empty layout.
    ///
    /// # Errors
    ///
    /// Returns `GuestRangeOverflow` if the last segment end
    /// overflows.
    pub fn last_guest_end(&self) -> Result<GuestPhysAddr> {
        self.segments
            .last()
            .copied()
            .map_or(Ok(self.guest_base), RamSegment::guest_end)
    }

    /// Size of the contiguous RAM backing blob.
    #[must_use]
    pub const fn backing_len(&self) -> usize {
        self.backing_len
    }

    /// Return the only RAM segment, rejecting sparse layouts.
    ///
    /// # Errors
    ///
    /// Returns `InvalidBootMemory` if the layout has zero
    /// or more than one RAM segment.
    #[cfg(any(target_arch = "aarch64", test))]
    pub fn single_ram_segment(&self) -> Result<RamSegment> {
        match self.segments.as_slice() {
            [segment] => Ok(*segment),
            [] => Err(BootMemoryError::InvalidBootMemory {
                reason: "RAM layout has no guest-visible RAM segments".into(),
            }),
            segments => Err(BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "RAM layout has {} segments; this boot path requires contiguous RAM",
                    segments.len()
                ),
            }),
        }
    }

    fn validate_segments(&self) -> Result<()> {
        let mut expected_backing = 0usize;
        let mut prev_guest_end = None;
        for seg in &self.segments {
            if seg.backing_start.as_usize() != expected_backing {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "RAM backing segment starts at {:#x}, expected {expected_backing:#x}",
                        seg.backing_start.as_usize()
                    ),
                });
            }
            if let Some(prev_end) = prev_guest_end
                && seg.guest_start.as_u64() < prev_end
            {
                return Err(BootMemoryError::InvalidBootMemory {
                    reason: "RAM segments are not sorted by guest address".into(),
                });
            }
            expected_backing = seg.backing_end()?.as_usize();
            prev_guest_end = Some(seg.guest_end()?.as_u64());
        }
        if expected_backing != self.backing_len {
            return Err(BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "RAM segments cover {expected_backing:#x} backing bytes, expected {:#x}",
                    self.backing_len
                ),
            });
        }
        Ok(())
    }

    fn validate_declared_holes_match_gaps(&self) -> Result<()> {
        for seg in &self.segments {
            let seg_start = seg.guest_start.as_u64();
            let seg_end = seg.guest_end()?.as_u64();
            for hole in self.holes.as_slice() {
                if hole.start < seg_end && hole.end > seg_start {
                    return Err(BootMemoryError::InvalidBootMemory {
                        reason: format!(
                            "RAM segment [{seg_start:#x}..{seg_end:#x}) overlaps declared hole \
                             [{:#x}..{:#x})",
                            hole.start, hole.end
                        ),
                    });
                }
            }
        }

        for pair in self.segments.windows(2) {
            let gap_start = pair[0].guest_end()?.as_u64();
            let gap_end = pair[1].guest_start.as_u64();
            if gap_start < gap_end {
                self.validate_gap_is_declared(gap_start, gap_end)?;
            }
        }
        Ok(())
    }

    fn validate_gap_is_declared(&self, gap_start: u64, gap_end: u64) -> Result<()> {
        let mut cursor = gap_start;
        for hole in self.holes.as_slice() {
            if hole.end <= cursor {
                continue;
            }
            if hole.start >= gap_end {
                break;
            }
            if hole.start > cursor {
                break;
            }
            cursor = cursor.max(hole.end.min(gap_end));
            if cursor == gap_end {
                return Ok(());
            }
        }

        Err(BootMemoryError::InvalidBootMemory {
            reason: format!(
                "RAM layout gap [{gap_start:#x}..{gap_end:#x}) is not covered by declared holes"
            ),
        })
    }
}

#[derive(Debug, Clone, Copy)]
#[cfg(any(target_arch = "aarch64", test))]
struct BackingSlice {
    offset: usize,
    len: usize,
}

#[cfg(any(target_arch = "aarch64", test))]
struct BootMemWriter {
    base: NonNull<u8>,
    size: usize,
}

#[cfg(any(target_arch = "aarch64", test))]
impl BootMemWriter {
    const unsafe fn new(base: NonNull<u8>, size: usize) -> Self {
        Self { base, size }
    }

    fn write_at(&self, dst: RamBackingRange, data: &[u8]) -> Result<()> {
        if dst.len() != data.len() {
            return Err(BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "backing write length {} does not match range length {}",
                    data.len(),
                    dst.len()
                ),
            });
        }
        let range = self.checked_range(dst.offset(), dst.len())?;
        // SAFETY: `range` proves the destination bytes are within this memory
        // region. `ptr::copy` permits overlap, so callers do not need to prove
        // `data` is disjoint from guest memory.
        unsafe {
            std::ptr::copy(
                data.as_ptr(),
                self.base.as_ptr().add(range.offset),
                range.len,
            );
        }
        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    fn zero_at(&self, dst: RamBackingRange) -> Result<()> {
        let range = self.checked_range(dst.offset(), dst.len())?;
        // SAFETY: `range` proves the destination bytes are within this memory
        // region and `BootGuestMemory` owns exclusive boot-time write access.
        unsafe {
            std::ptr::write_bytes(self.base.as_ptr().add(range.offset), 0, range.len);
        }
        Ok(())
    }

    fn checked_range(&self, offset: usize, len: usize) -> Result<BackingSlice> {
        let end = offset
            .checked_add(len)
            .ok_or(BootMemoryError::GuestMemoryOutOfBounds {
                offset: offset as u64,
                len,
                mem_size: self.size,
            })?;
        if end > self.size {
            return Err(BootMemoryError::GuestMemoryOutOfBounds {
                offset: offset as u64,
                len,
                mem_size: self.size,
            });
        }
        Ok(BackingSlice { offset, len })
    }
}

/// Exclusive, typed access to guest RAM during boot setup.
#[cfg(any(target_arch = "aarch64", test))]
pub struct BootGuestMemory<'a> {
    writer: BootMemWriter,
    layout: BootRamLayout,
    _exclusive: PhantomData<&'a mut [u8]>,
}

#[cfg(any(target_arch = "aarch64", test))]
impl BootGuestMemory<'_> {
    /// Construct boot memory from a raw RAM pointer, backing length, and
    /// validated layout.
    ///
    /// # Safety
    ///
    /// `base` must point to writable memory valid for `len` bytes, and the
    /// caller must ensure no other mutable access aliases this region while
    /// the returned value is alive.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the validated layout does not fit in `len`.
    pub unsafe fn from_raw_parts(
        base: NonNull<u8>,
        len: usize,
        layout: BootRamLayout,
    ) -> Result<Self> {
        if layout.backing_len() > len {
            return Err(BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "RAM backing length {:#x} exceeds mapped length {len:#x}",
                    layout.backing_len()
                ),
            });
        }
        Ok(Self {
            // SAFETY: upheld by the caller of `from_raw_parts`.
            writer: unsafe { BootMemWriter::new(base, len) },
            layout,
            _exclusive: PhantomData,
        })
    }

    /// Borrow the validated RAM layout.
    #[must_use]
    #[cfg(target_arch = "aarch64")]
    pub const fn layout(&self) -> &BootRamLayout {
        &self.layout
    }

    // Reason: writes go through a raw-pointer guest memory writer that
    // the borrow checker can't see; `&mut self` is required to serialize
    // those raw stores against concurrent reads.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn write_guest(&mut self, gpa: GuestPhysAddr, data: &[u8]) -> Result<()> {
        let range = self.layout.translate_contiguous(gpa, data.len())?;
        self.writer.write_at(range, data)
    }

    #[cfg(target_arch = "aarch64")]
    pub(crate) fn zero_guest(&mut self, range: GuestRange) -> Result<()> {
        let backing = self.layout.translate(range)?;
        self.writer.zero_at(backing)
    }
}

#[cfg(target_arch = "aarch64")]
impl<'a> BootGuestMemory<'a> {
    /// Construct boot memory from the validated unified VM-state mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure the RAM portion of `region` is writable and is
    /// not mutably aliased while the returned boot-memory capability is alive.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the RAM range described by `view` is outside
    /// `region`, or if the derived boot layout is invalid.
    pub unsafe fn from_vm_state(
        view: &amla_core::vm_state::VmState<'_>,
        region: &'a amla_mem::MmapSlice,
        holes: amla_core::MemoryHoles<'_>,
    ) -> Result<Self> {
        let header = view.header();
        let ram_offset =
            usize::try_from(header.ram_offset).map_err(|_| BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "ram_offset {:#x} does not fit host address space",
                    header.ram_offset
                ),
            })?;
        let ram_size =
            usize::try_from(header.ram_size).map_err(|_| BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "ram_size {:#x} does not fit host address space",
                    header.ram_size
                ),
            })?;
        let ram_end =
            ram_offset
                .checked_add(ram_size)
                .ok_or_else(|| BootMemoryError::InvalidBootMemory {
                    reason: format!(
                        "ram_offset {:#x} + ram_size {:#x} overflows host address space",
                        header.ram_offset, header.ram_size
                    ),
                })?;
        if ram_end > region.len() {
            return Err(BootMemoryError::InvalidBootMemory {
                reason: format!(
                    "RAM range [{ram_offset:#x}..{ram_end:#x}) exceeds unified mapping {:#x}",
                    region.len()
                ),
            });
        }
        // SAFETY: range containment was checked above. `BootMemory` exposes
        // this RAM through explicit volatile guest-memory helpers.
        let base = unsafe { region.offset_mut_ptr(ram_offset) }.ok_or_else(|| {
            BootMemoryError::InvalidBootMemory {
                reason: format!("ram_offset {ram_offset:#x} is outside unified mapping"),
            }
        })?;
        let layout = BootRamLayout::from_vm_state(view, holes)?;
        // SAFETY: `base` points to `ram_size` bytes within `region`, checked
        // above; aliasing/writability are upheld by this function's caller.
        unsafe { Self::from_raw_parts(base, ram_size, layout) }
    }
}

#[cfg(test)]
mod tests {
    use std::ptr::NonNull;

    use super::*;

    #[test]
    fn from_vm_state_uses_view_guest_base() {
        let region = amla_core::vm_state::test_mmap(2 * 1024 * 1024);
        let mapped = amla_core::vm_state::MappedVmState::new(region, 0x4000_0000).unwrap();
        let view = mapped.view().unwrap();

        let layout = BootRamLayout::from_vm_state(&view, amla_core::MEMORY_HOLES).unwrap();
        let range = layout
            .translate_contiguous(GuestPhysAddr::new(0x4000_1000), 0x1000)
            .unwrap();

        assert_eq!(layout.guest_base().as_u64(), 0x4000_0000);
        assert_eq!(range.offset(), 0x1000);
    }

    #[test]
    fn sparse_layout_without_declared_hole_is_rejected() {
        let segments = [
            RamSegment::new(GuestPhysAddr::new(0), RamBackingOffset::new(0), 0x1000),
            RamSegment::new(
                GuestPhysAddr::new(0x3000),
                RamBackingOffset::new(0x1000),
                0x1000,
            ),
        ];
        let layout = BootRamLayout {
            guest_base: GuestPhysAddr::new(0),
            backing_len: 0x2000,
            segments: segments.to_vec(),
            holes: MemoryHoleSet::new(amla_core::MemoryHoles::EMPTY).unwrap(),
        };

        assert!(layout.single_ram_segment().is_err());
        let err = layout.validate_declared_holes_match_gaps().unwrap_err();
        assert!(matches!(err, BootMemoryError::InvalidBootMemory { .. }));
    }

    #[test]
    fn boot_guest_memory_writes_by_guest_address() {
        let mut buf = vec![0u8; 0x4000];
        let layout = BootRamLayout::from_ram(
            GuestPhysAddr::new(0x4000_0000),
            buf.len(),
            amla_core::MemoryHoles::EMPTY,
        )
        .unwrap();
        let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `buf` is uniquely borrowed for this boot-memory value.
        let mut mem = unsafe { BootGuestMemory::from_raw_parts(ptr, buf.len(), layout) }.unwrap();

        mem.write_guest(GuestPhysAddr::new(0x4000_0200), b"arm")
            .unwrap();

        assert_eq!(&buf[0x200..0x203], b"arm");
    }
}
