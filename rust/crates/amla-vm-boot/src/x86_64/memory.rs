// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Typed x86 boot-memory layout and translated guest writes.

use std::marker::PhantomData;
use std::ptr::NonNull;

pub use crate::boot_memory::{GuestPhysAddr, GuestRange, RamBackingRange, RamSegment};
use crate::boot_memory::BootRamLayout as CommonBootRamLayout;
use crate::x86_64::builder::{BootError, Result};
use crate::x86_64::consts::{
    CMDLINE_ADDR, CMDLINE_MAX_SIZE, GDT_ADDR, GDT_SIZE_BYTES, HIGH_MEMORY_START, HIGH_PDPT_ADDR,
    INITIAL_STACK_POINTER, LOW_MEMORY_END, MPTABLE_START, PAGE_TABLE_EXTRA_ARENA_ADDR,
    PAGE_TABLE_EXTRA_ARENA_SIZE, PD_ADDR, PDPT_ADDR, PML4_ADDR, RESERVED_REGION_SIZE,
    ZERO_PAGE_ADDR,
};
use crate::x86_64::writer::GuestMemWriter;

const INITIAL_STACK_SIZE: usize = 0x1000;

/// Validated x86 RAM layout used by every boot writer.
#[derive(Debug, Clone)]
pub struct BootRamLayout {
    inner: CommonBootRamLayout,
}

impl BootRamLayout {
    /// Build a layout from contiguous RAM backing and architecture holes.
    ///
    /// # Errors
    ///
    /// Returns [`BootError::MemoryLayout`] if hole splitting fails, or a
    /// layout/range error if a split segment cannot fit host address types.
    pub fn from_ram(
        guest_base: GuestPhysAddr,
        ram_size: usize,
        holes: amla_core::MemoryHoles<'_>,
    ) -> Result<Self> {
        Ok(Self {
            inner: CommonBootRamLayout::from_ram(guest_base, ram_size, holes)?,
        })
    }

    /// Build a boot RAM layout from the guest-memory mappings in `VmState`.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the `VmState` RAM mappings do not describe a
    /// contiguous RAM backing blob split only by the declared architecture
    /// holes.
    pub fn from_vm_state(view: &amla_core::vm_state::VmState<'_>) -> Result<Self> {
        Ok(Self {
            inner: CommonBootRamLayout::from_vm_state(view, amla_core::MEMORY_HOLES)?,
        })
    }

    /// Translate a guest range to a contiguous RAM backing range.
    ///
    /// # Errors
    ///
    /// Returns [`BootError::GuestRangeUnmapped`] if the range is not fully
    /// contained in a single RAM segment.
    pub fn translate(&self, range: GuestRange) -> Result<RamBackingRange> {
        Ok(self.inner.translate(range)?)
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
        Ok(self.inner.translate_contiguous(start, len)?)
    }

    /// RAM segments in guest-visible order.
    #[must_use]
    pub fn ram_segments(&self) -> &[RamSegment] {
        self.inner.ram_segments()
    }

    fn holes(&self) -> &[amla_core::MemoryHole] {
        self.inner.holes()
    }

    /// Exclusive end of the last guest-visible RAM segment.
    ///
    /// Returns the base GPA for an empty layout.
    ///
    /// # Errors
    ///
    /// Returns [`BootError::GuestRangeOverflow`] if the last segment end overflows.
    pub fn last_guest_end(&self) -> Result<GuestPhysAddr> {
        Ok(self.inner.last_guest_end()?)
    }

    /// Size of the contiguous RAM backing blob.
    #[must_use]
    pub const fn backing_len(&self) -> usize {
        self.inner.backing_len()
    }

    /// Prove that the fixed x86 boot workspace is backed by RAM.
    ///
    /// # Errors
    ///
    /// Returns a translation error if any fixed boot structure crosses a hole.
    pub fn validate_low_boot_workspace(&self) -> Result<LowBootWorkspace> {
        let regions = BootRegionSet::new()?;
        for region in regions.iter() {
            self.translate_contiguous(GuestPhysAddr::new(region.start), region.len)
                .map_err(|_| BootError::BootWorkspaceUnmapped {
                    region: region.name,
                    start: region.start,
                    len: region.len,
                })?;
        }
        Ok(LowBootWorkspace { _regions: regions })
    }

    /// Construct the E820 map from the validated layout.
    ///
    /// # Errors
    ///
    /// Returns [`BootError::E820TableTooLarge`] if the map exceeds the Linux
    /// zero-page table capacity.
    pub(crate) fn e820_map(&self) -> Result<E820Map> {
        E820Map::from_layout(self)
    }

}

#[derive(Debug, Clone, Copy)]
struct BootRegion {
    name: &'static str,
    start: u64,
    len: usize,
}

impl BootRegion {
    fn end(self) -> Result<u64> {
        let len = u64::try_from(self.len).map_err(|_| BootError::InvalidBootMemory {
            reason: format!(
                "boot workspace region {} length does not fit u64",
                self.name
            ),
        })?;
        self.start
            .checked_add(len)
            .ok_or_else(|| BootError::InvalidBootMemory {
                reason: format!("boot workspace region {} end overflows", self.name),
            })
    }
}

#[derive(Debug, Clone, Copy)]
struct BootRegionSet {
    regions: [BootRegion; 10],
}

impl BootRegionSet {
    fn new() -> Result<Self> {
        let regions = [
            BootRegion {
                name: "GDT",
                start: GDT_ADDR,
                len: GDT_SIZE_BYTES,
            },
            BootRegion {
                name: "zero page",
                start: ZERO_PAGE_ADDR,
                len: 4096,
            },
            BootRegion {
                name: "initial stack",
                start: INITIAL_STACK_POINTER - INITIAL_STACK_SIZE as u64,
                len: INITIAL_STACK_SIZE,
            },
            BootRegion {
                name: "PML4",
                start: PML4_ADDR,
                len: 4096,
            },
            BootRegion {
                name: "PDPT",
                start: PDPT_ADDR,
                len: 4096,
            },
            BootRegion {
                name: "PD tables",
                start: PD_ADDR,
                len: 4 * 4096,
            },
            BootRegion {
                name: "high-half PDPT",
                start: HIGH_PDPT_ADDR,
                len: 4096,
            },
            BootRegion {
                name: "extra page-table arena",
                start: PAGE_TABLE_EXTRA_ARENA_ADDR,
                len: PAGE_TABLE_EXTRA_ARENA_SIZE,
            },
            BootRegion {
                name: "cmdline",
                start: CMDLINE_ADDR,
                len: CMDLINE_MAX_SIZE,
            },
            BootRegion {
                name: "MP table",
                start: MPTABLE_START,
                len: usize::try_from(LOW_MEMORY_END - MPTABLE_START).map_err(|_| {
                    BootError::InvalidBootMemory {
                        reason: "MP table workspace length does not fit usize".into(),
                    }
                })?,
            },
        ];
        for pair in regions.windows(2) {
            let first = pair[0];
            let second = pair[1];
            let first_end = first.end()?;
            let second_end = second.end()?;
            if first_end > second.start {
                return Err(BootError::BootWorkspaceOverlap {
                    first: first.name,
                    first_start: first.start,
                    first_end,
                    second: second.name,
                    second_start: second.start,
                    second_end,
                });
            }
        }
        Ok(Self { regions })
    }

    fn iter(&self) -> impl Iterator<Item = BootRegion> + '_ {
        self.regions.iter().copied()
    }
}

/// Opaque proof that fixed low-memory x86 boot structures are mapped and disjoint.
#[derive(Debug, Clone, Copy)]
pub struct LowBootWorkspace {
    _regions: BootRegionSet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum E820Type {
    Ram,
    Reserved,
}

impl E820Type {
    pub(crate) const fn as_u32(self) -> u32 {
        match self {
            Self::Ram => crate::x86_64::consts::E820_TYPE_RAM,
            Self::Reserved => crate::x86_64::consts::E820_TYPE_RESERVED,
        }
    }
}

/// One validated E820 entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct E820Entry {
    pub(crate) addr: u64,
    pub(crate) size: u64,
    pub(crate) mem_type: E820Type,
}

/// Count-validated E820 map.
#[derive(Debug, Clone)]
pub struct E820Map {
    entries: Vec<E820Entry>,
}

impl E820Map {
    pub(crate) fn entries(&self) -> &[E820Entry] {
        &self.entries
    }

    fn from_layout(layout: &BootRamLayout) -> Result<Self> {
        use crate::x86_64::consts::E820_MAX_ENTRIES;

        let mut entries = Vec::new();
        push_e820(
            &mut entries,
            E820Entry {
                addr: 0,
                size: LOW_MEMORY_END,
                mem_type: E820Type::Ram,
            },
        )?;
        push_e820(
            &mut entries,
            E820Entry {
                addr: LOW_MEMORY_END,
                size: RESERVED_REGION_SIZE,
                mem_type: E820Type::Reserved,
            },
        )?;

        for seg in layout.ram_segments() {
            let start = seg.guest_start().as_u64().max(HIGH_MEMORY_START);
            let end = seg.guest_end()?.as_u64();
            if end > start {
                push_e820(
                    &mut entries,
                    E820Entry {
                        addr: start,
                        size: end - start,
                        mem_type: E820Type::Ram,
                    },
                )?;
            }
        }

        let last_guest_end = layout.last_guest_end()?.as_u64();
        for hole in layout.holes() {
            if hole.advertise_reserved
                && hole.start < last_guest_end
                && hole.end > HIGH_MEMORY_START
            {
                push_e820(
                    &mut entries,
                    E820Entry {
                        addr: hole.start,
                        size: hole.end - hole.start,
                        mem_type: E820Type::Reserved,
                    },
                )?;
            }
        }

        let entries = normalize_e820_entries(entries)?;

        if entries.len() > E820_MAX_ENTRIES as usize {
            return Err(BootError::E820TableTooLarge {
                count: entries.len() as u64,
                max: E820_MAX_ENTRIES,
            });
        }
        Ok(Self { entries })
    }
}

fn normalize_e820_entries(mut entries: Vec<E820Entry>) -> Result<Vec<E820Entry>> {
    entries.sort_by_key(|entry| entry.addr);

    let mut normalized: Vec<E820Entry> = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.size == 0 {
            continue;
        }
        let entry_end = entry.addr.checked_add(entry.size).ok_or_else(|| {
            BootError::InvalidBootMemory {
                reason: format!(
                    "E820 entry [{:#x}..+{:#x}) overflows",
                    entry.addr, entry.size
                ),
            }
        })?;
        if let Some(last) = normalized.last_mut() {
            let last_end = last.addr.checked_add(last.size).ok_or_else(|| {
                BootError::InvalidBootMemory {
                    reason: format!("E820 entry [{:#x}..+{:#x}) overflows", last.addr, last.size),
                }
            })?;
            if entry.addr < last_end {
                return Err(BootError::InvalidBootMemory {
                    reason: format!(
                        "E820 entries overlap: previous [{:#x}..{:#x}), next [{:#x}..{:#x})",
                        last.addr, last_end, entry.addr, entry_end
                    ),
                });
            }
            if entry.addr == last_end && entry.mem_type == last.mem_type {
                last.size = last.size.checked_add(entry.size).ok_or_else(|| {
                    BootError::InvalidBootMemory {
                        reason: format!(
                            "coalesced E820 entry [{:#x}..+{:#x}) overflows",
                            last.addr, entry.size
                        ),
                    }
                })?;
                continue;
            }
        }
        normalized.push(entry);
    }
    Ok(normalized)
}

fn push_e820(entries: &mut Vec<E820Entry>, entry: E820Entry) -> Result<()> {
    use crate::x86_64::consts::E820_MAX_ENTRIES;

    if entries.len() >= E820_MAX_ENTRIES as usize {
        return Err(BootError::E820TableTooLarge {
            count: entries.len() as u64 + 1,
            max: E820_MAX_ENTRIES,
        });
    }
    entries.push(entry);
    Ok(())
}

/// Exclusive, typed access to guest RAM during x86 boot setup.
pub struct BootGuestMemory<'a> {
    writer: GuestMemWriter,
    layout: BootRamLayout,
    _workspace: LowBootWorkspace,
    _exclusive: PhantomData<&'a mut [u8]>,
}

impl<'a> BootGuestMemory<'a> {
    /// Construct boot memory from a raw pointer, backing length, and layout.
    ///
    /// # Safety
    ///
    /// `base` must point to writable memory valid for `len` bytes, and the
    /// caller must ensure no other mutable access aliases this region while
    /// the returned value is alive.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the validated layout does not fit in `len` or
    /// if fixed boot workspace ranges are not backed by RAM.
    pub unsafe fn from_raw_parts(
        base: NonNull<u8>,
        len: usize,
        layout: BootRamLayout,
    ) -> Result<Self> {
        if layout.backing_len() > len {
            return Err(BootError::InvalidBootMemory {
                reason: format!(
                    "RAM backing length {:#x} exceeds mapped length {len:#x}",
                    layout.backing_len()
                ),
            });
        }
        let workspace = layout.validate_low_boot_workspace()?;
        Ok(Self {
            // SAFETY: upheld by the caller of `from_raw_parts`.
            writer: unsafe { GuestMemWriter::new(base, len) },
            layout,
            _workspace: workspace,
            _exclusive: PhantomData,
        })
    }

    /// Construct boot memory from the validated unified VM-state mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure the RAM portion of `region` is writable and is not
    /// mutably aliased while the returned boot-memory capability is alive.
    ///
    /// # Errors
    ///
    /// Returns a layout error if the RAM range described by `view` is outside
    /// `region`, or if the derived boot layout is invalid.
    pub unsafe fn from_vm_state(
        view: &amla_core::vm_state::VmState<'_>,
        region: &'a amla_mem::MmapSlice,
    ) -> Result<Self> {
        let header = view.header();
        let ram_offset =
            usize::try_from(header.ram_offset).map_err(|_| BootError::InvalidBootMemory {
                reason: format!(
                    "ram_offset {:#x} does not fit host address space",
                    header.ram_offset
                ),
            })?;
        let ram_size =
            usize::try_from(header.ram_size).map_err(|_| BootError::InvalidBootMemory {
                reason: format!(
                    "ram_size {:#x} does not fit host address space",
                    header.ram_size
                ),
            })?;
        let ram_end =
            ram_offset
                .checked_add(ram_size)
                .ok_or_else(|| BootError::InvalidBootMemory {
                    reason: format!(
                        "ram_offset {:#x} + ram_size {:#x} overflows host address space",
                        header.ram_offset, header.ram_size
                    ),
                })?;
        if ram_end > region.len() {
            return Err(BootError::InvalidBootMemory {
                reason: format!(
                    "RAM range [{ram_offset:#x}..{ram_end:#x}) exceeds unified mapping {:#x}",
                    region.len()
                ),
            });
        }
        // SAFETY: range containment was checked above. `BootMemory` exposes
        // this RAM through explicit volatile guest-memory helpers.
        let base = unsafe { region.offset_mut_ptr(ram_offset) }.ok_or_else(|| {
            BootError::InvalidBootMemory {
                reason: format!("ram_offset {ram_offset:#x} is outside unified mapping"),
            }
        })?;
        let layout = BootRamLayout::from_vm_state(view)?;
        // SAFETY: `base` points to `ram_size` bytes within `region`, checked
        // above; aliasing/writability are upheld by this function's caller.
        unsafe { Self::from_raw_parts(base, ram_size, layout) }
    }

    #[cfg(test)]
    pub(crate) unsafe fn from_raw_parts_for_test(
        base: NonNull<u8>,
        len: usize,
        layout: BootRamLayout,
    ) -> Self {
        let workspace = layout
            .validate_low_boot_workspace()
            .expect("test layout should map low boot workspace");
        Self {
            // SAFETY: upheld by the caller of this test-only constructor.
            writer: unsafe { GuestMemWriter::new(base, len) },
            layout,
            _workspace: workspace,
            _exclusive: PhantomData,
        }
    }

    /// Borrow the validated RAM layout.
    #[must_use]
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

    // Reason: writes go through a raw-pointer guest memory writer that
    // the borrow checker can't see; `&mut self` is required to serialize
    // those raw stores against concurrent reads.
    #[allow(clippy::needless_pass_by_ref_mut)]
    pub(crate) fn zero_guest(&mut self, range: GuestRange) -> Result<()> {
        let backing = self.layout.translate(range)?;
        self.writer.zero_at(backing)
    }

    pub(crate) fn write_u8_guest(&mut self, gpa: GuestPhysAddr, value: u8) -> Result<()> {
        self.write_guest(gpa, &[value])
    }

    pub(crate) fn write_u16_guest(&mut self, gpa: GuestPhysAddr, value: u16) -> Result<()> {
        self.write_guest(gpa, &value.to_le_bytes())
    }

    pub(crate) fn write_u32_guest(&mut self, gpa: GuestPhysAddr, value: u32) -> Result<()> {
        self.write_guest(gpa, &value.to_le_bytes())
    }

    pub(crate) fn write_u64_guest(&mut self, gpa: GuestPhysAddr, value: u64) -> Result<()> {
        self.write_guest(gpa, &value.to_le_bytes())
    }

    pub(crate) fn read_guest(&self, range: GuestRange) -> Result<&[u8]> {
        let backing = self.layout.translate(range)?;
        self.writer.read_at(backing)
    }
}
