// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Identity-mapped page tables using 2MB huge pages for 64-bit long mode.

use std::marker::PhantomData;

use crate::x86_64::builder::{BootError, Result};
use crate::x86_64::consts::{
    HIGH_PDPT_ADDR, PAGE_PRESENT, PAGE_SIZE, PAGE_TABLE_EXTRA_ARENA_ADDR,
    PAGE_TABLE_EXTRA_ARENA_SIZE, PAGE_WRITABLE, PD_ADDR, PDPT_ADDR, PML4_ADDR,
};
use crate::x86_64::memory::{BootGuestMemory, BootRamLayout, GuestPhysAddr};

/// Maximum identity-mapped memory: 512 GiB (one full PML4 entry / PDPT).
const MAX_MAPPED_MEMORY: usize = 512 << 30;
const PAGE_4K: u64 = 4096;
const PAGE_2M: u64 = 2 << 20;
const PAGE_1G: u64 = 1 << 30;
const ENTRIES_PER_TABLE: u64 = 512;

trait PageSize {
    const BYTES: u64;
}

#[derive(Debug, Clone, Copy)]
struct Page4K;

#[derive(Debug, Clone, Copy)]
struct Page2M;

#[derive(Debug, Clone, Copy)]
struct Page1G;

impl PageSize for Page4K {
    const BYTES: u64 = PAGE_4K;
}

impl PageSize for Page2M {
    const BYTES: u64 = PAGE_2M;
}

impl PageSize for Page1G {
    const BYTES: u64 = PAGE_1G;
}

#[derive(Debug, Clone, Copy)]
struct AlignedPage<S: PageSize> {
    addr: GuestPhysAddr,
    _size: PhantomData<S>,
}

impl<S: PageSize> AlignedPage<S> {
    fn new(addr: GuestPhysAddr) -> Result<Self> {
        if !addr.as_u64().is_multiple_of(S::BYTES) {
            return Err(BootError::PageTableLimit {
                mem_size: usize::try_from(addr.as_u64()).unwrap_or(usize::MAX),
                reason: "page address is not aligned to required page size",
            });
        }
        Ok(Self {
            addr,
            _size: PhantomData,
        })
    }

    const fn gpa(self) -> GuestPhysAddr {
        self.addr
    }

    const fn raw(self) -> u64 {
        self.addr.as_u64()
    }
}

#[derive(Debug, Clone, Copy)]
struct PageAlignedRamRange {
    start: AlignedPage<Page4K>,
    end: AlignedPage<Page4K>,
}

impl PageAlignedRamRange {
    fn new(start: GuestPhysAddr, end: GuestPhysAddr) -> Result<Self> {
        if end.as_u64() < start.as_u64() {
            return Err(BootError::PageTableLimit {
                mem_size: usize::MAX,
                reason: "RAM segment end precedes start",
            });
        }
        Ok(Self {
            start: AlignedPage::new(start)?,
            end: AlignedPage::new(end)?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct PageTablePage(AlignedPage<Page4K>);

impl PageTablePage {
    fn new(addr: GuestPhysAddr) -> Result<Self> {
        Ok(Self(AlignedPage::new(addr)?))
    }

    const fn gpa(self) -> GuestPhysAddr {
        self.0.gpa()
    }

    const fn raw(self) -> u64 {
        self.0.raw()
    }

    const fn entry(self, index: PageTableIndex) -> PageTableEntryAddr {
        PageTableEntryAddr(GuestPhysAddr::new(self.raw() + index.raw() * 8))
    }
}

#[derive(Debug, Clone, Copy)]
struct PageTableIndex(u64);

impl PageTableIndex {
    fn new(index: u64) -> Result<Self> {
        if index >= ENTRIES_PER_TABLE {
            return Err(BootError::PageTableLimit {
                mem_size: usize::try_from(index).unwrap_or(usize::MAX),
                reason: "page-table index exceeds 512 entries",
            });
        }
        Ok(Self(index))
    }

    const fn pdpt<S: PageSize>(addr: AlignedPage<S>) -> Self {
        Self((addr.raw() >> 30) & 0x1FF)
    }

    const fn pd<S: PageSize>(addr: AlignedPage<S>) -> Self {
        Self((addr.raw() >> 21) & 0x1FF)
    }

    const fn pt<S: PageSize>(addr: AlignedPage<S>) -> Self {
        Self((addr.raw() >> 12) & 0x1FF)
    }

    const fn raw(self) -> u64 {
        self.0
    }
}

#[derive(Debug, Clone, Copy)]
struct PageTableEntryAddr(GuestPhysAddr);

impl PageTableEntryAddr {
    const fn gpa(self) -> GuestPhysAddr {
        self.0
    }
}

struct PageTablePlan {
    gb_to_map: u64,
    ram_ranges: Vec<PageAlignedRamRange>,
}

impl PageTablePlan {
    fn from_layout(layout: &BootRamLayout) -> Result<Self> {
        let map_end = usize::try_from(layout.last_guest_end()?.as_u64()).map_err(|_| {
            BootError::PageTableLimit {
                mem_size: usize::MAX,
                reason: "guest address extent does not fit host address space",
            }
        })?;

        if map_end > MAX_MAPPED_MEMORY {
            return Err(BootError::PageTableLimit {
                mem_size: map_end,
                reason: "exceeds 512 GiB identity-map limit",
            });
        }

        let mut ram_ranges = Vec::with_capacity(layout.ram_segments().len());
        for seg in layout.ram_segments() {
            ram_ranges.push(PageAlignedRamRange::new(
                seg.guest_start(),
                seg.guest_end()?,
            )?);
        }

        Ok(Self {
            gb_to_map: (map_end as u64).div_ceil(PAGE_1G).min(ENTRIES_PER_TABLE),
            ram_ranges,
        })
    }
}

/// Set up page tables for 64-bit mode with identity mapping.
///
/// Creates a 4-level page table structure from RAM segments in the validated
/// boot layout. Holes remain unmapped. The mapper uses 1 GiB, 2 MiB, and 4 KiB
/// pages depending on segment alignment.
///
/// # Errors
///
/// Returns [`BootError::PageTableLimit`] if the layout exceeds 512 GiB.
pub fn setup_page_tables(mem: &mut BootGuestMemory<'_>) -> Result<()> {
    let plan = PageTablePlan::from_layout(mem.layout())?;
    let pml4 = PageTablePage::new(GuestPhysAddr::new(PML4_ADDR))?;
    let pdpt = PageTablePage::new(GuestPhysAddr::new(PDPT_ADDR))?;
    let high_pdpt = PageTablePage::new(GuestPhysAddr::new(HIGH_PDPT_ADDR))?;

    mem.zero_guest(pml4.gpa().range(PAGE_4K as usize)?)?;
    mem.zero_guest(pdpt.gpa().range(PAGE_4K as usize)?)?;

    // PML4[0] -> PDPT (identity mapping)
    write_entry(
        mem,
        pml4.entry(PageTableIndex::new(0)?),
        pdpt.raw() | PAGE_PRESENT | PAGE_WRITABLE,
    )?;

    let gb_with_pd_tables = plan.gb_to_map.min(4);

    // 0-4GB: fixed PD pages. Individual PDEs are filled from RAM segments
    // below, so holes remain unmapped.
    for i in 0..gb_with_pd_tables {
        let directory = PageTablePage::new(GuestPhysAddr::new(PD_ADDR + i * PAGE_4K))?;
        write_entry(
            mem,
            pdpt.entry(PageTableIndex::new(i)?),
            directory.raw() | PAGE_PRESENT | PAGE_WRITABLE,
        )?;
        mem.zero_guest(directory.gpa().range(PAGE_4K as usize)?)?;
    }

    let mut allocator = PageTablePageAllocator::new();
    for range in plan.ram_ranges {
        identity_map_ram_segment(mem, &mut allocator, range)?;
    }

    // Higher-half kernel mapping mirrors the low identity PDs for the first
    // 2 GiB. Any holes split in those PDs remain split in the alias.
    mem.zero_guest(high_pdpt.gpa().range(PAGE_4K as usize)?)?;
    write_entry(
        mem,
        pml4.entry(PageTableIndex::new(511)?),
        high_pdpt.raw() | PAGE_PRESENT | PAGE_WRITABLE,
    )?;
    write_entry(
        mem,
        high_pdpt.entry(PageTableIndex::new(510)?),
        PD_ADDR | PAGE_PRESENT | PAGE_WRITABLE,
    )?;
    if plan.gb_to_map >= 2 {
        write_entry(
            mem,
            high_pdpt.entry(PageTableIndex::new(511)?),
            (PD_ADDR + 4096) | PAGE_PRESENT | PAGE_WRITABLE,
        )?;
    }

    Ok(())
}

struct PageTablePageAllocator {
    next: u64,
    end: u64,
}

impl PageTablePageAllocator {
    const fn new() -> Self {
        Self {
            next: PAGE_TABLE_EXTRA_ARENA_ADDR,
            end: PAGE_TABLE_EXTRA_ARENA_ADDR + PAGE_TABLE_EXTRA_ARENA_SIZE as u64,
        }
    }

    fn alloc(&mut self, mem: &mut BootGuestMemory<'_>) -> Result<PageTablePage> {
        let page = self.next;
        let Some(next) = page.checked_add(PAGE_4K) else {
            return Err(BootError::PageTableLimit {
                mem_size: usize::MAX,
                reason: "page-table arena address overflow",
            });
        };
        if next > self.end {
            return Err(BootError::PageTableLimit {
                mem_size: PAGE_TABLE_EXTRA_ARENA_SIZE,
                reason: "page-table arena exhausted while splitting RAM holes",
            });
        }
        self.next = next;
        let page = PageTablePage::new(GuestPhysAddr::new(page))?;
        mem.zero_guest(page.gpa().range(PAGE_4K as usize)?)?;
        Ok(page)
    }
}

fn identity_map_ram_segment(
    mem: &mut BootGuestMemory<'_>,
    allocator: &mut PageTablePageAllocator,
    range: PageAlignedRamRange,
) -> Result<()> {
    let mut start = range.start.raw();
    let end = range.end.raw();

    while start < end {
        let remaining = end - start;
        if start >= 4 * Page1G::BYTES
            && remaining >= Page1G::BYTES
            && let Ok(page) = AlignedPage::<Page1G>::new(GuestPhysAddr::new(start))
        {
            map_1g_page(mem, page)?;
            start += PAGE_1G;
        } else if remaining >= Page2M::BYTES
            && let Ok(page) = AlignedPage::<Page2M>::new(GuestPhysAddr::new(start))
        {
            map_2m_page(mem, allocator, page)?;
            start += PAGE_2M;
        } else {
            let page = AlignedPage::<Page4K>::new(GuestPhysAddr::new(start))?;
            map_4k_page(mem, allocator, page)?;
            start += PAGE_4K;
        }
    }

    Ok(())
}

fn map_1g_page(mem: &mut BootGuestMemory<'_>, page: AlignedPage<Page1G>) -> Result<()> {
    let pdpt = PageTablePage::new(GuestPhysAddr::new(PDPT_ADDR))?;
    let entry_addr = pdpt.entry(PageTableIndex::pdpt(page));
    let existing = read_entry(mem, entry_addr)?;
    if existing != 0 {
        return Err(BootError::PageTableLimit {
            mem_size: usize::try_from(page.raw()).unwrap_or(usize::MAX),
            reason: "conflicting page-table entry while mapping 1 GiB page",
        });
    }
    write_entry(
        mem,
        entry_addr,
        page.raw() | PAGE_PRESENT | PAGE_WRITABLE | PAGE_SIZE,
    )
}

fn map_2m_page(
    mem: &mut BootGuestMemory<'_>,
    allocator: &mut PageTablePageAllocator,
    page: AlignedPage<Page2M>,
) -> Result<()> {
    let directory = ensure_pd_page(mem, allocator, PageTableIndex::pdpt(page))?;
    let entry_addr = directory.entry(PageTableIndex::pd(page));
    let existing = read_entry(mem, entry_addr)?;
    if existing != 0 {
        return Err(BootError::PageTableLimit {
            mem_size: usize::try_from(page.raw()).unwrap_or(usize::MAX),
            reason: "conflicting page-table entry while mapping 2 MiB page",
        });
    }
    write_entry(
        mem,
        entry_addr,
        page.raw() | PAGE_PRESENT | PAGE_WRITABLE | PAGE_SIZE,
    )
}

fn map_4k_page(
    mem: &mut BootGuestMemory<'_>,
    allocator: &mut PageTablePageAllocator,
    page: AlignedPage<Page4K>,
) -> Result<()> {
    let directory = ensure_pd_page(mem, allocator, PageTableIndex::pdpt(page))?;
    let table = ensure_pt_page(mem, allocator, directory, PageTableIndex::pd(page))?;
    let entry_addr = table.entry(PageTableIndex::pt(page));
    let existing = read_entry(mem, entry_addr)?;
    if existing != 0 {
        return Err(BootError::PageTableLimit {
            mem_size: usize::try_from(page.raw()).unwrap_or(usize::MAX),
            reason: "conflicting page-table entry while mapping 4 KiB page",
        });
    }
    write_entry(mem, entry_addr, page.raw() | PAGE_PRESENT | PAGE_WRITABLE)
}

fn ensure_pd_page(
    mem: &mut BootGuestMemory<'_>,
    allocator: &mut PageTablePageAllocator,
    pdpt_index: PageTableIndex,
) -> Result<PageTablePage> {
    let pdpt = PageTablePage::new(GuestPhysAddr::new(PDPT_ADDR))?;
    let entry_addr = pdpt.entry(pdpt_index);
    let existing = read_entry(mem, entry_addr)?;
    if existing & PAGE_PRESENT != 0 {
        if existing & PAGE_SIZE != 0 {
            return Err(BootError::PageTableLimit {
                mem_size: usize::try_from(pdpt_index.raw() << 30).unwrap_or(usize::MAX),
                reason: "cannot split an existing 1 GiB page",
            });
        }
        return PageTablePage::new(GuestPhysAddr::new(existing & !0xFFF));
    }

    let directory = allocator.alloc(mem)?;
    write_entry(
        mem,
        entry_addr,
        directory.raw() | PAGE_PRESENT | PAGE_WRITABLE,
    )?;
    Ok(directory)
}

fn ensure_pt_page(
    mem: &mut BootGuestMemory<'_>,
    allocator: &mut PageTablePageAllocator,
    directory: PageTablePage,
    pd_index: PageTableIndex,
) -> Result<PageTablePage> {
    let entry_addr = directory.entry(pd_index);
    let existing = read_entry(mem, entry_addr)?;
    if existing & PAGE_PRESENT != 0 {
        if existing & PAGE_SIZE != 0 {
            return Err(BootError::PageTableLimit {
                mem_size: usize::try_from(directory.raw()).unwrap_or(usize::MAX),
                reason: "cannot split an existing 2 MiB page",
            });
        }
        return PageTablePage::new(GuestPhysAddr::new(existing & !0xFFF));
    }

    let table = allocator.alloc(mem)?;
    write_entry(mem, entry_addr, table.raw() | PAGE_PRESENT | PAGE_WRITABLE)?;
    Ok(table)
}

fn write_entry(
    mem: &mut BootGuestMemory<'_>,
    entry_addr: PageTableEntryAddr,
    value: u64,
) -> Result<()> {
    mem.write_u64_guest(entry_addr.gpa(), value)
}

fn read_entry(mem: &BootGuestMemory<'_>, entry_addr: PageTableEntryAddr) -> Result<u64> {
    let bytes = mem.read_guest(entry_addr.gpa().range(8)?)?;
    let mut entry = [0u8; 8];
    entry.copy_from_slice(bytes);
    Ok(u64::from_le_bytes(entry))
}
