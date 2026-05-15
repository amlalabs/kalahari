// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Public API: `LinuxBootBuilder`, types, ELF loading, boot params.

use thiserror::Error;

use crate::boot_memory::BootMemoryError;
use crate::x86_64::consts::{
    BOOT_PROTOCOL_VERSION, BOOT_SIGNATURE, BP_BOOT_FLAG, BP_CMD_LINE_PTR, BP_CMDLINE_SIZE,
    BP_E820_ENTRIES, BP_E820_TABLE, BP_HEADER_MAGIC, BP_LOADFLAGS, BP_TYPE_OF_LOADER, BP_VERSION,
    BZIMAGE_MAGIC, CMDLINE_ADDR, CMDLINE_MAX_SIZE, E820_ENTRY_SIZE, HIGH_MEMORY_START, LOAD_FLAGS,
    LOADER_TYPE_UNDEFINED, MINIMUM_MEMORY_SIZE, ZERO_PAGE_ADDR,
};
use crate::x86_64::cpu_state::{X86BootState, setup_cpu_state};
use crate::x86_64::gdt::setup_gdt;
use crate::x86_64::memory::{BootGuestMemory, GuestPhysAddr};
use crate::x86_64::mptable::setup_mptable;
use crate::x86_64::page_tables::setup_page_tables;

// =============================================================================
// Error Types
// =============================================================================

/// Errors that can occur during boot setup.
#[derive(Debug, Error)]
pub enum BootError {
    /// ELF file is not 64-bit (x86-64).
    #[error("Not a 64-bit ELF")]
    Not64Bit,

    /// Kernel segment would exceed available memory.
    #[error("Kernel segment at {addr:#x} size {size} exceeds memory {mem_size}")]
    KernelTooLarge {
        /// Load address of the kernel segment.
        addr: u64,
        /// Size of the kernel segment.
        size: usize,
        /// Total available guest memory.
        mem_size: usize,
    },

    /// Kernel segment overlaps the boot loader's low-memory workspace.
    #[error(
        "Kernel segment [{segment_start:#x}..{segment_end:#x}) overlaps reserved boot region {region} [{region_start:#x}..{region_end:#x})"
    )]
    KernelOverlapsBootRegion {
        /// Start of the kernel segment.
        segment_start: u64,
        /// End of the kernel segment.
        segment_end: u64,
        /// Name of the reserved region.
        region: &'static str,
        /// Start of the reserved region.
        region_start: u64,
        /// End of the reserved region.
        region_end: u64,
    },

    /// Boot setup attempted to write outside guest memory.
    #[error("Guest memory write at offset {offset:#x} len {len} exceeds memory size {mem_size:#x}")]
    GuestMemoryOutOfBounds {
        /// RAM backing offset of the attempted write.
        offset: u64,
        /// Number of bytes in the attempted write.
        len: usize,
        /// Total guest memory size.
        mem_size: usize,
    },

    /// Guest range construction overflowed.
    #[error("Guest range at {start:#x} len {len} overflows")]
    GuestRangeOverflow {
        /// Start of the requested guest range.
        start: u64,
        /// Length of the requested range.
        len: usize,
    },

    /// Guest range is not backed by a single RAM segment.
    #[error("Guest range [{start:#x}..+{len:#x}) is not mapped as contiguous RAM")]
    GuestRangeUnmapped {
        /// Start of the requested guest range.
        start: u64,
        /// Length of the requested range.
        len: usize,
    },

    /// Fixed x86 boot workspace is not fully mapped by RAM.
    #[error("Boot workspace {region} at {start:#x} len {len:#x} is not mapped")]
    BootWorkspaceUnmapped {
        /// Name of the fixed boot workspace region.
        region: &'static str,
        /// Start GPA of the workspace region.
        start: u64,
        /// Length of the workspace region.
        len: usize,
    },

    /// Fixed x86 boot workspace regions overlap each other.
    #[error(
        "Boot workspace region {first} [{first_start:#x}..{first_end:#x}) overlaps {second} [{second_start:#x}..{second_end:#x})"
    )]
    BootWorkspaceOverlap {
        /// Name of the first overlapping region.
        first: &'static str,
        /// Start GPA of the first region.
        first_start: u64,
        /// Exclusive end GPA of the first region.
        first_end: u64,
        /// Name of the second overlapping region.
        second: &'static str,
        /// Start GPA of the second region.
        second_start: u64,
        /// Exclusive end GPA of the second region.
        second_end: u64,
    },

    /// Boot-memory validation failed.
    #[error("Invalid boot memory: {reason}")]
    InvalidBootMemory {
        /// Validation failure details.
        reason: String,
    },

    /// A guest address does not fit in a boot-protocol field.
    #[error("Boot address field {field} value {value:#x} exceeds limit {limit:#x}")]
    BootAddressTooLarge {
        /// Name of the boot protocol field.
        field: &'static str,
        /// Actual value.
        value: u64,
        /// Field limit.
        limit: u64,
    },

    /// Kernel command line exceeds maximum length.
    #[error("Command line too long: {len} bytes, max {max}")]
    CmdlineTooLong {
        /// Actual command line length.
        len: usize,
        /// Maximum allowed length.
        max: usize,
    },

    /// Guest memory is below minimum required.
    #[error(
        "Memory too small: {size} bytes, need at least {}",
        MINIMUM_MEMORY_SIZE
    )]
    MemoryTooSmall {
        /// Provided memory size.
        size: usize,
    },

    /// Invalid CPU count for MP table.
    #[error("Invalid CPU count: {requested} (must be 1-{max})")]
    InvalidCpuCount {
        /// Requested CPU count.
        requested: usize,
        /// Maximum CPU count supported by the fixed boot table layout.
        max: usize,
    },

    /// MP table too large for conventional memory.
    #[error("MP table ({size} bytes) overflows conventional memory with {num_cpus} CPUs")]
    MpTableOverflow {
        /// Size of the MP table in bytes.
        size: u64,
        /// Number of CPUs requested.
        num_cpus: usize,
    },

    /// Page table setup cannot map the given memory configuration.
    #[error("Page table limit: {mem_size:#x} bytes — {reason}")]
    PageTableLimit {
        /// Provided memory size in bytes.
        mem_size: usize,
        /// Explanation of why the configuration is unsupported.
        reason: &'static str,
    },

    /// Generated E820 memory map exceeds the Linux boot zero-page table.
    #[error("E820 table has {count} entries, max {max}")]
    E820TableTooLarge {
        /// Number of entries that would be emitted.
        count: u64,
        /// Maximum entries the boot table can hold.
        max: u64,
    },

    /// Error parsing ELF file.
    #[error("ELF parse error: {0}")]
    ElfParse(String),

    /// Memory layout error (e.g. mapping starts inside a hole).
    #[error("Memory layout: {0}")]
    MemoryLayout(#[from] amla_core::VmmError),
}

/// Result type for boot operations.
pub type Result<T> = std::result::Result<T, BootError>;

impl From<BootMemoryError> for BootError {
    fn from(err: BootMemoryError) -> Self {
        match err {
            BootMemoryError::GuestMemoryOutOfBounds {
                offset,
                len,
                mem_size,
            } => Self::GuestMemoryOutOfBounds {
                offset,
                len,
                mem_size,
            },
            BootMemoryError::GuestRangeOverflow { start, len } => {
                Self::GuestRangeOverflow { start, len }
            }
            BootMemoryError::GuestRangeUnmapped { start, len } => {
                Self::GuestRangeUnmapped { start, len }
            }
            BootMemoryError::InvalidBootMemory { reason } => Self::InvalidBootMemory { reason },
            BootMemoryError::BootAddressTooLarge {
                field,
                value,
                limit,
            } => Self::BootAddressTooLarge {
                field,
                value,
                limit,
            },
            BootMemoryError::MemoryLayout(err) => Self::MemoryLayout(err),
        }
    }
}

/// Result of setting up Linux boot environment.
///
/// Contains a platform-agnostic CPU register state and metadata about
/// the loaded kernel.
#[derive(Debug, Clone)]
pub struct BootResult {
    /// Platform-agnostic CPU state for 64-bit long mode entry.
    /// Convert to backend-specific types (KVM, WHP, HVF) before use.
    pub cpu_state: X86BootState,

    /// Kernel entry point address (from ELF header).
    pub entry_point: u64,
}

// =============================================================================
// Builder Pattern API
// =============================================================================

/// Builder for configuring Linux boot setup.
///
/// # Example
///
/// ```no_run
/// # fn example(boot_mem: amla_boot::BootGuestMemory<'_>) -> Result<(), Box<dyn std::error::Error>> {
/// use amla_boot::LinuxBootBuilder;
/// # let kernel = vec![0u8; 1024];
/// let result = LinuxBootBuilder::new(boot_mem, &kernel)
///     .cmdline("console=ttyS0 init=/bin/guest_agent")
///     .num_cpus(4)
///     .build()?;
/// # Ok(())
/// # }
/// ```
#[must_use]
pub struct LinuxBootBuilder<'a> {
    boot_mem: BootGuestMemory<'a>,
    kernel: &'a [u8],
    cmdline: String,
    num_cpus: usize,
}

impl<'a> LinuxBootBuilder<'a> {
    /// Create a new boot builder with required parameters.
    pub fn new(boot_mem: BootGuestMemory<'a>, kernel: &'a [u8]) -> Self {
        Self {
            boot_mem,
            kernel,
            cmdline: "console=ttyS0".to_string(),
            num_cpus: 1,
        }
    }

    /// Set the kernel command line.
    pub fn cmdline(mut self, cmdline: &str) -> Self {
        self.cmdline = cmdline.to_string();
        self
    }

    /// Append additional arguments to the kernel command line.
    pub fn cmdline_append(mut self, extra: &str) -> Self {
        if !self.cmdline.is_empty() && !extra.is_empty() {
            self.cmdline.push(' ');
        }
        self.cmdline.push_str(extra);
        self
    }

    /// Set the number of CPUs listed in the MP table.
    ///
    /// Validation is deferred to [`build()`](Self::build): setting an invalid
    /// value will produce a [`BootError::InvalidCpuCount`] at build time.
    pub const fn num_cpus(mut self, num_cpus: usize) -> Self {
        self.num_cpus = num_cpus;
        self
    }

    /// Set virtio MMIO device descriptors (x86: ignored — devices discovered via cmdline).
    pub const fn virtio_devices(self, _devices: &[(u64, u32)]) -> Self {
        self
    }

    /// Declare extra memory regions (x86: ignored — no DTB).
    pub const fn extra_memory(self, _regions: &[(u64, u64)]) -> Self {
        self
    }

    /// Build the boot configuration and set up guest memory.
    pub fn build(self) -> Result<BootResult> {
        setup_linux_boot(self.boot_mem, self.kernel, &self.cmdline, self.num_cpus)
    }
}

// =============================================================================
// Main Entry Point
// =============================================================================

/// Set up everything needed to boot a Linux kernel in 64-bit mode.
pub fn setup_linux_boot(
    mut boot_mem: BootGuestMemory<'_>,
    kernel: &[u8],
    cmdline: &str,
    num_cpus: usize,
) -> Result<BootResult> {
    if boot_mem.layout().backing_len() < MINIMUM_MEMORY_SIZE {
        return Err(BootError::MemoryTooSmall {
            size: boot_mem.layout().backing_len(),
        });
    }

    let max_cpus = crate::x86_64::mptable::max_mptable_cpus();
    if num_cpus == 0 || num_cpus > max_cpus {
        return Err(BootError::InvalidCpuCount {
            requested: num_cpus,
            max: max_cpus,
        });
    }

    let entry_point = load_elf_kernel(&mut boot_mem, kernel)?;
    setup_boot_params(&mut boot_mem, cmdline)?;

    setup_page_tables(&mut boot_mem)?;
    setup_gdt(&mut boot_mem)?;
    setup_mptable(&mut boot_mem, num_cpus)?;

    let cpu_state = setup_cpu_state(entry_point);

    Ok(BootResult {
        cpu_state,
        entry_point,
    })
}

// =============================================================================
// ELF Kernel Loading
// =============================================================================

pub fn load_elf_kernel(mem: &mut BootGuestMemory<'_>, kernel: &[u8]) -> Result<u64> {
    use goblin::elf::{Elf, header::EM_X86_64, program_header::PT_LOAD};

    let elf = Elf::parse(kernel).map_err(|e| BootError::ElfParse(e.to_string()))?;

    if !elf.is_64 {
        return Err(BootError::Not64Bit);
    }

    if elf.header.e_machine != EM_X86_64 {
        return Err(BootError::ElfParse(format!(
            "expected x86_64 ELF (machine type {}), got {}",
            EM_X86_64, elf.header.e_machine
        )));
    }

    for phdr in &elf.program_headers {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let file_offset = usize::try_from(phdr.p_offset)
            .map_err(|_| BootError::ElfParse("segment file offset does not fit usize".into()))?;
        let file_size = usize::try_from(phdr.p_filesz)
            .map_err(|_| BootError::ElfParse("segment file size does not fit usize".into()))?;
        let phys_addr = phdr.p_paddr;
        let mem_size_seg = usize::try_from(phdr.p_memsz)
            .map_err(|_| BootError::ElfParse("segment memory size does not fit usize".into()))?;

        let seg_end = phys_addr
            .checked_add(phdr.p_memsz)
            .ok_or_else(|| BootError::KernelTooLarge {
                addr: phys_addr,
                size: mem_size_seg,
                mem_size: mem.layout().backing_len(),
            })?;
        validate_kernel_segment_layout(phys_addr, seg_end)?;
        let guest_addr = GuestPhysAddr::new(phys_addr);
        let guest_range = guest_addr.range(mem_size_seg)?;
        mem.layout().translate(guest_range)?;

        let file_end = file_offset
            .checked_add(file_size)
            .ok_or_else(|| BootError::ElfParse("segment file offset + size overflows".into()))?;
        if file_end > kernel.len() {
            return Err(BootError::ElfParse(
                "segment file range exceeds kernel image".into(),
            ));
        }

        if file_size > mem_size_seg {
            return Err(BootError::ElfParse(
                "segment file size exceeds memory size".into(),
            ));
        }

        if file_size > 0 {
            let src = &kernel[file_offset..file_offset + file_size];
            mem.write_guest(guest_addr, src)?;
        }

        if mem_size_seg > file_size {
            let bss_size = mem_size_seg - file_size;
            let bss_addr = guest_addr.checked_add_u64(file_size as u64)?;
            mem.zero_guest(bss_addr.range(bss_size)?)?;
        }
    }

    Ok(elf.entry)
}

const fn validate_kernel_segment_layout(segment_start: u64, segment_end: u64) -> Result<()> {
    let low_boot_end = HIGH_MEMORY_START;
    if segment_start < segment_end && segment_start < low_boot_end {
        return Err(BootError::KernelOverlapsBootRegion {
            segment_start,
            segment_end,
            region: "low boot memory",
            region_start: 0,
            region_end: low_boot_end,
        });
    }
    Ok(())
}

// =============================================================================
// Boot Parameters (Zero Page)
// =============================================================================

pub fn setup_boot_params(mem: &mut BootGuestMemory<'_>, cmdline: &str) -> Result<()> {
    if cmdline.len() >= CMDLINE_MAX_SIZE {
        return Err(BootError::CmdlineTooLong {
            len: cmdline.len(),
            max: CMDLINE_MAX_SIZE - 1,
        });
    }

    mem.zero_guest(GuestPhysAddr::new(ZERO_PAGE_ADDR).range(4096)?)?;

    mem.write_u16_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_VERSION),
        BOOT_PROTOCOL_VERSION,
    )?;
    mem.write_u32_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_HEADER_MAGIC),
        BZIMAGE_MAGIC,
    )?;
    mem.write_u8_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_TYPE_OF_LOADER),
        LOADER_TYPE_UNDEFINED,
    )?;
    mem.write_u8_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_LOADFLAGS),
        LOAD_FLAGS,
    )?;
    mem.write_u16_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_BOOT_FLAG),
        BOOT_SIGNATURE,
    )?;
    mem.write_u32_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_CMD_LINE_PTR),
        CMDLINE_ADDR as u32,
    )?;
    mem.write_u32_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_CMDLINE_SIZE),
        CMDLINE_MAX_SIZE as u32,
    )?;

    mem.write_guest(GuestPhysAddr::new(CMDLINE_ADDR), cmdline.as_bytes())?;
    mem.write_u8_guest(GuestPhysAddr::new(CMDLINE_ADDR + cmdline.len() as u64), 0)?;

    let e820 = mem.layout().e820_map()?;
    for (entry_idx, entry) in e820.entries().iter().enumerate() {
        write_e820_entry(
            mem,
            GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_E820_TABLE + entry_idx as u64 * E820_ENTRY_SIZE),
            entry.addr,
            entry.size,
            entry.mem_type.as_u32(),
        )?;
    }

    mem.write_u8_guest(
        GuestPhysAddr::new(ZERO_PAGE_ADDR + BP_E820_ENTRIES),
        e820.entries().len() as u8,
    )?;

    Ok(())
}

fn write_e820_entry(
    mem: &mut BootGuestMemory<'_>,
    offset: GuestPhysAddr,
    addr: u64,
    size: u64,
    mem_type: u32,
) -> Result<()> {
    mem.write_u64_guest(offset, addr)?;
    mem.write_u64_guest(offset.checked_add_u64(8)?, size)?;
    mem.write_u32_guest(offset.checked_add_u64(16)?, mem_type)?;
    Ok(())
}
