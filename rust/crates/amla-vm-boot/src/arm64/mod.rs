// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 Linux boot protocol.
//!
//! ARM64 Image header parsing, Device Tree Blob (DTB) generation
//! (GICv3, PL011, PSCI, virtio MMIO), and kernel/DTB memory placement.
//!
//! Returns initial vCPU register state for kernel entry.

/// ARM64 platform IRQ assignment.
pub mod irq;

#[cfg(target_arch = "aarch64")]
mod dtb;
#[cfg(target_arch = "aarch64")]
mod error;
#[cfg(target_arch = "aarch64")]
mod image;

#[cfg(target_arch = "aarch64")]
pub use dtb::{DtbConfig, VirtioMmioDtbDevice, generate_dtb};
#[cfg(target_arch = "aarch64")]
pub use error::{BootError, Result};
#[cfg(target_arch = "aarch64")]
pub use image::ImageHeader;

#[cfg(target_arch = "aarch64")]
use amla_core::arm64::{Arm64Reg, Arm64VcpuSnapshot};

/// Validated ARM64 RAM layout.
#[cfg(target_arch = "aarch64")]
pub type BootRamLayout = crate::boot_memory::BootRamLayout;

/// Guest physical address: the address space visible to Linux.
#[cfg(target_arch = "aarch64")]
pub type GuestPhysAddr = crate::boot_memory::GuestPhysAddr;

/// Exclusive, typed access to ARM64 guest RAM during boot setup.
#[cfg(target_arch = "aarch64")]
pub struct BootGuestMemory<'a> {
    inner: crate::boot_memory::BootGuestMemory<'a>,
}

#[cfg(target_arch = "aarch64")]
impl<'a> BootGuestMemory<'a> {
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
    /// Returns a boot-memory error if the layout does not fit in `len`.
    pub unsafe fn from_raw_parts(
        base: std::ptr::NonNull<u8>,
        len: usize,
        layout: BootRamLayout,
    ) -> Result<Self> {
        Ok(Self {
            // SAFETY: forwarded from this function's caller.
            inner: unsafe {
                crate::boot_memory::BootGuestMemory::from_raw_parts(base, len, layout)?
            },
        })
    }

    /// Construct boot memory from the validated unified VM-state mapping.
    ///
    /// # Safety
    ///
    /// The caller must ensure the RAM portion of `region` is writable and is
    /// not mutably aliased while the returned boot-memory capability is alive.
    ///
    /// # Errors
    ///
    /// Returns a boot-memory error if the RAM range described by `view` is
    /// outside `region`, or if the derived boot layout is invalid.
    pub unsafe fn from_vm_state(
        view: &amla_core::vm_state::VmState<'_>,
        region: &'a amla_mem::MmapSlice,
    ) -> Result<Self> {
        Ok(Self {
            // SAFETY: forwarded from this function's caller.
            inner: unsafe {
                crate::boot_memory::BootGuestMemory::from_vm_state(
                    view,
                    region,
                    amla_core::MEMORY_HOLES,
                )?
            },
        })
    }

    /// Borrow the validated RAM layout.
    #[must_use]
    pub const fn layout(&self) -> &BootRamLayout {
        self.inner.layout()
    }

    fn write_guest(&mut self, gpa: GuestPhysAddr, data: &[u8]) -> Result<()> {
        Ok(self.inner.write_guest(gpa, data)?)
    }

    fn zero_guest(&mut self, range: crate::boot_memory::GuestRange) -> Result<()> {
        Ok(self.inner.zero_guest(range)?)
    }
}

/// Minimum guest memory required for a valid ARM64 boot layout (16 MiB).
#[cfg(target_arch = "aarch64")]
const MIN_MEM_SIZE: u64 = 16 * 1024 * 1024;

/// Reserved space below top of RAM for DTB placement (2 MiB).
#[cfg(target_arch = "aarch64")]
const DTB_HEADROOM: u64 = 0x20_0000;

/// Maximum DTB size we reserve space for (2 MiB).
#[cfg(target_arch = "aarch64")]
const DTB_MAX_SIZE: u64 = 0x20_0000;

/// Result of booting an ARM64 Linux kernel.
///
/// Contains the initial vCPU state and metadata about the loaded kernel,
/// and DTB placement in guest memory.
#[cfg(target_arch = "aarch64")]
#[derive(Debug, Clone)]
pub struct BootResult {
    /// Initial vCPU register snapshot (PC, X0 set; all others zero).
    pub cpu_state: Arm64VcpuSnapshot,
    /// Guest physical address where the kernel was loaded.
    pub kernel_load_addr: u64,
    /// Guest physical address of the DTB.
    pub dtb_addr: u64,
}

/// Computed memory layout: where the kernel and DTB live
/// inside guest RAM. All addresses are already validated for alignment,
/// bounds, and mutual non-overlap by `compute_layout`.
#[cfg(target_arch = "aarch64")]
struct BootLayout {
    kernel_load_addr: u64,
    dtb_addr: u64,
}

/// Builder for ARM64 Linux boot configuration.
///
/// # Example
///
/// ```ignore
/// use amla_boot::LinuxBootBuilder;
///
/// let result = LinuxBootBuilder::new(boot_mem, &kernel)
///     .cmdline("console=ttyAMA0 init=/sbin/init")
///     .num_cpus(4)
///     .build()?;
///
/// // Kernel and DTB are written to guest memory.
/// // Apply result.cpu_state to vCPU 0.
/// ```
#[cfg(target_arch = "aarch64")]
#[must_use]
pub struct LinuxBootBuilder<'a> {
    boot_mem: BootGuestMemory<'a>,
    kernel: &'a [u8],
    cmdline: Option<&'a str>,
    num_cpus: usize,
    virtio_devices: &'a [VirtioMmioDtbDevice],
    extra_memory: &'a [(u64, u64)],
}

#[cfg(target_arch = "aarch64")]
impl<'a> LinuxBootBuilder<'a> {
    /// Create a new boot builder.
    ///
    /// # Arguments
    /// - `boot_mem`: Validated, exclusive access to guest RAM
    /// - `kernel`: Raw ARM64 Image binary
    pub fn new(boot_mem: BootGuestMemory<'a>, kernel: &'a [u8]) -> Self {
        Self {
            boot_mem,
            kernel,
            cmdline: None,
            num_cpus: 1,
            virtio_devices: &[],
            extra_memory: &[],
        }
    }

    /// Set the kernel command line (written into the DTB `/chosen` node).
    pub fn cmdline(mut self, cmdline: &'a str) -> Self {
        self.cmdline = Some(cmdline);
        self
    }

    /// Set the number of vCPUs (reflected in DTB `/cpus` node).
    pub fn num_cpus(mut self, n: usize) -> Self {
        self.num_cpus = n;
        self
    }

    /// Set virtio MMIO device descriptors.
    pub fn virtio_devices(mut self, devices: &'a [VirtioMmioDtbDevice]) -> Self {
        self.virtio_devices = devices;
        self
    }

    /// Declare extra memory regions `(gpa, size)` in the DTB.
    pub fn extra_memory(mut self, regions: &'a [(u64, u64)]) -> Self {
        self.extra_memory = regions;
        self
    }

    /// Parse the kernel Image header, generate the DTB, write kernel/DTB
    /// to guest memory, and return the initial CPU state.
    pub fn build(mut self) -> Result<BootResult> {
        let ram_segment = self.boot_mem.layout().single_ram_segment()?;
        let mem_size_u64 = u64::try_from(ram_segment.len()).map_err(|_| {
            BootError::LayoutConflict(format!(
                "RAM segment size {:#x} does not fit u64",
                ram_segment.len()
            ))
        })?;
        let ram_base = ram_segment.guest_start().as_u64();
        if mem_size_u64 < MIN_MEM_SIZE {
            return Err(BootError::MemoryTooSmall(mem_size_u64, MIN_MEM_SIZE));
        }
        let header = ImageHeader::parse(self.kernel)?;
        if header.is_big_endian() {
            return Err(BootError::UnsupportedEndianness);
        }

        let layout = self.compute_layout(ram_segment, &header)?;

        // Generate DTB.
        let dtb_config = DtbConfig {
            mem_size: mem_size_u64,
            num_cpus: self.num_cpus,
            cmdline: self.cmdline.unwrap_or(""),
            virtio_devices: self.virtio_devices,
            ram_base,
            extra_memory: self.extra_memory,
        };
        let dtb = generate_dtb(&dtb_config)?;
        if dtb.len() as u64 > DTB_MAX_SIZE {
            return Err(BootError::LayoutConflict(format!(
                "generated DTB ({} bytes) exceeds reserved space ({DTB_MAX_SIZE} bytes)",
                dtb.len(),
            )));
        }

        // Write kernel and DTB to guest memory.
        self.boot_mem
            .write_guest(GuestPhysAddr::new(layout.kernel_load_addr), self.kernel)?;
        if header.image_size > self.kernel.len() as u64 {
            let tail_start = layout
                .kernel_load_addr
                .checked_add(self.kernel.len() as u64)
                .ok_or_else(|| {
                    BootError::LayoutConflict("kernel tail start overflows address space".into())
                })?;
            let tail_len =
                usize::try_from(header.image_size - self.kernel.len() as u64).map_err(|_| {
                    BootError::LayoutConflict("kernel image tail does not fit host usize".into())
                })?;
            self.boot_mem
                .zero_guest(GuestPhysAddr::new(tail_start).range(tail_len)?)?;
        }
        self.boot_mem
            .write_guest(GuestPhysAddr::new(layout.dtb_addr), &dtb)?;

        // Build initial CPU state.
        let mut cpu_state = Arm64VcpuSnapshot::empty();
        cpu_state.gp_regs[Arm64Reg::PC.index()] = layout.kernel_load_addr;
        cpu_state.gp_regs[Arm64Reg::X0.index()] = layout.dtb_addr;
        cpu_state.gp_regs[Arm64Reg::CPSR.index()] = 0x3c5;

        Ok(BootResult {
            cpu_state,
            kernel_load_addr: layout.kernel_load_addr,
            dtb_addr: layout.dtb_addr,
        })
    }

    /// Compute placement for kernel and DTB within the guest RAM.
    /// All addresses are validated for alignment, bounds, and non-overlap.
    fn compute_layout(
        &self,
        ram_segment: crate::boot_memory::RamSegment,
        header: &ImageHeader,
    ) -> Result<BootLayout> {
        let ram_base = ram_segment.guest_start().as_u64();
        let mem_size_u64 = u64::try_from(ram_segment.len()).map_err(|_| {
            BootError::LayoutConflict(format!(
                "RAM segment size {:#x} does not fit u64",
                ram_segment.len()
            ))
        })?;
        // Kernel loaded at ram_base + text_offset.
        let kernel_load_addr = ram_base.checked_add(header.text_offset).ok_or_else(|| {
            BootError::LayoutConflict("kernel load address overflows address space".into())
        })?;
        let kernel_size = if header.image_size > 0 {
            header.image_size.max(self.kernel.len() as u64)
        } else {
            self.kernel.len() as u64
        };
        let kernel_end = kernel_load_addr.checked_add(kernel_size).ok_or_else(|| {
            BootError::LayoutConflict("kernel region overflows address space".into())
        })?;
        let ram_end = ram_base.checked_add(mem_size_u64).ok_or_else(|| {
            BootError::LayoutConflict("RAM region overflows address space".into())
        })?;
        if kernel_end > ram_end {
            return Err(BootError::LayoutConflict(format!(
                "kernel extends beyond RAM: {kernel_end:#x} > ram_end {ram_end:#x}",
            )));
        }

        // DTB placed at min(ram_base + 1 GiB, ram_end - 2 MiB).
        let dtb_addr = ram_base.saturating_add(0x4000_0000_u64).min(
            ram_end
                .checked_sub(DTB_HEADROOM)
                .ok_or(BootError::MemoryTooSmall(mem_size_u64, MIN_MEM_SIZE))?,
        );
        let dtb_end = dtb_addr.checked_add(DTB_MAX_SIZE).ok_or_else(|| {
            BootError::LayoutConflict("DTB region overflows address space".into())
        })?;
        if dtb_end > ram_end {
            return Err(BootError::LayoutConflict(format!(
                "DTB region extends beyond RAM: {dtb_end:#x} > ram_end {ram_end:#x}",
            )));
        }
        if kernel_load_addr < dtb_end && dtb_addr < kernel_end {
            return Err(BootError::LayoutConflict(format!(
                "kernel [{kernel_load_addr:#x}..{kernel_end:#x}) overlaps \
                 DTB [{dtb_addr:#x}..{dtb_end:#x})"
            )));
        }
        Ok(BootLayout {
            kernel_load_addr,
            dtb_addr,
        })
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod tests {
    use std::ptr::NonNull;

    use super::*;

    fn guest_mem(size: usize) -> Vec<u8> {
        vec![0u8; size]
    }

    fn make_valid_image(text_offset: u64) -> Vec<u8> {
        let mut img = vec![0u8; 128];
        img[56..60].copy_from_slice(b"ARM\x64");
        img[8..16].copy_from_slice(&text_offset.to_le_bytes());
        img[16..24].copy_from_slice(&128_u64.to_le_bytes());
        img
    }

    fn boot_mem(buf: &mut [u8], ram_base: u64) -> BootGuestMemory<'_> {
        let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
        let layout = BootRamLayout::from_ram(
            GuestPhysAddr::new(ram_base),
            buf.len(),
            amla_core::MemoryHoles::EMPTY,
        )
        .unwrap();
        // SAFETY: `buf` is writable and uniquely borrowed for the returned boot memory.
        unsafe { BootGuestMemory::from_raw_parts(ptr, buf.len(), layout).unwrap() }
    }

    #[test]
    fn build_sets_pc_and_x0() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, 0);
        let result = LinuxBootBuilder::new(mem, &kernel)
            .cmdline("console=ttyAMA0")
            .num_cpus(2)
            .build()
            .unwrap();

        assert_eq!(result.cpu_state.gp_regs[Arm64Reg::PC.index()], 0x8_0000);
        assert_ne!(result.cpu_state.gp_regs[Arm64Reg::X0.index()], 0);
        assert_eq!(result.kernel_load_addr, 0x8_0000);
    }

    #[test]
    fn build_writes_kernel_to_memory() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, 0);
        let result = LinuxBootBuilder::new(mem, &kernel).build().unwrap();

        // Check kernel bytes were written at kernel_load_addr offset.
        let offset = result.kernel_load_addr as usize;
        assert_eq!(&buf[offset..offset + 4], &kernel[..4]);
    }

    #[test]
    fn build_uses_layout_ram_base() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let ram_base = 0x5000_0000;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, ram_base);
        let result = LinuxBootBuilder::new(mem, &kernel).build().unwrap();

        assert_eq!(result.kernel_load_addr, ram_base + 0x8_0000);
        assert_eq!(&buf[0x8_0000..0x8_0004], &kernel[..4]);
    }

    #[test]
    fn build_rejects_sparse_ram_layout() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let ptr = NonNull::new(buf.as_mut_ptr()).unwrap();
        let holes = [amla_core::MemoryHole {
            start: 0x1000_0000,
            end: 0x1001_0000,
            advertise_reserved: false,
        }];
        let layout = BootRamLayout::from_ram(
            GuestPhysAddr::new(0),
            mem_size,
            amla_core::MemoryHoles::new(&holes).unwrap(),
        )
        .unwrap();
        // SAFETY: `buf` is writable and uniquely borrowed for this test boot memory.
        let mem = unsafe { BootGuestMemory::from_raw_parts(ptr, buf.len(), layout) }.unwrap();
        let err = LinuxBootBuilder::new(mem, &kernel).build().unwrap_err();

        assert!(matches!(err, BootError::BootMemory(_)));
    }

    #[test]
    fn build_rejects_too_small_kernel() {
        let kernel = vec![0u8; 32];
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, 0);
        assert!(LinuxBootBuilder::new(mem, &kernel).build().is_err());
    }

    #[test]
    fn build_rejects_too_small_memory() {
        let kernel = make_valid_image(0x8_0000);
        let mut buf = guest_mem(128);
        let mem = boot_mem(&mut buf, 0);
        assert!(matches!(
            LinuxBootBuilder::new(mem, &kernel).build(),
            Err(BootError::MemoryTooSmall(128, _))
        ));
    }

    #[test]
    fn build_rejects_zero_cpus() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, 0);
        let err = LinuxBootBuilder::new(mem, &kernel)
            .num_cpus(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("at least 1 vCPU"));
    }

    #[test]
    fn build_sets_cpsr_el1h() {
        let kernel = make_valid_image(0x8_0000);
        let mem_size = 512 * 1024 * 1024;
        let mut buf = guest_mem(mem_size);
        let mem = boot_mem(&mut buf, 0);
        let result = LinuxBootBuilder::new(mem, &kernel).build().unwrap();
        assert_eq!(result.cpu_state.gp_regs[Arm64Reg::CPSR.index()], 0x3c5);
    }
}
