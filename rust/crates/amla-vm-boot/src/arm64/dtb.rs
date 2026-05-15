// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 Device Tree Blob (DTB) generation.
//!
//! Generates a Flattened Device Tree for ARM64 VMs, matching the layout
//! of QEMU `-M virt` so Linux boots without modification.
//!
//! # Memory Map (IPA space, default `ram_base = 0x4000_0000`)
//!
//! ```text
//! Address         Device
//! ────────────────────────────────
//! 0x0800_0000     GICv3 distributor (64 KiB)
//! 0x080A_0000     GICv3 redistributor (N × 128 KiB)
//! 0x0900_0000     PL011 UART (4 KiB)
//! 0x0901_0000     PL031 RTC (4 KiB)
//! 0x0A00_0000+    Virtio MMIO devices (512 bytes each)
//! 0x4000_0000+    RAM (configurable via `ram_base`)
//! ```

use vm_fdt::{FdtReserveEntry, FdtWriter};

use crate::arm64::error::{BootError, Result};
use crate::arm64::irq::{Arm64IrqAllocator, GicSpi};

// --- Physical addresses (matching QEMU virt machine) ---

/// `GICv3` distributor base address.
const GICD_BASE: u64 = 0x0800_0000;
/// `GICv3` distributor size.
const GICD_SIZE: u64 = 0x1_0000; // 64 KiB

/// `GICv3` redistributor base address.
const GICR_BASE: u64 = 0x080A_0000;
/// `GICv3` redistributor size per CPU (2 × 64 KiB frames).
const GICR_PER_CPU: u64 = 0x2_0000; // 128 KiB

/// PL011 UART base address.
const UART_BASE: u64 = 0x0900_0000;
/// PL011 UART region size.
const UART_SIZE: u64 = 0x1000; // 4 KiB
/// PL031 RTC base address (immediately after UART).
const RTC_BASE: u64 = 0x0901_0000;
/// PL031 RTC region size.
const RTC_SIZE: u64 = 0x1000; // 4 KiB

// --- GIC interrupt type constants ---

/// SPI (Shared Peripheral Interrupt) type for interrupt-cells.
const GIC_SPI: u32 = 0;
/// PPI (Private Peripheral Interrupt) type for interrupt-cells.
const GIC_PPI: u32 = 1;
/// `IRQ_TYPE_LEVEL_HIGH` — standard for devices and timer PPIs.
const IRQ_TYPE_LEVEL_HIGH: u32 = 4;

// --- Phandle constants ---

const PHANDLE_GIC: u32 = 1;
const PHANDLE_APB_PCLK: u32 = 2;

/// A virtio-mmio device described in the ARM64 DTB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioMmioDtbDevice {
    /// Device MMIO base address.
    pub base: u64,
    /// Device SPI interrupt number.
    pub spi: GicSpi,
}

/// Configuration for DTB generation.
pub struct DtbConfig<'a> {
    /// Total guest memory in bytes.
    pub mem_size: u64,
    /// Number of vCPUs.
    pub num_cpus: usize,
    /// Kernel command line.
    pub cmdline: &'a str,
    /// Virtio MMIO devices with allocator-owned SPI assignments.
    pub virtio_devices: &'a [VirtioMmioDtbDevice],
    /// Base IPA of guest RAM (default: `0x4000_0000`).
    pub ram_base: u64,
    /// Extra memory regions (GPA, size) — pmem, ring buffer, etc.
    /// Declared as separate `memory@` nodes so the kernel's `/dev/mem`
    /// maps them with normal cached semantics (not device/uncached).
    pub extra_memory: &'a [(u64, u64)],
}

/// Generate a Flattened Device Tree Blob for an ARM64 VM.
///
/// The generated DTB describes a QEMU-virt-compatible machine with:
/// - `GICv3` interrupt controller
/// - PL011 UART at `0x0900_0000`
/// - PSCI for CPU power management
/// - ARM generic timer
/// - Virtio MMIO devices
///
/// # Errors
///
/// Returns [`BootError::DtbGeneration`] if `num_cpus` is zero, exceeds
/// `u32::MAX`, or the underlying FDT writer fails.
pub fn generate_dtb(config: &DtbConfig<'_>) -> Result<Vec<u8>> {
    if config.num_cpus == 0 {
        return Err(BootError::DtbGeneration(
            "num_cpus must be at least 1 vCPU".into(),
        ));
    }
    let num_cpus_u32: u32 = config.num_cpus.try_into().map_err(|_| {
        BootError::DtbGeneration(format!("num_cpus {} exceeds u32::MAX", config.num_cpus))
    })?;

    // Validate GICR region doesn't overlap UART.
    // Max vCPUs: (UART_BASE - GICR_BASE) / GICR_PER_CPU = 123
    let gicr_end = GICR_BASE + GICR_PER_CPU * u64::from(num_cpus_u32);
    if gicr_end > UART_BASE {
        return Err(BootError::DtbGeneration(format!(
            "GICR region [{GICR_BASE:#x}..{gicr_end:#x}) overlaps UART at {UART_BASE:#x} \
             (max {} vCPUs)",
            (UART_BASE - GICR_BASE) / GICR_PER_CPU,
        )));
    }

    // Reserve extra memory regions so the kernel doesn't allocate pages from them.
    // These are declared as memory nodes (for cached mmap semantics in /dev/mem)
    // AND as memreserve entries (to prevent kernel allocation).
    let reservations: Vec<FdtReserveEntry> = config
        .extra_memory
        .iter()
        .filter_map(|&(base, size)| FdtReserveEntry::new(base, size).ok())
        .collect();
    let mut fdt = FdtWriter::new_with_mem_reserv(&reservations)?;

    // --- Root node ---
    let root = fdt.begin_node("")?;
    fdt.property_string("compatible", "linux,dummy-virt")?;
    fdt.property_u32("#address-cells", 2)?;
    fdt.property_u32("#size-cells", 2)?;

    // --- /chosen ---
    write_chosen_node(&mut fdt, config)?;

    // --- /memory ---
    write_memory_node(&mut fdt, config.ram_base, config.mem_size)?;

    // --- /cpus ---
    write_cpus_node(&mut fdt, num_cpus_u32)?;

    // --- /psci ---
    write_psci_node(&mut fdt)?;

    // --- /intc (GICv3) ---
    write_gic_node(&mut fdt, num_cpus_u32)?;

    // --- /timer ---
    write_timer_node(&mut fdt)?;

    // --- /apb-pclk (fixed clock for AMBA devices) ---
    write_apb_pclk_node(&mut fdt)?;

    // --- /pl011 UART ---
    write_uart_node(&mut fdt)?;
    write_rtc_node(&mut fdt)?;

    // --- /virtio_mmio devices ---
    for device in config.virtio_devices {
        write_virtio_mmio_node(&mut fdt, device)?;
    }

    // --- Extra memory regions (ring buffer, etc.) ---
    // Declared as both memory nodes (so kernel maps with cached attributes)
    // and memreserve entries (so kernel doesn't allocate pages from them).
    for &(base, size) in config.extra_memory {
        write_memory_node(&mut fdt, base, size)?;
    }

    fdt.end_node(root)?;
    Ok(fdt.finish()?)
}

fn write_chosen_node(fdt: &mut FdtWriter, config: &DtbConfig<'_>) -> Result<()> {
    let chosen = fdt.begin_node("chosen")?;
    fdt.property_string("bootargs", config.cmdline)?;
    // stdout-path points at the PL011 UART
    fdt.property_string("stdout-path", "/pl011@9000000")?;

    fdt.end_node(chosen)?;
    Ok(())
}

fn write_memory_node(fdt: &mut FdtWriter, ram_base: u64, mem_size: u64) -> Result<()> {
    let name = format!("memory@{ram_base:x}");
    let mem = fdt.begin_node(&name)?;
    fdt.property_string("device_type", "memory")?;
    // reg = <base_hi base_lo size_hi size_lo>
    fdt.property_array_u64("reg", &[ram_base, mem_size])?;
    fdt.end_node(mem)?;
    Ok(())
}

fn write_cpus_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    let cpus = fdt.begin_node("cpus")?;
    fdt.property_u32("#address-cells", 1)?;
    fdt.property_u32("#size-cells", 0)?;

    for i in 0..num_cpus {
        let name = format!("cpu@{i}");
        let cpu = fdt.begin_node(&name)?;
        fdt.property_string("device_type", "cpu")?;
        fdt.property_string("compatible", "arm,arm-v8")?;
        fdt.property_u32("reg", i)?;
        if num_cpus > 1 {
            fdt.property_string("enable-method", "psci")?;
        }
        fdt.end_node(cpu)?;
    }

    fdt.end_node(cpus)?;
    Ok(())
}

fn write_psci_node(fdt: &mut FdtWriter) -> Result<()> {
    let psci = fdt.begin_node("psci")?;
    fdt.property_string("compatible", "arm,psci-1.0")?;
    fdt.property_string("method", "hvc")?;
    fdt.end_node(psci)?;
    Ok(())
}

fn write_gic_node(fdt: &mut FdtWriter, num_cpus: u32) -> Result<()> {
    let gic = fdt.begin_node("intc@8000000")?;
    fdt.property_string("compatible", "arm,gic-v3")?;
    fdt.property_phandle(PHANDLE_GIC)?;
    fdt.property_null("interrupt-controller")?;
    // 3 cells: type (SPI/PPI), number, flags
    fdt.property_u32("#interrupt-cells", 3)?;
    fdt.property_u32("#address-cells", 0)?;

    let gicr_size = GICR_PER_CPU * u64::from(num_cpus);
    fdt.property_array_u64("reg", &[GICD_BASE, GICD_SIZE, GICR_BASE, gicr_size])?;

    fdt.end_node(gic)?;
    Ok(())
}

fn write_timer_node(fdt: &mut FdtWriter) -> Result<()> {
    let timer = fdt.begin_node("timer")?;
    fdt.property_string("compatible", "arm,armv8-timer")?;
    fdt.property_null("always-on")?;

    // 4 timer interrupts (all PPIs): secure phys, non-secure phys, virt, hyp
    // PPI numbers: 13, 14, 11, 10 (as per ARM spec)
    // LEVEL_HIGH matches QEMU virt DTB. Linux >= 4.8 ignores the flag and
    // always configures timers as level-triggered, but older kernels rely on it.
    #[rustfmt::skip]
    let interrupts: &[u32] = &[
        GIC_PPI, 13, IRQ_TYPE_LEVEL_HIGH,  // Secure physical timer
        GIC_PPI, 14, IRQ_TYPE_LEVEL_HIGH,  // Non-secure physical timer
        GIC_PPI, 11, IRQ_TYPE_LEVEL_HIGH,  // Virtual timer
        GIC_PPI, 10, IRQ_TYPE_LEVEL_HIGH,  // Hypervisor timer
    ];
    fdt.property_array_u32("interrupts", interrupts)?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;

    fdt.end_node(timer)?;
    Ok(())
}

/// Fixed 24 MHz clock for AMBA/PrimeCell devices (PL011, PL031).
/// AMBA bus probing requires a `clocks`/`clock-names` reference.
fn write_apb_pclk_node(fdt: &mut FdtWriter) -> Result<()> {
    let clk = fdt.begin_node("apb-pclk")?;
    fdt.property_string("compatible", "fixed-clock")?;
    fdt.property_u32("#clock-cells", 0)?;
    fdt.property_u32("clock-frequency", 24_000_000)?;
    fdt.property_string("clock-output-names", "clk24mhz")?;
    fdt.property_u32("phandle", PHANDLE_APB_PCLK)?;
    fdt.end_node(clk)?;
    Ok(())
}

fn write_uart_node(fdt: &mut FdtWriter) -> Result<()> {
    let irq = Arm64IrqAllocator::new().uart();
    let uart = fdt.begin_node("pl011@9000000")?;
    fdt.property_string("compatible", "arm,pl011")?;
    fdt.property_array_u64("reg", &[UART_BASE, UART_SIZE])?;
    fdt.property_array_u32("interrupts", &[GIC_SPI, irq.dtb_spi(), IRQ_TYPE_LEVEL_HIGH])?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.end_node(uart)?;
    Ok(())
}

fn write_rtc_node(fdt: &mut FdtWriter) -> Result<()> {
    let irq = Arm64IrqAllocator::new().rtc();
    let rtc = fdt.begin_node("pl031@9010000")?;
    fdt.property_string_list(
        "compatible",
        vec!["arm,pl031".into(), "arm,primecell".into()],
    )?;
    fdt.property_array_u64("reg", &[RTC_BASE, RTC_SIZE])?;
    fdt.property_array_u32("interrupts", &[GIC_SPI, irq.dtb_spi(), IRQ_TYPE_LEVEL_HIGH])?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.property_u32("clocks", PHANDLE_APB_PCLK)?;
    fdt.property_string("clock-names", "apb_pclk")?;
    fdt.end_node(rtc)?;
    Ok(())
}

fn write_virtio_mmio_node(fdt: &mut FdtWriter, device: &VirtioMmioDtbDevice) -> Result<()> {
    let base = device.base;
    let name = format!("virtio_mmio@{base:x}");
    let node = fdt.begin_node(&name)?;
    fdt.property_string("compatible", "virtio,mmio")?;
    // Standard virtio-mmio region: 512 bytes
    fdt.property_array_u64("reg", &[base, 0x200])?;
    fdt.property_array_u32(
        "interrupts",
        &[GIC_SPI, device.spi.get(), IRQ_TYPE_LEVEL_HIGH],
    )?;
    fdt.property_u32("interrupt-parent", PHANDLE_GIC)?;
    fdt.end_node(node)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_config() -> DtbConfig<'static> {
        DtbConfig {
            mem_size: 256 * 1024 * 1024,
            num_cpus: 2,
            cmdline: "console=ttyAMA0",
            virtio_devices: &[],
            ram_base: 0x4000_0000,
            extra_memory: &[],
        }
    }

    #[test]
    fn generate_minimal_dtb() {
        let config = basic_config();
        let dtb = generate_dtb(&config).unwrap();
        // FDT magic: 0xd00dfeed (big-endian)
        assert_eq!(&dtb[..4], &[0xd0, 0x0d, 0xfe, 0xed]);
        // Sanity: DTB should be non-trivial size
        assert!(dtb.len() > 200, "DTB too small: {} bytes", dtb.len());
    }

    #[test]
    fn generate_dtb_with_virtio_devices() {
        let alloc = Arm64IrqAllocator::new();
        let devices = [
            VirtioMmioDtbDevice {
                base: 0x0A00_0000,
                spi: alloc.virtio_mmio(0).unwrap().spi(),
            },
            VirtioMmioDtbDevice {
                base: 0x0A00_0200,
                spi: alloc.virtio_mmio(1).unwrap().spi(),
            },
            VirtioMmioDtbDevice {
                base: 0x0A00_0400,
                spi: alloc.virtio_mmio(2).unwrap().spi(),
            },
        ];
        let config = DtbConfig {
            virtio_devices: &devices,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(!dtb.is_empty());
    }

    #[test]
    fn generate_dtb_single_cpu() {
        let config = DtbConfig {
            num_cpus: 1,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(!dtb.is_empty());
    }

    #[test]
    fn generate_dtb_many_cpus() {
        let config = DtbConfig {
            num_cpus: 8,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(!dtb.is_empty());
    }

    #[test]
    fn generate_dtb_rejects_zero_cpus() {
        let config = DtbConfig {
            num_cpus: 0,
            ..basic_config()
        };
        assert!(generate_dtb(&config).is_err());
    }

    #[test]
    fn generate_dtb_rejects_too_many_cpus_gicr_overlap() {
        // 124 vCPUs: GICR end = 0x080A_0000 + 124 * 0x2_0000 = 0x0F8A_0000 > UART 0x0900_0000
        let config = DtbConfig {
            num_cpus: 124,
            ..basic_config()
        };
        let err = generate_dtb(&config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("GICR") && msg.contains("UART"),
            "Expected GICR/UART overlap error, got: {msg}"
        );
    }

    #[test]
    fn generate_dtb_max_cpus_123() {
        // 123 vCPUs should fit: GICR end = 0x080A_0000 + 123 * 0x2_0000 = 0x08FC_0000 <= 0x0900_0000
        let config = DtbConfig {
            num_cpus: 123,
            ..basic_config()
        };
        assert!(generate_dtb(&config).is_ok());
    }

    #[test]
    fn generate_dtb_custom_ram_base() {
        let config = DtbConfig {
            ram_base: 0x8000_0000,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(!dtb.is_empty());
    }

    #[test]
    fn generate_dtb_zero_ram_base() {
        let config = DtbConfig {
            ram_base: 0,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(!dtb.is_empty());
    }

    #[test]
    fn dtb_contains_expected_strings() {
        let config = basic_config();
        let dtb = generate_dtb(&config).unwrap();
        // Check that key strings are present in the DTB blob
        let dtb_str = String::from_utf8_lossy(&dtb);
        assert!(dtb_str.contains("linux,dummy-virt"));
        assert!(dtb_str.contains("arm,gic-v3"));
        assert!(dtb_str.contains("arm,pl011"));
        assert!(dtb_str.contains("arm,armv8-timer"));
        assert!(dtb_str.contains("arm,psci-1.0"));
        assert!(dtb_str.contains("console=ttyAMA0"));
    }

    #[test]
    fn dtb_size_reasonable() {
        // With 4 CPUs and 4 virtio devices, DTB should be under 8KB
        let alloc = Arm64IrqAllocator::new();
        let devices = [
            VirtioMmioDtbDevice {
                base: 0x0A00_0000,
                spi: alloc.virtio_mmio(0).unwrap().spi(),
            },
            VirtioMmioDtbDevice {
                base: 0x0A00_0200,
                spi: alloc.virtio_mmio(1).unwrap().spi(),
            },
            VirtioMmioDtbDevice {
                base: 0x0A00_0400,
                spi: alloc.virtio_mmio(2).unwrap().spi(),
            },
            VirtioMmioDtbDevice {
                base: 0x0A00_0600,
                spi: alloc.virtio_mmio(3).unwrap().spi(),
            },
        ];
        let config = DtbConfig {
            num_cpus: 4,
            virtio_devices: &devices,
            ..basic_config()
        };
        let dtb = generate_dtb(&config).unwrap();
        assert!(
            dtb.len() < 8192,
            "DTB unexpectedly large: {} bytes",
            dtb.len()
        );
    }

    // COV-6: num_cpus = usize::MAX triggers try_into failure
    #[test]
    fn generate_dtb_rejects_usize_max_cpus() {
        let config = DtbConfig {
            num_cpus: usize::MAX,
            ..basic_config()
        };
        let err = generate_dtb(&config).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("exceeds u32::MAX"),
            "expected u32 overflow error, got: {msg}"
        );
    }

    // COV-1: From<vm_fdt::Error> conversion
    #[test]
    fn vm_fdt_error_converts_to_boot_error() {
        // Trigger a vm-fdt error by constructing one
        let vm_err = vm_fdt::Error::InvalidString;
        let boot_err: BootError = vm_err.into();
        let msg = boot_err.to_string();
        assert!(
            msg.contains("DTB generation error"),
            "expected DtbGeneration variant, got: {msg}"
        );
    }
}
