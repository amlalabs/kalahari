// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 platform IRQ allocation.
//!
//! `GICv3` describes Shared Peripheral Interrupts (SPIs) in three related
//! number spaces:
//! - DTB interrupt cells use a zero-based SPI number.
//! - Architectural INTIDs add 32 to that SPI number.
//! - The KVM/HVF backends use the same zero-based SPI number as their device
//!   IRQ line key, then inject `SPI_START_INTID + spi`.

/// First architectural INTID used by `GICv3` SPIs.
pub const GIC_SPI_START_INTID: u32 = 32;

/// Number of SPIs modeled by the AMLA ARM64 platform.
///
/// This must match the fixed-size GIC snapshot POD layouts.
pub const GIC_SPI_COUNT: u32 = 64;

/// Total number of interrupt IDs modeled by the AMLA ARM64 platform.
pub const GIC_NR_IRQS: u32 = GIC_SPI_START_INTID + GIC_SPI_COUNT;

/// PL011 UART SPI number.
pub const UART_SPI: GicSpi = GicSpi::new_unchecked(1);

/// PL031 RTC SPI number.
pub const RTC_SPI: GicSpi = GicSpi::new_unchecked(2);

/// First SPI reserved for virtio-mmio devices.
pub const VIRTIO_MMIO_SPI_BASE: u32 = 16;

/// Maximum number of virtio-mmio IRQs in the ARM64 platform layout.
pub const MAX_VIRTIO_MMIO_IRQS: usize = (GIC_SPI_COUNT - VIRTIO_MMIO_SPI_BASE) as usize;

const fn const_true(condition: bool) -> usize {
    if condition { 1 } else { 0 }
}

const _: [(); 1] = [(); const_true(UART_SPI.get() < VIRTIO_MMIO_SPI_BASE)];
const _: [(); 1] = [(); const_true(RTC_SPI.get() < VIRTIO_MMIO_SPI_BASE)];
const _: [(); 1] = [(); const_true(VIRTIO_MMIO_SPI_BASE < GIC_SPI_COUNT)];

/// A zero-based `GICv3` SPI number.
///
/// This is the value stored in DTB `interrupts = <GIC_SPI N ...>` cells and in
/// GIC distributor SPI-indexed register arrays.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct GicSpi(u32);

impl GicSpi {
    /// Create a SPI number after validating it fits the platform GIC.
    pub const fn new(spi: u32) -> Result<Self, IrqAllocError> {
        if spi < GIC_SPI_COUNT {
            Ok(Self(spi))
        } else {
            Err(IrqAllocError::SpiOutOfRange { spi })
        }
    }

    const fn new_unchecked(spi: u32) -> Self {
        Self(spi)
    }

    /// Return the zero-based SPI number.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Convert this SPI number to its architectural GIC INTID.
    pub const fn to_intid(self) -> GicIntid {
        GicIntid(GIC_SPI_START_INTID + self.0)
    }
}

/// An architectural `GICv3` interrupt ID.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct GicIntid(u32);

impl GicIntid {
    /// Create an INTID after validating it is an SPI INTID modeled by this platform.
    pub const fn new(intid: u32) -> Result<Self, IrqAllocError> {
        if intid < GIC_SPI_START_INTID || intid >= GIC_NR_IRQS {
            Err(IrqAllocError::IntidOutOfRange { intid })
        } else {
            Ok(Self(intid))
        }
    }

    /// Return the architectural INTID.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Convert this INTID to its zero-based SPI number.
    pub const fn to_spi(self) -> GicSpi {
        GicSpi(self.0 - GIC_SPI_START_INTID)
    }
}

/// A platform IRQ assigned to an ARM64 device.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Arm64Irq {
    spi: GicSpi,
}

impl Arm64Irq {
    const fn new(spi: GicSpi) -> Self {
        Self { spi }
    }

    /// Return the DTB-compatible SPI interrupt-cell value.
    pub const fn dtb_spi(self) -> u32 {
        self.spi.get()
    }

    /// Return the backend IRQ line key used for KVM irqfd and HVF IPC.
    pub const fn backend_gsi(self) -> u32 {
        self.spi.get()
    }

    /// Return the architectural `GICv3` INTID injected into the guest.
    pub const fn gic_intid(self) -> u32 {
        self.spi.to_intid().get()
    }

    /// Return the underlying zero-based SPI number.
    pub const fn spi(self) -> GicSpi {
        self.spi
    }
}

/// Stateless allocator for the fixed AMLA ARM64 interrupt layout.
#[derive(Clone, Copy, Debug, Default)]
pub struct Arm64IrqAllocator;

impl Arm64IrqAllocator {
    /// Create a new allocator.
    pub const fn new() -> Self {
        Self
    }

    /// IRQ assigned to the PL011 UART.
    pub const fn uart(self) -> Arm64Irq {
        Arm64Irq::new(UART_SPI)
    }

    /// IRQ assigned to the PL031 RTC.
    pub const fn rtc(self) -> Arm64Irq {
        Arm64Irq::new(RTC_SPI)
    }

    /// IRQ assigned to a virtio-mmio device slot.
    #[allow(clippy::cast_possible_truncation)] // idx is bounded by MAX_VIRTIO_MMIO_IRQS.
    pub const fn virtio_mmio(self, idx: usize) -> Result<Arm64Irq, IrqAllocError> {
        if idx >= MAX_VIRTIO_MMIO_IRQS {
            Err(IrqAllocError::VirtioIndexOutOfRange {
                index: idx,
                max: MAX_VIRTIO_MMIO_IRQS,
            })
        } else {
            Ok(Arm64Irq::new(GicSpi::new_unchecked(
                VIRTIO_MMIO_SPI_BASE + idx as u32,
            )))
        }
    }
}

/// IRQ allocation error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IrqAllocError {
    /// SPI number exceeds the platform GIC range.
    SpiOutOfRange {
        /// Rejected SPI number.
        spi: u32,
    },
    /// INTID is not a valid SPI INTID for this platform.
    IntidOutOfRange {
        /// Rejected INTID.
        intid: u32,
    },
    /// Virtio device slot exceeds the allocated virtio IRQ range.
    VirtioIndexOutOfRange {
        /// Rejected virtio-mmio slot index.
        index: usize,
        /// Number of valid virtio-mmio IRQ slots.
        max: usize,
    },
}

impl core::fmt::Display for IrqAllocError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::SpiOutOfRange { spi } => {
                write!(
                    f,
                    "SPI {spi} is outside ARM64 GIC SPI range 0..{GIC_SPI_COUNT}"
                )
            }
            Self::IntidOutOfRange { intid } => write!(
                f,
                "INTID {intid} is outside ARM64 GIC SPI INTID range \
                 {GIC_SPI_START_INTID}..{GIC_NR_IRQS}"
            ),
            Self::VirtioIndexOutOfRange { index, max } => {
                write!(f, "virtio-mmio index {index} exceeds ARM64 IRQ slots {max}")
            }
        }
    }
}

impl std::error::Error for IrqAllocError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spi_to_intid_conversion() {
        assert_eq!(GicSpi::new(1).unwrap().to_intid().get(), 33);
        assert_eq!(GicSpi::new(16).unwrap().to_intid().get(), 48);
        assert_eq!(GicIntid::new(48).unwrap().to_spi().get(), 16);
    }

    #[test]
    fn rejects_out_of_range_numbers() {
        assert!(GicSpi::new(GIC_SPI_COUNT).is_err());
        assert!(GicIntid::new(GIC_SPI_START_INTID - 1).is_err());
        assert!(GicIntid::new(GIC_NR_IRQS).is_err());
    }

    #[test]
    fn platform_irqs_do_not_conflict_with_virtio() {
        let alloc = Arm64IrqAllocator::new();
        assert_eq!(alloc.uart().dtb_spi(), 1);
        assert_eq!(alloc.rtc().dtb_spi(), 2);

        let mut used = [false; GIC_SPI_COUNT as usize];
        used[alloc.uart().dtb_spi() as usize] = true;
        used[alloc.rtc().dtb_spi() as usize] = true;

        for idx in 0..MAX_VIRTIO_MMIO_IRQS {
            let spi = alloc.virtio_mmio(idx).unwrap().dtb_spi() as usize;
            assert!(!used[spi], "duplicate SPI {spi} at virtio slot {idx}");
            used[spi] = true;
        }

        let first = alloc.virtio_mmio(0).unwrap();
        let last = alloc.virtio_mmio(MAX_VIRTIO_MMIO_IRQS - 1).unwrap();
        assert_eq!(first.dtb_spi(), VIRTIO_MMIO_SPI_BASE);
        assert_eq!(last.dtb_spi(), GIC_SPI_COUNT - 1);
        assert_ne!(first.dtb_spi(), alloc.uart().dtb_spi());
        assert_ne!(first.dtb_spi(), alloc.rtc().dtb_spi());
        assert!(alloc.virtio_mmio(MAX_VIRTIO_MMIO_IRQS).is_err());
    }
}
