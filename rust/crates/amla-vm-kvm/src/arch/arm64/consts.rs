// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 architecture constants for interrupt routing.

/// Number of `GICv3` SPI (Shared Peripheral Interrupt) lines modeled by AMLA.
pub const IRQ_LINE_COUNT: u32 = amla_boot::arm64::irq::GIC_SPI_COUNT;

/// First architectural INTID used by `GICv3` SPIs.
pub const GIC_SPI_START_INTID: u32 = amla_boot::arm64::irq::GIC_SPI_START_INTID;
