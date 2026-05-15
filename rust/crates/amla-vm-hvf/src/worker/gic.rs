// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Thin adapter around the userspace `amla-vm-gic` crate.

pub(crate) use amla_vm_gic::GicConfig;
pub(crate) use amla_vm_gic::GicState;
pub(crate) use amla_vm_gic::GicV3;
pub(crate) use amla_vm_gic::InterruptSink;
pub(crate) use amla_vm_gic::{GICD_BASE, GICR_BASE};

/// ARM generic virtual timer interrupt (PPI 27).
pub(crate) const VTIMER_PPI: u32 = 27;
