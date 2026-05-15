// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! repr(C) VM state layout for mmap'd freeze/spawn.
//!
//! This module defines the binary layout of a unified VM state region.
//! All mutable VM state — device transport, device-specific data, vCPU
//! registers, irqchip, ring buffer, and guest RAM — lives in a single
//! contiguous region that can be CoW-branched for instant spawn.
//!
//! # Design Principles
//!
//! - **Platform-agnostic**: Works with any already-mapped `*mut u8` region.
//! - **POD only**: All structs are `#[repr(C)]` + `bytemuck::{Pod, Zeroable}`.
//! - **Fixed-size**: Every field has a compile-time-known size.
//! - **Page-aligned sections**: Each major section starts on a 16 KiB boundary.

mod device_meta;
pub mod guest_mem;
mod header;
mod irqchip;
mod layout;
pub mod pfn;
mod ram_descriptor;
mod view;

pub use device_meta::*;
pub use guest_mem::*;
pub use header::*;
pub use irqchip::*;
pub use layout::*;
pub use ram_descriptor::*;
pub use view::*;

/// Assert at compile time that a backend's `VcpuSnapshot` type fits in `VCPU_SLOT_SIZE`.
#[macro_export]
macro_rules! assert_vcpu_fits {
    ($ty:ty) => {
        const _: () = assert!(
            core::mem::size_of::<$ty>() <= $crate::vm_state::VCPU_SLOT_SIZE,
            "VcpuSnapshot exceeds VCPU_SLOT_SIZE"
        );
    };
}

/// Assert at compile time that a backend's irqchip blob type fits in `IRQCHIP_BLOB_SIZE`.
#[macro_export]
macro_rules! assert_irqchip_fits {
    ($ty:ty) => {
        const _: () = assert!(
            core::mem::size_of::<$ty>() <= $crate::vm_state::IRQCHIP_BLOB_SIZE,
            "Irqchip blob exceeds IRQCHIP_BLOB_SIZE"
        );
    };
}
