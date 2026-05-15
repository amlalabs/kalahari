// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! macOS Hypervisor.framework backend for amla-vm.
//!
//! On native macOS/aarch64: provides the real HVF implementation with
//! subprocess-isolated vCPU workers, pre-warmed VM pools, and `GICv3` emulation.
//!
//! On all other targets: re-exports stub types so the workspace compiles.

// Real HVF modules — only compiled on macOS aarch64.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod device_waker;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod irq;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod pools;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod protocol;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod vm;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub mod worker;

// Re-export real types on macOS aarch64.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use layout::{DeviceSlotLayout, HardwareLayout};
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use pools::VmPools;
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
pub use vm::{Vm, VmBuilder};

/// Subprocess worker entry point. Never returns.
pub async fn worker_main() -> ! {
    worker::worker_main().await
}

// Stub modules — used on non-macOS-aarch64 targets.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
mod stubs;

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub use layout::{DeviceSlotLayout, HardwareLayout};
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub use stubs::{Vm, VmBuilder, VmPools};

/// Stub worker module for non-macOS-aarch64 targets.
#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
pub mod worker {
    /// Subprocess worker entry point (stub).
    pub async fn worker_main() -> ! {
        unimplemented!("HVF worker not available on this platform")
    }
}

// Always-available modules.
mod error;
pub mod ffi;
pub mod layout;
pub use error::{Result, VmmError};
