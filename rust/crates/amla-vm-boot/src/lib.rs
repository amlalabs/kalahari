// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

// Boot-protocol code is full of deliberate narrowings: u64 guest addresses to
// usize host offsets (guarded by `compile_error!` in writer.rs for non-64-bit
// hosts), u64 config values to u16/u32/u8 boot-struct fields (validated by
// caller or const assert at each site). Per-site allows across ~17 sites were
// attribute noise; inline comments at each cast already explain the reason.
#![allow(clippy::cast_possible_truncation)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Platform-agnostic Linux boot protocol with architecture-specific backends.
//!
//! This crate provides a unified API for loading a Linux kernel into guest
//! memory across different CPU architectures:
//!
//! - **`x86_64`**: ELF kernel loading, boot parameters (zero page), identity-mapped
//!   page tables, GDT, MP table for SMP discovery.
//! - **`ARM64`**: Image header parsing, Device Tree Blob (DTB) generation with
//!   `GICv3`, `PL011`, PSCI, and virtio MMIO nodes.
//!
//! # Unified API
//!
//! Both architectures provide the same public type names through the
//! `define_arch!` macro, so consumers use a single import path regardless of
//! target. Both architectures take a validated `BootGuestMemory` capability
//! derived from the VM-state memory mappings.
//!
//! ```text
//! use amla_boot::{LinuxBootBuilder, BootResult, BootError};
//!
//! let result = LinuxBootBuilder::new(boot_mem, &kernel)
//!     .cmdline("console=...")
//!     .num_cpus(4)
//!     .build()?;
//! ```
//!
//! The `BootResult` contains architecture-specific CPU state that hypervisor
//! backends (KVM, HVF, Hyper-V) convert to their register types.

mod boot_memory;

/// ARM64 boot support and platform interrupt layout.
pub mod arm64;

/// Select the architecture-specific boot module and re-export its public API.
///
/// Each architecture module must provide all types listed in `exports`.
/// If a module is missing any of them, the `pub use` will fail to compile.
/// CI cross-checks both targets, so both architectures are verified.
///
/// # Why a macro?
///
/// Analogous to `define_backend!` in amla-vmm: the macro enforces that both
/// arch modules present the **same API surface** to consumers. A missing
/// export is a compile error, not a runtime surprise on a different arch.
///
/// The generated code is trivial (`mod` + `pub use`), but the macro makes the
/// contract explicit and prevents one arch from drifting out of sync.
///
/// # Generated API Contract
///
/// ## `LinuxBootBuilder<'a>`
/// - `new(boot_mem: BootGuestMemory<'a>, kernel: &[u8]) -> Self`
/// - `.cmdline(&str) -> Self`
/// - `.num_cpus(u8) -> Self`
/// - `.build() -> Result<BootResult>`
///
/// ## `BootResult`
/// - Architecture-specific CPU state (x86: `X86BootState`, ARM64: `Arm64VcpuSnapshot`)
///
/// ## `BootError`
/// - Architecture-specific error enum (implements `std::error::Error`)
macro_rules! define_arch {
    (
        x86_64: $x86_mod:ident,
        aarch64: $arm_mod:ident,
        exports: [ $( $export:ident ),* $(,)? ]
    ) => {
        #[cfg(target_arch = "x86_64")]
        /// `x86_64` boot protocol implementation.
        pub mod $x86_mod;
        #[cfg(target_arch = "x86_64")]
        pub use $x86_mod::{ $( $export ),* };

        #[cfg(target_arch = "aarch64")]
        pub use $arm_mod::{ $( $export ),* };
    };
}

define_arch! {
    x86_64: x86_64,
    aarch64: arm64,
    exports: [LinuxBootBuilder, BootResult, BootError, Result, BootGuestMemory, BootRamLayout, GuestPhysAddr]
}

#[cfg(target_arch = "aarch64")]
pub use arm64::VirtioMmioDtbDevice;
