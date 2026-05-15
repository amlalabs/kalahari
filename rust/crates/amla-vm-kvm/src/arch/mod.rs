// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Architecture-specific modules selected at compile time.
//!
//! Each target architecture provides the same public interface (boot setup,
//! vCPU snapshot, VM state, exit decoding) so the rest of the crate can call
//! `arch::setup_boot(...)`, `arch::VcpuSnapshot`, etc. without knowing which
//! architecture is compiled in.
//!
//! Only same-architecture guests are supported (e.g. an arm64 host boots
//! arm64 guests only). No cross-architecture virtualization.

mod mmio;

#[cfg(target_arch = "x86_64")]
mod x86_64;
#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
mod arm64;
#[cfg(target_arch = "aarch64")]
pub use arm64::*;
