// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! VM builder for KVM shell lifecycle management.
//!
//! # Lifecycle
//!
//! ```text
//!                         ┌─────────┐
//!                         │ Builder │
//!                         └────┬────┘
//!                              │ build_shell()
//!                              ▼
//!                         ┌─────────┐
//!                   ┌────►│   Vm    │◄────┐
//!                   │     └────┬────┘     │
//!                   │          │ start()  │
//!                   │          │          │
//!                   │          │          │
//!                   │          └──────────┘
//!                   │            pause()
//! ```

#[cfg_attr(feature = "subprocess", allow(dead_code, unused_imports))]
mod pools;
#[cfg_attr(feature = "subprocess", allow(dead_code, unused_imports))]
mod vm;

#[cfg(not(feature = "subprocess"))]
pub use pools::VmPools;
#[cfg(not(feature = "subprocess"))]
pub use vm::{Vm, VmBuilder};

// When subprocess feature is enabled, Vm/VmBuilder/VmPools come from the
// subprocess module instead. Same public API, different implementation.
#[cfg(feature = "subprocess")]
pub use crate::subprocess::{Vm, VmBuilder, VmPools};

#[cfg(test)]
mod tests;
