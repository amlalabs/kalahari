// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` architecture support for KVM.
//!
//! Provides Linux boot protocol, vCPU state capture/restore, VM-level device
//! setup, and exit decoding — all using `x86_64` KVM types and ioctls.

pub mod boot;
pub mod consts;
mod exit;
mod shell;
mod state;

pub use exit::map_exit;
pub use shell::InitialDeviceState;
pub use shell::{capture_initial_state, setup_vcpus, setup_vm};
#[allow(unused_imports)] // Exported for arch-neutral wire format code
pub use state::MAX_SNAPSHOT_MSRS;
pub use state::{VcpuSnapshot, VmStateSnapshot};
