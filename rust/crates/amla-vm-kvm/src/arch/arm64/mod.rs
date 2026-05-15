// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 architecture support for KVM.
//!
//! Provides the same interface as `x86_64` but for ARM64 guests running
//! under KVM with `GICv3`. Modules:
//!
//! - `shell`: `GICv3` setup and vCPU init (`KVM_ARM_VCPU_INIT`)
//! - `exit`: MMIO exit decoding for virtio device dispatch
//! - `state`: vCPU register snapshot/restore (core + system registers)
//! - `boot`: re-exports from `amla-boot-arm64` for kernel loading
//! - `consts`: interrupt routing constants (SPI base, line count)

pub mod boot;
pub mod consts;
mod exit;
pub(crate) mod gic_pod;
pub(crate) mod gic_state;
mod shell;
pub(crate) mod state;

pub(crate) use exit::map_exit;
pub use shell::InitialDeviceState;
#[allow(unused_imports)]
pub(crate) use shell::{ArchSetupState, capture_initial_state, setup_vcpus, setup_vm};
#[allow(unused_imports)]
pub(crate) use state::MAX_SNAPSHOT_REGS as MAX_SNAPSHOT_MSRS;
pub use state::{VcpuSnapshot, VmStateSnapshot};
