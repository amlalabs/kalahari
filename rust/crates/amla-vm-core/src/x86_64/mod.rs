// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` architecture-specific types shared across hypervisor backends.
//!
//! Provides:
//! - MSR index constants (`msr` module)
//! - Multi-processor state enum (`MpState`)
//! - vCPU snapshot types (`snapshot` module)
//!
//! These types are hypervisor-agnostic — usable by both KVM (Linux) and
//! Hyper-V/WHP (Windows) `x86_64` backends.

pub mod msr;
pub mod snapshot;

pub use msr::SNAPSHOT_MSRS;
pub use snapshot::X86VcpuSnapshot;

/// `x86_64` multi-processor state.
///
/// These values are architecture-level and identical across KVM and WHP:
///
/// | State           | Value | `KVM_RUN` behavior                  |
/// |-----------------|-------|-------------------------------------|
/// | `Runnable`      | 0     | vCPU executes normally              |
/// | `Uninitialized` | 1     | `KVM_RUN` fails immediately         |
/// | `InitReceived`  | 2     | `KVM_RUN` blocks waiting for SIPI   |
/// | `Halted`        | 3     | `KVM_RUN` blocks until interrupt    |
/// | `SipiReceived`  | 4     | KVM sets this after SIPI delivery   |
///
/// For APs, always use `InitReceived` (not `Uninitialized`).
#[repr(u32)]
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum MpState {
    Runnable = 0,
    Uninitialized = 1,
    InitReceived = 2,
    Halted = 3,
    SipiReceived = 4,
}

impl TryFrom<u32> for MpState {
    type Error = u32;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Runnable),
            1 => Ok(Self::Uninitialized),
            2 => Ok(Self::InitReceived),
            3 => Ok(Self::Halted),
            4 => Ok(Self::SipiReceived),
            _ => Err(value),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mp_state_values() {
        assert_eq!(MpState::Runnable as u32, 0);
        assert_eq!(MpState::Uninitialized as u32, 1);
        assert_eq!(MpState::InitReceived as u32, 2);
        assert_eq!(MpState::Halted as u32, 3);
        assert_eq!(MpState::SipiReceived as u32, 4);
    }

    #[test]
    fn mp_state_try_from_u32() {
        assert_eq!(MpState::try_from(0), Ok(MpState::Runnable));
        assert_eq!(MpState::try_from(3), Ok(MpState::Halted));
        assert_eq!(MpState::try_from(4), Ok(MpState::SipiReceived));
        assert_eq!(MpState::try_from(5), Err(5));
        assert_eq!(MpState::try_from(u32::MAX), Err(u32::MAX));
    }
}
