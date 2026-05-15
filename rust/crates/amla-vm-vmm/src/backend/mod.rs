// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Hypervisor backend abstraction.
//!
//! Each backend provides `BackendVm` with methods for memory mapping,
//! vCPU creation, state save/restore, and boot state initialization.
//! Platform selection is via `cfg(target_os)` gates.

// Macro must be declared before the modules that use it.
#[macro_use]
mod macros;

// Under cfg(test): use the mock backend (no hypervisor needed for unit tests).
#[cfg(test)]
mod mock;
#[cfg(test)]
pub use mock::*;

// KVM backend (Linux only, not in test mode).
#[cfg(all(not(test), target_os = "linux"))]
mod kvm;
#[cfg(all(not(test), target_os = "linux"))]
pub use kvm::*;

#[cfg(all(not(test), target_os = "macos"))]
mod hvf;
#[cfg(all(not(test), target_os = "macos"))]
pub use hvf::*;

#[cfg(all(not(test), target_os = "windows"))]
mod hyperv;
#[cfg(all(not(test), target_os = "windows"))]
pub use hyperv::*;

#[cfg(not(any(test, target_os = "linux", target_os = "macos", target_os = "windows")))]
mod stub;
#[cfg(not(any(test, target_os = "linux", target_os = "macos", target_os = "windows")))]
pub use stub::*;

// Platform-specific backend error type alias.

/// The platform-specific hypervisor error type.
#[cfg(test)]
pub type BackendError = mock::MockVmmError;
/// Return whether the backend error means host hypervisor resources are exhausted.
#[cfg(test)]
#[must_use]
pub const fn is_resource_exhausted(_error: &BackendError) -> bool {
    false
}

/// The platform-specific hypervisor error type.
#[cfg(all(not(test), target_os = "linux"))]
pub type BackendError = amla_kvm::VmmError;
/// Return whether the backend error means host hypervisor resources are exhausted.
#[cfg(all(not(test), target_os = "linux"))]
#[must_use]
pub const fn is_resource_exhausted(_error: &BackendError) -> bool {
    false
}

/// The platform-specific hypervisor error type.
#[cfg(all(not(test), target_os = "macos"))]
pub type BackendError = amla_hvf::VmmError;
/// Return whether the backend error means host hypervisor resources are exhausted.
#[cfg(all(not(test), target_os = "macos"))]
#[must_use]
pub fn is_resource_exhausted(error: &BackendError) -> bool {
    matches!(error, amla_hvf::VmmError::HvNoResources { .. })
}

/// The platform-specific hypervisor error type.
#[cfg(all(not(test), target_os = "windows"))]
pub type BackendError = amla_hyperv::VmmError;
/// Return whether the backend error means host hypervisor resources are exhausted.
#[cfg(all(not(test), target_os = "windows"))]
#[must_use]
pub fn is_resource_exhausted(_error: &BackendError) -> bool {
    false
}

/// The platform-specific hypervisor error type.
#[cfg(not(any(test, target_os = "linux", target_os = "macos", target_os = "windows")))]
pub type BackendError = amla_stub::VmmError;
/// Return whether the backend error means host hypervisor resources are exhausted.
#[cfg(not(any(test, target_os = "linux", target_os = "macos", target_os = "windows")))]
#[must_use]
pub fn is_resource_exhausted(_error: &BackendError) -> bool {
    false
}
