// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Error types for the HVF backend.

use crate::ffi;

/// HVF backend error.
#[derive(Debug, thiserror::Error)]
pub enum VmmError {
    /// Platform not supported (non-macOS or non-aarch64).
    #[error("HVF not implemented on this platform")]
    NotImplemented,

    /// Hypervisor.framework has no resources available for the operation.
    #[error("HVF resources exhausted during {operation}")]
    HvNoResources {
        /// HVF operation that exhausted host resources.
        operation: String,
    },

    /// Hypervisor.framework call failed.
    #[error("HVF error: {0}")]
    Hvf(ffi::HvfError),

    /// IPC communication error with worker subprocess.
    #[error("IPC error: {0}")]
    Ipc(String),

    /// Worker subprocess died unexpectedly.
    #[error("worker died: {0}")]
    WorkerDead(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// VM used after inner was dropped.
    #[error("use after drop")]
    UseAfterDrop,

    /// Alignment error (e.g., non-16 KiB-aligned memory mapping).
    #[error("alignment error: {msg}")]
    Alignment {
        /// Description of the alignment violation.
        msg: String,
    },

    /// Invalid state during snapshot restore.
    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState {
        /// What was expected.
        expected: &'static str,
        /// What was found.
        actual: &'static str,
    },

    /// System call error with context.
    #[error("{operation}: {source}")]
    SystemCall {
        /// The operation that failed.
        operation: &'static str,
        /// Underlying OS error.
        #[source]
        source: std::io::Error,
    },
}

impl VmmError {
    /// Create a system call error closure for use with `.map_err()`.
    pub fn sys(operation: &'static str) -> impl FnOnce(std::io::Error) -> Self {
        move |source| Self::SystemCall { operation, source }
    }
}

impl From<ffi::HvfError> for VmmError {
    fn from(source: ffi::HvfError) -> Self {
        if source.is_no_resources() {
            Self::HvNoResources {
                operation: source.operation().to_owned(),
            }
        } else {
            Self::Hvf(source)
        }
    }
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, VmmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_resources_maps_to_typed_vmm_error() {
        let source = ffi::check("hv_vm_create", ffi::HV_NO_RESOURCES).unwrap_err();
        let err = VmmError::from(source);
        assert!(matches!(
            err,
            VmmError::HvNoResources { ref operation } if operation == "hv_vm_create"
        ));
    }
}
