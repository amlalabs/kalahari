// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Error types for amla-kvm.

use std::io;
use thiserror::Error;

/// VMM error type.
#[derive(Debug, Error)]
pub enum VmmError {
    /// KVM ioctl failed.
    #[error("KVM error: {0}")]
    Kvm(#[from] kvm_ioctls::Error),

    /// System call failed.
    #[error("{operation} failed: {source}")]
    SystemCall {
        /// Which operation failed (e.g. "mmap", "`memfd_create`").
        operation: &'static str,
        /// The underlying OS error.
        #[source]
        source: io::Error,
    },

    /// Zygote VM memfd is smaller than the slot.
    #[error("zygote size ({zygote_size}) < slot size ({slot_size})")]
    ZygoteTooSmall {
        /// Size of the frozen VM memfd.
        zygote_size: usize,
        /// Size of the slot.
        slot_size: usize,
    },

    /// Memory size not page-aligned.
    #[error("size {size} is not page-aligned")]
    NotPageAligned {
        /// The unaligned size.
        size: usize,
    },

    /// Invalid memory size.
    #[error("invalid size {size}: {reason}")]
    InvalidSize {
        /// Invalid size in bytes.
        size: usize,
        /// Reason the size is invalid.
        reason: &'static str,
    },

    /// Invalid page range.
    #[error("invalid range offset={offset} len={len} size={size}: {reason}")]
    InvalidRange {
        /// Range start in bytes.
        offset: u64,
        /// Range length in bytes.
        len: u64,
        /// Containing object size in bytes.
        size: usize,
        /// Reason the range is invalid.
        reason: &'static str,
    },

    /// VM is in wrong state for this operation.
    #[error("invalid VM state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state description.
        expected: &'static str,
        /// Actual state description.
        actual: &'static str,
    },

    /// vCPU operation failed.
    #[error("vCPU error: {0}")]
    Vcpu(#[from] amla_core::VcpuError),

    /// Invalid memfd (e.g. not sealed, wrong size).
    #[error("invalid memfd: {reason}")]
    InvalidMemfd {
        /// Reason the memfd is invalid.
        reason: &'static str,
    },

    /// Size mismatch during validation.
    #[error("size mismatch: expected {expected}, actual {actual}")]
    SizeMismatch {
        /// Expected size.
        expected: usize,
        /// Actual size.
        actual: usize,
    },

    /// Configuration error.
    #[error("config error: {0}")]
    Config(String),

    /// Shell pool limit reached.
    #[error("at shell pool limit")]
    AtShellLimit,

    /// VM used after internal state was consumed.
    #[error("VM used after drop or move")]
    UseAfterDrop,

    /// Memory allocation failed (mmap returned null).
    #[error("memory allocation failed: requested {size} bytes")]
    AllocationFailed {
        /// Requested allocation size in bytes.
        size: usize,
    },

    /// `CowTree` kernel module operation failed.
    #[error("cowtree error: {0}")]
    CowTree(String),

    /// MSR (Model Specific Register) operation failed.
    #[error("MSR error: {0}")]
    MsrError(String),

    /// Operation not supported by this memory backing.
    #[error("unsupported operation: {0}")]
    UnsupportedOperation(&'static str),

    /// vCPU index does not fit in xAPIC's 8-bit ID register.
    ///
    /// Valid xAPIC IDs are 0..=254 (255 is the broadcast destination). This
    /// is tripped before any silent truncation is performed — aliasing two
    /// vCPUs to the same APIC ID would corrupt SMP boot irreversibly.
    #[error("APIC ID overflow: vcpu index {0} does not fit in xAPIC 8-bit ID (max 254)")]
    ApicIdOverflow(usize),

    /// `kvm_mp_state.mp_state` returned by the host kernel does not match any
    /// value in our [`MpState`](amla_core::x86_64::MpState) enum.
    #[error("unknown KVM mp_state value: {0}")]
    UnknownMpState(u32),
}

impl From<amla_mem::MemError> for VmmError {
    fn from(e: amla_mem::MemError) -> Self {
        match e {
            amla_mem::MemError::SystemCall { operation, source } => {
                Self::SystemCall { operation, source }
            }
            amla_mem::MemError::NotPageAligned { size } => Self::NotPageAligned { size },
            amla_mem::MemError::InvalidSize { size, reason } => Self::InvalidSize { size, reason },
            amla_mem::MemError::InvalidRange {
                offset,
                len,
                size,
                reason,
            } => Self::InvalidRange {
                offset,
                len,
                size,
                reason,
            },
            amla_mem::MemError::InvalidMemfd { reason } => Self::InvalidMemfd { reason },
            amla_mem::MemError::SizeMismatch { expected, actual } => {
                Self::SizeMismatch { expected, actual }
            }
            amla_mem::MemError::CowTree(msg) => Self::CowTree(msg),
            amla_mem::MemError::Unsupported(msg) => Self::UnsupportedOperation(msg),
            amla_mem::MemError::AllocationFailed { size } => Self::AllocationFailed { size },
            amla_mem::MemError::InvalidState { expected, actual } => {
                Self::InvalidState { expected, actual }
            }
        }
    }
}

impl VmmError {
    /// Ergonomic constructor for `SystemCall` — use with `.map_err(VmmError::sys("mmap"))`.
    ///
    /// Accepts any error type that converts to `io::Error` (including
    /// `rustix::io::Errno` and `io::Error` itself).
    pub fn sys<E: Into<io::Error>>(operation: &'static str) -> impl FnOnce(E) -> Self {
        move |e| Self::SystemCall {
            operation,
            source: e.into(),
        }
    }
}

/// Result type for VMM operations.
pub type Result<T> = std::result::Result<T, VmmError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_system_call() {
        let err = VmmError::SystemCall {
            operation: "mmap",
            source: io::Error::from_raw_os_error(12),
        };
        let msg = err.to_string();
        assert!(msg.contains("mmap"), "should mention operation: {msg}");
        assert!(msg.contains("failed"), "should say failed: {msg}");
    }

    #[test]
    fn display_zygote_too_small() {
        let err = VmmError::ZygoteTooSmall {
            zygote_size: 100,
            slot_size: 200,
        };
        let msg = err.to_string();
        assert!(msg.contains("100"), "{msg}");
        assert!(msg.contains("200"), "{msg}");
    }

    #[test]
    fn display_not_page_aligned() {
        let err = VmmError::NotPageAligned { size: 4097 };
        assert!(err.to_string().contains("4097"));
    }

    #[test]
    fn display_invalid_state() {
        let err = VmmError::InvalidState {
            expected: "Running",
            actual: "Paused",
        };
        let msg = err.to_string();
        assert!(msg.contains("Running"), "{msg}");
        assert!(msg.contains("Paused"), "{msg}");
    }

    #[test]
    fn display_invalid_memfd() {
        let err = VmmError::InvalidMemfd {
            reason: "bad seals",
        };
        assert!(err.to_string().contains("bad seals"));
    }

    #[test]
    fn display_size_mismatch() {
        let err = VmmError::SizeMismatch {
            expected: 4096,
            actual: 8192,
        };
        let msg = err.to_string();
        assert!(msg.contains("4096"), "{msg}");
        assert!(msg.contains("8192"), "{msg}");
    }

    #[test]
    fn display_config() {
        let err = VmmError::Config("bad vcpu count".into());
        assert!(err.to_string().contains("bad vcpu count"));
    }

    #[test]
    fn display_at_shell_limit() {
        assert_eq!(VmmError::AtShellLimit.to_string(), "at shell pool limit");
    }

    #[test]
    fn display_use_after_drop() {
        assert_eq!(
            VmmError::UseAfterDrop.to_string(),
            "VM used after drop or move"
        );
    }

    #[test]
    fn display_allocation_failed() {
        let err = VmmError::AllocationFailed { size: 1 << 30 };
        let msg = err.to_string();
        assert!(msg.contains("1073741824"), "{msg}");
    }

    #[test]
    fn display_cowtree() {
        let err = VmmError::CowTree("ioctl failed".into());
        assert!(err.to_string().contains("ioctl failed"));
    }

    #[test]
    fn display_msr_error() {
        let err = VmmError::MsrError("unknown MSR".into());
        assert!(err.to_string().contains("unknown MSR"));
    }

    #[test]
    fn display_unsupported_operation() {
        let err = VmmError::UnsupportedOperation("cow snapshots");
        assert!(err.to_string().contains("cow snapshots"));
    }

    #[test]
    fn sys_helper_creates_system_call() {
        let make_err = VmmError::sys("memfd_create");
        let err = make_err(io::Error::from_raw_os_error(22));
        let msg = err.to_string();
        assert!(msg.contains("memfd_create"), "{msg}");
        assert!(msg.contains("failed"), "{msg}");
    }

    #[test]
    fn sys_helper_preserves_source() {
        let make_err = VmmError::sys("mmap");
        let source = io::Error::from_raw_os_error(12);
        let err = make_err(source);
        // std::error::Error::source() should return the io::Error
        let src = std::error::Error::source(&err).unwrap();
        let io_err = src.downcast_ref::<io::Error>().unwrap();
        assert_eq!(io_err.raw_os_error(), Some(12));
    }

    #[test]
    fn system_call_source_chain() {
        let err = VmmError::SystemCall {
            operation: "write",
            source: io::Error::from_raw_os_error(5),
        };
        // source() should return the io::Error
        let src = std::error::Error::source(&err).unwrap();
        assert!(src.downcast_ref::<io::Error>().is_some());
    }

    #[test]
    fn error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<VmmError>();
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());

        let err: Result<u32> = Err(VmmError::AtShellLimit);
        assert!(err.is_err());
    }
}
