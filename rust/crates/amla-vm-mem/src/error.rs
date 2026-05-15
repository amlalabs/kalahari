// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Memory-specific error types.

use std::io;
use thiserror::Error;

/// Memory operation error.
#[derive(Debug, Error)]
pub enum MemError {
    /// System call failed.
    #[error("{operation} failed: {source}")]
    SystemCall {
        /// Which operation failed (e.g. "mmap", "`memfd_create`").
        operation: &'static str,
        /// The underlying OS error.
        #[source]
        source: io::Error,
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

    /// `CowTree` kernel module operation failed.
    #[error("cowtree error: {0}")]
    CowTree(String),

    /// Operation not supported by this memory backing.
    #[error("unsupported operation: {0}")]
    Unsupported(&'static str),

    /// Memory allocation failed.
    #[error("allocation failed: requested {size} bytes")]
    AllocationFailed {
        /// Requested allocation size in bytes.
        size: usize,
    },

    /// Invalid state for this operation.
    #[error("invalid state: expected {expected}, got {actual}")]
    InvalidState {
        /// Expected state description.
        expected: &'static str,
        /// Actual state description.
        actual: &'static str,
    },
}

impl MemError {
    /// Ergonomic constructor for `SystemCall` — use with `.map_err(MemError::sys("mmap"))`.
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

/// Result type for memory operations.
pub type Result<T> = std::result::Result<T, MemError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_system_call() {
        let err = MemError::SystemCall {
            operation: "mmap",
            source: io::Error::from_raw_os_error(12),
        };
        let msg = err.to_string();
        assert!(msg.contains("mmap"), "should mention operation: {msg}");
        assert!(msg.contains("failed"), "should say failed: {msg}");
    }

    #[test]
    fn display_not_page_aligned() {
        let err = MemError::NotPageAligned { size: 4097 };
        assert!(err.to_string().contains("4097"));
    }

    #[test]
    fn display_invalid_memfd() {
        let err = MemError::InvalidMemfd {
            reason: "bad seals",
        };
        assert!(err.to_string().contains("bad seals"));
    }

    #[test]
    fn display_size_mismatch() {
        let err = MemError::SizeMismatch {
            expected: 4096,
            actual: 8192,
        };
        let msg = err.to_string();
        assert!(msg.contains("4096"), "{msg}");
        assert!(msg.contains("8192"), "{msg}");
    }

    #[test]
    fn display_cowtree() {
        let err = MemError::CowTree("ioctl failed".into());
        assert!(err.to_string().contains("ioctl failed"));
    }

    #[test]
    fn display_unsupported() {
        let err = MemError::Unsupported("cow snapshots");
        assert!(err.to_string().contains("cow snapshots"));
    }

    #[test]
    fn display_allocation_failed() {
        let err = MemError::AllocationFailed { size: 1 << 30 };
        let msg = err.to_string();
        assert!(msg.contains("1073741824"), "{msg}");
    }

    #[test]
    fn sys_helper_creates_system_call() {
        let make_err = MemError::sys("memfd_create");
        let err = make_err(io::Error::from_raw_os_error(22));
        let msg = err.to_string();
        assert!(msg.contains("memfd_create"), "{msg}");
        assert!(msg.contains("failed"), "{msg}");
    }

    #[test]
    fn error_is_send() {
        fn assert_send<T: Send>() {}
        assert_send::<MemError>();
    }

    #[test]
    fn result_alias_works() {
        let ok: Result<u32> = Ok(42);
        assert!(ok.is_ok());

        let err: Result<u32> = Err(MemError::Unsupported("test"));
        assert!(err.is_err());
    }
}
