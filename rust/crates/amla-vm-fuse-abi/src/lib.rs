// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! FUSE protocol constants (Linux ABI).
//!
//! The FUSE protocol uses Linux errno values and Linux file mode bits
//! regardless of host platform. These are **protocol constants**, not
//! host-specific values. Defining them internally lets the crate compile
//! on Linux, macOS, and Windows without depending on `libc`.
//!
//! This crate is `no_std`-compatible. The default `"std"` feature adds
//! `std::error::Error` for `FuseError`.
//!
//! # Compatibility
//!
//! These constants mirror the Linux FUSE UAPI values. Amla does not add a
//! separate versioned ABI in this crate: callers that build higher-level
//! internal protocols from these constants are responsible for running matching
//! same-version code unless they explicitly implement their own negotiation.

#![no_std]

#[cfg(feature = "std")]
extern crate std;

// ── Linux errno values used in FUSE responses ───────────────────────────

pub const EPERM: i32 = 1;
pub const ENOENT: i32 = 2;
pub const EIO: i32 = 5;
pub const E2BIG: i32 = 7;
pub const EBADF: i32 = 9;
pub const ENOMEM: i32 = 12;
pub const EACCES: i32 = 13;
pub const EEXIST: i32 = 17;
pub const EXDEV: i32 = 18;
pub const ENOTDIR: i32 = 20;
pub const EISDIR: i32 = 21;
pub const EINVAL: i32 = 22;
pub const ENOTTY: i32 = 25;
pub const EFBIG: i32 = 27;
pub const ENOSPC: i32 = 28;
pub const EROFS: i32 = 30;
pub const ERANGE: i32 = 34;
pub const ENAMETOOLONG: i32 = 36;
pub const ENOSYS: i32 = 38;
pub const ENOTEMPTY: i32 = 39;
pub const ENODATA: i32 = 61;
pub const ENOTSUP: i32 = 95;

// ── Typed FUSE error ────────────────────────────────────────────────────

/// A FUSE protocol error.
///
/// Replaces raw `i32` returns in filesystem backend and overlay store trait
/// methods. The enum is closed over the Linux errno values this ABI crate
/// supports so zero, negative, and overflowing wire errors are not
/// representable.
///
/// # Wire Protocol Convention
///
/// The FUSE wire protocol uses *negative* errno values (e.g., `-EIO`).
/// Use [`to_wire_error`](FuseError::to_wire_error) when writing responses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[must_use]
pub enum FuseError {
    /// Operation not permitted.
    NotPermitted,
    /// No such file or directory.
    NotFound,
    /// I/O error.
    Io,
    /// Argument list too long.
    TooBig,
    /// Bad file descriptor.
    BadFd,
    /// Out of memory.
    NoMemory,
    /// Permission denied.
    PermissionDenied,
    /// File exists.
    Exists,
    /// Cross-device link.
    CrossDevice,
    /// Not a directory.
    NotDir,
    /// Is a directory.
    IsDir,
    /// Invalid argument.
    Invalid,
    /// Inappropriate ioctl for device.
    NotTty,
    /// File too large.
    FileTooBig,
    /// No space left on device.
    NoSpace,
    /// Read-only filesystem.
    ReadOnly,
    /// Result too large.
    Range,
    /// File name too long.
    NameTooLong,
    /// Function not implemented.
    NoSys,
    /// Directory not empty.
    NotEmpty,
    /// No data available.
    NoData,
    /// Operation not supported.
    NotSupported,
}

impl FuseError {
    pub const fn not_permitted() -> Self {
        Self::NotPermitted
    }
    pub const fn not_found() -> Self {
        Self::NotFound
    }
    pub const fn io() -> Self {
        Self::Io
    }
    pub const fn bad_fd() -> Self {
        Self::BadFd
    }
    pub const fn no_memory() -> Self {
        Self::NoMemory
    }
    pub const fn permission_denied() -> Self {
        Self::PermissionDenied
    }
    pub const fn exists() -> Self {
        Self::Exists
    }
    pub const fn cross_device() -> Self {
        Self::CrossDevice
    }
    pub const fn not_dir() -> Self {
        Self::NotDir
    }
    pub const fn is_dir() -> Self {
        Self::IsDir
    }
    pub const fn invalid() -> Self {
        Self::Invalid
    }
    pub const fn not_tty() -> Self {
        Self::NotTty
    }
    pub const fn read_only() -> Self {
        Self::ReadOnly
    }
    pub const fn range() -> Self {
        Self::Range
    }
    pub const fn no_sys() -> Self {
        Self::NoSys
    }
    pub const fn not_empty() -> Self {
        Self::NotEmpty
    }
    pub const fn no_data() -> Self {
        Self::NoData
    }
    pub const fn not_supported() -> Self {
        Self::NotSupported
    }
    pub const fn no_space() -> Self {
        Self::NoSpace
    }
    pub const fn too_big() -> Self {
        Self::TooBig
    }
    pub const fn file_too_big() -> Self {
        Self::FileTooBig
    }
    pub const fn name_too_long() -> Self {
        Self::NameTooLong
    }

    /// Return the positive errno value.
    #[must_use]
    pub const fn raw(self) -> i32 {
        match self {
            Self::NotPermitted => EPERM,
            Self::NotFound => ENOENT,
            Self::Io => EIO,
            Self::TooBig => E2BIG,
            Self::BadFd => EBADF,
            Self::NoMemory => ENOMEM,
            Self::PermissionDenied => EACCES,
            Self::Exists => EEXIST,
            Self::CrossDevice => EXDEV,
            Self::NotDir => ENOTDIR,
            Self::IsDir => EISDIR,
            Self::Invalid => EINVAL,
            Self::NotTty => ENOTTY,
            Self::FileTooBig => EFBIG,
            Self::NoSpace => ENOSPC,
            Self::ReadOnly => EROFS,
            Self::Range => ERANGE,
            Self::NameTooLong => ENAMETOOLONG,
            Self::NoSys => ENOSYS,
            Self::NotEmpty => ENOTEMPTY,
            Self::NoData => ENODATA,
            Self::NotSupported => ENOTSUP,
        }
    }

    /// Return the negative FUSE wire error value.
    #[must_use]
    pub const fn to_wire_error(self) -> i32 {
        -self.raw()
    }
}

impl core::fmt::Display for FuseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.raw() {
            EPERM => f.write_str("EPERM"),
            ENOENT => f.write_str("ENOENT"),
            EIO => f.write_str("EIO"),
            E2BIG => f.write_str("E2BIG"),
            EBADF => f.write_str("EBADF"),
            ENOMEM => f.write_str("ENOMEM"),
            EACCES => f.write_str("EACCES"),
            EEXIST => f.write_str("EEXIST"),
            EXDEV => f.write_str("EXDEV"),
            ENOTDIR => f.write_str("ENOTDIR"),
            EISDIR => f.write_str("EISDIR"),
            EINVAL => f.write_str("EINVAL"),
            ENOTTY => f.write_str("ENOTTY"),
            EFBIG => f.write_str("EFBIG"),
            ENOSPC => f.write_str("ENOSPC"),
            EROFS => f.write_str("EROFS"),
            ERANGE => f.write_str("ERANGE"),
            ENAMETOOLONG => f.write_str("ENAMETOOLONG"),
            ENOSYS => f.write_str("ENOSYS"),
            ENOTEMPTY => f.write_str("ENOTEMPTY"),
            ENODATA => f.write_str("ENODATA"),
            ENOTSUP => f.write_str("ENOTSUP"),
            _ => unreachable!("FuseError::raw returns only known errno values"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FuseError {}

// ── Linux file type mode bits ───────────────────────────────────────────

pub const S_IFMT: u32 = 0o17_0000;
pub const S_IFSOCK: u32 = 0o14_0000;
pub const S_IFLNK: u32 = 0o12_0000;
pub const S_IFREG: u32 = 0o10_0000;
pub const S_IFBLK: u32 = 0o06_0000;
pub const S_IFDIR: u32 = 0o04_0000;
pub const S_IFCHR: u32 = 0o02_0000;
pub const S_IFIFO: u32 = 0o01_0000;

// ── Linux open flags ────────────────────────────────────────────────────

pub const O_RDONLY: u32 = 0;
pub const O_WRONLY: u32 = 1;
pub const O_RDWR: u32 = 2;
pub const O_ACCMODE: u32 = 3;

// ── Access-check flags (for FUSE_ACCESS) ────────────────────────────────

pub const F_OK: u32 = 0;
pub const X_OK: u32 = 1;
pub const W_OK: u32 = 2;
pub const R_OK: u32 = 4;

// ── Xattr flags ─────────────────────────────────────────────────────────

pub const XATTR_CREATE: u32 = 1;
pub const XATTR_REPLACE: u32 = 2;

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    extern crate alloc;
    use alloc::format;

    #[test]
    fn named_constructors_return_correct_raw() {
        assert_eq!(FuseError::not_permitted().raw(), EPERM);
        assert_eq!(FuseError::not_found().raw(), ENOENT);
        assert_eq!(FuseError::io().raw(), EIO);
        assert_eq!(FuseError::too_big().raw(), E2BIG);
        assert_eq!(FuseError::bad_fd().raw(), EBADF);
        assert_eq!(FuseError::no_memory().raw(), ENOMEM);
        assert_eq!(FuseError::permission_denied().raw(), EACCES);
        assert_eq!(FuseError::exists().raw(), EEXIST);
        assert_eq!(FuseError::cross_device().raw(), EXDEV);
        assert_eq!(FuseError::not_dir().raw(), ENOTDIR);
        assert_eq!(FuseError::is_dir().raw(), EISDIR);
        assert_eq!(FuseError::invalid().raw(), EINVAL);
        assert_eq!(FuseError::not_tty().raw(), ENOTTY);
        assert_eq!(FuseError::file_too_big().raw(), EFBIG);
        assert_eq!(FuseError::no_space().raw(), ENOSPC);
        assert_eq!(FuseError::read_only().raw(), EROFS);
        assert_eq!(FuseError::range().raw(), ERANGE);
        assert_eq!(FuseError::name_too_long().raw(), ENAMETOOLONG);
        assert_eq!(FuseError::no_sys().raw(), ENOSYS);
        assert_eq!(FuseError::not_empty().raw(), ENOTEMPTY);
        assert_eq!(FuseError::no_data().raw(), ENODATA);
        assert_eq!(FuseError::not_supported().raw(), ENOTSUP);
    }

    #[test]
    fn wire_errors_are_negative_errno_values() {
        assert_eq!(FuseError::io().to_wire_error(), -EIO);
        assert_eq!(FuseError::not_tty().to_wire_error(), -ENOTTY);
    }

    #[test]
    fn display_known_errnos() {
        assert_eq!(format!("{}", FuseError::not_permitted()), "EPERM");
        assert_eq!(format!("{}", FuseError::not_found()), "ENOENT");
        assert_eq!(format!("{}", FuseError::io()), "EIO");
        assert_eq!(format!("{}", FuseError::too_big()), "E2BIG");
        assert_eq!(format!("{}", FuseError::bad_fd()), "EBADF");
        assert_eq!(format!("{}", FuseError::no_memory()), "ENOMEM");
        assert_eq!(format!("{}", FuseError::permission_denied()), "EACCES");
        assert_eq!(format!("{}", FuseError::exists()), "EEXIST");
        assert_eq!(format!("{}", FuseError::cross_device()), "EXDEV");
        assert_eq!(format!("{}", FuseError::not_dir()), "ENOTDIR");
        assert_eq!(format!("{}", FuseError::is_dir()), "EISDIR");
        assert_eq!(format!("{}", FuseError::invalid()), "EINVAL");
        assert_eq!(format!("{}", FuseError::not_tty()), "ENOTTY");
        assert_eq!(format!("{}", FuseError::file_too_big()), "EFBIG");
        assert_eq!(format!("{}", FuseError::no_space()), "ENOSPC");
        assert_eq!(format!("{}", FuseError::read_only()), "EROFS");
        assert_eq!(format!("{}", FuseError::range()), "ERANGE");
        assert_eq!(format!("{}", FuseError::name_too_long()), "ENAMETOOLONG");
        assert_eq!(format!("{}", FuseError::no_sys()), "ENOSYS");
        assert_eq!(format!("{}", FuseError::not_empty()), "ENOTEMPTY");
        assert_eq!(format!("{}", FuseError::no_data()), "ENODATA");
        assert_eq!(format!("{}", FuseError::not_supported()), "ENOTSUP");
    }

    #[test]
    fn equality_clone_copy() {
        let a = FuseError::io();
        let b = FuseError::io();
        assert_eq!(a, b);

        let c = FuseError::not_found();
        assert_ne!(a, c);

        // Copy trait — this is a bitwise copy, no clone needed
        let d = a;
        assert_eq!(a, d);
    }

    #[test]
    fn hash_works() {
        use core::hash::{Hash, Hasher};
        struct SimpleHasher(u64);
        impl Hasher for SimpleHasher {
            fn finish(&self) -> u64 {
                self.0
            }
            fn write(&mut self, bytes: &[u8]) {
                for &b in bytes {
                    self.0 = self.0.wrapping_mul(31).wrapping_add(u64::from(b));
                }
            }
        }

        let mut h1 = SimpleHasher(0);
        FuseError::io().hash(&mut h1);
        let mut h2 = SimpleHasher(0);
        FuseError::io().hash(&mut h2);
        assert_eq!(h1.finish(), h2.finish());
    }

    #[test]
    fn errno_constant_values() {
        assert_eq!(EPERM, 1);
        assert_eq!(ENOENT, 2);
        assert_eq!(EIO, 5);
        assert_eq!(EBADF, 9);
        assert_eq!(ENOMEM, 12);
        assert_eq!(EACCES, 13);
        assert_eq!(EEXIST, 17);
        assert_eq!(EXDEV, 18);
        assert_eq!(ENOTDIR, 20);
        assert_eq!(EISDIR, 21);
        assert_eq!(EINVAL, 22);
        assert_eq!(ENOTTY, 25);
        assert_eq!(EFBIG, 27);
        assert_eq!(ENOSPC, 28);
        assert_eq!(EROFS, 30);
        assert_eq!(ERANGE, 34);
        assert_eq!(ENAMETOOLONG, 36);
        assert_eq!(ENOSYS, 38);
        assert_eq!(ENOTEMPTY, 39);
        assert_eq!(ENODATA, 61);
        assert_eq!(ENOTSUP, 95);
    }

    #[test]
    fn file_mode_constants() {
        assert_eq!(S_IFMT, 0o17_0000);
        assert_eq!(S_IFSOCK, 0o14_0000);
        assert_eq!(S_IFLNK, 0o12_0000);
        assert_eq!(S_IFREG, 0o10_0000);
        assert_eq!(S_IFBLK, 0o06_0000);
        assert_eq!(S_IFDIR, 0o04_0000);
        assert_eq!(S_IFCHR, 0o02_0000);
        assert_eq!(S_IFIFO, 0o01_0000);
    }

    #[test]
    fn open_flag_constants() {
        assert_eq!(O_RDONLY, 0);
        assert_eq!(O_WRONLY, 1);
        assert_eq!(O_RDWR, 2);
        assert_eq!(O_ACCMODE, 3);
    }

    #[test]
    fn access_and_xattr_constants() {
        assert_eq!(F_OK, 0);
        assert_eq!(X_OK, 1);
        assert_eq!(W_OK, 2);
        assert_eq!(R_OK, 4);
        assert_eq!(XATTR_CREATE, 1);
        assert_eq!(XATTR_REPLACE, 2);
    }
}
