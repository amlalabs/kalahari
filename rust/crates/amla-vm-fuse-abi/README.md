# amla-vm-fuse-abi

FUSE protocol constants (Linux ABI) — `no_std`, host-independent.

## What It Does

FUSE is a Linux protocol: errno values and mode bits are part of the wire format and do not depend on the host OS. This crate defines the subset of Linux `errno.h` used in FUSE responses (`EPERM`, `ENOENT`, `EIO`, `E2BIG`, `EBADF`, `ENOMEM`, `EACCES`, `EEXIST`, `EXDEV`, `ENOTDIR`, `EISDIR`, `EINVAL`, `ENOTTY`, `EFBIG`, `ENOSPC`, `EROFS`, `ERANGE`, `ENAMETOOLONG`, `ENOSYS`, `ENOTEMPTY`, `ENODATA`, `ENOTSUP`) so the crate compiles without `libc` on Linux, macOS, and Windows.

`#![no_std]`. The default `"std"` feature adds `std::error::Error` for `FuseError`.

## Key Types

- `FuseError` — closed enum over supported Linux errno values, with named constructors (`not_found`, `io`, `bad_fd`, `permission_denied`, `exists`, `cross_device`, `not_tty`, `read_only`, ...) and `to_wire_error()` for negative FUSE response values.

## Where It Fits

Leaf-level crate, re-exported as `amla_fuse::fuse_abi` from `amla-vm-fuse`. Every filesystem backend (`amla-vm-synthesized-fs`, `amla-vm-redbfs`, `amla-vm-composite-fs`) returns `FuseError` rather than raw integers, so backends stay host-OS-agnostic.

## License

AGPL-3.0-or-later OR BUSL-1.1
