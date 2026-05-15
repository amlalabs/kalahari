// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Shared constants for amla-vm.
//!
//! This crate is `no_std` compatible so it can be used by both host-side
//! crates (`amla-vm-core`, `amla-vm-usernet`) and the guest-side
//! `amla-guest` binary.

#![cfg_attr(not(feature = "std"), no_std)]

pub mod net;
pub mod num;
pub mod protocol;

/// Guest page size: 4 KiB on all platforms.
///
/// The guest kernel always uses 4 KiB pages. On Apple Silicon (16 KiB
/// host pages), the pmem device is mapped at a 16 KiB-aligned GPA for
/// `hv_vm_map` compatibility, but the guest operates at 4 KiB granularity
/// internally.
pub const GUEST_PAGE_SIZE: u64 = 4096;

/// UID used for user-owned files on host-side shared filesystems.
///
/// The guest remaps this to the container's actual UID via an idmapped
/// bind mount (`mount_setattr` with `MOUNT_ATTR_IDMAP`).
pub const HOST_FILE_UID: u32 = 1000;

/// GID used for user-owned files on host-side shared filesystems.
pub const HOST_FILE_GID: u32 = 1000;
