// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! FUSE protocol types, dispatch, and filesystem backend types for amla-vm.
//!
//! Extracted from `amla-virtio-fs` so that the FUSE protocol layer can be
//! reused independently of the virtio transport.

pub mod fs_types;
pub mod fuse;
pub mod null;
pub use amla_fuse_abi as fuse_abi;
pub use null::NullFsBackend;
