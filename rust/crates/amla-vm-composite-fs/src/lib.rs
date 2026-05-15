// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)] // u64→usize inode casts, lossless on 64-bit

//! Composable FUSE filesystem wrappers.
//!
//! - [`MountedFsBackend`] — prefixes a backend's tree under a directory path
//! - [`OverlayFsBackend`] — merges a `DynamicFsBackend` and `FixedFsBackend`
//!   into one namespace with fixed-low / dynamic-high inode partitioning
//! - [`MultiFixedFsBackend`] — combines multiple `FixedFsBackend`s into a
//!   single namespace

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-composite-fs requires a 64-bit target");

pub mod hlist;
mod mounted;
mod multi_fixed;
mod overlay;

pub use hlist::{FixedList, HCons, HNil};
pub use mounted::{InvalidMount, InvalidMountPrefix, MountedFsBackend};
pub use multi_fixed::{InvalidMultiFixedLayout, MultiFixedFsBackend};
pub use overlay::OverlayFsBackend;
