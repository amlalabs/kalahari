// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Platform-specific memory implementations.
//!
//! - **Linux**: branch and allocation tests.
//! - **macOS**: Mach VM helpers (future).
//! - **Windows**: Section-object helpers for pmem image sharing.

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;
