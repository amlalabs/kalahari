// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 architecture-specific types and syndrome decoding.
//!
//! This module contains pure logic for decoding `ESR_EL2` syndrome values and
//! PSCI function IDs. It is hypervisor-agnostic — usable by both HVF (macOS)
//! and KVM (Linux) ARM64 backends.
//!
//! # Module structure
//!
//! - [`syndrome`]: `ESR_EL2` bitfield decode, MMIO/HVC/exception types
//! - [`snapshot`]: Register enums, snapshot struct, constant arrays

pub mod snapshot;
pub mod syndrome;

// Re-export all public items from submodules for backwards compatibility.
pub use snapshot::*;
pub use syndrome::*;

// =============================================================================
// PSCI function IDs (ARM Power State Coordination Interface)
// =============================================================================

/// PSCI `SYSTEM_OFF` (shutdown).
pub const PSCI_SYSTEM_OFF: u64 = 0x8400_0008;
/// PSCI `SYSTEM_RESET` (reboot).
pub const PSCI_SYSTEM_RESET: u64 = 0x8400_0009;
/// PSCI `CPU_OFF`.
pub const PSCI_CPU_OFF: u64 = 0x8400_0002;
/// PSCI `CPU_ON` (64-bit).
pub const PSCI_CPU_ON: u64 = 0xC400_0003;
/// PSCI `AFFINITY_INFO` (32-bit).
pub const PSCI_AFFINITY_INFO_32: u64 = 0x8400_0004;
/// PSCI `AFFINITY_INFO` (64-bit).
pub const PSCI_AFFINITY_INFO_64: u64 = 0xC400_0004;

// =============================================================================
// PSCI return codes (PSCI spec §5.2, Table 6)
// =============================================================================

/// PSCI call completed successfully.
pub const PSCI_RET_SUCCESS: i64 = 0;
/// Function not supported.
pub const PSCI_RET_NOT_SUPPORTED: i64 = -1;
/// Invalid parameters.
pub const PSCI_RET_INVALID_PARAMETERS: i64 = -2;
/// Permission denied.
pub const PSCI_RET_DENIED: i64 = -3;
/// Target CPU is already on.
pub const PSCI_RET_ALREADY_ON: i64 = -4;
/// A previous `CPU_ON` for the target is still in progress.
pub const PSCI_RET_ON_PENDING: i64 = -5;
/// Internal failure.
pub const PSCI_RET_INTERNAL_FAILURE: i64 = -6;
