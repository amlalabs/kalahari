// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Error types for ARM64 boot protocol.

/// Errors that can occur during ARM64 boot setup.
#[derive(Debug, thiserror::Error)]
pub enum BootError {
    /// Kernel image is too small to contain a valid ARM64 Image header.
    #[error("kernel image too small: {0} bytes (need at least 64)")]
    ImageTooSmall(usize),

    /// Missing or invalid ARM64 Image magic number.
    #[error("invalid ARM64 Image magic (expected ARM\\x64 at offset 56)")]
    InvalidMagic,

    /// The `text_offset` field is invalid.
    #[error("invalid text_offset: {0:#x}")]
    InvalidTextOffset(u64),

    /// Kernel is big-endian, which is not supported.
    #[error("big-endian ARM64 kernels are not supported")]
    UnsupportedEndianness,

    /// Guest memory is too small for a valid boot layout.
    #[error("memory too small: {0:#x} bytes (need at least {1:#x})")]
    MemoryTooSmall(u64, u64),

    /// Kernel and DTB regions overlap or extend beyond guest RAM.
    #[error("layout conflict: {0}")]
    LayoutConflict(String),

    /// DTB generation failed.
    #[error("DTB generation error: {0}")]
    DtbGeneration(String),

    /// Boot-memory layout or write validation failed.
    #[error("boot memory: {0}")]
    BootMemory(String),
}

impl From<vm_fdt::Error> for BootError {
    fn from(e: vm_fdt::Error) -> Self {
        Self::DtbGeneration(e.to_string())
    }
}

impl From<crate::boot_memory::BootMemoryError> for BootError {
    fn from(e: crate::boot_memory::BootMemoryError) -> Self {
        Self::BootMemory(e.to_string())
    }
}

/// Result type for boot operations.
pub type Result<T> = std::result::Result<T, BootError>;
