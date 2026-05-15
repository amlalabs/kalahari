// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Base kernel and embedded guest binary for VM rootfs assembly.
//!
//! This crate provides:
//! - Linux kernel image (amla-guest-kernel with `CONFIG_VIRTIO_FS`)
//! - Embedded unified `amla-guest` binary (agent, init, exec, coreutils, tests)
//! - [`RootfsBuilder`] for assembling EROFS rootfs images at runtime
//!
//! Consumers use [`RootfsBuilder::base()`] to get a rootfs with the guest binary,
//! then call [`RootfsBuilder::build()`] to finalize.

mod rootfs_builder;
pub use rootfs_builder::RootfsBuilder;

/// Linux kernel image (`vmlinux` ELF on `x86_64`, `Image` on `aarch64`).
///
/// Security model: these bytes are the untrusted guest payload, not part of
/// the host isolation TCB. Kernel provenance pinning matters for release
/// reproducibility and GPL source correspondence; the VMM/virtio stack must
/// remain secure even if the guest kernel is stale or malicious.
pub const KERNEL: &[u8] = include_bytes!(env!("AMLA_KERNEL_BIN"));

/// Unified amla-guest binary (static musl). Contains agent, init, exec,
/// coreutils, and (with `test-binaries` feature) test subcommands.
pub const AMLA_GUEST: &[u8] = include_bytes!(env!("AMLA_GUEST_BIN"));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amla_guest_is_elf() {
        assert!(AMLA_GUEST.len() > 4, "amla-guest too small");
        assert_eq!(&AMLA_GUEST[..4], b"\x7fELF", "amla-guest not ELF");
    }

    #[test]
    fn kernel_has_valid_magic() {
        assert!(
            KERNEL.len() >= 4,
            "kernel too small: {} bytes",
            KERNEL.len()
        );

        #[cfg(target_arch = "x86_64")]
        assert_eq!(&KERNEL[..4], b"\x7fELF", "kernel does not have ELF magic");

        #[cfg(target_arch = "aarch64")]
        {
            assert!(
                KERNEL.len() >= 64,
                "kernel too small for ARM64 Image header"
            );
            assert_eq!(
                &KERNEL[56..60],
                b"ARM\x64",
                "kernel does not have ARM64 Image magic"
            );
        }
    }
}
