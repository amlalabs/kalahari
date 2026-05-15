// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Backend composition for configuring or spawning a VM.
//!
//! [`Backends`] is the load-time backend set callers pass to
//! `VirtualMachine::load_kernel()`. [`SpawnBackends`] is the smaller runtime
//! backend set callers pass to `VirtualMachine::spawn()`.

use amla_core::backends::{NetBackend, NullNetBackend};
use amla_fuse::fuse::FsBackend;

use crate::error::ConfigError;

/// Backends for [`VirtualMachine::load_kernel()`](crate::VirtualMachine::load_kernel).
///
/// Console is always required. Net and Fs are optional (must match config).
/// Pmem count must match config's pmem disk count.
///
/// These objects are host backends, not VM state. `freeze()` / `spawn()` keep
/// the mmap-backed guest/device state, but backend-internal state is preserved
/// only if the caller keeps or explicitly snapshots/restores the backend it
/// passes here.
pub struct Backends<'a, F: FsBackend, N: NetBackend = NullNetBackend> {
    /// Console I/O backend (always required).
    pub console: &'a dyn amla_core::backends::ConsoleBackend,
    /// Network backend (required if config has net).
    ///
    /// This is intentionally raw device plumbing: the VMM accepts any
    /// [`NetBackend`](amla_core::backends::NetBackend). `None` means no NIC,
    /// a bare user-mode backend means unrestricted network access, and a
    /// wrapped backend means whatever policy/interception the wrapper enforces.
    /// Callers that advertise a security boundary must build and pass a
    /// policy-enforced outer backend instead of treating this field itself as
    /// proof of egress control.
    pub net: Option<&'a N>,
    /// Filesystem backend (required if config has fs).
    ///
    /// The `F` type parameter is monomorphized by the caller — when no FS
    /// device is configured, pass `Option::<&NullFsBackend>::None`
    /// (or any concrete `F`) since the variant is never instantiated.
    pub fs: Option<&'a F>,
    /// Pmem image handles (one per image across all devices).
    /// Each handle contains one EROFS image.
    pub pmem: Vec<amla_mem::MemHandle>,
}

/// Backends for [`VirtualMachine::spawn()`](crate::VirtualMachine::spawn).
///
/// A zygote already owns its memory handles, including pmem image handles, and
/// spawn branches those handles copy-on-write. Spawn-time callers provide only
/// live host backends that cannot be carried in the frozen VM state.
pub struct SpawnBackends<'a, F: FsBackend, N: NetBackend = NullNetBackend> {
    /// Console I/O backend (always required).
    pub console: &'a dyn amla_core::backends::ConsoleBackend,
    /// Network backend (required if config has net).
    ///
    /// This is intentionally raw device plumbing. Callers that advertise a
    /// security boundary must pass a policy-enforced outer backend.
    pub net: Option<&'a N>,
    /// Filesystem backend (required if config has fs).
    ///
    /// The `F` type parameter is monomorphized by the caller — when no FS
    /// device is configured, pass `Option::<&NullFsBackend>::None`
    /// (or any concrete `F`) since the variant is never instantiated.
    pub fs: Option<&'a F>,
}

impl<F: FsBackend, N: NetBackend> Clone for SpawnBackends<'_, F, N> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: FsBackend, N: NetBackend> Copy for SpawnBackends<'_, F, N> {}

impl<F: FsBackend, N: NetBackend> std::fmt::Debug for Backends<'_, F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Backends")
            .field("console", &"(..)")
            .field("net", &self.net.map(|_| "(..)"))
            .field("fs", &self.fs.map(|_| "(..)"))
            .field("pmem_count", &self.pmem.len())
            .finish()
    }
}

impl<F: FsBackend, N: NetBackend> std::fmt::Debug for SpawnBackends<'_, F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SpawnBackends")
            .field("console", &"(..)")
            .field("net", &self.net.map(|_| "(..)"))
            .field("fs", &self.fs.map(|_| "(..)"))
            .finish()
    }
}

/// Validate that backends match the config's device requirements.
///
/// Returns typed errors:
/// - `MissingNetBackend` if config has net but `backends.net` is `None`
/// - `MissingFsBackend` if config has fs but `backends.fs` is `None`
/// - `PmemCountMismatch` if `backends.pmem.len()` != config pmem disk count
pub fn validate_load_backends<F: FsBackend, N: NetBackend>(
    backends: &Backends<'_, F, N>,
    config: &crate::VmConfig,
) -> std::result::Result<(), ConfigError> {
    validate_runtime_backends(backends.net, backends.fs.is_some(), config)?;
    let pmem_count: usize = config.pmem_disks.iter().map(|d| d.images.len()).sum();

    if backends.pmem.len() != pmem_count {
        return Err(ConfigError::PmemCountMismatch {
            provided: backends.pmem.len(),
            expected: pmem_count,
        });
    }
    Ok(())
}

/// Validate that spawn-time backends match the config's runtime devices.
pub fn validate_spawn_backends<F: FsBackend, N: NetBackend>(
    backends: &SpawnBackends<'_, F, N>,
    config: &crate::VmConfig,
) -> std::result::Result<(), ConfigError> {
    validate_runtime_backends(backends.net, backends.fs.is_some(), config)
}

fn validate_runtime_backends<N: NetBackend>(
    net_backend: Option<&N>,
    has_fs_backend: bool,
    config: &crate::VmConfig,
) -> std::result::Result<(), ConfigError> {
    let Some(net_config) = config.net.as_ref() else {
        if config.fs.is_some() && !has_fs_backend {
            return Err(ConfigError::MissingFsBackend);
        }
        return Ok(());
    };

    let Some(net_backend) = net_backend else {
        return Err(ConfigError::MissingNetBackend);
    };

    if let Some(backend_mac) = net_backend.guest_mac() {
        let config_mac = net_config.guest_mac();
        if backend_mac != config_mac {
            return Err(ConfigError::NetBackendGuestMacMismatch {
                config: config_mac,
                backend: backend_mac,
            });
        }
    }

    if config.fs.is_some() && !has_fs_backend {
        return Err(ConfigError::MissingFsBackend);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, IoSlice};

    struct MacBackend(Option<[u8; 6]>);

    impl amla_core::backends::NetBackend for MacBackend {
        type RxPacket<'a> = amla_core::backends::NoRxPacket;

        fn guest_mac(&self) -> Option<[u8; 6]> {
            self.0
        }

        fn send(&self, _bufs: &[IoSlice<'_>]) -> io::Result<()> {
            Ok(())
        }

        fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
            Ok(None)
        }

        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn validate_runtime_backends_accepts_matching_guest_mac() {
        let config = crate::VmConfig::default().net(crate::NetConfig::default());
        let backend = MacBackend(Some(amla_constants::net::DEFAULT_GUEST_MAC));

        validate_runtime_backends(Some(&backend), false, &config).unwrap();
    }

    #[test]
    fn validate_runtime_backends_rejects_guest_mac_mismatch() {
        let config = crate::VmConfig::default().net(crate::NetConfig::default());
        let backend = MacBackend(Some([1, 2, 3, 4, 5, 6]));

        let err = validate_runtime_backends(Some(&backend), false, &config).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::NetBackendGuestMacMismatch {
                config: amla_constants::net::DEFAULT_GUEST_MAC,
                backend: [1, 2, 3, 4, 5, 6],
            }
        ));
    }
}
