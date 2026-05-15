// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Platform-specific IPC implementations.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "linux")]
pub use linux::{RingBuffer, Subprocess};
#[cfg(target_os = "macos")]
pub use macos::{RingBuffer, Subprocess};

#[cfg(target_os = "linux")]
pub type Sender<'a> = crate::channel::Sender<'a, linux::LinuxDoorbellSend, linux::LinuxAuxSend>;

#[cfg(target_os = "linux")]
pub type SendPermit<'s, 'a> =
    crate::channel::SendPermit<'s, 'a, linux::LinuxDoorbellSend, linux::LinuxAuxSend>;

#[cfg(target_os = "linux")]
pub type Receiver<'a> = crate::channel::Receiver<'a, linux::LinuxDoorbellRecv, linux::LinuxAuxRecv>;

#[cfg(target_os = "macos")]
pub type Sender<'a> = crate::channel::Sender<'a, macos::MacosDoorbellSend, macos::MacosAuxSend<'a>>;

#[cfg(target_os = "macos")]
pub type SendPermit<'s, 'a> =
    crate::channel::SendPermit<'s, 'a, macos::MacosDoorbellSend, macos::MacosAuxSend<'a>>;

#[cfg(target_os = "macos")]
pub type Receiver<'a> = crate::channel::Receiver<'a, macos::MacosDoorbellRecv, macos::MacosAuxRecv>;

/// Non-owning fd wrapper for `AsyncFd` registration.
pub(crate) struct RawFdWrap(pub(crate) std::os::fd::RawFd);

impl std::os::fd::AsRawFd for RawFdWrap {
    fn as_raw_fd(&self) -> std::os::fd::RawFd {
        self.0
    }
}
