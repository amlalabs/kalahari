// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Inter-process communication for amla-vm subprocess mode.
//!
//! ## Architecture
//!
//! - **Ring buffer**: postcard-serialized data (fast, shared memory)
//! - **Doorbell**: notification that ring data is available
//! - **Aux transport**: out-of-band resource transfer (`AuxSlot` = fd + metadata)
//! - **IpcResource trait**: types that travel on the aux transport
//!
//! The `IpcMessage` derive macro extracts `#[ipc_resource]` fields into
//! `AuxSlot`s automatically. Multiple resource types can coexist in one
//! message — each just needs `impl IpcResource`.
//!
//! ## Compatibility
//!
//! IPC schemas are same-version only. The ring frame carries transport
//! sequencing and aux-slot counts, not an independent schema version, and
//! `IpcMessage` payloads use postcard over the current generated wire type.
//! Endpoints must be launched from the same source version; this crate does not
//! provide a durable or independently upgraded wire ABI.

#[cfg(unix)]
mod aux_frame;
#[cfg(unix)]
pub mod channel;
pub mod codec;
#[cfg(unix)]
pub mod platform;

#[doc(hidden)]
pub mod __private {
    pub use log;
}

/// Debug trace helper for temporary IPC instrumentation.
#[macro_export]
macro_rules! dbg_log {
    ($($arg:tt)*) => {{
        $crate::__private::log::trace!($($arg)*);
    }};
}

pub use amla_ipc_derive::IpcMessage;
#[cfg(unix)]
pub use channel::{AuxRecv, AuxSend, DoorbellRecv, DoorbellSend};
#[cfg(unix)]
pub use codec::{ResourceSlots, take_slot};
#[cfg(unix)]
pub use platform::{Receiver, RingBuffer, SendPermit, Sender, Subprocess};

// ============================================================================
// AuxSlot — what travels on the aux transport per resource
// ============================================================================

/// A single resource payload for out-of-band transfer (Linux: fd via SCM_RIGHTS).
#[cfg(target_os = "linux")]
pub struct AuxSlot {
    /// Shared fd ownership — the kernel performs the real ownership transfer
    /// via SCM_RIGHTS, and an `Arc` lets the sender keep holding the handle
    /// (e.g. as a `MemHandle`) while the aux-transport frames fan out.
    pub fd: std::sync::Arc<std::os::fd::OwnedFd>,
    /// Resource-specific metadata (e.g., size in bytes for `MemHandle`).
    pub meta: u64,
}

/// A single resource payload for out-of-band transfer (macOS: Mach port via mach_msg).
#[cfg(target_os = "macos")]
pub struct AuxSlot {
    /// Mach memory entry send right.
    pub port: u32,
    /// Resource-specific metadata (e.g., size in bytes for `MemHandle`).
    pub meta: u64,
}

#[cfg(target_os = "macos")]
impl Drop for AuxSlot {
    fn drop(&mut self) {
        if self.port != 0 {
            amla_mem::platform::macos::deallocate_port(self.port);
        }
    }
}

// ============================================================================
// IpcResource — types that can travel on the aux transport
// ============================================================================

/// Trait for types transferred out-of-band via the aux transport.
#[cfg(unix)]
pub trait IpcResource: Sized {
    /// Serialize into an aux slot for transfer.
    fn into_slot(self) -> std::io::Result<AuxSlot>;
    /// Reconstruct from a received aux slot.
    fn from_slot(slot: AuxSlot) -> std::io::Result<Self>;
}

/// Bit 63 of `AuxSlot::meta` encodes the writable flag for `MemHandle`.
///
/// Sizes cannot reach 2^63, so this bit is always free. This ensures
/// file-backed (read-only) handles survive IPC transfer without losing
/// their read-only semantics — without it, `map_handle()` on the
/// receiving side would attempt a `MAP_SHARED` RW mmap on a read-only
/// fd (Linux) or entry (macOS), causing EACCES.
#[cfg(unix)]
const META_WRITABLE_FLAG: u64 = 1 << 63;

/// Encode size + writable flag into the meta field.
#[cfg(unix)]
fn encode_meta(size: u64, writable: bool) -> std::io::Result<u64> {
    if size & META_WRITABLE_FLAG != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "mem handle size overflows",
        ));
    }
    if writable {
        Ok(size | META_WRITABLE_FLAG)
    } else {
        Ok(size)
    }
}

/// Decode meta field into (size, writable).
#[cfg(unix)]
fn decode_meta(meta: u64) -> std::io::Result<(usize, bool)> {
    let writable = (meta & META_WRITABLE_FLAG) != 0;
    let size = usize::try_from(meta & !META_WRITABLE_FLAG).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "mem handle size overflows")
    })?;
    Ok((size, writable))
}

#[cfg(target_os = "linux")]
impl IpcResource for amla_mem::MemHandle {
    fn into_slot(self) -> std::io::Result<AuxSlot> {
        let meta = encode_meta(*self.size() as u64, self.is_writable())?;
        Ok(AuxSlot {
            fd: self.fd_arc(),
            meta,
        })
    }

    fn from_slot(slot: AuxSlot) -> std::io::Result<Self> {
        let (size, writable) = decode_meta(slot.meta)?;
        if writable {
            amla_mem::MemHandle::from_fd_arc(slot.fd, size).map_err(std::io::Error::other)
        } else {
            amla_mem::MemHandle::from_fd_arc_readonly(slot.fd, size).map_err(std::io::Error::other)
        }
    }
}

#[cfg(target_os = "macos")]
impl IpcResource for amla_mem::MemHandle {
    fn into_slot(self) -> std::io::Result<AuxSlot> {
        let meta = encode_meta(*self.size() as u64, self.is_writable())?;
        let port = self.into_port().map_err(std::io::Error::other)?;
        Ok(AuxSlot { port, meta })
    }

    fn from_slot(mut slot: AuxSlot) -> std::io::Result<Self> {
        let (size, writable) = decode_meta(slot.meta)?;
        // Take ownership of the port — zero it so AuxSlot's Drop doesn't deallocate.
        let port = std::mem::replace(&mut slot.port, 0);
        if writable {
            // SAFETY: `port` is a valid send right to a `size`-byte Mach memory object owned by the task; ownership transfers.
            unsafe { amla_mem::MemHandle::from_mach_port(port, size) }
                .map_err(std::io::Error::other)
        } else {
            // SAFETY: `port` is a valid send right to a `size`-byte Mach memory object owned by the task; ownership transfers.
            unsafe { amla_mem::MemHandle::from_mach_port_readonly(port, size) }
                .map_err(std::io::Error::other)
        }
    }
}

// ============================================================================
// IpcMessage trait
// ============================================================================

/// Trait for types that can be split into serializable data + aux resources.
///
/// Generated by `#[derive(IpcMessage)]`. Fields marked `#[ipc_resource]`
/// are extracted as `AuxSlot`s; everything else goes through postcard.
#[cfg(unix)]
pub trait IpcMessage: Sized {
    fn serialize(self) -> Result<(Vec<u8>, Vec<AuxSlot>)>;
    fn deserialize(data: &[u8], slots: Vec<AuxSlot>) -> Result<Self>;
}

// ============================================================================
// Error
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("codec: {0}")]
    Codec(#[from] postcard::Error),
    #[error("missing resource at index {0}")]
    MissingResource(u32),
    #[error("unused resource at index {0}")]
    UnusedResource(u32),
    #[error("protocol: {0}")]
    Protocol(&'static str),
    #[cfg(unix)]
    #[error("ring: {0}")]
    Ring(amla_vm_ringbuf::RingError),
}

#[cfg(unix)]
impl From<amla_vm_ringbuf::RingError> for Error {
    fn from(e: amla_vm_ringbuf::RingError) -> Self {
        Self::Ring(e)
    }
}

pub type Result<T> = std::result::Result<T, Error>;
