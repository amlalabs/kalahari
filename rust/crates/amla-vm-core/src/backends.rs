// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Backend traits for virtio devices.
//!
//! These traits define the host-side I/O interfaces that virtio devices use.
//! Backend implementations live in separate crates (amla-usernet, amla-vmm, etc.).
//! Backend-internal state is outside the mmap-backed VM snapshot; callers that
//! need backend continuity across `freeze()` / `spawn()` must preserve or
//! explicitly snapshot and restore the backend object.

use std::io::{self, IoSlice};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Cancelable host-side wake token for backend RX notifications.
///
/// Backends may clone this token into detached I/O tasks. Once the VMM run that
/// registered it ends, the registration cancels the token so stale tasks cannot
/// wake a later VM run or retain live control-plane state.
#[derive(Clone)]
pub struct RxWaker {
    inner: Arc<RxWakerInner<dyn Fn() + Send + Sync + 'static>>,
}

struct RxWakerInner<F: Fn() + Send + Sync + ?Sized> {
    active: AtomicBool,
    callback: F,
}

impl RxWaker {
    /// Create an active RX waker from a host callback.
    pub fn new<F>(callback: F) -> Self
    where
        F: Fn() + Send + Sync + 'static,
    {
        Self {
            inner: Arc::new(RxWakerInner {
                active: AtomicBool::new(true),
                callback,
            }),
        }
    }

    /// Wake the registered receiver if this token is still active.
    pub fn wake(&self) {
        if self.inner.active.load(Ordering::Acquire) {
            (self.inner.callback)();
        }
    }

    /// Cancel this token and every clone derived from it.
    pub fn cancel(&self) {
        self.inner.active.store(false, Ordering::Release);
    }

    /// Return whether this token still wakes its receiver.
    pub fn is_active(&self) -> bool {
        self.inner.active.load(Ordering::Acquire)
    }
}

// =============================================================================
// Console Backend
// =============================================================================

/// Backend for console I/O operations.
///
/// Implementations provide the host-side read/write for the virtio console device.
pub trait ConsoleBackend: Send + Sync {
    /// Write data from guest to console output.
    ///
    /// This is a record-atomic operation from the device's perspective: the
    /// backend must accept all bytes or return an error without making any
    /// partial guest-visible side effects.
    fn write(&self, data: &[u8]) -> io::Result<()>;

    /// Read data from console input for guest.
    ///
    /// Returns the number of bytes read, or `WouldBlock` if no data available.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize>;

    /// Check if there's input data available (non-blocking).
    ///
    /// Backends that can produce input **must** override this method.
    /// The default returns `false`, which causes the RX queue processor to skip
    /// queue processing entirely — meaning `read()` will never be called.
    fn has_pending_input(&self) -> bool {
        false
    }

    /// Set a waker callback invoked when RX data may be available for the guest.
    ///
    /// The VMM calls this before starting the device to wire up async
    /// notifications. The backend should invoke the waker after receiving
    /// host→guest input.
    fn set_rx_waker(&self, _waker: Option<RxWaker>) {}

    /// Handle emergency write (single character, no queue needed).
    fn emergency_write(&self, ch: u8) -> io::Result<()> {
        self.write(&[ch])?;
        Ok(())
    }

    /// Create an owned console writer for serial PIO forwarding.
    ///
    /// On x86, guest serial port (UART) writes need a `Send + Sync` console
    /// handle that can live on vCPU threads. The default returns `None`
    /// (no serial forwarding). Override in backends that support cloning
    /// (e.g. `ConsoleStream` clones via `Arc`).
    fn clone_writer(&self) -> Option<Box<dyn ConsoleBackend>> {
        None
    }
}

// =============================================================================
// Network Backend
// =============================================================================

/// Backend for network I/O operations.
///
/// Implementations must be Send + Sync for use across threads.
/// The device calls `set_nonblocking(true)` during activation — backends
/// that wrap blocking file descriptors must support this.
pub trait NetBackend: Send + Sync {
    /// Guest MAC address this backend expects, if the backend enforces one.
    ///
    /// Backends that validate Ethernet source identity should return `Some`
    /// so the VMM can reject mismatched VM/backend wiring before the guest
    /// boots. Generic passthrough or drop-only backends may return `None`.
    fn guest_mac(&self) -> Option<[u8; 6]> {
        None
    }

    /// Send a packet to the network (scatter-gather).
    ///
    /// `bufs` is a slice of `IoSlice` representing one complete packet. The
    /// backend must accept/drop the whole packet or return an error without
    /// consuming any prefix as a successful partial send.
    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()>;

    /// Scoped lease for the next guest-bound packet.
    type RxPacket<'a>: NetRxPacketLease<'a>
    where
        Self: 'a;

    /// Lease the next guest-bound packet, if one is available.
    ///
    /// Dropping the returned lease leaves the packet pending. Calling
    /// [`NetRxPacketLease::commit`] consumes exactly the packet exposed by the
    /// lease.
    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>>;

    /// Set non-blocking mode.
    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()>;

    /// Set a waker callback invoked when RX data may be available for the guest.
    ///
    /// The VMM calls this before starting the device to wire up async
    /// notifications. The backend should invoke the waker after generating
    /// response packets.
    fn set_rx_waker(&self, _waker: Option<RxWaker>) {}
}

/// Borrowed packet leased from a [`NetBackend`].
pub trait NetRxPacketLease<'a> {
    /// Packet bytes that will be consumed by this lease.
    fn packet(&self) -> &[u8];

    /// Consume the leased packet after the caller has durably accepted it.
    fn commit(self) -> io::Result<()>;
}

/// Uninhabited packet lease used by backends that never receive packets.
pub enum NoRxPacket {}

impl NetRxPacketLease<'_> for NoRxPacket {
    fn packet(&self) -> &[u8] {
        // `NoRxPacket` is uninhabited (zero variants), so any reference to
        // it is statically unreachable. We use `unreachable_unchecked()` to
        // express this without dereferencing the `&Never` (which clippy's
        // `uninhabited_references` correctly flags as UB).
        //
        // SAFETY: reaching this branch requires a live `&NoRxPacket`, which
        // cannot be constructed because `NoRxPacket` has no inhabitants.
        unsafe { std::hint::unreachable_unchecked() }
    }

    fn commit(self) -> io::Result<()> {
        match self {}
    }
}

/// Network backend that drops all packets.
///
/// This provides complete network isolation — no packets ever leave the VM.
#[derive(Debug)]
pub struct NullNetBackend {
    dropped_tx: AtomicU64,
}

impl Default for NullNetBackend {
    fn default() -> Self {
        Self {
            dropped_tx: AtomicU64::new(0),
        }
    }
}

impl NullNetBackend {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn dropped_tx_count(&self) -> u64 {
        self.dropped_tx.load(Ordering::Relaxed)
    }
}

impl NetBackend for NullNetBackend {
    type RxPacket<'a> = NoRxPacket;

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let total: usize = bufs.iter().map(|b| b.len()).sum();
        self.dropped_tx.fetch_add(1, Ordering::Relaxed);
        log::trace!("NullNetBackend: dropped {total} byte packet");
        Ok(())
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Ok(None)
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::RxWaker;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn rx_waker_cancel_disarms_all_clones() {
        let count = Arc::new(AtomicUsize::new(0));
        let waker = {
            let count = Arc::clone(&count);
            RxWaker::new(move || {
                count.fetch_add(1, Ordering::SeqCst);
            })
        };
        let clone = waker.clone();

        waker.wake();
        assert_eq!(count.load(Ordering::SeqCst), 1);

        clone.cancel();
        waker.wake();
        clone.wake();

        assert!(!waker.is_active());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
