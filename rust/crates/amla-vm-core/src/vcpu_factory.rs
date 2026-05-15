// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Factory traits for creating backend-agnostic IRQ lines and device wakers.
//!
//! These traits allow the VMM layer to create hypervisor resources without
//! depending on a specific backend (KVM, HVF, WHP).

use crate::IrqLine;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};

/// Result returned by backend device-wake polling.
pub type DeviceWakeResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

/// Valid wake-bit index for [`DeviceWaker`].
///
/// Device wake state is represented as a `u64` bitset, so only indexes
/// `0..64` are representable. Carrying this as a type keeps invalid shift
/// counts out of release builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DeviceWakeIndex(u8);

impl DeviceWakeIndex {
    /// Number of wake bits representable by the device waker bitset.
    pub const MAX: usize = u64::BITS as usize;

    /// Construct a wake index after checking it fits the waker bitset.
    pub fn new(index: usize) -> Result<Self, DeviceWakeIndexError> {
        match u8::try_from(index) {
            Ok(index_u8) if usize::from(index_u8) < Self::MAX => Ok(Self(index_u8)),
            _ => Err(DeviceWakeIndexError { index }),
        }
    }

    /// Return the wake index as a `usize`.
    pub const fn as_usize(self) -> usize {
        self.0 as usize
    }

    /// Return the wake index as a compact wire integer.
    pub const fn as_u8(self) -> u8 {
        self.0
    }

    /// Return the bitmask represented by this wake index.
    pub const fn mask(self) -> u64 {
        1u64 << self.0
    }
}

impl TryFrom<usize> for DeviceWakeIndex {
    type Error = DeviceWakeIndexError;

    fn try_from(index: usize) -> Result<Self, Self::Error> {
        Self::new(index)
    }
}

impl TryFrom<u8> for DeviceWakeIndex {
    type Error = DeviceWakeIndexError;

    fn try_from(index: u8) -> Result<Self, Self::Error> {
        Self::new(usize::from(index))
    }
}

impl From<DeviceWakeIndex> for usize {
    fn from(index: DeviceWakeIndex) -> Self {
        index.as_usize()
    }
}

impl From<DeviceWakeIndex> for u8 {
    fn from(index: DeviceWakeIndex) -> Self {
        index.as_u8()
    }
}

impl fmt::Display for DeviceWakeIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Error returned when a wake bit index cannot fit in [`DeviceWakeIndex`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("device wake index {index} exceeds max {}", DeviceWakeIndex::MAX - 1)]
pub struct DeviceWakeIndexError {
    /// Rejected wake index.
    pub index: usize,
}

/// Factory for creating IRQ lines.
///
/// This abstracts over the backend-specific mechanism for creating interrupt
/// delivery channels. On KVM, this uses irqfd/eventfd. On HVF, it would
/// use the native interrupt injection API.
pub trait IrqFactory {
    /// Create a level-triggered (resampled) IRQ line for the given GSI.
    ///
    /// Resampled IRQ lines support EOI notification, which is needed for
    /// level-triggered interrupts used by most virtio devices.
    fn create_resampled_irq_line(
        &self,
        gsi: u32,
    ) -> Result<Box<dyn IrqLine>, Box<dyn std::error::Error + Send + Sync>>;
}

// =============================================================================
// DeviceWaker — unified device polling notification
// =============================================================================

/// Coordinates device polling notifications. Backend-specific:
/// KVM polls eventfds internally, other backends use direct kicks.
///
/// The waker manages a 64-bit bitmask where each bit represents one device.
/// When a bit is set, the corresponding device has pending work and needs
/// `poll()` called.
///
/// # Implementations
///
/// - [`BasicDeviceWaker`]: Bitmask + stored `Waker`. Used by non-KVM backends
///   (HVF, Hyper-V, stub) and as the base for `KvmDeviceWaker`.
/// - `KvmDeviceWaker` (in `amla-kvm`): Wraps `BasicDeviceWaker` plus
///   `AsyncFd<EventFd>` for each ioeventfd. Eventfds never leave `amla-kvm`.
pub trait DeviceWaker: Send + Sync {
    /// Signal that device `idx` needs polling (sets bit + wakes task).
    fn kick(&self, idx: DeviceWakeIndex);

    /// Set bit without waking (caller is already processing).
    fn set_bit(&self, idx: DeviceWakeIndex);

    /// Atomically take all pending device bits.
    fn take_pending(&self) -> u64;

    /// Drain backend-owned notification sources into the pending bitmask.
    ///
    /// Most backends only use [`Self::kick`] and therefore have no extra work.
    /// KVM overrides this to sample ioeventfds before stop-time quiesce.
    fn drain_pending_sources(&self) -> DeviceWakeResult {
        Ok(())
    }

    /// Poll for device work. Returns `Ready` when `pending != 0`.
    ///
    /// Implementations must store `cx.waker()` so that a subsequent `kick()`
    /// can wake the task. The standard pattern:
    ///
    /// 1. Store the waker from `cx`
    /// 2. Check pending bits
    /// 3. Return `Ready(())` if any bits are set, `Pending` otherwise
    ///
    /// `kick()` may fire between steps 1 and 3 — because the waker is
    /// already stored, `wake()` reaches the right task. If `kick()` fires
    /// before the waker is stored, the bit is set and step 2 sees it
    /// immediately.
    fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<DeviceWakeResult>;
}

/// Basic device waker using an atomic bitmask and a stored `Waker`.
///
/// Used directly by non-KVM backends (HVF, Hyper-V, stub). Also serves
/// as the base layer inside `KvmDeviceWaker`.
pub struct BasicDeviceWaker {
    pending: AtomicU64,
    task_waker: parking_lot::Mutex<Option<Waker>>,
}

impl BasicDeviceWaker {
    /// Create a new `BasicDeviceWaker` with no pending bits.
    pub const fn new() -> Self {
        Self {
            pending: AtomicU64::new(0),
            task_waker: parking_lot::Mutex::new(None),
        }
    }
}

impl Default for BasicDeviceWaker {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceWaker for BasicDeviceWaker {
    fn kick(&self, idx: DeviceWakeIndex) {
        self.pending.fetch_or(idx.mask(), Ordering::Release);
        let waker_opt = {
            let guard = self.task_waker.lock();
            guard.clone()
        };
        if let Some(w) = waker_opt {
            w.wake();
        }
    }

    fn set_bit(&self, idx: DeviceWakeIndex) {
        self.pending.fetch_or(idx.mask(), Ordering::Release);
    }

    fn take_pending(&self) -> u64 {
        self.pending.swap(0, Ordering::Acquire)
    }

    fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<DeviceWakeResult> {
        // Store waker first, then check bits. This ordering ensures
        // a kick() between store and check still wakes us.
        {
            let mut guard = self.task_waker.lock();
            *guard = Some(cx.waker().clone());
        }
        if self.pending.load(Ordering::Acquire) != 0 {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_wake_index_rejects_unrepresentable_bits() {
        assert_eq!(DeviceWakeIndex::new(63).unwrap().mask(), 1u64 << 63);
        assert!(matches!(
            DeviceWakeIndex::new(64),
            Err(DeviceWakeIndexError { index: 64 })
        ));
    }

    #[test]
    fn basic_device_waker_uses_typed_masks() {
        let waker = BasicDeviceWaker::new();
        waker.set_bit(DeviceWakeIndex::new(3).unwrap());
        waker.kick(DeviceWakeIndex::new(5).unwrap());

        assert_eq!(waker.take_pending(), (1u64 << 3) | (1u64 << 5));
    }
}
