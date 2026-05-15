// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Virtio filesystem device — FUSE over virtqueues.
//!
//! Queues: hiprio (0) for high-priority requests, plus 1..=N request queues.
//! Queue processing is a no-op here — actual FUSE request handling is done
//! asynchronously via `Device::poll_fs` in the VMM layer.

#[cfg(test)]
mod tests;

use amla_virtio::{DEVICE_ID_FS, QueueView, QueueViolation, VIRTIO_F_VERSION_1, VirtioDevice};

/// Queue index for hiprio (high-priority / notification) queue.
pub const HIPRIO_QUEUE: usize = 0;

/// First request queue index. Request queues span `FIRST_REQUEST_QUEUE..FIRST_REQUEST_QUEUE + num_request_queues`.
pub const FIRST_REQUEST_QUEUE: usize = 1;

/// Maximum number of request queues (limited by `FsState` slot size).
pub const MAX_REQUEST_QUEUES: u32 = 9;
const MAX_REQUEST_QUEUES_U8: u8 = 9;

/// Error returned when a virtio-fs request queue count is outside `1..=9`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestQueueCountError {
    value: u32,
}

impl RequestQueueCountError {
    /// Return the rejected raw value.
    #[must_use]
    pub const fn value(self) -> u32 {
        self.value
    }
}

impl std::fmt::Display for RequestQueueCountError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "request queue count {} is outside 1..={MAX_REQUEST_QUEUES}",
            self.value
        )
    }
}

impl std::error::Error for RequestQueueCountError {}

/// Validated number of virtio-fs request queues.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestQueueCount(u8);

impl RequestQueueCount {
    /// Single request queue.
    pub const ONE: Self = Self(1);

    /// Maximum supported request queue count.
    pub const MAX: Self = Self(MAX_REQUEST_QUEUES_U8);

    /// Validate a raw request queue count.
    ///
    /// # Errors
    ///
    /// Returns [`RequestQueueCountError`] when `value` is not in
    /// `1..=MAX_REQUEST_QUEUES`.
    pub fn new(value: u32) -> Result<Self, RequestQueueCountError> {
        let value_u8 = u8::try_from(value).map_err(|_| RequestQueueCountError { value })?;
        if value == 0 || value > MAX_REQUEST_QUEUES {
            return Err(RequestQueueCountError { value });
        }
        Ok(Self(value_u8))
    }

    /// Return the validated count as `u8`.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// Return the validated count as `u32`.
    #[must_use]
    pub const fn as_u32(self) -> u32 {
        self.0 as u32
    }

    /// Return the total virtqueue count including the hiprio queue.
    #[must_use]
    pub const fn total_queue_count(self) -> usize {
        FIRST_REQUEST_QUEUE + self.0 as usize
    }
}

impl TryFrom<u32> for RequestQueueCount {
    type Error = RequestQueueCountError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<RequestQueueCount> for u32 {
    fn from(value: RequestQueueCount) -> Self {
        value.as_u32()
    }
}

impl From<RequestQueueCount> for usize {
    fn from(value: RequestQueueCount) -> Self {
        Self::from(value.get())
    }
}

impl Default for RequestQueueCount {
    fn default() -> Self {
        Self::ONE
    }
}

/// Virtio filesystem device.
///
/// Implements `VirtioDevice` for MMIO transport dispatch (device ID, features,
/// queue count). Queue processing is a no-op — FS requests are handled
/// asynchronously via `Device::poll_fs`.
pub struct Fs {
    /// Total queue count: 1 (hiprio) + `num_request_queues`.
    queue_count: usize,
}

impl Fs {
    /// Create with the given validated number of request queues.
    #[must_use]
    pub const fn new(num_request_queues: RequestQueueCount) -> Self {
        Self {
            queue_count: num_request_queues.total_queue_count(),
        }
    }
}

impl Default for Fs {
    fn default() -> Self {
        Self::new(RequestQueueCount::ONE)
    }
}

impl<M: amla_core::vm_state::guest_mem::GuestMemory> VirtioDevice<M> for Fs {
    fn device_id(&self) -> u32 {
        DEVICE_ID_FS
    }

    fn queue_count(&self) -> usize {
        self.queue_count
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        _queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        // No-op: FS requests are processed asynchronously via Device::poll_fs.
        Ok(())
    }
}
