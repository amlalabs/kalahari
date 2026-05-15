// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Platform-agnostic hardware layout types shared by the real HVF backend
//! and the non-macOS stubs.

use amla_core::DeviceWakeIndex;

/// Per-device interrupt slot layout.
#[derive(Clone, Copy, Debug)]
pub struct DeviceSlotLayout {
    /// GSI for this device's interrupt line.
    pub gsi: u32,
    /// Queue wake bit to set when this interrupt line receives guest EOI.
    pub resample_wake_idx: Option<DeviceWakeIndex>,
}

/// Per-queue MMIO notification layout.
#[derive(Clone, Copy, Debug)]
pub struct IoEventSlotLayout {
    /// Device slot that owns this queue notification.
    pub device_idx: usize,
    /// MMIO `QueueNotify` address.
    pub mmio_notify_addr: u64,
    /// `QueueNotify` value.
    pub queue_idx: u32,
    /// Global queue wake bit.
    pub wake_idx: DeviceWakeIndex,
}

/// Fixed device topology for hardware pre-registration.
#[derive(Clone, Debug)]
pub struct HardwareLayout {
    /// Per-device IRQ layout.
    pub device_slots: Vec<DeviceSlotLayout>,
    /// Per-queue wake layout.
    pub io_slots: Vec<IoEventSlotLayout>,
}

impl HardwareLayout {
    pub const fn empty() -> Self {
        Self {
            device_slots: Vec::new(),
            io_slots: Vec::new(),
        }
    }

    pub fn from_device_and_queue_slots(
        device_slots: impl IntoIterator<Item = (u32, Option<DeviceWakeIndex>)>,
        io_slots: impl IntoIterator<Item = (usize, u64, u32, DeviceWakeIndex)>,
    ) -> Self {
        Self {
            device_slots: device_slots
                .into_iter()
                .map(|(gsi, resample_wake_idx)| DeviceSlotLayout {
                    gsi,
                    resample_wake_idx,
                })
                .collect(),
            io_slots: io_slots
                .into_iter()
                .map(
                    |(device_idx, mmio_notify_addr, queue_idx, wake_idx)| IoEventSlotLayout {
                        device_idx,
                        mmio_notify_addr,
                        queue_idx,
                        wake_idx,
                    },
                )
                .collect(),
        }
    }
}
