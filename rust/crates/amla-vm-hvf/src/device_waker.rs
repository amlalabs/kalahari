// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF subprocess device waker — delegates to `BasicDeviceWaker`.

use std::task::{Context, Poll};

use amla_core::{BasicDeviceWaker, DeviceWakeIndex, DeviceWakeResult, DeviceWaker};

/// Device waker for the HVF subprocess backend.
///
/// Wraps [`BasicDeviceWaker`] — the bitmask + stored `Waker` pattern
/// shared by all non-KVM backends. IPC `DeviceKick` messages arrive
/// in the `ipc_task` and call `kick()` to set the corresponding bit
/// and wake the device-polling task.
pub(crate) struct HvfDeviceWaker {
    base: BasicDeviceWaker,
}

impl HvfDeviceWaker {
    pub(crate) fn new() -> Self {
        Self {
            base: BasicDeviceWaker::new(),
        }
    }
}

impl DeviceWaker for HvfDeviceWaker {
    fn kick(&self, idx: DeviceWakeIndex) {
        self.base.kick(idx);
    }

    fn set_bit(&self, idx: DeviceWakeIndex) {
        self.base.set_bit(idx);
    }

    fn take_pending(&self) -> u64 {
        self.base.take_pending()
    }

    fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<DeviceWakeResult> {
        self.base.poll_wait(cx)
    }
}
