// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! KVM-specific device waker that internally polls ioeventfds.
//!
//! Wraps [`BasicDeviceWaker`] with `AsyncFd<EventFd>` per device slot.
//! Eventfds never leave this crate — the [`DeviceWaker`] trait is the
//! only interface exposed to the VMM layer.

use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};

use tokio::io::unix::AsyncFd;
use vmm_sys_util::eventfd::EventFd;

use crate::{Result, VmmError};
use amla_core::{BasicDeviceWaker, DeviceWakeIndex, DeviceWakeResult, DeviceWaker};

/// Newtype for `Arc<EventFd>` that implements `AsRawFd`.
///
/// Required by `AsyncFd` which needs the inner type to implement `AsRawFd`.
struct SharedEventFd(Arc<EventFd>);

impl AsRawFd for SharedEventFd {
    fn as_raw_fd(&self) -> i32 {
        self.0.as_raw_fd()
    }
}

/// KVM-specific device waker that polls ioeventfds internally.
///
/// Combines a [`BasicDeviceWaker`] (atomic bitmask + stored waker) with
/// `AsyncFd<EventFd>` per device slot. When `poll_wait` is called, it
/// drains all ready eventfds, sets the corresponding bits, then delegates
/// to the base waker.
///
/// This replaces the old `ioevent_poller` task — instead of a separate
/// bridging task, the polling is done inline by the device loop.
pub struct KvmDeviceWaker {
    base: BasicDeviceWaker,
    afds: Vec<(
        AsyncFd<SharedEventFd>,
        DeviceWakeIndex,
        Option<Arc<AtomicBool>>,
    )>,
}

impl KvmDeviceWaker {
    /// Create a `KvmDeviceWaker` from `(eventfd, wake_index, pending_flag)` tuples.
    ///
    /// Each eventfd is wrapped in an `AsyncFd` for reactor integration.
    pub fn new(
        entries: Vec<(Arc<EventFd>, DeviceWakeIndex, Option<Arc<AtomicBool>>)>,
    ) -> Result<Self> {
        let mut afds = Vec::with_capacity(entries.len());
        for (efd, idx, pending) in entries {
            let afd = AsyncFd::new(SharedEventFd(efd)).map_err(|source| VmmError::SystemCall {
                operation: "AsyncFd::new(ioeventfd)",
                source,
            })?;
            afds.push((afd, idx, pending));
        }

        Ok(Self {
            base: BasicDeviceWaker::new(),
            afds,
        })
    }

    fn drain_ready_eventfds(&self, cx: &mut Context<'_>) -> DeviceWakeResult {
        // Drain loop: keep polling until no fd is ready. This ensures
        // every fd's final `poll_read_ready(cx)` returns Pending, which
        // registers the waker with the reactor. Without this loop, an
        // fd that was Ready+cleared would have no waker registered if
        // new data arrives later.
        loop {
            let mut any_ready = false;
            for (afd, idx, pending) in &self.afds {
                match afd.poll_read_ready(cx) {
                    Poll::Ready(Ok(mut guard)) => {
                        guard.clear_ready();
                        match afd.get_ref().0.read() {
                            Ok(_) => {
                                if let Some(pending) = pending {
                                    pending.store(true, Ordering::Release);
                                }
                                self.base.set_bit(*idx);
                                any_ready = true;
                            }
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                            Err(source) => {
                                return Err(Box::new(VmmError::SystemCall {
                                    operation: "device_waker eventfd read",
                                    source,
                                }));
                            }
                        }
                    }
                    Poll::Ready(Err(source)) => {
                        return Err(Box::new(VmmError::SystemCall {
                            operation: "device_waker poll_read_ready",
                            source,
                        }));
                    }
                    Poll::Pending => {}
                }
            }
            if !any_ready {
                break Ok(());
            }
        }
    }
}

impl DeviceWaker for KvmDeviceWaker {
    fn kick(&self, idx: DeviceWakeIndex) {
        self.base.kick(idx);
    }

    fn set_bit(&self, idx: DeviceWakeIndex) {
        self.base.set_bit(idx);
    }

    fn take_pending(&self) -> u64 {
        self.base.take_pending()
    }

    fn drain_pending_sources(&self) -> DeviceWakeResult {
        let waker = std::task::Waker::noop();
        let mut cx = Context::from_waker(waker);
        self.drain_ready_eventfds(&mut cx)
    }

    fn poll_wait(&self, cx: &mut Context<'_>) -> Poll<DeviceWakeResult> {
        if let Err(error) = self.drain_ready_eventfds(cx) {
            return Poll::Ready(Err(error));
        }
        // Delegate to base: store waker, check pending bits.
        self.base.poll_wait(cx)
    }
}
