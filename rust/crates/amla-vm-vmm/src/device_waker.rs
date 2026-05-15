// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Single inline device loop: replaces per-device tokio tasks.
//!
//! Instead of spawning one tokio task per device, `device_loop` runs as a
//! single `select!` arm inside `run()`. It awaits the backend-specific
//! `DeviceWaker` (which internally polls ioeventfds on KVM) plus optional
//! console and net-RX notifications, then drains each pending device.

use std::{
    future::Future,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use futures_util::{StreamExt, stream::FuturesUnordered};
use tokio::sync::Notify;

use amla_core::backends::NetBackend;
use amla_core::{DeviceWakeIndex, DeviceWaker};

use crate::agent::AgentRingWake;
use crate::device::{AnyDevice, FS_MAX_REQUEST_BUDGET_BYTES, RingDevice};
use crate::devices::{DeviceKind, QueueWakeMap};
use crate::error::{DeviceError, Error};
use crate::shared_state::VmEnd;

/// Maximum drain iterations per device before yielding back to tokio.
/// Prevents a chatty device from starving the runtime.
const MAX_DRAIN_ROUNDS: u32 = 64;
const FS_MAX_IN_FLIGHT_REQUESTS: usize = 128;
const FS_MAX_IN_FLIGHT_BYTES: usize = 32 * 1024 * 1024;

/// Result of the final shutdown drain before snapshot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuiesceResult {
    /// All pending sync-device work drained within budget.
    Quiescent,
    /// A sync device still reported work after the final drain budget.
    SyncDeviceWorkRemaining(PendingSyncDeviceWork),
}

impl QuiesceResult {
    const fn merge(self, other: Self) -> Self {
        match self {
            Self::Quiescent => other,
            Self::SyncDeviceWorkRemaining(_) => self,
        }
    }

    /// Convert a final drain result into the typed VMM error space.
    pub(crate) const fn into_result(self) -> crate::Result<()> {
        match self {
            Self::Quiescent => Ok(()),
            Self::SyncDeviceWorkRemaining(pending) => {
                Err(Error::Device(DeviceError::ShutdownDrainExhausted {
                    device: pending.kind,
                    wake_idx: pending.wake_idx.as_usize(),
                    queue_idx: pending.queue_idx,
                    max_rounds: pending.max_rounds,
                }))
            }
        }
    }
}

/// Sync-device work that survived the final shutdown drain budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PendingSyncDeviceWork {
    /// Global wake bit index.
    pub wake_idx: DeviceWakeIndex,
    /// Device kind.
    pub kind: DeviceKind,
    /// Virtqueue index inside the device.
    pub queue_idx: usize,
    /// Maximum drain rounds attempted.
    pub max_rounds: u32,
}

/// Notification source that wakes a specific device in the device loop.
///
/// When `wake` fires, the device loop sets the waker bit for `idx`,
/// causing that device to be polled on the next drain cycle. Used for
/// console (host stdin) and network (RX packets from NAT proxy).
pub struct DeviceNotify {
    /// Wake-bit indexes to set when the notification fires.
    pub wake_indices: Vec<DeviceWakeIndex>,
    /// Async notification source.
    pub wake: Arc<Notify>,
    /// Sticky pending flag set before `wake` fires.
    pub pending: Option<Arc<AtomicBool>>,
}

/// Sticky wake used to hand virtio-fs work to the fs worker future.
#[derive(Clone)]
pub struct FsWake {
    wake: Arc<Notify>,
    pending: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
}

impl FsWake {
    /// Create an fs wake with no pending work.
    pub(crate) fn new() -> Self {
        Self {
            wake: Arc::new(Notify::new()),
            pending: Arc::new(AtomicBool::new(false)),
            stopping: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn request(&self) {
        self.pending.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    pub(crate) fn request_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.wake.notify_one();
    }

    fn consume_pending(&self) -> bool {
        self.pending.swap(false, Ordering::AcqRel)
    }

    fn is_stopping(&self) -> bool {
        self.stopping.load(Ordering::Acquire)
    }

    async fn wait(&self) {
        loop {
            if self.pending.load(Ordering::Acquire) || self.is_stopping() {
                return;
            }
            self.wake.notified().await;
        }
    }
}

enum DeviceWake {
    Bits(u64),
    Fault(Box<dyn std::error::Error + Send + Sync>),
    Stopped,
}

/// Single async device loop replacing all per-device tasks.
///
/// Awaits the `DeviceWaker` (which handles ioeventfd polling internally on
/// KVM) plus optional console/net notifications. On wakeup, drains each
/// pending device in a bounded loop, then processes the ring buffer with
/// the agent ring is polled after each device drain.
///
/// Console and net notifications use `Notify::notified()` with `enable()`
/// to prevent losing `notify_one()` calls that fire between select! loops.
///
/// # Snapshot Safety
///
/// The caller must signal `end.stop()` (or `end.report(...)`) then `.await`
/// this future and [`fs_worker_loop`] to completion before capturing VM state.
#[allow(clippy::too_many_arguments)]
pub async fn device_loop<F: amla_fuse::fuse::FsBackend, N: NetBackend, W: AgentRingWake>(
    waker: &dyn DeviceWaker,
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    ring: &RingDevice<'_, W>,
    console: Option<DeviceNotify>,
    net: Option<DeviceNotify>,
    fs_wake: FsWake,
    end: Arc<VmEnd>,
) -> QuiesceResult {
    loop {
        let bits = match wait_for_device_wake(waker, console.as_ref(), net.as_ref(), &end).await {
            DeviceWake::Bits(bits) => bits,
            DeviceWake::Fault(error) => {
                log::error!("device_loop: device waker failed: {error}");
                end.report(crate::shared_state::VmOutcome::Fatal);
                break;
            }
            DeviceWake::Stopped => break,
        };

        log::debug!("device_loop: take_pending bits=0x{bits:x}");
        let _ = drain_pending(devices, queue_wakes, bits, &end, Some(waker), &fs_wake).await;

        // Process agent ring buffer after device drain.
        ring.process();
    }

    // Drain any remaining backend-owned notifications after stop. On KVM, a
    // QueueNotify ioeventfd can be readable even if `poll_wait` lost the
    // select race to the stop signal.
    if let Err(error) = waker.drain_pending_sources() {
        log::error!("device_loop: final device waker drain failed: {error}");
        end.report(crate::shared_state::VmOutcome::Fatal);
    }
    let mut quiesce = QuiesceResult::Quiescent;
    let bits = waker.take_pending();
    if bits != 0 {
        quiesce = drain_pending(devices, queue_wakes, bits, &end, None, &fs_wake).await;
    }
    fs_wake.request_stop();
    // Final ring drain.
    ring.process();
    quiesce
}

/// Dedicated virtio-fs worker future.
///
/// It is intentionally a borrowed future, not a spawned task: this keeps the
/// existing backend and guest-memory lifetimes intact while moving long FUSE
/// awaits out of the main device loop.
pub async fn fs_worker_loop<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    fs_wake: FsWake,
    end: Arc<VmEnd>,
) {
    let mut in_flight = FuturesUnordered::new();
    let mut in_flight_bytes = 0usize;
    let mut next_request_queue = 0usize;
    let mut pending = false;
    let mut final_drain = false;

    loop {
        pending |= fs_wake.consume_pending();
        let stopping = fs_wake.is_stopping() || end.is_stopped();
        if stopping && pending {
            final_drain = true;
        }

        if pending && (!stopping || final_drain) {
            let mut blocked_by_capacity = false;
            let start_in_flight = in_flight.len();
            for (idx, device) in devices.iter().enumerate() {
                let AnyDevice::Fs(fs) = device else {
                    continue;
                };
                let slots = fs_available_slots(in_flight.len(), in_flight_bytes);
                if slots == 0 {
                    blocked_by_capacity = true;
                    break;
                }
                for request in fs.pop_ready_requests(slots, &mut next_request_queue) {
                    in_flight_bytes = in_flight_bytes.saturating_add(request.budget_bytes());
                    in_flight.push(fs.start_request(idx, request));
                }
                // Popping can fault malformed descriptor chains and assert
                // DEVICE_NEEDS_RESET without producing a completion. Resample
                // here as well as after completions so that reset IRQs are not
                // left pending until some unrelated fs work finishes.
                fs.check_resample();
            }
            pending = blocked_by_capacity;
            if stopping && final_drain && !blocked_by_capacity && in_flight.len() == start_in_flight
            {
                final_drain = false;
            }
        }

        if stopping && !final_drain && in_flight.is_empty() {
            break;
        }

        if in_flight.is_empty() {
            fs_wake.wait().await;
            continue;
        }

        tokio::select! {
            Some(mut completion) = in_flight.next() => {
                let request_bytes = completion.request_budget_bytes();
                let Some(device) = devices.get(completion.device_idx) else {
                    in_flight_bytes = in_flight_bytes.saturating_sub(request_bytes);
                    continue;
                };
                let AnyDevice::Fs(fs) = device else {
                    in_flight_bytes = in_flight_bytes.saturating_sub(request_bytes);
                    continue;
                };
                let _had_work = fs.push_fs_completion(&mut completion);
                fs.check_resample();
                in_flight_bytes = in_flight_bytes.saturating_sub(request_bytes);
                if !stopping || final_drain {
                    pending = true;
                }
            }
            () = fs_wake.wait(), if !stopping => {
                pending = true;
            }
            () = end.stopped(), if !stopping => {
                // Stop popping new descriptors; outstanding requests still run
                // to completion so VM state can quiesce before snapshot/return.
            }
        }
    }
}

fn fs_available_slots(in_flight: usize, in_flight_bytes: usize) -> usize {
    let count_slots = FS_MAX_IN_FLIGHT_REQUESTS.saturating_sub(in_flight);
    let byte_slots =
        FS_MAX_IN_FLIGHT_BYTES.saturating_sub(in_flight_bytes) / FS_MAX_REQUEST_BUDGET_BYTES;
    count_slots.min(byte_slots)
}

async fn wait_for_device_wake(
    waker: &dyn DeviceWaker,
    console: Option<&DeviceNotify>,
    net: Option<&DeviceNotify>,
    end: &VmEnd,
) -> DeviceWake {
    loop {
        let woke_console = consume_sticky_notify(waker, console);
        let woke_net = consume_sticky_notify(waker, net);
        let woke_from_sticky = woke_console || woke_net;

        // Create fresh Notified futures each iteration and immediately enable
        // them to register as waiters. This ensures notify_one() calls that
        // fire during drain_pending are not lost.
        if !woke_from_sticky {
            let console_notified = console.map(|dn| dn.wake.notified());
            let net_notified = net.map(|dn| dn.wake.notified());
            tokio::pin!(console_notified);
            tokio::pin!(net_notified);
            // Enable after pinning: registers the future as a waiter so
            // notify_one() calls that fire during drain are captured.
            if let Some(n) = console_notified.as_mut().as_pin_mut() {
                n.enable();
            }
            if let Some(n) = net_notified.as_mut().as_pin_mut() {
                n.enable();
            }

            tokio::select! {
                () = end.stopped() => return DeviceWake::Stopped,
                result = std::future::poll_fn(|cx| waker.poll_wait(cx)) => {
                    if let Err(error) = result {
                        return DeviceWake::Fault(error);
                    }
                },
                Some(()) = async {
                    match console_notified.as_mut().as_pin_mut() {
                        Some(n) => { n.await; Some(()) }
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(dn) = console {
                        log::debug!(
                            "device_loop: console_wake fired, setting bits {:?}",
                            dn.wake_indices
                        );
                        consume_or_set_notify(waker, dn);
                    }
                },
                Some(()) = async {
                    match net_notified.as_mut().as_pin_mut() {
                        Some(n) => { n.await; Some(()) }
                        None => std::future::pending().await,
                    }
                } => {
                    if let Some(dn) = net {
                        consume_or_set_notify(waker, dn);
                    }
                },
            }

            // A non-selected enabled `Notified` future may have consumed a
            // wake while another select arm won. The sticky flag keeps the
            // device bit observable after that future is dropped.
            consume_sticky_notify(waker, console);
            consume_sticky_notify(waker, net);
        }

        let bits = waker.take_pending();
        if bits != 0 {
            return DeviceWake::Bits(bits);
        }
    }
}

fn consume_sticky_notify(waker: &dyn DeviceWaker, notify: Option<&DeviceNotify>) -> bool {
    let Some(dn) = notify else {
        return false;
    };
    let Some(pending) = dn.pending.as_ref() else {
        return false;
    };
    if pending.swap(false, Ordering::AcqRel) {
        set_notify_bits(waker, dn);
        true
    } else {
        false
    }
}

fn consume_or_set_notify(waker: &dyn DeviceWaker, notify: &DeviceNotify) {
    if !consume_sticky_notify(waker, Some(notify)) {
        set_notify_bits(waker, notify);
    }
}

fn set_notify_bits(waker: &dyn DeviceWaker, notify: &DeviceNotify) {
    for wake_idx in notify.wake_indices.iter().copied() {
        waker.set_bit(wake_idx);
    }
}

/// Process pending device bits: poll sync devices and wake the fs worker.
///
/// `rearm_waker` is `Some` for the live drain path: when a sync device still
/// has work after `MAX_DRAIN_ROUNDS`, its bit is re-set so the next
/// `poll_wait` returns `Ready` and the device runs again on the next outer
/// iteration. The shutdown drain passes `None` because no later device-loop
/// iteration will consume the bit.
async fn drain_pending<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    bits: u64,
    end: &VmEnd,
    rearm_waker: Option<&dyn DeviceWaker>,
    fs_wake: &FsWake,
) -> QuiesceResult {
    let quiesce = drain_sync_pending(devices, queue_wakes, bits, end, rearm_waker).await;
    if pending_contains_fs(devices, queue_wakes, bits) {
        check_fs_resample_pending(devices, queue_wakes, bits);
        fs_wake.request();
    }
    quiesce
}

async fn drain_one_pending<P, Fut, C>(
    wake_idx: DeviceWakeIndex,
    kind: DeviceKind,
    queue_idx: usize,
    end: &VmEnd,
    rearm_waker: Option<&dyn DeviceWaker>,
    mut poll: P,
    check_resample: C,
) -> QuiesceResult
where
    P: FnMut() -> Fut,
    Fut: Future<Output = bool>,
    C: FnOnce(),
{
    let mut rounds = 0u32;
    loop {
        if rearm_waker.is_some() && end.is_stopped() && rounds > 0 {
            if let Some(w) = rearm_waker {
                w.set_bit(wake_idx);
            }
            break;
        }
        let had_work = poll().await;
        if !had_work {
            log::debug!("drain_pending[wake={wake_idx} {kind:?}]: no work (rounds={rounds})");
            break;
        }
        rounds += 1;
        if rounds >= MAX_DRAIN_ROUNDS {
            if let Some(w) = rearm_waker {
                // Re-arm: the device still reported work on its last
                // poll. Setting the bit makes the next `poll_wait`
                // return Ready immediately, so the outer loop drives
                // this device again after giving the runtime a turn.
                w.set_bit(wake_idx);
                log::debug!(
                    "drain_pending[wake={wake_idx} {kind:?}]: hit drain limit ({MAX_DRAIN_ROUNDS} rounds), re-armed"
                );
            } else {
                log::debug!(
                    "drain_pending[wake={wake_idx} {kind:?}]: hit drain limit ({MAX_DRAIN_ROUNDS} rounds) during shutdown"
                );
                check_resample();
                return QuiesceResult::SyncDeviceWorkRemaining(PendingSyncDeviceWork {
                    wake_idx,
                    kind,
                    queue_idx,
                    max_rounds: MAX_DRAIN_ROUNDS,
                });
            }
            break;
        }
        tokio::task::yield_now().await;
    }
    if rounds > 0 {
        log::debug!("drain_pending[wake={wake_idx} {kind:?}]: drained rounds={rounds}");
    }
    check_resample();
    QuiesceResult::Quiescent
}

async fn drain_sync_pending<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    bits: u64,
    end: &VmEnd,
    rearm_waker: Option<&dyn DeviceWaker>,
) -> QuiesceResult {
    let mut quiesce = QuiesceResult::Quiescent;
    for wake in pending_wakes(queue_wakes, bits) {
        let Some(device) = devices.get(wake.device) else {
            continue;
        };
        if matches!(device, AnyDevice::Fs(_)) {
            continue;
        }
        let queue_count = queue_wakes.device_queue_count(wake.device);
        let queue_quiesce =
            drain_sync_device_queue(wake.wake, wake.queue, queue_count, device, end, rearm_waker)
                .await;
        quiesce = quiesce.merge(queue_quiesce);
    }
    quiesce
}

async fn drain_sync_device_queue<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    wake_idx: DeviceWakeIndex,
    queue_idx: usize,
    queue_count: usize,
    device: &AnyDevice<'_, F, N>,
    end: &VmEnd,
    rearm_waker: Option<&dyn DeviceWaker>,
) -> QuiesceResult {
    debug_assert!(!matches!(device, AnyDevice::Fs(_)));
    drain_one_pending(
        wake_idx,
        device.kind(),
        queue_idx,
        end,
        rearm_waker,
        || {
            let mut had_work = device.poll_queue_now(queue_idx);
            if had_work {
                for sibling_queue_idx in 0..queue_count {
                    if sibling_queue_idx != queue_idx {
                        had_work |= device.poll_queue_now(sibling_queue_idx);
                    }
                }
            }
            std::future::ready(had_work)
        },
        || device.check_resample(),
    )
    .await
}

fn pending_contains_fs<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    bits: u64,
) -> bool {
    pending_wakes(queue_wakes, bits).any(|wake| {
        devices
            .get(wake.device)
            .is_some_and(|device| matches!(device, AnyDevice::Fs(_)))
    })
}

fn check_fs_resample_pending<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    bits: u64,
) {
    let mut checked_devices = 0u64;
    for wake in pending_wakes(queue_wakes, bits) {
        let Some(AnyDevice::Fs(fs)) = devices.get(wake.device) else {
            continue;
        };
        let Some(mask) = 1u64.checked_shl(wake.device as u32) else {
            fs.check_resample();
            continue;
        };
        if checked_devices & mask == 0 {
            fs.check_resample();
            checked_devices |= mask;
        }
    }
}

fn pending_wakes(
    queue_wakes: &QueueWakeMap,
    mut bits: u64,
) -> impl Iterator<Item = crate::devices::DeviceQueueWake> + '_ {
    std::iter::from_fn(move || {
        while bits != 0 {
            let wake_idx = bits.trailing_zeros() as usize;
            bits &= bits - 1;
            if let Ok(wake_idx) = DeviceWakeIndex::new(wake_idx)
                && let Some(wake) = queue_wakes.get(wake_idx)
            {
                return Some(wake);
            }
        }
        None
    })
}

#[cfg(test)]
mod tests {
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };

    use amla_core::vm_state::{
        DEVICE_KIND_FS, DeviceSlot, make_test_vmstate, test_mmap_with_device_kinds,
    };
    use amla_core::{BasicDeviceWaker, IrqLine};
    use amla_fuse::fuse::MAX_FUSE_REQUEST_SIZE;
    use amla_fuse::null::NullFsBackend;
    use amla_virtio::FsState;

    use super::*;
    use crate::device::{AnyDevice, FsDevice};
    use crate::devices::{DeviceKind, QueueWakeMap};

    fn fs_slot() -> DeviceSlot<FsState> {
        // SAFETY: this test constructs a single Fs device backed by VM-state slot 0.
        unsafe { DeviceSlot::new_unchecked(0) }
    }

    fn wake(index: usize) -> DeviceWakeIndex {
        DeviceWakeIndex::new(index).unwrap()
    }

    #[derive(Default)]
    struct CountingIrqLine {
        resamples: AtomicU32,
    }

    impl IrqLine for CountingIrqLine {
        fn assert(&self) {}

        fn deassert(&self) {}

        fn check_resample(&self) {
            self.resamples.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn drain_one_rearms_live_device_after_cap() {
        let polls = Arc::new(AtomicU32::new(0));
        let resamples = Arc::new(AtomicU32::new(0));
        let end = VmEnd::new();
        let waker = BasicDeviceWaker::new();

        let poll_count = Arc::clone(&polls);
        let resample_count = Arc::clone(&resamples);
        let quiesce = drain_one_pending(
            wake(3),
            DeviceKind::Rng,
            0,
            &end,
            Some(&waker),
            move || {
                let poll_count = Arc::clone(&poll_count);
                async move {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                    true
                }
            },
            move || {
                resample_count.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert_eq!(quiesce, QuiesceResult::Quiescent);
        assert_eq!(polls.load(Ordering::SeqCst), MAX_DRAIN_ROUNDS);
        assert_eq!(waker.take_pending(), 1 << 3);
        assert_eq!(resamples.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn drain_one_reports_shutdown_drain_exhaustion_after_cap() {
        let polls = Arc::new(AtomicU32::new(0));
        let resamples = Arc::new(AtomicU32::new(0));
        let end = VmEnd::new();
        let waker = BasicDeviceWaker::new();

        let poll_count = Arc::clone(&polls);
        let resample_count = Arc::clone(&resamples);
        let quiesce = drain_one_pending(
            wake(3),
            DeviceKind::Rng,
            0,
            &end,
            None,
            move || {
                let poll_count = Arc::clone(&poll_count);
                async move {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                    true
                }
            },
            move || {
                resample_count.fetch_add(1, Ordering::SeqCst);
            },
        )
        .await;

        assert_eq!(polls.load(Ordering::SeqCst), MAX_DRAIN_ROUNDS);
        assert_eq!(waker.take_pending(), 0);
        assert_eq!(resamples.load(Ordering::SeqCst), 1);
        assert_eq!(
            quiesce,
            QuiesceResult::SyncDeviceWorkRemaining(PendingSyncDeviceWork {
                wake_idx: wake(3),
                kind: DeviceKind::Rng,
                queue_idx: 0,
                max_rounds: MAX_DRAIN_ROUNDS,
            })
        );
        assert!(matches!(
            quiesce.into_result(),
            Err(Error::Device(DeviceError::ShutdownDrainExhausted {
                device: DeviceKind::Rng,
                wake_idx: 3,
                queue_idx: 0,
                max_rounds: MAX_DRAIN_ROUNDS,
            }))
        ));
    }

    #[tokio::test]
    async fn final_drain_uses_full_budget_even_after_stop() {
        let polls = Arc::new(AtomicU32::new(0));
        let end = VmEnd::new();
        end.stop();

        let poll_count = Arc::clone(&polls);
        let quiesce = drain_one_pending(
            wake(3),
            DeviceKind::Rng,
            0,
            &end,
            None,
            move || {
                let poll_count = Arc::clone(&poll_count);
                async move {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                    true
                }
            },
            || {},
        )
        .await;

        assert_eq!(polls.load(Ordering::SeqCst), MAX_DRAIN_ROUNDS);
        assert!(matches!(quiesce, QuiesceResult::SyncDeviceWorkRemaining(_)));
    }

    #[tokio::test]
    async fn live_drain_rearms_when_stop_arrives_after_work() {
        let polls = Arc::new(AtomicU32::new(0));
        let end = Arc::new(VmEnd::new());
        let waker = BasicDeviceWaker::new();

        let poll_count = Arc::clone(&polls);
        let poll_end = Arc::clone(&end);
        let quiesce = drain_one_pending(
            wake(3),
            DeviceKind::Rng,
            0,
            end.as_ref(),
            Some(&waker),
            move || {
                let poll_count = Arc::clone(&poll_count);
                let poll_end = Arc::clone(&poll_end);
                async move {
                    poll_count.fetch_add(1, Ordering::SeqCst);
                    poll_end.stop();
                    true
                }
            },
            || {},
        )
        .await;

        assert_eq!(quiesce, QuiesceResult::Quiescent);
        assert_eq!(polls.load(Ordering::SeqCst), 1);
        assert_eq!(waker.take_pending(), 1 << 3);
    }

    #[tokio::test]
    async fn drain_pending_checks_fs_resample_without_completion() {
        let mmap = test_mmap_with_device_kinds(
            amla_core::vm_state::BITMAP_BLOCK_SIZE as usize,
            &[DEVICE_KIND_FS],
        );
        let vm = make_test_vmstate(&mmap, 0);
        let irq = CountingIrqLine::default();
        let backend = NullFsBackend;
        let fs = FsDevice::new(
            fs_slot(),
            &vm,
            &irq,
            &backend,
            amla_virtio_fs::RequestQueueCount::ONE,
        );
        let devices: Vec<AnyDevice<'_, _, amla_core::backends::NullNetBackend>> =
            vec![AnyDevice::Fs(fs)];
        let queue_wakes = QueueWakeMap::from_queue_counts_for_test(&[1]).unwrap();
        let end = VmEnd::new();
        let fs_wake = FsWake::new();

        let quiesce = drain_pending(&devices, &queue_wakes, 1, &end, None, &fs_wake).await;

        assert_eq!(quiesce, QuiesceResult::Quiescent);
        assert_eq!(irq.resamples.load(Ordering::SeqCst), 1);
        assert!(fs_wake.consume_pending());
    }

    #[test]
    fn fs_available_slots_uses_full_request_budget() {
        let slots = fs_available_slots(0, 0);

        assert!(slots > 0);
        assert!(slots < FS_MAX_IN_FLIGHT_BYTES / MAX_FUSE_REQUEST_SIZE);
        assert!(slots * FS_MAX_REQUEST_BUDGET_BYTES <= FS_MAX_IN_FLIGHT_BYTES);
    }

    #[test]
    fn fs_available_slots_respects_remaining_byte_budget() {
        let one_slot_remaining = FS_MAX_IN_FLIGHT_BYTES - FS_MAX_REQUEST_BUDGET_BYTES;
        assert_eq!(fs_available_slots(0, one_slot_remaining), 1);
        assert_eq!(fs_available_slots(0, one_slot_remaining + 1), 0);
    }
}
