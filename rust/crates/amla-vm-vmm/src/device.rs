// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Enum-dispatched virtio device system.
//!
//! Each device kind is its own struct with a typed slot token into `VmState`.
//! `AnyDevice` wraps all concrete types in an enum with a tiny dispatch macro
//! for compile-time delegation. No boxed device trait objects are used.
//!
//! # Safety
//!
//! Each concrete device holds a `DeviceSlot<T>` and a `&VmState` reference.
//! Device state is accessed via `VmState::device_slot_mut(slot)`, which
//! returns a `RefGuard<T>`. In debug mode, the guard tracks the
//! borrowed byte span and panics on overlap. In release mode, it is
//! zero-cost (`#[repr(transparent)]` over `&mut T`).

use parking_lot::Mutex;

use amla_core::IrqLine;
use amla_core::backends::{ConsoleBackend, NetBackend};
use amla_core::vm_state::{DeviceSlot, VmState};
use amla_fuse::fuse::FsBackend;
use amla_virtio::{
    ConsoleState, MmioTransportState, NetState, PmemState, QueueRunner, QueueState, RngState,
    VirtioDevice, VirtioState,
};
use amla_virtio_console::{AgentPortBackend, Console};
use amla_virtio_net::Net;
use amla_virtio_pmem::Pmem;
use amla_virtio_rng::Rng;

use crate::agent::{AgentRingState, AgentRingWake};
use crate::devices::DeviceKind;

mod fs;
pub use fs::{FS_MAX_REQUEST_BUDGET_BYTES, FsDevice};

/// Wraps all concrete device types for storage in a single array.
pub enum AnyDevice<'irq, F: FsBackend, N: NetBackend> {
    Console(ConsoleDevice<'irq>),
    Net(NetDevice<'irq, N>),
    Rng(RngDevice<'irq>),
    Fs(FsDevice<'irq, F>),
    Pmem(PmemDevice<'irq>),
}

/// Dispatch a method call to all `AnyDevice` variants.
///
/// Generates a match with one arm per variant, each delegating to the inner type.
/// Keeps stack traces readable (each arm is a real match) while eliminating
/// the boilerplate of writing out all six variants for every method.
macro_rules! delegate {
    ($self:expr, $method:ident( $($arg:expr),* $(,)? )) => {
        match $self {
            Self::Console(d) => d.$method($($arg),*),
            Self::Net(d) => d.$method($($arg),*),
            Self::Rng(d) => d.$method($($arg),*),
            Self::Fs(d) => d.$method($($arg),*),
            Self::Pmem(d) => d.$method($($arg),*),
        }
    };
}

impl<F: FsBackend, N: NetBackend> AnyDevice<'_, F, N> {
    /// Synchronous best-effort poll for one virtqueue.
    pub(crate) fn poll_queue_now(&self, queue_idx: usize) -> bool {
        delegate!(self, poll_queue_now(queue_idx))
    }

    /// Device kind for logging.
    pub(crate) const fn kind(&self) -> DeviceKind {
        delegate!(self, kind())
    }

    /// Handle an MMIO read.
    pub(crate) fn handle_read(&self, offset: u64, size: u8) -> u64 {
        delegate!(self, handle_read(offset, size))
    }

    /// Handle an MMIO write.
    pub(crate) fn handle_write(&self, offset: u64, size: u8, value: u64) {
        delegate!(self, handle_write(offset, size, value));
    }

    /// Check IRQ resample state.
    pub(crate) fn check_resample(&self) {
        delegate!(self, check_resample());
    }
}

/// Agent ring buffer processor.
///
/// Not a virtio device — no MMIO, no waker bit, no IRQ. Called directly
/// by the device loop via [`process()`](Self::process) after draining
/// MMIO devices. The `Mutex` provides `Sync` (required for `&RingDevice`
/// across the thread scope boundary), not contention protection.
pub struct RingDevice<'ring, W: AgentRingWake> {
    inner: Mutex<AgentRingState<'ring, W>>,
}

impl<'ring, W: AgentRingWake> RingDevice<'ring, W> {
    pub(crate) const fn new(ring: AgentRingState<'ring, W>) -> Self {
        Self {
            inner: Mutex::new(ring),
        }
    }

    /// Process the ring buffer.
    pub(crate) fn process(&self) -> bool {
        self.inner.lock().process()
    }

    /// Notify the guest to re-check durable ring state.
    pub(crate) fn kick_peer(&self) {
        self.inner.lock().kick_peer();
    }

    /// Ensure the ring has no transient host-side state outside mmap.
    pub(crate) fn assert_snapshot_quiescent(&self) -> crate::Result<()> {
        let detail = self.inner.lock().snapshot_quiescence_error();
        if let Some(detail) = detail {
            return Err(crate::Error::Device(
                crate::DeviceError::SnapshotNotQuiescent {
                    component: "agent ring",
                    detail,
                },
            ));
        }
        Ok(())
    }
}

/// Decode a virtio-mmio register offset to a short name for logs.
///
/// Offsets are hardcoded here (spec-defined) because the crate-private
/// constants in `amla-vm-virtio-mmio` aren't re-exported.
const fn mmio_reg_name(offset: u64) -> Option<&'static str> {
    Some(match offset {
        0x000 => "MagicValue",
        0x004 => "Version",
        0x008 => "DeviceID",
        0x00C => "VendorID",
        0x010 => "DeviceFeatures",
        0x014 => "DeviceFeaturesSel",
        0x020 => "DriverFeatures",
        0x024 => "DriverFeaturesSel",
        0x030 => "QueueSel",
        0x034 => "QueueNumMax",
        0x038 => "QueueNum",
        0x044 => "QueueReady",
        0x050 => "QueueNotify",
        0x060 => "InterruptStatus",
        0x064 => "InterruptAck",
        0x070 => "Status",
        0x080 => "QueueDescLow",
        0x084 => "QueueDescHigh",
        0x090 => "QueueAvailLow",
        0x094 => "QueueAvailHigh",
        0x0A0 => "QueueUsedLow",
        0x0A4 => "QueueUsedHigh",
        0x0AC => "ShmSel",
        0x0FC => "ConfigGen",
        _ => return None,
    })
}

fn log_mmio_read(path: &'static str, slot_idx: usize, offset: u64, size: u8, value: u64) {
    if let Some(name) = mmio_reg_name(offset) {
        log::debug!(
            "mmio_read [slot={slot_idx} {name} off=0x{offset:03x} sz={size}] ({path}) = 0x{value:x}"
        );
    } else {
        log::trace!(
            "mmio_read [slot={slot_idx} off=0x{offset:03x} sz={size}] ({path}) = 0x{value:x}"
        );
    }
}

fn log_mmio_write(slot_idx: usize, offset: u64, size: u8, value: u64) {
    if let Some(name) = mmio_reg_name(offset) {
        log::debug!(
            "mmio_write[slot={slot_idx} {name} off=0x{offset:03x} sz={size}] = 0x{value:x}"
        );
    } else {
        log::trace!("mmio_write[slot={slot_idx} off=0x{offset:03x} sz={size}] = 0x{value:x}");
    }
}

/// Process all ready queues for a device. Returns `true` if any work was done.
#[cfg(test)]
fn poll_queues<'a, D: VirtioDevice<VmState<'a>>>(
    device: &mut D,
    transport: &mut MmioTransportState,
    queues: &mut [QueueState],
    vm: &'a VmState<'a>,
    irq: &dyn IrqLine,
) -> bool {
    let mut runner = QueueRunner::new(transport, vm, irq);
    runner.run_device_queues(queues, device).had_work()
}

/// Process one ready queue for a device. Returns `true` if work was done.
fn poll_queue<'a, D: VirtioDevice<VmState<'a>>>(
    device: &mut D,
    queue_idx: usize,
    transport: &mut MmioTransportState,
    queues: &mut [QueueState],
    vm: &'a VmState<'a>,
    irq: &dyn IrqLine,
) -> bool {
    if queue_idx >= device.queue_count() || queue_idx >= queues.len() {
        return false;
    }
    let mut runner = QueueRunner::new(transport, vm, irq);
    runner
        .run_device_queue(queue_idx, &mut queues[queue_idx], device)
        .had_work()
}

/// Poll one virtio queue via `VirtioState::split_mut()`.
fn poll_virtio_queue<'a, D: VirtioDevice<VmState<'a>>, S: VirtioState>(
    device: &mut D,
    queue_idx: usize,
    state: &mut S,
    vm: &'a VmState<'a>,
    irq: &dyn IrqLine,
) -> bool {
    let (transport, queues, _) = state.split_mut();
    poll_queue(device, queue_idx, transport, queues, vm, irq)
}

/// Fast-path MMIO read for transport registers.
/// Returns `Some(value)` if handled, `None` if the caller must do full dispatch.
fn transport_read_fast_path(
    transport: &MmioTransportState,
    offset: u64,
    size: u8,
    device_id: u32,
) -> Option<u64> {
    use amla_virtio_mmio::{
        CONFIG_GENERATION, DEVICE_ID, INTERRUPT_STATUS, MAGIC_VALUE, STATUS, VENDOR_ID_REG,
        VERSION, VIRTIO_MMIO_MAGIC, VIRTIO_MMIO_VERSION,
    };
    if size != 4 {
        return match offset {
            MAGIC_VALUE | VERSION | DEVICE_ID | VENDOR_ID_REG | INTERRUPT_STATUS | STATUS
            | CONFIG_GENERATION => Some(0),
            _ => None,
        };
    }

    match offset {
        MAGIC_VALUE => Some(u64::from(VIRTIO_MMIO_MAGIC)),
        VERSION => Some(u64::from(VIRTIO_MMIO_VERSION)),
        DEVICE_ID => Some(u64::from(device_id)),
        VENDOR_ID_REG => Some(u64::from(amla_virtio::VENDOR_ID)),
        INTERRUPT_STATUS => Some(u64::from(transport.interrupt_status)),
        STATUS => Some(u64::from(transport.status)),
        CONFIG_GENERATION => Some(u64::from(transport.config_generation)),
        _ => None,
    }
}

/// Shared `check_resample` logic.
///
/// Delegates to `IrqLine::check_resample()` which drains the KVM resample
/// eventfd and re-asserts if the level is still high. We intentionally do
/// NOT unconditionally re-assert based on `interrupt_status` here — that
/// would override the `EVENT_IDX` notification suppression decision made by
/// `poll_queues` / `needs_notification()`.
fn check_resample_virtio(irq: &dyn IrqLine) {
    irq.check_resample();
}

/// Build an `MmioTransport` via `VirtioState::split_mut()` and call the closure.
fn with_transport<'a, D: VirtioDevice<VmState<'a>>, S: VirtioState, R>(
    device: &mut D,
    state: &mut S,
    vm: &'a VmState<'a>,
    irq: &dyn IrqLine,
    f: impl FnOnce(&mut amla_virtio_mmio::MmioTransport<'_, D, VmState<'a>>) -> R,
) -> R {
    let (transport, queues, config) = state.split_mut();
    let mut t = amla_virtio_mmio::MmioTransport::new(transport, queues, config, device, vm, irq);
    f(&mut t)
}

/// Generate a concrete device struct with the standard Mutex<Inner> + IRQ pattern.
macro_rules! define_device {
    (
        $(#[$meta:meta])*
        $Name:ident / $Inner:ident {
            state: $State:ty,
            $( $field:ident : $ty:ty ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        pub struct $Name<'irq> {
            inner: Mutex<$Inner<'irq>>,
            irq: &'irq dyn IrqLine,
        }

        struct $Inner<'irq> {
            slot: DeviceSlot<$State>,
            vm: &'irq VmState<'irq>,
            $( $field: $ty, )*
        }

        // SAFETY: DeviceSlot + &VmState are Send. VmState is Send+Sync.
        // All access serialized via the outer Mutex.
        // Reason: clippy can't see the safety invariant of the outer
        // Mutex serialization; the per-field Send check is conservative.
        #[allow(clippy::non_send_fields_in_send_ty)]
        unsafe impl Send for $Inner<'_> {}

        impl<'irq> $Name<'irq> {
            #[allow(clippy::too_many_arguments)]
            pub(crate) fn new(
                slot: DeviceSlot<$State>,
                vm: &'irq VmState<'irq>,
                irq: &'irq dyn IrqLine,
                $( $field: $ty, )*
            ) -> Self {
                Self {
                    inner: Mutex::new($Inner {
                        slot,
                        vm,
                        $( $field, )*
                    }),
                    irq,
                }
            }

        }
    };
}

/// Generate inherent device methods for a standard virtio device.
///
/// Most virtio devices follow the same lock→state→poll/transport→resample
/// pattern. This macro eliminates the boilerplate, leaving only the
/// device-specific constructor expression (`make_dev`).
///
/// `make_dev($inner, $state)` receives `&mut Inner` plus the mmap-backed
/// device state and returns a `VirtioDevice`.
macro_rules! impl_virtio_device {
    (
        $Device:ident,
        state_type: $State:ty,
        device_id: $device_id:expr,
        kind: $kind:expr,
        make_dev($inner:ident, $state:ident) $make_dev:block
    ) => {
        impl $Device<'_> {
            // Reason: lock guard intentionally spans the body so the operation
            // observes a single consistent state snapshot.
            #[allow(clippy::significant_drop_tightening)]
            fn poll_queue_now(&self, queue_idx: usize) -> bool {
                let mut guard = self.inner.lock();
                let $inner = &mut *guard;
                let mut state = $inner.vm.device_slot_mut($inner.slot);
                let $state = &mut *state;
                let mut dev = $make_dev;
                poll_virtio_queue(&mut dev, queue_idx, $state, $inner.vm, self.irq)
            }
            const fn kind(&self) -> DeviceKind {
                $kind
            }
            // Reason: lock guard intentionally spans the body so the operation
            // observes a single consistent state snapshot.
            #[allow(clippy::significant_drop_tightening)]
            fn handle_read(&self, offset: u64, size: u8) -> u64 {
                let mut guard = self.inner.lock();
                let $inner = &mut *guard;
                let slot_idx = $inner.slot.index();
                let mut state = $inner.vm.device_slot_mut($inner.slot);
                let $state = &mut *state;
                if let Some(v) =
                    transport_read_fast_path(&$state.transport, offset, size, $device_id)
                {
                    log_mmio_read("fast", slot_idx, offset, size, v);
                    return v;
                }
                let mut dev = $make_dev;
                let v = with_transport(&mut dev, $state, $inner.vm, self.irq, |t| {
                    t.read(offset, size)
                });
                log_mmio_read("slow", slot_idx, offset, size, v);
                v
            }
            // Reason: lock guard intentionally spans the body so the operation
            // observes a single consistent state snapshot.
            #[allow(clippy::significant_drop_tightening)]
            fn handle_write(&self, offset: u64, size: u8, value: u64) {
                let mut guard = self.inner.lock();
                let $inner = &mut *guard;
                let slot_idx = $inner.slot.index();
                log_mmio_write(slot_idx, offset, size, value);
                let mut state = $inner.vm.device_slot_mut($inner.slot);
                let $state = &mut *state;
                let mut dev = $make_dev;
                with_transport(&mut dev, $state, $inner.vm, self.irq, |t| {
                    t.write(offset, size, value);
                });
            }
            fn check_resample(&self) {
                check_resample_virtio(self.irq);
            }
        }
    };
}

define_device! {
    /// Console device (multiport: serial + agent channel).
    ConsoleDevice / ConsoleInner {
        state: ConsoleState,
        console: &'irq dyn ConsoleBackend,
        agent_port: Box<dyn AgentPortBackend>,
    }
}

impl ConsoleDevice<'_> {
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn poll_queue_now(&self, queue_idx: usize) -> bool {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        let mut dev = Console::new(inner.console, inner.agent_port.as_mut(), &mut state.control);
        poll_queue(
            &mut dev,
            queue_idx,
            &mut state.transport,
            &mut state.queues,
            inner.vm,
            self.irq,
        )
    }

    #[allow(clippy::unused_self)]
    const fn kind(&self) -> DeviceKind {
        DeviceKind::Console
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_read(&self, offset: u64, size: u8) -> u64 {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let slot_idx = inner.slot.index();
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        if let Some(v) = transport_read_fast_path(
            &state.transport,
            offset,
            size,
            amla_virtio::DEVICE_ID_CONSOLE,
        ) {
            log_mmio_read("fast", slot_idx, offset, size, v);
            return v;
        }
        let mut dev = Console::new(inner.console, inner.agent_port.as_mut(), &mut state.control);
        let config = amla_core::bytemuck::bytes_of_mut(&mut state.config);
        let t = amla_virtio_mmio::MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            config,
            &mut dev,
            inner.vm,
            self.irq,
        );
        let v = t.read(offset, size);
        log_mmio_read("slow", slot_idx, offset, size, v);
        v
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_write(&self, offset: u64, size: u8, value: u64) {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let slot_idx = inner.slot.index();
        log_mmio_write(slot_idx, offset, size, value);
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        let mut dev = Console::new(inner.console, inner.agent_port.as_mut(), &mut state.control);
        let config = amla_core::bytemuck::bytes_of_mut(&mut state.config);
        let mut t = amla_virtio_mmio::MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            config,
            &mut dev,
            inner.vm,
            self.irq,
        );
        t.write(offset, size, value);
    }

    fn check_resample(&self) {
        check_resample_virtio(self.irq);
    }
}

// ── Net ──────────────────────────────────────────────────────────────

/// Network device with configurable multi-queue.
pub struct NetDevice<'irq, N: NetBackend> {
    inner: Mutex<NetInner<'irq, N>>,
    irq: &'irq dyn IrqLine,
}

struct NetInner<'irq, N: NetBackend> {
    slot: DeviceSlot<NetState>,
    vm: &'irq VmState<'irq>,
    backend: &'irq N,
    queue_pairs: u16,
}

// SAFETY: DeviceSlot + &VmState + &N are Send when N: NetBackend. VmState is
// Send+Sync. All mutable access is serialized via the outer Mutex.
unsafe impl<N: NetBackend> Send for NetInner<'_, N> {}

impl<'irq, N: NetBackend> NetDevice<'irq, N> {
    pub(crate) fn new(
        slot: DeviceSlot<NetState>,
        vm: &'irq VmState<'irq>,
        irq: &'irq dyn IrqLine,
        backend: &'irq N,
        queue_pairs: u16,
    ) -> Self {
        Self {
            inner: Mutex::new(NetInner {
                slot,
                vm,
                backend,
                queue_pairs,
            }),
            irq,
        }
    }
}

impl<N: NetBackend> NetDevice<'_, N> {
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn poll_queue_now(&self, queue_idx: usize) -> bool {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        let mut dev = Net::new(inner.backend, inner.queue_pairs, &mut state.control);
        poll_queue(
            &mut dev,
            queue_idx,
            &mut state.transport,
            &mut state.queues,
            inner.vm,
            self.irq,
        )
    }

    #[allow(clippy::unused_self)]
    const fn kind(&self) -> DeviceKind {
        DeviceKind::Net
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_read(&self, offset: u64, size: u8) -> u64 {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let slot_idx = inner.slot.index();
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        if let Some(v) =
            transport_read_fast_path(&state.transport, offset, size, amla_virtio::DEVICE_ID_NET)
        {
            log_mmio_read("fast", slot_idx, offset, size, v);
            return v;
        }
        let mut dev = Net::new(inner.backend, inner.queue_pairs, &mut state.control);
        let config = amla_core::bytemuck::bytes_of_mut(&mut state.config);
        let t = amla_virtio_mmio::MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            config,
            &mut dev,
            inner.vm,
            self.irq,
        );
        let v = t.read(offset, size);
        log_mmio_read("slow", slot_idx, offset, size, v);
        v
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn handle_write(&self, offset: u64, size: u8, value: u64) {
        let mut guard = self.inner.lock();
        let inner = &mut *guard;
        let slot_idx = inner.slot.index();
        log_mmio_write(slot_idx, offset, size, value);
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *state;
        let mut dev = Net::new(inner.backend, inner.queue_pairs, &mut state.control);
        let config = amla_core::bytemuck::bytes_of_mut(&mut state.config);
        let mut t = amla_virtio_mmio::MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            config,
            &mut dev,
            inner.vm,
            self.irq,
        );
        t.write(offset, size, value);
    }

    fn check_resample(&self) {
        check_resample_virtio(self.irq);
    }
}

// ── Rng ──────────────────────────────────────────────────────────────

define_device! {
    /// Entropy source device.
    RngDevice / RngInner {
        state: RngState,
    }
}

impl_virtio_device!(
    RngDevice,
    state_type: RngState,
    device_id: amla_virtio::DEVICE_ID_RNG,
    kind: DeviceKind::Rng,
    make_dev(_inner, _state) { Rng::default() }
);

// ── Pmem ─────────────────────────────────────────────────────────────

define_device! {
    /// Persistent memory device.
    PmemDevice / PmemInner {
        state: PmemState,
    }
}

impl_virtio_device!(
    PmemDevice,
    state_type: PmemState,
    device_id: amla_virtio::DEVICE_ID_PMEM,
    kind: DeviceKind::Pmem,
    make_dev(_inner, _state) { Pmem }
);

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

    use super::*;
    use crate::shared_state::VmEnd;

    fn fs_slot() -> DeviceSlot<FsState> {
        // SAFETY: these tests create a single-device VM state whose slot 0 is
        // deliberately initialized and exercised as FsState.
        unsafe { DeviceSlot::new_unchecked(0) }
    }

    fn fs_device<'a, F: FsBackend>(
        vm: &'a VmState<'a>,
        irq: &'a dyn IrqLine,
        backend: &'a F,
    ) -> FsDevice<'a, F> {
        FsDevice::new(
            fs_slot(),
            vm,
            irq,
            backend,
            amla_virtio_fs::RequestQueueCount::ONE,
        )
    }

    use amla_core::NullIrqLine;
    use amla_core::bytemuck::Zeroable;
    use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};
    use amla_core::vm_state::{
        DEVICE_KIND_FS, VmState, make_test_vmstate, test_mmap_with_device_kinds,
    };
    use amla_fuse::fuse::{
        FUSE_GETATTR, FuseAttr, FuseAttrOut, FuseEntryOut, FuseGetattrIn, FuseInHeader,
        FuseInitOut, FuseOpenOut, FuseStatfsOut,
    };
    use amla_fuse::fuse_abi::FuseError;
    use amla_virtio::{
        Descriptor, FsState, INT_CONFIG, INT_VRING, QueueView, STATUS_ACKNOWLEDGE,
        STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FAILED,
        STATUS_FEATURES_OK, VIRTIO_F_VERSION_1, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    };
    use amla_virtio_fs::{FIRST_REQUEST_QUEUE, HIPRIO_QUEUE};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Notify;

    const READY_STATUS: u32 =
        STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
    const FUSE_GETATTR_REQUEST_LEN: usize =
        std::mem::size_of::<FuseInHeader>() + std::mem::size_of::<FuseGetattrIn>();
    const FUSE_GETATTR_REQUEST_LEN_U32: u32 = FUSE_GETATTR_REQUEST_LEN as u32;

    fn test_mmap_with_fs_slot(ram_size: usize) -> amla_mem::MmapSlice {
        test_mmap_with_device_kinds(ram_size, &[DEVICE_KIND_FS])
    }

    struct CountingDevice {
        queue_count: usize,
        processed: Vec<usize>,
    }

    impl CountingDevice {
        fn new(queue_count: usize) -> Self {
            Self {
                queue_count,
                processed: Vec::new(),
            }
        }
    }

    impl VirtioDevice<VmState<'_>> for CountingDevice {
        fn device_id(&self) -> u32 {
            amla_virtio::DEVICE_ID_CONSOLE
        }

        fn queue_count(&self) -> usize {
            self.queue_count
        }

        fn device_features(&self) -> u64 {
            0
        }

        fn process_queue(
            &mut self,
            queue_idx: usize,
            _queue: &mut QueueView<'_, '_, '_, VmState<'_>>,
        ) -> Result<(), amla_virtio::QueueViolation> {
            self.processed.push(queue_idx);
            Ok(())
        }
    }

    fn ready_queue() -> QueueState {
        QueueState {
            size: 16,
            ready: 1,
            pad0: 0,
            desc_addr: 0,
            avail_addr: 0,
            used_addr: 0,
            last_avail_idx: 0,
            last_used_idx: 0,
            generation: 0,
        }
    }

    fn transport(status: u32) -> MmioTransportState {
        MmioTransportState {
            status,
            pad0: 0,
            driver_features: 0,
            interrupt_status: 0,
            config_generation: 0,
            queue_sel: 0,
            features_sel: 0,
            driver_features_sel: 0,
            shm_sel: 0,
        }
    }

    struct BlockingGetattrBackend {
        entered: Notify,
        release: Notify,
        wait_for_release: bool,
        block_nodeid: Option<u64>,
    }

    impl BlockingGetattrBackend {
        fn new() -> Self {
            Self {
                entered: Notify::new(),
                release: Notify::new(),
                wait_for_release: true,
                block_nodeid: None,
            }
        }

        fn ready() -> Self {
            Self {
                entered: Notify::new(),
                release: Notify::new(),
                wait_for_release: false,
                block_nodeid: None,
            }
        }

        fn blocking_nodeid(nodeid: u64) -> Self {
            Self {
                entered: Notify::new(),
                release: Notify::new(),
                wait_for_release: true,
                block_nodeid: Some(nodeid),
            }
        }
    }

    impl FsBackend for BlockingGetattrBackend {
        async fn init(&self) -> Result<FuseInitOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn lookup(&self, _parent: u64, _name: &[u8]) -> Result<FuseEntryOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn forget(&self, _nodeid: u64, _nlookup: u64) {}

        async fn batch_forget(&self, _forgets: &[(u64, u64)]) {}

        async fn getattr(&self, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
            let should_block = self.wait_for_release
                && self
                    .block_nodeid
                    .is_none_or(|block_nodeid| block_nodeid == nodeid);
            if should_block {
                self.entered.notify_one();
                self.release.notified().await;
            }
            Ok(FuseAttrOut::new(FuseAttr {
                ino: nodeid,
                size: 1,
                blocks: 1,
                mode: 0o100_644,
                nlink: 1,
                blksize: 4096,
                ..FuseAttr::default()
            }))
        }

        async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn open(&self, _nodeid: u64, _flags: u32) -> Result<FuseOpenOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn read(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn release(&self, _nodeid: u64, _fh: u64) {}

        async fn opendir(&self, _nodeid: u64) -> Result<FuseOpenOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readdir(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn readdirplus(
            &self,
            _nodeid: u64,
            _fh: u64,
            _offset: u64,
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn releasedir(&self, _nodeid: u64, _fh: u64) {}

        async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn access(&self, _nodeid: u64, _mask: u32) -> Result<(), FuseError> {
            Err(FuseError::no_sys())
        }

        async fn getxattr(
            &self,
            _nodeid: u64,
            _name: &[u8],
            _size: u32,
        ) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn listxattr(&self, _nodeid: u64, _size: u32) -> Result<Vec<u8>, FuseError> {
            Err(FuseError::no_sys())
        }

        async fn get_parent(&self, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
            Err(FuseError::no_sys())
        }
    }

    fn fill_guest(vm: &VmState<'_>, gpa: u64, bytes: &[u8]) {
        let gw = vm
            .gpa_write(gpa, bytes.len())
            .expect("test GPA write must map");
        gw.write_from(bytes);
    }

    fn read_guest(vm: &VmState<'_>, gpa: u64, len: usize) -> Vec<u8> {
        let mut out = vec![0; len];
        let gr = vm.gpa_read(gpa, len).expect("test GPA read must map");
        gr.read_to(&mut out);
        out
    }

    #[test]
    fn poll_queues_requires_driver_ok_clear_reset_and_not_failed() {
        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut queues = [ready_queue()];
        let mut device = CountingDevice::new(1);

        let mut state = transport(0);
        assert!(!poll_queues(
            &mut device,
            &mut state,
            &mut queues,
            &vm,
            &irq
        ));
        assert!(device.processed.is_empty());

        state.status = READY_STATUS | STATUS_DEVICE_NEEDS_RESET;
        assert!(!poll_queues(
            &mut device,
            &mut state,
            &mut queues,
            &vm,
            &irq
        ));
        assert!(device.processed.is_empty());

        state.status = READY_STATUS | STATUS_FAILED;
        assert!(!poll_queues(
            &mut device,
            &mut state,
            &mut queues,
            &vm,
            &irq
        ));
        assert!(device.processed.is_empty());

        state.status = READY_STATUS;
        assert!(!poll_queues(
            &mut device,
            &mut state,
            &mut queues,
            &vm,
            &irq
        ));
        assert_eq!(device.processed, vec![0]);
    }

    #[test]
    fn poll_queues_respects_device_active_queue_count() {
        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut queues = [ready_queue(), ready_queue()];
        let mut device = CountingDevice::new(1);
        let mut state = transport(READY_STATUS);

        assert!(!poll_queues(
            &mut device,
            &mut state,
            &mut queues,
            &vm,
            &irq
        ));

        assert_eq!(device.processed, vec![0]);
    }

    #[test]
    fn device_queue_counts_come_from_durable_config() {
        let mut net = NetState::zeroed();
        net.config.max_virtqueue_pairs = 3u16.to_le();
        assert_eq!(
            crate::devices::checked_durable_net_queue_pairs(&net).unwrap(),
            3
        );

        let mut fs = FsState::zeroed();
        fs.config.num_request_queues = 4u32.to_le();
        assert_eq!(
            crate::devices::checked_durable_fs_request_queues(&fs)
                .unwrap()
                .as_u32(),
            4
        );
    }

    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_reset_discards_inflight_reply_without_writing_old_descriptors() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::new();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0xfeed,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let initial = vec![0xcc; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &initial);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let poll = fs.poll();
        tokio::pin!(poll);
        tokio::select! {
            result = &mut poll => panic!("poll completed before backend was released: {result}"),
            () = backend.entered.notified() => {}
        }

        fs.handle_write(0x070, 4, 0);
        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        backend.release.notify_one();
        let had_work = poll.await;
        assert!(!had_work);

        assert_eq!(read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN), canary);
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_eq!(state.transport.interrupt_status & INT_VRING, 0);
        assert_eq!(state.queues[FIRST_REQUEST_QUEUE].ready, 0);
        assert_eq!(state.queues[FIRST_REQUEST_QUEUE].generation, 8);
    }

    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_stop_quiesces_inflight_poll_with_real_reply() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::new();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0xfeed,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let end = VmEnd::new();
        let poll = fs.poll();
        tokio::pin!(poll);
        tokio::select! {
            result = &mut poll => panic!("poll completed before backend was entered: {result}"),
            () = backend.entered.notified() => {}
        }

        end.stop();
        tokio::select! {
            result = &mut poll => panic!("poll completed before backend was released after stop: {result}"),
            () = tokio::time::sleep(Duration::from_millis(10)) => {}
        }

        assert_eq!(
            read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN),
            canary,
            "stop must wait for the real FUSE reply instead of publishing a synthetic completion",
        );
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 0);

        backend.release.notify_one();
        let had_work = poll.await;
        assert!(had_work);

        assert_ne!(
            read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN),
            canary,
            "released backend should commit the real FUSE reply",
        );
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        let used_head = vm.read_obj::<u32>(USED_GPA + 4).unwrap();
        let used_len = vm.read_obj::<u32>(USED_GPA + 8).unwrap();
        assert_eq!(used_idx, 1);
        assert_eq!(used_head, 0);
        assert!(used_len > 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_ne!(state.transport.interrupt_status & INT_VRING, 0);
        assert_eq!(state.queues[FIRST_REQUEST_QUEUE].last_avail_idx, 1);
        assert_eq!(state.queues[FIRST_REQUEST_QUEUE].last_used_idx, 1);
    }

    /// Companion to `fs_reset_discards_inflight_reply_without_writing_old_descriptors`.
    /// That test resets via STATUS=0. This test reconfigures the request queue
    /// (`QueueReady=0`) without touching STATUS, exercising the queue-runner
    /// queue-token gate before any stale FUSE reply bytes are committed.
    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_queue_generation_bump_discards_inflight_reply() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 256;
        const QUEUE_SEL_OFFSET: u64 = 0x030;
        const QUEUE_READY_OFFSET: u64 = 0x044;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::new();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0xfeed,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let initial = vec![0xcc; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &initial);

        let initial_status = READY_STATUS;
        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(initial_status);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let poll = fs.poll();
        tokio::pin!(poll);
        tokio::select! {
            result = &mut poll => panic!("poll completed before backend was released: {result}"),
            () = backend.entered.notified() => {}
        }

        // Bump the queue generation via the production MMIO path. STATUS is
        // never touched, so only the queue-runner token gate stops the stale
        // completion before reply bytes are written.
        fs.handle_write(QUEUE_SEL_OFFSET, 4, FIRST_REQUEST_QUEUE as u64);
        fs.handle_write(QUEUE_READY_OFFSET, 4, 0);

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        backend.release.notify_one();
        // The behavioral assertions below verify that the stale descriptor was
        // not written or published.
        let _ = poll.await;

        assert_eq!(
            read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN),
            canary,
            "stale FUSE reply must not be committed into the reconfigured queue's buffer",
        );
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_eq!(
            state.transport.status, initial_status,
            "STATUS must be unchanged — proves the queue-runner token gate discarded the reply",
        );
        assert_eq!(state.transport.interrupt_status & INT_VRING, 0);
        assert_eq!(state.queues[FIRST_REQUEST_QUEUE].generation, 8);
    }

    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_undersized_writable_response_faults_queue_without_guest_fallback() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 16;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0xbeef,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let had_work = fs.poll().await;
        assert!(!had_work);

        assert_eq!(
            read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN),
            canary,
            "undersized writable chain must not receive a synthetic EIO response",
        );
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_ne!(
            state.transport.status & STATUS_DEVICE_NEEDS_RESET,
            0,
            "undersized response capacity is a queue/device fault",
        );
        assert_eq!(state.transport.interrupt_status & INT_VRING, 0);
        assert_ne!(state.transport.interrupt_status & INT_CONFIG, 0);
    }

    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_dispatch_error_faults_queue_without_zero_completion() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 64;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        let descriptor = Descriptor {
            addr: RESPONSE_GPA,
            len: u32::try_from(RESPONSE_LEN).unwrap(),
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        vm.write_obj(DESC_GPA, &descriptor)
            .expect("descriptor write must map");
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let had_work = fs.poll().await;
        assert!(!had_work);

        assert_eq!(read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN), canary);
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_ne!(
            state.transport.status & STATUS_DEVICE_NEEDS_RESET,
            0,
            "malformed FUSE request must fault instead of publishing len=0",
        );
        assert_eq!(state.transport.interrupt_status & INT_VRING, 0);
        assert_ne!(state.transport.interrupt_status & INT_CONFIG, 0);
    }

    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_hiprio_getattr_gets_real_reply_instead_of_zero_completion() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0xcafe,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &1u16)
            .expect("avail idx write must map");

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[HIPRIO_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let had_work = fs.poll().await;
        assert!(had_work);

        assert_ne!(read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN), canary);
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        let used_head = vm.read_obj::<u32>(USED_GPA + 4).unwrap();
        let used_len = vm.read_obj::<u32>(USED_GPA + 8).unwrap();
        assert_eq!(used_idx, 1);
        assert_eq!(used_head, 0);
        assert!(used_len > 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
        assert_ne!(state.transport.interrupt_status & INT_VRING, 0);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn fs_pop_ready_requests_counts_per_queue_limit_after_hiprio() {
        const HIPRIO_DESC_GPA: u64 = 0x1000;
        const HIPRIO_AVAIL_GPA: u64 = 0x2000;
        const HIPRIO_USED_GPA: u64 = 0x3000;
        const HIPRIO_HEADER_GPA: u64 = 0x4000;
        const HIPRIO_RESPONSE_GPA: u64 = 0x5000;
        const REQUEST_DESC_GPA: u64 = 0x6000;
        const REQUEST_AVAIL_GPA: u64 = 0x7000;
        const REQUEST_USED_GPA: u64 = 0x8000;
        const REQUEST_HEADER_GPA: u64 = 0x9000;
        const REQUEST_RESPONSE_GPA: u64 = 0xa000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        for (header_gpa, unique) in [(HIPRIO_HEADER_GPA, 0x10), (REQUEST_HEADER_GPA, 0x20)] {
            let header = FuseInHeader {
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                opcode: FUSE_GETATTR,
                unique,
                nodeid: 1,
                ..FuseInHeader::default()
            };
            vm.write_obj(header_gpa, &header).unwrap();
        }

        for (desc_gpa, header_gpa, response_gpa) in [
            (HIPRIO_DESC_GPA, HIPRIO_HEADER_GPA, HIPRIO_RESPONSE_GPA),
            (REQUEST_DESC_GPA, REQUEST_HEADER_GPA, REQUEST_RESPONSE_GPA),
        ] {
            let descriptors = [
                Descriptor {
                    addr: header_gpa,
                    len: FUSE_GETATTR_REQUEST_LEN_U32,
                    flags: VIRTQ_DESC_F_NEXT,
                    next: 1,
                },
                Descriptor {
                    addr: response_gpa,
                    len: u32::try_from(RESPONSE_LEN).unwrap(),
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                },
            ];
            for (i, descriptor) in descriptors.iter().enumerate() {
                vm.write_obj(desc_gpa + u64::try_from(i).unwrap() * 16, descriptor)
                    .unwrap();
            }
        }

        for avail_gpa in [HIPRIO_AVAIL_GPA, REQUEST_AVAIL_GPA] {
            vm.write_obj(avail_gpa + 4, &0u16).unwrap();
            vm.write_obj(avail_gpa + 2, &1u16).unwrap();
        }

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[HIPRIO_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: HIPRIO_DESC_GPA,
                avail_addr: HIPRIO_AVAIL_GPA,
                used_addr: HIPRIO_USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: REQUEST_DESC_GPA,
                avail_addr: REQUEST_AVAIL_GPA,
                used_addr: REQUEST_USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 9,
            };
        }

        let mut cursor = 0;
        let requests = fs.pop_ready_requests(2, &mut cursor);

        assert_eq!(requests.len(), 2);
        assert_eq!(requests[0].queue_idx().unwrap(), HIPRIO_QUEUE);
        assert_eq!(requests[1].queue_idx().unwrap(), FIRST_REQUEST_QUEUE);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn fs_publishes_fast_completion_while_slow_backend_request_is_pending() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER1_GPA: u64 = 0x4000;
        const RESPONSE1_GPA: u64 = 0x5000;
        const HEADER2_GPA: u64 = 0x6000;
        const RESPONSE2_GPA: u64 = 0x7000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::blocking_nodeid(1);
        let fs = fs_device(&vm, &irq, &backend);

        let header1 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x1001,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        let header2 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x1002,
            nodeid: 2,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER1_GPA, &header1).unwrap();
        vm.write_obj(HEADER2_GPA, &header2).unwrap();

        let descriptors = [
            Descriptor {
                addr: HEADER1_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE1_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            Descriptor {
                addr: HEADER2_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 3,
            },
            Descriptor {
                addr: RESPONSE2_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .unwrap();
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16).unwrap();
        vm.write_obj(AVAIL_GPA + 6, &2u16).unwrap();
        vm.write_obj(AVAIL_GPA + 2, &2u16).unwrap();

        let canary1 = vec![0xa5; RESPONSE_LEN];
        let canary2 = vec![0x5a; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE1_GPA, &canary1);
        fill_guest(&vm, RESPONSE2_GPA, &canary2);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let poll = fs.poll();
        tokio::pin!(poll);
        tokio::select! {
            result = &mut poll => panic!("poll completed before slow request was released: {result}"),
            () = backend.entered.notified() => {}
        }

        for _ in 0..100 {
            if vm.read_obj::<u16>(USED_GPA + 2).unwrap() == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert_eq!(vm.read_obj::<u16>(USED_GPA + 2).unwrap(), 1);
        assert_eq!(vm.read_obj::<u32>(USED_GPA + 4).unwrap(), 2);
        assert_eq!(read_guest(&vm, RESPONSE1_GPA, RESPONSE_LEN), canary1);
        assert_ne!(read_guest(&vm, RESPONSE2_GPA, RESPONSE_LEN), canary2);

        backend.release.notify_one();
        let had_work = poll.await;
        assert!(had_work);
        assert_eq!(vm.read_obj::<u16>(USED_GPA + 2).unwrap(), 2);
        assert_eq!(vm.read_obj::<u32>(USED_GPA + 12).unwrap(), 0);
        assert_ne!(read_guest(&vm, RESPONSE1_GPA, RESPONSE_LEN), canary1);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    async fn fs_worker_accepts_later_kick_while_prior_request_is_pending() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER1_GPA: u64 = 0x4000;
        const RESPONSE1_GPA: u64 = 0x5000;
        const HEADER2_GPA: u64 = 0x6000;
        const RESPONSE2_GPA: u64 = 0x7000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::blocking_nodeid(1);
        let fs = fs_device(&vm, &irq, &backend);

        let header1 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x2001,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        let header2 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x2002,
            nodeid: 2,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER1_GPA, &header1).unwrap();
        vm.write_obj(HEADER2_GPA, &header2).unwrap();

        let descriptors = [
            Descriptor {
                addr: HEADER1_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE1_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            Descriptor {
                addr: HEADER2_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 3,
            },
            Descriptor {
                addr: RESPONSE2_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .unwrap();
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16).unwrap();
        vm.write_obj(AVAIL_GPA + 2, &1u16).unwrap();

        let canary1 = vec![0xa5; RESPONSE_LEN];
        let canary2 = vec![0x5a; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE1_GPA, &canary1);
        fill_guest(&vm, RESPONSE2_GPA, &canary2);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let devices: Vec<AnyDevice<'_, _, amla_core::backends::NullNetBackend>> =
            vec![AnyDevice::Fs(fs)];
        let fs_wake = crate::device_waker::FsWake::new();
        let end = Arc::new(VmEnd::new());
        let worker =
            crate::device_waker::fs_worker_loop(&devices, fs_wake.clone(), Arc::clone(&end));
        tokio::pin!(worker);

        fs_wake.request();
        tokio::select! {
            () = &mut worker => panic!("fs worker exited before slow request was released"),
            () = backend.entered.notified() => {}
        }

        vm.write_obj(AVAIL_GPA + 6, &2u16).unwrap();
        vm.write_obj(AVAIL_GPA + 2, &2u16).unwrap();
        fs_wake.request();

        for _ in 0..100 {
            if vm.read_obj::<u16>(USED_GPA + 2).unwrap() == 1 {
                break;
            }
            tokio::select! {
                () = &mut worker => panic!("fs worker exited before later request completed"),
                () = tokio::task::yield_now() => {}
            }
        }

        assert_eq!(vm.read_obj::<u16>(USED_GPA + 2).unwrap(), 1);
        assert_eq!(vm.read_obj::<u32>(USED_GPA + 4).unwrap(), 2);
        assert_eq!(read_guest(&vm, RESPONSE1_GPA, RESPONSE_LEN), canary1);
        assert_ne!(read_guest(&vm, RESPONSE2_GPA, RESPONSE_LEN), canary2);

        backend.release.notify_one();
        for _ in 0..100 {
            if vm.read_obj::<u16>(USED_GPA + 2).unwrap() == 2 {
                break;
            }
            tokio::select! {
                () = &mut worker => panic!("fs worker exited before slow request completed"),
                () = tokio::task::yield_now() => {}
            }
        }

        assert_eq!(vm.read_obj::<u16>(USED_GPA + 2).unwrap(), 2);
        assert_eq!(vm.read_obj::<u32>(USED_GPA + 12).unwrap(), 0);
        assert_ne!(read_guest(&vm, RESPONSE1_GPA, RESPONSE_LEN), canary1);

        end.stop();
        fs_wake.request_stop();
        tokio::time::timeout(Duration::from_secs(1), &mut worker)
            .await
            .expect("fs worker should exit after stop");
    }

    #[tokio::test]
    async fn fs_worker_final_stop_drains_pending_kick_before_exit() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER_GPA: u64 = 0x4000;
        const RESPONSE_GPA: u64 = 0x5000;
        const RESPONSE_LEN: usize = 256;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        let header = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x3001,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER_GPA, &header).unwrap();
        let descriptors = [
            Descriptor {
                addr: HEADER_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE_GPA,
                len: u32::try_from(RESPONSE_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .unwrap();
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16).unwrap();
        vm.write_obj(AVAIL_GPA + 2, &1u16).unwrap();

        let canary = vec![0xa5; RESPONSE_LEN];
        fill_guest(&vm, RESPONSE_GPA, &canary);
        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let devices: Vec<AnyDevice<'_, _, amla_core::backends::NullNetBackend>> =
            vec![AnyDevice::Fs(fs)];
        let fs_wake = crate::device_waker::FsWake::new();
        let end = Arc::new(VmEnd::new());
        let worker =
            crate::device_waker::fs_worker_loop(&devices, fs_wake.clone(), Arc::clone(&end));
        tokio::pin!(worker);

        fs_wake.request();
        end.stop();
        fs_wake.request_stop();
        tokio::time::timeout(Duration::from_secs(1), &mut worker)
            .await
            .expect("fs worker should final-drain pending fs work before exit");

        assert_eq!(vm.read_obj::<u16>(USED_GPA + 2).unwrap(), 1);
        assert_eq!(vm.read_obj::<u32>(USED_GPA + 4).unwrap(), 0);
        assert_ne!(read_guest(&vm, RESPONSE_GPA, RESPONSE_LEN), canary);
    }

    #[tokio::test]
    #[allow(clippy::too_many_lines)]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn fs_per_completion_prevalidation_faults_bad_completion_after_prior_publish() {
        const DESC_GPA: u64 = 0x1000;
        const AVAIL_GPA: u64 = 0x2000;
        const USED_GPA: u64 = 0x3000;
        const HEADER1_GPA: u64 = 0x4000;
        const RESPONSE1_GPA: u64 = 0x5000;
        const HEADER2_GPA: u64 = 0x6000;
        const RESPONSE2_GPA: u64 = 0x7000;
        const RESPONSE1_LEN: usize = 256;
        const RESPONSE2_LEN: usize = 16;

        let mmap = test_mmap_with_fs_slot(amla_core::vm_state::BITMAP_BLOCK_SIZE as usize);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let backend = BlockingGetattrBackend::ready();
        let fs = fs_device(&vm, &irq, &backend);

        let header1 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x1001,
            nodeid: 1,
            ..FuseInHeader::default()
        };
        let header2 = FuseInHeader {
            len: FUSE_GETATTR_REQUEST_LEN_U32,
            opcode: FUSE_GETATTR,
            unique: 0x1002,
            nodeid: 2,
            ..FuseInHeader::default()
        };
        vm.write_obj(HEADER1_GPA, &header1)
            .expect("header write must map");
        vm.write_obj(HEADER2_GPA, &header2)
            .expect("header write must map");

        let descriptors = [
            Descriptor {
                addr: HEADER1_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: RESPONSE1_GPA,
                len: u32::try_from(RESPONSE1_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
            Descriptor {
                addr: HEADER2_GPA,
                len: FUSE_GETATTR_REQUEST_LEN_U32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 3,
            },
            Descriptor {
                addr: RESPONSE2_GPA,
                len: u32::try_from(RESPONSE2_LEN).unwrap(),
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ];
        for (i, descriptor) in descriptors.iter().enumerate() {
            vm.write_obj(DESC_GPA + u64::try_from(i).unwrap() * 16, descriptor)
                .expect("descriptor write must map");
        }
        vm.write_obj(AVAIL_GPA + 4, &0u16)
            .expect("first avail ring write must map");
        vm.write_obj(AVAIL_GPA + 6, &2u16)
            .expect("second avail ring write must map");
        vm.write_obj(AVAIL_GPA + 2, &2u16)
            .expect("avail idx write must map");

        let canary1 = vec![0xa5; RESPONSE1_LEN];
        let canary2 = vec![0x5a; RESPONSE2_LEN];
        fill_guest(&vm, RESPONSE1_GPA, &canary1);
        fill_guest(&vm, RESPONSE2_GPA, &canary2);

        {
            let mut state = vm.device_slot_mut(fs_slot());
            *state = FsState::zeroed();
            state.transport = transport(READY_STATUS);
            state.transport.driver_features = VIRTIO_F_VERSION_1;
            state.config.num_request_queues = 1;
            state.queues[FIRST_REQUEST_QUEUE] = QueueState {
                size: 16,
                ready: 1,
                pad0: 0,
                desc_addr: DESC_GPA,
                avail_addr: AVAIL_GPA,
                used_addr: USED_GPA,
                last_avail_idx: 0,
                last_used_idx: 0,
                generation: 7,
            };
        }

        let had_work = fs.poll().await;
        assert!(had_work);

        assert_ne!(read_guest(&vm, RESPONSE1_GPA, RESPONSE1_LEN), canary1);
        assert_eq!(read_guest(&vm, RESPONSE2_GPA, RESPONSE2_LEN), canary2);
        let used_idx = vm.read_obj::<u16>(USED_GPA + 2).unwrap();
        assert_eq!(used_idx, 1);
        let used_head = vm.read_obj::<u32>(USED_GPA + 4).unwrap();
        assert_eq!(used_head, 0);

        let state = vm.device_slot_mut(fs_slot());
        assert_ne!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
        assert_ne!(state.transport.interrupt_status & INT_VRING, 0);
        assert_ne!(state.transport.interrupt_status & INT_CONFIG, 0);
    }
}
