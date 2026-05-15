// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Device management for the VMM.
//!
//! Device objects are created as locals in `run()` via `create_devices()` and
//! live only for the duration of that call — no `Arc` needed.
//! Those locals are adapters around mmap-backed device state and external
//! backends. Guest-visible progress must live in `VmState` (or be explicitly
//! backend-owned), not in these per-run device structs.
//!
//! Free functions (`mmio_read`, `mmio_write`, etc.) operate on the device array.

use std::collections::VecDeque;
use std::ops::Range;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::Notify;

use amla_core::backends::{ConsoleBackend, NetBackend, RxWaker};
use amla_core::vm_state::{
    DEVICE_KIND_CONSOLE, DEVICE_KIND_FS, DEVICE_KIND_NET, DEVICE_KIND_PMEM, DEVICE_KIND_RNG,
    DeviceMetaError, DeviceMetaMountPath, DeviceMetaSlot, DeviceMetaTag, DeviceSlot, VmState,
    VmStateHeader,
};
use amla_core::{DeviceWakeIndex, DeviceWaker, IrqFactory};
use amla_fuse::fuse::FsBackend;
use amla_virtio::{ConsoleState, FsState, NetState, PmemState, RngState};
use amla_virtio_console::{AGENT_TAG_KICK, AgentPortBackend};
#[cfg(not(target_arch = "aarch64"))]
use amla_virtio_mmio::{MMIO_DEVICE_SIZE, device_mmio_addr};
use amla_virtio_mmio::{QUEUE_NOTIFY, resolve_mmio_addr};

use crate::agent::HostNotify;
use crate::agent::{AgentLink, AgentRingState, AgentRingWake};
use crate::config::{KernelCmdlineAtom, PmemDiskConfig, PmemImageConfig, VmConfig};
use crate::device::{AnyDevice, ConsoleDevice, FsDevice, NetDevice, PmemDevice, RngDevice};
use crate::error::{DeviceError, Result};

/// Identifies a virtio device type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceKind {
    /// Serial console.
    Console,
    /// Network.
    Net,
    /// Entropy source.
    Rng,
    /// Filesystem (FUSE).
    Fs,
    /// Persistent memory.
    Pmem,
}

/// One pending-wake bit mapped to a concrete device queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceQueueWake {
    /// Global wake bit index.
    pub wake: DeviceWakeIndex,
    /// MMIO device slot index.
    pub device: usize,
    /// Virtqueue index inside the device.
    pub queue: usize,
}

/// Maximum queue-wake bits supported by [`amla_core::DeviceWaker`].
pub const MAX_QUEUE_WAKE_BITS: usize = DeviceWakeIndex::MAX;

/// Per-device virtqueue count after layout validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceQueueCount(u16);

impl DeviceQueueCount {
    fn new(count: usize) -> Result<Self> {
        let count = u16::try_from(count).map_err(|_| {
            device_layout_error(format!("device queue count {count} does not fit u16"))
        })?;
        Ok(Self(count))
    }

    const fn as_u16(self) -> u16 {
        self.0
    }

    fn as_usize(self) -> usize {
        usize::from(self.0)
    }
}

/// Global wake-bit layout for all device queues.
#[derive(Debug, Clone)]
pub struct QueueWakeMap {
    wakes: Vec<DeviceQueueWake>,
    device_ranges: Vec<Range<usize>>,
}

impl QueueWakeMap {
    /// Build the queue wake map from a device layout.
    pub fn new(layout: &DeviceLayout) -> Result<Self> {
        Self::from_queue_counts(layout.queue_counts())
    }

    #[cfg(test)]
    pub(crate) fn from_queue_counts_for_test(queue_counts: &[usize]) -> Result<Self> {
        let queue_counts = queue_counts
            .iter()
            .copied()
            .map(DeviceQueueCount::new)
            .collect::<Result<Vec<_>>>()?;
        Self::from_queue_counts(&queue_counts)
    }

    fn from_queue_counts(queue_counts: &[DeviceQueueCount]) -> Result<Self> {
        let mut wakes = Vec::new();
        let mut device_ranges = Vec::with_capacity(queue_counts.len());
        for (device_idx, queue_count) in queue_counts.iter().copied().enumerate() {
            let start = wakes.len();
            for queue_idx in 0..queue_count.as_usize() {
                let wake = DeviceWakeIndex::new(wakes.len()).map_err(|_| {
                    crate::Error::Config(crate::ConfigError::TooManyQueueWakes {
                        count: wakes.len() + 1,
                        max: MAX_QUEUE_WAKE_BITS,
                    })
                })?;
                wakes.push(DeviceQueueWake {
                    wake,
                    device: device_idx,
                    queue: queue_idx,
                });
            }
            device_ranges.push(start..wakes.len());
        }
        Ok(Self {
            wakes,
            device_ranges,
        })
    }

    /// Return the queue wake for `wake_idx`.
    pub fn get(&self, wake_idx: DeviceWakeIndex) -> Option<DeviceQueueWake> {
        self.wakes.get(wake_idx.as_usize()).copied()
    }

    /// Return the queue wake for a device-local queue notification.
    pub fn device_queue_wake(
        &self,
        device_idx: usize,
        queue_idx: usize,
    ) -> Option<DeviceQueueWake> {
        let range = self.device_ranges.get(device_idx)?;
        if queue_idx >= range.len() {
            return None;
        }
        self.wakes.get(range.start + queue_idx).copied()
    }

    /// Queue wake indexes assigned to a device.
    pub fn device_wake_indices(
        &self,
        device_idx: usize,
    ) -> impl Iterator<Item = DeviceWakeIndex> + '_ {
        let range = self.device_ranges.get(device_idx).cloned().unwrap_or(0..0);
        self.wakes[range].iter().map(|wake| wake.wake)
    }

    /// Number of wake slots reserved for a device.
    pub fn device_queue_count(&self, device_idx: usize) -> usize {
        self.device_ranges
            .get(device_idx)
            .map_or(0, std::ops::Range::len)
    }

    /// Iterate all wake entries.
    #[allow(dead_code)]
    pub fn iter(&self) -> impl Iterator<Item = DeviceQueueWake> + '_ {
        self.wakes.iter().copied()
    }
}

const fn default_queue_count_for_kind(kind: DeviceKind) -> usize {
    match kind {
        DeviceKind::Console => amla_virtio_console::QUEUE_COUNT,
        DeviceKind::Net => amla_virtio_net::queue_count_for_pairs(1),
        DeviceKind::Rng | DeviceKind::Pmem => 1,
        DeviceKind::Fs => amla_virtio_fs::RequestQueueCount::ONE.total_queue_count(),
    }
}

impl std::fmt::Display for DeviceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl DeviceKind {
    const fn state_code(self) -> u8 {
        match self {
            Self::Console => DEVICE_KIND_CONSOLE,
            Self::Net => DEVICE_KIND_NET,
            Self::Rng => DEVICE_KIND_RNG,
            Self::Fs => DEVICE_KIND_FS,
            Self::Pmem => DEVICE_KIND_PMEM,
        }
    }

    const fn from_state_code(code: u8) -> Option<Self> {
        match code {
            DEVICE_KIND_CONSOLE => Some(Self::Console),
            DEVICE_KIND_NET => Some(Self::Net),
            DEVICE_KIND_RNG => Some(Self::Rng),
            DEVICE_KIND_FS => Some(Self::Fs),
            DEVICE_KIND_PMEM => Some(Self::Pmem),
            _ => None,
        }
    }
}

/// Typed state slot for one device layout entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceStateSlot {
    /// Console state slot.
    Console(DeviceSlot<ConsoleState>),
    /// Net state slot.
    Net(DeviceSlot<NetState>),
    /// Rng state slot.
    Rng(DeviceSlot<RngState>),
    /// Fs state slot.
    Fs(DeviceSlot<FsState>),
    /// Pmem state slot.
    Pmem(DeviceSlot<PmemState>),
}

impl DeviceStateSlot {
    fn new(index: usize, kind: DeviceKind) -> Self {
        match kind {
            DeviceKind::Console => {
                // SAFETY: `DeviceLayout::new` mints this token while building
                // the authoritative device-kind vector; this arm ties Console
                // kind to ConsoleState for the same slot index.
                Self::Console(unsafe { DeviceSlot::new_unchecked(index) })
            }
            DeviceKind::Net => {
                // SAFETY: see Console arm; Net kind maps to NetState.
                Self::Net(unsafe { DeviceSlot::new_unchecked(index) })
            }
            DeviceKind::Rng => {
                // SAFETY: see Console arm; Rng kind maps to RngState.
                Self::Rng(unsafe { DeviceSlot::new_unchecked(index) })
            }
            DeviceKind::Fs => {
                // SAFETY: see Console arm; Fs kind maps to FsState.
                Self::Fs(unsafe { DeviceSlot::new_unchecked(index) })
            }
            DeviceKind::Pmem => {
                // SAFETY: see Console arm; Pmem kind maps to PmemState.
                Self::Pmem(unsafe { DeviceSlot::new_unchecked(index) })
            }
        }
    }

    /// Raw device slot index for array lookups and wake-map indexing.
    pub(crate) const fn index(self) -> usize {
        match self {
            Self::Console(slot) => slot.index(),
            Self::Net(slot) => slot.index(),
            Self::Rng(slot) => slot.index(),
            Self::Fs(slot) => slot.index(),
            Self::Pmem(slot) => slot.index(),
        }
    }
}

/// Precomputed device layout with O(1) typed slot lookups.
///
/// Replaces raw `Vec<DeviceKind>` + repeated `.position()` scans. Built once
/// from `VmConfig` and carried through all state transitions.
///
/// Fixed devices (Console, Rng) always have indices.
/// Optional devices (Net, Fs) have typed optional slots. Pmem devices are
/// tracked as typed slots in config order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceLayout {
    /// Device kinds in slot order (for iteration and backend matching).
    kinds: Vec<DeviceKind>,
    /// Exact hardware virtqueue count per device slot.
    queue_counts: Vec<DeviceQueueCount>,
    /// Typed state slot per device kind entry.
    slots: Vec<DeviceStateSlot>,
    /// Console device slot (always present).
    pub console: DeviceSlot<ConsoleState>,
    /// Net device slot (present when `config.net` is set).
    pub net: Option<DeviceSlot<NetState>>,
    /// Fs device slot (present when `config.fs` is set).
    pub fs: Option<DeviceSlot<FsState>>,
    /// Pmem device slots in config order.
    pub pmem: Vec<DeviceSlot<PmemState>>,
}

impl DeviceLayout {
    /// Build a default single-queue test layout from raw device kinds.
    #[allow(clippy::expect_used)]
    #[cfg(test)]
    pub fn new(kinds: Vec<DeviceKind>) -> Self {
        let queue_counts = kinds
            .iter()
            .copied()
            .map(default_queue_count_for_kind)
            .collect();
        Self::try_new(kinds, queue_counts).expect("invalid device layout")
    }

    /// Build the exact device layout described by a VM config.
    pub(crate) fn from_config(config: &VmConfig) -> Result<Self> {
        let mut kinds = vec![DeviceKind::Console, DeviceKind::Rng];
        let mut queue_counts = vec![
            amla_virtio_console::QUEUE_COUNT,
            default_queue_count_for_kind(DeviceKind::Rng),
        ];

        if let Some(net) = config.net.as_ref() {
            kinds.push(DeviceKind::Net);
            queue_counts.push(amla_virtio_net::queue_count_for_pairs(net.queue_pairs));
        }
        if let Some(fs) = config.fs.as_ref() {
            kinds.push(DeviceKind::Fs);
            queue_counts.push(fs.num_request_queues.virtio().total_queue_count());
        }
        for _ in &config.pmem_disks {
            kinds.push(DeviceKind::Pmem);
            queue_counts.push(default_queue_count_for_kind(DeviceKind::Pmem));
        }

        Self::try_new(kinds, queue_counts)
    }

    fn try_new(kinds: Vec<DeviceKind>, queue_counts: Vec<usize>) -> Result<Self> {
        let queue_counts = queue_counts
            .into_iter()
            .map(DeviceQueueCount::new)
            .collect::<Result<Vec<_>>>()?;
        validate_device_topology(&kinds, &queue_counts)?;
        let slots: Vec<_> = kinds
            .iter()
            .copied()
            .enumerate()
            .map(|(index, kind)| DeviceStateSlot::new(index, kind))
            .collect();
        let console = slots
            .iter()
            .find_map(|slot| match *slot {
                DeviceStateSlot::Console(slot) => Some(slot),
                _ => None,
            })
            .ok_or_else(|| device_layout_error("device layout must include Console"))?;
        let net = slots.iter().find_map(|slot| match *slot {
            DeviceStateSlot::Net(slot) => Some(slot),
            _ => None,
        });
        let fs = slots.iter().find_map(|slot| match *slot {
            DeviceStateSlot::Fs(slot) => Some(slot),
            _ => None,
        });
        let pmem = slots
            .iter()
            .filter_map(|slot| match *slot {
                DeviceStateSlot::Pmem(slot) => Some(slot),
                _ => None,
            })
            .collect();
        Ok(Self {
            kinds,
            queue_counts,
            slots,
            console,
            net,
            fs,
            pmem,
        })
    }

    /// Reconstruct the exact device layout from the durable mmap header.
    pub(crate) fn from_header(header: &VmStateHeader) -> Result<Self> {
        let count = usize::try_from(header.device_count)
            .map_err(|_| device_layout_error("header device_count does not fit usize"))?;
        if count > amla_core::vm_state::MAX_DEVICES {
            return Err(device_layout_error(format!(
                "header device_count {count} exceeds MAX_DEVICES"
            )));
        }

        let mut kinds = Vec::with_capacity(count);
        let mut queue_counts = Vec::with_capacity(count);
        for (idx, &code) in header.device_kinds[..count].iter().enumerate() {
            let kind = DeviceKind::from_state_code(code).ok_or_else(|| {
                device_layout_error(format!(
                    "header device_kinds[{idx}] has unknown code {code}"
                ))
            })?;
            kinds.push(kind);
            queue_counts.push(usize::from(header.device_queue_counts[idx]));
        }

        if header.device_kinds[count..].iter().any(|&code| code != 0) {
            return Err(device_layout_error(
                "header has nonzero device kind beyond device_count",
            ));
        }
        if header.device_queue_counts[count..]
            .iter()
            .any(|&count| count != 0)
        {
            return Err(device_layout_error(
                "header has nonzero device queue count beyond device_count",
            ));
        }

        Self::try_new(kinds, queue_counts)
    }

    /// Reconstruct and cross-check the exact durable device layout.
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn from_vm_state(vm: &VmState<'_>) -> Result<Self> {
        let layout = Self::from_header(vm.header())?;
        if let Some(slot) = layout.net {
            let state = vm.device_slot_mut(slot);
            let queue_pairs = checked_durable_net_queue_pairs(&state)?;
            let expected = amla_virtio_net::queue_count_for_pairs(queue_pairs);
            layout.require_queue_count(slot.index(), expected, "net durable config")?;
        }
        if let Some(slot) = layout.fs {
            let state = vm.device_slot_mut(slot);
            let request_queues = checked_durable_fs_request_queues(&state)?;
            let expected = request_queues.total_queue_count();
            layout.require_queue_count(slot.index(), expected, "fs durable config")?;
        }
        Ok(layout)
    }

    /// Device kinds in slot order (for iteration, IRQ creation, backend matching).
    pub fn kinds(&self) -> &[DeviceKind] {
        &self.kinds
    }

    /// Exact virtqueue counts in device slot order.
    pub(crate) fn queue_counts(&self) -> &[DeviceQueueCount] {
        &self.queue_counts
    }

    fn require_queue_count(
        &self,
        device_idx: usize,
        expected: usize,
        source: &'static str,
    ) -> Result<()> {
        let actual = self.queue_counts.get(device_idx).copied().ok_or_else(|| {
            device_layout_error(format!(
                "{source}: device index {device_idx} is out of range"
            ))
        })?;
        if actual.as_usize() != expected {
            return Err(device_layout_error(format!(
                "{source}: device slot {device_idx} queue count {} != expected {expected}",
                actual.as_usize()
            )));
        }
        Ok(())
    }

    /// Device topology entries suitable for diagnostics.
    pub(crate) fn diagnostic_entries(&self) -> Vec<(DeviceKind, usize)> {
        self.kinds
            .iter()
            .copied()
            .zip(
                self.queue_counts
                    .iter()
                    .copied()
                    .map(DeviceQueueCount::as_usize),
            )
            .collect()
    }

    /// Typed device-state slots in slot order.
    pub fn slots(&self) -> &[DeviceStateSlot] {
        &self.slots
    }

    /// Stamp the durable mmap header with the device kind order.
    pub(crate) fn write_header(&self, header: &mut VmStateHeader) {
        header.device_kinds = [0; amla_core::vm_state::MAX_DEVICES];
        header.device_queue_counts = [0; amla_core::vm_state::MAX_DEVICES];
        for (dst, kind) in header.device_kinds.iter_mut().zip(self.kinds.iter()) {
            *dst = kind.state_code();
        }
        for (dst, count) in header
            .device_queue_counts
            .iter_mut()
            .zip(self.queue_counts.iter().copied())
        {
            *dst = count.as_u16();
        }
    }

    /// Number of devices in the layout.
    pub const fn len(&self) -> usize {
        self.kinds.len()
    }
}

/// Validate device-specific persisted state before a backend shell consumes it.
pub fn validate_durable_device_state(vm: &VmState<'_>, device_layout: &DeviceLayout) -> Result<()> {
    for slot in device_layout.slots() {
        match *slot {
            DeviceStateSlot::Console(slot) => {
                let state = vm.device_slot_mut(slot);
                state.control.validate().map_err(|error| {
                    device_layout_error(format!("console device state is not canonical: {error}"))
                })?;
            }
            DeviceStateSlot::Net(_)
            | DeviceStateSlot::Rng(_)
            | DeviceStateSlot::Fs(_)
            | DeviceStateSlot::Pmem(_) => {}
        }
    }
    Ok(())
}

fn validate_device_topology(kinds: &[DeviceKind], queue_counts: &[DeviceQueueCount]) -> Result<()> {
    fn count(kinds: &[DeviceKind], kind: DeviceKind) -> usize {
        kinds.iter().filter(|&&k| k == kind).count()
    }

    if kinds.len() != queue_counts.len() {
        return Err(device_layout_error(format!(
            "device topology kind count {} != queue count count {}",
            kinds.len(),
            queue_counts.len()
        )));
    }

    for kind in [DeviceKind::Console, DeviceKind::Rng] {
        let n = count(kinds, kind);
        if n != 1 {
            return Err(device_layout_error(format!(
                "device layout must contain exactly one {kind}, found {n}"
            )));
        }
    }

    for kind in [DeviceKind::Net, DeviceKind::Fs] {
        let n = count(kinds, kind);
        if n > 1 {
            return Err(device_layout_error(format!(
                "device layout must contain at most one {kind}, found {n}"
            )));
        }
    }

    for (idx, (&kind, queue_count)) in kinds.iter().zip(queue_counts).enumerate() {
        validate_device_queue_count(idx, kind, queue_count.as_usize())?;
    }

    Ok(())
}

fn validate_device_queue_count(idx: usize, kind: DeviceKind, queue_count: usize) -> Result<()> {
    match kind {
        DeviceKind::Console => {
            if queue_count != amla_virtio_console::QUEUE_COUNT {
                return Err(device_layout_error(format!(
                    "device {idx} Console queue count {queue_count} != {}",
                    amla_virtio_console::QUEUE_COUNT
                )));
            }
        }
        DeviceKind::Net => {
            let queue_pairs = net_queue_pairs_from_queue_count(queue_count)?;
            if amla_virtio_net::queue_count_for_pairs(queue_pairs) != queue_count {
                return Err(device_layout_error(format!(
                    "device {idx} Net queue count {queue_count} is not canonical"
                )));
            }
        }
        DeviceKind::Rng | DeviceKind::Pmem => {
            if queue_count != 1 {
                return Err(device_layout_error(format!(
                    "device {idx} {kind} queue count {queue_count} != 1"
                )));
            }
        }
        DeviceKind::Fs => {
            if queue_count == amla_virtio_fs::HIPRIO_QUEUE {
                return Err(device_layout_error(format!(
                    "device {idx} Fs queue count {queue_count} is missing request queues"
                )));
            }
            let Ok(request_queues) =
                u32::try_from(queue_count - amla_virtio_fs::FIRST_REQUEST_QUEUE)
            else {
                return Err(device_layout_error(format!(
                    "device {idx} Fs queue count {queue_count} does not fit u32"
                )));
            };
            amla_virtio_fs::RequestQueueCount::new(request_queues).map_err(|err| {
                device_layout_error(format!(
                    "device {idx} Fs queue count {queue_count} is invalid: {err}"
                ))
            })?;
        }
    }
    Ok(())
}

fn net_queue_pairs_from_queue_count(queue_count: usize) -> Result<u16> {
    if queue_count == amla_virtio_net::queue_count_for_pairs(1) {
        return Ok(1);
    }
    if queue_count < 5 || queue_count.is_multiple_of(2) {
        return Err(device_layout_error(format!(
            "net queue count {queue_count} is not RX/TX pairs plus control queue"
        )));
    }
    let pairs = (queue_count - 1) / 2;
    let pairs = u16::try_from(pairs)
        .map_err(|_| device_layout_error(format!("net queue count {queue_count} too large")))?;
    if !(2..=amla_virtio_net::MAX_QUEUE_PAIRS).contains(&pairs) {
        return Err(device_layout_error(format!(
            "net queue count {queue_count} is outside supported pair range"
        )));
    }
    Ok(pairs)
}

pub fn checked_durable_net_queue_pairs(state: &NetState) -> Result<u16> {
    let queue_pairs = u16::from_le(state.config.max_virtqueue_pairs);
    if !(1..=amla_virtio_net::MAX_QUEUE_PAIRS).contains(&queue_pairs) {
        return Err(device_layout_error(format!(
            "durable net max_virtqueue_pairs {queue_pairs} is outside 1..={}",
            amla_virtio_net::MAX_QUEUE_PAIRS
        )));
    }
    Ok(queue_pairs)
}

pub fn checked_durable_fs_request_queues(
    state: &FsState,
) -> Result<amla_virtio_fs::RequestQueueCount> {
    let num_request_queues = u32::from_le(state.config.num_request_queues);
    amla_virtio_fs::RequestQueueCount::new(num_request_queues).map_err(|err| {
        device_layout_error(format!(
            "durable fs num_request_queues {num_request_queues} is invalid: {err}"
        ))
    })
}

fn device_layout_error(message: impl Into<String>) -> crate::Error {
    crate::Error::Core(amla_core::VmmError::DeviceConfig(message.into()))
}

fn device_meta_error(error: DeviceMetaError) -> crate::Error {
    crate::Error::Core(amla_core::VmmError::DeviceConfig(format!(
        "device metadata: {error}"
    )))
}

/// Return the maximum number of active virtio-mmio devices supported by the platform.
#[cfg(target_arch = "aarch64")]
pub(crate) const fn max_active_device_slots() -> usize {
    amla_boot::arm64::irq::MAX_VIRTIO_MMIO_IRQS
}

/// Return the maximum number of active virtio-mmio devices supported by the platform.
#[cfg(not(target_arch = "aarch64"))]
pub const fn max_active_device_slots() -> usize {
    amla_virtio_mmio::MAX_ACTIVE_DEVICES
}

/// Return the backend IRQ line number for a virtio-mmio device slot.
///
/// On `x86_64` this is an IOAPIC GSI. On `ARM64` it is the zero-based GIC SPI
/// number allocated by the shared ARM64 platform IRQ allocator.
#[cfg(target_arch = "aarch64")]
pub(crate) fn device_irq_line(
    device_idx: usize,
) -> std::result::Result<u32, amla_boot::arm64::irq::IrqAllocError> {
    amla_boot::arm64::irq::Arm64IrqAllocator::new()
        .virtio_mmio(device_idx)
        .map(amla_boot::arm64::irq::Arm64Irq::backend_gsi)
}

/// Return the backend IRQ line number for a virtio-mmio device slot.
///
/// `Result` here mirrors the aarch64 signature where IRQ allocation can
/// fail; the x86 path is infallible.
#[cfg(not(target_arch = "aarch64"))]
#[allow(clippy::unnecessary_wraps)]
pub fn device_irq_line(device_idx: usize) -> std::result::Result<u32, core::convert::Infallible> {
    Ok(amla_virtio_mmio::device_gsi(device_idx))
}

/// Return the ARM64 IRQ descriptor for a virtio-mmio device slot.
#[cfg(target_arch = "aarch64")]
pub(crate) fn arm64_device_irq(
    device_idx: usize,
) -> std::result::Result<amla_boot::arm64::irq::Arm64Irq, amla_boot::arm64::irq::IrqAllocError> {
    amla_boot::arm64::irq::Arm64IrqAllocator::new().virtio_mmio(device_idx)
}

/// Agent port backend: doorbell + stored u64 value.
///
/// Port 1 carries a framed u64 (ring GPA) on first read, then single-byte
/// doorbell kicks for bidirectional host↔guest notification.
///
/// Framing: `0x01` + 8 bytes = initial u64 value, `0x02` = doorbell kick.
struct AgentPort {
    /// Shared RX buffer (host→guest). `VirtioKick` pushes kick bytes here.
    rx_buf: Arc<parking_lot::Mutex<VecDeque<u8>>>,
}

impl AgentPortBackend for AgentPort {
    fn has_pending_rx(&self) -> bool {
        !self.rx_buf.lock().is_empty()
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn read_rx(&mut self, buf: &mut [u8]) -> usize {
        let mut rx = self.rx_buf.lock();
        let n = buf.len().min(rx.len());
        for (b, val) in buf[..n].iter_mut().zip(rx.drain(..n)) {
            *b = val;
        }
        n
    }

    fn write_tx(&mut self, _data: &[u8]) {
        // No-op: guest→host doorbell wakes the device loop
        // via console_wake, which processes the ring.
    }
}

/// Kick implementation for VM host→guest notification via virtio console.
///
/// Pushes a `AGENT_TAG_KICK` byte into the console port's RX buffer and
/// wakes the device loop so it delivers the byte as a virtio IRQ to the guest.
pub struct VirtioKick {
    rx_buf: Arc<parking_lot::Mutex<VecDeque<u8>>>,
    console_notify: HostNotify,
}

impl VirtioKick {
    fn kick(&self) {
        let mut rx = self.rx_buf.lock();
        if rx.is_empty() {
            rx.push_back(AGENT_TAG_KICK);
        }
        drop(rx);
        self.console_notify.notify();
    }
}

impl AgentRingWake for VirtioKick {
    fn wake_peer(&self) {
        self.kick();
    }
}

/// Everything `run()` needs from device creation.
///
/// Groups the devices, agent ring, and notification handles created by
/// `create_devices`. The agent infrastructure (link, console wake, rx buffer)
/// is created internally by `create_devices` — callers only see the outputs.
pub struct DeviceOutput<'irq, F: FsBackend, N: NetBackend> {
    /// All device objects (local to `run()`).
    pub devices: Vec<AnyDevice<'irq, F, N>>,
    /// Agent ring state for host↔guest communication.
    pub agent_ring: AgentRingState<'irq, VirtioKick>,
    /// Agent link for host↔guest command execution.
    pub agent_link: Arc<AgentLink>,
    /// Console wake notify — shared between console and device loop.
    pub console_wake: Arc<Notify>,
    /// Net RX notify (present when a net backend is configured).
    pub net_rx_notify: Option<NetRxNotify>,
    /// Run-scoped backend RX registrations.
    pub rx_registrations: DeviceRxRegistrations,
}

/// Backend RX registrations that are valid only for one `run()` scope.
pub struct DeviceRxRegistrations {
    console_waker: RxWaker,
    net_waker: Option<RxWaker>,
}

impl Drop for DeviceRxRegistrations {
    fn drop(&mut self) {
        self.console_waker.cancel();
        if let Some(waker) = &self.net_waker {
            waker.cancel();
        }
    }
}

/// Sticky notification state for net RX packets.
pub struct NetRxNotify {
    /// Async wake used by the device loop.
    pub wake: Arc<Notify>,
    /// Set by the producer before waking so notifications survive dropped waiters.
    pub pending: Arc<AtomicBool>,
}

/// Create IRQ lines for all devices in the layout.
///
/// Returns one `Box<dyn IrqLine>` per device. The caller stores these
/// and passes them by reference to `create_devices()` — devices borrow
/// the IRQ lines, so the lines must outlive the devices.
pub fn create_irq_lines(
    irq_factory: &dyn IrqFactory,
    device_layout: &DeviceLayout,
) -> Result<Vec<Box<dyn amla_core::IrqLine>>> {
    device_layout
        .kinds()
        .iter()
        .enumerate()
        .map(|(idx, kind)| {
            let irq = device_irq_line(idx).map_err(|e| DeviceError::IrqCreation {
                kind: kind.to_string(),
                source: Box::new(e),
            })?;
            irq_factory.create_resampled_irq_line(irq).map_err(|e| {
                DeviceError::IrqCreation {
                    kind: kind.to_string(),
                    source: e,
                }
                .into()
            })
        })
        .collect()
}

/// Create all device objects and agent infrastructure.
///
/// Every device in `device_layout` gets a real backend — there are no
/// empty slots. Backends are validated upstream by `load_kernel()` / `spawn()`.
///
/// Agent infrastructure (`AgentLink`, console wake, RX buffer) is created
/// internally and returned via `DeviceOutput`. The console backend's RX
/// waker is wired to the console wake notify before device construction.
#[allow(
    clippy::too_many_lines, // device match is one logical unit
    clippy::unnecessary_wraps
)]
pub fn create_devices<'irq, F: FsBackend, N: NetBackend>(
    console_backend: &'irq dyn ConsoleBackend,
    mut fs_backend: Option<&'irq F>,
    mut net_backend: Option<&'irq N>,
    irq_lines: &'irq [Box<dyn amla_core::IrqLine>],
    device_layout: &DeviceLayout,
    vm: &'irq VmState<'irq>,
) -> Result<DeviceOutput<'irq, F, N>> {
    // Create agent infrastructure.
    let agent_link = Arc::new(AgentLink::new());
    let console_wake = agent_link.host_notify();
    let console_notify = agent_link.host_notifier();
    let rx_buf = Arc::new(parking_lot::Mutex::new(VecDeque::new()));

    // Wire console backend to wake device loop.
    let wake = console_notify.clone();
    let console_waker = RxWaker::new(move || wake.notify());
    console_backend.set_rx_waker(Some(console_waker.clone()));

    let mut console_backend = Some(console_backend);

    let mut devices = Vec::with_capacity(device_layout.len());
    let mut agent_port_taken = false;
    let mut agent_ring: Option<AgentRingState<'_, VirtioKick>> = None;
    let mut net_rx_notify: Option<NetRxNotify> = None;
    let mut registered_net_waker: Option<RxWaker> = None;

    for (idx, (&kind, &slot)) in device_layout
        .kinds()
        .iter()
        .zip(device_layout.slots())
        .enumerate()
    {
        let irq: &'irq dyn amla_core::IrqLine = &**irq_lines
            .get(idx)
            .ok_or_else(|| missing_irq_line(idx, kind))?;

        let device = match slot {
            DeviceStateSlot::Console(slot) => {
                if agent_port_taken {
                    return Err(device_layout_error(
                        "device layout contains more than one Console device",
                    ));
                }
                agent_port_taken = true;

                let backend = console_backend
                    .take()
                    .ok_or_else(|| missing_backend(DeviceKind::Console))?;
                let port = AgentPort {
                    rx_buf: Arc::clone(&rx_buf),
                };

                // SAFETY:
                // - `ring_ptr` is derived from `VmStateView::ring_buffer_hva()`, which
                //   returns `offset_mut_ptr(header.ring_offset)` on a region whose layout
                //   reserves `HostGuestRingBuffer::TOTAL_SIZE` bytes at that offset
                //   (enforced by the vm_state layout builder in amla-vm-core).
                // - The ring buffer offset is placed on a 64-byte boundary by the
                //   layout builder, satisfying `RingBuffer`'s alignment requirement.
                // - The backing `MmapSlice` is owned by `vm` (Ready::regions) and
                //   outlives every device built in this loop — the returned
                //   `&HostGuestRingBuffer` borrows through `'irq`.
                // - SPSC discipline: this is the sole host-side acquisition of the
                //   ring; `hg_writer()` and `gh_reader()` are each moved to a single
                //   owner (the agent ring task). The header was initialized once in
                //   `machine::create()` via `init_ring_buffer` before the guest ran.
                let ready = unsafe {
                    let ring_ptr = vm.ring_buffer_hva().ok_or_else(|| {
                        amla_core::VmmError::DeviceConfig("ring buffer offset out of bounds".into())
                    })?;
                    amla_vm_ringbuf::HostGuestRingBufferHandle::attach(
                        ring_ptr,
                        amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE,
                    )
                }
                .and_then(amla_vm_ringbuf::HostGuestRingBufferHandle::validate)
                .map_err(|e| {
                    amla_core::VmmError::DeviceConfig(format!("agent ring validation: {e}"))
                })?;
                let endpoints = ready.split_host();

                let kick = VirtioKick {
                    rx_buf: Arc::clone(&rx_buf),
                    console_notify: console_notify.clone(),
                };
                let ring = AgentRingState::new(
                    endpoints.to_guest,
                    endpoints.from_guest,
                    Arc::clone(&agent_link),
                    kick,
                );
                agent_ring = Some(ring);

                AnyDevice::Console(ConsoleDevice::new(slot, vm, irq, backend, Box::new(port)))
            }
            DeviceStateSlot::Net(slot) => {
                let b = net_backend
                    .take()
                    .ok_or_else(|| missing_backend(DeviceKind::Net))?;
                let queue_pairs = {
                    let state = vm.device_slot_mut(slot);
                    checked_durable_net_queue_pairs(&state)?
                };
                let notify = Arc::new(Notify::new());
                let pending = Arc::new(AtomicBool::new(false));
                let wake_notify = Arc::clone(&notify);
                let wake_pending = Arc::clone(&pending);
                let net_waker = RxWaker::new(move || {
                    wake_pending.store(true, Ordering::Release);
                    wake_notify.notify_one();
                });
                b.set_rx_waker(Some(net_waker.clone()));
                registered_net_waker = Some(net_waker);
                net_rx_notify = Some(NetRxNotify {
                    wake: notify,
                    pending,
                });
                AnyDevice::Net(NetDevice::new(slot, vm, irq, b, queue_pairs))
            }
            DeviceStateSlot::Rng(slot) => AnyDevice::Rng(RngDevice::new(slot, vm, irq)),
            DeviceStateSlot::Fs(slot) => {
                let fb = fs_backend
                    .take()
                    .ok_or_else(|| missing_backend(DeviceKind::Fs))?;
                let request_queues = {
                    let state = vm.device_slot_mut(slot);
                    checked_durable_fs_request_queues(&state)?
                };
                AnyDevice::Fs(FsDevice::new(slot, vm, irq, fb, request_queues))
            }
            DeviceStateSlot::Pmem(slot) => AnyDevice::Pmem(PmemDevice::new(slot, vm, irq)),
        };

        debug_assert_eq!(slot.index(), idx);
        debug_assert_eq!(device.kind(), kind);
        devices.push(device);
    }

    // Log the device-state-as-loaded-from-memory for every slot. For a fresh
    // VM these are zero; for a spawned-from-zygote VM they reflect whatever
    // the parent's last run() left behind, which is the signal we want when
    // debugging regressions after freeze/spawn.
    for (&kind, &slot) in device_layout.kinds().iter().zip(device_layout.slots()) {
        log_device_initial_state(vm, slot, kind);
    }

    let ring = agent_ring.ok_or_else(|| {
        device_layout_error("device layout must include Console to create the agent ring")
    })?;
    Ok(DeviceOutput {
        devices,
        agent_ring: ring,
        agent_link,
        console_wake,
        net_rx_notify,
        rx_registrations: DeviceRxRegistrations {
            console_waker,
            net_waker: registered_net_waker,
        },
    })
}

fn missing_backend(kind: DeviceKind) -> crate::Error {
    device_layout_error(format!("{kind} device has no backend"))
}

fn missing_irq_line(idx: usize, kind: DeviceKind) -> crate::Error {
    device_layout_error(format!("device {idx} {kind} has no IRQ line"))
}

/// Log the transport + per-queue state for a device slot as it was loaded
/// from the shared VM-state mmap. Intended as a one-shot dump per spawn.
// Reason: lock guard intentionally spans the body so the operation
// observes a single consistent state snapshot.
#[allow(clippy::significant_drop_tightening)]
fn log_device_initial_state(vm: &VmState<'_>, slot: DeviceStateSlot, kind: DeviceKind) {
    // Each state struct has the same `transport: MmioTransportState` + `queues`
    // prefix because they share the `VirtioState` trait. We dispatch per kind
    // to get the right generic arg; the logic is the same afterwards.
    use amla_virtio::VirtioState;
    fn dump<S: VirtioState + amla_core::vm_state::DeviceState>(
        vm: &VmState<'_>,
        slot: DeviceSlot<S>,
        kind: DeviceKind,
    ) {
        let idx = slot.index();
        let mut state = vm.device_slot_mut(slot);
        let (transport, queues, _config) = state.split_mut();
        log::info!(
            "device_init[slot={idx} kind={kind:?}] status=0x{:x} features_sel={} driver_features=0x{:x} int_status=0x{:x} queue_sel={} cfg_gen={}",
            transport.status,
            transport.features_sel,
            transport.driver_features,
            transport.interrupt_status,
            transport.queue_sel,
            transport.config_generation,
        );
        for (qi, q) in queues.iter().enumerate() {
            if q.ready == 0 && q.size == 0 && q.last_avail_idx == 0 && q.last_used_idx == 0 {
                continue; // untouched queue — don't spam
            }
            log::info!(
                "device_init[slot={idx} kind={kind:?} q={qi}] ready={} size={} desc=0x{:x} avail=0x{:x} used=0x{:x} last_avail={} last_used={}",
                q.ready,
                q.size,
                q.desc_addr,
                q.avail_addr,
                q.used_addr,
                q.last_avail_idx,
                q.last_used_idx,
            );
        }
    }
    match slot {
        DeviceStateSlot::Console(slot) => dump(vm, slot, kind),
        DeviceStateSlot::Net(slot) => dump(vm, slot, kind),
        DeviceStateSlot::Rng(slot) => dump(vm, slot, kind),
        DeviceStateSlot::Fs(slot) => dump(vm, slot, kind),
        DeviceStateSlot::Pmem(slot) => dump(vm, slot, kind),
    }
}

/// Build the kernel cmdline fragment for virtio-mmio devices from the layout.
///
/// On ARM64, virtio-mmio devices are discovered via DTB nodes (not cmdline).
/// Using both causes EBUSY when the cmdline devices try to claim MMIO regions
/// already registered by the DTB-based driver.
#[allow(unused_variables)]
pub fn build_cmdline_fragment(
    config: &VmConfig,
    device_layout: &DeviceLayout,
) -> crate::Result<Vec<KernelCmdlineAtom>> {
    let mut parts = Vec::new();
    #[cfg(not(target_arch = "aarch64"))]
    {
        for (idx, _) in device_layout.kinds().iter().enumerate() {
            let gsi = amla_virtio_mmio::device_gsi(idx);
            let addr = device_mmio_addr(idx);
            parts.push(KernelCmdlineAtom::generated(format!(
                "virtio_mmio.device=0x{MMIO_DEVICE_SIZE:x}@0x{addr:x}:{gsi}"
            ))?);
        }
    }

    if let Some((i, _)) = config
        .pmem_disks
        .iter()
        .enumerate()
        .filter(|(_, d)| d.overlay_target.is_none())
        .find(|(_, d)| {
            d.images.iter().any(|img| {
                img.mount_path
                    .as_ref()
                    .is_some_and(crate::config::GuestPath::is_root)
            })
        })
    {
        parts.push(KernelCmdlineAtom::generated(format!("root=/dev/pmem{i}"))?);
        parts.push(KernelCmdlineAtom::generated("rootfstype=erofs")?);
        parts.push(KernelCmdlineAtom::generated("rootflags=dax=always")?);
    }
    if let Some(fs) = config
        .fs
        .as_ref()
        .filter(|f| f.mount_path.is_root() && !config.virtiofs_tag_consumed_by_overlay(&f.tag))
    {
        parts.push(KernelCmdlineAtom::generated("rootfstype=virtiofs")?);
        parts.push(KernelCmdlineAtom::generated(format!("root={}", fs.tag))?);
        parts.push(KernelCmdlineAtom::generated("rw")?);
    }
    Ok(parts)
}

/// Initialize durable per-device mmap state from the VM config.
///
/// This runs once for a newly-created VM. Per-run device objects are only
/// adapters over these bytes plus backend references; they must not recreate
/// guest-visible config during snapshot restore.
pub fn init_device_state(
    config: &VmConfig,
    layout: &DeviceLayout,
    vm: &mut VmState<'_>,
) -> Result<()> {
    write_device_meta(config, layout, vm)?;
    write_initial_device_configs(config, layout, vm)?;
    Ok(())
}

fn write_device_meta(config: &VmConfig, layout: &DeviceLayout, vm: &mut VmState<'_>) -> Result<()> {
    let mut pmem_iter = config.pmem_disks.iter();
    for (&kind, &slot) in layout.kinds().iter().zip(layout.slots()) {
        let Some(meta) = vm.device_meta_mut(slot.index()) else {
            continue;
        };
        *meta = DeviceMetaSlot::new(kind.state_code());
        match kind {
            DeviceKind::Fs => {
                if let Some(fs) = config.fs.as_ref() {
                    let tag = DeviceMetaTag::new(fs.tag.as_str()).map_err(device_meta_error)?;
                    let path = DeviceMetaMountPath::new(fs.mount_path.as_str())
                        .map_err(device_meta_error)?;
                    meta.set_tag(tag);
                    meta.set_mount_path(path);
                }
            }
            DeviceKind::Pmem => {
                if let Some(disk) = pmem_iter.next()
                    && disk.images.len() == 1
                    && disk.overlay_target.is_none()
                    && let Some(mount_path) = disk.images[0].mount_path.as_ref()
                {
                    let path =
                        DeviceMetaMountPath::new(mount_path.as_str()).map_err(device_meta_error)?;
                    meta.set_mount_path(path);
                }
            }
            DeviceKind::Console | DeviceKind::Net | DeviceKind::Rng => {}
        }
    }
    Ok(())
}

fn write_initial_device_configs(
    config: &VmConfig,
    layout: &DeviceLayout,
    vm: &VmState<'_>,
) -> Result<()> {
    {
        let mut state = vm.device_slot_mut(layout.console);
        state.config.max_nr_ports = 2u32.to_le();
    }

    if let Some((net_config, slot)) = config.net.as_ref().zip(layout.net) {
        let mut state = vm.device_slot_mut(slot);
        state.config.mac = net_config.guest_mac();
        state.config.max_virtqueue_pairs = net_config.queue_pairs.to_le();
        state.control.active_queue_pairs = 1;
    }

    if let Some((fs, slot)) = config.fs.as_ref().zip(layout.fs) {
        let mut state = vm.device_slot_mut(slot);
        let tag = fs.tag.as_str().as_bytes();
        state.config.tag[..tag.len()].copy_from_slice(tag);
        state.config.num_request_queues = fs.num_request_queues.as_u32().to_le();
    }

    for (disk_idx, slot) in layout.pmem.iter().copied().enumerate() {
        let (gpa, total) = vm.pmem_device_gpa(disk_idx).map_err(crate::Error::Core)?;
        let mut state = vm.device_slot_mut(slot);
        state.config.start = gpa.to_le();
        state.config.size = total.to_le();
    }

    Ok(())
}

/// Build mount operations in `device_layout` order.
pub fn build_mount_ops(
    config: &VmConfig,
    device_layout: &DeviceLayout,
) -> Result<Vec<amla_constants::protocol::MountOp>> {
    let mut mounts = Vec::new();
    let mut pmem_iter = config.pmem_disks.iter().enumerate();
    for &kind in device_layout.kinds() {
        match kind {
            DeviceKind::Pmem => {
                if let Some((pmem_idx, disk)) = pmem_iter.next() {
                    append_pmem_mount_ops(&mut mounts, pmem_idx, disk)?;
                }
            }
            DeviceKind::Fs => {
                if let Some(fs) = &config.fs
                    && !config.virtiofs_tag_consumed_by_overlay(&fs.tag)
                {
                    mounts.push(amla_constants::protocol::MountOp::VirtioFs {
                        tag: fs.tag.as_str().to_owned(),
                        mount_path: Some(fs.mount_path.as_str().to_owned()),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(mounts)
}

fn append_pmem_mount_ops(
    mounts: &mut Vec<amla_constants::protocol::MountOp>,
    pmem_idx: usize,
    disk: &PmemDiskConfig,
) -> Result<()> {
    let lower = build_pmem_lower_mounts(pmem_idx, disk)?;
    if let Some(target) = &disk.overlay_target {
        mounts.push(amla_constants::protocol::MountOp::Overlay {
            lower,
            upper: disk.overlay_upper_tag.as_ref().map(|tag| {
                Box::new(amla_constants::protocol::MountOp::VirtioFs {
                    tag: tag.as_str().to_owned(),
                    mount_path: None,
                })
            }),
            mount_path: target.as_str().to_owned(),
        });
    } else {
        mounts.extend(lower);
    }
    Ok(())
}

fn build_pmem_lower_mounts(
    pmem_idx: usize,
    disk: &PmemDiskConfig,
) -> Result<Vec<amla_constants::protocol::MountOp>> {
    if disk.images.len() == 1 {
        checked_pmem_image_size(pmem_idx, 0, disk.images[0].image_size)?;
        return Ok(vec![pmem_mount(
            amla_constants::protocol::MountOp::Pmem {
                device_index: pmem_device_index(pmem_idx)?,
            },
            disk.overlay_target.is_some(),
            &disk.images[0],
        )]);
    }

    let dev_idx = pmem_device_index(pmem_idx)?;
    let mut mounts = Vec::with_capacity(disk.images.len());
    let mut offset = 0u64;
    for (image_index, image) in disk.images.iter().enumerate() {
        let size = checked_pmem_image_size(pmem_idx, image_index, image.image_size)?;
        mounts.push(pmem_mount(
            amla_constants::protocol::MountOp::DmLinear {
                device_index: dev_idx,
                offset,
                size,
            },
            disk.overlay_target.is_some(),
            image,
        ));
        offset = offset.checked_add(size).ok_or_else(|| {
            crate::Error::Config(crate::ConfigError::PmemDiskSizeInvalid {
                disk_index: pmem_idx,
                size: offset,
                reason: format!("adding image {image_index} overflows u64"),
            })
        })?;
    }
    Ok(mounts)
}

fn pmem_mount(
    source: amla_constants::protocol::MountOp,
    is_overlay_lower: bool,
    image: &PmemImageConfig,
) -> amla_constants::protocol::MountOp {
    amla_constants::protocol::MountOp::Mount {
        source: Box::new(source),
        mount_path: if is_overlay_lower {
            None
        } else {
            image
                .mount_path
                .as_ref()
                .map(|path| path.as_str().to_owned())
        },
        fs_type: String::from("erofs"),
        options: String::from("dax=always"),
    }
}

fn pmem_device_index(pmem_idx: usize) -> Result<u32> {
    u32::try_from(pmem_idx).map_err(|_| {
        crate::Error::Config(crate::ConfigError::PmemDiskSizeInvalid {
            disk_index: pmem_idx,
            size: u64::MAX,
            reason: String::from("device index exceeds u32::MAX"),
        })
    })
}

fn checked_pmem_image_size(disk_index: usize, image_index: usize, image_size: u64) -> Result<u64> {
    if image_size == 0 {
        return Err(crate::Error::Config(
            crate::ConfigError::PmemImageSizeInvalid {
                disk_index,
                image_index,
                image_size,
                reason: String::from("must be greater than zero"),
            },
        ));
    }
    checked_host_page_align(image_size).ok_or_else(|| {
        crate::Error::Config(crate::ConfigError::PmemImageSizeInvalid {
            disk_index,
            image_index,
            image_size,
            reason: String::from("overflows host page alignment"),
        })
    })
}

fn checked_host_page_align(size: u64) -> Option<u64> {
    let page_size = u64::try_from(amla_mem::page_size()).ok()?;
    Some(size.checked_add(page_size - 1)? & !(page_size - 1))
}

/// Handle an MMIO read from a vCPU exit.
///
/// Resolves the address to a device and offset, then dispatches.
/// Reason an MMIO access could not be routed to a device.
///
/// For VMM-generated layouts every trap address is known by construction,
/// so any of these is a layout bug rather than a recoverable guest fault —
/// the vCPU loop surfaces it as [`VmOutcome::Fatal`] and stops the VM.
///
/// [`VmOutcome::Fatal`]: crate::shared_state::VmOutcome::Fatal
#[derive(Debug, thiserror::Error)]
pub enum MmioAccessError {
    #[error(
        "MMIO {op} at {addr:#x} (size {size}): address outside virtio-mmio region — VMM layout bug"
    )]
    OutOfRegion {
        op: &'static str,
        addr: u64,
        size: u8,
    },
    #[error(
        "MMIO {op} at {addr:#x} (size {size}): slot {slot} out of range (layout has {count} devices) — VMM layout bug"
    )]
    SlotOutOfRange {
        op: &'static str,
        addr: u64,
        size: u8,
        slot: usize,
        count: usize,
    },
}

pub fn mmio_read<F: FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    addr: u64,
    size: u8,
) -> std::result::Result<u64, MmioAccessError> {
    let (dev_idx, offset) = resolve_mmio_addr(addr).ok_or(MmioAccessError::OutOfRegion {
        op: "read",
        addr,
        size,
    })?;
    let device = devices
        .get(dev_idx)
        .ok_or(MmioAccessError::SlotOutOfRange {
            op: "read",
            addr,
            size,
            slot: dev_idx,
            count: devices.len(),
        })?;
    Ok(device.handle_read(offset, size))
}

/// Handle an MMIO write from a vCPU exit.
///
/// `QueueNotify` writes are intercepted and routed to the device waker
/// (which wakes the device loop), instead of processing the queue inline
/// on the vCPU thread. On KVM with ioeventfd, this path is never reached
/// for `QueueNotify` (kernel intercepts).
pub fn mmio_write<F: FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    waker: &dyn DeviceWaker,
    queue_wakes: &QueueWakeMap,
    addr: u64,
    data: u64,
    size: u8,
) -> std::result::Result<(), MmioAccessError> {
    let (dev_idx, offset) = resolve_mmio_addr(addr).ok_or(MmioAccessError::OutOfRegion {
        op: "write",
        addr,
        size,
    })?;
    let device = devices
        .get(dev_idx)
        .ok_or(MmioAccessError::SlotOutOfRange {
            op: "write",
            addr,
            size,
            slot: dev_idx,
            count: devices.len(),
        })?;
    if offset == QUEUE_NOTIFY {
        if size != 4 {
            log::debug!("ignoring non-32-bit QueueNotify write for slot {dev_idx}: size={size}");
            return Ok(());
        }
        let Ok(queue_idx) = u32::try_from(data) else {
            log::debug!("ignoring QueueNotify value wider than 32 bits for slot {dev_idx}: {data}");
            return Ok(());
        };
        let Ok(queue_idx) = usize::try_from(queue_idx) else {
            return Ok(());
        };
        let Some(wake) = queue_wakes.device_queue_wake(dev_idx, queue_idx) else {
            log::debug!("ignoring QueueNotify for slot {dev_idx}, out-of-range queue {queue_idx}");
            return Ok(());
        };
        log::trace!(
            "QueueNotify for slot {dev_idx}, queue {queue_idx}, wake {}",
            wake.wake
        );
        waker.kick(wake.wake);
    } else {
        device.handle_write(offset, size, data);
    }
    Ok(())
}

/// Fire all device bits once via the waker.
///
/// Called after the device loop starts to ensure any pending virtqueue
/// descriptors (from a snapshot or stale eventfds) are processed.
/// Harmless on first boot — the drain loop returns immediately.
pub fn force_kick_all<F: FsBackend, N: NetBackend>(
    devices: &[AnyDevice<'_, F, N>],
    queue_wakes: &QueueWakeMap,
    waker: &dyn DeviceWaker,
) {
    let _ = devices;
    let mut first_wake = None;
    for wake in queue_wakes.iter() {
        first_wake.get_or_insert(wake.wake);
        waker.set_bit(wake.wake);
    }
    // One kick to wake the device loop task.
    if let Some(wake) = first_wake {
        waker.kick(wake);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a complete device layout for testing (includes all required devices).
    fn test_layout(extra: &[DeviceKind]) -> DeviceLayout {
        let mut kinds = vec![DeviceKind::Console, DeviceKind::Rng];
        kinds.extend_from_slice(extra);
        DeviceLayout::new(kinds)
    }

    fn queue_count_values(layout: &DeviceLayout) -> Vec<usize> {
        layout
            .queue_counts()
            .iter()
            .copied()
            .map(DeviceQueueCount::as_usize)
            .collect()
    }

    #[test]
    fn device_layout_fixed_indices() {
        let layout = test_layout(&[]);
        assert_eq!(layout.console.index(), 0);
        assert!(layout.net.is_none());
        assert!(layout.fs.is_none());
        assert!(layout.pmem.is_empty());
        assert_eq!(layout.len(), 2);
    }

    #[test]
    fn device_layout_with_net_and_pmem() {
        let layout = test_layout(&[DeviceKind::Net, DeviceKind::Pmem, DeviceKind::Pmem]);
        assert_eq!(layout.net.map(DeviceSlot::index), Some(2));
        assert_eq!(
            layout
                .pmem
                .iter()
                .copied()
                .map(DeviceSlot::index)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn device_layout_kinds_roundtrip() {
        let kinds = vec![
            DeviceKind::Console,
            DeviceKind::Rng,
            DeviceKind::Net,
            DeviceKind::Fs,
            DeviceKind::Pmem,
        ];
        let layout = DeviceLayout::new(kinds.clone());
        assert_eq!(layout.kinds(), &kinds);
        assert_eq!(layout.net.map(DeviceSlot::index), Some(2));
        assert_eq!(layout.fs.map(DeviceSlot::index), Some(3));
        assert_eq!(
            layout
                .pmem
                .iter()
                .copied()
                .map(DeviceSlot::index)
                .collect::<Vec<_>>(),
            vec![4]
        );
    }

    #[test]
    fn queue_wake_map_rejects_layouts_that_do_not_fit_bitset() {
        let mut kinds = vec![
            DeviceKind::Console,
            DeviceKind::Rng,
            DeviceKind::Net,
            DeviceKind::Fs,
        ];
        kinds.extend(std::iter::repeat_n(DeviceKind::Pmem, 60));
        let layout = DeviceLayout::new(kinds);

        assert!(matches!(
            QueueWakeMap::new(&layout),
            Err(crate::Error::Config(crate::ConfigError::TooManyQueueWakes {
                count,
                max: MAX_QUEUE_WAKE_BITS,
            })) if count == MAX_QUEUE_WAKE_BITS + 1
        ));
    }

    #[test]
    fn queue_wake_map_uses_exact_config_queue_counts() {
        let config = VmConfig::default()
            .net(crate::config::NetConfig::default().queue_pairs(1).unwrap())
            .fs(crate::config::FsConfig::try_new("hostfs", "/mnt")
                .unwrap()
                .with_request_queues(1)
                .unwrap());
        let layout = DeviceLayout::from_config(&config).unwrap();
        let queue_wakes = QueueWakeMap::new(&layout).unwrap();

        assert_eq!(queue_count_values(&layout), [6, 1, 2, 2]);
        assert_eq!(
            queue_wakes.device_queue_count(layout.net.unwrap().index()),
            2
        );
        assert_eq!(
            queue_wakes.device_queue_count(layout.fs.unwrap().index()),
            2
        );
        assert!(
            queue_wakes
                .device_queue_wake(layout.net.unwrap().index(), 2)
                .is_none()
        );
        assert!(
            queue_wakes
                .device_queue_wake(layout.fs.unwrap().index(), 2)
                .is_none()
        );
    }

    #[test]
    fn device_layout_roundtrips_through_durable_header() {
        let kinds = vec![
            DeviceKind::Console,
            DeviceKind::Rng,
            DeviceKind::Net,
            DeviceKind::Fs,
            DeviceKind::Pmem,
        ];
        let layout = DeviceLayout::new(kinds.clone());
        let mut header = amla_core::vm_state::VmStateHeader::compute(
            1,
            layout.len() as u32,
            amla_core::vm_state::BITMAP_BLOCK_SIZE,
            &[0x4000],
            &[1],
        )
        .unwrap();
        layout.write_header(&mut header);

        let from_header = DeviceLayout::from_header(&header).unwrap();
        assert_eq!(from_header.kinds(), &kinds);
        assert_eq!(from_header.queue_counts(), layout.queue_counts());
        assert_eq!(from_header.net.map(DeviceSlot::index), Some(2));
        assert_eq!(from_header.fs.map(DeviceSlot::index), Some(3));
        assert_eq!(
            from_header
                .pmem
                .iter()
                .copied()
                .map(DeviceSlot::index)
                .collect::<Vec<_>>(),
            vec![4]
        );
    }

    #[test]
    fn device_layout_from_header_rejects_invalid_kind_table() {
        let mut header = amla_core::vm_state::VmStateHeader::compute(
            1,
            2,
            amla_core::vm_state::BITMAP_BLOCK_SIZE,
            &[],
            &[],
        )
        .unwrap();
        header.device_kinds[0] = DeviceKind::Console.state_code();
        header.device_kinds[1] = 99;

        let err = DeviceLayout::from_header(&header).unwrap_err();
        assert!(err.to_string().contains("unknown code 99"), "{err}");
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn init_device_state_writes_durable_header_meta_and_config() {
        let config = VmConfig::default()
            .net(
                crate::config::NetConfig::default()
                    .mac([1, 2, 3, 4, 5, 6])
                    .queue_pairs(3)
                    .unwrap(),
            )
            .fs(crate::config::FsConfig::try_new("hostfs", "/mnt")
                .unwrap()
                .with_request_queues(2)
                .unwrap())
            .try_pmem_disk(0x4000, "/data")
            .unwrap();
        let layout = DeviceLayout::from_config(&config).unwrap();
        let data_sizes = [0x4000];
        let image_counts = [1];
        let mut header = amla_core::vm_state::VmStateHeader::compute(
            config.vcpu_count,
            layout.len() as u32,
            amla_core::vm_state::BITMAP_BLOCK_SIZE,
            &data_sizes,
            &image_counts,
        )
        .unwrap();
        layout.write_header(&mut header);
        assert_eq!(
            &header.device_kinds[..layout.len()],
            &[
                DeviceKind::Console.state_code(),
                DeviceKind::Rng.state_code(),
                DeviceKind::Net.state_code(),
                DeviceKind::Fs.state_code(),
                DeviceKind::Pmem.state_code(),
            ]
        );
        assert_eq!(
            &header.device_queue_counts[..layout.len()],
            &[6, 1, 7, 3, 1]
        );

        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        amla_core::vm_state::VmState::init_region(&mut mmap, header).unwrap();
        let mapped =
            amla_core::vm_state::MappedVmState::new(mmap, amla_core::GUEST_PHYS_ADDR).unwrap();
        let mut vm = mapped.view().unwrap();
        init_device_state(&config, &layout, &mut vm).unwrap();

        {
            let state = vm.device_slot_mut(layout.console);
            assert_eq!(u32::from_le(state.config.max_nr_ports), 2);
        }
        {
            let state = vm.device_slot_mut(layout.net.unwrap());
            assert_eq!(state.config.mac, [1, 2, 3, 4, 5, 6]);
            assert_eq!(u16::from_le(state.config.max_virtqueue_pairs), 3);
        }
        {
            let state = vm.device_slot_mut(layout.fs.unwrap());
            assert_eq!(&state.config.tag[..6], b"hostfs");
            assert_eq!(u32::from_le(state.config.num_request_queues), 2);
        }
        {
            let (gpa, total) = vm.pmem_device_gpa(0).unwrap();
            let state = vm.device_slot_mut(layout.pmem[0]);
            assert_eq!(u64::from_le(state.config.start), gpa);
            assert_eq!(u64::from_le(state.config.size), total);
        }

        let fs_meta = vm.device_meta(layout.fs.unwrap().index()).unwrap();
        assert_eq!(fs_meta.kind(), DeviceKind::Fs.state_code());
        assert_eq!(fs_meta.tag_str().unwrap(), "hostfs");
        assert_eq!(fs_meta.mount_path_str().unwrap(), "/mnt");

        let pmem_meta = vm.device_meta(layout.pmem[0].index()).unwrap();
        assert_eq!(pmem_meta.kind(), DeviceKind::Pmem.state_code());
        assert_eq!(pmem_meta.mount_path_str().unwrap(), "/data");
    }

    #[test]
    fn device_layout_from_vm_state_rejects_header_config_queue_mismatch() {
        let config =
            VmConfig::default().net(crate::config::NetConfig::default().queue_pairs(3).unwrap());
        let layout = DeviceLayout::from_config(&config).unwrap();
        let mut header = amla_core::vm_state::VmStateHeader::compute(
            config.vcpu_count,
            layout.len() as u32,
            amla_core::vm_state::BITMAP_BLOCK_SIZE,
            &[],
            &[],
        )
        .unwrap();
        layout.write_header(&mut header);
        header.device_queue_counts[layout.net.unwrap().index()] =
            u16::try_from(amla_virtio_net::queue_count_for_pairs(1)).unwrap();

        let mut mmap = amla_mem::MmapSlice::anonymous_rw(header.total_size() as usize).unwrap();
        amla_core::vm_state::VmState::init_region(&mut mmap, header).unwrap();
        let mapped =
            amla_core::vm_state::MappedVmState::new(mmap, amla_core::GUEST_PHYS_ADDR).unwrap();
        let mut vm = mapped.view().unwrap();
        init_device_state(&config, &layout, &mut vm).unwrap();

        let err = DeviceLayout::from_vm_state(&vm).unwrap_err();
        assert!(err.to_string().contains("net durable config"), "{err}");
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn virtio_kick_coalesces_pending_doorbell_byte() {
        let rx_buf = Arc::new(parking_lot::Mutex::new(VecDeque::new()));
        let link = AgentLink::new();
        let kick = VirtioKick {
            rx_buf: Arc::clone(&rx_buf),
            console_notify: link.host_notifier(),
        };

        kick.kick();
        kick.kick();

        {
            let rx = rx_buf.lock();
            assert_eq!(rx.len(), 1);
            assert_eq!(rx.front().copied(), Some(AGENT_TAG_KICK));
        }
        assert!(link.host_pending().load(Ordering::Acquire));

        assert_eq!(rx_buf.lock().pop_front(), Some(AGENT_TAG_KICK));
        kick.kick();
        assert_eq!(rx_buf.lock().len(), 1);
    }

    // ── build_mount_ops tests ─────────────────────────────────────��────

    use crate::config::{FsConfig, GuestPath, PmemImageConfig, VirtioFsTag};
    use amla_constants::protocol::MountOp;

    // Single pmem image without overlay: bare Mount with explicit mount_path.
    #[test]
    fn mount_ops_single_pmem_no_overlay() {
        let config = VmConfig::default().pmem_disk(4096, GuestPath::new("/data").unwrap());
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(
            matches!(&ops[0], MountOp::Mount { source, mount_path: Some(p), fs_type, .. }
                if matches!(source.as_ref(), MountOp::Pmem { device_index: 0 })
                && p == "/data"
                && fs_type == "erofs"
            ),
            "expected Mount(Pmem(0)) at /data, got: {:?}",
            ops[0]
        );
    }

    #[test]
    fn mount_ops_rejects_zero_pmem_image_size() {
        let config = VmConfig::default().pmem_disk(0, GuestPath::new("/data").unwrap());
        let layout = DeviceLayout::from_config(&config).unwrap();
        let err = build_mount_ops(&config, &layout).unwrap_err().to_string();
        assert!(err.contains("image_size=0"), "{err}");
        assert!(err.contains("greater than zero"), "{err}");
    }

    // Rootfs pmem (mount_path "/") produces a Mount at "/".
    #[test]
    fn mount_ops_pmem_root() {
        let config = VmConfig::default().pmem_root(4096);
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(matches!(
            &ops[0],
            MountOp::Mount {
                mount_path: Some(p),
                ..
            } if p == "/"
        ));
    }

    // Single pmem image with overlay_target: Overlay wrapping one Mount.
    #[test]
    fn mount_ops_single_pmem_overlay() {
        let config = VmConfig::default().pmem_overlay(
            vec![PmemImageConfig::overlay(4096)],
            GuestPath::new("/mnt").unwrap(),
        );
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            MountOp::Overlay {
                lower,
                upper,
                mount_path,
            } => {
                assert_eq!(mount_path, "/mnt");
                assert!(upper.is_none(), "single-image overlay uses tmpfs upper");
                assert_eq!(lower.len(), 1);
                // Inner mount has no mount_path (agent picks temp dir).
                assert!(matches!(
                    &lower[0],
                    MountOp::Mount {
                        mount_path: None,
                        source,
                        ..
                    } if matches!(source.as_ref(), MountOp::Pmem { device_index: 0 })
                ));
            }
            other => panic!("expected Overlay, got: {other:?}"),
        }
    }

    // Multi-image pmem with overlay_target: Overlay with DmLinear sources.
    #[test]
    fn mount_ops_multi_image_pmem_overlay() {
        let config = VmConfig::default().pmem_overlay(
            vec![
                PmemImageConfig::overlay(4096),
                PmemImageConfig::overlay(8192),
            ],
            GuestPath::new("/mnt").unwrap(),
        );
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 1);
        match &ops[0] {
            MountOp::Overlay {
                lower,
                upper,
                mount_path,
            } => {
                assert_eq!(mount_path, "/mnt");
                assert!(upper.is_none());
                assert_eq!(lower.len(), 2, "two layers");
                // Both inner mounts should use DmLinear with no mount_path.
                for m in lower {
                    assert!(
                        matches!(m, MountOp::Mount { mount_path: None, source, .. }
                            if matches!(source.as_ref(), MountOp::DmLinear { device_index: 0, .. })
                        ),
                        "inner mount should be DmLinear with no mount_path: {m:?}"
                    );
                }
                // Second layer has non-zero offset.
                if let MountOp::Mount { source, .. } = &lower[1]
                    && let MountOp::DmLinear { offset, .. } = source.as_ref()
                {
                    assert!(*offset > 0, "second layer should have offset > 0");
                }
            }
            other => panic!("expected Overlay, got: {other:?}"),
        }
    }

    // Multi-image pmem WITHOUT overlay: individual Mounts with DmLinear.
    #[test]
    fn mount_ops_multi_image_pmem_no_overlay() {
        let config = VmConfig::default().pmem_packed(vec![
            PmemImageConfig::new(4096, GuestPath::new("/layer0").unwrap()),
            PmemImageConfig::new(8192, GuestPath::new("/layer1").unwrap()),
        ]);
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 2, "each image gets its own Mount");
        assert!(matches!(
            &ops[0],
            MountOp::Mount {
                mount_path: Some(p),
                ..
            } if p == "/layer0"
        ));
        assert!(matches!(
            &ops[1],
            MountOp::Mount {
                mount_path: Some(p),
                ..
            } if p == "/layer1"
        ));
    }

    // Virtiofs without workspace path: bare VirtioFs at mount_path.
    #[test]
    fn mount_ops_virtiofs_bare() {
        let config = VmConfig::default().fs(FsConfig::new(
            VirtioFsTag::new("myfs").unwrap(),
            GuestPath::new("/shared").unwrap(),
        ));
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert_eq!(ops.len(), 1);
        assert!(
            matches!(&ops[0], MountOp::VirtioFs { tag, mount_path: Some(p) }
                if tag == "myfs" && p == "/shared"
            ),
            "got: {:?}",
            ops[0]
        );
    }

    // Virtiofs consumed as overlay upper: no separate mount op emitted.
    #[test]
    fn mount_ops_virtiofs_consumed_by_overlay() {
        let config = VmConfig::default()
            .fs(FsConfig::new(
                VirtioFsTag::new("upper").unwrap(),
                GuestPath::new("/unused").unwrap(),
            ))
            .pmem_overlay_with_upper(
                vec![PmemImageConfig::overlay(100_000)],
                GuestPath::new("/mnt").unwrap(),
                VirtioFsTag::new("upper").unwrap(),
            );
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        // Only 1 op: the pmem overlay (no separate virtiofs mount).
        assert_eq!(ops.len(), 1, "ops: {ops:#?}");
        match &ops[0] {
            MountOp::Overlay {
                upper, mount_path, ..
            } => {
                assert_eq!(mount_path, "/mnt");
                let upper = upper.as_ref().expect("should have virtiofs upper");
                assert!(
                    matches!(upper.as_ref(), MountOp::VirtioFs { tag, mount_path: None }
                        if tag == "upper"
                    ),
                    "upper should be VirtioFs: {upper:?}"
                );
            }
            other => panic!("expected Overlay, got: {other:?}"),
        }
    }

    #[test]
    fn cmdline_ignores_virtiofs_root_consumed_by_overlay() {
        let config = VmConfig::default()
            .fs(FsConfig::root(VirtioFsTag::new("upper").unwrap()))
            .pmem_overlay_with_upper(
                vec![PmemImageConfig::overlay(100_000)],
                GuestPath::new("/mnt").unwrap(),
                VirtioFsTag::new("upper").unwrap(),
            );
        let layout = DeviceLayout::from_config(&config).unwrap();
        let atoms = build_cmdline_fragment(&config, &layout).unwrap();
        let atoms: Vec<&str> = atoms
            .iter()
            .map(crate::config::KernelCmdlineAtom::as_str)
            .collect();

        assert!(!atoms.contains(&"root=upper"), "{atoms:?}");
        assert!(!atoms.contains(&"rootfstype=virtiofs"), "{atoms:?}");
    }

    // Production-like config: rootfs pmem + container overlay with virtiofs upper.
    #[test]
    fn mount_ops_production_topology() {
        let config = VmConfig::default()
            .pmem_root(65536)
            .pmem_overlay_with_upper(
                vec![
                    PmemImageConfig::overlay(100_000),
                    PmemImageConfig::overlay(50_000),
                ],
                GuestPath::new("/mnt").unwrap(),
                VirtioFsTag::new("upper").unwrap(),
            )
            .fs(FsConfig::new(
                VirtioFsTag::new("upper").unwrap(),
                GuestPath::new("/unused").unwrap(),
            ));
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();

        // 2 ops: rootfs mount + container overlay (virtiofs consumed by overlay).
        assert_eq!(ops.len(), 2, "ops: {ops:#?}");

        // Op 0: rootfs pmem at "/"
        assert!(
            matches!(
                &ops[0],
                MountOp::Mount {
                    mount_path: Some(p),
                    ..
                } if p == "/"
            ),
            "op[0] should be rootfs Mount at /, got: {:#?}",
            ops[0]
        );
        // Op 1: container overlay at "/mnt" with virtiofs upper
        match &ops[1] {
            MountOp::Overlay {
                mount_path,
                lower,
                upper,
            } => {
                assert_eq!(mount_path, "/mnt");
                assert_eq!(lower.len(), 2);
                let upper = upper.as_ref().expect("should have virtiofs upper");
                assert!(
                    matches!(upper.as_ref(), MountOp::VirtioFs { tag, .. } if tag == "upper"),
                    "upper should be virtiofs 'upper': {upper:?}"
                );
            }
            other => panic!("expected Overlay, got: {other:?}"),
        }
    }

    // No pmem or fs: empty mount ops.
    #[test]
    fn mount_ops_empty_config() {
        let config = VmConfig::default();
        let layout = DeviceLayout::from_config(&config).unwrap();
        let ops = build_mount_ops(&config, &layout).unwrap();
        assert!(ops.is_empty());
    }
}
