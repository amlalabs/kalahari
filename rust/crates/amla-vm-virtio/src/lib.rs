// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Zero-copy virtio queue API and device trait.
//!
//! This crate provides the core virtio abstractions:
//! - [`VirtioDevice`] trait — processors whose guest-visible state is provided by the caller
//! - [`QueueView`] — zero-copy queue access over guest memory
//! - [`DescriptorChain`] / typed descriptor chains — safe guest memory I/O via raw pointers
//! - [`MmioTransportState`] / [`QueueState`] — `#[repr(C)]` Pod state in mmap bytes
//!
//! Devices never touch guest memory directly. All concurrency (barriers, raw pointers,
//! ring index arithmetic) is encapsulated in [`QueueView`].
//!
//! # State Compatibility
//!
//! The mmap-backed `#[repr(C)]`/`Pod` state structs are same-version internal
//! state. Helpers in this crate cast bytes directly into the current structs,
//! so readers and writers must be built from the same source version. These
//! layouts are not durable cross-version snapshot or migration ABIs unless a
//! caller wraps them in an explicit rejecting/migrating envelope.

#![allow(unexpected_cfgs)] // `cfg(kani)` is set by the Kani verifier
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

mod descriptor;
mod queue;
mod queue_runner;
#[cfg(test)]
mod tests;

pub use descriptor::{
    DescriptorChain, DescriptorRef, ReadCap, ReadableDescriptor, WritableDescriptor,
};
pub use queue::{
    CompletableDescriptorChain, CompletedDescriptorChain, DEFERRED_WRITABLE_REGION_RESERVED_BYTES,
    PoppedDescriptorChain, QueueView, QueueViolation, ReadableDescriptorChain, ReadyQueue,
    SplitDescriptorChain, WritableDescriptorChain, WrittenBytes, validate_queue_layout,
};
pub use queue_runner::{
    DeferredDescriptorCompletion, QueuePopContext, QueueRunOutcome, QueueRunner,
    notify_config_change, queue_work_enabled, signal_device_needs_reset,
};

use amla_core::vm_state::{
    DEVICE_KIND_CONSOLE, DEVICE_KIND_FS, DEVICE_KIND_NET, DEVICE_KIND_PMEM, DEVICE_KIND_RNG,
    DeviceState,
};
use bytemuck::{Pod, Zeroable};

// =============================================================================
// Virtio Feature Bits (virtio spec 6)
// =============================================================================

/// `VIRTIO_F_RING_INDIRECT_DESC` — driver can use indirect descriptors.
pub const VIRTIO_F_INDIRECT_DESC: u64 = 1 << 28;

/// `VIRTIO_F_RING_EVENT_IDX` — enables `used_event` / `avail_event` notification suppression.
pub const VIRTIO_F_EVENT_IDX: u64 = 1 << 29;

/// `VIRTIO_F_VERSION_1` — modern virtio device (required by mmio v2).
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// `VIRTIO_F_ACCESS_PLATFORM` — device accesses memory via IOMMU.
pub const VIRTIO_F_ACCESS_PLATFORM: u64 = 1 << 33;

/// `VIRTIO_CONSOLE_F_MULTIPORT` — console supports multiple ports.
pub const VIRTIO_CONSOLE_F_MULTIPORT: u64 = 1 << 1;

// =============================================================================
// Virtio Device Status Bits (virtio spec 2.1)
// =============================================================================

/// Guest OS has found the device and recognized it.
pub const STATUS_ACKNOWLEDGE: u32 = 1;

/// Guest OS knows how to drive the device.
pub const STATUS_DRIVER: u32 = 2;

/// Driver has acknowledged all features it understands.
pub const STATUS_FEATURES_OK: u32 = 8;

/// Driver is set up and ready to drive the device.
pub const STATUS_DRIVER_OK: u32 = 4;

/// Device has experienced an unrecoverable error from a driver protocol
/// violation; driver must reset (write `STATUS=0`) to recover.
pub const STATUS_DEVICE_NEEDS_RESET: u32 = 64;

/// Something went wrong in the guest.
pub const STATUS_FAILED: u32 = 128;

// =============================================================================
// Virtio Interrupt Bits
// =============================================================================

/// Used buffer notification (virtio spec 4.2.3.2).
pub const INT_VRING: u32 = 1;

/// Configuration change notification.
pub const INT_CONFIG: u32 = 2;

// =============================================================================
// Descriptor Flags
// =============================================================================

/// This marks a buffer as continuing via the next field.
pub const VIRTQ_DESC_F_NEXT: u16 = 1;

/// This marks a buffer as device write-only (otherwise device read-only).
pub const VIRTQ_DESC_F_WRITE: u16 = 2;

/// This means the buffer contains a list of buffer descriptors.
pub const VIRTQ_DESC_F_INDIRECT: u16 = 4;

/// Flag in avail ring: don't interrupt me.
pub const VRING_AVAIL_F_NO_INTERRUPT: u16 = 1;

/// Flag in used ring: don't kick me.
pub const VRING_USED_F_NO_NOTIFY: u16 = 1;

// =============================================================================
// Virtio Device Type IDs (virtio spec 5)
// =============================================================================

pub const DEVICE_ID_NET: u32 = 1;
pub const DEVICE_ID_CONSOLE: u32 = 3;
pub const DEVICE_ID_RNG: u32 = 4;
pub const DEVICE_ID_FS: u32 = 26;
pub const DEVICE_ID_PMEM: u32 = 27;
pub const DEVICE_ID_MEM: u32 = 24;

// =============================================================================
// Vendor ID
// =============================================================================

/// Amla vendor ID for virtio-mmio.
pub const VENDOR_ID: u32 = 0x414D_4C41; // "AMLA" in ASCII

// =============================================================================
// Virtio-mem feature bits (virtio spec 5.15.3)
// =============================================================================

/// `VIRTIO_MEM_F_ACPI_PXM` — device has an ACPI proximity domain.
/// We don't use this (`CONFIG_ACPI=n`), but define it for completeness.
pub const VIRTIO_MEM_F_ACPI_PXM: u64 = 1 << 0;

/// `VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE` — unplugged memory must not be
/// accessed by the guest. Linux >= 5.16 negotiates this.
pub const VIRTIO_MEM_F_UNPLUGGED_INACCESSIBLE: u64 = 1 << 1;

// =============================================================================
// Virtio-net feature bits (virtio spec 5.1.3)
// =============================================================================

/// `VIRTIO_NET_F_MAC` — device has given MAC address.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;
/// `VIRTIO_NET_F_CTRL_VQ` — control channel is available.
pub const VIRTIO_NET_F_CTRL_VQ: u64 = 1 << 17;
/// `VIRTIO_NET_F_MQ` — device supports multiqueue with automatic receive steering.
pub const VIRTIO_NET_F_MQ: u64 = 1 << 22;

// =============================================================================
// Transport State (lives in mmap state bytes, survives snapshot)
// =============================================================================

/// MMIO transport register state — one per device, in the state bytes.
///
/// 40 bytes, 8-byte aligned. All fields are little-endian on the host.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct MmioTransportState {
    /// Device status register (ACKNOWLEDGE | DRIVER | `FEATURES_OK` | `DRIVER_OK` | FAILED).
    pub status: u32,
    /// Explicit padding for u64 alignment.
    pub pad0: u32,
    /// Features the guest driver selected.
    pub driver_features: u64,
    /// Pending interrupts (bit 0 = used buffer, bit 1 = config change).
    pub interrupt_status: u32,
    /// Config generation counter (incremented on config change).
    pub config_generation: u32,
    /// Currently selected queue index (for MMIO register access).
    pub queue_sel: u32,
    /// Which 32-bit feature page guest is reading.
    pub features_sel: u32,
    /// Which 32-bit feature page guest is writing to `driver_features`.
    pub driver_features_sel: u32,
    /// Shared memory region selector (for virtio-fs DAX).
    pub shm_sel: u32,
}

const _: () = assert!(size_of::<MmioTransportState>() == 40);

// =============================================================================
// Per-Queue State (lives in mmap state bytes, survives snapshot)
// =============================================================================

/// Per-virtqueue state — addresses, cursors, and async completion identity.
///
/// 40 bytes, 8-byte aligned. Descriptor table, available ring, and used ring
/// addresses are guest physical addresses set by the driver during queue setup.
///
/// Field order is intentionally packed, not protocol-visible: this state lives
/// in the VMM mmap, not guest memory. Keeping `generation` as `u64` uses the
/// bytes that would otherwise be padding, so stale-completion protection costs
/// no extra space per queue.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct QueueState {
    /// GPA of descriptor table.
    pub desc_addr: u64,
    /// GPA of available ring.
    pub avail_addr: u64,
    /// GPA of used ring.
    pub used_addr: u64,
    /// Logical queue instance id for delayed completions.
    ///
    /// This is needed for async virtio-fs: a backend future can finish after
    /// the guest reset/reconfigured the same queue slot. Queue index, ready
    /// bit, descriptor head, and even ring addresses are not enough because
    /// the driver may reuse all of them for a new queue instance. Tokens
    /// captured while popping descriptors compare this value before writing
    /// guest response bytes or publishing used-ring entries.
    pub generation: u64,
    /// VMM's cursor into the available ring (next index to consume).
    pub last_avail_idx: u16,
    /// VMM's cursor into the used ring (next index to produce).
    pub last_used_idx: u16,
    /// Negotiated queue size (number of entries, must be power of 2).
    pub size: u16,
    /// 1 if queue is ready/enabled, 0 otherwise.
    pub ready: u8,
    pub pad0: u8,
}

const _: () = assert!(size_of::<QueueState>() == 40);
const _: () = {
    assert!(std::mem::offset_of!(QueueState, desc_addr) == 0);
    assert!(std::mem::offset_of!(QueueState, avail_addr) == 8);
    assert!(std::mem::offset_of!(QueueState, used_addr) == 16);
    assert!(std::mem::offset_of!(QueueState, generation) == 24);
    assert!(std::mem::offset_of!(QueueState, last_avail_idx) == 32);
    assert!(std::mem::offset_of!(QueueState, last_used_idx) == 34);
    assert!(std::mem::offset_of!(QueueState, size) == 36);
    assert!(std::mem::offset_of!(QueueState, ready) == 38);
};

// =============================================================================
// Device-Specific Config Structs
// =============================================================================

/// Console device config (12 bytes).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct ConsoleConfig {
    pub cols: u16,
    pub rows: u16,
    pub max_nr_ports: u32,
    pub emerg_wr: u32,
}

const _: () = assert!(size_of::<ConsoleConfig>() == 12);

/// Net device config (20 bytes).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct NetConfig {
    pub mac: [u8; 6],
    pub status: u16,
    pub max_virtqueue_pairs: u16,
    pub mtu: u16,
    pub speed: u32,
    pub duplex: u8,
    pub pad: [u8; 3],
}

const _: () = assert!(size_of::<NetConfig>() == 20);

/// Net device host-only control state (12 bytes).
///
/// This is not part of the guest-visible virtio-net config space. It lives in
/// the mmap-backed device slot so runtime control-queue decisions survive the
/// VMM's short-lived `Net` device wrappers.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct NetControlState {
    /// Active RX/TX queue pairs selected by `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`.
    ///
    /// A zero value is treated as the virtio reset default of one queue pair.
    pub active_queue_pairs: u16,
    /// Reserved bytes in the fixed 512-byte device slot.
    pub pad: [u8; 10],
}

const _: () = assert!(size_of::<NetControlState>() == 12);

/// Pmem device config (16 bytes).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct PmemConfig {
    pub start: u64,
    pub size: u64,
}

const _: () = assert!(size_of::<PmemConfig>() == 16);

/// Mem (virtio-mem) device config (56 bytes).
///
/// Virtio spec 5.15.4: device configuration layout.
/// Fields are little-endian. `requested_size` is host-writable;
/// `plugged_size` is guest-writable. The rest are read-only after init.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct MemDeviceConfig {
    /// Size of each pluggable block in bytes (must be power of 2, >= page size).
    pub block_size: u64,
    /// NUMA node ID (0 for single-node setups).
    pub node_id: u16,
    /// Padding for alignment.
    pub pad0: [u8; 6],
    /// GPA of the start of the usable region.
    pub addr: u64,
    /// Total usable region size in bytes (address space ceiling).
    pub region_size: u64,
    /// Host-requested size of plugged memory in bytes.
    /// Host writes this to request plug/unplug.
    pub usable_region_size: u64,
    /// Guest-reported size of actually plugged memory in bytes.
    pub plugged_size: u64,
    /// Host-requested target plugged size in bytes.
    pub requested_size: u64,
}

const _: () = assert!(size_of::<MemDeviceConfig>() == 56);

/// Filesystem device config (40 bytes).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct FsConfig {
    pub tag: [u8; 36],
    pub num_request_queues: u32,
}

const _: () = assert!(size_of::<FsConfig>() == 40);

// =============================================================================
// Complete Per-Device State Layouts (flat structs, one per device type)
// =============================================================================

/// Device slot size in bytes. Each device gets a fixed 512-byte slot.
pub const DEVICE_SLOT_SIZE: usize = 512;

/// Number of distinct host-to-guest console control states persisted here.
///
/// The current console exposes two ports. MULTIPORT negotiation has five
/// idempotent host responses: `PORT_ADD(0)`, `PORT_ADD(1)`, `CONSOLE_PORT(0)`,
/// `PORT_OPEN(0)`, and `PORT_OPEN(1)`.
pub const CONSOLE_PENDING_CTRL_CAPACITY: usize = 5;

const CONSOLE_CTRL_PORT_ADD: u16 = 1;
const CONSOLE_CTRL_CONSOLE_PORT: u16 = 4;
const CONSOLE_CTRL_PORT_OPEN: u16 = 6;

#[derive(Clone, Copy)]
struct ConsoleCtrlSlot {
    bit: u8,
    event: u16,
    id: u32,
    value: u16,
}

const CONSOLE_CTRL_SLOTS: [ConsoleCtrlSlot; CONSOLE_PENDING_CTRL_CAPACITY] = [
    ConsoleCtrlSlot {
        bit: 1 << 0,
        event: CONSOLE_CTRL_PORT_ADD,
        id: 0,
        value: 1,
    },
    ConsoleCtrlSlot {
        bit: 1 << 1,
        event: CONSOLE_CTRL_PORT_ADD,
        id: 1,
        value: 1,
    },
    ConsoleCtrlSlot {
        bit: 1 << 2,
        event: CONSOLE_CTRL_CONSOLE_PORT,
        id: 0,
        value: 1,
    },
    ConsoleCtrlSlot {
        bit: 1 << 3,
        event: CONSOLE_CTRL_PORT_OPEN,
        id: 0,
        value: 1,
    },
    ConsoleCtrlSlot {
        bit: 1 << 4,
        event: CONSOLE_CTRL_PORT_OPEN,
        id: 1,
        value: 1,
    },
];

/// Persisted virtio-console control response state.
///
/// The VMM records idempotent host-to-guest MULTIPORT responses here when
/// handling guest control TX. Keeping this state in the device slot makes
/// control handshake progress part of the mmap snapshot instead of transient
/// VMM local state. Duplicate guest readiness messages set the same bit again
/// rather than growing a FIFO that can crowd out required later responses.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct ConsoleControlState {
    /// Bitset of pending semantic control responses.
    pub pending_mask: u8,
    _pad: [u8; 135],
}

const _: () = assert!(size_of::<ConsoleControlState>() == 136);

const CONSOLE_CTRL_VALID_MASK: u8 = (1 << CONSOLE_PENDING_CTRL_CAPACITY) - 1;

/// Invalid persisted virtio-console control state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleControlStateError {
    pending_mask: u8,
}

impl std::fmt::Display for ConsoleControlStateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "console control pending mask {:#04x} has bits outside valid mask {:#04x}",
            self.pending_mask, CONSOLE_CTRL_VALID_MASK
        )
    }
}

impl std::error::Error for ConsoleControlStateError {}

impl ConsoleControlState {
    /// Validate canonical persisted console control state.
    ///
    /// The state is a bitset of known semantic host-to-guest control responses;
    /// no future or corrupt bits may be silently ignored.
    pub const fn validate(&self) -> Result<(), ConsoleControlStateError> {
        if self.pending_mask & !CONSOLE_CTRL_VALID_MASK != 0 {
            return Err(ConsoleControlStateError {
                pending_mask: self.pending_mask,
            });
        }
        Ok(())
    }

    /// Number of queued control messages.
    pub fn len(&self) -> usize {
        CONSOLE_CTRL_SLOTS
            .iter()
            .filter(|slot| self.pending_mask & slot.bit != 0)
            .count()
    }

    /// Returns `true` if no control messages are queued.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the queued message at `index`, relative to the oldest message.
    pub fn get(&self, index: usize) -> Option<[u8; 8]> {
        let mut seen = 0usize;
        for slot in CONSOLE_CTRL_SLOTS {
            if self.pending_mask & slot.bit == 0 {
                continue;
            }
            if seen == index {
                return Some(console_ctrl_msg(slot));
            }
            seen += 1;
        }
        None
    }

    /// Return the oldest queued message.
    pub fn front(&self) -> Option<[u8; 8]> {
        self.get(0)
    }

    /// Mark a control response as pending.
    ///
    /// Duplicate messages are idempotent and return `true`. Returns `false`
    /// only for a message shape this two-port console implementation does not
    /// support.
    pub fn push_back(&mut self, msg: [u8; 8]) -> bool {
        let Some(slot) = console_ctrl_slot_for_msg(msg) else {
            return false;
        };
        self.pending_mask |= slot.bit;
        true
    }

    /// Remove and return the oldest queued control message.
    pub fn pop_front(&mut self) -> Option<[u8; 8]> {
        for slot in CONSOLE_CTRL_SLOTS {
            if self.pending_mask & slot.bit != 0 {
                self.pending_mask &= !slot.bit;
                return Some(console_ctrl_msg(slot));
            }
        }
        None
    }

    /// Drop all queued control messages.
    pub const fn clear(&mut self) {
        self.pending_mask = 0;
    }
}

fn console_ctrl_msg(slot: ConsoleCtrlSlot) -> [u8; 8] {
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&slot.id.to_le_bytes());
    msg[4..6].copy_from_slice(&slot.event.to_le_bytes());
    msg[6..8].copy_from_slice(&slot.value.to_le_bytes());
    msg
}

fn console_ctrl_slot_for_msg(msg: [u8; 8]) -> Option<ConsoleCtrlSlot> {
    let id = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
    let event = u16::from_le_bytes([msg[4], msg[5]]);
    let value = u16::from_le_bytes([msg[6], msg[7]]);
    CONSOLE_CTRL_SLOTS
        .into_iter()
        .find(|slot| slot.id == id && slot.event == event && slot.value == value)
}

/// Console device state: transport + 6 queues (MULTIPORT) + config + control queue.
///
/// Queue layout with MULTIPORT:
///   0,1 = port 0 (serial console) RX/TX
///   2,3 = control RX/TX
///   4,5 = port 1 (agent channel) RX/TX
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct ConsoleState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 6],
    pub config: ConsoleConfig,
    /// Persisted host-to-guest control responses.
    pub control: ConsoleControlState,
    _pad: [u8; 84],
}

const _: () = assert!(size_of::<ConsoleState>() == 512);

/// Net device state: transport + 11 queues + config.
///
/// Supports up to 5 queue pairs (10 data queues: even=RX, odd=TX) plus
/// 1 control queue. Unused queue slots stay zeroed — the guest discovers
/// active queues via `QUEUE_NUM_MAX`.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct NetState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 11],
    pub config: NetConfig,
    /// Persisted host-only control state for MQ negotiation.
    pub control: NetControlState,
}

const _: () = assert!(size_of::<NetState>() == 512);

/// RNG device state: transport + 1 queue, no config.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct RngState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 1],
}

const _: () = assert!(size_of::<RngState>() == 80);

/// Filesystem device state: transport + 10 queues + config.
///
/// Supports up to 1 hiprio queue + 9 request queues. The active queue count
/// is determined by `config.num_request_queues` (1..=9). Unused queue slots
/// stay zeroed — the guest discovers active queues via `QUEUE_NUM_MAX`.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct FsState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 10],
    pub config: FsConfig,
    /// Padding to fill the 512-byte device slot.
    _pad: [u8; 32],
}

const _: () = assert!(size_of::<FsState>() == 512);

/// Pmem device state: transport + 1 queue + config.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct PmemState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 1],
    pub config: PmemConfig,
}

const _: () = assert!(size_of::<PmemState>() == 96);

/// Mem (virtio-mem) device state: transport + 1 queue + config.
///
/// The plug-state bitmap is no longer in the device slot — it lives in
/// the hotplug node's RAM descriptor section (dynamically sized, no cap).
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct MemState {
    pub transport: MmioTransportState,
    pub queues: [QueueState; 1],
    pub config: MemDeviceConfig,
    _pad: [u8; 376],
}

// Verify all device states fit in a 512-byte slot.
const _: () = assert!(size_of::<ConsoleState>() <= DEVICE_SLOT_SIZE);
const _: () = assert!(size_of::<NetState>() <= DEVICE_SLOT_SIZE);
const _: () = assert!(size_of::<RngState>() <= DEVICE_SLOT_SIZE);
const _: () = assert!(size_of::<FsState>() <= DEVICE_SLOT_SIZE);
const _: () = assert!(size_of::<PmemState>() <= DEVICE_SLOT_SIZE);
const _: () = assert!(size_of::<MemState>() <= DEVICE_SLOT_SIZE);

// =============================================================================
// VirtioState — uniform access to transport, queues, and config
// =============================================================================

/// Common interface for virtio device state types.
///
/// All per-device state structs have `transport`, `queues`, and optionally
/// `config`. This trait provides uniform access for shared helper functions
/// (poll, MMIO transport, resample) without needing per-type match arms.
pub trait VirtioState {
    /// Immutable transport state reference.
    fn transport(&self) -> &MmioTransportState;
    /// Mutable transport state reference.
    fn transport_mut(&mut self) -> &mut MmioTransportState;
    /// Mutable queue slice (variable length per device type).
    fn queues_mut(&mut self) -> &mut [QueueState];
    /// Mutable config bytes (empty for devices without config, e.g. Rng).
    fn config_bytes_mut(&mut self) -> &mut [u8];
    /// Split into disjoint mutable references (transport, queues, config).
    fn split_mut(&mut self) -> (&mut MmioTransportState, &mut [QueueState], &mut [u8]);
}

macro_rules! impl_virtio_state {
    ($T:ty, config) => {
        impl VirtioState for $T {
            fn transport(&self) -> &MmioTransportState {
                &self.transport
            }
            fn transport_mut(&mut self) -> &mut MmioTransportState {
                &mut self.transport
            }
            fn queues_mut(&mut self) -> &mut [QueueState] {
                &mut self.queues
            }
            fn config_bytes_mut(&mut self) -> &mut [u8] {
                bytemuck::bytes_of_mut(&mut self.config)
            }
            fn split_mut(&mut self) -> (&mut MmioTransportState, &mut [QueueState], &mut [u8]) {
                (
                    &mut self.transport,
                    &mut self.queues,
                    bytemuck::bytes_of_mut(&mut self.config),
                )
            }
        }
    };
    ($T:ty, no_config) => {
        impl VirtioState for $T {
            fn transport(&self) -> &MmioTransportState {
                &self.transport
            }
            fn transport_mut(&mut self) -> &mut MmioTransportState {
                &mut self.transport
            }
            fn queues_mut(&mut self) -> &mut [QueueState] {
                &mut self.queues
            }
            fn config_bytes_mut(&mut self) -> &mut [u8] {
                &mut []
            }
            fn split_mut(&mut self) -> (&mut MmioTransportState, &mut [QueueState], &mut [u8]) {
                (&mut self.transport, &mut self.queues, &mut [])
            }
        }
    };
}

impl_virtio_state!(ConsoleState, config);
impl_virtio_state!(NetState, config);
impl_virtio_state!(RngState, no_config);
impl_virtio_state!(FsState, config);
impl_virtio_state!(PmemState, config);
impl_virtio_state!(MemState, config);

// SAFETY: these POD structs are the durable VM-state layouts for the matching
// virtio device-kind codes written into `VmStateHeader::device_kinds`.
unsafe impl DeviceState for ConsoleState {
    const DEVICE_KIND: u8 = DEVICE_KIND_CONSOLE;
}

// SAFETY: see `ConsoleState`.
unsafe impl DeviceState for NetState {
    const DEVICE_KIND: u8 = DEVICE_KIND_NET;
}

// SAFETY: see `ConsoleState`.
unsafe impl DeviceState for RngState {
    const DEVICE_KIND: u8 = DEVICE_KIND_RNG;
}

// SAFETY: see `ConsoleState`.
unsafe impl DeviceState for FsState {
    const DEVICE_KIND: u8 = DEVICE_KIND_FS;
}

// SAFETY: see `ConsoleState`.
unsafe impl DeviceState for PmemState {
    const DEVICE_KIND: u8 = DEVICE_KIND_PMEM;
}

// =============================================================================
// Descriptor Table Entry (virtio spec 2.7.5)
// =============================================================================

/// A single virtio descriptor table entry.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct Descriptor {
    /// Guest physical address of the buffer.
    pub addr: u64,
    /// Length of the buffer in bytes.
    pub len: u32,
    /// Flags: NEXT, WRITE, INDIRECT.
    pub flags: u16,
    /// Index of the next descriptor if NEXT flag is set.
    pub next: u16,
}

const _: () = assert!(size_of::<Descriptor>() == 16);

impl Descriptor {
    /// Zero-valued descriptor constant for array initialization.
    pub(crate) const ZERO: Self = Self {
        addr: 0,
        len: 0,
        flags: 0,
        next: 0,
    };
}

// =============================================================================
// VirtioDevice Trait
// =============================================================================

/// Trait for virtio device implementations.
///
/// Devices are pure data processors: they receive queue access via [`QueueView`],
/// process descriptors, and return. They never touch guest memory directly, never
/// issue barriers, never do atomic ops. All that complexity lives in [`QueueView`].
///
/// Devices hold only backend references (console PTY, TAP fd, etc.) — no queues,
/// no transport state, no IRQ handles.
pub trait VirtioDevice<M: amla_core::vm_state::guest_mem::GuestMemory> {
    /// Virtio device type ID (e.g., 5 for balloon). Used by transport for `DeviceID` register.
    fn device_id(&self) -> u32;

    /// Number of virtqueues this device uses.
    fn queue_count(&self) -> usize;

    /// Maximum queue size (entries). Default 256.
    fn queue_max_size(&self) -> u16 {
        256
    }

    /// Device-offered features (constant, not stored in state bytes).
    fn device_features(&self) -> u64;

    /// Process available buffers on the given queue.
    ///
    /// Returns `Err(QueueViolation)` if the device observes a structural
    /// virtqueue defect (e.g., a malformed descriptor chain). The transport
    /// converts this into `DEVICE_NEEDS_RESET`. Devices propagate walker
    /// errors via `let slice = step?;` inside `for step in chain { ... }`.
    #[must_use = "queue processing violations must be propagated to the transport"]
    fn process_queue(
        &mut self,
        queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation>;

    /// Handle a config space read (offset relative to 0x100).
    ///
    /// Default: copy from config bytes at offset. Override for dynamic config.
    /// Transport bounds-checks `offset + data.len() <= config.len()` BEFORE calling.
    fn read_config(&self, config: &[u8], offset: usize, data: &mut [u8]) {
        let end = (offset + data.len()).min(config.len());
        if offset < end {
            data[..end - offset].copy_from_slice(&config[offset..end]);
        }
    }

    /// Handle a config space write (offset relative to 0x100).
    ///
    /// Default: NO-OP (most config fields are read-only). Override for writable fields.
    /// Transport bounds-checks `offset + data.len() <= config.len()` BEFORE calling.
    fn write_config(&mut self, _config: &mut [u8], _offset: usize, _data: &[u8]) {}

    /// Return shared memory region info `(base_gpa, length)` for the given region ID.
    ///
    /// Default: None. Override for virtio-fs DAX window.
    fn shm_region(&self, _id: u32) -> Option<(u64, u64)> {
        None
    }

    /// Called when guest writes 0 to status register (full device reset).
    fn reset(&mut self) {}

    /// Give the device a Waker for backend-initiated processing.
    ///
    /// Devices that need RX wakeups store this and pass it to their backend.
    /// Default: no-op (guest-driven-only devices like balloon, rng).
    fn set_waker(&mut self, _waker: std::task::Waker) {}
}

// =============================================================================
// Helpers
// =============================================================================

/// Transmute a mutable byte slice into a typed Pod reference.
///
/// Panics if `bytes` is too small or misaligned for `T`.
pub fn state_from<T: Pod>(bytes: &mut [u8]) -> &mut T {
    bytemuck::from_bytes_mut(&mut bytes[..size_of::<T>()])
}

/// Transmute an immutable byte slice into a typed Pod reference.
///
/// Panics if `bytes` is too small or misaligned for `T`.
pub fn state_ref<T: Pod>(bytes: &[u8]) -> &T {
    bytemuck::from_bytes(&bytes[..size_of::<T>()])
}
