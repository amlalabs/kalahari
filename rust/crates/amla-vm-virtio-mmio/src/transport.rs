// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! MMIO transport register dispatch per virtio-mmio v2.
//!
//! This is mechanical spec translation. One implementation, works for all devices.

use amla_core::IrqLine;
use amla_core::num::{hi32, lo32};
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{
    MmioTransportState, QueueState, STATUS_ACKNOWLEDGE, STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER,
    STATUS_DRIVER_OK, STATUS_FAILED, STATUS_FEATURES_OK, VENDOR_ID, VIRTIO_F_VERSION_1,
    VirtioDevice, notify_config_change as publish_config_change, signal_device_needs_reset,
    validate_queue_layout,
};
use bytemuck::Zeroable;

// =============================================================================
// MMIO Register Offsets (virtio-mmio spec v2)
// =============================================================================

/// `MagicValue` register offset.
pub const MAGIC_VALUE: u64 = 0x000;
/// `Version` register offset.
pub const VERSION: u64 = 0x004;
/// `DeviceID` register offset.
pub const DEVICE_ID: u64 = 0x008;
/// `VendorID` register offset.
pub const VENDOR_ID_REG: u64 = 0x00C;
pub const DEVICE_FEATURES: u64 = 0x010;
pub const DEVICE_FEATURES_SEL: u64 = 0x014;
pub const DRIVER_FEATURES: u64 = 0x020;
pub const DRIVER_FEATURES_SEL: u64 = 0x024;
pub const QUEUE_SEL: u64 = 0x030;
pub const QUEUE_NUM_MAX: u64 = 0x034;
pub const QUEUE_NUM: u64 = 0x038;
pub const QUEUE_READY: u64 = 0x044;
/// `QueueNotify` register offset.
pub const QUEUE_NOTIFY: u64 = 0x050;
/// `InterruptStatus` register offset.
pub const INTERRUPT_STATUS: u64 = 0x060;
pub const INTERRUPT_ACK: u64 = 0x064;
/// `Status` register offset.
pub const STATUS: u64 = 0x070;
pub const QUEUE_DESC_LOW: u64 = 0x080;
pub const QUEUE_DESC_HIGH: u64 = 0x084;
pub const QUEUE_AVAIL_LOW: u64 = 0x090;
pub const QUEUE_AVAIL_HIGH: u64 = 0x094;
pub const QUEUE_USED_LOW: u64 = 0x0A0;
pub const QUEUE_USED_HIGH: u64 = 0x0A4;
pub const SHM_SEL: u64 = 0x0AC;
pub const SHM_LEN_LOW: u64 = 0x0B0;
pub const SHM_LEN_HIGH: u64 = 0x0B4;
pub const SHM_BASE_LOW: u64 = 0x0B8;
pub const SHM_BASE_HIGH: u64 = 0x0BC;
/// `ConfigGeneration` register offset.
pub const CONFIG_GENERATION: u64 = 0x0FC;
/// Start of the device-specific config space.
pub const CONFIG_SPACE: u64 = 0x100;

/// Magic value identifying a virtio-mmio device (`"virt"` in ASCII).
pub const VIRTIO_MMIO_MAGIC: u32 = 0x7472_6976;

/// MMIO version: 2 (modern only).
pub const VIRTIO_MMIO_VERSION: u32 = 2;

// =============================================================================
// MmioTransport
// =============================================================================

/// MMIO transport — dispatches register reads/writes for a single virtio device.
///
/// Created per-device during `run()`, holds mutable references to the device's
/// transport state, queue states, config bytes, and the device implementation.
///
/// Fields are private — callers must drive state through [`read`](Self::read),
/// [`write`](Self::write), and [`notify_config_change`](Self::notify_config_change)
/// so that spec invariants (`FEATURES_OK` locks `driver_features`, `STATUS=0`
/// resets all queues and deasserts IRQ, etc.) cannot be bypassed.
pub struct MmioTransport<'a, D: VirtioDevice<M>, M: GuestMemory> {
    transport: &'a mut MmioTransportState,
    queues: &'a mut [QueueState],
    config: &'a mut [u8],
    device: &'a mut D,
    memory: &'a M,
    irq: &'a dyn IrqLine,
}

impl<'a, D: VirtioDevice<M>, M: GuestMemory> MmioTransport<'a, D, M> {
    /// Construct a per-device transport around borrowed state.
    pub fn new(
        transport: &'a mut MmioTransportState,
        queues: &'a mut [QueueState],
        config: &'a mut [u8],
        device: &'a mut D,
        memory: &'a M,
        irq: &'a dyn IrqLine,
    ) -> Self {
        Self {
            transport,
            queues,
            config,
            device,
            memory,
            irq,
        }
    }

    /// Handle an MMIO read. Returns the value to return to the guest.
    ///
    /// `offset` is relative to the device's MMIO base (0x000..0x1FF).
    /// `size` is the access width in bytes (1, 2, or 4).
    pub fn read(&self, offset: u64, size: u8) -> u64 {
        // Transport registers are 32-bit
        if offset < CONFIG_SPACE {
            if size != 4 {
                return 0;
            }
            return u64::from(self.read_transport(offset));
        }

        // Config space (0x100+) — offset is < 0x200, always fits in usize
        #[allow(clippy::cast_possible_truncation)]
        let config_offset = (offset - CONFIG_SPACE) as usize;
        self.read_config(config_offset, size)
    }

    /// Handle an MMIO write from the guest.
    ///
    /// `offset` is relative to the device's MMIO base (0x000..0x1FF).
    /// `size` is the access width in bytes (1, 2, or 4).
    pub fn write(&mut self, offset: u64, size: u8, value: u64) {
        // Transport registers are 32-bit
        if offset < CONFIG_SPACE {
            if size != 4 {
                return;
            }
            // Transport registers are 32-bit, upper bits discarded per spec
            #[allow(clippy::cast_possible_truncation)]
            self.write_transport(offset, value as u32);
            return;
        }

        // Config space (0x100+) — offset is < 0x200, always fits in usize
        #[allow(clippy::cast_possible_truncation)]
        let config_offset = (offset - CONFIG_SPACE) as usize;
        self.write_config(config_offset, size, value);
    }

    /// Notify a config change. Sets `INT_CONFIG`, bumps generation, asserts IRQ.
    pub fn notify_config_change(&mut self) {
        publish_config_change(self.transport, self.irq);
    }

    // =========================================================================
    // Transport Register Reads
    // =========================================================================

    fn read_transport(&self, offset: u64) -> u32 {
        match offset {
            MAGIC_VALUE => VIRTIO_MMIO_MAGIC,
            VERSION => VIRTIO_MMIO_VERSION,
            DEVICE_ID => self.device.device_id(),
            VENDOR_ID_REG => VENDOR_ID,

            DEVICE_FEATURES => {
                let features = self.device.device_features();
                match self.transport.features_sel {
                    0 => lo32(features),
                    1 => hi32(features),
                    _ => 0,
                }
            }

            QUEUE_NUM_MAX => {
                if self.selected_queue_index().is_some() {
                    u32::from(self.device.queue_max_size())
                } else {
                    0 // nonexistent queue
                }
            }

            QUEUE_READY => self
                .selected_queue_index()
                .map_or(0, |sel| u32::from(self.queues[sel].ready)),

            INTERRUPT_STATUS => self.transport.interrupt_status,

            STATUS => self.transport.status,

            CONFIG_GENERATION => self.transport.config_generation,

            SHM_LEN_LOW => self.shm_half(|_base, len| len),
            SHM_LEN_HIGH => self.shm_half(|_base, len| len >> 32),
            SHM_BASE_LOW => self.shm_half(|base, _len| base),
            SHM_BASE_HIGH => self.shm_half(|base, _len| base >> 32),

            _ => {
                log::debug!("unhandled MMIO read at offset {offset:#x}");
                0
            }
        }
    }

    // =========================================================================
    // Transport Register Writes
    // =========================================================================

    // Each match arm is a distinct spec register — cannot be meaningfully split
    #[allow(clippy::too_many_lines)]
    fn write_transport(&mut self, offset: u64, value: u32) {
        match offset {
            DEVICE_FEATURES_SEL => {
                self.transport.features_sel = value;
            }

            DRIVER_FEATURES => {
                // Per virtio spec §2.2.1: features are locked once FEATURES_OK is set.
                if self.transport.status & STATUS_FEATURES_OK != 0 {
                    return;
                }
                let sel = self.transport.driver_features_sel;
                if sel <= 1 {
                    set_addr_half(&mut self.transport.driver_features, value, sel == 1);
                }
            }

            DRIVER_FEATURES_SEL => {
                self.transport.driver_features_sel = value;
            }

            QUEUE_SEL => {
                // Accept any value — guest probes queue existence by reading QueueNumMax
                self.transport.queue_sel = value;
            }

            QUEUE_NUM => {
                let max = self.device.queue_max_size();
                if let Some(q) = self.require_queue_modifiable("QUEUE_NUM")
                    && let Ok(size) = u16::try_from(value)
                    && size > 0
                    && size.is_power_of_two()
                    && size <= max
                {
                    q.size = size;
                }
            }

            QUEUE_READY => {
                if let Some(sel) = self.selected_queue_index() {
                    let max = self.device.queue_max_size();
                    let q = &mut self.queues[sel];
                    let new_ready = value != 0;
                    let was_ready = q.ready != 0;
                    if new_ready == was_ready {
                        return;
                    }
                    if new_ready {
                        if self.transport.status & STATUS_FEATURES_OK == 0 {
                            log::warn!(
                                "guest enabled queue {sel} before FEATURES_OK — setting DEVICE_NEEDS_RESET"
                            );
                            self.signal_needs_reset();
                            return;
                        }
                        if q.size == 0 || !q.size.is_power_of_two() || q.size > max {
                            log::warn!(
                                "guest enabled queue {sel} with invalid size {} — setting DEVICE_NEEDS_RESET",
                                q.size
                            );
                            self.signal_needs_reset();
                            return;
                        }
                        // Validate ring base+length against guest RAM. This
                        // is the single point at which queue address validity
                        // is checked: the spec freezes addresses while ready,
                        // so once this passes, all per-access offset adds in
                        // pop/push/needs_notification cannot wrap u64.
                        if let Err(violation) =
                            validate_queue_layout(q, self.memory, self.transport.driver_features)
                        {
                            log::warn!(
                                "guest enabled queue {sel} with invalid ring layout: {violation} — setting DEVICE_NEEDS_RESET"
                            );
                            self.signal_needs_reset();
                            return;
                        }
                        q.ready = 1;
                    } else {
                        reset_queue_state(q);
                    }
                }
            }

            QUEUE_NOTIFY => {
                log::trace!(
                    "QueueNotify({value}) observed by MMIO transport; queue work is routed through the VMM device waker",
                );
            }

            INTERRUPT_ACK => {
                self.transport.interrupt_status &= !value;
                if self.transport.interrupt_status == 0 {
                    self.irq.deassert();
                }
            }

            STATUS => {
                if value == 0 {
                    // Device reset
                    self.transport.status = 0;
                    self.transport.driver_features = 0;
                    self.transport.interrupt_status = 0;
                    self.transport.queue_sel = 0;
                    self.transport.features_sel = 0;
                    self.transport.driver_features_sel = 0;
                    self.transport.shm_sel = 0;
                    // Reset all queues
                    for q in self.queues.iter_mut() {
                        reset_queue_state(q);
                    }
                    self.device.reset();
                    self.irq.deassert();
                    return;
                }

                // Check FEATURES_OK transition
                let old = self.transport.status;
                let sticky_reset = old & STATUS_DEVICE_NEEDS_RESET;
                // Virtio device status is monotonic: the driver may only add
                // bits, except for STATUS=0 which performs a full reset. If a
                // nonzero write could clear FEATURES_OK/DRIVER_OK, the driver
                // could reopen feature negotiation or resume queue work without
                // the reset path that invalidates in-flight async completions.
                let new = old | value | sticky_reset;

                // If FEATURES_OK is being set for the first time
                if new & STATUS_FEATURES_OK != 0 && old & STATUS_FEATURES_OK == 0 {
                    // virtio 1.2 §3.1.1: feature negotiation starts only
                    // after ACKNOWLEDGE and DRIVER are visible. Keep this as
                    // a prior-write rule so combined out-of-order status
                    // writes cannot make later queue layout validation depend
                    // on transient feature bits.
                    let prereq = STATUS_ACKNOWLEDGE | STATUS_DRIVER;
                    if old & prereq != prereq {
                        log::warn!(
                            "FEATURES_OK rejected: ACKNOWLEDGE|DRIVER not previously accepted (old={old:#x} new={new:#x})"
                        );
                        self.transport.status =
                            (new & !(STATUS_FEATURES_OK | STATUS_DRIVER_OK)) | sticky_reset;
                        return;
                    }
                    // Validate: VIRTIO_F_VERSION_1 must be negotiated
                    let valid = self.transport.driver_features & VIRTIO_F_VERSION_1 != 0;
                    // Validate: driver_features must be a subset of device_features
                    let device_features = self.device.device_features();
                    let valid = valid && (self.transport.driver_features & !device_features) == 0;

                    if !valid {
                        log::warn!(
                            "FEATURES_OK rejected: driver={:#x} device={:#x} version1={} subset={}",
                            self.transport.driver_features,
                            device_features,
                            self.transport.driver_features & VIRTIO_F_VERSION_1 != 0,
                            (self.transport.driver_features & !device_features) == 0,
                        );
                        // Clear FEATURES_OK so the guest detects rejection on
                        // re-read. Also clear DRIVER_OK from this write: a
                        // combined invalid FEATURES_OK|DRIVER_OK write must
                        // not latch DRIVER_OK before feature negotiation
                        // succeeds.
                        self.transport.status =
                            (new & !(STATUS_FEATURES_OK | STATUS_DRIVER_OK)) | sticky_reset;
                        return;
                    }
                }

                // virtio 1.2 §3.1.1: the driver MUST set FEATURES_OK, re-read
                // STATUS to confirm it stayed set, and only then set DRIVER_OK.
                // A combined write that flips both in one step bypasses the
                // re-read; require FEATURES_OK to have been accepted in a
                // *prior* status write (old, not new). Clear DRIVER_OK and let
                // the guest detect the failure on its next read.
                if new & STATUS_DRIVER_OK != 0
                    && old & STATUS_DRIVER_OK == 0
                    && old & STATUS_FEATURES_OK == 0
                {
                    log::warn!(
                        "DRIVER_OK rejected: FEATURES_OK not previously accepted (old={old:#x} new={new:#x})"
                    );
                    self.transport.status = (new & !STATUS_DRIVER_OK) | sticky_reset;
                    return;
                }

                self.transport.status = new;

                if new & STATUS_FAILED != 0 {
                    log::warn!(
                        "guest set FAILED status bit (device_id={}, status={:#x}, driver_features={:#x}, device_features={:#x})",
                        self.device.device_id(),
                        new,
                        self.transport.driver_features,
                        self.device.device_features(),
                    );
                }
            }

            QUEUE_DESC_LOW | QUEUE_DESC_HIGH => {
                if let Some(q) = self.require_queue_modifiable("QUEUE_DESC") {
                    set_addr_half(&mut q.desc_addr, value, offset == QUEUE_DESC_HIGH);
                }
            }
            QUEUE_AVAIL_LOW | QUEUE_AVAIL_HIGH => {
                if let Some(q) = self.require_queue_modifiable("QUEUE_AVAIL") {
                    set_addr_half(&mut q.avail_addr, value, offset == QUEUE_AVAIL_HIGH);
                }
            }
            QUEUE_USED_LOW | QUEUE_USED_HIGH => {
                if let Some(q) = self.require_queue_modifiable("QUEUE_USED") {
                    set_addr_half(&mut q.used_addr, value, offset == QUEUE_USED_HIGH);
                }
            }

            SHM_SEL => {
                self.transport.shm_sel = value;
            }

            _ => {
                log::debug!("unhandled MMIO write at offset {offset:#x}, value={value:#x}");
            }
        }
    }

    // =========================================================================
    // Config Space Access
    // =========================================================================

    fn read_config(&self, offset: usize, size: u8) -> u64 {
        let Some(access) = ConfigAccess::new(offset, size, self.config.len()) else {
            return 0;
        };
        let mut data = [0u8; 8];
        self.device
            .read_config(self.config, access.offset, &mut data[..access.size.bytes()]);
        access.size.decode_read(data)
    }

    fn write_config(&mut self, offset: usize, size: u8, value: u64) {
        let Some(access) = ConfigAccess::new(offset, size, self.config.len()) else {
            return;
        };
        let bytes = value.to_le_bytes();
        self.device
            .write_config(self.config, access.offset, &bytes[..access.size.bytes()]);
    }

    /// Read a 32-bit half of a SHM region field.
    ///
    /// Callers pass `x` for the low half or `x >> 32` for the high half; `lo32`
    /// narrows the callback's u64 result to the selected u32 half.
    fn shm_half(&self, get_field: impl FnOnce(u64, u64) -> u64) -> u32 {
        match self.device.shm_region(self.transport.shm_sel) {
            Some((base, len)) => lo32(get_field(base, len)),
            None => 0xFFFF_FFFF,
        }
    }

    fn active_queue_count(&self) -> usize {
        self.device.queue_count().min(self.queues.len())
    }

    fn selected_queue_index(&self) -> Option<usize> {
        let sel = usize::try_from(self.transport.queue_sel).ok()?;
        (sel < self.active_queue_count()).then_some(sel)
    }

    /// Return the selected queue iff it is currently modifiable per the
    /// virtio spec — i.e. `QueueReady == 0`.
    ///
    /// On a protocol violation (write to a register that is read-only after
    /// `QueueReady` is set), set `DEVICE_NEEDS_RESET` and notify the driver
    /// per virtio 1.2 §2.1.2, then return `None` so the caller drops the
    /// write. An out-of-range `queue_sel` is treated as a probe (silent
    /// drop), matching the existing `QueueNumMax` read behavior.
    fn require_queue_modifiable(&mut self, reg: &str) -> Option<&mut QueueState> {
        let sel = self.selected_queue_index()?;
        if self.queues[sel].ready != 0 {
            log::warn!("guest wrote {reg} while queue {sel} is ready — setting DEVICE_NEEDS_RESET");
            self.signal_needs_reset();
            return None;
        }
        Some(&mut self.queues[sel])
    }

    /// Set `DEVICE_NEEDS_RESET` and, if the driver has reached `DRIVER_OK`,
    /// fire a configuration-change interrupt so the driver wakes up and
    /// notices the status bit (virtio 1.2 §2.1.2).
    fn signal_needs_reset(&mut self) {
        signal_device_needs_reset(self.transport, self.irq);
    }
}

/// Set the low or high 32-bit half of a 64-bit queue address.
fn set_addr_half(addr: &mut u64, value: u32, high: bool) {
    if high {
        *addr = (*addr & 0x0000_0000_FFFF_FFFF) | (u64::from(value) << 32);
    } else {
        *addr = (*addr & 0xFFFF_FFFF_0000_0000) | u64::from(value);
    }
}

#[derive(Clone, Copy)]
enum ConfigAccessSize {
    One,
    Two,
    Four,
}

impl ConfigAccessSize {
    const fn new(size: u8) -> Option<Self> {
        match size {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            4 => Some(Self::Four),
            _ => None,
        }
    }

    const fn bytes(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    fn decode_read(self, data: [u8; 8]) -> u64 {
        match self {
            Self::One => u64::from(data[0]),
            Self::Two => u64::from(u16::from_le_bytes([data[0], data[1]])),
            Self::Four => u64::from(u32::from_le_bytes([data[0], data[1], data[2], data[3]])),
        }
    }
}

struct ConfigAccess {
    offset: usize,
    size: ConfigAccessSize,
}

impl ConfigAccess {
    fn new(offset: usize, size: u8, config_len: usize) -> Option<Self> {
        let size = ConfigAccessSize::new(size)?;
        let bytes = size.bytes();
        if !offset.is_multiple_of(bytes) {
            return None;
        }
        if offset.checked_add(bytes).is_none_or(|end| end > config_len) {
            return None;
        }
        Some(Self { offset, size })
    }
}

fn reset_queue_state(queue: &mut QueueState) {
    // Preserve only the queue-instance generation across zeroing. A reset
    // invalidates all in-flight async completions for this slot, even if the
    // driver later reuses the same descriptor table address and head index.
    let generation = queue.generation.wrapping_add(1);
    *queue = Zeroable::zeroed();
    queue.generation = generation;
}
