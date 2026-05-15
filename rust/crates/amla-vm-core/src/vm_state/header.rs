// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! VM state file header and layout computation.

use bytemuck::{Pod, Zeroable};

use super::irqchip::IrqchipSectionState;
use super::layout::{RING_BUFFER_SIZE, VCPU_SLOT_SIZE, checked_page_align};
use super::ram_descriptor::{RamSize, ram_desc_section_size};

/// Magic number: "AMLA" in little-endian.
pub const VM_STATE_MAGIC: u32 = u32::from_le_bytes(*b"AMLA");

/// Current layout version. Bump on breaking changes.
///
/// v2 → v3: added `device_meta` section, `device_kinds` array, `MAX_VCPUS`=64, `MAX_DEVICES`=64.
/// v3 → v4: added CPU hotplug count state.
/// v4 → v5: added `ram_desc_offset/size` for hole bitmap (replaced `reserved`).
/// v5 → v6: added `pmem_offset/size` for PFN superblock + vmemmap sections.
/// v6 → v7: replaced `online_vcpu_count` with per-vCPU PSCI power states.
/// v7 → v8: repacked `QueueState` and widened its async completion generation.
/// v8 → v9: moved virtio-console pending control queue into `ConsoleState`.
/// v9 → v10: added host-owned PMEM geometry, independent of guest-writable PFN superblocks.
/// v10 → v11: added exact per-device virtqueue counts to the durable topology.
/// v11 → v12: replaced virtio-console control FIFO bytes with canonical semantic pending bitset.
pub const VM_STATE_VERSION: u32 = 12;

/// Section alignment for the vmstate file format.
///
/// Fixed format constant (not the host page size). 16 KiB covers both x86
/// and ARM64 vCPU slot sizes and keeps the file layout portable.
pub const PAGE_SIZE: usize = 16384;

/// Maximum number of vCPUs supported.
pub const MAX_VCPUS: usize = 64;

/// vCPU is running from the PSCI `CPU_ON` state machine's perspective.
pub const PSCI_POWER_ON: u8 = 0;

/// vCPU is stopped and can accept a PSCI `CPU_ON` request.
pub const PSCI_POWER_OFF: u8 = 1;

/// A PSCI `CPU_ON` request has been accepted but not consumed by the target.
pub const PSCI_POWER_ON_PENDING: u8 = 2;

/// Typed PSCI vCPU power-state value stored in the VM-state PSCI section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciPowerState {
    /// vCPU is running from the PSCI `CPU_ON` state machine's perspective.
    On,
    /// vCPU is stopped and can accept a PSCI `CPU_ON` request.
    Off,
    /// A PSCI `CPU_ON` request has been accepted but not consumed.
    OnPending,
}

/// Non-`Off` PSCI state that prevented claiming an off vCPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PsciPowerStateBusy {
    /// vCPU is already running.
    On,
    /// vCPU already has a pending `CPU_ON` request.
    OnPending,
}

impl PsciPowerState {
    /// Return the stable persisted byte encoding.
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::On => PSCI_POWER_ON,
            Self::Off => PSCI_POWER_OFF,
            Self::OnPending => PSCI_POWER_ON_PENDING,
        }
    }

    /// Decode a persisted PSCI power-state byte.
    pub const fn from_u8(state: u8) -> Option<Self> {
        match state {
            PSCI_POWER_ON => Some(Self::On),
            PSCI_POWER_OFF => Some(Self::Off),
            PSCI_POWER_ON_PENDING => Some(Self::OnPending),
            _ => None,
        }
    }
}

/// Maximum number of device slots (over-provisioned, matches MMIO address space).
pub const MAX_DEVICES: usize = 64;

/// Device-state kind code for an unused slot.
pub const DEVICE_KIND_UNUSED: u8 = 0;

/// Device-state kind code for virtio-console slots.
pub const DEVICE_KIND_CONSOLE: u8 = 1;

/// Device-state kind code for virtio-net slots.
pub const DEVICE_KIND_NET: u8 = 2;

/// Device-state kind code for virtio-rng slots.
pub const DEVICE_KIND_RNG: u8 = 3;

/// Device-state kind code for virtio-fs slots.
pub const DEVICE_KIND_FS: u8 = 4;

/// Device-state kind code for virtio-pmem slots.
pub const DEVICE_KIND_PMEM: u8 = 5;

/// Durable device kind code validated from the VM-state header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceKindCode {
    /// Virtio console.
    Console = DEVICE_KIND_CONSOLE,
    /// Virtio net.
    Net = DEVICE_KIND_NET,
    /// Virtio rng.
    Rng = DEVICE_KIND_RNG,
    /// Virtio fs.
    Fs = DEVICE_KIND_FS,
    /// Virtio pmem.
    Pmem = DEVICE_KIND_PMEM,
}

impl DeviceKindCode {
    /// Parse an active device-kind code.
    pub const fn from_active_code(code: u8) -> Option<Self> {
        match code {
            DEVICE_KIND_CONSOLE => Some(Self::Console),
            DEVICE_KIND_NET => Some(Self::Net),
            DEVICE_KIND_RNG => Some(Self::Rng),
            DEVICE_KIND_FS => Some(Self::Fs),
            DEVICE_KIND_PMEM => Some(Self::Pmem),
            _ => None,
        }
    }

    /// Return this kind's durable code.
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// Return true for PMEM device slots.
    pub const fn is_pmem(self) -> bool {
        matches!(self, Self::Pmem)
    }

    /// Validate queue-count shape for this device kind.
    pub const fn has_valid_queue_count(self, queue_count: u16) -> bool {
        match self {
            Self::Console => queue_count == 6,
            Self::Net => queue_count == 2 || (queue_count >= 5 && !queue_count.is_multiple_of(2)),
            Self::Rng | Self::Pmem => queue_count == 1,
            Self::Fs => queue_count >= 2,
        }
    }
}

/// Size of each device state slot in the device section.
pub const DEVICE_SLOT_SIZE: usize = 512;

/// Size of each device metadata slot.
pub const DEVICE_META_SLOT_SIZE: usize = 128;

/// Header at offset 0 of the unified VM state file.
///
/// Contains magic/version for validation, and byte offsets + sizes for
/// each section. All offsets are relative to the start of the file.
#[derive(Clone, Copy, Debug, Pod, Zeroable)]
#[repr(C)]
pub struct VmStateHeader {
    /// Magic number (`VM_STATE_MAGIC`).
    pub magic: u32,
    /// Layout version (`VM_STATE_VERSION`).
    pub version: u32,
    /// Number of vCPU slots (`max_vcpu_count` for mmap sizing).
    pub vcpu_count: u32,
    /// Number of device slots in use.
    pub device_count: u32,

    /// Byte offset of the host-owned PSCI power-state section.
    pub psci_offset: u64,
    /// Total size of the PSCI power-state section in bytes.
    pub psci_size: u64,

    /// Byte offset of the vCPU state array.
    pub vcpu_offset: u64,
    /// Total size of the vCPU state section in bytes.
    pub vcpu_size: u64,

    /// Byte offset of the irqchip state section.
    pub irqchip_offset: u64,
    /// Total size of the irqchip state section in bytes.
    pub irqchip_size: u64,

    /// Byte offset of the device state array.
    pub device_offset: u64,
    /// Total size of the device state section in bytes.
    pub device_size: u64,

    /// Byte offset of the ring buffer section.
    pub ring_offset: u64,
    /// Total size of the ring buffer section in bytes.
    pub ring_size: u64,

    /// Byte offset of the device metadata section.
    pub device_meta_offset: u64,
    /// Total size of the device metadata section in bytes.
    pub device_meta_size: u64,

    /// Byte offset of guest RAM.
    pub ram_offset: u64,
    /// Total size of guest RAM in bytes.
    pub ram_size: u64,

    /// Device kind for each slot (0 = Reserved/unused).
    ///
    /// Populated at VM creation so restore can reconstruct the device layout
    /// without needing the original `VmConfig`.
    pub device_kinds: [u8; MAX_DEVICES],
    /// Exact virtqueue count for each active device slot.
    ///
    /// This is host-owned topology metadata. Runtime code must not infer
    /// backend queue/eventfd layout from device kind maxima or guest-writable
    /// device config bytes.
    pub device_queue_counts: [u16; MAX_DEVICES],

    /// Byte offset of the RAM descriptor section (hole bitmap).
    pub ram_desc_offset: u64,
    /// Total size of the RAM descriptor section in bytes.
    pub ram_desc_size: u64,

    /// Byte offset of the combined PMEM sections (superblock + vmemmap per device).
    pub pmem_offset: u64,
    /// Total size of all PMEM sections combined.
    pub pmem_size: u64,
    /// Number of PMEM devices whose sections are stored at `pmem_offset`.
    pub pmem_count: u32,
    /// Number of images packed in each PMEM device (for multi-image packing).
    /// Handles are assigned contiguously starting from index 1.
    pub pmem_image_counts: [u32; MAX_DEVICES],
    /// Padding for alignment (Pod requires explicit padding).
    pub pad1: u32,
    /// Host-owned PMEM data offsets, indexed by PMEM device.
    ///
    /// These values are immutable layout metadata. The guest-visible PFN
    /// superblocks contain the same data for Linux, but host mapping must
    /// never be derived from those guest-writable bytes.
    pub pmem_data_offsets: [u64; MAX_DEVICES],
    /// Host-owned unaligned total PMEM sizes, indexed by PMEM device.
    pub pmem_total_sizes: [u64; MAX_DEVICES],
}

/// Proof that a VM-state header describes exactly the canonical file layout.
///
/// This token is only constructible by validating a header against the mapped
/// metadata length. Holding it means section sizes, offsets, PMEM geometry, and
/// padding fields match the single layout emitted by [`VmStateHeader::compute`].
#[derive(Clone, Copy, Debug)]
pub struct CanonicalVmStateLayout {
    total_size: u64,
}

impl CanonicalVmStateLayout {
    /// Total VM-state metadata size proven by this token.
    #[must_use]
    pub const fn total_size(self) -> u64 {
        self.total_size
    }
}

impl VmStateHeader {
    /// Compute a fully populated header from VM parameters.
    ///
    /// Calculates page-aligned section offsets for vCPU state, irqchip,
    /// device slots, device metadata, ring buffer, PMEM sections, RAM
    /// descriptor, and guest RAM. Returns `None` if parameters exceed
    /// limits (`MAX_VCPUS`, `MAX_DEVICES`).
    /// `pmem_data_sizes`: total packed data size per device (sum of page-aligned images).
    /// `pmem_image_counts`: number of images packed in each device.
    #[allow(clippy::cast_possible_truncation)]
    pub fn compute(
        vcpu_count: u32,
        device_count: u32,
        ram_size: u64,
        pmem_data_sizes: &[u64],
        pmem_image_counts: &[u32],
    ) -> Option<Self> {
        if vcpu_count == 0 {
            return None;
        }
        if vcpu_count as usize > MAX_VCPUS {
            return None;
        }
        if device_count as usize > MAX_DEVICES {
            return None;
        }
        if pmem_data_sizes.len() > MAX_DEVICES || pmem_image_counts.len() != pmem_data_sizes.len() {
            return None;
        }

        let ram_size = RamSize::new(ram_size).ok()?;

        // Use checked arithmetic throughout — overflow means the layout
        // doesn't fit in a u64 address space, so return None.
        let pa = checked_page_align;

        let header_size = pa(core::mem::size_of::<Self>() as u64)?;

        let psci_offset = header_size;
        let psci_size = pa(u64::from(vcpu_count))?;

        let vcpu_offset = psci_offset.checked_add(psci_size)?;
        let vcpu_size = pa(u64::from(vcpu_count).checked_mul(VCPU_SLOT_SIZE as u64)?)?;

        let irqchip_offset = vcpu_offset.checked_add(vcpu_size)?;
        let irqchip_size = pa(core::mem::size_of::<IrqchipSectionState>() as u64)?;

        let device_offset = irqchip_offset.checked_add(irqchip_size)?;
        let device_size = pa(u64::from(device_count).checked_mul(DEVICE_SLOT_SIZE as u64)?)?;

        // Device metadata: always MAX_DEVICES slots so layout is fixed.
        let device_meta_offset = device_offset.checked_add(device_size)?;
        let device_meta_size = pa((MAX_DEVICES * DEVICE_META_SLOT_SIZE) as u64)?;

        let ring_offset = device_meta_offset.checked_add(device_meta_size)?;
        let ring_size = pa(RING_BUFFER_SIZE as u64)?;

        // PMEM sections: one per device, each page-aligned by dataoff.
        let pmem_offset = ring_offset.checked_add(ring_size)?;
        let page_size = super::pfn::GUEST_PAGE_SIZE;
        let mut pmem_size: u64 = 0;
        let mut pmem_data_offsets = [0u64; MAX_DEVICES];
        let mut pmem_total_sizes = [0u64; MAX_DEVICES];
        for (i, &data_size) in pmem_data_sizes.iter().enumerate() {
            let geom = super::pfn::PmemGeometry::checked_compute(data_size, page_size)?;
            super::layout::checked_section_align(geom.total)?;
            pmem_size = pmem_size.checked_add(pa(geom.dataoff)?)?;
            pmem_data_offsets[i] = geom.dataoff;
            pmem_total_sizes[i] = geom.total;
        }

        let ram_desc_offset = pmem_offset.checked_add(pmem_size)?;
        let ram_desc_size = ram_desc_section_size(ram_size);

        let ram_offset = ram_desc_offset.checked_add(ram_desc_size)?;
        let ram_size = pa(ram_size.bytes())?;

        // Verify total_size doesn't overflow.
        ram_offset.checked_add(ram_size)?;

        Some(Self {
            magic: VM_STATE_MAGIC,
            version: VM_STATE_VERSION,
            vcpu_count,
            device_count,
            psci_offset,
            psci_size,
            vcpu_offset,
            vcpu_size,
            irqchip_offset,
            irqchip_size,
            device_offset,
            device_size,
            device_meta_offset,
            device_meta_size,
            ring_offset,
            ring_size,
            ram_offset,
            ram_size,
            device_kinds: [0; MAX_DEVICES],
            device_queue_counts: [0; MAX_DEVICES],
            ram_desc_offset,
            ram_desc_size,
            pmem_offset,
            pmem_size,
            pmem_count: pmem_data_sizes.len() as u32,
            pmem_image_counts: {
                let mut counts = [0u32; MAX_DEVICES];
                for (i, &c) in pmem_image_counts.iter().enumerate().take(MAX_DEVICES) {
                    counts[i] = c;
                }
                counts
            },
            pad1: 0,
            pmem_data_offsets,
            pmem_total_sizes,
        })
    }

    /// Total file size: end of the RAM section.
    pub const fn total_size(&self) -> u64 {
        self.ram_offset + self.ram_size
    }

    /// Check that all section offsets are page-aligned.
    pub const fn is_page_aligned(&self) -> bool {
        let ps = PAGE_SIZE as u64;
        self.psci_offset.is_multiple_of(ps)
            && self.vcpu_offset.is_multiple_of(ps)
            && self.irqchip_offset.is_multiple_of(ps)
            && self.device_offset.is_multiple_of(ps)
            && self.device_meta_offset.is_multiple_of(ps)
            && self.ring_offset.is_multiple_of(ps)
            && (self.pmem_size == 0 || self.pmem_offset.is_multiple_of(ps))
            && self.ram_desc_offset.is_multiple_of(ps)
            && self.ram_offset.is_multiple_of(ps)
    }

    /// Validate the header magic and version.
    pub const fn validate(&self) -> Result<(), &'static str> {
        if self.magic != VM_STATE_MAGIC {
            return Err("invalid magic");
        }
        if self.version != VM_STATE_VERSION {
            return Err("unsupported version");
        }
        if self.vcpu_count as usize > MAX_VCPUS {
            return Err("vcpu_count exceeds MAX_VCPUS");
        }
        Ok(())
    }

    /// Fully validate every section offset, size, and invariant against
    /// `metadata_len` (the length of the mmap the header was read from).
    ///
    /// Called once at `VmState` construction. On success, every accessor
    /// (`slice_at`, `ref_at`, `vcpu_slot`, …) is guaranteed to be in-bounds
    /// and properly aligned without re-checking — the header is trusted
    /// for the remainder of the `VmState`'s lifetime.
    ///
    /// Strict: a malformed header is rejected outright. No best-effort
    /// recovery, no inferred legacy layouts, no tolerance for trailing slop.
    pub fn validate_layout(&self, metadata_len: u64) -> Result<(), &'static str> {
        self.validate_canonical_layout(metadata_len).map(|_| ())
    }

    /// Validate this header against the one canonical VM-state layout.
    pub fn validate_canonical_layout(
        &self,
        metadata_len: u64,
    ) -> Result<CanonicalVmStateLayout, &'static str> {
        self.validate()?;

        if self.vcpu_count == 0 {
            return Err("vcpu_count is zero");
        }
        if self.device_count as usize > MAX_DEVICES {
            return Err("device_count exceeds MAX_DEVICES");
        }
        if self.pmem_count as usize > MAX_DEVICES {
            return Err("pmem_count exceeds MAX_DEVICES");
        }
        self.validate_device_topology()?;
        if (self.pmem_size == 0) != (self.pmem_count == 0) {
            return Err("pmem_size and pmem_count disagree on emptiness");
        }
        if self.pad1 != 0 {
            return Err("padding field is nonzero");
        }
        RamSize::new(self.ram_size)?;

        let (pmem_data_sizes, pmem_image_counts) = self.canonical_pmem_inputs()?;
        let expected = Self::compute(
            self.vcpu_count,
            self.device_count,
            self.ram_size,
            &pmem_data_sizes,
            &pmem_image_counts,
        )
        .ok_or("canonical layout recomputation overflow")?;

        self.require_exact_layout(&expected)?;

        if expected.total_size() != metadata_len {
            return Err("metadata_len does not match canonical total size");
        }

        Ok(CanonicalVmStateLayout {
            total_size: metadata_len,
        })
    }

    fn validate_device_topology(&self) -> Result<(), &'static str> {
        let active_count = self.device_count as usize;
        let mut pmem_slots = 0u32;

        for index in 0..active_count {
            let kind = DeviceKindCode::from_active_code(self.device_kinds[index])
                .ok_or("active device kind is unknown or unused")?;
            let queue_count = self.device_queue_counts[index];
            if !kind.has_valid_queue_count(queue_count) {
                return Err("active device queue count is invalid for device kind");
            }
            if kind.is_pmem() {
                pmem_slots = pmem_slots
                    .checked_add(1)
                    .ok_or("pmem slot count overflow")?;
            }
        }

        for index in active_count..MAX_DEVICES {
            if self.device_kinds[index] != DEVICE_KIND_UNUSED {
                return Err("inactive device kind is nonzero");
            }
            if self.device_queue_counts[index] != 0 {
                return Err("inactive device queue count is nonzero");
            }
        }

        if self.pmem_count != pmem_slots {
            return Err("pmem_count does not match PMEM device slots");
        }

        Ok(())
    }

    fn canonical_pmem_inputs(&self) -> Result<(Vec<u64>, Vec<u32>), &'static str> {
        let mut data_sizes = Vec::with_capacity(self.pmem_count as usize);
        let mut image_counts = Vec::with_capacity(self.pmem_count as usize);
        for i in 0..self.pmem_count as usize {
            let dataoff = self.pmem_data_offsets[i];
            let total = self.pmem_total_sizes[i];
            let image_count = self.pmem_image_counts[i];
            if image_count == 0 {
                return Err("pmem image count is zero");
            }
            let packed_data_size = total
                .checked_sub(dataoff)
                .ok_or("pmem total size is smaller than data offset")?;
            let geom = super::pfn::PmemGeometry::checked_compute(
                packed_data_size,
                super::pfn::GUEST_PAGE_SIZE,
            )
            .ok_or("pmem geometry recomputation overflow")?;
            if geom.dataoff != dataoff || geom.total != total {
                return Err("pmem geometry is not canonical");
            }
            data_sizes.push(packed_data_size);
            image_counts.push(image_count);
        }

        for i in self.pmem_count as usize..MAX_DEVICES {
            if self.pmem_image_counts[i] != 0 {
                return Err("inactive pmem image count is nonzero");
            }
            if self.pmem_data_offsets[i] != 0 {
                return Err("inactive pmem data offset is nonzero");
            }
            if self.pmem_total_sizes[i] != 0 {
                return Err("inactive pmem total size is nonzero");
            }
        }

        Ok((data_sizes, image_counts))
    }

    fn require_exact_layout(&self, expected: &Self) -> Result<(), &'static str> {
        if self.psci_offset != expected.psci_offset || self.psci_size != expected.psci_size {
            return Err("psci section is not canonical");
        }
        if self.vcpu_offset != expected.vcpu_offset || self.vcpu_size != expected.vcpu_size {
            return Err("vcpu section is not canonical");
        }
        if self.irqchip_offset != expected.irqchip_offset
            || self.irqchip_size != expected.irqchip_size
        {
            return Err("irqchip section is not canonical");
        }
        if self.device_offset != expected.device_offset || self.device_size != expected.device_size
        {
            return Err("device section is not canonical");
        }
        if self.device_meta_offset != expected.device_meta_offset
            || self.device_meta_size != expected.device_meta_size
        {
            return Err("device metadata section is not canonical");
        }
        if self.ring_offset != expected.ring_offset || self.ring_size != expected.ring_size {
            return Err("ring section is not canonical");
        }
        if self.pmem_offset != expected.pmem_offset || self.pmem_size != expected.pmem_size {
            return Err("pmem section is not canonical");
        }
        if self.ram_desc_offset != expected.ram_desc_offset
            || self.ram_desc_size != expected.ram_desc_size
        {
            return Err("ram descriptor section is not canonical");
        }
        if self.ram_offset != expected.ram_offset || self.ram_size != expected.ram_size {
            return Err("ram section is not canonical");
        }
        if self.pmem_count != expected.pmem_count {
            return Err("pmem_count is not canonical");
        }
        if self.pmem_image_counts != expected.pmem_image_counts
            || self.pmem_data_offsets != expected.pmem_data_offsets
            || self.pmem_total_sizes != expected.pmem_total_sizes
        {
            return Err("pmem arrays are not canonical");
        }
        Ok(())
    }
}

/// Return whether `state` is a valid `PSCI_POWER_*` value.
pub const fn is_valid_psci_power_state(state: u8) -> bool {
    PsciPowerState::from_u8(state).is_some()
}
