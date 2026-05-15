// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! KVM in-kernel `GICv3` state save/restore via `KVM_GET/SET_DEVICE_ATTR`.
//!
//! Saves and restores the full `GICv3` state (distributor, redistributors, and
//! ICC CPU interface system registers) for freeze/spawn on ARM64 KVM.
//!
//! Register lists follow the Linux KVM vGIC save/restore protocol:
//! 1. `SAVE_PENDING_TABLES` to flush pending state
//! 2. Read GICD registers
//! 3. Read GICR registers per vCPU
//! 4. Read ICC sysregs per vCPU

use kvm_bindings::{
    KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
    KVM_DEV_ARM_VGIC_GRP_REDIST_REGS, KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES,
    KVM_DEV_ARM_VGIC_V3_MPIDR_MASK, KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT, kvm_device_attr,
};

use kvm_ioctls::DeviceFd;

use crate::error::{Result, VmmError};

// GICD/GICR register offsets and counts — only needed for in-kernel GIC device ioctls.

use super::consts::{GIC_SPI_START_INTID, IRQ_LINE_COUNT};

const NR_SPIS: u32 = IRQ_LINE_COUNT;

const NR_IRQS: u32 = GIC_SPI_START_INTID + NR_SPIS;

const GICD_CTLR: u64 = 0x0000;

const GICD_ISENABLER: u64 = 0x0100;

const GICD_ISPENDR: u64 = 0x0200;

const GICD_ISACTIVER: u64 = 0x0300;

const GICD_IPRIORITYR: u64 = 0x0400;

const GICD_ICFGR: u64 = 0x0C00;

const GICD_IROUTER: u64 = 0x6100; // INTID 32 (first SPI), matches consts.rs

const GICD_IGROUPR: u64 = 0x0080;

/// `GICR_WAKER` — redistributor sleep/wake control (`RD_base` frame, offset 0x14).
/// Bit 1 (`ProcessorSleep`) controls whether the redistributor is active.
const GICR_WAKER: u64 = 0x0014;

const GICR_IGROUPR0: u64 = 0x10080;

const GICR_ISENABLER0: u64 = 0x10100;

const GICR_ISPENDR0: u64 = 0x10200;

const GICR_ISACTIVER0: u64 = 0x10300;

const GICR_IPRIORITYR: u64 = 0x10400;

const GICR_ICFGR0: u64 = 0x10C00;

const GICR_ICFGR1: u64 = 0x10C04;

/// ICC system register encodings: (`Op0` << 14) | (`Op1` << 11) | (`CRn` << 7) | (`CRm` << 3) | `Op2`
const ICC_SRE_EL1: u64 = 0xC665;
const ICC_CTLR_EL1: u64 = 0xC664;
const ICC_PMR_EL1: u64 = 0xC230;
const ICC_BPR0_EL1: u64 = 0xC643;
const ICC_BPR1_EL1: u64 = 0xC663;
const ICC_IGRPEN0_EL1: u64 = 0xC666;
const ICC_IGRPEN1_EL1: u64 = 0xC667;
const ICC_AP0R_EL1_BASE: u64 = 0xC644; // AP0R0..AP0R3 = 0xC644..0xC647
const ICC_AP1R_EL1_BASE: u64 = 0xC648; // AP1R0..AP1R3 = 0xC648..0xC64B

/// Number of ICC sysregs saved per vCPU.
pub const NUM_ICC_REGS: usize = 15;

/// All ICC sysregs to save per vCPU.
const ICC_REGS: &[u64] = &[
    ICC_SRE_EL1,
    ICC_CTLR_EL1,
    ICC_PMR_EL1,
    ICC_BPR0_EL1,
    ICC_BPR1_EL1,
    ICC_IGRPEN0_EL1,
    ICC_IGRPEN1_EL1,
    ICC_AP0R_EL1_BASE,
    ICC_AP0R_EL1_BASE + 1,
    ICC_AP0R_EL1_BASE + 2,
    ICC_AP0R_EL1_BASE + 3,
    ICC_AP1R_EL1_BASE,
    ICC_AP1R_EL1_BASE + 1,
    ICC_AP1R_EL1_BASE + 2,
    ICC_AP1R_EL1_BASE + 3,
];

const _: () = assert!(ICC_REGS.len() == NUM_ICC_REGS);

/// ICC sysregs that may return EINVAL on some KVM implementations.
///
/// - AP0R1-3 / AP1R1-3: only exist when the GIC implements enough priority
///   bits. Return EINVAL on implementations with ≤5 priority bits (e.g. QEMU
///   TCG `GICv3`).
/// - `ICC_CTLR_EL1`: mostly read-only (writable bits are implementation-defined).
///   Returns EINVAL under nested virtualization where the outer hypervisor
///   doesn't expose the register for writing.
fn is_optional_icc_reg(sysreg: u64) -> bool {
    sysreg == ICC_CTLR_EL1
        || (ICC_AP0R_EL1_BASE + 1..=ICC_AP0R_EL1_BASE + 3).contains(&sysreg)
        || (ICC_AP1R_EL1_BASE + 1..=ICC_AP1R_EL1_BASE + 3).contains(&sysreg)
}

/// Complete in-kernel `GICv3` register state.
#[derive(Clone, Debug)]
pub struct KvmGicState {
    /// `GICD_CTLR` value.
    pub dist_ctlr: u32,
    /// GICD bitmap registers: ISENABLER, ISPENDR, ISACTIVER for SPIs.
    /// Each u32 covers 32 IRQs. Indexed by (`reg_offset` / 4).
    pub dist_isenabler: Vec<u32>,
    pub dist_ispendr: Vec<u32>,
    pub dist_isactiver: Vec<u32>,
    /// `GICD_IPRIORITYR` — one byte per SPI, packed 4 per u32.
    pub dist_ipriorityr: Vec<u32>,
    /// `GICD_ICFGR` — 2 bits per SPI, 16 per u32.
    pub dist_icfgr: Vec<u32>,
    /// `GICD_IROUTER` — 8 bytes per SPI (affinity routing).
    pub dist_irouter: Vec<u64>,
    /// `GICD_IGROUPR` — interrupt group for SPIs (1 bit per IRQ).
    /// Controls Group 0 vs Group 1. Linux uses Group 1 for all interrupts.
    pub dist_igroupr: Vec<u32>,
    /// Per-vCPU state (redistributor + ICC sysregs combined).
    /// Length equals the number of vCPUs.
    pub per_cpu: Vec<KvmGicPerCpuState>,
}

/// Per-vCPU GIC state: redistributor registers and ICC sysregs combined.
///
/// Combining these prevents length mismatches — each vCPU always has
/// exactly one redistributor state and one ICC state.
#[derive(Clone, Debug)]
pub struct KvmGicPerCpuState {
    /// GICR (redistributor) registers.
    pub redist: KvmGicRedistState,
    /// ICC (CPU interface) system registers.
    pub icc: KvmGicIccState,
}

/// Per-vCPU GICR (redistributor) register state.
#[derive(Clone, Debug)]
pub struct KvmGicRedistState {
    /// `GICR_WAKER` — redistributor sleep/wake control.
    /// Bit 1 (`ProcessorSleep`): 1 = sleeping, 0 = awake.
    pub waker: u32,
    pub isenabler0: u32,
    pub ispendr0: u32,
    pub isactiver0: u32,
    /// `GICR_IPRIORITYR` — 8 u32s covering SGIs/PPIs 0-31 (4 bytes per u32).
    pub ipriorityr: [u32; 8],
    pub icfgr0: u32,
    pub icfgr1: u32,
    /// `GICR_IGROUPR0` — interrupt group for SGIs/PPIs (1 bit per IRQ).
    /// Linux uses Group 1; fresh GIC defaults to Group 0.
    pub igroupr0: u32,
}

/// Per-vCPU ICC (CPU interface) system register state.
#[derive(Clone, Debug)]
pub struct KvmGicIccState {
    /// ICC register values, indexed parallel to `ICC_REGS`.
    pub regs: [u64; NUM_ICC_REGS],
}

// ---------------------------------------------------------------------------
// Low-level KVM device helpers (only compiled for in-kernel GIC)
// ---------------------------------------------------------------------------

fn get_dist_reg(gic_fd: &DeviceFd, offset: u64) -> Result<u32> {
    let mut val: u32 = 0;
    let mut attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        attr: offset,
        addr: std::ptr::from_mut(&mut val) as u64,
        flags: 0,
    };
    // SAFETY: `addr` points to a valid `val` that lives for the duration of the ioctl.
    unsafe { gic_fd.get_device_attr(&mut attr) }
        .map_err(|e| VmmError::Config(format!("get GICD reg {offset:#x}: {e}")))?;
    Ok(val)
}

fn set_dist_reg(gic_fd: &DeviceFd, offset: u64, val: u32) -> Result<()> {
    let attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        attr: offset,
        addr: std::ptr::from_ref(&val) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&attr)
        .map_err(|e| VmmError::Config(format!("set GICD reg {offset:#x}: {e}")))?;
    Ok(())
}

fn get_dist_reg_u64(gic_fd: &DeviceFd, offset: u64) -> Result<u64> {
    let mut val: u64 = 0;
    let mut attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        attr: offset,
        addr: std::ptr::from_mut(&mut val) as u64,
        flags: 0,
    };
    // SAFETY: `addr` points to a valid `val` that lives for the duration of the ioctl.
    unsafe { gic_fd.get_device_attr(&mut attr) }
        .map_err(|e| VmmError::Config(format!("get GICD reg64 {offset:#x}: {e}")))?;
    Ok(val)
}

fn set_dist_reg_u64(gic_fd: &DeviceFd, offset: u64, val: u64) -> Result<()> {
    let attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_DIST_REGS,
        attr: offset,
        addr: std::ptr::from_ref(&val) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&attr)
        .map_err(|e| VmmError::Config(format!("set GICD reg64 {offset:#x}: {e}")))?;
    Ok(())
}

/// Encode MPIDR for a vCPU index (simple Aff0 = `vcpu_id` for < 256 vCPUs).
fn mpidr_for_vcpu(vcpu_id: usize) -> u64 {
    vcpu_id as u64
}

fn get_redist_reg(gic_fd: &DeviceFd, vcpu_id: usize, offset: u64) -> Result<u32> {
    let mpidr = mpidr_for_vcpu(vcpu_id);
    let mut val: u32 = 0;
    let mut attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        #[allow(clippy::cast_sign_loss)] // KVM_DEV_ARM_VGIC_V3_MPIDR_MASK is always non-negative
        attr: ((mpidr << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT) & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64)
            | offset,
        addr: std::ptr::from_mut(&mut val) as u64,
        flags: 0,
    };
    // SAFETY: `addr` points to a valid `val` that lives for the duration of the ioctl.
    unsafe { gic_fd.get_device_attr(&mut attr) }
        .map_err(|e| VmmError::Config(format!("get GICR reg {offset:#x} vcpu {vcpu_id}: {e}")))?;
    Ok(val)
}

fn set_redist_reg(gic_fd: &DeviceFd, vcpu_id: usize, offset: u64, val: u32) -> Result<()> {
    let mpidr = mpidr_for_vcpu(vcpu_id);
    let attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
        #[allow(clippy::cast_sign_loss)] // KVM_DEV_ARM_VGIC_V3_MPIDR_MASK is always non-negative
        attr: ((mpidr << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT) & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64)
            | offset,
        addr: std::ptr::from_ref(&val) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&attr)
        .map_err(|e| VmmError::Config(format!("set GICR reg {offset:#x} vcpu {vcpu_id}: {e}")))?;
    Ok(())
}

fn get_icc_reg(gic_fd: &DeviceFd, vcpu_id: usize, sysreg: u64) -> Result<u64> {
    let mpidr = mpidr_for_vcpu(vcpu_id);
    let mut val: u64 = 0;
    let mut attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        #[allow(clippy::cast_sign_loss)] // KVM_DEV_ARM_VGIC_V3_MPIDR_MASK is always non-negative
        attr: ((mpidr << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT) & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64)
            | sysreg,
        addr: std::ptr::from_mut(&mut val) as u64,
        flags: 0,
    };
    // SAFETY: `addr` points to a valid `val` that lives for the duration of the ioctl.
    unsafe { gic_fd.get_device_attr(&mut attr) }
        .map_err(|e| VmmError::Config(format!("get ICC reg {sysreg:#x} vcpu {vcpu_id}: {e}")))?;
    Ok(val)
}

fn set_icc_reg(gic_fd: &DeviceFd, vcpu_id: usize, sysreg: u64, val: u64) -> Result<()> {
    let mpidr = mpidr_for_vcpu(vcpu_id);
    let attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CPU_SYSREGS,
        #[allow(clippy::cast_sign_loss)] // KVM_DEV_ARM_VGIC_V3_MPIDR_MASK is always non-negative
        attr: ((mpidr << KVM_DEV_ARM_VGIC_V3_MPIDR_SHIFT) & KVM_DEV_ARM_VGIC_V3_MPIDR_MASK as u64)
            | sysreg,
        addr: std::ptr::from_ref(&val) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&attr)
        .map_err(|e| VmmError::Config(format!("set ICC reg {sysreg:#x} vcpu {vcpu_id}: {e}")))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Save (in-kernel GIC only)
// ---------------------------------------------------------------------------

/// Save the in-kernel `GICv3` state. All vCPUs must be stopped.
pub(crate) fn save_gic_state(gic_fd: &DeviceFd, num_vcpus: usize) -> Result<KvmGicState> {
    // Step 1: Flush pending tables so ISPENDR reflects true pending state.
    let attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_SAVE_PENDING_TABLES),
        addr: 0,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&attr)
        .map_err(|e| VmmError::Config(format!("SAVE_PENDING_TABLES: {e}")))?;

    // Step 2: Save GICD registers for SPIs (32..NR_IRQS).
    let dist_ctlr = get_dist_reg(gic_fd, GICD_CTLR)?;

    // Bitmap registers: one bit per IRQ, 32 per u32.
    // SPIs start at IRQ 32 (register index 1).
    let num_bitmap_regs = NR_IRQS.div_ceil(32) as usize;
    let mut dist_isenabler = Vec::with_capacity(num_bitmap_regs);
    let mut dist_ispendr = Vec::with_capacity(num_bitmap_regs);
    let mut dist_isactiver = Vec::with_capacity(num_bitmap_regs);
    for i in 1..num_bitmap_regs {
        dist_isenabler.push(get_dist_reg(gic_fd, GICD_ISENABLER + (i as u64) * 4)?);
        dist_ispendr.push(get_dist_reg(gic_fd, GICD_ISPENDR + (i as u64) * 4)?);
        dist_isactiver.push(get_dist_reg(gic_fd, GICD_ISACTIVER + (i as u64) * 4)?);
    }

    // Priority registers: one byte per IRQ, 4 per u32. SPIs start at byte 32.
    let num_prio_regs = NR_IRQS.div_ceil(4) as usize;
    let mut dist_ipriorityr = Vec::with_capacity(num_prio_regs);
    for i in 8..num_prio_regs {
        // Start at register 8 (byte offset 32 = SPI 32)
        dist_ipriorityr.push(get_dist_reg(gic_fd, GICD_IPRIORITYR + (i as u64) * 4)?);
    }

    // Config registers: 2 bits per IRQ, 16 per u32. SPIs start at register 2.
    let num_cfg_regs = NR_IRQS.div_ceil(16) as usize;
    let mut dist_icfgr = Vec::with_capacity(num_cfg_regs);
    for i in 2..num_cfg_regs {
        dist_icfgr.push(get_dist_reg(gic_fd, GICD_ICFGR + (i as u64) * 4)?);
    }

    // IROUTER: 8 bytes per SPI.
    let num_spis = (NR_IRQS - 32) as usize;
    let mut dist_irouter = Vec::with_capacity(num_spis);
    for i in 0..num_spis {
        dist_irouter.push(get_dist_reg_u64(gic_fd, GICD_IROUTER + (i as u64) * 8)?);
    }

    // IGROUPR: interrupt group (Group 0 vs Group 1). SPIs start at register 1.
    // Linux uses Group 1 for all interrupts — without saving this, a fresh GIC
    // defaults to Group 0, causing ENOSYS when delivering Group 1 interrupts.
    let mut dist_igroupr = Vec::with_capacity(num_bitmap_regs);
    for i in 1..num_bitmap_regs {
        dist_igroupr.push(get_dist_reg(gic_fd, GICD_IGROUPR + (i as u64) * 4)?);
    }

    // Step 3: Save GICR + ICC registers per vCPU.
    let mut per_cpu = Vec::with_capacity(num_vcpus);
    for vcpu_id in 0..num_vcpus {
        // GICR (redistributor)
        let waker = get_redist_reg(gic_fd, vcpu_id, GICR_WAKER)?;
        let isenabler0 = get_redist_reg(gic_fd, vcpu_id, GICR_ISENABLER0)?;
        let ispendr0 = get_redist_reg(gic_fd, vcpu_id, GICR_ISPENDR0)?;
        let isactiver0 = get_redist_reg(gic_fd, vcpu_id, GICR_ISACTIVER0)?;
        let mut ipriorityr = [0u32; 8];
        for (j, slot) in ipriorityr.iter_mut().enumerate() {
            *slot = get_redist_reg(gic_fd, vcpu_id, GICR_IPRIORITYR + (j as u64) * 4)?;
        }
        let icfgr0 = get_redist_reg(gic_fd, vcpu_id, GICR_ICFGR0)?;
        let icfgr1 = get_redist_reg(gic_fd, vcpu_id, GICR_ICFGR1)?;
        let igroupr0 = get_redist_reg(gic_fd, vcpu_id, GICR_IGROUPR0)?;

        // ICC (CPU interface sysregs).
        // AP0R1-3 and AP1R1-3 only exist when the GIC has enough
        // priority bits; EINVAL means the register is absent → treat as 0.
        let mut regs = [0u64; NUM_ICC_REGS];
        for (j, &sysreg) in ICC_REGS.iter().enumerate() {
            regs[j] = match get_icc_reg(gic_fd, vcpu_id, sysreg) {
                Ok(v) => v,
                Err(_) if is_optional_icc_reg(sysreg) => 0,
                Err(e) => return Err(e),
            };
        }

        per_cpu.push(KvmGicPerCpuState {
            redist: KvmGicRedistState {
                waker,
                isenabler0,
                ispendr0,
                isactiver0,
                ipriorityr,
                icfgr0,
                icfgr1,
                igroupr0,
            },
            icc: KvmGicIccState { regs },
        });
    }

    Ok(KvmGicState {
        dist_ctlr,
        dist_isenabler,
        dist_ispendr,
        dist_isactiver,
        dist_ipriorityr,
        dist_icfgr,
        dist_irouter,
        dist_igroupr,
        per_cpu,
    })
}

// ---------------------------------------------------------------------------
// Restore
// ---------------------------------------------------------------------------

/// Restore the in-kernel `GICv3` state. GIC must be initialized, all vCPUs stopped.
///
/// Restore order matters: ICC sysregs first (particularly `SRE_EL1`), then
/// redistributors, then distributor. CTLR is written last since enabling
/// the distributor while registers are inconsistent can cause spurious IRQs.
pub(crate) fn restore_gic_state(gic_fd: &DeviceFd, state: &KvmGicState) -> Result<()> {
    // Step 1: Restore ICC sysregs per vCPU (SRE_EL1 first to enable system register access).
    // Skip optional AP registers that don't exist on this implementation.
    for (vcpu_id, cpu) in state.per_cpu.iter().enumerate() {
        for (j, &sysreg) in ICC_REGS.iter().enumerate() {
            match set_icc_reg(gic_fd, vcpu_id, sysreg, cpu.icc.regs[j]) {
                Ok(()) => {}
                Err(_) if is_optional_icc_reg(sysreg) => {}
                Err(e) => return Err(e),
            }
        }
    }

    // Step 2: Restore GICR registers per vCPU.
    // WAKER first — controls redistributor sleep/wake state. Must be
    // restored before programming other GICR registers to ensure the
    // redistributor is in the correct active/sleep state.
    // IGROUPR0 next — sets interrupt group (Group 0 vs Group 1) before
    // enabling interrupts. Linux uses Group 1 for all interrupts including
    // the virtual timer PPI; a fresh GIC defaults to Group 0.
    for (vcpu_id, cpu) in state.per_cpu.iter().enumerate() {
        let r = &cpu.redist;
        set_redist_reg(gic_fd, vcpu_id, GICR_WAKER, r.waker)?;
        set_redist_reg(gic_fd, vcpu_id, GICR_IGROUPR0, r.igroupr0)?;
        set_redist_reg(gic_fd, vcpu_id, GICR_ICFGR0, r.icfgr0)?;
        set_redist_reg(gic_fd, vcpu_id, GICR_ICFGR1, r.icfgr1)?;
        for j in 0..8 {
            set_redist_reg(
                gic_fd,
                vcpu_id,
                GICR_IPRIORITYR + (j as u64) * 4,
                r.ipriorityr[j],
            )?;
        }
        set_redist_reg(gic_fd, vcpu_id, GICR_ISPENDR0, r.ispendr0)?;
        set_redist_reg(gic_fd, vcpu_id, GICR_ISACTIVER0, r.isactiver0)?;
        set_redist_reg(gic_fd, vcpu_id, GICR_ISENABLER0, r.isenabler0)?;
    }

    // Step 3: Restore GICD registers.
    // IGROUPR first — sets interrupt group (Group 0 vs Group 1) before
    // enabling SPIs. Linux uses Group 1; fresh GIC defaults to Group 0.
    for (i, &val) in state.dist_igroupr.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_IGROUPR + ((i + 1) as u64) * 4, val)?;
    }
    for (i, &val) in state.dist_icfgr.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_ICFGR + ((i + 2) as u64) * 4, val)?;
    }
    for (i, &val) in state.dist_ipriorityr.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_IPRIORITYR + ((i + 8) as u64) * 4, val)?;
    }
    for (i, &val) in state.dist_irouter.iter().enumerate() {
        set_dist_reg_u64(gic_fd, GICD_IROUTER + (i as u64) * 8, val)?;
    }
    for (i, &val) in state.dist_ispendr.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_ISPENDR + ((i + 1) as u64) * 4, val)?;
    }
    for (i, &val) in state.dist_isactiver.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_ISACTIVER + ((i + 1) as u64) * 4, val)?;
    }
    for (i, &val) in state.dist_isenabler.iter().enumerate() {
        set_dist_reg(gic_fd, GICD_ISENABLER + ((i + 1) as u64) * 4, val)?;
    }

    // CTLR last — enables the distributor after all state is consistent.
    if let Err(e) = set_dist_reg(gic_fd, GICD_CTLR, state.dist_ctlr) {
        log::warn!(
            "GICD_CTLR restore failed ({:#x}): {e} — GIC may be left disabled",
            state.dist_ctlr
        );
    }

    Ok(())
}

// ============================================================================
// KvmGicState <-> GicState conversion
// ============================================================================

use super::gic_pod::{GIC_PPI_SGI_COUNT, GIC_SPI_COUNT};

impl From<&KvmGicState> for super::gic_pod::GicState {
    #[allow(clippy::cast_possible_truncation)]
    fn from(kvm: &KvmGicState) -> Self {
        let mut state: super::gic_pod::GicState = bytemuck::Zeroable::zeroed();
        state.vcpu_count = kvm.per_cpu.len() as u32;

        // Distributor: unpack bitmap registers → per-SPI config/state
        state.distributor.ctlr = kvm.dist_ctlr;
        for spi in 0..GIC_SPI_COUNT {
            let reg_idx = spi / 32;
            let bit = spi % 32;

            // Enabled
            if reg_idx < kvm.dist_isenabler.len() {
                state.distributor.spi_config[spi].enabled =
                    u8::from(kvm.dist_isenabler[reg_idx] & (1 << bit) != 0);
            }
            // Group (1 = Group 1)
            if reg_idx < kvm.dist_igroupr.len() {
                state.distributor.spi_config[spi].group =
                    u8::from(kvm.dist_igroupr[reg_idx] & (1 << bit) != 0);
            }
            // Priority: 4 per u32, byte-packed
            let prio_reg = spi / 4;
            let prio_byte = spi % 4;
            if prio_reg < kvm.dist_ipriorityr.len() {
                state.distributor.spi_config[spi].priority =
                    (kvm.dist_ipriorityr[prio_reg] >> (prio_byte * 8)) as u8;
            }
            // Trigger: 2 bits per IRQ, 16 per u32 in ICFGR
            let cfg_reg = spi / 16;
            let cfg_shift = (spi % 16) * 2;
            if cfg_reg < kvm.dist_icfgr.len() {
                let field = (kvm.dist_icfgr[cfg_reg] >> cfg_shift) & 0x3;
                state.distributor.spi_config[spi].trigger = u8::from(field & 0x2 != 0);
            }

            // Pending
            if reg_idx < kvm.dist_ispendr.len() {
                state.distributor.spi_state[spi].pending =
                    u8::from(kvm.dist_ispendr[reg_idx] & (1 << bit) != 0);
            }
            // Active
            if reg_idx < kvm.dist_isactiver.len() {
                state.distributor.spi_state[spi].active =
                    u8::from(kvm.dist_isactiver[reg_idx] & (1 << bit) != 0);
            }
        }
        // Routers
        for (i, &route) in kvm.dist_irouter.iter().enumerate().take(GIC_SPI_COUNT) {
            state.distributor.irouter[i] = route;
        }

        // Per-CPU: redistributor + ICC
        for (cpu, kvm_cpu) in kvm.per_cpu.iter().enumerate() {
            if cpu >= state.redistributors.len() {
                break;
            }
            let redist = &mut state.redistributors[cpu];
            redist.waker = kvm_cpu.redist.waker;
            // Unpack SGI/PPI bitmaps (32 IRQs in one u32 each)
            for irq in 0..GIC_PPI_SGI_COUNT {
                let bit = irq;
                redist.ppi_sgi_config[irq].enabled =
                    u8::from(kvm_cpu.redist.isenabler0 & (1 << bit) != 0);
                redist.ppi_sgi_state[irq].pending =
                    u8::from(kvm_cpu.redist.ispendr0 & (1 << bit) != 0);
                redist.ppi_sgi_state[irq].active =
                    u8::from(kvm_cpu.redist.isactiver0 & (1 << bit) != 0);

                // Priority
                let prio_reg = irq / 4;
                let prio_byte = irq % 4;
                redist.ppi_sgi_config[irq].priority =
                    (kvm_cpu.redist.ipriorityr[prio_reg] >> (prio_byte * 8)) as u8;

                // Trigger from ICFGR0 (IRQs 0-15) and ICFGR1 (IRQs 16-31)
                let (cfg_reg, cfg_irq) = if irq < 16 {
                    (kvm_cpu.redist.icfgr0, irq)
                } else {
                    (kvm_cpu.redist.icfgr1, irq - 16)
                };
                let field = (cfg_reg >> (cfg_irq * 2)) & 0x3;
                redist.ppi_sgi_config[irq].trigger = u8::from(field & 0x2 != 0);

                // Group
                redist.ppi_sgi_config[irq].group =
                    u8::from(kvm_cpu.redist.igroupr0 & (1 << bit) != 0);
            }

            // ICC sysregs → CpuInterfaceState
            let icc = &mut state.cpu_interfaces[cpu];
            for (i, &sysreg) in ICC_REGS.iter().enumerate() {
                let val = kvm_cpu.icc.regs[i];
                match sysreg {
                    ICC_PMR_EL1 => icc.pmr = val as u8,
                    ICC_BPR0_EL1 => icc.bpr0 = val as u8,
                    ICC_BPR1_EL1 => icc.bpr1 = val as u8,
                    ICC_IGRPEN0_EL1 => icc.igrpen0 = val as u8,
                    ICC_IGRPEN1_EL1 => icc.igrpen1 = val as u8,
                    ICC_CTLR_EL1 => icc.eoi_mode = ((val >> 1) & 1) as u8,
                    x if x == ICC_AP0R_EL1_BASE => icc.ap0r[0] = val as u32,
                    x if x == ICC_AP0R_EL1_BASE + 1 => icc.ap0r[1] = val as u32,
                    x if x == ICC_AP0R_EL1_BASE + 2 => icc.ap0r[2] = val as u32,
                    x if x == ICC_AP0R_EL1_BASE + 3 => icc.ap0r[3] = val as u32,
                    x if x == ICC_AP1R_EL1_BASE => icc.ap1r[0] = val as u32,
                    x if x == ICC_AP1R_EL1_BASE + 1 => icc.ap1r[1] = val as u32,
                    x if x == ICC_AP1R_EL1_BASE + 2 => icc.ap1r[2] = val as u32,
                    x if x == ICC_AP1R_EL1_BASE + 3 => icc.ap1r[3] = val as u32,
                    _ => {} // SRE — fixed value, not modeled
                }
            }
        }

        state
    }
}

fn convert_per_cpu_to_kvm(
    redist: &super::gic_pod::GicRedistributorState,
    icc_state: &super::gic_pod::GicCpuInterfaceState,
) -> KvmGicPerCpuState {
    let mut isenabler0 = 0u32;
    let mut ispendr0 = 0u32;
    let mut isactiver0 = 0u32;
    let mut r_ipriorityr = [0u32; 8];
    let mut icfgr0 = 0u32;
    let mut icfgr1 = 0u32;
    let mut igroupr0 = 0u32;

    for irq in 0..GIC_PPI_SGI_COUNT {
        if redist.ppi_sgi_config[irq].enabled != 0 {
            isenabler0 |= 1 << irq;
        }
        if redist.ppi_sgi_state[irq].pending != 0 {
            ispendr0 |= 1 << irq;
        }
        if redist.ppi_sgi_state[irq].active != 0 {
            isactiver0 |= 1 << irq;
        }
        if redist.ppi_sgi_config[irq].group != 0 {
            igroupr0 |= 1 << irq;
        }

        r_ipriorityr[irq / 4] |= u32::from(redist.ppi_sgi_config[irq].priority) << ((irq % 4) * 8);

        if redist.ppi_sgi_config[irq].trigger != 0 {
            if irq < 16 {
                icfgr0 |= 0x2 << (irq * 2);
            } else {
                icfgr1 |= 0x2 << ((irq - 16) * 2);
            }
        }
    }

    let mut icc_regs = [0u64; NUM_ICC_REGS];
    for (i, &sysreg) in ICC_REGS.iter().enumerate() {
        icc_regs[i] = match sysreg {
            ICC_PMR_EL1 => u64::from(icc_state.pmr),
            ICC_BPR0_EL1 => u64::from(icc_state.bpr0),
            ICC_BPR1_EL1 => u64::from(icc_state.bpr1),
            ICC_IGRPEN0_EL1 => u64::from(icc_state.igrpen0),
            ICC_IGRPEN1_EL1 => u64::from(icc_state.igrpen1),
            ICC_CTLR_EL1 => u64::from(icc_state.eoi_mode) << 1,
            ICC_SRE_EL1 => 0x7,
            x if x == ICC_AP0R_EL1_BASE => u64::from(icc_state.ap0r[0]),
            x if x == ICC_AP0R_EL1_BASE + 1 => u64::from(icc_state.ap0r[1]),
            x if x == ICC_AP0R_EL1_BASE + 2 => u64::from(icc_state.ap0r[2]),
            x if x == ICC_AP0R_EL1_BASE + 3 => u64::from(icc_state.ap0r[3]),
            x if x == ICC_AP1R_EL1_BASE => u64::from(icc_state.ap1r[0]),
            x if x == ICC_AP1R_EL1_BASE + 1 => u64::from(icc_state.ap1r[1]),
            x if x == ICC_AP1R_EL1_BASE + 2 => u64::from(icc_state.ap1r[2]),
            x if x == ICC_AP1R_EL1_BASE + 3 => u64::from(icc_state.ap1r[3]),
            _ => 0,
        };
    }

    KvmGicPerCpuState {
        redist: KvmGicRedistState {
            waker: redist.waker,
            isenabler0,
            ispendr0,
            isactiver0,
            ipriorityr: r_ipriorityr,
            icfgr0,
            icfgr1,
            igroupr0,
        },
        icc: KvmGicIccState { regs: icc_regs },
    }
}

impl From<&super::gic_pod::GicState> for KvmGicState {
    #[allow(clippy::cast_possible_truncation)]
    fn from(state: &super::gic_pod::GicState) -> Self {
        let num_cpus = (state.vcpu_count as usize).min(state.redistributors.len());
        let num_bitmap_regs = GIC_SPI_COUNT.div_ceil(32);
        let num_prio_regs = GIC_SPI_COUNT.div_ceil(4);
        let num_cfg_regs = GIC_SPI_COUNT.div_ceil(16);

        let mut isenabler = vec![0u32; num_bitmap_regs];
        let mut ispendr = vec![0u32; num_bitmap_regs];
        let mut isactiver = vec![0u32; num_bitmap_regs];
        let mut ipriorityr = vec![0u32; num_prio_regs];
        let mut icfgr = vec![0u32; num_cfg_regs];
        let mut igroupr = vec![0u32; num_bitmap_regs];
        let mut irouter = vec![0u64; GIC_SPI_COUNT];

        for (spi, (cfg, st)) in state
            .distributor
            .spi_config
            .iter()
            .zip(state.distributor.spi_state.iter())
            .enumerate()
            .take(GIC_SPI_COUNT)
        {
            let reg_idx = spi / 32;
            let bit = spi % 32;

            if cfg.enabled != 0 {
                isenabler[reg_idx] |= 1 << bit;
            }
            if cfg.group != 0 {
                igroupr[reg_idx] |= 1 << bit;
            }
            if st.pending != 0 {
                ispendr[reg_idx] |= 1 << bit;
            }
            if st.active != 0 {
                isactiver[reg_idx] |= 1 << bit;
            }

            ipriorityr[spi / 4] |= u32::from(cfg.priority) << ((spi % 4) * 8);

            if cfg.trigger != 0 {
                icfgr[spi / 16] |= 0x2 << ((spi % 16) * 2);
            }

            irouter[spi] = state.distributor.irouter[spi];
        }

        let per_cpu = (0..num_cpus)
            .map(|cpu| {
                convert_per_cpu_to_kvm(&state.redistributors[cpu], &state.cpu_interfaces[cpu])
            })
            .collect();

        KvmGicState {
            dist_ctlr: state.distributor.ctlr,
            dist_isenabler: isenabler,
            dist_ispendr: ispendr,
            dist_isactiver: isactiver,
            dist_ipriorityr: ipriorityr,
            dist_icfgr: icfgr,
            dist_irouter: irouter,
            dist_igroupr: igroupr,
            per_cpu,
        }
    }
}
