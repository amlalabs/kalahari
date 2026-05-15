// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 KVM VM and vCPU setup/reset.
//!
//! Handles ARM64-specific VM initialization:
//! - `GICv3` interrupt controller via `KVM_CREATE_DEVICE`
//! - Per-vCPU initialization via `KVM_ARM_VCPU_INIT`

use kvm_bindings::{KVM_ARM_VCPU_PSCI_0_2, kvm_vcpu_init};
use kvm_bindings::{
    KVM_DEV_ARM_VGIC_CTRL_INIT, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_DEV_ARM_VGIC_GRP_CTRL,
    KVM_DEV_ARM_VGIC_GRP_NR_IRQS, KVM_VGIC_V3_ADDR_TYPE_DIST, KVM_VGIC_V3_ADDR_TYPE_REDIST,
    kvm_create_device, kvm_device_attr, kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
};

use kvm_ioctls::DeviceFd;
use kvm_ioctls::{Kvm, VcpuFd, VmFd};
use std::os::fd::AsRawFd;

use super::consts::{GIC_SPI_START_INTID, IRQ_LINE_COUNT};
use crate::error::{Result, VmmError};

/// Architecture-specific state returned by `setup_vcpus`.
pub(crate) type ArchSetupState = (kvm_vcpu_init, DeviceFd);

/// `GICv3` distributor base address (matching DTB in `amla-boot-arm64`).
const GICD_BASE: u64 = 0x0800_0000;

/// `GICv3` redistributor base address (matching DTB in `amla-boot-arm64`).
const GICR_BASE: u64 = 0x080A_0000;

/// Number of IRQ lines: 32 base (SGI+PPI) + `IRQ_LINE_COUNT` SPIs.
const NR_IRQS: u32 = GIC_SPI_START_INTID + IRQ_LINE_COUNT;

/// Initial device state captured after shell creation (ARM64).
///
/// With in-kernel GIC: stores the `GICv3` `DeviceFd` for register-level save/restore.
/// With userspace-gic: empty (no in-kernel GIC device).
pub struct InitialDeviceState {
    /// `GICv3` device fd. Used for register-level save/restore via
    /// `KVM_GET_DEVICE_ATTR` / `KVM_SET_DEVICE_ATTR`.
    gic_fd: DeviceFd,
}

impl std::fmt::Debug for InitialDeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialDeviceState").finish_non_exhaustive()
    }
}

impl InitialDeviceState {
    /// Get a reference to the GIC `DeviceFd` for state save/restore.
    pub(crate) fn gic_fd(&self) -> &DeviceFd {
        &self.gic_fd
    }
}

/// Create and configure the `GICv3` interrupt controller.
///
/// Returns the `DeviceFd` for the GIC (caller must keep it alive).
fn create_gic(vm_fd: &VmFd, nr_vcpus: usize) -> Result<DeviceFd> {
    // Create the GICv3 device
    let mut gic_device = kvm_create_device {
        type_: kvm_device_type_KVM_DEV_TYPE_ARM_VGIC_V3,
        fd: 0,
        flags: 0,
    };
    let gic_fd = vm_fd.create_device(&mut gic_device)?;

    // Set number of IRQs
    let nr_irqs = u64::from(NR_IRQS);
    let nr_irqs_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_NR_IRQS,
        attr: 0,
        addr: std::ptr::from_ref(&nr_irqs) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&nr_irqs_attr)
        .map_err(|e| VmmError::Config(format!("set GIC NR_IRQS: {e}")))?;

    // Set distributor address
    let dist_addr = GICD_BASE;
    let dist_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_DIST),
        addr: std::ptr::from_ref(&dist_addr) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&dist_attr)
        .map_err(|e| VmmError::Config(format!("set GIC dist addr: {e}")))?;

    // Set redistributor address (one per vCPU, contiguous)
    let redist_addr = GICR_BASE;
    let _ = nr_vcpus; // redistributor region auto-sizes based on nr_vcpus
    let redist_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_ADDR,
        attr: u64::from(KVM_VGIC_V3_ADDR_TYPE_REDIST),
        addr: std::ptr::from_ref(&redist_addr) as u64,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&redist_attr)
        .map_err(|e| VmmError::Config(format!("set GIC redist addr: {e}")))?;

    // Finalize GIC initialization
    let init_attr = kvm_device_attr {
        group: KVM_DEV_ARM_VGIC_GRP_CTRL,
        attr: u64::from(KVM_DEV_ARM_VGIC_CTRL_INIT),
        addr: 0,
        flags: 0,
    };
    gic_fd
        .set_device_attr(&init_attr)
        .map_err(|e| VmmError::Config(format!("GIC CTRL_INIT: {e}")))?;

    Ok(gic_fd)
}

/// Capture initial device state after VM and vCPU creation.
///
/// Stores the `GICv3` `DeviceFd` from `setup_vcpus` for state save/restore.
#[allow(clippy::unnecessary_wraps)] // signature must return Result for arch-neutral interface
pub(crate) fn capture_initial_state(
    _vm_fd: &VmFd,
    _vcpus: &[VcpuFd],
    arch_state: ArchSetupState,
) -> Result<InitialDeviceState> {
    let (_vcpu_init, gic_fd) = arch_state;
    Ok(InitialDeviceState { gic_fd })
}

/// Enable `KVM_CAP_ARM_NISV_TO_USER` so that data aborts with ISS Not Valid
/// are returned to userspace (as `KVM_EXIT_ARM_NISV`) instead of failing the
/// `KVM_RUN` ioctl with `-ENOSYS`.
///
/// Required on Apple Silicon and other CPUs that produce NISV for common
/// instructions (LDP/STP to device memory).
///
/// `kvm-ioctls` gates `VmFd::enable_cap()` with `#[cfg(not(aarch64))]`
/// because its doc-test lacked an arm64 example, but the ioctl is fully
/// supported on arm64 KVM.
fn enable_nisv_to_user(vm_fd: &VmFd) {
    // KVM_ENABLE_CAP ioctl number: _IOW(KVMIO, 0xa3, struct kvm_enable_cap)
    // KVMIO = 0xAE
    const KVMIO: libc::Ioctl = 0xAE;
    const KVM_ENABLE_CAP_NR: libc::Ioctl = 0xa3;
    let ioctl_nr: libc::Ioctl = 0x4000_0000 // _IOC_WRITE
        | ((std::mem::size_of::<kvm_bindings::kvm_enable_cap>() as libc::Ioctl & 0x3FFF) << 16)
        | (KVMIO << 8)
        | KVM_ENABLE_CAP_NR;

    let cap = kvm_bindings::kvm_enable_cap {
        cap: kvm_bindings::KVM_CAP_ARM_NISV_TO_USER,
        ..Default::default()
    };

    // SAFETY: vm_fd is a valid KVM VM file descriptor; cap is properly initialized.
    let ret = unsafe { libc::ioctl(vm_fd.as_raw_fd(), ioctl_nr, std::ptr::from_ref(&cap)) };
    if ret < 0 {
        log::warn!(
            "KVM_CAP_ARM_NISV_TO_USER not available: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Set up ARM64 VM-level KVM devices (pre-vCPU phase).
///
/// On ARM64, this enables `KVM_CAP_ARM_NISV_TO_USER`. `GICv3` creation
/// requires vCPUs to exist first (redistributors are per-vCPU), so it is
/// deferred to `setup_vcpus`.
#[allow(clippy::unnecessary_wraps)] // signature must return Result for arch-neutral interface
pub(crate) fn setup_vm(vm_fd: &VmFd) -> Result<()> {
    enable_nisv_to_user(vm_fd);
    Ok(())
}

/// Set up ARM64 vCPUs and `GICv3` interrupt controller.
///
/// ARM64 KVM requires this ordering:
/// 1. Create vCPUs (done by `Shell::new` before this call)
/// 2. Create `GICv3` device (redistributors map to existing vCPUs)
/// 3. Configure GIC addresses and finalize
/// 4. `KVM_ARM_VCPU_INIT` on each vCPU (PSCI 0.2 support)
pub(crate) fn setup_vcpus(_kvm: &Kvm, vm_fd: &VmFd, vcpus: &[VcpuFd]) -> Result<ArchSetupState> {
    // Default vcpu_init — returned as-is if no vCPUs exist.
    #[allow(clippy::field_reassign_with_default)] // features[0] requires indexed assignment
    let kvi = {
        let mut kvi = kvm_vcpu_init::default();
        kvi.target = 5; // KVM_ARM_TARGET_GENERIC_V8
        kvi.features[0] = 1 << KVM_ARM_VCPU_PSCI_0_2;
        kvi
    };

    // Step 1: Create GICv3 — must happen after vCPUs exist (redistributors are per-vCPU).
    let gic_fd = create_gic(vm_fd, std::cmp::max(vcpus.len(), 1))?;

    // Step 2: KVM_ARM_VCPU_INIT with PSCI 0.2 on each vCPU.
    for vcpu in vcpus {
        vcpu.vcpu_init(&kvi)?;
    }

    Ok((kvi, gic_fd))
}
