// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! GIC freeze/thaw to mmap'd `GicState`.
//!
//! Converts between the runtime types (`IrqConfig`, `IrqState`, `CpuInterface`)
//! and the fixed-size, repr(C)/Pod `GicState` in amla-vm-state.

use crate::pod_state::{
    GIC_MAX_ACTIVE_PRIORITIES, GIC_PPI_SGI_COUNT, GIC_SPI_COUNT, GicActivePriority,
    GicCpuInterfaceState, GicDistributorState, GicIrqConfig, GicIrqDynState, GicRedistributorState,
    GicState,
};

use crate::consts::{GICD_CTLR_RO_MASK, GICD_CTLR_RW_MASK, PRIORITY_IDLE, PRIORITY_MASK};
use crate::cpu_interface::CpuInterface;
use crate::distributor::Distributor;
use crate::irq_state::{IrqConfig, IrqState, TriggerMode};
use crate::redistributor::{Redistributor, RedistributorCpu};

// =============================================================================
// IrqConfig <-> GicIrqConfig
// =============================================================================

fn irq_config_to_pod(cfg: &IrqConfig) -> GicIrqConfig {
    GicIrqConfig {
        enabled: u8::from(cfg.enabled),
        group: u8::from(cfg.group),
        priority: cfg.priority,
        trigger: match cfg.trigger {
            TriggerMode::Level => 0,
            TriggerMode::Edge => 1,
        },
    }
}

const fn irq_config_from_pod(pod: GicIrqConfig) -> IrqConfig {
    IrqConfig {
        enabled: pod.enabled != 0,
        group: pod.group != 0,
        priority: pod.priority & PRIORITY_MASK,
        trigger: if pod.trigger != 0 {
            TriggerMode::Edge
        } else {
            TriggerMode::Level
        },
    }
}

// =============================================================================
// IrqState <-> GicIrqDynState
// =============================================================================

fn irq_state_to_pod(st: &IrqState) -> GicIrqDynState {
    GicIrqDynState {
        pending: u8::from(st.pending),
        active: u8::from(st.active),
        edge_latch: u8::from(st.edge_latch),
        hw_level: u8::from(st.hw_level),
    }
}

const fn irq_state_from_pod(pod: GicIrqDynState) -> IrqState {
    IrqState {
        pending: pod.pending != 0,
        active: pod.active != 0,
        edge_latch: pod.edge_latch != 0,
        hw_level: pod.hw_level != 0,
    }
}

// =============================================================================
// Distributor
// =============================================================================

pub(crate) fn freeze_distributor(dist: &Distributor) -> GicDistributorState {
    let mut out = GicDistributorState {
        ctlr: dist.ctlr(),
        pad: 0,
        spi_config: [GicIrqConfig {
            enabled: 0,
            group: 0,
            priority: 0,
            trigger: 0,
        }; GIC_SPI_COUNT],
        spi_state: [GicIrqDynState {
            pending: 0,
            active: 0,
            edge_latch: 0,
            hw_level: 0,
        }; GIC_SPI_COUNT],
        irouter: [0u64; GIC_SPI_COUNT],
    };
    let n = dist.nr_spis().min(GIC_SPI_COUNT);
    for i in 0..n {
        out.spi_config[i] = irq_config_to_pod(&dist.spi_cfg()[i]);
        out.spi_state[i] = irq_state_to_pod(&dist.spi_st()[i]);
        out.irouter[i] = dist.irouter(i);
    }
    out
}

pub(crate) fn thaw_distributor(dist: &mut Distributor, pod: &GicDistributorState) {
    dist.set_ctlr((pod.ctlr & GICD_CTLR_RW_MASK) | GICD_CTLR_RO_MASK);
    let n = dist.nr_spis().min(GIC_SPI_COUNT);
    for i in 0..n {
        dist.spi_cfg_mut()[i] = irq_config_from_pod(pod.spi_config[i]);
        dist.spi_st_mut()[i] = irq_state_from_pod(pod.spi_state[i]);
        dist.set_irouter(i, pod.irouter[i]);
    }
    // Reset tail entries beyond snapshot to defaults.
    for i in n..dist.nr_spis() {
        dist.spi_cfg_mut()[i] = IrqConfig::default();
        dist.spi_st_mut()[i] = IrqState::default();
        dist.set_irouter(i, 0);
    }
}

// =============================================================================
// Redistributor
// =============================================================================

pub(crate) fn freeze_redistributor(cpu: &RedistributorCpu) -> GicRedistributorState {
    let mut out = GicRedistributorState {
        waker: cpu.waker,
        pad: 0,
        ppi_sgi_config: [GicIrqConfig {
            enabled: 0,
            group: 0,
            priority: 0,
            trigger: 0,
        }; GIC_PPI_SGI_COUNT],
        ppi_sgi_state: [GicIrqDynState {
            pending: 0,
            active: 0,
            edge_latch: 0,
            hw_level: 0,
        }; GIC_PPI_SGI_COUNT],
    };
    for i in 0..GIC_PPI_SGI_COUNT {
        out.ppi_sgi_config[i] = irq_config_to_pod(&cpu.ppi_sgi_config[i]);
        out.ppi_sgi_state[i] = irq_state_to_pod(&cpu.ppi_sgi_state[i]);
    }
    out
}

pub(crate) fn thaw_redistributor(cpu: &mut RedistributorCpu, pod: &GicRedistributorState) {
    cpu.waker = pod.waker;
    for i in 0..GIC_PPI_SGI_COUNT {
        cpu.ppi_sgi_config[i] = irq_config_from_pod(pod.ppi_sgi_config[i]);
        cpu.ppi_sgi_state[i] = irq_state_from_pod(pod.ppi_sgi_state[i]);
    }
}

// =============================================================================
// CPU Interface
// =============================================================================

#[allow(clippy::cast_possible_truncation)] // count bounded by GIC_MAX_ACTIVE_PRIORITIES (16)
pub(crate) fn freeze_cpu_interface(ci: &CpuInterface) -> GicCpuInterfaceState {
    let ci = ci.snapshot();
    let active = ci.active_priorities.as_slice();
    let count = active.len().min(GIC_MAX_ACTIVE_PRIORITIES);
    let mut priorities = [GicActivePriority {
        priority: 0,
        pad: [0; 3],
        intid: 0,
    }; GIC_MAX_ACTIVE_PRIORITIES];
    for (i, &(prio, intid)) in active.iter().take(count).enumerate() {
        priorities[i] = GicActivePriority {
            priority: prio,
            pad: [0; 3],
            intid,
        };
    }
    GicCpuInterfaceState {
        pmr: ci.pmr,
        bpr0: 0, // Group 0 not modeled in userspace GIC (single security state)
        bpr1: ci.bpr1,
        igrpen0: 0, // Group 0 not modeled in userspace GIC
        igrpen1: u8::from(ci.igrpen1),
        eoi_mode: u8::from(ci.eoi_mode),
        running_priority: ci.running_priority,
        #[allow(clippy::cast_possible_truncation)] // count bounded by GIC_MAX_ACTIVE_PRIORITIES (16)
        active_priority_count: count as u8,
        ap0r: ci.ap0r,
        ap1r: ci.ap1r,
        active_priorities: priorities,
    }
}

pub(crate) fn thaw_cpu_interface(
    ci: &CpuInterface,
    pod: &GicCpuInterfaceState,
) -> Result<(), amla_core::VmmError> {
    validate_cpu_interface_pod(pod)?;
    let count = pod.active_priority_count as usize;
    let active: Vec<(u8, u32)> = pod.active_priorities[..count]
        .iter()
        .map(|ap| (ap.priority & PRIORITY_MASK, ap.intid))
        .collect();
    let running = if let Some(&(priority, _)) = active.last() {
        priority
    } else {
        PRIORITY_IDLE
    };
    ci.restore_from_pod(
        pod.pmr & PRIORITY_MASK,
        pod.bpr1 & 0x7,
        pod.igrpen1 != 0,
        pod.eoi_mode != 0,
        running,
        active,
        pod.ap0r,
        pod.ap1r,
    );
    Ok(())
}

fn validate_cpu_interface_pod(pod: &GicCpuInterfaceState) -> Result<(), amla_core::VmmError> {
    if pod.bpr0 != 0 || pod.igrpen0 != 0 {
        return Err(amla_core::VmmError::DeviceConfig(format!(
            "GIC snapshot contains Group 0 CPU-interface state (bpr0={:#x}, igrpen0={:#x}) but Group 0 is not modeled",
            pod.bpr0, pod.igrpen0
        )));
    }
    let count = pod.active_priority_count as usize;
    if count > GIC_MAX_ACTIVE_PRIORITIES {
        return Err(amla_core::VmmError::DeviceConfig(format!(
            "GIC snapshot active_priority_count {count} exceeds max {GIC_MAX_ACTIVE_PRIORITIES}"
        )));
    }

    let expected_running_priority = if count == 0 {
        if pod.ap0r != [0; 4] || pod.ap1r != [0; 4] {
            return Err(amla_core::VmmError::DeviceConfig(
                "GIC snapshot contains AP register state without an active-priority stack"
                    .to_string(),
            ));
        }
        PRIORITY_IDLE
    } else {
        pod.active_priorities[count - 1].priority
    };
    if pod.running_priority != expected_running_priority {
        return Err(amla_core::VmmError::DeviceConfig(format!(
            "GIC snapshot running_priority {:#x} does not match active-priority stack {:#x}",
            pod.running_priority, expected_running_priority
        )));
    }

    for (idx, active) in pod.active_priorities.iter().enumerate() {
        if active.pad != [0; 3] {
            return Err(amla_core::VmmError::DeviceConfig(format!(
                "GIC snapshot active priority entry {idx} has nonzero padding"
            )));
        }
        if idx < count {
            if active.priority & PRIORITY_MASK != active.priority {
                return Err(amla_core::VmmError::DeviceConfig(format!(
                    "GIC snapshot active priority entry {idx} has noncanonical priority {:#x}",
                    active.priority
                )));
            }
        } else if active.priority != 0 || active.intid != 0 {
            return Err(amla_core::VmmError::DeviceConfig(format!(
                "GIC snapshot active priority tail entry {idx} is not zero"
            )));
        }
    }

    Ok(())
}

// =============================================================================
// Full GIC freeze/thaw
// =============================================================================

/// Freeze entire GIC state into a `GicState`.
#[allow(clippy::cast_possible_truncation)] // vcpu_count and active_priority_count bounded by GIC limits
pub(crate) fn freeze_gic(
    dist: &Distributor,
    redist: &Redistributor,
    cpu_interfaces: &[CpuInterface],
    num_vcpus: usize,
) -> GicState {
    let mut state = bytemuck::Zeroable::zeroed();
    let gs: &mut GicState = &mut state;
    #[allow(clippy::cast_possible_truncation)] // num_vcpus bounded by MAX_VCPUS
    {
        gs.vcpu_count = num_vcpus as u32;
    }
    gs.distributor = freeze_distributor(dist);
    for i in 0..num_vcpus.min(gs.redistributors.len()) {
        if let Some(cpu) = redist.cpu(i) {
            gs.redistributors[i] = freeze_redistributor(cpu);
        }
    }
    for (i, ci) in cpu_interfaces.iter().enumerate() {
        if i < gs.cpu_interfaces.len() {
            gs.cpu_interfaces[i] = freeze_cpu_interface(ci);
        }
    }
    state
}

/// Thaw entire GIC state from a `GicState`.
pub(crate) fn thaw_gic(
    dist: &mut Distributor,
    redist: &mut Redistributor,
    cpu_interfaces: &[CpuInterface],
    state: &GicState,
    num_vcpus: usize,
) -> Result<(), amla_core::VmmError> {
    if state.vcpu_count as usize != num_vcpus {
        return Err(amla_core::VmmError::DeviceConfig(format!(
            "GIC snapshot vCPU count {} does not match VM vCPU count {num_vcpus}",
            state.vcpu_count
        )));
    }
    if num_vcpus > state.redistributors.len()
        || num_vcpus > state.cpu_interfaces.len()
        || num_vcpus > cpu_interfaces.len()
    {
        return Err(amla_core::VmmError::DeviceConfig(format!(
            "GIC snapshot vCPU count {num_vcpus} exceeds compiled/runtime limits"
        )));
    }
    for i in 0..num_vcpus {
        if redist.cpu(i).is_none() {
            return Err(amla_core::VmmError::DeviceConfig(format!(
                "GIC redistributor missing vCPU {i}"
            )));
        }
        validate_cpu_interface_pod(&state.cpu_interfaces[i])?;
    }
    thaw_distributor(dist, &state.distributor);
    for i in 0..num_vcpus {
        let cpu = redist.cpu_mut(i).ok_or_else(|| {
            amla_core::VmmError::DeviceConfig(format!("GIC redistributor missing vCPU {i}"))
        })?;
        thaw_redistributor(cpu, &state.redistributors[i]);
    }
    for (i, ci) in cpu_interfaces.iter().enumerate().take(num_vcpus) {
        thaw_cpu_interface(ci, &state.cpu_interfaces[i])?;
    }
    Ok(())
}
