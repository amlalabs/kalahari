// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! `GICv3` CPU Interface (ICC) — per-vCPU system register handling.
//!
//! The CPU interface is accessed via MSR/MRS instructions trapped as sysreg exits.
//! Each vCPU has its own CPU interface state.

use parking_lot::Mutex;

use crate::GicV3;
use crate::consts::{
    ICC_AP0R0_EL1, ICC_AP0R1_EL1, ICC_AP0R2_EL1, ICC_AP0R3_EL1, ICC_AP1R0_EL1, ICC_AP1R1_EL1,
    ICC_AP1R2_EL1, ICC_AP1R3_EL1, ICC_BPR1_EL1, ICC_CTLR_EL1, ICC_CTLR_PRI_BITS, ICC_DIR_EL1,
    ICC_EOIR1_EL1, ICC_HPPIR1_EL1, ICC_IAR1_EL1, ICC_IGRPEN1_EL1, ICC_PMR_EL1, ICC_RPR_EL1,
    ICC_SGI1R_EL1, ICC_SRE_EL1, ICC_SRE_EL1_VAL, INTID_SPECIAL_START, INTID_SPURIOUS,
    PRIORITY_IDLE, PRIORITY_MASK, SPI_START,
};
use crate::irq_state::TriggerMode;
use crate::priority::PriorityEngine;

/// Per-vCPU CPU interface state.
pub struct CpuInterface {
    inner: Mutex<CpuInterfaceInner>,
}

pub struct CpuInterfaceSnapshot {
    pub(crate) pmr: u8,
    pub(crate) bpr1: u8,
    pub(crate) igrpen1: bool,
    pub(crate) eoi_mode: bool,
    pub(crate) running_priority: u8,
    pub(crate) active_priorities: Vec<(u8, u32)>,
    pub(crate) ap0r: [u32; 4],
    pub(crate) ap1r: [u32; 4],
}

struct CpuInterfaceInner {
    pmr: u8,
    bpr1: u8,
    igrpen1: bool,
    eoi_mode: bool,
    running_priority: u8,
    active_priorities: Vec<(u8, u32)>,
    ap0r: [u32; 4],
    ap1r: [u32; 4],
}

impl Default for CpuInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuInterface {
    pub(crate) const fn new() -> Self {
        Self {
            inner: Mutex::new(CpuInterfaceInner {
                pmr: PRIORITY_IDLE & PRIORITY_MASK,
                bpr1: 0,
                igrpen1: false,
                eoi_mode: false,
                running_priority: PRIORITY_IDLE,
                active_priorities: Vec::new(),
                ap0r: [0; 4],
                ap1r: [0; 4],
            }),
        }
    }

    pub(crate) fn pmr(&self) -> u8 {
        self.inner.lock().pmr
    }

    pub(crate) fn running_priority(&self) -> u8 {
        self.inner.lock().running_priority
    }

    pub(crate) fn igrpen1(&self) -> bool {
        self.inner.lock().igrpen1
    }

    pub(crate) fn bpr1(&self) -> u8 {
        self.inner.lock().bpr1
    }

    pub(crate) fn snapshot(&self) -> CpuInterfaceSnapshot {
        let ci = self.inner.lock();
        CpuInterfaceSnapshot {
            pmr: ci.pmr,
            bpr1: ci.bpr1,
            igrpen1: ci.igrpen1,
            eoi_mode: ci.eoi_mode,
            running_priority: ci.running_priority,
            active_priorities: ci.active_priorities.clone(),
            ap0r: ci.ap0r,
            ap1r: ci.ap1r,
        }
    }

    /// Restore CPU interface state from Pod fields (used by thaw).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn restore_from_pod(
        &self,
        pmr: u8,
        bpr1: u8,
        igrpen1: bool,
        eoi_mode: bool,
        running_priority: u8,
        active_priorities: Vec<(u8, u32)>,
        ap0r: [u32; 4],
        ap1r: [u32; 4],
    ) {
        let mut ci = self.inner.lock();
        ci.pmr = pmr;
        ci.bpr1 = bpr1;
        ci.igrpen1 = igrpen1;
        ci.eoi_mode = eoi_mode;
        ci.running_priority = running_priority;
        ci.active_priorities = active_priorities;
        ci.ap0r = ap0r;
        ci.ap1r = ap1r;
    }

    /// Reset CPU interface state to construction defaults (used by thaw tail reset).
    pub(crate) fn reset(&self) {
        self.restore_from_pod(
            PRIORITY_IDLE & PRIORITY_MASK,
            0,
            false,
            false,
            PRIORITY_IDLE,
            Vec::new(),
            [0; 4],
            [0; 4],
        );
    }

    /// Handle a system register read (MRS).
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn handle_read(&self, encoding: u32, vcpu_id: usize, gic: &GicV3) -> u64 {
        let mut ci = self.inner.lock();
        match encoding {
            ICC_IAR1_EL1 => acknowledge_irq(&mut ci, vcpu_id, gic),
            ICC_HPPIR1_EL1 => highest_pending_intid(vcpu_id, gic),
            ICC_RPR_EL1 => u64::from(ci.running_priority),
            ICC_PMR_EL1 => u64::from(ci.pmr),
            ICC_BPR1_EL1 => u64::from(ci.bpr1),
            ICC_CTLR_EL1 => read_ctlr(&ci),
            ICC_SRE_EL1 => ICC_SRE_EL1_VAL,
            ICC_IGRPEN1_EL1 => u64::from(ci.igrpen1),

            ICC_AP1R0_EL1 => u64::from(ci.ap1r[0]),
            ICC_AP1R1_EL1 => u64::from(ci.ap1r[1]),
            ICC_AP1R2_EL1 => u64::from(ci.ap1r[2]),
            ICC_AP1R3_EL1 => u64::from(ci.ap1r[3]),
            ICC_AP0R0_EL1 => u64::from(ci.ap0r[0]),
            ICC_AP0R1_EL1 => u64::from(ci.ap0r[1]),
            ICC_AP0R2_EL1 => u64::from(ci.ap0r[2]),
            ICC_AP0R3_EL1 => u64::from(ci.ap0r[3]),

            _ => {
                log::warn!("ICC read unknown encoding={encoding:#x} vcpu={vcpu_id}");
                0
            }
        }
    }

    /// Handle a system register write (MSR).
    ///
    /// Returns vCPU IDs that need delivery re-evaluation. The caller MUST
    /// sync atomic mirrors (`sync_cpu_interface_atoms`) before evaluating
    /// delivery, to avoid reading stale `PMR`/`running_priority` values.
    #[allow(clippy::cast_possible_truncation)]
    // MMIO register decode: values bounded by architecture
    // Reason: lock guard intentionally spans the body so the dispatch
    // observes a single consistent inner-state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn handle_write(
        &self,
        encoding: u32,
        value: u64,
        vcpu_id: usize,
        gic: &GicV3,
    ) -> Vec<usize> {
        let mut ci = self.inner.lock();
        match encoding {
            ICC_EOIR1_EL1 => return end_of_interrupt(&mut ci, value as u32, vcpu_id, gic),
            ICC_DIR_EL1 => {
                if value as u32 >= INTID_SPECIAL_START {
                    return vec![];
                }
                do_deactivate(value as u32, vcpu_id, gic);
                return vec![vcpu_id];
            }
            ICC_SGI1R_EL1 => return send_sgi(value, vcpu_id, gic),

            ICC_PMR_EL1 => {
                ci.pmr = (value as u8) & PRIORITY_MASK;
                return vec![vcpu_id];
            }
            ICC_BPR1_EL1 => {
                ci.bpr1 = (value & 0x7) as u8;
                return vec![vcpu_id];
            }
            ICC_CTLR_EL1 => {
                ci.eoi_mode = value & (1 << 1) != 0;
            }
            ICC_SRE_EL1 => {
                // Writes accepted but SRE must never read as 0
            }
            ICC_IGRPEN1_EL1 => {
                ci.igrpen1 = value & 1 != 0;
                return vec![vcpu_id];
            }

            ICC_AP1R0_EL1 => ci.ap1r[0] = value as u32,
            ICC_AP1R1_EL1 => ci.ap1r[1] = value as u32,
            ICC_AP1R2_EL1 => ci.ap1r[2] = value as u32,
            ICC_AP1R3_EL1 => ci.ap1r[3] = value as u32,
            ICC_AP0R0_EL1 => ci.ap0r[0] = value as u32,
            ICC_AP0R1_EL1 => ci.ap0r[1] = value as u32,
            ICC_AP0R2_EL1 => ci.ap0r[2] = value as u32,
            ICC_AP0R3_EL1 => ci.ap0r[3] = value as u32,

            _ => {
                log::warn!(
                    "ICC write unknown encoding={encoding:#x} value={value:#x} vcpu={vcpu_id}"
                );
            }
        }
        vec![]
    }

    // (All ICC helper methods moved to free functions below to avoid
    // re-entrant self.inner() calls — see acknowledge_irq, end_of_interrupt,
    // read_ctlr.)
}

// =============================================================================
// Free functions (no &self needed)
// =============================================================================

// =============================================================================
// IAR (Acknowledge)
// =============================================================================

// Reason: lock guard intentionally spans the body so the operation
// observes a single consistent state snapshot.
#[allow(clippy::significant_drop_tightening)]
fn acknowledge_irq(ci: &mut CpuInterfaceInner, vcpu_id: usize, gic: &GicV3) -> u64 {
    let Some((intid, priority)) = PriorityEngine::highest_pending(vcpu_id, gic) else {
        return u64::from(INTID_SPURIOUS);
    };

    // Transition state: pending -> active
    if intid < SPI_START {
        let mut redist = gic.redistributor().lock();
        if let Some(cpu) = redist.cpu_mut(vcpu_id) {
            let idx = intid as usize;
            let trigger = cpu.ppi_sgi_config[idx].trigger;
            let st = &mut cpu.ppi_sgi_state[idx];
            st.active = true;
            st.edge_latch = false;
            match trigger {
                TriggerMode::Edge => st.pending = false,
                TriggerMode::Level => {
                    if !st.hw_level {
                        st.pending = false;
                    }
                }
            }
        }
    } else {
        let spi_idx = (intid - SPI_START) as usize;
        let mut dist = gic.distributor().write();
        if spi_idx < dist.spi_state.len() {
            let trigger = dist.spi_config[spi_idx].trigger;
            let st = &mut dist.spi_state[spi_idx];
            st.active = true;
            st.edge_latch = false;
            match trigger {
                TriggerMode::Edge => st.pending = false,
                TriggerMode::Level => {
                    if !st.hw_level {
                        st.pending = false;
                    }
                }
            }
        }
    }

    ci.active_priorities.push((priority, intid));
    ci.running_priority = priority;

    u64::from(intid)
}

// =============================================================================
// EOIR (End of Interrupt)
// =============================================================================

fn end_of_interrupt(
    ci: &mut CpuInterfaceInner,
    intid: u32,
    vcpu_id: usize,
    gic: &GicV3,
) -> Vec<usize> {
    if intid >= INTID_SPECIAL_START {
        return vec![];
    }

    let Some(pos) = ci
        .active_priorities
        .iter()
        .rposition(|(_, id)| *id == intid)
    else {
        log::warn!("EOIR for non-active INTID {intid} on vcpu {vcpu_id}");
        return vec![];
    };

    if pos != ci.active_priorities.len() - 1 {
        log::warn!("Out-of-order EOIR: INTID {intid} is not top of stack on vcpu {vcpu_id}");
    }

    ci.active_priorities.remove(pos);
    ci.running_priority = ci
        .active_priorities
        .last()
        .map_or(PRIORITY_IDLE, |(p, _)| *p);

    if !ci.eoi_mode {
        // EOImode=0: combined drop + deactivate
        do_deactivate(intid, vcpu_id, gic);
    }

    vec![vcpu_id]
}

// =============================================================================
// ICC_CTLR_EL1
// =============================================================================

fn read_ctlr(ci: &CpuInterfaceInner) -> u64 {
    let mut val = ICC_CTLR_PRI_BITS;
    if ci.eoi_mode {
        val |= 1 << 1;
    }
    u64::from(val)
}

/// Actually deactivate an interrupt (clear active, handle level retrigger).
// Reason: lock guard intentionally spans the body so the operation
// observes a single consistent state snapshot.
#[allow(clippy::significant_drop_tightening)]
fn do_deactivate(intid: u32, vcpu_id: usize, gic: &GicV3) {
    if intid < SPI_START {
        let mut redist = gic.redistributor().lock();
        if let Some(cpu) = redist.cpu_mut(vcpu_id) {
            let idx = intid as usize;
            if !cpu.ppi_sgi_state[idx].active {
                log::warn!("DIR/deactivate for non-active SGI/PPI {intid} on vcpu {vcpu_id}");
                return;
            }
            let trigger = cpu.ppi_sgi_config[idx].trigger;
            let st = &mut cpu.ppi_sgi_state[idx];
            st.active = false;
            if trigger == TriggerMode::Level && st.hw_level {
                st.pending = true;
            }
        }
    } else {
        let spi_idx = (intid - SPI_START) as usize;
        let mut dist = gic.distributor().write();
        if spi_idx < dist.spi_state.len() {
            if !dist.spi_state[spi_idx].active {
                log::warn!("DIR/deactivate for non-active SPI {intid} on vcpu {vcpu_id}");
                return;
            }
            let trigger = dist.spi_config[spi_idx].trigger;
            let st = &mut dist.spi_state[spi_idx];
            st.active = false;
            if trigger == TriggerMode::Level && st.hw_level {
                st.pending = true;
            }
        }
    }
}

/// Peek at the highest pending interrupt INTID without side effects.
fn highest_pending_intid(vcpu_id: usize, gic: &GicV3) -> u64 {
    PriorityEngine::highest_pending(vcpu_id, gic)
        .map_or_else(|| u64::from(INTID_SPURIOUS), |(intid, _)| u64::from(intid))
}

/// Handle `ICC_SGI1R_EL1` write (Send SGI).
///
/// Returns affected vCPU IDs that need delivery re-evaluation.
fn send_sgi(value: u64, source_vcpu: usize, gic: &GicV3) -> Vec<usize> {
    let target_list = (value & 0xFFFF) as u16;
    let aff1 = ((value >> 16) & 0xFF) as usize;
    let intid = ((value >> 24) & 0xF) as u32;
    let aff2 = ((value >> 32) & 0xFF) as usize;
    let irm = (value >> 40) & 1;
    let rs = ((value >> 44) & 0xF) as usize;
    let aff3 = ((value >> 48) & 0xFF) as usize;

    let num_vcpus = gic.num_vcpus();
    let mut targets = Vec::new();

    if irm == 1 {
        for i in 0..num_vcpus {
            if i != source_vcpu {
                targets.push(i);
            }
        }
    } else {
        for bit in 0u32..16 {
            if target_list & (1 << bit) != 0 {
                let aff0 = rs * 16 + bit as usize;
                for target in 0..num_vcpus {
                    if vcpu_matches_affinity(target, aff3, aff2, aff1, aff0) {
                        targets.push(target);
                    }
                }
            }
        }
    }

    // Inject SGI under lock, collect affected vCPUs. The block value is
    // returned after releasing the redistributor lock.
    {
        let mut redist = gic.redistributor().lock();
        redist.inject_sgi(intid, source_vcpu, &targets)
    }
}

const fn vcpu_matches_affinity(
    vcpu_id: usize,
    aff3: usize,
    aff2: usize,
    aff1: usize,
    aff0: usize,
) -> bool {
    ((vcpu_id >> 24) & 0xFF) == aff3
        && ((vcpu_id >> 16) & 0xFF) == aff2
        && ((vcpu_id >> 8) & 0xFF) == aff1
        && (vcpu_id & 0xFF) == aff0
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::consts::*;
    use crate::{GicConfig, NullInterruptSink};

    fn make_gic(num_vcpus: usize) -> GicV3 {
        GicV3::new(
            GicConfig {
                num_vcpus,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        )
    }

    #[test]
    fn initial_state() {
        let ci = CpuInterface::new();
        assert_eq!(ci.pmr(), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(ci.running_priority(), PRIORITY_IDLE);
        assert!(!ci.igrpen1());
        assert_eq!(ci.bpr1(), 0);
    }

    #[test]
    fn sre_always_returns_7() {
        let gic = make_gic(1);
        let val = gic.handle_sysreg_read(0, ICC_SRE_EL1);
        assert_eq!(val, 0x7);
        gic.handle_sysreg_write(0, ICC_SRE_EL1, 0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_SRE_EL1), 0x7);
    }

    #[test]
    fn pmr_readwrite() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_PMR_EL1), 0xF0);
    }

    #[test]
    fn igrpen1_readwrite() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        assert_eq!(gic.handle_sysreg_read(0, ICC_IGRPEN1_EL1), 1);
    }

    #[test]
    fn ctlr_eoimode() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2);
        let val = gic.handle_sysreg_read(0, ICC_CTLR_EL1);
        assert_ne!(val & 0x2, 0);
        assert_ne!(val & 0x700, 0);
    }

    #[test]
    fn iar_spurious_when_nothing_pending() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    #[test]
    fn iar_spurious_when_group_disabled() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    #[test]
    fn eoir_ignores_special_intids() {
        let gic = make_gic(1);
        for id in 1020u32..=1023 {
            gic.handle_sysreg_write(0, ICC_EOIR1_EL1, u64::from(id));
        }
    }

    #[test]
    fn dir_ignores_special_intids() {
        let gic = make_gic(1);
        for id in 1020u32..=1023 {
            gic.handle_sysreg_write(0, ICC_DIR_EL1, u64::from(id));
        }
    }

    #[test]
    fn hppir_spurious_when_idle() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_HPPIR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    #[test]
    fn ap_registers_readwrite() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_AP1R0_EL1, 0xDEAD_BEEF);
        assert_eq!(gic.handle_sysreg_read(0, ICC_AP1R0_EL1), 0xDEAD_BEEF);
        gic.handle_sysreg_write(0, ICC_AP0R0_EL1, 0xCAFE_BABE);
        assert_eq!(gic.handle_sysreg_read(0, ICC_AP0R0_EL1), 0xCAFE_BABE);
    }

    #[test]
    // Reason: lock guard scope intentionally spans the assertion
    // block to observe a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn sgi_delivery_irm0() {
        let gic = make_gic(4);
        for i in 0..4 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }
        {
            let mut r = gic.redistributor().lock();
            r.cpu_mut(1).unwrap().ppi_sgi_config[3].enabled = true;
            r.cpu_mut(2).unwrap().ppi_sgi_config[3].enabled = true;
        }
        let sgi_val = (3u64 << 24) | 0b0110;
        gic.handle_sysreg_write(0, ICC_SGI1R_EL1, sgi_val);

        let r = gic.redistributor().lock();
        assert!(r.cpu(1).unwrap().ppi_sgi_state[3].pending);
        assert!(r.cpu(2).unwrap().ppi_sgi_state[3].pending);
        assert!(!r.cpu(0).unwrap().ppi_sgi_state[3].pending);
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn sgi_delivery_irm0_respects_range_selector() {
        let gic = make_gic(20);
        for i in 0..20 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }

        let sgi_val = (7u64 << 24) | (1u64 << 44) | 0b10;
        gic.handle_sysreg_write(0, ICC_SGI1R_EL1, sgi_val);

        let r = gic.redistributor().lock();
        assert!(
            r.cpu(17).unwrap().ppi_sgi_state[7].pending,
            "RS=1,target bit 1 should address Aff0=17"
        );
        assert!(
            !r.cpu(1).unwrap().ppi_sgi_state[7].pending,
            "target bit 1 must not alias vCPU 1 when RS=1"
        );
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn sgi_delivery_irm0_respects_affinity_fields() {
        let gic = make_gic(4);
        for i in 0..4 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }

        let sgi_val = (9u64 << 24) | (1u64 << 16) | 0b10;
        gic.handle_sysreg_write(0, ICC_SGI1R_EL1, sgi_val);

        let r = gic.redistributor().lock();
        for vcpu in 0..4 {
            assert!(
                !r.cpu(vcpu).unwrap().ppi_sgi_state[9].pending,
                "Aff1=1 must not target flat Aff1=0 vCPU {vcpu}"
            );
        }
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn sgi_delivery_irm1() {
        let gic = make_gic(4);
        for i in 0..4 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }
        let sgi_val = (5u64 << 24) | (1u64 << 40);
        gic.handle_sysreg_write(2, ICC_SGI1R_EL1, sgi_val);

        let r = gic.redistributor().lock();
        assert!(r.cpu(0).unwrap().ppi_sgi_state[5].pending);
        assert!(r.cpu(1).unwrap().ppi_sgi_state[5].pending);
        assert!(!r.cpu(2).unwrap().ppi_sgi_state[5].pending);
        assert!(r.cpu(3).unwrap().ppi_sgi_state[5].pending);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn iar_eoir_lifecycle() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[7].enabled = true;
            cpu.ppi_sgi_config[7].priority = 0x80;
            cpu.ppi_sgi_state[7].pending = true;
            cpu.ppi_sgi_state[7].edge_latch = true;
        }

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 7);
        assert_eq!(gic.handle_sysreg_read(0, ICC_RPR_EL1), 0x80);

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 7);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_RPR_EL1),
            u64::from(PRIORITY_IDLE)
        );
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn level_retrigger_on_eoir() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[20].enabled = true;
            cpu.ppi_sgi_config[20].priority = 0x60;
            cpu.ppi_sgi_config[20].trigger = TriggerMode::Level;
            cpu.ppi_sgi_state[20].pending = true;
            cpu.ppi_sgi_state[20].hw_level = true;
        }

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 20);

        {
            let r = gic.redistributor().lock();
            assert!(r.cpu(0).unwrap().ppi_sgi_state[20].pending);
            assert!(r.cpu(0).unwrap().ppi_sgi_state[20].active);
        }

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 20);

        {
            let r = gic.redistributor().lock();
            assert!(!r.cpu(0).unwrap().ppi_sgi_state[20].active);
            assert!(r.cpu(0).unwrap().ppi_sgi_state[20].pending);
        }
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn eoimode1_dir_lifecycle() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[3].enabled = true;
            cpu.ppi_sgi_config[3].priority = 0x40;
            cpu.ppi_sgi_state[3].pending = true;
            cpu.ppi_sgi_state[3].edge_latch = true;
        }

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 3);

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 3);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_RPR_EL1),
            u64::from(PRIORITY_IDLE)
        );
        {
            let r = gic.redistributor().lock();
            assert!(r.cpu(0).unwrap().ppi_sgi_state[3].active);
        }

        gic.handle_sysreg_write(0, ICC_DIR_EL1, 3);
        {
            let r = gic.redistributor().lock();
            assert!(!r.cpu(0).unwrap().ppi_sgi_state[3].active);
        }
    }

    #[test]
    fn freeze_thaw_roundtrip() {
        let ci = CpuInterface::new();
        ci.restore_from_pod(0xF0, 2, true, false, 0x80, vec![(0x80, 33)], [0; 4], [0; 4]);

        let pod = crate::snapshot::freeze_cpu_interface(&ci);
        assert_eq!(pod.pmr, 0xF0);

        let ci2 = CpuInterface::new();
        crate::snapshot::thaw_cpu_interface(&ci2, &pod).unwrap();
        assert_eq!(ci2.pmr(), 0xF0);
        assert_eq!(ci2.bpr1(), 2);
        assert!(ci2.igrpen1());
    }

    #[test]
    fn thaw_rejects_ap_bitmap_without_active_stack() {
        let mut pod: crate::pod_state::GicCpuInterfaceState = bytemuck::Zeroable::zeroed();
        pod.pmr = 0xF0;
        pod.igrpen1 = 1;
        pod.running_priority = PRIORITY_IDLE;
        pod.active_priority_count = 0;
        pod.ap1r[0] = 1;

        let ci = CpuInterface::new();
        let err = crate::snapshot::thaw_cpu_interface(&ci, &pod).unwrap_err();

        assert!(format!("{err}").contains("without an active-priority stack"));
    }

    #[test]
    fn thaw_rejects_zeroed_legacy_cpu_interface_snapshot() {
        let pod: crate::pod_state::GicCpuInterfaceState = bytemuck::Zeroable::zeroed();

        let ci = CpuInterface::new();
        let err = crate::snapshot::thaw_cpu_interface(&ci, &pod).unwrap_err();

        assert!(format!("{err}").contains("running_priority"));
    }

    #[test]
    fn thaw_rejects_running_priority_mismatch() {
        let mut pod: crate::pod_state::GicCpuInterfaceState = bytemuck::Zeroable::zeroed();
        pod.pmr = 0xF0;
        pod.igrpen1 = 1;
        pod.running_priority = 0x80;
        pod.active_priority_count = 1;
        pod.active_priorities[0].priority = 0x60;
        pod.active_priorities[0].intid = 33;

        let ci = CpuInterface::new();
        let err = crate::snapshot::thaw_cpu_interface(&ci, &pod).unwrap_err();

        assert!(format!("{err}").contains("does not match active-priority stack"));
    }

    #[test]
    fn linux_boot_sequence() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_SRE_EL1, 0x7);
        let sre = gic.handle_sysreg_read(0, ICC_SRE_EL1);
        assert_eq!(sre & 1, 1, "SRE must read as 1");

        let ctlr = gic.handle_sysreg_read(0, ICC_CTLR_EL1);
        let pri_bits = ((ctlr >> 8) & 0x7) + 1;
        assert_eq!(pri_bits, u64::from(crate::consts::PRIORITY_BITS));

        gic.handle_sysreg_write(0, ICC_AP1R0_EL1, 0);
        gic.handle_sysreg_write(0, ICC_AP0R0_EL1, 0);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        gic.handle_sysreg_write(0, ICC_BPR1_EL1, 0);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        assert_eq!(gic.handle_sysreg_read(0, ICC_PMR_EL1), 0xF0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_BPR1_EL1), 0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_IGRPEN1_EL1), 1);
    }

    // =========================================================================
    // BPR1 clamping
    // =========================================================================

    #[test]
    fn bpr1_clamped_to_3_bits() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_BPR1_EL1, 0xFF); // Only low 3 bits matter
        assert_eq!(gic.handle_sysreg_read(0, ICC_BPR1_EL1), 7);
    }

    // =========================================================================
    // CTLR EOImode and PRI_BITS
    // =========================================================================

    #[test]
    fn ctlr_pri_bits_readonly() {
        let gic = make_gic(1);
        // Write something to CTLR
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0);
        let val = gic.handle_sysreg_read(0, ICC_CTLR_EL1);
        // PRI_BITS should still be present (bits [10:8])
        let pri_bits = (val >> 8) & 0x7;
        assert_eq!(pri_bits, u64::from(PRIORITY_BITS - 1));
    }

    #[test]
    fn ctlr_eoimode_toggle() {
        let gic = make_gic(1);
        // Set EOImode=1
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2);
        let val = gic.handle_sysreg_read(0, ICC_CTLR_EL1);
        assert_ne!(val & 0x2, 0);

        // Clear EOImode=0
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x0);
        let val = gic.handle_sysreg_read(0, ICC_CTLR_EL1);
        assert_eq!(val & 0x2, 0);
    }

    // =========================================================================
    // AP registers (all 8)
    // =========================================================================

    #[test]
    fn all_ap_registers_readwrite() {
        let gic = make_gic(1);

        let regs = [
            (ICC_AP1R0_EL1, 0x1111_1111u64),
            (ICC_AP1R1_EL1, 0x2222_2222),
            (ICC_AP1R2_EL1, 0x3333_3333),
            (ICC_AP1R3_EL1, 0x4444_4444),
            (ICC_AP0R0_EL1, 0x5555_5555),
            (ICC_AP0R1_EL1, 0x6666_6666),
            (ICC_AP0R2_EL1, 0x7777_7777),
            (ICC_AP0R3_EL1, 0x8888_8888),
        ];

        for &(reg, val) in &regs {
            gic.handle_sysreg_write(0, reg, val);
        }

        for &(reg, expected) in &regs {
            let val = gic.handle_sysreg_read(0, reg);
            assert_eq!(val, expected & 0xFFFF_FFFF, "AP register {reg:#x} mismatch");
        }
    }

    // =========================================================================
    // RPR tracks running priority
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn rpr_tracks_running_priority() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Initially idle
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_RPR_EL1),
            u64::from(PRIORITY_IDLE)
        );

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[0].enabled = true;
            cpu.ppi_sgi_config[0].priority = 0x60;
            cpu.ppi_sgi_state[0].pending = true;
            cpu.ppi_sgi_state[0].edge_latch = true;
        }

        // Acknowledge → RPR should update
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_RPR_EL1), 0x60);

        // EOI → back to idle
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 0);
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_RPR_EL1),
            u64::from(PRIORITY_IDLE)
        );
    }

    // =========================================================================
    // IAR with SPI (through distributor)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn iar_eoir_spi_edge() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);

        // Edge: pending cleared, active set
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].pending);
            assert!(d.spi_state[0].active);
            assert!(!d.spi_state[0].edge_latch);
        }

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 32);
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].active);
        }
    }

    // =========================================================================
    // IAR with level-triggered: pending stays if hw_level asserted
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn iar_level_keeps_pending_if_hw_asserted() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Level;
            d.spi_state[0].pending = true;
            d.spi_state[0].hw_level = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);

        // Level with hw_level=true: pending stays
        let d = gic.distributor().read();
        assert!(
            d.spi_state[0].pending,
            "Level IRQ should stay pending when hw_level asserted"
        );
        assert!(d.spi_state[0].active);
    }

    #[test]
    // Reason: lock guard scope intentionally spans the body to keep
    // the operation atomic against concurrent observers.
    #[allow(clippy::significant_drop_tightening)]
    fn iar_level_clears_pending_if_hw_deasserted() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Level;
            d.spi_state[0].pending = true;
            d.spi_state[0].hw_level = false; // Line deasserted between pend and IAR
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);

        let d = gic.distributor().read();
        assert!(
            !d.spi_state[0].pending,
            "Level IRQ should clear pending when hw_level deasserted"
        );
    }

    // =========================================================================
    // EOIR for non-active INTID
    // =========================================================================

    #[test]
    fn eoir_non_active_intid_no_crash() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        // EOIR for INTID 50 that was never acknowledged — should warn but not crash
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 50);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // DIR for non-active INTID
    // =========================================================================

    #[test]
    fn dir_non_active_intid_no_crash() {
        let gic = make_gic(1);
        // Enable EOImode=1
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        // DIR for non-active — should warn but not crash
        gic.handle_sysreg_write(0, ICC_DIR_EL1, 50);
    }

    // =========================================================================
    // DIR level retrigger
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn dir_level_retrigger() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2); // EOImode=1

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[20].enabled = true;
            cpu.ppi_sgi_config[20].priority = 0x60;
            cpu.ppi_sgi_config[20].trigger = TriggerMode::Level;
            cpu.ppi_sgi_state[20].pending = true;
            cpu.ppi_sgi_state[20].hw_level = true;
        }

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 20);

        // EOIR (priority drop only)
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 20);

        // Still active
        {
            let r = gic.redistributor().lock();
            assert!(r.cpu(0).unwrap().ppi_sgi_state[20].active);
        }

        // DIR (deactivate) → should retrigger since hw_level still asserted
        gic.handle_sysreg_write(0, ICC_DIR_EL1, 20);
        {
            let r = gic.redistributor().lock();
            assert!(!r.cpu(0).unwrap().ppi_sgi_state[20].active);
            assert!(
                r.cpu(0).unwrap().ppi_sgi_state[20].pending,
                "DIR should re-pend level-triggered IRQ when hw_level asserted"
            );
        }
    }

    // =========================================================================
    // Multiple nested active priorities
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn nested_active_priorities_stack() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Set up 3 SGIs at different priorities
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            for (id, pri) in [(1, 0x20u8), (2, 0x40), (3, 0x60)] {
                cpu.ppi_sgi_config[id].enabled = true;
                cpu.ppi_sgi_config[id].priority = pri;
                cpu.ppi_sgi_state[id].pending = true;
                cpu.ppi_sgi_state[id].edge_latch = true;
            }
        }

        // Acknowledge in priority order: 1(0x20), 2(0x40), 3(0x60)
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 1);
        assert_eq!(gic.running_priority_atomic(0), 0x20);

        // Pend another higher-priority interrupt
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[0].enabled = true;
            cpu.ppi_sgi_config[0].priority = 0x10; // Highest yet
            cpu.ppi_sgi_state[0].pending = true;
            cpu.ppi_sgi_state[0].edge_latch = true;
        }

        // SGI 0 at 0x10 can preempt running 0x20
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 0);
        assert_eq!(gic.running_priority_atomic(0), 0x10);

        // EOIR SGI 0 → back to 0x20
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 0);
        assert_eq!(gic.running_priority_atomic(0), 0x20);

        // EOIR SGI 1 → back to idle (only had 2 active)
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 1);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // HPPIR with pending interrupt
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn hppir_returns_highest_pending() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x80;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;

            cpu.ppi_sgi_config[3].enabled = true;
            cpu.ppi_sgi_config[3].priority = 0x40;
            cpu.ppi_sgi_state[3].pending = true;
            cpu.ppi_sgi_state[3].edge_latch = true;
        }

        // Should return 3 (higher priority)
        assert_eq!(gic.handle_sysreg_read(0, ICC_HPPIR1_EL1), 3);

        // Still pending (no side effects)
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // SRE write of 0 still reads as 7
    // =========================================================================

    #[test]
    fn sre_write_zero_reads_back_7() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_SRE_EL1, 0);
        assert_eq!(gic.handle_sysreg_read(0, ICC_SRE_EL1), 0x7);
    }

    // =========================================================================
    // handle_write return values
    // =========================================================================

    #[test]
    fn handle_write_pmr_returns_vcpu_id() {
        let gic = make_gic(2);
        let ci = gic.cpu_interface(1);
        let affected = ci.handle_write(ICC_PMR_EL1, 0xF0, 1, &gic);
        assert_eq!(affected, vec![1]);
    }

    #[test]
    fn handle_write_bpr1_returns_vcpu_id() {
        let gic = make_gic(1);
        let ci = gic.cpu_interface(0);
        let affected = ci.handle_write(ICC_BPR1_EL1, 3, 0, &gic);
        assert_eq!(affected, vec![0]);
    }

    #[test]
    fn handle_write_igrpen1_returns_vcpu_id() {
        let gic = make_gic(1);
        let ci = gic.cpu_interface(0);
        let affected = ci.handle_write(ICC_IGRPEN1_EL1, 1, 0, &gic);
        assert_eq!(affected, vec![0]);
    }

    #[test]
    fn handle_write_ctlr_returns_empty() {
        let gic = make_gic(1);
        let ci = gic.cpu_interface(0);
        let affected = ci.handle_write(ICC_CTLR_EL1, 0x2, 0, &gic);
        assert!(
            affected.is_empty(),
            "CTLR write doesn't need delivery re-eval"
        );
    }

    #[test]
    fn handle_write_sre_returns_empty() {
        let gic = make_gic(1);
        let ci = gic.cpu_interface(0);
        let affected = ci.handle_write(ICC_SRE_EL1, 0x7, 0, &gic);
        assert!(affected.is_empty());
    }

    #[test]
    fn handle_write_unknown_returns_empty() {
        let gic = make_gic(1);
        let ci = gic.cpu_interface(0);
        let affected = ci.handle_write(0xDEAD, 0, 0, &gic);
        assert!(affected.is_empty());
    }

    // =========================================================================
    // Snapshot preserves active_priorities
    // =========================================================================

    // =========================================================================
    // Coverage: Default trait impl (lines 48-49)
    // =========================================================================

    #[test]
    fn default_trait_creates_same_as_new() {
        let ci = CpuInterface::default();
        assert_eq!(ci.pmr(), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(ci.running_priority(), PRIORITY_IDLE);
        assert!(!ci.igrpen1());
        assert_eq!(ci.bpr1(), 0);
    }

    // =========================================================================
    // Coverage: IAR level-triggered PPI with hw_level=false (line 205)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn iar_level_ppi_clears_pending_when_hw_deasserted() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[20].enabled = true;
            cpu.ppi_sgi_config[20].priority = 0x60;
            cpu.ppi_sgi_config[20].trigger = TriggerMode::Level;
            cpu.ppi_sgi_state[20].pending = true;
            cpu.ppi_sgi_state[20].hw_level = false; // Line deasserted
        }

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 20);

        // Level with hw_level=false: pending should be cleared
        {
            let r = gic.redistributor().lock();
            assert!(
                !r.cpu(0).unwrap().ppi_sgi_state[20].pending,
                "Level PPI should clear pending when hw_level is false"
            );
            assert!(r.cpu(0).unwrap().ppi_sgi_state[20].active);
        }
    }

    // =========================================================================
    // Coverage: Out-of-order EOIR (line 257)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn out_of_order_eoir_still_works() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Acknowledge two interrupts: SGI 1 (priority 0x20), SGI 2 (priority 0x10)
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[1].enabled = true;
            cpu.ppi_sgi_config[1].priority = 0x20;
            cpu.ppi_sgi_state[1].pending = true;
            cpu.ppi_sgi_state[1].edge_latch = true;
        }
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[2].enabled = true;
            cpu.ppi_sgi_config[2].priority = 0x10;
            cpu.ppi_sgi_state[2].pending = true;
            cpu.ppi_sgi_state[2].edge_latch = true;
        }
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 2);

        // Active stack: [(0x20, 1), (0x10, 2)]
        // EOIR SGI 1 first (out-of-order — SGI 2 is on top)
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 1);

        // Running priority should now be 0x10 (SGI 2 still active)
        assert_eq!(gic.running_priority_atomic(0), 0x10);

        // EOIR SGI 2
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 2);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // Coverage: DIR for non-active SGI/PPI (lines 348-349)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn dir_non_active_sgi_ppi_no_crash() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2); // EOImode=1
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // DIR for SGI 5 (INTID < 32) that is not active — should warn but not crash
        gic.handle_sysreg_write(0, ICC_DIR_EL1, 5);

        // Verify no side effects
        {
            let r = gic.redistributor().lock();
            assert!(!r.cpu(0).unwrap().ppi_sgi_state[5].active);
        }
    }

    // =========================================================================
    // Coverage: DIR for non-active SPI (lines 362-364)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn dir_non_active_spi_no_crash() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_CTLR_EL1, 0x2); // EOImode=1
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // DIR for SPI 40 (INTID >= 32) that is not active
        gic.handle_sysreg_write(0, ICC_DIR_EL1, 40);

        // Verify no side effects
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[8].active);
        }
    }

    // =========================================================================
    // Coverage: Unknown ICC read (line 120-121)
    // =========================================================================

    #[test]
    fn unknown_icc_read_returns_zero() {
        let gic = make_gic(1);
        let val = gic.handle_sysreg_read(0, 0xBEEF);
        assert_eq!(val, 0);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn freeze_preserves_active_priorities() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x60;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 5); // Acknowledge

        let pod = crate::snapshot::freeze_cpu_interface(gic.cpu_interface(0));
        assert_eq!(pod.running_priority, 0x60);
        assert_eq!(pod.active_priority_count, 1);
        assert_eq!(pod.active_priorities[0].priority, 0x60);
        assert_eq!(pod.active_priorities[0].intid, 5);

        // Thaw
        let ci = CpuInterface::new();
        crate::snapshot::thaw_cpu_interface(&ci, &pod).unwrap();
        assert_eq!(ci.running_priority(), 0x60);
    }
}
