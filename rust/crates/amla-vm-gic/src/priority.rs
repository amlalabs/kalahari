// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! Priority resolution engine.
//!
//! Determines the highest-priority pending interrupt for each vCPU and
//! generates delivery actions.

use crate::GicV3;
use crate::consts::{PRIORITY_IDLE, SPI_START};
use crate::delivery::DeliveryAction;

pub struct PriorityEngine;

impl PriorityEngine {
    /// Find the highest-priority pending interrupt for a vCPU.
    ///
    /// Returns `Some((intid, priority))` or `None` if nothing qualifies.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    // spi_idx bounded by NR_SPIS (64) which fits in u32
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn highest_pending(vcpu_id: usize, gic: &GicV3) -> Option<(u32, u8)> {
        // All reads go through atomic mirrors — safe for cross-thread access.
        // The owning vCPU thread syncs these atomics after every ICC write/read
        // that modifies state (see GicV3::sync_cpu_interface_atoms).

        // Gate: Group 1 must be enabled on this CPU
        if !gic.igrpen1_atomic(vcpu_id) {
            return None;
        }

        let pmr = gic.pmr_atomic(vcpu_id);
        let running = gic.running_priority_atomic(vcpu_id);
        let bpr1 = gic.bpr1_atomic(vcpu_id);

        let mut best: Option<(u32, u8)> = None;

        // Check SGIs/PPIs (IRQs 0-31) from this vCPU's redistributor
        {
            let redist = gic.redistributor().lock();
            if let Some(cpu) = redist.cpu(vcpu_id) {
                for intid in 0..32u32 {
                    let idx = intid as usize;
                    let cfg = &cpu.ppi_sgi_config[idx];
                    let st = &cpu.ppi_sgi_state[idx];

                    if !cfg.enabled {
                        continue;
                    }
                    if !cfg.group {
                        continue;
                    }
                    // Active IRQs are not selectable on the same PE until
                    // deactivated (DIR with EOImode=1, or EOIR with EOImode=0).
                    // Without this, an edge re-pend or a level line still
                    // asserted between EOIR and DIR would re-IAR while still
                    // active.
                    if st.active {
                        continue;
                    }
                    if !(st.pending || st.edge_latch) {
                        continue;
                    }
                    if cfg.priority >= pmr {
                        continue;
                    }
                    if !Self::can_preempt(cfg.priority, running, bpr1) {
                        continue;
                    }

                    match best {
                        Some((_, best_pri)) if cfg.priority < best_pri => {
                            best = Some((intid, cfg.priority));
                        }
                        None => {
                            best = Some((intid, cfg.priority));
                        }
                        _ => {}
                    }
                }
            }
        }

        // Check SPIs (IRQs 32+) from distributor
        {
            let dist = gic.distributor().read();

            // Gate: distributor must have Group1A enabled
            if !dist.grp1a_enabled() {
                // SPIs are gated, but SGI/PPI result still valid
                return best;
            }

            let nr_spis = dist.nr_spis();
            for spi_idx in 0..nr_spis {
                let intid = spi_idx as u32 + SPI_START;
                let cfg = &dist.spi_config[spi_idx];
                let st = &dist.spi_state[spi_idx];

                if !cfg.enabled {
                    continue;
                }
                if !cfg.group {
                    continue;
                }
                // See the SGI/PPI loop above for the active-state rationale.
                if st.active {
                    continue;
                }
                if !(st.pending || st.edge_latch) {
                    continue;
                }

                // Check routing
                if !dist.is_targeted_at(spi_idx, vcpu_id, gic.num_vcpus()) {
                    continue;
                }

                if cfg.priority >= pmr {
                    continue;
                }
                if !Self::can_preempt(cfg.priority, running, bpr1) {
                    continue;
                }

                match best {
                    Some((_, best_pri)) if cfg.priority < best_pri => {
                        best = Some((intid, cfg.priority));
                    }
                    None => {
                        best = Some((intid, cfg.priority));
                    }
                    _ => {}
                }
            }
        }

        best
    }

    /// Check if an interrupt at `priority` can preempt the current `running` priority.
    ///
    /// Uses BPR1 to compute group priority for preemption comparison.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // u16 mask intentionally truncated to u8 (lower 8 bits)
    pub fn can_preempt(priority: u8, running: u8, bpr1: u8) -> bool {
        if running == PRIORITY_IDLE {
            return true;
        }
        let group_mask = !((1u16 << (u16::from(bpr1) + 1)) - 1) as u8;
        let new_group = priority & group_mask;
        let running_group = running & group_mask;
        new_group < running_group
    }

    /// Compute group priority from a raw priority value.
    #[must_use]
    #[allow(clippy::cast_possible_truncation)] // u16 mask intentionally truncated to u8 (lower 8 bits)
    pub fn group_priority(priority: u8, bpr1: u8) -> u8 {
        let group_mask = !((1u16 << (u16::from(bpr1) + 1)) - 1) as u8;
        priority & group_mask
    }

    /// Evaluate delivery for a vCPU and return the appropriate action.
    pub fn update_delivery(vcpu_id: usize, gic: &GicV3) -> DeliveryAction {
        let pending = Self::highest_pending(vcpu_id, gic).is_some();
        DeliveryAction { vcpu_id, pending }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::consts::GICD_CTLR;

    #[test]
    fn can_preempt_idle() {
        assert!(PriorityEngine::can_preempt(0x80, PRIORITY_IDLE, 0));
    }

    #[test]
    fn can_preempt_higher_priority() {
        // Priority 0x40 can preempt running 0x80 with bpr=0
        assert!(PriorityEngine::can_preempt(0x40, 0x80, 0));
    }

    #[test]
    fn cannot_preempt_same_priority() {
        assert!(!PriorityEngine::can_preempt(0x80, 0x80, 0));
    }

    #[test]
    fn cannot_preempt_lower_priority() {
        assert!(!PriorityEngine::can_preempt(0xC0, 0x80, 0));
    }

    #[test]
    fn bpr_groups_priorities() {
        // With bpr=2, group mask = !0x7 = 0xF8
        // 0x10 group = 0x10, 0x18 group = 0x18 → different groups, can preempt
        assert!(PriorityEngine::can_preempt(0x10, 0x18, 2));
        // 0x10 and 0x17 are in same group (0x10) → cannot preempt
        assert!(!PriorityEngine::can_preempt(0x10, 0x10, 2));
    }

    #[test]
    fn group_priority_bpr0() {
        // bpr=0: mask = !1 = 0xFE
        assert_eq!(PriorityEngine::group_priority(0xA1, 0), 0xA0);
    }

    #[test]
    fn group_priority_bpr3() {
        // bpr=3: mask = !0xF = 0xF0
        assert_eq!(PriorityEngine::group_priority(0xAB, 3), 0xA0);
    }

    #[test]
    fn group_priority_bpr7() {
        // bpr=7: mask = !0xFF = 0x00 — all priorities in same group
        assert_eq!(PriorityEngine::group_priority(0xAB, 7), 0);
    }

    #[test]
    fn can_preempt_with_bpr_grouping() {
        // bpr=3: mask = 0xF0. Group of 0x80 = 0x80, group of 0x70 = 0x70
        // 0x70 < 0x80 → can preempt
        assert!(PriorityEngine::can_preempt(0x70, 0x80, 3));
        // 0x78 and 0x70 have same group (0x70) → cannot preempt
        assert!(!PriorityEngine::can_preempt(0x78, 0x70, 3));
    }

    // Tests using full GIC (highest_pending, update_delivery)

    use crate::{GicConfig, GicV3, NullInterruptSink};

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
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_sgi() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x80;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((5, 0x80)));
    }

    #[test]
    fn highest_pending_spi() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x60;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((32, 0x60)));
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_sgi_beats_spi_at_same_priority() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[10].enabled = true;
            cpu.ppi_sgi_config[10].priority = 0x80;
            cpu.ppi_sgi_state[10].pending = true;
            cpu.ppi_sgi_state[10].edge_latch = true;
        }
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80; // Same priority
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        // SGI 10 (INTID 10) has lower INTID than SPI 32 → wins tiebreak
        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((10, 0x80)));
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_none_when_igrpen1_disabled() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        // igrpen1 stays disabled

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x80;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_none_when_pmr_masks() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0x40); // Only allow < 0x40
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x80; // >= PMR → masked
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_none_when_disabled() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = false; // Disabled!
            cpu.ppi_sgi_config[5].priority = 0x80;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }

    #[test]
    fn highest_pending_respects_spi_routing() {
        let gic = make_gic(2);
        for i in 0..2 {
            gic.handle_sysreg_write(i, crate::consts::ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, crate::consts::ICC_IGRPEN1_EL1, 1);
        }

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_state[0].pending = true;
            d.mmio_write(0x6100, 1, 8); // IROUTER[0] → Aff0=1
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        // vCPU 0 should not see it
        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
        // vCPU 1 should see it
        assert_eq!(PriorityEngine::highest_pending(1, &gic), Some((32, 0x80)));
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn highest_pending_dist_disabled_blocks_spi_not_sgi() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // Distributor NOT enabled (Grp1A=0)
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x40;
            d.spi_state[0].pending = true;
        }
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x80;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        // SPI blocked by dist, but SGI visible
        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((5, 0x80)));
    }

    // =========================================================================
    // Coverage: SPI filtered by PMR (line 101)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn spi_pmr_masked_while_sgi_passes() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0x80); // Only < 0x80
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // SPI at priority 0xA0 → filtered by PMR (0xA0 >= 0x80)
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0xA0;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        // SGI at priority 0x60 → passes PMR (0x60 < 0x80)
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x60;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        // SPI filtered by PMR, SGI wins
        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((5, 0x60)));
    }

    // =========================================================================
    // Coverage: SPI beats existing SGI best (line 109)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn spi_beats_sgi_with_better_priority() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // SGI at priority 0xA0
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[10].enabled = true;
            cpu.ppi_sgi_config[10].priority = 0xA0;
            cpu.ppi_sgi_state[10].pending = true;
            cpu.ppi_sgi_state[10].edge_latch = true;
        }

        // SPI at priority 0x60 → better than SGI's 0xA0
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x60;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        // SPI 32 at 0x60 should beat SGI 10 at 0xA0
        let result = PriorityEngine::highest_pending(0, &gic);
        assert_eq!(result, Some((32, 0x60)));
    }

    // =========================================================================
    // Coverage: SPI preemption check (line 103)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn spi_cannot_preempt_running_priority() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // Acknowledge a high-priority SGI first to set running_priority
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[0].enabled = true;
            cpu.ppi_sgi_config[0].priority = 0x20;
            cpu.ppi_sgi_state[0].pending = true;
            cpu.ppi_sgi_state[0].edge_latch = true;
        }
        let intid = gic.handle_sysreg_read(0, crate::consts::ICC_IAR1_EL1);
        assert_eq!(intid, 0);

        // Now pend an SPI at lower priority (0x80) — can't preempt running 0x20
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        // SPI can't preempt → nothing qualifies (SGI 0 already active)
        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn update_delivery_returns_action() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // Nothing pending → pending=false
        let action = PriorityEngine::update_delivery(0, &gic);
        assert_eq!(action.vcpu_id, 0);
        assert!(!action.pending);

        // Pend something
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[1].enabled = true;
            cpu.ppi_sgi_config[1].priority = 0x80;
            cpu.ppi_sgi_state[1].pending = true;
            cpu.ppi_sgi_state[1].edge_latch = true;
        }

        let action = PriorityEngine::update_delivery(0, &gic);
        assert!(action.pending);
    }

    // =========================================================================
    // Active IRQs are excluded from highest_pending selection.
    //
    // Without this, EOImode=1 (priority drop without deactivate) could
    // redeliver an active level IRQ between EOIR and DIR, or an active edge
    // IRQ that the device re-pended.
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn active_sgi_ppi_skipped_even_when_pending() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        // PPI 20 is active AND pending — simulates EOImode=1 between EOIR and DIR
        // for a level IRQ whose line is still asserted.
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[20].enabled = true;
            cpu.ppi_sgi_config[20].priority = 0x60;
            cpu.ppi_sgi_state[20].pending = true;
            cpu.ppi_sgi_state[20].active = true;
        }

        // Must not redeliver while active — caller should wait for DIR.
        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }

    #[test]
    fn active_spi_skipped_even_when_pending() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, crate::consts::ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, crate::consts::ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x60;
            d.spi_state[0].pending = true;
            d.spi_state[0].active = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(
                    crate::consts::GICD_CTLR_ENABLE_GRP1A
                        | crate::consts::GICD_CTLR_ARE_NS
                        | crate::consts::GICD_CTLR_DS,
                ),
                4,
            );
        }

        assert_eq!(PriorityEngine::highest_pending(0, &gic), None);
    }
}
