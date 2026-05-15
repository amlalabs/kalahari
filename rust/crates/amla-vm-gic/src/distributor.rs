// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! `GICv3` Distributor (GICD) — manages SPI state and MMIO register decode.
//!
//! The distributor owns all SPI (Shared Peripheral Interrupt) state for
//! IRQs 32-95. It is shared across all vCPUs via an `RwLock`.

use crate::consts::{
    GICD_CTLR, GICD_CTLR_DS, GICD_CTLR_ENABLE_GRP1A, GICD_CTLR_RO_MASK, GICD_CTLR_RW_MASK,
    GICD_IIDR, GICD_IIDR_VAL, GICD_PIDR2, GICD_PIDR2_VAL, GICD_TYPER, GICD_TYPER_VAL, NR_IRQS,
    NR_SPIS, PRIORITY_MASK, SPI_START,
};
use crate::irq_state::{
    IrqConfig, IrqState, TriggerMode, read_priority_bytes, write_priority_bytes,
};

/// `GICv3` distributor state.
///
/// This distributor always operates in ARE (Affinity Routing Enable) mode.
/// `GICD_CTLR.ARE_NS` is writable but the behavior is hardcoded: IRQs 0-31
/// are always RAZ/WI at the distributor (handled per-CPU by redistributors),
/// and SPIs always use affinity routing via IROUTER registers.
pub struct Distributor {
    /// `GICD_CTLR` register value.
    ctlr: u32,
    /// Per-SPI configuration (indexed by `spi_idx` = intid - 32).
    pub(crate) spi_config: Vec<IrqConfig>,
    /// Per-SPI dynamic state.
    pub(crate) spi_state: Vec<IrqState>,
    /// Per-SPI affinity routing (IROUTER values).
    irouter: Vec<u64>,
}

impl Distributor {
    pub fn new(nr_spis: usize) -> Self {
        Self {
            ctlr: GICD_CTLR_DS, // DS=1 always (single security state)
            spi_config: vec![IrqConfig::default(); nr_spis],
            spi_state: vec![IrqState::default(); nr_spis],
            irouter: vec![0u64; nr_spis],
        }
    }

    pub const fn nr_spis(&self) -> usize {
        self.spi_config.len()
    }

    /// Read `GICD_CTLR` value.
    pub const fn ctlr(&self) -> u32 {
        self.ctlr
    }

    /// Set `GICD_CTLR` value (used by thaw).
    pub const fn set_ctlr(&mut self, val: u32) {
        self.ctlr = val;
    }

    /// Read IROUTER for a given SPI index.
    pub fn irouter(&self, spi_idx: usize) -> u64 {
        self.irouter.get(spi_idx).copied().unwrap_or(0)
    }

    /// Set IROUTER for a given SPI index.
    pub fn set_irouter(&mut self, spi_idx: usize, val: u64) {
        if let Some(slot) = self.irouter.get_mut(spi_idx) {
            *slot = val;
        }
    }

    /// Public accessor for SPI configuration (read-only).
    pub fn spi_cfg(&self) -> &[IrqConfig] {
        &self.spi_config
    }

    /// Public accessor for SPI configuration (mutable).
    pub fn spi_cfg_mut(&mut self) -> &mut [IrqConfig] {
        &mut self.spi_config
    }

    /// Public accessor for SPI state (read-only).
    pub fn spi_st(&self) -> &[IrqState] {
        &self.spi_state
    }

    /// Public accessor for SPI state (mutable).
    pub fn spi_st_mut(&mut self) -> &mut [IrqState] {
        &mut self.spi_state
    }

    /// Whether `GICD_CTLR.EnableGrp1A` is set.
    pub const fn grp1a_enabled(&self) -> bool {
        self.ctlr & GICD_CTLR_ENABLE_GRP1A != 0
    }

    /// Check if SPI at `spi_idx` is targeted at `vcpu_id`.
    pub fn is_targeted_at(&self, spi_idx: usize, vcpu_id: usize, num_vcpus: usize) -> bool {
        let route = self.irouter[spi_idx];
        let irm = (route >> 31) & 1;
        if irm == 1 {
            // 1-of-N: deliver to lowest-numbered online vCPU (deterministic choice)
            vcpu_id == 0
        } else {
            // Specific CPU: Aff0 = vcpu_id (simple flat topology)
            let aff0 = (route & 0xFF) as usize;
            aff0 < num_vcpus && aff0 == vcpu_id
        }
    }

    // =========================================================================
    // MMIO register decode
    // =========================================================================

    /// Handle an MMIO read from the distributor.
    pub fn mmio_read(&self, offset: u64, size: u8) -> u64 {
        match offset {
            GICD_CTLR => u64::from(self.ctlr),
            GICD_TYPER => u64::from(GICD_TYPER_VAL),
            GICD_IIDR => u64::from(GICD_IIDR_VAL),
            GICD_PIDR2 => u64::from(GICD_PIDR2_VAL),
            o if (0x0080..0x0080 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_cfg_word(o, 0x0080, |cfg| cfg.group)
            }
            o if (0x0100..0x0100 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_cfg_word(o, 0x0100, |cfg| cfg.enabled)
            }
            o if (0x0180..0x0180 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_cfg_word(o, 0x0180, |cfg| cfg.enabled)
            }
            o if (0x0200..0x0200 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_state_word(o, 0x0200, |st| st.pending)
            }
            o if (0x0280..0x0280 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_state_word(o, 0x0280, |st| st.pending)
            }
            o if (0x0300..0x0300 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_state_word(o, 0x0300, |st| st.active)
            }
            o if (0x0380..0x0380 + 12).contains(&o) && o % 4 == 0 => {
                self.read_bit_state_word(o, 0x0380, |st| st.active)
            }
            o if (0x0400..0x0400 + u64::from(NR_IRQS)).contains(&o) => {
                self.read_priority_mmio(o, size)
            }
            o if (0x0C00..0x0C00 + 24).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0C00) / 4) as usize;
                if word_idx < 2 {
                    0
                } else {
                    self.read_icfgr_word(word_idx)
                }
            }
            o if (0x0D00..0x0D00 + 12).contains(&o) && o % 4 == 0 => 0,
            o if Self::is_irouter_offset(o) => self.read_irouter(o, size),
            _ => {
                log::trace!("GICD read RAZ: offset={offset:#x} size={size}");
                0
            }
        }
    }

    fn read_bit_cfg_word(&self, offset: u64, base: u64, f: fn(&IrqConfig) -> bool) -> u64 {
        let word_idx = ((offset - base) / 4) as usize;
        if word_idx == 0 {
            0
        } else {
            self.read_bit_register_word(word_idx, f)
        }
    }

    fn read_bit_state_word(&self, offset: u64, base: u64, f: fn(&IrqState) -> bool) -> u64 {
        let word_idx = ((offset - base) / 4) as usize;
        if word_idx == 0 {
            0
        } else {
            self.read_state_bit_word(word_idx, f)
        }
    }

    #[allow(clippy::cast_possible_truncation)] // MMIO offset bounded by NR_IRQS < u32::MAX
    fn read_priority_mmio(&self, offset: u64, size: u8) -> u64 {
        let intid = (offset - 0x0400) as u32;
        if intid < SPI_START {
            return 0;
        }
        let spi_idx = (intid - SPI_START) as usize;
        read_priority_bytes(&self.spi_config, spi_idx, size)
    }

    fn is_irouter_offset(o: u64) -> bool {
        (0x6100..0x6100 + u64::from(NR_SPIS) * 8).contains(&o) && o.is_multiple_of(4)
    }

    fn read_irouter(&self, o: u64, size: u8) -> u64 {
        let spi_idx = ((o - 0x6100) / 8) as usize;
        if spi_idx >= self.irouter.len() {
            return 0;
        }
        if o.is_multiple_of(8) {
            let val = self.irouter[spi_idx];
            // For 4-byte reads at 8-byte-aligned offsets, return only low 32 bits
            if size == 4 { val & 0xFFFF_FFFF } else { val }
        } else {
            // +4 offset: high 32 bits
            (self.irouter[spi_idx] >> 32) & 0xFFFF_FFFF
        }
    }

    /// Handle an MMIO write to the distributor.
    ///
    /// Returns `true` if delivery should be re-evaluated for all vCPUs.
    /// The caller must handle delivery updates after releasing the write lock.
    #[allow(clippy::cast_possible_truncation)] // MMIO register decode: 32-bit register values from 64-bit bus
    pub fn mmio_write(&mut self, offset: u64, data: u64, size: u8) -> bool {
        let data32 = data as u32;
        let mut needs_delivery = false;

        match offset {
            GICD_CTLR => {
                let new_ctlr = (data32 & GICD_CTLR_RW_MASK) | GICD_CTLR_RO_MASK;
                self.ctlr = new_ctlr;
                needs_delivery = true;
            }

            // IGROUPR — flipping group can change deliverability for any
            // already-pending IRQ in this word, since highest_pending only
            // selects Group-1 entries. Re-evaluate delivery.
            o if (0x0080..0x0080 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0080) / 4) as usize;
                if word_idx > 0 {
                    self.write_bit_register_word(word_idx, data32, |cfg, bit| {
                        cfg.group = bit;
                    });
                    needs_delivery = true;
                }
            }

            // ISENABLER (set-1)
            o if (0x0100..0x0100 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0100) / 4) as usize;
                if word_idx > 0 {
                    self.write_set1_config(word_idx, data32, |cfg| &mut cfg.enabled);
                    needs_delivery = true;
                }
            }

            // ICENABLER (clear by writing 1)
            o if (0x0180..0x0180 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0180) / 4) as usize;
                if word_idx > 0 {
                    self.write_clear1_config(word_idx, data32, |cfg| &mut cfg.enabled);
                    needs_delivery = true;
                }
            }

            // ISPENDR (set-1)
            o if (0x0200..0x0200 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0200) / 4) as usize;
                if word_idx > 0 {
                    self.write_set1_state(word_idx, data32, |st| &mut st.pending);
                    needs_delivery = true;
                }
            }

            // ICPENDR (clear-1) — trigger-aware (IHI0069D §8.9.8)
            o if (0x0280..0x0280 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0280) / 4) as usize;
                if word_idx > 0 {
                    self.clear_pending_trigger_aware(word_idx, data32);
                    needs_delivery = true;
                }
            }

            // ISACTIVER (set-1) — setting active removes the IRQ from
            // highest_pending selection (active IRQs are filtered out), so
            // the cached IRQ line must be re-evaluated.
            o if (0x0300..0x0300 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0300) / 4) as usize;
                if word_idx > 0 {
                    self.write_set1_state(word_idx, data32, |st| &mut st.active);
                    needs_delivery = true;
                }
            }

            // ICACTIVER (clear-1)
            o if (0x0380..0x0380 + 12).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0380) / 4) as usize;
                if word_idx > 0 {
                    self.write_clear1_state(word_idx, data32, |st| &mut st.active);
                    needs_delivery = true;
                }
            }

            // IPRIORITYR: 1 byte per IRQ
            o if (0x0400..0x0400 + u64::from(NR_IRQS)).contains(&o) => {
                self.write_priority(o, data, size);
                needs_delivery = true;
            }

            // ICFGR: 2 bits per IRQ
            o if (0x0C00..0x0C00 + 24).contains(&o) && o % 4 == 0 => {
                let word_idx = ((o - 0x0C00) / 4) as usize;
                if word_idx >= 2 {
                    self.write_icfgr_word(word_idx, data32);
                }
            }

            // IGRPMODR: WI (always 0 in NS-only)
            o if (0x0D00..0x0D00 + 12).contains(&o) && o % 4 == 0 => {}

            // IROUTER: 64-bit per SPI
            o if Self::is_irouter_offset(o) => {
                let spi_idx = ((o - 0x6100) / 8) as usize;
                let word_offset = (o - 0x6100) % 8;
                if spi_idx < self.irouter.len() {
                    if size == 8 && word_offset == 0 {
                        // Full 64-bit write
                        self.irouter[spi_idx] = data;
                    } else if word_offset == 4 {
                        // High 32-bit write
                        self.irouter[spi_idx] =
                            (self.irouter[spi_idx] & 0xFFFF_FFFF) | ((data & 0xFFFF_FFFF) << 32);
                    } else {
                        // Low 32-bit write (or 64-bit at 8-byte aligned with size 4)
                        self.irouter[spi_idx] =
                            (self.irouter[spi_idx] & !0xFFFF_FFFF) | (data & 0xFFFF_FFFF);
                    }
                    needs_delivery = true;
                }
            }

            // Everything else: WI
            _ => {
                log::trace!("GICD write WI: offset={offset:#x} data={data:#x} size={size}");
            }
        }

        needs_delivery
    }

    // =========================================================================
    // Level/edge injection (called from GicV3 under write lock)
    // =========================================================================

    /// Set level for an SPI (called under write lock).
    ///
    /// Returns `true` if delivery should be re-evaluated.
    pub fn set_level_mut(&mut self, spi_idx: usize, level: bool) -> bool {
        if spi_idx >= self.spi_state.len() {
            return false;
        }
        let st = &mut self.spi_state[spi_idx];
        st.hw_level = level;

        if level {
            if self.spi_config[spi_idx].trigger == TriggerMode::Level {
                st.pending = true;
            }
        } else if self.spi_config[spi_idx].trigger == TriggerMode::Level {
            st.pending = false;
        }

        true
    }

    /// Pulse edge for an SPI (called under write lock).
    ///
    /// Returns `true` if delivery should be re-evaluated.
    pub fn set_edge_mut(&mut self, spi_idx: usize) -> bool {
        if spi_idx >= self.spi_state.len() {
            return false;
        }
        let st = &mut self.spi_state[spi_idx];
        st.pending = true;
        st.edge_latch = true;

        true
    }

    // =========================================================================
    // Bit-banked register helpers
    // =========================================================================

    /// Read a 32-bit word from a bit-per-IRQ config register.
    fn read_bit_register_word(&self, word_idx: usize, extract: impl Fn(&IrqConfig) -> bool) -> u64 {
        let base_irq = word_idx * 32;
        let mut val = 0u32;
        for bit in 0..32 {
            let intid = base_irq + bit;
            if intid >= SPI_START as usize {
                let spi_idx = intid - SPI_START as usize;
                if spi_idx < self.spi_config.len() && extract(&self.spi_config[spi_idx]) {
                    val |= 1 << bit;
                }
            }
        }
        u64::from(val)
    }

    /// Read a 32-bit word from a bit-per-IRQ state register.
    fn read_state_bit_word(&self, word_idx: usize, extract: impl Fn(&IrqState) -> bool) -> u64 {
        let base_irq = word_idx * 32;
        let mut val = 0u32;
        for bit in 0..32 {
            let intid = base_irq + bit;
            if intid >= SPI_START as usize {
                let spi_idx = intid - SPI_START as usize;
                if spi_idx < self.spi_state.len() && extract(&self.spi_state[spi_idx]) {
                    val |= 1 << bit;
                }
            }
        }
        u64::from(val)
    }

    /// Write a full 32-bit word to a bit-per-IRQ config register.
    fn write_bit_register_word(
        &mut self,
        word_idx: usize,
        data: u32,
        mut apply: impl FnMut(&mut IrqConfig, bool),
    ) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            let intid = base_irq + bit;
            if intid >= SPI_START as usize {
                let spi_idx = intid - SPI_START as usize;
                if spi_idx < self.spi_config.len() {
                    apply(&mut self.spi_config[spi_idx], data & (1 << bit) != 0);
                }
            }
        }
    }

    /// Set bits (write-1-to-set) in a config field.
    fn write_set1_config(
        &mut self,
        word_idx: usize,
        data: u32,
        field: impl Fn(&mut IrqConfig) -> &mut bool,
    ) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            if data & (1 << bit) != 0 {
                let intid = base_irq + bit;
                if intid >= SPI_START as usize {
                    let spi_idx = intid - SPI_START as usize;
                    if spi_idx < self.spi_config.len() {
                        *field(&mut self.spi_config[spi_idx]) = true;
                    }
                }
            }
        }
    }

    /// Clear bits (write-1-to-clear) in a config field.
    fn write_clear1_config(
        &mut self,
        word_idx: usize,
        data: u32,
        field: impl Fn(&mut IrqConfig) -> &mut bool,
    ) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            if data & (1 << bit) != 0 {
                let intid = base_irq + bit;
                if intid >= SPI_START as usize {
                    let spi_idx = intid - SPI_START as usize;
                    if spi_idx < self.spi_config.len() {
                        *field(&mut self.spi_config[spi_idx]) = false;
                    }
                }
            }
        }
    }

    /// Set bits (write-1-to-set) in a state field.
    fn write_set1_state(
        &mut self,
        word_idx: usize,
        data: u32,
        field: impl Fn(&mut IrqState) -> &mut bool,
    ) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            if data & (1 << bit) != 0 {
                let intid = base_irq + bit;
                if intid >= SPI_START as usize {
                    let spi_idx = intid - SPI_START as usize;
                    if spi_idx < self.spi_state.len() {
                        *field(&mut self.spi_state[spi_idx]) = true;
                    }
                }
            }
        }
    }

    /// Clear bits (write-1-to-clear) in a state field.
    fn write_clear1_state(
        &mut self,
        word_idx: usize,
        data: u32,
        field: impl Fn(&mut IrqState) -> &mut bool,
    ) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            if data & (1 << bit) != 0 {
                let intid = base_irq + bit;
                if intid >= SPI_START as usize {
                    let spi_idx = intid - SPI_START as usize;
                    if spi_idx < self.spi_state.len() {
                        *field(&mut self.spi_state[spi_idx]) = false;
                    }
                }
            }
        }
    }

    /// Clear pending bits with trigger-aware semantics (ICPENDR).
    ///
    /// For edge-triggered IRQs: clears both `pending` and `edge_latch`.
    /// For level-triggered IRQs: clears pending, then re-pends if `hw_level` still asserted.
    fn clear_pending_trigger_aware(&mut self, word_idx: usize, data: u32) {
        let base_irq = word_idx * 32;
        for bit in 0..32 {
            if data & (1 << bit) != 0 {
                let intid = base_irq + bit;
                if intid >= SPI_START as usize {
                    let spi_idx = intid - SPI_START as usize;
                    if spi_idx < self.spi_state.len() {
                        self.spi_state[spi_idx].pending = false;
                        self.spi_state[spi_idx].edge_latch = false;
                        if self.spi_config[spi_idx].trigger == TriggerMode::Level
                            && self.spi_state[spi_idx].hw_level
                        {
                            self.spi_state[spi_idx].pending = true;
                        }
                    }
                }
            }
        }
    }

    /// Write priority byte(s) to IPRIORITYR.
    ///
    /// Per `GICv3` spec, unimplemented low priority bits are WI (masked by `PRIORITY_MASK`).
    #[allow(clippy::cast_possible_truncation)] // MMIO offset bounded by NR_IRQS < u32::MAX
    fn write_priority(&mut self, offset: u64, data: u64, size: u8) {
        let intid = (offset - 0x0400) as u32;
        if intid < SPI_START {
            return;
        }
        let spi_idx = (intid - SPI_START) as usize;
        write_priority_bytes(&mut self.spi_config, spi_idx, data, size, PRIORITY_MASK);
    }

    /// Read ICFGR word (2 bits per IRQ, 16 IRQs per word).
    fn read_icfgr_word(&self, word_idx: usize) -> u64 {
        let base_irq = word_idx * 16;
        let mut val = 0u32;
        for i in 0..16 {
            let intid = base_irq + i;
            if intid >= SPI_START as usize {
                let spi_idx = intid - SPI_START as usize;
                if spi_idx < self.spi_config.len()
                    && self.spi_config[spi_idx].trigger == TriggerMode::Edge
                {
                    val |= 0b10 << (i * 2); // bit 1 of each 2-bit field = edge
                }
            }
        }
        u64::from(val)
    }

    /// Write ICFGR word.
    fn write_icfgr_word(&mut self, word_idx: usize, data: u32) {
        let base_irq = word_idx * 16;
        for i in 0..16 {
            let intid = base_irq + i;
            if intid >= SPI_START as usize {
                let spi_idx = intid - SPI_START as usize;
                if spi_idx < self.spi_config.len() {
                    let field = (data >> (i * 2)) & 0x3;
                    self.spi_config[spi_idx].trigger = if field & 0b10 != 0 {
                        TriggerMode::Edge
                    } else {
                        TriggerMode::Level
                    };
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )]
    use super::*;
    use crate::consts::GICD_CTLR_ARE_NS;
    use crate::{GicConfig, GicV3, NullInterruptSink};

    #[test]
    fn new_distributor_defaults() {
        let dist = Distributor::new(64);
        assert_eq!(dist.nr_spis(), 64);
        assert!(!dist.grp1a_enabled());
        // DS bit is always set
        assert_ne!(dist.ctlr & GICD_CTLR_DS, 0);
    }

    #[test]
    fn mmio_read_typer() {
        let dist = Distributor::new(64);
        assert_eq!(dist.mmio_read(GICD_TYPER, 4), u64::from(GICD_TYPER_VAL));
    }

    #[test]
    fn mmio_read_pidr2() {
        let dist = Distributor::new(64);
        assert_eq!(dist.mmio_read(GICD_PIDR2, 4), u64::from(GICD_PIDR2_VAL));
    }

    #[test]
    fn mmio_read_ctlr_ds_always_set() {
        let dist = Distributor::new(64);
        let ctlr = dist.mmio_read(GICD_CTLR, 4) as u32;
        assert_ne!(ctlr & GICD_CTLR_DS, 0);
    }

    #[test]
    fn irouter_routing() {
        let mut dist = Distributor::new(64);
        // Route SPI 0 (intid 32) to vCPU 2
        dist.irouter[0] = 2; // Aff0 = 2
        assert!(dist.is_targeted_at(0, 2, 4));
        assert!(!dist.is_targeted_at(0, 0, 4));
        assert!(!dist.is_targeted_at(0, 1, 4));
    }

    #[test]
    fn irouter_irm_mode() {
        let mut dist = Distributor::new(64);
        // Set IRM=1 (bit 31) for 1-of-N routing
        dist.irouter[0] = 1u64 << 31;
        // Should target vCPU 0 (lowest-numbered)
        assert!(dist.is_targeted_at(0, 0, 4));
        assert!(!dist.is_targeted_at(0, 1, 4));
    }

    #[test]
    fn isenabler_icenabler_roundtrip() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write ISENABLER for word 1 (IRQs 32-63)
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0104, 0xFFFF_FFFF, 4);
        }

        // Read back
        let val = {
            let d = gic.distributor().read();
            d.mmio_read(0x0104, 4)
        };
        assert_eq!(val, 0xFFFF_FFFF);

        // Clear some bits via ICENABLER
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0184, 0x0000_00FF, 4);
        }

        let val = {
            let d = gic.distributor().read();
            d.mmio_read(0x0104, 4)
        };
        assert_eq!(val, 0xFFFF_FF00);
    }

    #[test]
    fn priority_byte_readwrite() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write priority for SPI 32 (offset 0x0420)
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0420, 0xA0, 1);
        }

        let val = {
            let d = gic.distributor().read();
            d.mmio_read(0x0420, 1)
        };
        assert_eq!(val, 0xA0);
    }

    #[test]
    fn icfgr_edge_level() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write ICFGR for word 2 (IRQs 32-47): all edge
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0C08, 0xAAAA_AAAA, 4);
        }

        let val = {
            let d = gic.distributor().read();
            d.mmio_read(0x0C08, 4)
        };
        assert_eq!(val, 0xAAAA_AAAA);
    }

    #[test]
    fn raz_for_irqs_0_31_at_distributor() {
        let dist = Distributor::new(64);
        // ISENABLER[0] at distributor with ARE=1 should be RAZ
        assert_eq!(dist.mmio_read(0x0100, 4), 0);
        // IGROUPR[0]
        assert_eq!(dist.mmio_read(0x0080, 4), 0);
    }

    #[test]
    fn freeze_thaw_roundtrip() {
        let mut dist = Distributor::new(64);
        // Set CTLR to EnableGrp1A | ARE_NS | DS (realistic value)
        dist.ctlr = GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS;
        dist.spi_config[0].enabled = true;
        dist.spi_config[0].priority = 0xA0;
        dist.irouter[0] = 3;

        let pod = crate::snapshot::freeze_distributor(&dist);
        let mut dist2 = Distributor::new(64);
        crate::snapshot::thaw_distributor(&mut dist2, &pod);

        // Thaw masks CTLR: RW bits preserved, DS forced on
        assert_eq!(
            dist2.ctlr,
            GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS
        );
        assert!(dist2.spi_config[0].enabled);
        assert_eq!(dist2.spi_config[0].priority, 0xA0);
        assert_eq!(dist2.irouter[0], 3);
    }

    // =========================================================================
    // GICD_CTLR
    // =========================================================================

    #[test]
    fn ctlr_write_preserves_ds_bit() {
        let mut dist = Distributor::new(64);
        // Write without DS → DS should remain set (read-only)
        dist.mmio_write(GICD_CTLR, 0, 4);
        let ctlr = dist.mmio_read(GICD_CTLR, 4) as u32;
        assert_ne!(ctlr & GICD_CTLR_DS, 0, "DS bit must remain set");
    }

    #[test]
    fn ctlr_enable_grp1a() {
        let mut dist = Distributor::new(64);
        assert!(!dist.grp1a_enabled());
        dist.mmio_write(
            GICD_CTLR,
            u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS),
            4,
        );
        assert!(dist.grp1a_enabled());
    }

    #[test]
    fn ctlr_rwp_always_zero() {
        let dist = Distributor::new(64);
        let ctlr = dist.mmio_read(GICD_CTLR, 4) as u32;
        assert_eq!(ctlr & (1 << 31), 0, "RWP must always be 0");
    }

    // =========================================================================
    // GICD_IIDR
    // =========================================================================

    #[test]
    fn mmio_read_iidr() {
        let dist = Distributor::new(64);
        assert_eq!(dist.mmio_read(GICD_IIDR, 4), u64::from(GICD_IIDR_VAL));
    }

    // =========================================================================
    // IGROUPR
    // =========================================================================

    #[test]
    fn igroupr_readwrite() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write all-1 to IGROUPR[1] (IRQs 32-63)
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0084, 0xFFFF_FFFF, 4);
        }
        let val = gic.distributor().read().mmio_read(0x0084, 4);
        assert_eq!(val, 0xFFFF_FFFF);

        // Write all-0 to IGROUPR[1]
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0084, 0, 4);
        }
        let val = gic.distributor().read().mmio_read(0x0084, 4);
        assert_eq!(val, 0);
    }

    /// Regression: an IGROUPR write that flips a pending Group-0 IRQ into
    /// Group 1 must trigger delivery re-evaluation. Previously the write
    /// path returned `false` here, so the IRQ stayed undelivered until
    /// some unrelated event re-drove the GIC.
    #[test]
    fn igroupr_write_redrives_delivery() {
        let mut dist = Distributor::new(64);
        // Pre-stage an SPI as pending in Group 0 (group=false).
        dist.spi_config[0].enabled = true;
        dist.spi_config[0].priority = 0x40;
        dist.spi_config[0].group = false;
        dist.spi_state[0].pending = true;

        // IGROUPR[1] covers IRQs 32-63; bit 0 → SPI 32 → spi_idx 0.
        let needs_delivery = dist.mmio_write(0x0084, 0x0000_0001, 4);
        assert!(
            needs_delivery,
            "IGROUPR write must request delivery re-eval"
        );
        assert!(dist.spi_config[0].group, "group bit must be set");
    }

    // =========================================================================
    // ISPENDR / ICPENDR
    // =========================================================================

    #[test]
    fn ispendr_icpendr_roundtrip() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0204, 0x0000_00FF, 4); // ISPENDR[1]: pend SPIs 32-39
        }
        let val = gic.distributor().read().mmio_read(0x0204, 4);
        assert_eq!(val, 0xFF);

        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0284, 0x0000_000F, 4); // ICPENDR[1]: clear SPIs 32-35
        }
        let val = gic.distributor().read().mmio_read(0x0204, 4);
        assert_eq!(val, 0xF0);
    }

    // =========================================================================
    // ISACTIVER / ICACTIVER
    // =========================================================================

    #[test]
    fn isactiver_icactiver_roundtrip() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0304, 0x0000_FFFF, 4); // ISACTIVER[1]
        }
        let val = gic.distributor().read().mmio_read(0x0304, 4);
        assert_eq!(val, 0xFFFF);

        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0384, 0x0000_00FF, 4); // ICACTIVER[1]
        }
        let val = gic.distributor().read().mmio_read(0x0304, 4);
        assert_eq!(val, 0xFF00);
    }

    // =========================================================================
    // IROUTER
    // =========================================================================

    #[test]
    fn irouter_64bit_readwrite() {
        let mut dist = Distributor::new(64);
        // Write full 64-bit value for SPI 32 (offset 0x6100)
        dist.mmio_write(0x6100, 0x0000_0003_0000_0002, 8);
        assert_eq!(dist.irouter[0], 0x0000_0003_0000_0002);

        // Read back 64-bit
        let val = dist.mmio_read(0x6100, 8);
        assert_eq!(val, 0x0000_0003_0000_0002);
    }

    #[test]
    fn irouter_32bit_split_readwrite() {
        let mut dist = Distributor::new(64);
        // Write low 32 bits
        dist.mmio_write(0x6100, 0xDEAD_BEEF, 4);
        // Write high 32 bits
        dist.mmio_write(0x6104, 0xCAFE_BABE, 4);

        assert_eq!(dist.irouter[0], 0xCAFE_BABE_DEAD_BEEF);

        // Read full 64-bit at 8-byte-aligned offset
        assert_eq!(dist.mmio_read(0x6100, 8), 0xCAFE_BABE_DEAD_BEEF);
        // Read low 32 bits at 8-byte-aligned offset with size=4
        assert_eq!(dist.mmio_read(0x6100, 4), 0xDEAD_BEEF);
        // Read high 32 bits at +4 offset
        assert_eq!(dist.mmio_read(0x6104, 4), 0xCAFE_BABE);
    }

    #[test]
    fn irouter_last_spi() {
        let mut dist = Distributor::new(64);
        // SPI 95 = spi_idx 63, offset = 0x6100 + 63*8 = 0x62F8
        dist.mmio_write(0x62F8, 7, 8);
        assert_eq!(dist.irouter[63], 7);
        assert_eq!(dist.mmio_read(0x62F8, 8), 7);
    }

    #[test]
    fn irouter_out_of_range_is_wi() {
        let mut dist = Distributor::new(64);
        // Offset for SPI 96 (spi_idx 64) — out of range
        dist.mmio_write(0x6100 + 64 * 8, 0xFF, 8);
        // Should be ignored (WI)
    }

    #[test]
    fn is_irouter_offset_boundaries() {
        assert!(Distributor::is_irouter_offset(0x6100)); // First SPI
        assert!(Distributor::is_irouter_offset(0x62F8)); // Last SPI (63*8=0x1F8)
        assert!(!Distributor::is_irouter_offset(0x60FF)); // Before range
        assert!(!Distributor::is_irouter_offset(0x6300)); // After range
    }

    // =========================================================================
    // IGRPMODR
    // =========================================================================

    #[test]
    fn igrpmodr_write_ignored() {
        let mut dist = Distributor::new(64);
        dist.mmio_write(0x0D04, 0xFFFF_FFFF, 4);
        // No effect — IGRPMODR is WI
    }

    // =========================================================================
    // set_level_mut / set_edge_mut
    // =========================================================================

    #[test]
    fn set_level_mut_level_triggered() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].trigger = TriggerMode::Level;

        assert!(dist.set_level_mut(0, true));
        assert!(dist.spi_state[0].pending);
        assert!(dist.spi_state[0].hw_level);

        assert!(dist.set_level_mut(0, false));
        assert!(!dist.spi_state[0].pending);
        assert!(!dist.spi_state[0].hw_level);
    }

    #[test]
    fn set_level_mut_edge_triggered_no_pend() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].trigger = TriggerMode::Edge;

        // set_level with edge trigger: hw_level updates but no auto-pend
        dist.set_level_mut(0, true);
        assert!(dist.spi_state[0].hw_level);
        assert!(!dist.spi_state[0].pending); // Edge doesn't auto-pend on level
    }

    #[test]
    fn set_edge_mut_sets_pending_and_latch() {
        let mut dist = Distributor::new(64);
        assert!(dist.set_edge_mut(0));
        assert!(dist.spi_state[0].pending);
        assert!(dist.spi_state[0].edge_latch);
    }

    #[test]
    fn set_level_mut_out_of_range() {
        let mut dist = Distributor::new(64);
        assert!(!dist.set_level_mut(100, true));
    }

    #[test]
    fn set_edge_mut_out_of_range() {
        let mut dist = Distributor::new(64);
        assert!(!dist.set_edge_mut(100));
    }

    // =========================================================================
    // ICPENDR trigger-aware
    // =========================================================================

    #[test]
    fn icpendr_clears_edge_latch() {
        let mut dist = Distributor::new(64);
        // Set up edge-triggered SPI 32 (spi_idx 0) as pending
        dist.spi_config[0].trigger = TriggerMode::Edge;
        dist.spi_state[0].pending = true;
        dist.spi_state[0].edge_latch = true;

        // ICPENDR word 1, bit 0 → clears SPI 32
        dist.mmio_write(0x0284, 1, 4);

        assert!(!dist.spi_state[0].pending);
        assert!(
            !dist.spi_state[0].edge_latch,
            "ICPENDR must clear edge_latch"
        );
    }

    #[test]
    fn icpendr_level_respects_hw_level() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].trigger = TriggerMode::Level;
        dist.spi_state[0].pending = true;
        dist.spi_state[0].hw_level = true;

        // Clear pending via ICPENDR
        dist.mmio_write(0x0284, 1, 4);

        // Level still asserted → should re-pend
        assert!(
            dist.spi_state[0].pending,
            "Level IRQ should re-pend if hw_level still asserted"
        );
    }

    #[test]
    fn icpendr_level_stays_clear_when_hw_deasserted() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].trigger = TriggerMode::Level;
        dist.spi_state[0].pending = true;
        dist.spi_state[0].hw_level = false;

        dist.mmio_write(0x0284, 1, 4);

        assert!(
            !dist.spi_state[0].pending,
            "Level IRQ should stay clear when hw_level deasserted"
        );
    }

    // =========================================================================
    // Priority 4-byte read/write
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn priority_4byte_readwrite() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write 4 priority bytes at once for SPIs 32-35.
        // Values must be aligned to PRIORITY_MASK (top 5 bits implemented).
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x0420, 0x1020_3040, 4);
        }
        {
            let d = gic.distributor().read();
            let val = d.mmio_read(0x0420, 4);
            assert_eq!(val, 0x1020_3040);

            // Individual byte reads
            assert_eq!(d.mmio_read(0x0420, 1), 0x40);
            assert_eq!(d.mmio_read(0x0421, 1), 0x30);
            assert_eq!(d.mmio_read(0x0422, 1), 0x20);
            assert_eq!(d.mmio_read(0x0423, 1), 0x10);
        }
    }

    // =========================================================================
    // RAZ for unknown offsets
    // =========================================================================

    #[test]
    fn raz_for_unknown_offsets() {
        let dist = Distributor::new(64);
        // Reserved range
        assert_eq!(dist.mmio_read(0x0010, 4), 0);
        assert_eq!(dist.mmio_read(0x0050, 4), 0);
        // Between ICFGR and IROUTER
        assert_eq!(dist.mmio_read(0x1000, 4), 0);
    }

    #[test]
    fn wi_for_unknown_offsets() {
        let mut dist = Distributor::new(64);
        dist.mmio_write(0x0010, 0xFFFF_FFFF, 4); // Reserved — should be WI
    }

    // =========================================================================
    // Targeting
    // =========================================================================

    #[test]
    fn targeting_specific_aff0() {
        let mut dist = Distributor::new(64);
        dist.irouter[0] = 3; // Aff0=3
        assert!(dist.is_targeted_at(0, 3, 4));
        assert!(!dist.is_targeted_at(0, 0, 4));
        assert!(!dist.is_targeted_at(0, 1, 4));
        assert!(!dist.is_targeted_at(0, 2, 4));
    }

    // =========================================================================
    // ICENABLER / ICPENDR / ICACTIVER read paths
    // =========================================================================

    #[test]
    fn icenabler_read_returns_enabled_bits() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].enabled = true;
        dist.spi_config[3].enabled = true;
        // Read from ICENABLER offset 0x0184 (same as ISENABLER, reads enabled status)
        let val = dist.mmio_read(0x0184, 4);
        assert_eq!(val & 1, 1, "SPI 32 (bit 0 of word 1) should be enabled");
        assert_eq!((val >> 3) & 1, 1, "SPI 35 (bit 3) should be enabled");
    }

    #[test]
    fn icpendr_read_returns_pending_bits() {
        let mut dist = Distributor::new(64);
        dist.spi_state[0].pending = true;
        dist.spi_state[5].pending = true;
        // ICPENDR at offset 0x0284 reads pending state
        let val = dist.mmio_read(0x0284, 4);
        assert_eq!(val & 1, 1, "SPI 32 pending");
        assert_eq!((val >> 5) & 1, 1, "SPI 37 pending");
    }

    #[test]
    fn icactiver_read_returns_active_bits() {
        let mut dist = Distributor::new(64);
        dist.spi_state[0].active = true;
        dist.spi_state[7].active = true;
        // ICACTIVER at offset 0x0384 reads active state
        let val = dist.mmio_read(0x0384, 4);
        assert_eq!(val & 1, 1, "SPI 32 active");
        assert_eq!((val >> 7) & 1, 1, "SPI 39 active");
    }

    // =========================================================================
    // Priority read edge cases
    // =========================================================================

    #[test]
    fn priority_read_for_irq_below_spi_start_returns_zero() {
        let dist = Distributor::new(64);
        // Read priority for IRQ 0 (offset 0x0400) — below SPI_START, should be RAZ
        assert_eq!(dist.mmio_read(0x0400, 1), 0);
        // IRQ 31 (offset 0x041F)
        assert_eq!(dist.mmio_read(0x041F, 1), 0);
    }

    #[test]
    fn priority_read_for_out_of_range_spi_returns_zero() {
        let dist = Distributor::new(64);
        // SPI 96 = intid 96, spi_idx 64 — out of range for 64 SPIs
        // offset = 0x0400 + 96 = 0x0460
        assert_eq!(dist.mmio_read(0x0460, 1), 0);
    }

    #[test]
    fn priority_read_unsupported_size_returns_zero() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].priority = 0xA0;
        // Read with size=2 (unsupported) — should return 0
        assert_eq!(dist.mmio_read(0x0420, 2), 0);
    }

    #[test]
    fn priority_write_unsupported_size_ignored() {
        let mut dist = Distributor::new(64);
        dist.spi_config[0].priority = 0xA0;
        // Write with size=2 (unsupported) — should be ignored
        dist.mmio_write(0x0420, 0xFF, 2);
        assert_eq!(
            dist.spi_config[0].priority, 0xA0,
            "Priority should not change with size=2"
        );
    }

    // =========================================================================
    // ICFGR read/write for non-SPI range
    // =========================================================================

    #[test]
    fn icfgr_word0_and_word1_return_zero() {
        let dist = Distributor::new(64);
        // ICFGR[0] and ICFGR[1] cover IRQs 0-31 → RAZ at distributor with ARE=1
        assert_eq!(dist.mmio_read(0x0C00, 4), 0);
        assert_eq!(dist.mmio_read(0x0C04, 4), 0);
    }

    #[test]
    fn icfgr_write_for_spi_range() {
        let mut dist = Distributor::new(64);
        // ICFGR[2] covers IRQs 32-47: set all to level (0x0000_0000)
        dist.mmio_write(0x0C08, 0, 4);
        // All should be level
        for i in 0..16 {
            assert_eq!(dist.spi_config[i].trigger, TriggerMode::Level);
        }
        // Now set all to edge
        dist.mmio_write(0x0C08, 0xAAAA_AAAA, 4);
        for i in 0..16 {
            assert_eq!(dist.spi_config[i].trigger, TriggerMode::Edge);
        }
    }

    // =========================================================================
    // C4: ISPENDR[0] / ISACTIVER[0] / ICACTIVER[0] RAZ at distributor
    // =========================================================================

    #[test]
    fn ispendr0_raz_at_distributor() {
        let dist = Distributor::new(64);
        // ISPENDR[0] at offset 0x0200: IRQs 0-31 are RAZ with ARE mode
        assert_eq!(dist.mmio_read(0x0200, 4), 0);
    }

    #[test]
    fn icpendr0_raz_at_distributor() {
        let dist = Distributor::new(64);
        // ICPENDR[0] at offset 0x0280: IRQs 0-31 are RAZ with ARE mode
        assert_eq!(dist.mmio_read(0x0280, 4), 0);
    }

    #[test]
    fn isactiver0_raz_at_distributor() {
        let dist = Distributor::new(64);
        // ISACTIVER[0] at offset 0x0300: IRQs 0-31 are RAZ with ARE mode
        assert_eq!(dist.mmio_read(0x0300, 4), 0);
    }

    #[test]
    fn icactiver0_raz_at_distributor() {
        let dist = Distributor::new(64);
        // ICACTIVER[0] at offset 0x0380: IRQs 0-31 are RAZ with ARE mode
        assert_eq!(dist.mmio_read(0x0380, 4), 0);
    }

    // =========================================================================
    // C6: IROUTER read for out-of-range SPI
    // =========================================================================

    #[test]
    fn irouter_read_out_of_range_returns_zero() {
        let dist = Distributor::new(64);
        // SPI 96 (spi_idx=64) — out of range for 64 SPIs
        // Offset = 0x6100 + 64 * 8 = 0x6300
        assert_eq!(dist.mmio_read(0x6100 + 64 * 8, 8), 0);
        // Also check 4-byte reads at both halves
        assert_eq!(dist.mmio_read(0x6100 + 64 * 8, 4), 0);
        assert_eq!(dist.mmio_read(0x6100 + 64 * 8 + 4, 4), 0);
    }

    // =========================================================================
    // C7: Distributor restore with smaller snapshot
    // =========================================================================

    #[test]
    fn thaw_from_smaller_dist_resets_tail() {
        let mut dist = Distributor::new(64);
        // Set up state in upper SPIs
        dist.spi_config[60].enabled = true;
        dist.spi_config[60].priority = 0xA0;
        dist.spi_state[60].pending = true;
        dist.irouter[60] = 3;

        // Freeze from a smaller distributor (32 SPIs) — pod entries 32..63 are zeros
        let mut small_dist = Distributor::new(32);
        small_dist.spi_config[0].enabled = true;
        small_dist.spi_config[0].priority = 0x80;
        small_dist.irouter[0] = 1;
        let pod = crate::snapshot::freeze_distributor(&small_dist);

        // Thaw into the larger distributor
        crate::snapshot::thaw_distributor(&mut dist, &pod);

        // First 32 entries should match snapshot
        assert!(dist.spi_config[0].enabled);
        assert_eq!(dist.spi_config[0].priority, 0x80);
        assert_eq!(dist.irouter[0], 1);

        // Entries 32..63 were zero in the pod → thaw restores as defaults
        assert!(!dist.spi_config[60].enabled);
        assert_eq!(dist.spi_config[60].priority, 0);
        assert!(!dist.spi_state[60].pending);
        assert_eq!(dist.irouter[60], 0);
    }

    #[test]
    fn targeting_aff0_out_of_range() {
        let mut dist = Distributor::new(64);
        dist.irouter[0] = 10; // Aff0=10, but only 4 vCPUs
        assert!(!dist.is_targeted_at(0, 10, 4)); // vcpu_id out of range
        assert!(!dist.is_targeted_at(0, 0, 4)); // aff0 >= num_vcpus
    }
}
