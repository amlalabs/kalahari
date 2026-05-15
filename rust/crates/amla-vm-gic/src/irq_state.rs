// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! Per-IRQ state machine and configuration.

/// Trigger mode for an interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TriggerMode {
    /// Level-triggered: interrupt stays pending while the line is asserted.
    Level,
    /// Edge-triggered: interrupt latches on rising edge.
    Edge,
}

/// Static configuration for an interrupt (set by guest via MMIO registers).
#[derive(Clone, Debug)]
pub struct IrqConfig {
    /// Whether this interrupt is enabled (ISENABLER/ICENABLER).
    pub enabled: bool,
    /// Group bit (always Group 1 NS in our single-security-state implementation).
    pub group: bool,
    /// Priority value (0 = highest, 0xFF = lowest).
    pub priority: u8,
    /// Edge or level triggered (ICFGR).
    pub trigger: TriggerMode,
}

impl Default for IrqConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            group: true, // Group 1 NS by default
            priority: 0,
            trigger: TriggerMode::Level,
        }
    }
}

/// Dynamic state of an interrupt (changes at runtime).
#[allow(clippy::struct_excessive_bools)]
#[derive(Clone, Debug, Default)]
pub struct IrqState {
    /// Currently pending (waiting to be acknowledged).
    pub pending: bool,
    /// Currently active (acknowledged, not yet EOI'd).
    pub active: bool,
    /// Edge latch — sticky bit set on rising edge, cleared on IAR.
    pub edge_latch: bool,
    /// Hardware line level for level-triggered interrupts.
    pub hw_level: bool,
}

// =============================================================================
// Shared priority I/O helpers (used by both Distributor and Redistributor)
// =============================================================================

/// Read priority byte(s) from a contiguous `IrqConfig` slice.
///
/// For `size=1`, reads the single byte at `idx`.
/// For `size=4`, reads 4 consecutive bytes starting at `idx & !3`.
/// Out-of-range indices return 0.
#[allow(clippy::cast_possible_truncation)] // priority bytes are 8-bit values packed into u32
pub(crate) fn read_priority_bytes(configs: &[IrqConfig], idx: usize, size: u8) -> u64 {
    match size {
        1 => configs.get(idx).map_or(0, |c| u64::from(c.priority)),
        4 => {
            if idx >= configs.len() {
                return 0;
            }
            let base = idx & !3;
            let mut val = 0u32;
            for i in 0..4 {
                if let Some(cfg) = configs.get(base + i) {
                    val |= u32::from(cfg.priority) << (i * 8);
                }
            }
            u64::from(val)
        }
        _ => 0,
    }
}

/// Write priority byte(s) to a contiguous `IrqConfig` slice.
///
/// For `size=1`, writes the single byte at `idx`.
/// For `size=4`, writes 4 consecutive bytes starting at `idx & !3`.
/// Values are masked by `mask` (unimplemented low priority bits are WI).
/// Out-of-range indices are silently ignored.
#[allow(clippy::cast_possible_truncation)] // priority bytes: values bounded by 8-bit register width
pub(crate) fn write_priority_bytes(
    configs: &mut [IrqConfig],
    idx: usize,
    data: u64,
    size: u8,
    mask: u8,
) {
    match size {
        1 => {
            if let Some(cfg) = configs.get_mut(idx) {
                cfg.priority = (data as u8) & mask;
            }
        }
        4 => {
            if idx >= configs.len() {
                return;
            }
            let base = idx & !3;
            for i in 0..4u32 {
                if let Some(cfg) = configs.get_mut(base + i as usize) {
                    cfg.priority = (((data >> (i * 8)) & 0xFF) as u8) & mask;
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn default_irq_config() {
        let cfg = IrqConfig::default();
        assert!(!cfg.enabled);
        assert!(cfg.group); // Group 1 NS
        assert_eq!(cfg.priority, 0);
        assert_eq!(cfg.trigger, TriggerMode::Level);
    }

    #[test]
    fn default_irq_state() {
        let st = IrqState::default();
        assert!(!st.pending);
        assert!(!st.active);
        assert!(!st.edge_latch);
        assert!(!st.hw_level);
    }

    // =========================================================================
    // Shared priority helpers
    // =========================================================================

    fn make_configs(priorities: &[u8]) -> Vec<IrqConfig> {
        priorities
            .iter()
            .map(|&p| IrqConfig {
                priority: p,
                ..IrqConfig::default()
            })
            .collect()
    }

    #[test]
    fn read_priority_bytes_single() {
        let configs = make_configs(&[0xA0, 0x60, 0x80, 0x40]);
        assert_eq!(read_priority_bytes(&configs, 0, 1), 0xA0);
        assert_eq!(read_priority_bytes(&configs, 2, 1), 0x80);
    }

    #[test]
    fn read_priority_bytes_word() {
        let configs = make_configs(&[0x40, 0x30, 0x20, 0x10]);
        assert_eq!(read_priority_bytes(&configs, 0, 4), 0x1020_3040);
    }

    #[test]
    fn read_priority_bytes_out_of_range() {
        let configs = make_configs(&[0xA0]);
        assert_eq!(read_priority_bytes(&configs, 5, 1), 0);
    }

    #[test]
    fn read_priority_bytes_unsupported_size() {
        let configs = make_configs(&[0xA0, 0x60]);
        assert_eq!(read_priority_bytes(&configs, 0, 2), 0);
    }

    #[test]
    fn write_priority_bytes_single() {
        let mut configs = make_configs(&[0, 0, 0, 0]);
        write_priority_bytes(&mut configs, 1, 0xA0, 1, 0xF8);
        assert_eq!(configs[1].priority, 0xA0);
    }

    #[test]
    fn write_priority_bytes_word() {
        let mut configs = make_configs(&[0, 0, 0, 0]);
        write_priority_bytes(&mut configs, 0, 0x1020_3040, 4, 0xF8);
        assert_eq!(configs[0].priority, 0x40);
        assert_eq!(configs[1].priority, 0x30);
        assert_eq!(configs[2].priority, 0x20);
        assert_eq!(configs[3].priority, 0x10);
    }

    #[test]
    fn write_priority_bytes_masks_unimplemented_bits() {
        let mut configs = make_configs(&[0]);
        write_priority_bytes(&mut configs, 0, 0xFF, 1, 0xF8);
        assert_eq!(configs[0].priority, 0xF8);
    }

    #[test]
    fn write_priority_bytes_out_of_range_ignored() {
        let mut configs = make_configs(&[0xA0]);
        write_priority_bytes(&mut configs, 5, 0xFF, 1, 0xF8);
        assert_eq!(configs[0].priority, 0xA0); // Unchanged
    }

    #[test]
    fn read_priority_word_past_end_no_alias() {
        // 5 entries: idx=5 is out of range, but 5 & !3 = 4 is in range.
        // The guard must reject the entire access to avoid aliasing entry 4.
        let configs = make_configs(&[0x10, 0x20, 0x30, 0x40, 0x50]);
        assert_eq!(read_priority_bytes(&configs, 5, 4), 0);
    }

    #[test]
    fn write_priority_word_past_end_no_alias() {
        // Same as above for writes: idx=5 out of range must not modify entry 4.
        let mut configs = make_configs(&[0x10, 0x20, 0x30, 0x40, 0x50]);
        write_priority_bytes(&mut configs, 5, 0xFFFF_FFFF, 4, 0xF8);
        assert_eq!(configs[4].priority, 0x50); // Unchanged
    }
}
