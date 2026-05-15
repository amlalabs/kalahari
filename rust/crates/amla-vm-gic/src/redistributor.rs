// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! `GICv3` Redistributor (GICR) — per-vCPU SGI/PPI state and MMIO register decode.
//!
//! Each vCPU gets a 128 KiB MMIO region split into two 64 KiB frames:
//! - `RD_base` (frame 0): Control, TYPER, WAKER
//! - `SGI_base` (frame 1): SGI/PPI registers (same layout as GICD for IRQs 0-31)

use crate::consts::{
    GICD_IIDR_VAL, GICD_PIDR2_VAL, GICR_CPU_SIZE, GICR_CTLR, GICR_ICACTIVER0, GICR_ICENABLER0,
    GICR_ICFGR0, GICR_ICFGR1, GICR_ICPENDR0, GICR_IGROUPR0, GICR_IGRPMODR0, GICR_IIDR,
    GICR_ISACTIVER0, GICR_ISENABLER0, GICR_ISPENDR0, GICR_PIDR2, GICR_SGI_BASE_OFFSET,
    GICR_STATUSR, GICR_TYPER, GICR_WAKER, GICR_WAKER_CHILDREN_ASLEEP, GICR_WAKER_PROCESSOR_SLEEP,
    PRIORITY_MASK,
};
use crate::irq_state::{
    IrqConfig, IrqState, TriggerMode, read_priority_bytes, write_priority_bytes,
};

/// Per-vCPU redistributor state.
pub struct RedistributorCpu {
    /// `GICR_WAKER` register value.
    pub waker: u32,
    /// IRQ configuration for SGIs (0-15) and PPIs (16-31).
    pub ppi_sgi_config: [IrqConfig; 32],
    /// IRQ state for SGIs/PPIs.
    pub ppi_sgi_state: [IrqState; 32],
}

impl RedistributorCpu {
    fn new() -> Self {
        Self {
            // Start with ProcessorSleep=1, ChildrenAsleep=1
            waker: GICR_WAKER_PROCESSOR_SLEEP | GICR_WAKER_CHILDREN_ASLEEP,
            ppi_sgi_config: std::array::from_fn(|i| {
                IrqConfig {
                    // SGIs (0-15) are edge-triggered by default
                    trigger: if i < 16 {
                        TriggerMode::Edge
                    } else {
                        TriggerMode::Level
                    },
                    ..IrqConfig::default()
                }
            }),
            ppi_sgi_state: std::array::from_fn(|_| IrqState::default()),
        }
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }
}

/// `GICv3` redistributor — owns all per-vCPU SGI/PPI state.
pub struct Redistributor {
    cpus: Vec<RedistributorCpu>,
}

impl Redistributor {
    pub fn new(num_vcpus: usize) -> Self {
        Self {
            cpus: (0..num_vcpus).map(|_| RedistributorCpu::new()).collect(),
        }
    }

    /// Get a reference to a specific vCPU's redistributor.
    pub fn cpu(&self, vcpu_id: usize) -> Option<&RedistributorCpu> {
        self.cpus.get(vcpu_id)
    }

    /// Get a mutable reference to a specific vCPU's redistributor.
    pub fn cpu_mut(&mut self, vcpu_id: usize) -> Option<&mut RedistributorCpu> {
        self.cpus.get_mut(vcpu_id)
    }

    // =========================================================================
    // MMIO decode
    // =========================================================================

    /// Handle an MMIO read from the redistributor region.
    ///
    /// `offset` is relative to `GICR_BASE`.
    pub fn mmio_read(&self, offset: u64, size: u8) -> u64 {
        let (vcpu_id, frame_offset) = self.decode_offset(offset);
        let Some(vcpu_id) = vcpu_id else { return 0 };

        if frame_offset < GICR_SGI_BASE_OFFSET {
            self.read_rd_base(vcpu_id, frame_offset, size)
        } else {
            let sgi_offset = frame_offset - GICR_SGI_BASE_OFFSET;
            self.read_sgi_base(vcpu_id, sgi_offset, size)
        }
    }

    /// Handle an MMIO write to the redistributor region.
    ///
    /// Returns `Some(vcpu_id)` if delivery should be re-evaluated for that vCPU.
    /// The caller must handle delivery updates after releasing the lock.
    pub fn mmio_write(&mut self, offset: u64, data: u64, size: u8) -> Option<usize> {
        let (vcpu_id, frame_offset) = self.decode_offset(offset);
        let vcpu_id = vcpu_id?;

        if frame_offset < GICR_SGI_BASE_OFFSET {
            self.write_rd_base(vcpu_id, frame_offset, data, size);
            None
        } else {
            let sgi_offset = frame_offset - GICR_SGI_BASE_OFFSET;
            self.write_sgi_base(vcpu_id, sgi_offset, data, size)
        }
    }

    /// Decode an offset into (`vcpu_id`, `frame_offset`).
    #[allow(clippy::cast_possible_truncation)] // offset / GICR_CPU_SIZE (128KiB) always fits in usize
    const fn decode_offset(&self, offset: u64) -> (Option<usize>, u64) {
        let vcpu_id = (offset / GICR_CPU_SIZE) as usize;
        if vcpu_id >= self.cpus.len() {
            return (None, 0);
        }
        let frame_offset = offset % GICR_CPU_SIZE;
        (Some(vcpu_id), frame_offset)
    }

    // =========================================================================
    // RD_base frame (frame 0: 0x0000 - 0xFFFF)
    // =========================================================================

    fn read_rd_base(&self, vcpu_id: usize, offset: u64, size: u8) -> u64 {
        let cpu = &self.cpus[vcpu_id];
        match offset {
            GICR_CTLR => 0,                        // RES0 for our implementation
            GICR_IIDR => u64::from(GICD_IIDR_VAL), // Same as GICD
            GICR_TYPER => {
                let typer = self.gicr_typer(vcpu_id);
                if size == 4 {
                    typer & 0xFFFF_FFFF
                } else {
                    typer
                }
            }
            // GICR_TYPER high 32 bits (offset 0x000C)
            0x000C => {
                let typer = self.gicr_typer(vcpu_id);
                (typer >> 32) & 0xFFFF_FFFF
            }
            GICR_STATUSR => 0,
            GICR_WAKER => u64::from(cpu.waker),
            GICR_PIDR2 => u64::from(GICD_PIDR2_VAL),
            _ => {
                log::trace!("GICR RD_base read RAZ: vcpu={vcpu_id} offset={offset:#x}");
                0
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // MMIO register decode: 32-bit register value from 64-bit bus
    fn write_rd_base(&mut self, vcpu_id: usize, offset: u64, data: u64, _size: u8) {
        let cpu = &mut self.cpus[vcpu_id];
        match offset {
            GICR_WAKER => {
                let data32 = data as u32;
                let sleep = data32 & GICR_WAKER_PROCESSOR_SLEEP;
                if sleep == 0 {
                    // Guest clearing ProcessorSleep → clear ChildrenAsleep immediately
                    cpu.waker = 0;
                } else {
                    cpu.waker = GICR_WAKER_PROCESSOR_SLEEP | GICR_WAKER_CHILDREN_ASLEEP;
                }
            }
            _ => {
                log::trace!("GICR RD_base write WI: vcpu={vcpu_id} offset={offset:#x}");
            }
        }
    }

    // =========================================================================
    // SGI_base frame (frame 1: 0x10000 - 0x1FFFF)
    // =========================================================================

    fn read_sgi_base(&self, vcpu_id: usize, offset: u64, size: u8) -> u64 {
        let cpu = &self.cpus[vcpu_id];
        match offset {
            GICR_IGROUPR0 => {
                let mut val = 0u32;
                for i in 0..32 {
                    if cpu.ppi_sgi_config[i].group {
                        val |= 1 << i;
                    }
                }
                u64::from(val)
            }

            GICR_ISENABLER0 | GICR_ICENABLER0 => {
                let mut val = 0u32;
                for i in 0..32 {
                    if cpu.ppi_sgi_config[i].enabled {
                        val |= 1 << i;
                    }
                }
                u64::from(val)
            }

            GICR_ISPENDR0 | GICR_ICPENDR0 => {
                let mut val = 0u32;
                for i in 0..32 {
                    if cpu.ppi_sgi_state[i].pending {
                        val |= 1 << i;
                    }
                }
                u64::from(val)
            }

            GICR_ISACTIVER0 | GICR_ICACTIVER0 => {
                let mut val = 0u32;
                for i in 0..32 {
                    if cpu.ppi_sgi_state[i].active {
                        val |= 1 << i;
                    }
                }
                u64::from(val)
            }

            // IPRIORITYR: 32 bytes for IRQs 0-31
            o if (0x0400..0x0420).contains(&o) => Self::read_priority(cpu, o - 0x0400, size),

            // ICFGR0 (SGIs 0-15) — always edge, read-only
            GICR_ICFGR0 => 0xAAAA_AAAA, // All edge-triggered

            // ICFGR1 (PPIs 16-31)
            GICR_ICFGR1 => {
                let mut val = 0u32;
                for i in 0..16 {
                    if cpu.ppi_sgi_config[16 + i].trigger == TriggerMode::Edge {
                        val |= 0b10 << (i * 2);
                    }
                }
                u64::from(val)
            }

            // IGRPMODR0: always 0
            GICR_IGRPMODR0 => 0,

            _ => {
                log::trace!("GICR SGI_base read RAZ: vcpu={vcpu_id} offset={offset:#x}");
                0
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // MMIO register decode: 32-bit register values from 64-bit bus
    fn write_sgi_base(
        &mut self,
        vcpu_id: usize,
        offset: u64,
        data: u64,
        size: u8,
    ) -> Option<usize> {
        let cpu = &mut self.cpus[vcpu_id];
        let data32 = data as u32;
        let mut needs_delivery = false;

        match offset {
            GICR_IGROUPR0 => {
                for i in 0..32 {
                    cpu.ppi_sgi_config[i].group = data32 & (1 << i) != 0;
                }
                // Group flips can change deliverability for any already-pending
                // SGI/PPI in the bank — highest_pending only selects Group-1.
                needs_delivery = true;
            }

            GICR_ISENABLER0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_config[i].enabled = true;
                    }
                }
                needs_delivery = true;
            }

            GICR_ICENABLER0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_config[i].enabled = false;
                    }
                }
                needs_delivery = true;
            }

            GICR_ISPENDR0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_state[i].pending = true;
                    }
                }
                needs_delivery = true;
            }

            // ICPENDR0 — trigger-aware: must also clear edge_latch,
            // and must respect hw_level for level-triggered IRQs (IHI0069D §8.9.8).
            GICR_ICPENDR0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_state[i].pending = false;
                        cpu.ppi_sgi_state[i].edge_latch = false;
                        // Level-triggered: re-pend if line still asserted
                        if cpu.ppi_sgi_config[i].trigger == TriggerMode::Level
                            && cpu.ppi_sgi_state[i].hw_level
                        {
                            cpu.ppi_sgi_state[i].pending = true;
                        }
                    }
                }
                needs_delivery = true;
            }

            GICR_ISACTIVER0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_state[i].active = true;
                    }
                }
                // Setting active hides the IRQ from highest_pending — the
                // cached line must be re-evaluated so it can drop.
                needs_delivery = true;
            }

            GICR_ICACTIVER0 => {
                for i in 0..32 {
                    if data32 & (1 << i) != 0 {
                        cpu.ppi_sgi_state[i].active = false;
                    }
                }
                needs_delivery = true;
            }

            // IPRIORITYR: 32 bytes
            o if (0x0400..0x0420).contains(&o) => {
                Self::write_priority(cpu, o - 0x0400, data, size);
                needs_delivery = true;
            }

            // ICFGR0: WI (SGIs always edge-triggered), IGRPMODR0: WI
            GICR_ICFGR0 | GICR_IGRPMODR0 => {}

            // ICFGR1: PPIs 16-31
            GICR_ICFGR1 => {
                for i in 0..16 {
                    let field = (data32 >> (i * 2)) & 0x3;
                    cpu.ppi_sgi_config[16 + i].trigger = if field & 0b10 != 0 {
                        TriggerMode::Edge
                    } else {
                        TriggerMode::Level
                    };
                }
            }

            _ => {
                log::trace!("GICR SGI_base write WI: vcpu={vcpu_id} offset={offset:#x}");
            }
        }

        if needs_delivery { Some(vcpu_id) } else { None }
    }

    // =========================================================================
    // Priority helpers (delegate to shared read/write_priority_bytes)
    // =========================================================================

    #[allow(clippy::cast_possible_truncation)] // MMIO byte offset bounded by 32-byte IPRIORITYR range
    fn read_priority(cpu: &RedistributorCpu, byte_offset: u64, size: u8) -> u64 {
        read_priority_bytes(&cpu.ppi_sgi_config, byte_offset as usize, size)
    }

    #[allow(clippy::cast_possible_truncation)] // MMIO byte offset bounded by 32-byte IPRIORITYR range
    fn write_priority(cpu: &mut RedistributorCpu, byte_offset: u64, data: u64, size: u8) {
        write_priority_bytes(
            &mut cpu.ppi_sgi_config,
            byte_offset as usize,
            data,
            size,
            PRIORITY_MASK,
        );
    }

    // =========================================================================
    // GICR_TYPER encoding
    // =========================================================================

    #[allow(clippy::cast_possible_truncation)] // vcpu_id fits in u64; offset/GICR_CPU_SIZE fits in usize
    fn gicr_typer(&self, vcpu_id: usize) -> u64 {
        let affinity = vcpu_id as u64;
        let processor_number = vcpu_id as u64;
        let last = u64::from(vcpu_id == self.cpus.len() - 1);

        (affinity << 32)            // Bits [63:32] = Affinity_Value
        | (processor_number << 8)   // Bits [23:8] = Processor_Number
        | (last << 4) // Bit [4] = Last
    }

    // =========================================================================
    // SGI injection (cross-vCPU)
    // =========================================================================

    /// Inject an SGI from one vCPU to target vCPUs.
    ///
    /// Called from `ICC_SGI1R_EL1` write handling.
    /// Returns the list of vCPU IDs that need delivery re-evaluation.
    /// The caller must call `update_delivery_for_vcpu` for each AFTER releasing
    /// the redistributor lock to avoid deadlock.
    pub fn inject_sgi(&mut self, intid: u32, _source_vcpu: usize, targets: &[usize]) -> Vec<usize> {
        debug_assert!(
            targets.windows(2).all(|w| w[0] <= w[1]),
            "inject_sgi targets must be in ascending order"
        );
        let mut affected = Vec::new();

        for &target in targets {
            if target < self.cpus.len() && intid < 16 {
                let cpu = &mut self.cpus[target];
                cpu.ppi_sgi_state[intid as usize].pending = true;
                cpu.ppi_sgi_state[intid as usize].edge_latch = true;
                affected.push(target);
            }
        }
        affected
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
    use crate::{GicConfig, GicV3, NullInterruptSink};

    #[test]
    fn gicr_typer_encoding() {
        let redist = Redistributor::new(4);
        let typer0 = redist.gicr_typer(0);
        // Aff0=0, ProcNum=0, Last=0
        assert_eq!(typer0 >> 32, 0); // Affinity
        assert_eq!((typer0 >> 8) & 0xFFFF, 0); // ProcNum
        assert_eq!((typer0 >> 4) & 1, 0); // Last=0

        let typer3 = redist.gicr_typer(3);
        assert_eq!(typer3 >> 32, 3); // Affinity=3
        assert_eq!((typer3 >> 4) & 1, 1); // Last=1
    }

    #[test]
    fn waker_handshake() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Initial state: ProcessorSleep=1, ChildrenAsleep=1
        let waker = {
            let r = gic.redistributor().lock();
            r.mmio_read(GICR_WAKER, 4) as u32
        };
        assert_ne!(waker & GICR_WAKER_PROCESSOR_SLEEP, 0);
        assert_ne!(waker & GICR_WAKER_CHILDREN_ASLEEP, 0);

        // Clear ProcessorSleep → ChildrenAsleep clears immediately
        {
            let mut r = gic.redistributor().lock();
            r.mmio_write(GICR_WAKER, 0, 4);
        }
        let waker = {
            let r = gic.redistributor().lock();
            r.mmio_read(GICR_WAKER, 4) as u32
        };
        assert_eq!(waker & GICR_WAKER_PROCESSOR_SLEEP, 0);
        assert_eq!(waker & GICR_WAKER_CHILDREN_ASLEEP, 0);
    }

    #[test]
    fn sgi_base_isenabler() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        // Write ISENABLER0 at SGI_base
        let sgi_offset = GICR_SGI_BASE_OFFSET + GICR_ISENABLER0;
        {
            let mut r = gic.redistributor().lock();
            r.mmio_write(sgi_offset, 0xFFFF_0000, 4);
        }

        let val = {
            let r = gic.redistributor().lock();
            r.mmio_read(sgi_offset, 4)
        };
        assert_eq!(val, 0xFFFF_0000);
    }

    #[test]
    // Reason: lock guard scope intentionally spans the assertion
    // block to observe a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn sgi_injection() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 4,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        {
            let mut r = gic.redistributor().lock();
            let affected = r.inject_sgi(5, 0, &[1, 3]);
            assert_eq!(affected, vec![1, 3]);
        }

        // Check that SGI 5 is pending on vCPUs 1 and 3
        let r = gic.redistributor().lock();
        assert!(r.cpus[1].ppi_sgi_state[5].pending);
        assert!(r.cpus[3].ppi_sgi_state[5].pending);
        assert!(!r.cpus[0].ppi_sgi_state[5].pending);
        assert!(!r.cpus[2].ppi_sgi_state[5].pending);
    }

    #[test]
    fn pidr2_from_rd_base() {
        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        let val = {
            let r = gic.redistributor().lock();
            r.mmio_read(GICR_PIDR2, 4)
        };
        assert_eq!(val, u64::from(GICD_PIDR2_VAL));
    }

    #[test]
    fn multi_vcpu_routing() {
        let redist = Redistributor::new(4);
        // Each vCPU should get its own GICR_TYPER
        for i in 0..4 {
            let offset = i as u64 * GICR_CPU_SIZE + GICR_TYPER;
            let (vcpu_id, frame_offset) = redist.decode_offset(offset);
            assert_eq!(vcpu_id, Some(i));
            assert_eq!(frame_offset, GICR_TYPER);
        }
    }

    // =========================================================================
    // GICR_CTLR, GICR_STATUSR, GICR_IIDR
    // =========================================================================

    #[test]
    fn gicr_ctlr_reads_zero() {
        let redist = Redistributor::new(1);
        assert_eq!(redist.mmio_read(GICR_CTLR, 4), 0);
    }

    #[test]
    fn gicr_statusr_reads_zero() {
        let redist = Redistributor::new(1);
        assert_eq!(redist.mmio_read(GICR_STATUSR, 4), 0);
    }

    #[test]
    fn gicr_iidr_matches_gicd() {
        let redist = Redistributor::new(1);
        assert_eq!(redist.mmio_read(GICR_IIDR, 4), u64::from(GICD_IIDR_VAL));
    }

    // =========================================================================
    // GICR_TYPER 32-bit split reads
    // =========================================================================

    #[test]
    fn gicr_typer_32bit_split() {
        let redist = Redistributor::new(2);
        // vCPU 1: affinity=1, Last=1
        let base = GICR_CPU_SIZE; // vCPU 1
        let low = redist.mmio_read(base + GICR_TYPER, 4);
        let high = redist.mmio_read(base + 0x000C, 4);
        let full = redist.mmio_read(base + GICR_TYPER, 8);
        assert_eq!(full, (high << 32) | low);
        assert_eq!(high, 1); // Affinity=1
        assert_ne!(low & (1 << 4), 0); // Last=1
    }

    // =========================================================================
    // WAKER — set ProcessorSleep back to 1
    // =========================================================================

    #[test]
    fn waker_set_sleep() {
        let mut redist = Redistributor::new(1);
        // Wake up
        redist.mmio_write(GICR_WAKER, 0, 4);
        let waker = redist.mmio_read(GICR_WAKER, 4) as u32;
        assert_eq!(waker, 0);

        // Put back to sleep
        redist.mmio_write(GICR_WAKER, u64::from(GICR_WAKER_PROCESSOR_SLEEP), 4);
        let waker = redist.mmio_read(GICR_WAKER, 4) as u32;
        assert_ne!(waker & GICR_WAKER_PROCESSOR_SLEEP, 0);
        assert_ne!(waker & GICR_WAKER_CHILDREN_ASLEEP, 0);
    }

    // =========================================================================
    // IGROUPR0
    // =========================================================================

    #[test]
    fn igroupr0_readwrite() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Default: all Group 1 (from IrqConfig default)
        let val = redist.mmio_read(sgi + GICR_IGROUPR0, 4);
        assert_eq!(val, 0xFFFF_FFFF);

        // Set all to Group 0
        redist.mmio_write(sgi + GICR_IGROUPR0, 0, 4);
        let val = redist.mmio_read(sgi + GICR_IGROUPR0, 4);
        assert_eq!(val, 0);
    }

    // =========================================================================
    // ISENABLER0 / ICENABLER0
    // =========================================================================

    #[test]
    fn icenabler0_clears_bits() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Enable all
        redist.mmio_write(sgi + GICR_ISENABLER0, 0xFFFF_FFFF, 4);
        let val = redist.mmio_read(sgi + GICR_ISENABLER0, 4);
        assert_eq!(val, 0xFFFF_FFFF);

        // Clear lower 16
        redist.mmio_write(sgi + GICR_ICENABLER0, 0x0000_FFFF, 4);
        let val = redist.mmio_read(sgi + GICR_ISENABLER0, 4);
        assert_eq!(val, 0xFFFF_0000);
    }

    // =========================================================================
    // ISPENDR0 / ICPENDR0
    // =========================================================================

    #[test]
    fn ispendr0_icpendr0_roundtrip() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        redist.mmio_write(sgi + GICR_ISPENDR0, 0x00FF, 4);
        let val = redist.mmio_read(sgi + GICR_ISPENDR0, 4);
        assert_eq!(val, 0xFF);

        redist.mmio_write(sgi + GICR_ICPENDR0, 0x000F, 4);
        let val = redist.mmio_read(sgi + GICR_ISPENDR0, 4);
        assert_eq!(val, 0xF0);
    }

    // =========================================================================
    // ISACTIVER0 / ICACTIVER0
    // =========================================================================

    #[test]
    fn isactiver0_icactiver0_roundtrip() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        redist.mmio_write(sgi + GICR_ISACTIVER0, 0xFF00, 4);
        let val = redist.mmio_read(sgi + GICR_ISACTIVER0, 4);
        assert_eq!(val, 0xFF00);

        redist.mmio_write(sgi + GICR_ICACTIVER0, 0x0F00, 4);
        let val = redist.mmio_read(sgi + GICR_ISACTIVER0, 4);
        assert_eq!(val, 0xF000);
    }

    // =========================================================================
    // IPRIORITYR
    // =========================================================================

    #[test]
    fn ipriorityr_byte_readwrite() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Write byte for IRQ 5
        redist.mmio_write(sgi + 0x0405, 0xC0, 1);
        assert_eq!(redist.mmio_read(sgi + 0x0405, 1), 0xC0);
    }

    #[test]
    fn ipriorityr_4byte_readwrite() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Write 4 bytes for IRQs 0-3.
        // Values must be aligned to PRIORITY_MASK (top 5 bits implemented).
        redist.mmio_write(sgi + 0x0400, 0x1020_3040, 4);
        assert_eq!(redist.mmio_read(sgi + 0x0400, 4), 0x1020_3040);

        // Verify individual bytes
        assert_eq!(redist.mmio_read(sgi + 0x0400, 1), 0x40);
        assert_eq!(redist.mmio_read(sgi + 0x0401, 1), 0x30);
    }

    // =========================================================================
    // ICFGR0 / ICFGR1
    // =========================================================================

    #[test]
    fn icfgr0_always_edge() {
        let redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        // SGIs are always edge-triggered
        assert_eq!(redist.mmio_read(sgi + GICR_ICFGR0, 4), 0xAAAA_AAAA);
    }

    #[test]
    fn icfgr0_write_ignored() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        // Write to ICFGR0 should be WI
        redist.mmio_write(sgi + GICR_ICFGR0, 0, 4);
        // Still all-edge
        assert_eq!(redist.mmio_read(sgi + GICR_ICFGR0, 4), 0xAAAA_AAAA);
    }

    #[test]
    fn icfgr1_readwrite() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Default: PPIs 16-31 are level-triggered
        assert_eq!(redist.mmio_read(sgi + GICR_ICFGR1, 4), 0);

        // Set all PPIs to edge
        redist.mmio_write(sgi + GICR_ICFGR1, 0xAAAA_AAAA, 4);
        assert_eq!(redist.mmio_read(sgi + GICR_ICFGR1, 4), 0xAAAA_AAAA);
    }

    // =========================================================================
    // IGRPMODR0
    // =========================================================================

    #[test]
    fn igrpmodr0_reads_zero_write_ignored() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        assert_eq!(redist.mmio_read(sgi + GICR_IGRPMODR0, 4), 0);
        redist.mmio_write(sgi + GICR_IGRPMODR0, 0xFFFF_FFFF, 4);
        assert_eq!(redist.mmio_read(sgi + GICR_IGRPMODR0, 4), 0);
    }

    // =========================================================================
    // ICPENDR0 trigger-aware
    // =========================================================================

    #[test]
    fn icpendr0_clears_edge_latch() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // SGI 3 is edge-triggered, pending with edge_latch
        redist.cpus[0].ppi_sgi_state[3].pending = true;
        redist.cpus[0].ppi_sgi_state[3].edge_latch = true;

        redist.mmio_write(sgi + GICR_ICPENDR0, 1 << 3, 4);

        assert!(!redist.cpus[0].ppi_sgi_state[3].pending);
        assert!(
            !redist.cpus[0].ppi_sgi_state[3].edge_latch,
            "ICPENDR must clear edge_latch for edge-triggered IRQs"
        );
    }

    #[test]
    fn icpendr0_level_respects_hw_level() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // PPI 20 is level-triggered, pending, hw_level still asserted
        redist.cpus[0].ppi_sgi_config[20].trigger = TriggerMode::Level;
        redist.cpus[0].ppi_sgi_state[20].pending = true;
        redist.cpus[0].ppi_sgi_state[20].hw_level = true;

        redist.mmio_write(sgi + GICR_ICPENDR0, 1 << 20, 4);

        assert!(
            redist.cpus[0].ppi_sgi_state[20].pending,
            "Level IRQ should re-pend if hw_level still asserted"
        );
    }

    #[test]
    fn icpendr0_level_clears_when_hw_deasserted() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        redist.cpus[0].ppi_sgi_config[20].trigger = TriggerMode::Level;
        redist.cpus[0].ppi_sgi_state[20].pending = true;
        redist.cpus[0].ppi_sgi_state[20].hw_level = false;

        redist.mmio_write(sgi + GICR_ICPENDR0, 1 << 20, 4);

        assert!(!redist.cpus[0].ppi_sgi_state[20].pending);
    }

    // =========================================================================
    // Out-of-bounds vCPU
    // =========================================================================

    #[test]
    fn out_of_bounds_vcpu_read_returns_zero() {
        let redist = Redistributor::new(2);
        // vCPU 5 doesn't exist
        let offset = 5 * GICR_CPU_SIZE + GICR_TYPER;
        assert_eq!(redist.mmio_read(offset, 4), 0);
    }

    #[test]
    fn out_of_bounds_vcpu_write_returns_none() {
        let mut redist = Redistributor::new(2);
        let offset = 5 * GICR_CPU_SIZE + GICR_SGI_BASE_OFFSET + GICR_ISENABLER0;
        assert!(redist.mmio_write(offset, 0xFFFF_FFFF, 4).is_none());
    }

    // =========================================================================
    // Multi-vCPU isolation
    // =========================================================================

    #[test]
    fn multi_vcpu_sgi_base_isolation() {
        let mut redist = Redistributor::new(3);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Enable IRQs on vCPU 1 only
        let vcpu1_base = GICR_CPU_SIZE;
        redist.mmio_write(vcpu1_base + sgi + GICR_ISENABLER0, 0xFFFF_FFFF, 4);

        // vCPU 0 should still have nothing enabled
        let val0 = redist.mmio_read(sgi + GICR_ISENABLER0, 4);
        assert_eq!(val0, 0);

        let val1 = redist.mmio_read(vcpu1_base + sgi + GICR_ISENABLER0, 4);
        assert_eq!(val1, 0xFFFF_FFFF);
    }

    // =========================================================================
    // SGI injection edge cases
    // =========================================================================

    #[test]
    fn sgi_injection_out_of_range_intid() {
        let mut redist = Redistributor::new(2);
        // INTID 16 is a PPI, not SGI
        let affected = redist.inject_sgi(16, 0, &[1]);
        assert!(affected.is_empty());
    }

    #[test]
    fn sgi_injection_out_of_range_vcpu() {
        let mut redist = Redistributor::new(2);
        let affected = redist.inject_sgi(5, 0, &[5, 10]);
        assert!(affected.is_empty());
    }

    // =========================================================================
    // Snapshot / Restore
    // =========================================================================

    #[test]
    fn freeze_thaw_roundtrip() {
        let mut redist = Redistributor::new(2);

        // Modify vCPU 0
        redist.cpus[0].waker = 0;
        redist.cpus[0].ppi_sgi_config[5].enabled = true;
        redist.cpus[0].ppi_sgi_config[5].priority = 0x40;
        redist.cpus[0].ppi_sgi_state[5].pending = true;

        // Modify vCPU 1
        redist.cpus[1].ppi_sgi_config[10].trigger = TriggerMode::Edge;

        // Freeze/thaw each CPU individually
        let pod0 = crate::snapshot::freeze_redistributor(&redist.cpus[0]);
        let pod1 = crate::snapshot::freeze_redistributor(&redist.cpus[1]);

        let mut redist2 = Redistributor::new(2);
        crate::snapshot::thaw_redistributor(redist2.cpu_mut(0).unwrap(), &pod0);
        crate::snapshot::thaw_redistributor(redist2.cpu_mut(1).unwrap(), &pod1);

        assert_eq!(redist2.cpus[0].waker, 0);
        assert!(redist2.cpus[0].ppi_sgi_config[5].enabled);
        assert_eq!(redist2.cpus[0].ppi_sgi_config[5].priority, 0x40);
        assert!(redist2.cpus[0].ppi_sgi_state[5].pending);
        assert_eq!(
            redist2.cpus[1].ppi_sgi_config[10].trigger,
            TriggerMode::Edge
        );
    }

    // =========================================================================
    // RAZ / WI for unknown SGI_base / RD_base offsets
    // =========================================================================

    #[test]
    fn raz_for_unknown_rd_base_offset() {
        let redist = Redistributor::new(1);
        // Unknown RD_base offset
        assert_eq!(redist.mmio_read(0x0020, 4), 0);
        assert_eq!(redist.mmio_read(0x0100, 4), 0);
    }

    #[test]
    fn raz_for_unknown_sgi_base_offset() {
        let redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        assert_eq!(redist.mmio_read(sgi + 0x0F00, 4), 0);
    }

    #[test]
    fn wi_for_unknown_rd_base_write() {
        let mut redist = Redistributor::new(1);
        redist.mmio_write(0x0020, 0xFFFF_FFFF, 4); // No crash = pass
    }

    #[test]
    fn wi_for_unknown_sgi_base_write() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        let result = redist.mmio_write(sgi + 0x0F00, 0xFFFF_FFFF, 4);
        assert!(result.is_none());
    }

    // =========================================================================
    // needs_delivery return values
    // =========================================================================

    #[test]
    fn mmio_write_returns_delivery_needed() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // ISENABLER should return Some(vcpu_id)
        let r = redist.mmio_write(sgi + GICR_ISENABLER0, 1, 4);
        assert_eq!(r, Some(0));

        // ICENABLER should return Some(vcpu_id)
        let r = redist.mmio_write(sgi + GICR_ICENABLER0, 1, 4);
        assert_eq!(r, Some(0));

        // ISPENDR should return Some(vcpu_id)
        let r = redist.mmio_write(sgi + GICR_ISPENDR0, 1, 4);
        assert_eq!(r, Some(0));

        // ICPENDR should return Some(vcpu_id)
        let r = redist.mmio_write(sgi + GICR_ICPENDR0, 1, 4);
        assert_eq!(r, Some(0));

        // IGROUPR0 must re-drive delivery — flipping group can change
        // whether an already-pending PPI/SGI is selectable.
        let r = redist.mmio_write(sgi + GICR_IGROUPR0, 0xFFFF_FFFF, 4);
        assert_eq!(r, Some(0));
    }

    // =========================================================================
    // Coverage: ICFGR1 write with level fields (line 340)
    // =========================================================================

    #[test]
    fn icfgr1_write_mixed_edge_and_level() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;

        // Write: PPI 16-17 = edge, PPI 18-31 = level
        // First 2 fields (4 bits) = 0b1010 (edge,edge), rest = 0
        redist.mmio_write(sgi + GICR_ICFGR1, 0x0000_000A, 4);

        assert_eq!(redist.cpus[0].ppi_sgi_config[16].trigger, TriggerMode::Edge);
        assert_eq!(redist.cpus[0].ppi_sgi_config[17].trigger, TriggerMode::Edge);
        assert_eq!(
            redist.cpus[0].ppi_sgi_config[18].trigger,
            TriggerMode::Level
        );
        assert_eq!(
            redist.cpus[0].ppi_sgi_config[31].trigger,
            TriggerMode::Level
        );
    }

    // =========================================================================
    // Coverage: Priority read out-of-range idx (line 364)
    // =========================================================================

    #[test]
    fn priority_read_out_of_range_byte() {
        let redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        // Byte offset 32 (IRQ 32 doesn't exist in redistributor)
        // IPRIORITYR range is 0x0400-0x041F (32 bytes for IRQs 0-31)
        // Offset 0x0420 is outside the range — but it's also outside the
        // (0x0400..0x0420).contains(&o) check, so it goes to RAZ.
        // To hit line 364, we need idx >= 32 with size=1.
        // Actually, the range check is (0x0400..0x0420), so offset 0x041F is
        // byte_offset = 0x1F = 31, idx=31 < 32, still in range.
        // Line 364 is unreachable via MMIO because the offset range check
        // prevents it. Let's verify the RAZ behavior instead.
        assert_eq!(redist.mmio_read(sgi + 0x0420, 1), 0); // Outside range → RAZ
    }

    // =========================================================================
    // Coverage: Priority read/write with unusual size (lines 378, 399)
    // =========================================================================

    #[test]
    fn priority_read_unsupported_size() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        redist.cpus[0].ppi_sgi_config[0].priority = 0xA0;
        // Read with size=2 (unsupported) — should return 0
        assert_eq!(redist.mmio_read(sgi + 0x0400, 2), 0);
    }

    #[test]
    fn priority_write_unsupported_size() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        redist.cpus[0].ppi_sgi_config[0].priority = 0xA0;
        // Write with size=2 (unsupported) — should be ignored
        redist.mmio_write(sgi + 0x0400, 0xFF, 2);
        assert_eq!(
            redist.cpus[0].ppi_sgi_config[0].priority, 0xA0,
            "Priority should not change with unsupported size"
        );
    }

    // =========================================================================
    // Coverage: ICACTIVER0 returns delivery needed
    // =========================================================================

    #[test]
    fn icactiver0_returns_delivery_needed() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        let r = redist.mmio_write(sgi + GICR_ICACTIVER0, 1, 4);
        assert_eq!(r, Some(0));
    }

    // =========================================================================
    // ISACTIVER0 must request delivery re-eval — setting active filters the
    // IRQ out of highest_pending, so any cached line state must be re-driven.
    // =========================================================================

    #[test]
    fn isactiver0_returns_delivery_needed() {
        let mut redist = Redistributor::new(1);
        let sgi = GICR_SGI_BASE_OFFSET;
        let r = redist.mmio_write(sgi + GICR_ISACTIVER0, 1, 4);
        assert_eq!(r, Some(0));
    }

    // =========================================================================
    // C11: Redistributor restore with short snapshot
    // =========================================================================

    #[test]
    fn thaw_overwrites_existing_state() {
        let mut redist = Redistributor::new(1);

        // Set up state across all 32 IRQs
        redist.cpus[0].ppi_sgi_config[5].enabled = true;
        redist.cpus[0].ppi_sgi_config[5].priority = 0x40;
        redist.cpus[0].ppi_sgi_state[5].pending = true;
        redist.cpus[0].ppi_sgi_config[30].enabled = true;
        redist.cpus[0].ppi_sgi_config[30].priority = 0xA0;
        redist.cpus[0].ppi_sgi_state[30].pending = true;

        // Freeze a fresh CPU (defaults) and thaw into the modified one
        let fresh = RedistributorCpu::new();
        let pod = crate::snapshot::freeze_redistributor(&fresh);
        crate::snapshot::thaw_redistributor(redist.cpu_mut(0).unwrap(), &pod);

        // All state should be reset to defaults
        assert!(!redist.cpus[0].ppi_sgi_config[5].enabled);
        assert_eq!(redist.cpus[0].ppi_sgi_config[5].priority, 0);
        assert!(!redist.cpus[0].ppi_sgi_state[5].pending);
        assert!(!redist.cpus[0].ppi_sgi_config[30].enabled);
        assert_eq!(redist.cpus[0].ppi_sgi_config[30].priority, 0);
        assert!(!redist.cpus[0].ppi_sgi_state[30].pending);
    }
}
