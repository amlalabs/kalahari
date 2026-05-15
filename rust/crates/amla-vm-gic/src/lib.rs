// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! Userspace `GICv3` emulator for ARM64 VMs.
//!
//! This crate provides a full software emulation of the ARM `GICv3` interrupt
//! controller, targeting HVF (macOS) where no in-kernel GIC is available.
//! It is hypervisor-agnostic and can also be used with KVM.
//!
//! # Architecture
//!
//! `GICv3` has three interfaces mapped to different access methods:
//!
//! | Interface | Access | Integration |
//! |-----------|--------|-------------|
//! | Distributor (GICD) | MMIO | `MmioDevice` registered on the MMIO bus |
//! | Redistributor (GICR) | MMIO | `MmioDevice` registered on the MMIO bus |
//! | CPU Interface (ICC) | System registers | `VcpuExit::SysReg` trap handler |
//!
//! Interrupt delivery uses a callback trait ([`InterruptSink`]) so the backend
//! can kick or wake vCPUs after GIC-level pending state changes.

pub mod consts;
mod cpu_interface;
pub mod delivery;
pub mod distributor;
pub mod irq_state;
pub mod pod_state;
pub mod priority;
pub mod redistributor;
pub mod snapshot;

pub use consts::*;
pub use delivery::{DeliveryAction, GicIrqLine, GicIrqSender, InterruptSink, NullInterruptSink};
pub use irq_state::{IrqConfig, IrqState, TriggerMode};
pub use pod_state::GicState;

use parking_lot::{Mutex, RwLock};
use std::cell::Cell;
use std::fmt;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

use crate::cpu_interface::CpuInterface;
use crate::distributor::Distributor;
use crate::priority::PriorityEngine;
use crate::redistributor::Redistributor;

mod private {
    pub trait Sealed {}
}

/// Access proof for a claimed vCPU CPU-interface.
///
/// The trait is sealed; outside this crate the only implementor is
/// `&mut GicVcpuInterface`, which keeps ICC sysreg access tied to a unique,
/// non-`Send` per-vCPU token.
#[allow(private_bounds)]
pub trait GicVcpuAccess: private::Sealed {
    /// Return the vCPU ID guarded by this access proof.
    #[doc(hidden)]
    fn vcpu_id(&mut self) -> usize;
}

/// Error returned when claiming a vCPU CPU-interface token fails.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimVcpuInterfaceError {
    /// The requested vCPU ID is outside this GIC's configured vCPU range.
    OutOfRange {
        /// Requested vCPU ID.
        vcpu_id: usize,
        /// Number of vCPUs configured for the GIC.
        num_vcpus: usize,
    },
    /// The vCPU CPU-interface is already claimed by another live token.
    AlreadyClaimed {
        /// Requested vCPU ID.
        vcpu_id: usize,
    },
}

impl fmt::Display for ClaimVcpuInterfaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::OutOfRange { vcpu_id, num_vcpus } => {
                write!(
                    f,
                    "GIC vCPU interface {vcpu_id} is out of range for {num_vcpus} vCPUs"
                )
            }
            Self::AlreadyClaimed { vcpu_id } => {
                write!(f, "GIC vCPU interface {vcpu_id} is already claimed")
            }
        }
    }
}

impl std::error::Error for ClaimVcpuInterfaceError {}

/// Unique owner token for one vCPU's GIC CPU-interface.
///
/// The token is deliberately neither `Send` nor `Sync`, so sysreg handling for
/// a claimed vCPU cannot be moved to or shared with another thread through safe
/// Rust. Dropping the token releases the claim.
///
/// ```compile_fail
/// use std::sync::Arc;
/// use amla_vm_gic::{GicConfig, GicV3, ICC_PMR_EL1, NullInterruptSink};
///
/// let gic = GicV3::new(GicConfig::default(), Arc::new(NullInterruptSink));
/// gic.handle_sysreg_write(0usize, ICC_PMR_EL1, 0xff);
/// ```
#[must_use]
#[derive(Debug)]
pub struct GicVcpuInterface<'g> {
    vcpu_id: usize,
    claims: &'g [AtomicBool],
    _not_send_or_sync: PhantomData<Rc<Cell<()>>>,
}

impl GicVcpuInterface<'_> {
    /// Return the vCPU ID owned by this token.
    #[must_use]
    pub const fn vcpu_id(&self) -> usize {
        self.vcpu_id
    }
}

impl Drop for GicVcpuInterface<'_> {
    fn drop(&mut self) {
        self.claims[self.vcpu_id].store(false, Ordering::Release);
    }
}

impl private::Sealed for &mut GicVcpuInterface<'_> {}

impl GicVcpuAccess for &mut GicVcpuInterface<'_> {
    fn vcpu_id(&mut self) -> usize {
        self.vcpu_id
    }
}

#[cfg(test)]
impl private::Sealed for usize {}

#[cfg(test)]
impl GicVcpuAccess for usize {
    fn vcpu_id(&mut self) -> usize {
        *self
    }
}

/// Configuration for creating a `GICv3` instance.
#[derive(Clone, Debug)]
pub struct GicConfig {
    /// Number of vCPUs.
    pub num_vcpus: usize,
    /// GICD base address (default `0x0800_0000`).
    pub gicd_base: u64,
    /// GICR base address (default `0x080A_0000`).
    pub gicr_base: u64,
}

impl Default for GicConfig {
    fn default() -> Self {
        Self {
            num_vcpus: 1,
            gicd_base: GICD_BASE,
            gicr_base: GICR_BASE,
        }
    }
}

/// Top-level `GICv3` emulator.
///
/// Owns the distributor, redistributors, and CPU interfaces. Registered on the
/// MMIO bus for GICD/GICR accesses, and called directly for ICC sysreg traps.
pub struct GicV3 {
    config: GicConfig,
    distributor: RwLock<Distributor>,
    redistributor: Mutex<Redistributor>,
    cpu_interfaces: Vec<CpuInterface>,
    cpu_interface_claims: Vec<AtomicBool>,
    sink: Arc<dyn InterruptSink>,
    /// Last IRQ line level driven into the sink for each vCPU.
    irq_line_atoms: Vec<AtomicBool>,
    /// Atomic PMR mirrors for lock-free reads from the delivery path.
    pmr_atoms: Vec<AtomicU8>,
    /// Atomic `running_priority` mirrors.
    running_priority_atoms: Vec<AtomicU8>,
    /// Atomic igrpen1 mirrors (Group 1 enable per vCPU).
    igrpen1_atoms: Vec<AtomicBool>,
    /// Atomic bpr1 mirrors (binary point per vCPU).
    bpr1_atoms: Vec<AtomicU8>,
}

impl GicV3 {
    /// Create a new `GICv3` emulator.
    pub fn new(config: GicConfig, sink: Arc<dyn InterruptSink>) -> Self {
        let num_vcpus = config.num_vcpus;

        let distributor = RwLock::new(Distributor::new(NR_SPIS as usize));
        let redistributor = Mutex::new(Redistributor::new(num_vcpus));
        let cpu_interfaces: Vec<_> = (0..num_vcpus).map(|_| CpuInterface::new()).collect();
        let cpu_interface_claims: Vec<_> = (0..num_vcpus).map(|_| AtomicBool::new(false)).collect();
        let irq_line_atoms: Vec<_> = (0..num_vcpus).map(|_| AtomicBool::new(false)).collect();

        let pmr_atoms: Vec<_> = cpu_interfaces
            .iter()
            .map(|ci| AtomicU8::new(ci.pmr()))
            .collect();
        let running_priority_atoms: Vec<_> = cpu_interfaces
            .iter()
            .map(|ci| AtomicU8::new(ci.running_priority()))
            .collect();
        let igrpen1_atoms: Vec<_> = cpu_interfaces
            .iter()
            .map(|ci| AtomicBool::new(ci.igrpen1()))
            .collect();
        let bpr1_atoms: Vec<_> = cpu_interfaces
            .iter()
            .map(|ci| AtomicU8::new(ci.bpr1()))
            .collect();

        Self {
            config,
            distributor,
            redistributor,
            cpu_interfaces,
            cpu_interface_claims,
            sink,
            irq_line_atoms,
            pmr_atoms,
            running_priority_atoms,
            igrpen1_atoms,
            bpr1_atoms,
        }
    }

    /// Claim unique access to one vCPU's CPU-interface sysregs.
    ///
    /// The returned token must be held by the thread that owns the
    /// corresponding vCPU and passed to [`GicV3::handle_sysreg_read`] and
    /// [`GicV3::handle_sysreg_write`].
    ///
    /// Fails if `vcpu_id` is out of range or if another live token already
    /// owns the same vCPU interface.
    pub fn claim_vcpu_interface(
        &self,
        vcpu_id: usize,
    ) -> Result<GicVcpuInterface<'_>, ClaimVcpuInterfaceError> {
        let Some(claim) = self.cpu_interface_claims.get(vcpu_id) else {
            return Err(ClaimVcpuInterfaceError::OutOfRange {
                vcpu_id,
                num_vcpus: self.config.num_vcpus,
            });
        };
        claim
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ClaimVcpuInterfaceError::AlreadyClaimed { vcpu_id })?;

        Ok(GicVcpuInterface {
            vcpu_id,
            claims: &self.cpu_interface_claims,
            _not_send_or_sync: PhantomData,
        })
    }

    /// Handle a system register read (MRS) from a vCPU.
    ///
    /// Called from the vCPU exit handler for `VcpuExit::SysReg` with `is_write=false`.
    #[must_use]
    pub fn handle_sysreg_read(&self, mut vcpu: impl GicVcpuAccess, encoding: u32) -> u64 {
        let vcpu_id = vcpu.vcpu_id();
        debug_assert!(vcpu_id < self.cpu_interfaces.len(), "vcpu_id out of bounds");
        let ci = &self.cpu_interfaces[vcpu_id];
        let value = ci.handle_read(encoding, vcpu_id, self);

        // IAR1 has side effects (changes running_priority, clears pending) —
        // sync atomics and re-evaluate delivery to deassert IRQ line if
        // no more pending interrupts can preempt the new running priority.
        if encoding == ICC_IAR1_EL1 {
            self.sync_cpu_interface_atoms(vcpu_id);
            self.execute_delivery(self.update_delivery_for_vcpu(vcpu_id));
        }

        value
    }

    /// Handle a system register write (MSR) from a vCPU.
    ///
    /// Called from the vCPU exit handler for `VcpuExit::SysReg` with `is_write=true`.
    pub fn handle_sysreg_write(&self, mut vcpu: impl GicVcpuAccess, encoding: u32, value: u64) {
        let vcpu_id = vcpu.vcpu_id();
        debug_assert!(vcpu_id < self.cpu_interfaces.len(), "vcpu_id out of bounds");
        let ci = &self.cpu_interfaces[vcpu_id];
        let affected_vcpus = ci.handle_write(encoding, value, vcpu_id, self);

        // Sync atomic mirrors BEFORE delivery evaluation — handle_write
        // modifies CPU-interface state, and the priority engine reads atomics.
        self.sync_cpu_interface_atoms(vcpu_id);

        // Evaluate delivery for each affected vCPU (outside any lock)
        for vid in affected_vcpus {
            self.execute_delivery(self.update_delivery_for_vcpu(vid));
        }
    }

    /// Return whether this sysreg encoding belongs to the emulated GIC CPU interface.
    #[must_use]
    pub const fn handles_sysreg(&self, encoding: u32) -> bool {
        is_gic_sysreg(encoding)
    }

    /// Return whether the guest physical address lies inside the emulated GIC MMIO window.
    #[must_use]
    pub fn handles_mmio_addr(&self, addr: u64) -> bool {
        (self.config.gicd_base..self.config.gicd_base + GICD_SIZE).contains(&addr)
            || (self.config.gicr_base
                ..self.config.gicr_base + self.config.num_vcpus as u64 * GICR_CPU_SIZE)
                .contains(&addr)
    }

    /// Handle a guest MMIO read to either GICD or GICR. Returns `None` if the
    /// address does not belong to the GIC.
    #[must_use]
    pub fn handle_mmio_read(&self, addr: u64, size: u8) -> Option<u64> {
        if (self.config.gicd_base..self.config.gicd_base + GICD_SIZE).contains(&addr) {
            let offset = addr - self.config.gicd_base;
            let dist = self.distributor.read();
            return Some(dist.mmio_read(offset, size));
        }

        let gicr_end = self.config.gicr_base + self.config.num_vcpus as u64 * GICR_CPU_SIZE;
        if (self.config.gicr_base..gicr_end).contains(&addr) {
            let offset = addr - self.config.gicr_base;
            let redist = self.redistributor.lock();
            return Some(redist.mmio_read(offset, size));
        }

        None
    }

    /// Handle a guest MMIO write to either GICD or GICR.
    ///
    /// Returns `true` when the address belongs to the GIC and was consumed.
    pub fn handle_mmio_write(&self, addr: u64, data: u64, size: u8) -> bool {
        if (self.config.gicd_base..self.config.gicd_base + GICD_SIZE).contains(&addr) {
            let offset = addr - self.config.gicd_base;
            let needs_delivery = {
                let mut dist = self.distributor.write();
                dist.mmio_write(offset, data, size)
            };
            if needs_delivery {
                self.deliver_all_vcpus();
            }
            return true;
        }

        let gicr_end = self.config.gicr_base + self.config.num_vcpus as u64 * GICR_CPU_SIZE;
        if (self.config.gicr_base..gicr_end).contains(&addr) {
            let offset = addr - self.config.gicr_base;
            let affected_vcpu = {
                let mut redist = self.redistributor.lock();
                redist.mmio_write(offset, data, size)
            };
            if let Some(vcpu_id) = affected_vcpu {
                self.execute_delivery(self.update_delivery_for_vcpu(vcpu_id));
            }
            return true;
        }

        false
    }

    /// Set the level of an IRQ line (for level-triggered SPIs).
    pub fn set_irq_level(&self, intid: u32, level: bool) {
        let needs_delivery = if intid >= SPI_START {
            let spi_idx = (intid - SPI_START) as usize;
            let mut dist = self.distributor.write();
            dist.set_level_mut(spi_idx, level)
        } else {
            log::warn!("set_irq_level for SGI/PPI {intid} not supported via this path");
            false
        };

        if needs_delivery {
            self.deliver_all_vcpus();
        }
    }

    /// Set the level of a zero-based SPI line.
    pub fn set_spi_level(&self, spi: u32, level: bool) {
        self.set_irq_level(SPI_START + spi, level);
    }

    /// Pulse an edge-triggered IRQ.
    pub fn assert_irq_edge(&self, intid: u32) {
        let needs_delivery = if intid >= SPI_START {
            let spi_idx = (intid - SPI_START) as usize;
            let mut dist = self.distributor.write();
            dist.set_edge_mut(spi_idx)
        } else {
            log::warn!("assert_irq_edge for SGI/PPI {intid} not supported via this path");
            false
        };

        if needs_delivery {
            self.deliver_all_vcpus();
        }
    }

    /// Pulse an edge-triggered private interrupt (SGI/PPI) on a specific vCPU.
    pub fn assert_private_irq_edge(&self, vcpu_id: usize, intid: u32) {
        if intid >= SPI_START {
            log::warn!("assert_private_irq_edge called for SPI {intid}");
            return;
        }

        let mut redist = self.redistributor.lock();
        let Some(cpu) = redist.cpu_mut(vcpu_id) else {
            log::warn!("assert_private_irq_edge for invalid vcpu {vcpu_id}");
            return;
        };
        let idx = intid as usize;
        cpu.ppi_sgi_state[idx].pending = true;
        cpu.ppi_sgi_state[idx].edge_latch = true;
        drop(redist);
        self.execute_delivery(self.update_delivery_for_vcpu(vcpu_id));
    }

    /// Set the level of a private interrupt (SGI/PPI) on a specific vCPU.
    pub fn set_private_irq_level(&self, vcpu_id: usize, intid: u32, level: bool) {
        if intid >= SPI_START {
            log::warn!("set_private_irq_level called for SPI {intid}");
            return;
        }

        let mut redist = self.redistributor.lock();
        let Some(cpu) = redist.cpu_mut(vcpu_id) else {
            log::warn!("set_private_irq_level for invalid vcpu {vcpu_id}");
            return;
        };

        let idx = intid as usize;
        let trigger = cpu.ppi_sgi_config[idx].trigger;
        let st = &mut cpu.ppi_sgi_state[idx];
        let old_level = st.hw_level;
        let old_pending = st.pending;

        st.hw_level = level;
        if trigger == TriggerMode::Level {
            st.pending = level;
            if !level {
                st.edge_latch = false;
            }
        }

        let needs_delivery = old_level != st.hw_level || old_pending != st.pending;
        drop(redist);
        if needs_delivery {
            self.execute_delivery(self.update_delivery_for_vcpu(vcpu_id));
        }
    }

    /// Create an `IrqLine` for a given INTID.
    pub fn create_irq_line(&self, intid: u32) -> GicIrqLine<'_> {
        GicIrqLine::new(self, intid)
    }

    /// Freeze the entire GIC state into a `GicState`.
    #[must_use]
    pub fn freeze(&self) -> GicState {
        let dist = self.distributor.read();
        let redist = self.redistributor.lock();
        snapshot::freeze_gic(&dist, &redist, &self.cpu_interfaces, self.config.num_vcpus)
    }

    /// Thaw GIC state from a `GicState`.
    ///
    /// After loading all state, re-drives IRQ delivery for every vCPU
    /// so the physical interrupt lines match the restored pending state.
    pub fn thaw(&self, state: &GicState) -> Result<(), amla_core::VmmError> {
        {
            let mut dist = self.distributor.write();
            let mut redist = self.redistributor.lock();
            snapshot::thaw_gic(
                &mut dist,
                &mut redist,
                &self.cpu_interfaces,
                state,
                self.config.num_vcpus,
            )?;
        }
        for i in 0..self.config.num_vcpus {
            self.sync_cpu_interface_atoms(i);
        }
        // Re-drive delivery: signal pending interrupts to the hypervisor
        self.force_deliver_all_vcpus();
        Ok(())
    }

    /// Reset per-vCPU redistributor and CPU-interface state to construction defaults.
    ///
    /// PSCI `CPU_ON` is a reset-like transition for the target CPU. Device-wide
    /// distributor state remains intact, but SGI/PPI and ICC state are local to
    /// the powered-off CPU and must not leak across a `CPU_OFF`/`CPU_ON` cycle.
    pub fn reset_vcpu(&self, mut vcpu: impl GicVcpuAccess) {
        let vcpu_id = vcpu.vcpu_id();
        if vcpu_id >= self.config.num_vcpus {
            return;
        }
        {
            let mut redist = self.redistributor.lock();
            if let Some(cpu) = redist.cpu_mut(vcpu_id) {
                cpu.reset();
            }
        }
        self.cpu_interfaces[vcpu_id].reset();
        self.sync_cpu_interface_atoms(vcpu_id);
        self.execute_delivery_forced(self.update_delivery_for_vcpu(vcpu_id));
    }

    /// Evaluate and execute delivery for all vCPUs.
    fn deliver_all_vcpus(&self) {
        for vcpu_id in 0..self.config.num_vcpus {
            self.execute_delivery(self.update_delivery_for_vcpu(vcpu_id));
        }
    }

    /// Force delivery callbacks for all vCPUs regardless of cached line state.
    fn force_deliver_all_vcpus(&self) {
        for vcpu_id in 0..self.config.num_vcpus {
            self.execute_delivery_forced(self.update_delivery_for_vcpu(vcpu_id));
        }
    }

    /// Execute a delivery action (call sink outside any lock).
    fn execute_delivery(&self, action: DeliveryAction) {
        let prev_pending =
            self.irq_line_atoms[action.vcpu_id].swap(action.pending, Ordering::AcqRel);
        if prev_pending == action.pending {
            log::debug!(
                "gic delivery steady: vcpu={} pending={} pmr={:#x} running={:#x} igrpen1={} bpr1={}",
                action.vcpu_id,
                action.pending,
                self.pmr_atomic(action.vcpu_id),
                self.running_priority_atomic(action.vcpu_id),
                self.igrpen1_atomic(action.vcpu_id),
                self.bpr1_atomic(action.vcpu_id)
            );
            return;
        }
        log::debug!(
            "gic delivery transition: vcpu={} pending={} prev_pending={} pmr={:#x} running={:#x} igrpen1={} bpr1={}",
            action.vcpu_id,
            action.pending,
            prev_pending,
            self.pmr_atomic(action.vcpu_id),
            self.running_priority_atomic(action.vcpu_id),
            self.igrpen1_atomic(action.vcpu_id),
            self.bpr1_atomic(action.vcpu_id)
        );
        self.sink.signal_irq(action.vcpu_id, action.pending);
        if action.pending {
            self.sink.wake_vcpu(action.vcpu_id);
        }
    }

    /// Execute a delivery action without suppressing steady-state callbacks.
    fn execute_delivery_forced(&self, action: DeliveryAction) {
        self.irq_line_atoms[action.vcpu_id].store(action.pending, Ordering::Release);
        log::debug!(
            "gic delivery forced: vcpu={} pending={} pmr={:#x} running={:#x} igrpen1={} bpr1={}",
            action.vcpu_id,
            action.pending,
            self.pmr_atomic(action.vcpu_id),
            self.running_priority_atomic(action.vcpu_id),
            self.igrpen1_atomic(action.vcpu_id),
            self.bpr1_atomic(action.vcpu_id)
        );
        self.sink.signal_irq(action.vcpu_id, action.pending);
        if action.pending {
            self.sink.wake_vcpu(action.vcpu_id);
        }
    }

    /// Get the number of vCPUs.
    #[must_use]
    pub const fn num_vcpus(&self) -> usize {
        self.config.num_vcpus
    }

    /// Get the atomic PMR for a vCPU (lock-free read from delivery path).
    #[must_use]
    pub fn pmr_atomic(&self, vcpu_id: usize) -> u8 {
        self.pmr_atoms[vcpu_id].load(Ordering::Acquire)
    }

    /// Get the atomic running priority for a vCPU (lock-free read from delivery path).
    #[must_use]
    pub fn running_priority_atomic(&self, vcpu_id: usize) -> u8 {
        self.running_priority_atoms[vcpu_id].load(Ordering::Acquire)
    }

    /// Get the atomic igrpen1 for a vCPU (lock-free read from delivery path).
    #[must_use]
    pub fn igrpen1_atomic(&self, vcpu_id: usize) -> bool {
        self.igrpen1_atoms[vcpu_id].load(Ordering::Acquire)
    }

    /// Get the atomic bpr1 for a vCPU (lock-free read from delivery path).
    #[must_use]
    pub fn bpr1_atomic(&self, vcpu_id: usize) -> u8 {
        self.bpr1_atoms[vcpu_id].load(Ordering::Acquire)
    }

    /// Sync all CPU interface atomic mirrors for a vCPU.
    ///
    /// Uses `Release` ordering so that cross-thread reads (via `Acquire`)
    /// observe the most recent values when evaluating interrupt delivery
    /// for a different vCPU.
    pub(crate) fn sync_cpu_interface_atoms(&self, vcpu_id: usize) {
        let ci = &self.cpu_interfaces[vcpu_id];
        self.pmr_atoms[vcpu_id].store(ci.pmr(), Ordering::Release);
        self.running_priority_atoms[vcpu_id].store(ci.running_priority(), Ordering::Release);
        self.igrpen1_atoms[vcpu_id].store(ci.igrpen1(), Ordering::Release);
        self.bpr1_atoms[vcpu_id].store(ci.bpr1(), Ordering::Release);
    }

    /// Get access to the distributor (read lock).
    pub const fn distributor(&self) -> &RwLock<Distributor> {
        &self.distributor
    }

    /// Get access to the redistributor (mutex).
    pub const fn redistributor(&self) -> &Mutex<Redistributor> {
        &self.redistributor
    }

    /// Get a CPU interface reference (crate-internal, used by tests).
    ///
    /// External callers use `GicVcpuInterface`; this bypass exists only for
    /// crate unit tests that validate CPU-interface helper behavior directly.
    #[cfg(test)]
    pub(crate) fn cpu_interface(&self, vcpu_id: usize) -> &CpuInterface {
        &self.cpu_interfaces[vcpu_id]
    }

    /// Get config reference.
    pub const fn config(&self) -> &GicConfig {
        &self.config
    }

    /// Evaluate pending delivery for a vCPU and return the action.
    pub fn update_delivery_for_vcpu(&self, vcpu_id: usize) -> DeliveryAction {
        PriorityEngine::update_delivery(vcpu_id, self)
    }
}

impl GicIrqSender for GicV3 {
    fn set_irq_level(&self, intid: u32, level: bool) {
        Self::set_irq_level(self, intid, level);
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
    use crate::irq_state::TriggerMode;
    use amla_core::IrqLine;
    use std::sync::Arc;

    /// Recording `InterruptSink` that captures all `signal_irq` / `wake_vcpu` calls.
    struct RecordingSink {
        signals: Mutex<Vec<(usize, bool)>>,
        wakes: Mutex<Vec<usize>>,
    }

    impl RecordingSink {
        fn new() -> Self {
            Self {
                signals: Mutex::new(Vec::new()),
                wakes: Mutex::new(Vec::new()),
            }
        }

        fn signals(&self) -> Vec<(usize, bool)> {
            self.signals.lock().clone()
        }

        fn wakes(&self) -> Vec<usize> {
            self.wakes.lock().clone()
        }

        fn clear(&self) {
            self.signals.lock().clear();
            self.wakes.lock().clear();
        }
    }

    impl InterruptSink for RecordingSink {
        fn signal_irq(&self, vcpu_id: usize, pending: bool) {
            self.signals.lock().push((vcpu_id, pending));
        }
        fn wake_vcpu(&self, vcpu_id: usize) {
            self.wakes.lock().push(vcpu_id);
        }
    }

    fn make_gic(num_vcpus: usize) -> GicV3 {
        make_gic_with_sink(num_vcpus, Arc::new(NullInterruptSink))
    }

    fn make_gic_with_sink(num_vcpus: usize, sink: Arc<dyn InterruptSink>) -> GicV3 {
        GicV3::new(
            GicConfig {
                num_vcpus,
                ..GicConfig::default()
            },
            sink,
        )
    }

    // =========================================================================
    // GicConfig / GicV3 construction
    // =========================================================================

    #[test]
    fn default_config() {
        let cfg = GicConfig::default();
        assert_eq!(cfg.num_vcpus, 1);
        assert_eq!(cfg.gicd_base, GICD_BASE);
        assert_eq!(cfg.gicr_base, GICR_BASE);
    }

    #[test]
    fn vcpu_interface_claim_is_unique_until_drop() {
        let gic = make_gic(1);
        let token = gic.claim_vcpu_interface(0).unwrap();
        assert_eq!(token.vcpu_id(), 0);
        assert_eq!(
            gic.claim_vcpu_interface(0).unwrap_err(),
            ClaimVcpuInterfaceError::AlreadyClaimed { vcpu_id: 0 }
        );
        drop(token);
        assert!(gic.claim_vcpu_interface(0).is_ok());
    }

    #[test]
    fn vcpu_interface_claim_rejects_out_of_range() {
        let gic = make_gic(1);
        assert_eq!(
            gic.claim_vcpu_interface(1).unwrap_err(),
            ClaimVcpuInterfaceError::OutOfRange {
                vcpu_id: 1,
                num_vcpus: 1
            }
        );
    }

    #[test]
    fn gic_new_creates_correct_structure() {
        let gic = make_gic(4);
        assert_eq!(gic.num_vcpus(), 4);
        assert_eq!(gic.config().num_vcpus, 4);
    }

    // =========================================================================
    // Atomic mirrors
    // =========================================================================

    #[test]
    fn initial_atomic_mirrors() {
        let gic = make_gic(2);
        for i in 0..2 {
            assert_eq!(gic.pmr_atomic(i), PRIORITY_IDLE & PRIORITY_MASK);
            assert_eq!(gic.running_priority_atomic(i), PRIORITY_IDLE);
            assert!(!gic.igrpen1_atomic(i));
            assert_eq!(gic.bpr1_atomic(i), 0);
        }
    }

    #[test]
    fn atomic_mirrors_sync_after_sysreg_write() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        assert_eq!(gic.pmr_atomic(0), 0xF0);

        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        assert!(gic.igrpen1_atomic(0));

        gic.handle_sysreg_write(0, ICC_BPR1_EL1, 3);
        assert_eq!(gic.bpr1_atomic(0), 3);
    }

    #[test]
    fn multi_vcpu_atomics_isolated() {
        let gic = make_gic(3);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0x80);
        gic.handle_sysreg_write(1, ICC_PMR_EL1, 0xA0);
        gic.handle_sysreg_write(2, ICC_PMR_EL1, 0xC0);

        assert_eq!(gic.pmr_atomic(0), 0x80);
        assert_eq!(gic.pmr_atomic(1), 0xA0);
        assert_eq!(gic.pmr_atomic(2), 0xC0);
    }

    // =========================================================================
    // =========================================================================
    // set_irq_level / assert_irq_edge
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn set_irq_level_spi() {
        let gic = make_gic(1);

        // Assert SPI 32 (spi_idx 0)
        gic.set_irq_level(32, true);
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[0].pending);
            assert!(d.spi_state[0].hw_level);
        }

        // Deassert
        gic.set_irq_level(32, false);
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].pending);
            assert!(!d.spi_state[0].hw_level);
        }
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn assert_irq_edge_spi() {
        let gic = make_gic(1);

        gic.assert_irq_edge(33);
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[1].pending);
            assert!(d.spi_state[1].edge_latch);
        }
    }

    #[test]
    fn set_irq_level_sgi_ppi_warns_but_no_crash() {
        let gic = make_gic(1);
        // Should warn but not panic
        gic.set_irq_level(0, true);
        gic.set_irq_level(16, true);
    }

    #[test]
    fn assert_irq_edge_sgi_ppi_warns_but_no_crash() {
        let gic = make_gic(1);
        gic.assert_irq_edge(0);
        gic.assert_irq_edge(16);
    }

    // =========================================================================
    // create_irq_line
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn irq_line_assert_deassert() {
        let gic = make_gic(1);
        let line = gic.create_irq_line(32);

        line.assert();
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[0].hw_level);
            assert!(d.spi_state[0].pending);
        }

        line.deassert();
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].hw_level);
            assert!(!d.spi_state[0].pending);
        }
    }

    // =========================================================================
    // Delivery with RecordingSink
    // =========================================================================

    #[test]
    fn delivery_signals_pending_on_edge_inject() {
        let sink = Arc::new(RecordingSink::new());
        let gic = make_gic_with_sink(1, sink.clone());

        // Set up CPU: enable interrupts
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Enable SPI 32 at distributor + enable distributor
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
        }
        {
            let mut d = gic.distributor().write();
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS),
                4,
            );
        }
        sink.clear();

        // Inject edge
        gic.assert_irq_edge(32);

        let signals = sink.signals();
        assert!(
            signals.iter().any(|&(vcpu, pending)| vcpu == 0 && pending),
            "Edge inject should signal pending to vcpu 0"
        );

        let wakes = sink.wakes();
        assert!(wakes.contains(&0), "Edge inject should wake vcpu 0");
    }

    #[test]
    fn delivery_deasserts_after_iar() {
        let sink = Arc::new(RecordingSink::new());
        let gic = make_gic_with_sink(1, sink.clone());

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS),
                4,
            );
        }

        gic.assert_irq_edge(32);
        sink.clear();

        // Acknowledge
        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);

        // After IAR, delivery re-evaluates — should deassert since no more pending
        let signals = sink.signals();
        assert!(
            signals.iter().any(|&(vcpu, pending)| vcpu == 0 && !pending),
            "IAR should deassert after acknowledging only pending IRQ"
        );
    }

    #[test]
    fn delivery_does_not_rewake_when_line_already_asserted() {
        let sink = Arc::new(RecordingSink::new());
        let gic = make_gic_with_sink(1, sink.clone());

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS),
                4,
            );
        }

        gic.assert_irq_edge(32);
        sink.clear();

        gic.execute_delivery(gic.update_delivery_for_vcpu(0));

        assert!(
            sink.signals().is_empty(),
            "steady asserted delivery should not re-signal"
        );
        assert!(
            sink.wakes().is_empty(),
            "steady asserted delivery should not re-wake"
        );
    }

    // =========================================================================
    // End-to-end interrupt lifecycle
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn full_spi_edge_lifecycle() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        // Inject edge
        gic.assert_irq_edge(32);

        // Acknowledge
        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);
        assert_eq!(gic.running_priority_atomic(0), 0x80);

        // SPI 32 should be active, not pending
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[0].active);
            assert!(!d.spi_state[0].pending);
        }

        // EOI
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 32);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);

        // SPI 32 should be fully idle
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].active);
            assert!(!d.spi_state[0].pending);
        }

        // No more pending → spurious
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn full_spi_level_lifecycle_with_retrigger() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Level;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        // Assert level
        gic.set_irq_level(32, true);

        // Acknowledge
        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 32);

        // Level still asserted → pending stays true
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[0].active);
            assert!(d.spi_state[0].pending); // hw_level still high
        }

        // EOI with level still asserted → re-pends
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 32);
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].active);
            assert!(d.spi_state[0].pending); // re-triggered by level
        }

        // Deassert the line
        gic.set_irq_level(32, false);
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].pending);
        }
    }

    #[test]
    fn full_sgi_lifecycle() {
        let gic = make_gic(2);

        // Set up both vCPUs
        for i in 0..2 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }

        // Enable SGI 3 on vCPU 1
        {
            let mut r = gic.redistributor().lock();
            r.cpu_mut(1).unwrap().ppi_sgi_config[3].enabled = true;
            r.cpu_mut(1).unwrap().ppi_sgi_config[3].priority = 0x60;
        }

        // vCPU 0 sends SGI 3 to vCPU 1
        let sgi_val = (3u64 << 24) | 0b10; // target vCPU 1
        gic.handle_sysreg_write(0, ICC_SGI1R_EL1, sgi_val);

        // vCPU 1 acknowledges
        let intid = gic.handle_sysreg_read(1, ICC_IAR1_EL1);
        assert_eq!(intid, 3);

        // vCPU 1 EOIs
        gic.handle_sysreg_write(1, ICC_EOIR1_EL1, 3);
        assert_eq!(gic.running_priority_atomic(1), PRIORITY_IDLE);
    }

    // =========================================================================
    // Multi-vCPU SPI routing
    // =========================================================================

    #[test]
    fn spi_routed_to_specific_vcpu() {
        let gic = make_gic(4);

        for i in 0..4 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }

        // Route SPI 32 to vCPU 2 (Aff0=2)
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(0x6100, 2, 8); // IROUTER[0] → Aff0=2
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        gic.assert_irq_edge(32);

        // Only vCPU 2 should see it
        assert_eq!(gic.handle_sysreg_read(2, ICC_IAR1_EL1), 32);
        // Other vCPUs get spurious
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
        assert_eq!(
            gic.handle_sysreg_read(1, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
        assert_eq!(
            gic.handle_sysreg_read(3, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    #[test]
    fn spi_irm_routes_to_vcpu_0() {
        let gic = make_gic(4);

        for i in 0..4 {
            gic.handle_sysreg_write(i, ICC_PMR_EL1, 0xFF);
            gic.handle_sysreg_write(i, ICC_IGRPEN1_EL1, 1);
        }

        // IRM=1 for SPI 32 → should route to vCPU 0
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(0x6100, 1u64 << 31, 8); // IROUTER[0] IRM=1
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        gic.assert_irq_edge(32);

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 32);
        assert_eq!(
            gic.handle_sysreg_read(1, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }

    // =========================================================================
    // Priority preemption
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn nested_interrupt_preemption() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            // SGI 1 at priority 0x80
            cpu.ppi_sgi_config[1].enabled = true;
            cpu.ppi_sgi_config[1].priority = 0x80;
            cpu.ppi_sgi_state[1].pending = true;
            cpu.ppi_sgi_state[1].edge_latch = true;
            // SGI 2 at priority 0x40 (higher priority)
            cpu.ppi_sgi_config[2].enabled = true;
            cpu.ppi_sgi_config[2].priority = 0x40;
            cpu.ppi_sgi_state[2].pending = true;
            cpu.ppi_sgi_state[2].edge_latch = true;
        }

        // Should get highest priority first (SGI 2 at 0x40)
        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 2);
        assert_eq!(gic.running_priority_atomic(0), 0x40);

        // SGI 1 at 0x80 cannot preempt running 0x40
        let intid2 = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid2, u64::from(INTID_SPURIOUS));

        // EOI SGI 2 → running drops back
        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 2);

        // Now SGI 1 should be deliverable
        let intid3 = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid3, 1);
        assert_eq!(gic.running_priority_atomic(0), 0x80);

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 1);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn pmr_masks_lower_priority_interrupts() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0x80); // Only allow priority < 0x80
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0xA0; // Masked by PMR
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        // Should be spurious — priority 0xA0 >= PMR 0x80
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );

        // Lower PMR → now it's visible
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 5);
    }

    // =========================================================================
    // Snapshot / Restore
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn freeze_thaw_roundtrip() {
        let gic = make_gic(2);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);
        gic.handle_sysreg_write(1, ICC_PMR_EL1, 0x80);
        gic.handle_sysreg_write(1, ICC_BPR1_EL1, 2);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0xA0;
            d.mmio_write(0x6100, 1, 8); // IROUTER[0] → Aff0=1
        }

        let state = gic.freeze();

        // Thaw to a fresh GIC
        let gic2 = make_gic(2);
        gic2.thaw(&state).unwrap();

        // Verify state
        assert_eq!(gic2.pmr_atomic(0), 0xF0);
        assert!(gic2.igrpen1_atomic(0));
        assert_eq!(gic2.pmr_atomic(1), 0x80);
        assert_eq!(gic2.bpr1_atomic(1), 2);

        {
            let d = gic2.distributor().read();
            assert!(d.spi_config[0].enabled);
            assert_eq!(d.spi_config[0].priority, 0xA0);
        }
    }

    #[test]
    fn thaw_re_drives_delivery() {
        let sink = Arc::new(RecordingSink::new());
        let gic = make_gic_with_sink(1, sink.clone());

        // Set up state with a pending interrupt
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
        }

        let state = gic.freeze();
        sink.clear();

        // Thaw — should re-drive delivery
        let sink2 = Arc::new(RecordingSink::new());
        let gic2 = make_gic_with_sink(1, sink2.clone());
        gic2.thaw(&state).unwrap();

        let signals = sink2.signals();
        assert!(
            signals.iter().any(|&(_, pending)| pending),
            "Thaw should re-drive delivery for pending interrupts"
        );
    }

    #[test]
    fn thaw_forces_delivery_when_cached_line_already_pending() {
        let sink = Arc::new(RecordingSink::new());
        let gic = make_gic_with_sink(1, sink.clone());

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        gic.assert_irq_edge(32);
        assert!(
            sink.signals().iter().any(|&(_, pending)| pending),
            "initial injection should assert the line"
        );

        let state = gic.freeze();
        sink.clear();

        gic.thaw(&state).unwrap();

        assert!(
            sink.signals()
                .iter()
                .any(|&(vcpu, pending)| vcpu == 0 && pending),
            "thaw must force signal_irq even when cached line state is already pending"
        );
        assert!(
            sink.wakes().contains(&0),
            "thaw must wake a vCPU with restored pending work"
        );
    }

    #[test]
    fn thaw_with_mismatched_vcpu_count_fails() {
        // Freeze from a 4-vCPU GIC, thaw to a 2-vCPU GIC.
        // Snapshot restore is exact: vCPU-count mismatches must fail before
        // any partial distributor/redistributor state is applied.
        let gic4 = make_gic(4);
        gic4.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        gic4.handle_sysreg_write(1, ICC_PMR_EL1, 0xE0);
        gic4.handle_sysreg_write(2, ICC_PMR_EL1, 0xD0);
        gic4.handle_sysreg_write(3, ICC_PMR_EL1, 0xC0);

        let state = gic4.freeze();
        assert_eq!(state.vcpu_count, 4);

        let gic2 = make_gic(2);
        let err = gic2.thaw(&state).unwrap_err().to_string();
        assert!(err.contains("vCPU count"), "unexpected error: {err}");
        assert_eq!(gic2.pmr_atomic(0), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(gic2.pmr_atomic(1), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(gic2.num_vcpus(), 2);
    }

    #[test]
    // Reason: lock guard scope intentionally spans the assertion
    // block to observe a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn thaw_from_smaller_snapshot_fails_without_resetting_tail() {
        let gic2 = make_gic(2);
        gic2.handle_sysreg_write(0, ICC_PMR_EL1, 0xF0);
        gic2.handle_sysreg_write(1, ICC_PMR_EL1, 0xE0);
        let state = gic2.freeze();

        let gic4 = make_gic(4);
        gic4.handle_sysreg_write(2, ICC_PMR_EL1, 0x20);
        gic4.handle_sysreg_write(2, ICC_IGRPEN1_EL1, 1);
        {
            let mut r = gic4.redistributor().lock();
            let cpu = r.cpu_mut(2).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x40;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        let err = gic4.thaw(&state).unwrap_err().to_string();
        assert!(err.contains("vCPU count"), "unexpected error: {err}");

        assert_eq!(gic4.pmr_atomic(0), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(gic4.pmr_atomic(1), PRIORITY_IDLE & PRIORITY_MASK);
        assert_eq!(gic4.pmr_atomic(2), 0x20);
        assert!(gic4.igrpen1_atomic(2));

        let r = gic4.redistributor().lock();
        let cpu = r.cpu(2).unwrap();
        assert!(cpu.ppi_sgi_config[5].enabled);
        assert!(cpu.ppi_sgi_state[5].pending);
        assert!(cpu.ppi_sgi_state[5].edge_latch);
    }

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn reset_vcpu_resets_private_gic_state() {
        let gic = make_gic(2);
        gic.handle_sysreg_write(1, ICC_PMR_EL1, 0x20);
        gic.handle_sysreg_write(1, ICC_IGRPEN1_EL1, 1);
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(1).unwrap();
            cpu.ppi_sgi_config[5].enabled = true;
            cpu.ppi_sgi_config[5].priority = 0x40;
            cpu.ppi_sgi_state[5].pending = true;
            cpu.ppi_sgi_state[5].edge_latch = true;
        }

        gic.reset_vcpu(1);

        assert_eq!(gic.pmr_atomic(1), PRIORITY_IDLE & PRIORITY_MASK);
        assert!(!gic.igrpen1_atomic(1));
        let r = gic.redistributor().lock();
        let cpu = r.cpu(1).unwrap();
        assert!(!cpu.ppi_sgi_config[5].enabled);
        assert!(!cpu.ppi_sgi_state[5].pending);
        assert!(!cpu.ppi_sgi_state[5].edge_latch);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn freeze_thaw_active_interrupt_lifecycle() {
        // Full lifecycle: acknowledge (active), freeze, thaw, EOI → idle
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Set up and pend SGI 4
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[4].enabled = true;
            cpu.ppi_sgi_config[4].priority = 0x80;
            cpu.ppi_sgi_state[4].pending = true;
            cpu.ppi_sgi_state[4].edge_latch = true;
        }

        // Acknowledge — makes it active, lowers running priority
        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 4);
        assert_ne!(gic.running_priority_atomic(0), PRIORITY_IDLE);

        // Freeze while interrupt is active
        let state = gic.freeze();

        // Thaw to a fresh GIC
        let sink2 = Arc::new(RecordingSink::new());
        let gic2 = make_gic_with_sink(1, sink2);
        gic2.thaw(&state).unwrap();

        // Running priority should still reflect the active interrupt
        assert_ne!(gic2.running_priority_atomic(0), PRIORITY_IDLE);

        // EOI on the restored GIC — running priority should return to idle
        gic2.handle_sysreg_write(0, ICC_EOIR1_EL1, 4);
        assert_eq!(gic2.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // HPPIR
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn hppir_reflects_pending_without_side_effects() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[8].enabled = true;
            cpu.ppi_sgi_config[8].priority = 0x60;
            cpu.ppi_sgi_state[8].pending = true;
            cpu.ppi_sgi_state[8].edge_latch = true;
        }

        // HPPIR should return 8
        assert_eq!(gic.handle_sysreg_read(0, ICC_HPPIR1_EL1), 8);

        // No side effects — still pending, running priority unchanged
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);

        // HPPIR again — same result (no state change)
        assert_eq!(gic.handle_sysreg_read(0, ICC_HPPIR1_EL1), 8);
    }

    // =========================================================================
    // Lowest INTID tiebreak
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn same_priority_lowest_intid_wins() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            for id in [5, 3, 7] {
                cpu.ppi_sgi_config[id].enabled = true;
                cpu.ppi_sgi_config[id].priority = 0x80;
                cpu.ppi_sgi_state[id].pending = true;
                cpu.ppi_sgi_state[id].edge_latch = true;
            }
        }

        // Lowest INTID (3) should win at same priority
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 3);
    }

    // =========================================================================
    // Distributor enable gate
    // =========================================================================

    #[test]
    fn distributor_disabled_blocks_spi_delivery() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Don't enable distributor (Grp1A stays disabled)
        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].priority = 0x80;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
        }

        // SPI 32 pending but distributor not enabled → spurious
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );

        // Enable distributor
        {
            let mut d = gic.distributor().write();
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        // Now visible
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 32);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn distributor_disabled_does_not_block_sgi_ppi() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        // Distributor NOT enabled, but SGI/PPI should still work
        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[10].enabled = true;
            cpu.ppi_sgi_config[10].priority = 0x80;
            cpu.ppi_sgi_state[10].pending = true;
            cpu.ppi_sgi_state[10].edge_latch = true;
        }

        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 10);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn group0_sgi_ppi_not_delivered_through_group1_interface() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[4].enabled = true;
            cpu.ppi_sgi_config[4].group = false;
            cpu.ppi_sgi_config[4].priority = 0x40;
            cpu.ppi_sgi_state[4].pending = true;
            cpu.ppi_sgi_state[4].edge_latch = true;
        }

        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );

        {
            let mut r = gic.redistributor().lock();
            r.cpu_mut(0).unwrap().ppi_sgi_config[4].group = true;
        }
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 4);
    }

    #[test]
    fn group0_spi_not_delivered_through_group1_interface() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].enabled = true;
            d.spi_config[0].group = false;
            d.spi_config[0].priority = 0x40;
            d.spi_config[0].trigger = TriggerMode::Edge;
            d.spi_state[0].pending = true;
            d.spi_state[0].edge_latch = true;
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ENABLE_GRP1A | GICD_CTLR_ARE_NS | GICD_CTLR_DS),
                4,
            );
        }

        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );

        {
            let mut d = gic.distributor().write();
            d.spi_config[0].group = true;
        }
        assert_eq!(gic.handle_sysreg_read(0, ICC_IAR1_EL1), 32);
    }

    // =========================================================================
    // Unknown sysreg (RAZ/WI)
    // =========================================================================

    #[test]
    fn unknown_sysreg_read_returns_zero() {
        let gic = make_gic(1);
        let val = gic.handle_sysreg_read(0, 0xDEAD); // bogus encoding
        assert_eq!(val, 0);
    }

    #[test]
    fn unknown_sysreg_write_does_not_crash() {
        let gic = make_gic(1);
        gic.handle_sysreg_write(0, 0xDEAD, 0xCAFE);
    }

    // =========================================================================
    // Linux boot sequence (full GICD + GICR + ICC init)
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn linux_boot_sequence_full() {
        let gic = make_gic(2);

        // ---- Step 1: Distributor init (gic_dist_init) ----
        {
            let d = gic.distributor().read();
            let pidr2 = d.mmio_read(GICD_PIDR2, 4);
            assert_eq!((pidr2 >> 4) & 0xF, 3, "ArchRev must be 3");
            let typer = d.mmio_read(GICD_TYPER, 4);
            let it_lines = typer & 0x1F;
            assert_eq!(it_lines, 2, "ITLinesNumber for 96 IRQs");
        }

        // Disable → enable ARE_NS → enable Grp1A
        {
            let mut d = gic.distributor().write();
            d.mmio_write(GICD_CTLR, 0, 4); // Disable all
            assert_eq!(d.mmio_read(GICD_CTLR, 4) & 1, 0); // RWP=0

            d.mmio_write(GICD_CTLR, u64::from(GICD_CTLR_ARE_NS), 4);

            // Set all SPIs to Group 1, clear enables, clear active
            d.mmio_write(0x0084, 0xFFFF_FFFF, 4); // IGROUPR[1]
            d.mmio_write(0x0088, 0xFFFF_FFFF, 4); // IGROUPR[2]
            d.mmio_write(0x0184, 0xFFFF_FFFF, 4); // ICENABLER[1]
            d.mmio_write(0x0188, 0xFFFF_FFFF, 4); // ICENABLER[2]
            d.mmio_write(0x0384, 0xFFFF_FFFF, 4); // ICACTIVER[1]
            d.mmio_write(0x0388, 0xFFFF_FFFF, 4); // ICACTIVER[2]

            // Set default priority 0xA0 for all SPIs
            for offset in (0x0420u64..0x0460).step_by(4) {
                d.mmio_write(offset, 0xA0A0_A0A0, 4);
            }

            // Enable distributor
            d.mmio_write(
                GICD_CTLR,
                u64::from(GICD_CTLR_ARE_NS | GICD_CTLR_ENABLE_GRP1A),
                4,
            );
        }

        // ---- Step 2: Per-CPU redistributor init (for both vCPUs) ----
        for vcpu_id in 0..2usize {
            let base = vcpu_id as u64 * GICR_CPU_SIZE;

            {
                let r = gic.redistributor().lock();
                // Scan TYPER to match affinity
                let typer = r.mmio_read(base + GICR_TYPER, 8);
                let affinity = (typer >> 32) & 0xFFFF_FFFF;
                assert_eq!(affinity, vcpu_id as u64);
                let last = (typer >> 4) & 1;
                if vcpu_id == 1 {
                    assert_eq!(last, 1, "Last bit for final vCPU");
                }
            }

            // Wake redistributor
            {
                let mut r = gic.redistributor().lock();
                r.mmio_write(base + GICR_WAKER, 0, 4);
            }
            {
                let r = gic.redistributor().lock();
                let waker = r.mmio_read(base + GICR_WAKER, 4) as u32;
                assert_eq!(
                    waker & GICR_WAKER_CHILDREN_ASLEEP,
                    0,
                    "ChildrenAsleep should clear"
                );
            }

            // Configure SGI_base
            let sgi = base + GICR_SGI_BASE_OFFSET;
            {
                let mut r = gic.redistributor().lock();
                r.mmio_write(sgi + GICR_IGROUPR0, 0xFFFF_FFFF, 4);
                r.mmio_write(sgi + GICR_IGRPMODR0, 0, 4);
                r.mmio_write(sgi + GICR_ISENABLER0, 0xFFFF_FFFF, 4);
                // Set priorities for all 32 SGIs/PPIs
                for off in (0x0400u64..0x0420).step_by(4) {
                    r.mmio_write(sgi + off, 0xA0A0_A0A0, 4);
                }
            }
        }

        // ---- Step 3: CPU interface init (gic_cpu_sys_reg_init) for both vCPUs ----
        for vcpu_id in 0..2 {
            gic.handle_sysreg_write(vcpu_id, ICC_SRE_EL1, 0x7);
            let sre = gic.handle_sysreg_read(vcpu_id, ICC_SRE_EL1);
            assert_eq!(sre & 1, 1, "SRE must be 1");

            let ctlr = gic.handle_sysreg_read(vcpu_id, ICC_CTLR_EL1);
            let pri_bits = ((ctlr >> 8) & 0x7) + 1;
            assert_eq!(pri_bits, u64::from(PRIORITY_BITS));

            gic.handle_sysreg_write(vcpu_id, ICC_AP1R0_EL1, 0);
            gic.handle_sysreg_write(vcpu_id, ICC_AP0R0_EL1, 0);
            gic.handle_sysreg_write(vcpu_id, ICC_PMR_EL1, 0xF0);
            gic.handle_sysreg_write(vcpu_id, ICC_BPR1_EL1, 0);
            gic.handle_sysreg_write(vcpu_id, ICC_CTLR_EL1, 0);
            gic.handle_sysreg_write(vcpu_id, ICC_IGRPEN1_EL1, 1);
        }

        // ---- Step 4: Interrupt delivery ----
        // Route SPI 33 (spi_idx 1) to vCPU 0, enable it
        {
            let mut d = gic.distributor().write();
            d.mmio_write(0x6108, 0, 8); // IROUTER for SPI 33 → Aff0=0
            d.mmio_write(0x0104, 0x2, 4); // ISENABLER word 1, bit 1 = SPI 33
        }

        gic.assert_irq_edge(33);

        let intid = gic.handle_sysreg_read(0, ICC_IAR1_EL1);
        assert_eq!(intid, 33);

        gic.handle_sysreg_write(0, ICC_EOIR1_EL1, 33);
        assert_eq!(gic.running_priority_atomic(0), PRIORITY_IDLE);
    }

    // =========================================================================
    // GicIrqSender trait
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn gic_irq_sender_trait() {
        let gic = make_gic(1);
        // GicV3 implements GicIrqSender — verify the trait object path works
        let sender: &dyn GicIrqSender = &gic;
        sender.set_irq_level(32, true);
        let d = gic.distributor().read();
        assert!(d.spi_state[0].pending);
        assert!(d.spi_state[0].hw_level);
    }

    // =========================================================================
    // Edge: disable interrupt while pending
    // =========================================================================

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn disabled_interrupt_not_deliverable() {
        let gic = make_gic(1);

        gic.handle_sysreg_write(0, ICC_PMR_EL1, 0xFF);
        gic.handle_sysreg_write(0, ICC_IGRPEN1_EL1, 1);

        {
            let mut r = gic.redistributor().lock();
            let cpu = r.cpu_mut(0).unwrap();
            cpu.ppi_sgi_config[4].enabled = false; // Disabled!
            cpu.ppi_sgi_config[4].priority = 0x80;
            cpu.ppi_sgi_state[4].pending = true;
            cpu.ppi_sgi_state[4].edge_latch = true;
        }

        // Disabled → spurious
        assert_eq!(
            gic.handle_sysreg_read(0, ICC_IAR1_EL1),
            u64::from(INTID_SPURIOUS)
        );
    }
}
