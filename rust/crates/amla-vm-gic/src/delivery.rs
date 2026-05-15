// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1
//! Interrupt delivery traits and IRQ line implementation.

use amla_core::IrqLine;

/// Hypervisor-agnostic callback for signaling vCPUs.
///
/// Implementers MAY implement `signal_irq` as a no-op when they drive the
/// hypervisor's architectural pending-IRQ state (e.g. HVF's
/// `hv_vcpu_set_pending_interrupt`) on the owning vCPU thread instead of
/// from arbitrary GIC-caller threads. Clients MUST NOT rely on `signal_irq`
/// alone to wake a halted vCPU — the authoritative wake path is `wake_vcpu`.
pub trait InterruptSink: Send + Sync {
    /// Notify the backend that the GIC-level pending state changed.
    ///
    /// Implementations MAY be a no-op on backends that redrive pending-IRQ
    /// state on the owning vCPU thread before guest entry (e.g. HVF). Do not
    /// rely on this to wake a vCPU — use `wake_vcpu` for that.
    fn signal_irq(&self, vcpu_id: usize, pending: bool);

    /// Wake a vCPU that may be halted (WFI).
    fn wake_vcpu(&self, vcpu_id: usize);
}

/// A no-op interrupt sink for testing.
pub struct NullInterruptSink;

impl InterruptSink for NullInterruptSink {
    fn signal_irq(&self, _vcpu_id: usize, _pending: bool) {}
    fn wake_vcpu(&self, _vcpu_id: usize) {}
}

/// Action computed by GIC state changes, executed after lock release.
///
/// This ensures `InterruptSink` callbacks are never called under lock,
/// preventing deadlock when callbacks re-enter the GIC.
#[derive(Debug, Clone, Copy)]
pub struct DeliveryAction {
    pub vcpu_id: usize,
    pub pending: bool,
}

/// An `IrqLine` that injects into the userspace GIC.
pub struct GicIrqLine<'a> {
    gic: &'a dyn GicIrqSender,
    intid: u32,
}

impl<'a> GicIrqLine<'a> {
    /// Create a new IRQ line for the given INTID.
    pub fn new(gic: &'a dyn GicIrqSender, intid: u32) -> Self {
        Self { gic, intid }
    }
}

impl IrqLine for GicIrqLine<'_> {
    fn assert(&self) {
        self.gic.set_irq_level(self.intid, true);
    }

    fn deassert(&self) {
        self.gic.set_irq_level(self.intid, false);
    }
}

/// Trait for the GIC's IRQ injection interface (used by `GicIrqLine`).
///
/// This avoids a circular dependency: `GicIrqLine` borrows `&dyn GicIrqSender`
/// instead of referencing `GicV3` directly, so `delivery.rs` doesn't depend on `lib.rs`.
pub trait GicIrqSender: Send + Sync {
    fn set_irq_level(&self, intid: u32, level: bool);
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn null_sink_is_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<NullInterruptSink>();
    }

    #[test]
    fn null_sink_operations() {
        let sink = NullInterruptSink;
        sink.signal_irq(0, true);
        sink.signal_irq(0, false);
        sink.wake_vcpu(0);
    }

    #[test]
    fn delivery_action_debug() {
        let action = DeliveryAction {
            vcpu_id: 3,
            pending: true,
        };
        let dbg = format!("{action:?}");
        assert!(dbg.contains("vcpu_id: 3"));
        assert!(dbg.contains("pending: true"));
    }

    #[test]
    fn delivery_action_clone_copy() {
        let action = DeliveryAction {
            vcpu_id: 1,
            pending: false,
        };
        let action2 = action;
        let action3 = action2;
        assert_eq!(action3.vcpu_id, 1);
        assert!(!action3.pending);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn gic_irq_line_assert_deassert() {
        use crate::{GicConfig, GicV3, NullInterruptSink};

        let gic = GicV3::new(
            GicConfig {
                num_vcpus: 1,
                ..GicConfig::default()
            },
            std::sync::Arc::new(NullInterruptSink),
        );

        let line = GicIrqLine::new(&gic, 32);
        line.assert();
        {
            let d = gic.distributor().read();
            assert!(d.spi_state[0].pending);
            assert!(d.spi_state[0].hw_level);
        }

        line.deassert();
        {
            let d = gic.distributor().read();
            assert!(!d.spi_state[0].pending);
            assert!(!d.spi_state[0].hw_level);
        }
    }
}
