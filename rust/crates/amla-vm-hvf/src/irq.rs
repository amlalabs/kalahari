// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HVF subprocess IRQ line — sends IPC messages for interrupt injection.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use amla_core::IrqLine;
use tokio::sync::mpsc;

use crate::vm::IpcSignal;

/// A resampled IRQ line backed by IPC to the HVF worker process.
///
/// Mirrors `SubprocessIrqLine` from the KVM backend. Assert/deassert
/// updates are sent as one-way `IrqLine` signals over the IPC ring buffer.
/// Resample (EOI) notifications arrive from the worker via `IrqResample`
/// responses.
pub(crate) struct HvfIrqLine {
    pub(crate) gsi: u32,
    pub(crate) level: AtomicBool,
    pub(crate) resample_flags: Arc<Vec<AtomicBool>>,
    pub(crate) signal_tx: mpsc::UnboundedSender<IpcSignal>,
}

impl IrqLine for HvfIrqLine {
    fn assert(&self) {
        self.level.store(true, Ordering::Release);
        let r = self.signal_tx.send(IpcSignal::IrqLine {
            gsi: self.gsi,
            level: true,
        });
        log::debug!("HvfIrqLine::assert gsi={} send_ok={}", self.gsi, r.is_ok());
    }

    fn deassert(&self) {
        self.level.store(false, Ordering::Release);
        let r = self.signal_tx.send(IpcSignal::IrqLine {
            gsi: self.gsi,
            level: false,
        });
        log::debug!(
            "HvfIrqLine::deassert gsi={} send_ok={}",
            self.gsi,
            r.is_ok()
        );
    }

    fn check_resample(&self) {
        if let Some(flag) = self.resample_flags.get(self.gsi as usize)
            && flag.swap(false, Ordering::AcqRel)
        {
            // EOI from guest. Re-assert if level still high.
            if self.level.load(Ordering::Acquire) {
                let r = self.signal_tx.send(IpcSignal::IrqLine {
                    gsi: self.gsi,
                    level: true,
                });
                log::debug!(
                    "HvfIrqLine::check_resample gsi={} re-asserted send_ok={}",
                    self.gsi,
                    r.is_ok()
                );
            } else {
                log::debug!(
                    "HvfIrqLine::check_resample gsi={} EOI (level already low)",
                    self.gsi
                );
            }
        }
    }
}
