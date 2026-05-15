// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Typestate markers with sealed trait pattern.
//!
//! The `MachineState` trait is sealed to prevent external implementations.
//! `Ready<'a>` holds all live backend state; `New` is a unit struct; `Parked`
//! carries saved guest state without a backend shell; and `Zygote` carries a
//! private proof that backend teardown completed before `CoW` branch.
//!
//! # Compiler-Enforced Safety
//!
//! - `MachineState` is sealed: only markers in this module can implement it
//! - Live backend state only exists in `Ready` -- no optional "maybe live" shell

use amla_core::backends::{NetBackend, NullNetBackend};
use amla_fuse::fuse::FsBackend;

use crate::backend::BackendVm;

mod sealed {
    pub trait Sealed {}
}

/// Marker trait for VM lifecycle states.
///
/// This trait is sealed - it cannot be implemented outside this crate.
pub trait MachineState: sealed::Sealed {}

/// Resources allocated, not yet configured with kernel/boot setup.
///
/// Transitions:
/// - `load_kernel()` → `Ready`
#[derive(Debug, Clone, Copy, Default)]
pub struct New;

impl sealed::Sealed for New {}
impl MachineState for New {}

/// Shell acquired, memory mapped, IRQ lines created, state restorable.
///
/// All live backend state lives here -- not on `VirtualMachine`.
///
/// # Drop Ordering
///
/// `irq_lines` holds raw fds into the shell. Fields are dropped in
/// declaration order, so `irq_lines` is declared before `shell`.
/// `regions` must outlive `VmState` views built from them.
///
/// Transitions:
/// - `run(closure)` -> `Ready` (consumes self, returns Ready only after state is saved)
/// - `freeze()` -> `Zygote` (drops live state, keeps memfd handles)
pub struct Ready<'a, F: FsBackend, N: NetBackend = NullNetBackend> {
    /// IRQ lines -- dropped BEFORE shell (raw fds into shell).
    pub(crate) irq_lines: Vec<Box<dyn amla_core::IrqLine>>,

    /// Backend shell -- dropped AFTER `irq_lines`, BEFORE regions.
    pub(crate) shell: BackendVm,

    /// Mapped VM-state memory. Keeps unified state/RAM and PMEM image maps
    /// alive until after the backend shell is dropped.
    /// Must outlive all KVM slot registrations (dropped after shell).
    pub(crate) regions: amla_core::vm_state::MappedVmState,

    /// Console backend reference.
    pub(crate) console: &'a dyn amla_core::backends::ConsoleBackend,

    /// Network backend reference (if config has net).
    pub(crate) net: Option<&'a N>,

    /// Filesystem backend reference (if config has fs).
    pub(crate) fs: Option<&'a F>,

    /// Serial console writer for PIO forwarding (x86).
    pub(crate) serial_console: Option<Box<dyn amla_core::backends::ConsoleBackend>>,
}

impl<F: FsBackend, N: NetBackend> sealed::Sealed for Ready<'_, F, N> {}
impl<F: FsBackend, N: NetBackend> MachineState for Ready<'_, F, N> {}

/// Proof that backend teardown completed before exposing a zygote.
#[derive(Debug)]
pub struct BackendClosed(());

impl BackendClosed {
    /// Construct a backend-closed proof after an awaited backend close.
    pub(crate) const fn new() -> Self {
        Self(())
    }
}

/// Frozen into a copy-on-write template.
///
/// Transitions:
/// - `spawn()` → `Ready`
#[derive(Debug)]
pub struct Zygote {
    _backend_closed: BackendClosed,
}

impl Zygote {
    /// Construct a zygote from an awaited backend-close proof.
    pub(crate) const fn new(backend_closed: BackendClosed) -> Self {
        Self {
            _backend_closed: backend_closed,
        }
    }
}

impl sealed::Sealed for Zygote {}
impl MachineState for Zygote {}

/// Saved VM state with no live backend shell.
///
/// Transitions:
/// - `resume()` → `Ready`
///
/// Unlike [`Zygote`], a parked VM is a single logical VM. Resuming it moves the
/// same memory handles into a fresh backend shell instead of branching them.
#[derive(Debug)]
pub struct Parked {
    _backend_closed: BackendClosed,
}

impl Parked {
    /// Construct a parked VM from an awaited backend-close proof.
    pub(crate) const fn new(backend_closed: BackendClosed) -> Self {
        Self {
            _backend_closed: backend_closed,
        }
    }
}

impl sealed::Sealed for Parked {}
impl MachineState for Parked {}
