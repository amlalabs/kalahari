// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! vCPU run loop: async exit handling for each vCPU.
//!
//! Each vCPU executes `vcpu_run_loop`, which calls `shell.resume()` and
//! handles exits. Preemption is explicit via `shell.preempt_vcpu()`.

use std::sync::atomic::Ordering;

use amla_core::vm_state::{PsciPowerState, PsciPowerStateBusy, PsciPowerStateTable};
use amla_core::{VcpuExit, VcpuResponse};
use tokio::sync::mpsc;

use crate::device::AnyDevice;
use crate::shared_state::{VmEnd, VmOutcome};

// =============================================================================
// PSCI CPU_ON cross-vCPU signaling
// =============================================================================

/// Boot request sent from BSP to target AP via [`CpuOnBus`].
pub struct CpuOnRequest {
    pub entry_point: u64,
    pub context_id: u64,
}

/// Result of attempting to deliver a PSCI `CPU_ON` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpuOnResult {
    /// Target vCPU was `Off`; request queued and target will boot.
    Accepted,
    /// Target vCPU index is out of range.
    InvalidTarget,
    /// Target vCPU already has a `CPU_ON` queued but not yet consumed.
    OnPending,
    /// Target vCPU is currently running.
    AlreadyOn,
    /// Target vCPU exists but cannot receive the boot request.
    TargetUnavailable,
}

/// Shared bus for PSCI `CPU_ON` cross-vCPU signaling.
///
/// Each vCPU gets a receiver; senders are indexed by MPIDR (== `vcpu_id`
/// for standard aarch64 VMs). The bus uses the persisted per-vCPU power state
/// so that `CPU_ON` returns the correct PSCI return code (`ALREADY_ON`,
/// `ON_PENDING`, etc.) without relying on channel capacity, which is not a
/// power-state oracle.
pub struct CpuOnBus<'a> {
    senders: Vec<mpsc::Sender<CpuOnRequest>>,
    /// Persisted per-vCPU power state. Index = vCPU id.
    state: PsciPowerStateTable<'a>,
}

impl<'a> CpuOnBus<'a> {
    /// Create a bus for `vcpu_count` vCPUs. Returns the bus + per-vCPU receivers.
    ///
    /// Initial state comes from the persisted VM-state header.
    pub fn new(
        vcpu_count: usize,
        state: PsciPowerStateTable<'a>,
    ) -> (Self, Vec<mpsc::Receiver<CpuOnRequest>>) {
        assert!(
            vcpu_count <= state.len(),
            "CPU_ON bus vCPU count exceeds persisted power-state table"
        );
        let mut senders = Vec::with_capacity(vcpu_count);
        let mut receivers = Vec::with_capacity(vcpu_count);
        for _ in 0..vcpu_count {
            let (tx, rx) = mpsc::channel(1);
            senders.push(tx);
            receivers.push(rx);
        }
        (Self { senders, state }, receivers)
    }

    /// Send a `CPU_ON` request to the target vCPU (by MPIDR/index).
    ///
    /// CAS `Off -> OnPending` gates delivery: only an `Off` target accepts
    /// a new boot request. `On` returns `AlreadyOn`; an existing
    /// `OnPending` returns `OnPending`. The receiver is responsible for
    /// flipping `OnPending -> On` after dequeuing (see [`Self::mark_on`]).
    fn send(&self, target: usize, req: CpuOnRequest) -> CpuOnResult {
        let Some(tx) = self.senders.get(target) else {
            return CpuOnResult::InvalidTarget;
        };
        let Some(claim) =
            self.state
                .claim_off_for_cpu_on(target, Ordering::AcqRel, Ordering::Acquire)
        else {
            return CpuOnResult::InvalidTarget;
        };
        match claim {
            Ok(()) => match tx.try_send(req) {
                Ok(()) => CpuOnResult::Accepted,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    // Channel cap is 1 and we just transitioned out of `Off`,
                    // so this should be unreachable. Revert and report.
                    self.state
                        .store(target, PsciPowerState::Off, Ordering::Release);
                    CpuOnResult::OnPending
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    // Receiver is gone — vCPU has exited. Revert the
                    // unconsumed request so the persisted mmap does not retain
                    // a boot request nobody can dequeue.
                    self.state
                        .store(target, PsciPowerState::Off, Ordering::Release);
                    CpuOnResult::TargetUnavailable
                }
            },
            Err(actual) => match actual {
                PsciPowerStateBusy::On => CpuOnResult::AlreadyOn,
                PsciPowerStateBusy::OnPending => CpuOnResult::OnPending,
            },
        }
    }

    /// Return PSCI `AFFINITY_INFO` status for a target vCPU.
    ///
    /// The persisted power-state bytes intentionally match PSCI's return
    /// values for `AFFINITY_INFO`: 0 = on, 1 = off, 2 = on pending.
    fn affinity_info(&self, target: usize) -> Option<u64> {
        self.state
            .load(target, Ordering::Acquire)
            .map(|state| u64::from(state.as_u8()))
    }

    /// Transition `On -> Off` for `vcpu_id`. No-op if state is already `Off`
    /// or `OnPending` (a peer raced ahead with a `CPU_ON` we must preserve).
    ///
    /// Called from the vCPU loop's `CpuOff` arm before awaiting the next
    /// `CPU_ON`, so a fresh `Off` window exists for senders.
    pub(crate) fn mark_off(&self, vcpu_id: usize) {
        let _ = self.state.compare_exchange(
            vcpu_id,
            PsciPowerState::On,
            PsciPowerState::Off,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Transition `OnPending -> On` for `vcpu_id`. Called by the receiver
    /// immediately after dequeuing the boot request, so subsequent
    /// `CPU_ON`s see the target as running and return `ALREADY_ON`.
    pub(crate) fn mark_on(&self, vcpu_id: usize) {
        let _ = self.state.compare_exchange(
            vcpu_id,
            PsciPowerState::OnPending,
            PsciPowerState::On,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    /// Read the persisted PSCI power state for `vcpu_id` (diagnostic only).
    pub(crate) fn persisted_state(&self, vcpu_id: usize) -> Option<&'static str> {
        self.state
            .load(vcpu_id, Ordering::Acquire)
            .map(|state| match state {
                PsciPowerState::On => "On",
                PsciPowerState::Off => "Off",
                PsciPowerState::OnPending => "OnPending",
            })
    }
}

/// Serial port base address (COM1).
#[cfg(target_arch = "x86_64")]
const SERIAL_PORT: u16 = 0x3F8;

/// AMD FCH power-management base used by Linux's Zen reset-reason probe.
#[cfg(target_arch = "x86_64")]
const AMD_FCH_PM_BASE: u64 = 0xFED8_0300;
/// `FCH::PM::S5_RESET_STATUS` offset from [`AMD_FCH_PM_BASE`].
#[cfg(target_arch = "x86_64")]
const AMD_FCH_S5_RESET_STATUS_OFFSET: u64 = 0xC0;
/// `FCH::PM::S5_RESET_STATUS` physical address.
#[cfg(target_arch = "x86_64")]
const AMD_FCH_S5_RESET_STATUS: u64 = AMD_FCH_PM_BASE + AMD_FCH_S5_RESET_STATUS_OFFSET;
/// `FCH::PM::S5_RESET_STATUS` register width.
#[cfg(target_arch = "x86_64")]
const AMD_FCH_S5_RESET_STATUS_SIZE: u8 = 4;

/// PL011 UART base address (ARM64).
#[cfg(target_arch = "aarch64")]
const PL011_BASE: u64 = 0x0900_0000;
/// PL011 UART region size.
#[cfg(target_arch = "aarch64")]
const PL011_SIZE: u64 = 0x1000;

/// PL031 RTC base address (ARM64).
#[cfg(target_arch = "aarch64")]
const PL031_BASE: u64 = 0x0901_0000;
/// PL031 RTC region size.
#[cfg(target_arch = "aarch64")]
const PL031_SIZE: u64 = 0x1000;

/// Counters for vCPU exit types, used for diagnostic logging.
#[derive(Default)]
struct ExitStats {
    hlt: u64,
    mmio: u64,
    pio: u64,
    other: u64,
    total: u64,
}

impl std::fmt::Display for ExitStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "hlt={} mmio={} pio={} other={} total={}",
            self.hlt, self.mmio, self.pio, self.other, self.total
        )
    }
}

/// Shared context borrowed by every `vcpu_run_loop` task.
///
/// Bundles the cross-vCPU handles (shell, devices, IRQ waker, serial, PSCI bus,
/// cancellation token) so each vCPU only owns the per-vCPU values (`vcpu_id`,
/// its `cpu_on_rx`) separately. Manually implements `Copy`/`Clone` because the
/// type parameter `F` appears only behind a reference in `devices`, so `F` does
/// not need to be `Copy` for the struct to be trivially copyable.
pub struct VcpuLoopCtx<'a, F: amla_fuse::fuse::FsBackend, N: amla_core::backends::NetBackend> {
    pub shell: &'a crate::backend::BackendVm,
    pub devices: &'a [AnyDevice<'a, F, N>],
    pub waker: &'a dyn amla_core::DeviceWaker,
    pub queue_wakes: &'a crate::devices::QueueWakeMap,
    pub serial: Option<&'a dyn amla_core::backends::ConsoleBackend>,
    pub end: &'a VmEnd,
    pub cpu_on_bus: &'a CpuOnBus<'a>,
}

impl<F: amla_fuse::fuse::FsBackend, N: amla_core::backends::NetBackend> Clone
    for VcpuLoopCtx<'_, F, N>
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<F: amla_fuse::fuse::FsBackend, N: amla_core::backends::NetBackend> Copy
    for VcpuLoopCtx<'_, F, N>
{
}

/// Run loop for a single vCPU.
///
/// This is the core execution loop for each vCPU:
/// 1. Check cancellation before entering kernel
/// 2. Call `shell.resume(vcpu_id, response)` (blocks in hypervisor)
/// 3. Handle the exit (MMIO, PIO, halt, etc.)
/// 4. Loop until cancelled or error
///
/// # Preemption
///
/// The caller preempts vCPUs explicitly via `shell.preempt_vcpu()`,
/// then awaits this future. The `cancel` token is checked at safe
/// boundaries after exit handling.
#[allow(clippy::too_many_lines)]
pub async fn vcpu_run_loop<F: amla_fuse::fuse::FsBackend, N: amla_core::backends::NetBackend>(
    ctx: VcpuLoopCtx<'_, F, N>,
    vcpu_id: amla_core::VcpuId,
    mut cpu_on_rx: mpsc::Receiver<CpuOnRequest>,
) {
    let VcpuLoopCtx {
        shell,
        devices,
        waker,
        queue_wakes,
        serial,
        end,
        cpu_on_bus,
    } = ctx;
    let mut stats = ExitStats::default();
    let mut last_log = std::time::Instant::now();
    let mut last_total = 0u64;

    // Serial output buffer: accumulates bytes, flushes on newline or at capacity.
    let mut serial_buf: Vec<u8> = Vec::with_capacity(128);

    // Response to pass with the next resume(). None for first call and
    // after exits that need no data returned to the guest.
    let mut response: Option<VcpuResponse> = None;

    loop {
        if last_log.elapsed() >= std::time::Duration::from_secs(5) {
            #[allow(clippy::cast_precision_loss)]
            let rate = (stats.total - last_total) as f64 / last_log.elapsed().as_secs_f64();
            log::info!("vCPU {vcpu_id} {stats} ({rate:.0} exits/s)");
            last_total = stats.total;
            last_log = std::time::Instant::now();
        }
        if end.is_stopped() && response.is_none() {
            return;
        }

        // Resume vCPU, racing against cancellation.
        let resume_fut = shell.resume(vcpu_id, response.take());
        tokio::pin!(resume_fut);

        let exit = tokio::select! {
            result = &mut resume_fut => {
                match result {
                    Ok(exit) => exit,
                    Err(e) => {
                        log::error!("vCPU {vcpu_id} error: {e:?}");
                        flush_serial(&mut serial_buf, serial);
                        end.report(VmOutcome::Fatal);
                        return;
                    }
                }
            }
            () = end.stopped() => {
                // Cancellation arrived while the vCPU was running. The
                // hypervisor may still return a real exit whose architectural
                // side effect has already been committed from the guest's
                // point of view. We must handle that exit before snapshotting;
                // dropping it can lose MMIO writes or leave a read response
                // unapplied.
                shell.preempt_vcpu(vcpu_id);
                match resume_fut.await {
                    Ok(exit) => exit,
                    Err(e) => {
                        log::error!("vCPU {vcpu_id} preempt error: {e:?}");
                        flush_serial(&mut serial_buf, serial);
                        end.report(VmOutcome::Fatal);
                        return;
                    }
                }
            }
        };

        // Drain any buffered UART console bytes from the worker
        // (subprocess mode only — no-op in direct mode).
        let console_bytes = shell.drain_console_output();
        if !console_bytes.is_empty()
            && let Some(console) = serial
            && let Err(e) = console.write(&console_bytes)
        {
            log::warn!(
                "vcpu_loop: console.write failed for {} drained bytes: {e}",
                console_bytes.len(),
            );
        }

        // Handle exit -> compute response for next resume.
        stats.total += 1;
        match exit {
            VcpuExit::Halt => {
                stats.hlt += 1;
                if end.is_stopped() {
                    log::info!("vCPU {vcpu_id} exiting: {stats}");
                    return;
                }
            }

            VcpuExit::Interrupted => {
                stats.other += 1;
                if end.is_stopped() {
                    log::info!("vCPU {vcpu_id} exiting (interrupted): {stats}");
                    return;
                }
            }

            VcpuExit::CleanShutdown => {
                stats.other += 1;
                log::debug!("vCPU {vcpu_id} clean shutdown: {stats}");
                flush_serial(&mut serial_buf, serial);
                end.report(VmOutcome::CleanShutdown);
                return;
            }
            VcpuExit::Reboot => {
                stats.other += 1;
                log::debug!("vCPU {vcpu_id} reboot: {stats}");
                flush_serial(&mut serial_buf, serial);
                end.report(VmOutcome::Reboot);
                return;
            }
            VcpuExit::Unrecoverable => {
                stats.other += 1;
                log::error!("vCPU {vcpu_id} unrecoverable exit: {stats}");
                flush_serial(&mut serial_buf, serial);
                end.report(VmOutcome::Fatal);
                return;
            }

            VcpuExit::CpuOff => {
                stats.other += 1;
                let prev = cpu_on_bus.persisted_state(vcpu_id.0 as usize);
                log::info!("vCPU {vcpu_id} PSCI CPU_OFF — waiting for CPU_ON (persisted={prev:?})");
                // CAS On->Off so a peer that already raced ahead with a
                // CPU_ON (state OnPending, request queued) is preserved.
                cpu_on_bus.mark_off(vcpu_id.0 as usize);
                let after = cpu_on_bus.persisted_state(vcpu_id.0 as usize);
                log::debug!("vCPU {vcpu_id} CPU_OFF mark_off done, persisted={after:?}");
                // Wait for a CPU_ON to re-activate this vCPU.
                tokio::select! {
                    Some(req) = cpu_on_rx.recv() => {
                        log::info!(
                            "vCPU {vcpu_id} dequeued CPU_ON: entry={:#x} ctx={:#x}",
                            req.entry_point, req.context_id
                        );
                        cpu_on_bus.mark_on(vcpu_id.0 as usize);
                        let after = cpu_on_bus.persisted_state(vcpu_id.0 as usize);
                        log::info!("vCPU {vcpu_id} CPU_ON mark_on done, persisted={after:?}");
                        response = Some(VcpuResponse::CpuOnBoot {
                            entry_point: req.entry_point,
                            context_id: req.context_id,
                        });
                    }
                    () = end.stopped() => {
                        log::debug!("vCPU {vcpu_id} CPU_OFF wait cancelled");
                        return;
                    }
                }
            }

            VcpuExit::CpuOn {
                target_cpu,
                entry_point,
                context_id,
            } => {
                stats.other += 1;
                // MPIDR low bits = vCPU index for standard aarch64 VMs.
                #[allow(clippy::cast_possible_truncation)]
                let target_idx = (target_cpu & 0xFF) as usize;
                let prev = cpu_on_bus.persisted_state(target_idx);
                log::debug!(
                    "vCPU {vcpu_id} PSCI CPU_ON: target={target_idx} entry={entry_point:#x} ctx={context_id:#x} target_persisted={prev:?}"
                );
                let result = cpu_on_bus.send(
                    target_idx,
                    CpuOnRequest {
                        entry_point,
                        context_id,
                    },
                );
                let after = cpu_on_bus.persisted_state(target_idx);
                log::debug!(
                    "vCPU {vcpu_id} CPU_ON dispatch result={result:?}, target_persisted={after:?}"
                );
                #[allow(clippy::cast_sign_loss)]
                let psci_return = match result {
                    CpuOnResult::Accepted => amla_core::arm64::PSCI_RET_SUCCESS as u64,
                    CpuOnResult::InvalidTarget => {
                        log::warn!("vCPU {vcpu_id}: CPU_ON target {target_idx} invalid");
                        amla_core::arm64::PSCI_RET_INVALID_PARAMETERS as u64
                    }
                    CpuOnResult::OnPending => {
                        log::warn!("vCPU {vcpu_id}: CPU_ON target {target_idx} already pending");
                        amla_core::arm64::PSCI_RET_ON_PENDING as u64
                    }
                    CpuOnResult::AlreadyOn => {
                        log::warn!("vCPU {vcpu_id}: CPU_ON target {target_idx} already on");
                        amla_core::arm64::PSCI_RET_ALREADY_ON as u64
                    }
                    CpuOnResult::TargetUnavailable => {
                        log::warn!(
                            "vCPU {vcpu_id}: CPU_ON target {target_idx} cannot receive request"
                        );
                        amla_core::arm64::PSCI_RET_INTERNAL_FAILURE as u64
                    }
                };
                response = Some(VcpuResponse::CpuOnResult { psci_return });
            }

            VcpuExit::CpuAffinityInfo {
                target_cpu,
                lowest_affinity_level,
            } => {
                stats.other += 1;
                #[allow(clippy::cast_possible_truncation)]
                let target_idx = (target_cpu & 0xFF) as usize;
                #[allow(clippy::cast_sign_loss)]
                let psci_return = if lowest_affinity_level == 0 {
                    cpu_on_bus
                        .affinity_info(target_idx)
                        .unwrap_or(amla_core::arm64::PSCI_RET_INVALID_PARAMETERS as u64)
                } else {
                    amla_core::arm64::PSCI_RET_INVALID_PARAMETERS as u64
                };
                log::debug!(
                    "vCPU {vcpu_id} PSCI AFFINITY_INFO: target={target_idx} level={lowest_affinity_level} -> {psci_return:#x}"
                );
                response = Some(VcpuResponse::CpuOnResult { psci_return });
            }

            VcpuExit::MmioRead { addr, size } => {
                stats.mmio += 1;
                #[cfg(target_arch = "aarch64")]
                if (PL011_BASE..PL011_BASE + PL011_SIZE).contains(&addr) {
                    response = Some(VcpuResponse::Mmio {
                        data: handle_pl011_read(addr - PL011_BASE),
                        size,
                    });
                    continue;
                }
                #[cfg(target_arch = "aarch64")]
                if (PL031_BASE..PL031_BASE + PL031_SIZE).contains(&addr) {
                    response = Some(VcpuResponse::Mmio {
                        data: handle_pl031_read(addr - PL031_BASE),
                        size,
                    });
                    continue;
                }
                #[cfg(target_arch = "x86_64")]
                if let Some(data) = handle_x86_platform_mmio_read(addr, size) {
                    response = Some(VcpuResponse::Mmio { data, size });
                    continue;
                }
                match crate::devices::mmio_read(devices, addr, size) {
                    Ok(value) => {
                        response = Some(VcpuResponse::Mmio { data: value, size });
                    }
                    Err(e) => {
                        log::error!("vCPU {vcpu_id}: {e}");
                        flush_serial(&mut serial_buf, serial);
                        end.report(VmOutcome::Fatal);
                        return;
                    }
                }
            }

            VcpuExit::MmioWrite { addr, data, size } => {
                stats.mmio += 1;
                #[cfg(target_arch = "aarch64")]
                if (PL011_BASE..PL011_BASE + PL011_SIZE).contains(&addr) {
                    handle_pl011_write(&mut serial_buf, serial, addr - PL011_BASE, data, size);
                    continue;
                }
                #[cfg(target_arch = "aarch64")]
                if (PL031_BASE..PL031_BASE + PL031_SIZE).contains(&addr) {
                    continue; // PL031 writes silently ignored (read-only RTC).
                }
                #[cfg(target_arch = "x86_64")]
                if handle_x86_platform_mmio_write(addr, size) {
                    continue;
                }
                if let Err(e) =
                    crate::devices::mmio_write(devices, waker, queue_wakes, addr, data, size)
                {
                    log::error!("vCPU {vcpu_id}: {e}");
                    flush_serial(&mut serial_buf, serial);
                    end.report(VmOutcome::Fatal);
                    return;
                }
                // PC already advanced by the backend (KVM in-kernel, HVF
                // during exit decode). No response needed for writes.
            }

            #[cfg(target_arch = "x86_64")]
            VcpuExit::IoIn { port, size } => {
                stats.pio += 1;
                let value = handle_pio_read(port);
                response = Some(VcpuResponse::Pio { data: value, size });
            }

            #[cfg(target_arch = "x86_64")]
            VcpuExit::IoOut { port, data, size } => {
                stats.pio += 1;
                handle_pio_write(&mut serial_buf, serial, end, port, data, size);
                // PC already advanced by KVM in-kernel.
            }

            VcpuExit::SysReg {
                encoding,
                register,
                is_write,
                write_data,
            } => {
                stats.other += 1;
                // If a system-register access reaches the generic VMM loop,
                // no backend-local emulator handled it. Treat it as missing
                // emulation rather than a blanket RAZ/WI register;
                // architectural RAZ/WI behavior belongs in explicit ARM
                // trap handling before this point.
                log::error!(
                    "unsupported sysreg exit: encoding={encoding:#06x} \
                     register={register} is_write={is_write} value={write_data:#x}: {stats}"
                );
                flush_serial(&mut serial_buf, serial);
                end.report(VmOutcome::Fatal);
                return;
            }

            VcpuExit::Unknown { code, source } => {
                stats.other += 1;
                log::error!("unknown vCPU exit: {source:?} code={code:#x}: {stats}");
                flush_serial(&mut serial_buf, serial);
                end.report(VmOutcome::Fatal);
                return;
            }
        }

        // After handling exit, check cancellation at this safe boundary
        if end.is_stopped() && response.is_none() {
            return;
        }
    }
}

/// Handle x86 platform MMIO reads that KVM does not emulate in-kernel.
#[cfg(target_arch = "x86_64")]
const fn handle_x86_platform_mmio_read(addr: u64, size: u8) -> Option<u64> {
    if size == AMD_FCH_S5_RESET_STATUS_SIZE && addr == AMD_FCH_S5_RESET_STATUS {
        // Linux probes this on AMD Zen CPUs to print the previous reset reason.
        // The VM does not expose an AMD FCH, so report an empty status value.
        return Some(0);
    }
    None
}

/// Handle x86 platform MMIO writes that KVM does not emulate in-kernel.
#[cfg(target_arch = "x86_64")]
const fn handle_x86_platform_mmio_write(addr: u64, size: u8) -> bool {
    // Linux writes the AMD FCH reset-status register after reading it. The VM
    // has no FCH state to clear, so accepting the write as a no-op is enough.
    size == AMD_FCH_S5_RESET_STATUS_SIZE && addr == AMD_FCH_S5_RESET_STATUS
}

/// Flush any buffered serial bytes to the console backend.
fn flush_serial(buf: &mut Vec<u8>, serial: Option<&dyn amla_core::backends::ConsoleBackend>) {
    if !buf.is_empty() {
        if let Some(console) = serial
            && let Err(e) = console.write(buf)
        {
            log::warn!(
                "flush_serial: console.write failed for {} bytes: {e}",
                buf.len()
            );
        }
        buf.clear();
    }
}

/// Append a serial byte to the buffer, flushing on newline or at capacity.
fn append_serial(
    buf: &mut Vec<u8>,
    serial: Option<&dyn amla_core::backends::ConsoleBackend>,
    byte: u8,
) {
    if serial.is_some() {
        buf.push(byte);
        if byte == b'\n' || buf.len() >= 128 {
            flush_serial(buf, serial);
        }
    }
}

// PL011 UART register offsets.
#[cfg(target_arch = "aarch64")]
mod pl011 {
    pub const UARTDR: u64 = 0x000; // Data register
    pub const UARTFR: u64 = 0x018; // Flag register
    pub const UARTFR_TXFE: u64 = 1 << 7; // TX FIFO empty
    pub const UARTFR_RXFE: u64 = 1 << 4; // RX FIFO empty
    pub const UARTCR: u64 = 0x030; // Control register
}

// PL031 RTC register offsets.
#[cfg(target_arch = "aarch64")]
mod pl031 {
    pub const RTCDR: u64 = 0x000; // Data register (current time, read-only)
    pub const RTCCR: u64 = 0x00C; // Control register
    // Peripheral ID (identifies as PL031 rev 1).
    pub const PERIPHID0: u64 = 0xFE0;
    pub const PERIPHID1: u64 = 0xFE4;
    pub const PERIPHID2: u64 = 0xFE8;
    // PrimeCell ID — magic 0xB105F00D split across 4 byte-wide registers.
    // AMBA bus rejects the device if these don't match.
    pub const PCELLID0: u64 = 0xFF0;
    pub const PCELLID1: u64 = 0xFF4;
    pub const PCELLID2: u64 = 0xFF8;
    pub const PCELLID3: u64 = 0xFFC;
}

/// Handle PL031 RTC MMIO read (ARM64).
///
/// Returns the host's current wall-clock time as Unix epoch seconds.
/// Each read is live — always accurate, even after snapshot/restore.
#[cfg(target_arch = "aarch64")]
fn handle_pl031_read(offset: u64) -> u64 {
    match offset {
        pl031::RTCDR => {
            // Live host wall clock — no caching, no stale data after restore.
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
        }
        pl031::RTCCR => 1, // RTC enabled
        // Peripheral ID (identifies as PL031 rev 1).
        pl031::PERIPHID0 => 0x31,
        pl031::PERIPHID1 => 0x10,
        pl031::PERIPHID2 => 0x04,
        // PERIPHID3 = 0 (falls through to default).
        // PrimeCell ID: magic 0xB105F00D — required by AMBA bus for probe.
        pl031::PCELLID0 => 0x0D,
        pl031::PCELLID1 => 0xF0,
        pl031::PCELLID2 => 0x05,
        pl031::PCELLID3 => 0xB1,
        _ => 0,
    }
}

/// Handle PL011 UART MMIO read (ARM64).
#[cfg(target_arch = "aarch64")]
fn handle_pl011_read(offset: u64) -> u64 {
    match offset {
        // Flag register: TX FIFO always empty, RX FIFO always empty
        pl011::UARTFR => pl011::UARTFR_TXFE | pl011::UARTFR_RXFE,
        // Control register: UART enabled, TX enabled
        pl011::UARTCR => 0x301,
        // All other registers: 0
        _ => 0,
    }
}

/// Handle PL011 UART MMIO write (ARM64).
#[cfg(target_arch = "aarch64")]
fn handle_pl011_write(
    buf: &mut Vec<u8>,
    serial: Option<&dyn amla_core::backends::ConsoleBackend>,
    offset: u64,
    data: u64,
    size: u8,
) {
    if offset == pl011::UARTDR && size <= 4 {
        let byte = (data & 0xFF) as u8;
        append_serial(buf, serial, byte);
    }
    // All other writes (baud rate, control, interrupt mask, etc.) are ignored.
}

/// Handle port I/O read (guest IN instruction).
#[cfg(target_arch = "x86_64")]
fn handle_pio_read(port: u16) -> u32 {
    match port {
        // Serial port line status register - always report TX empty
        p if p == SERIAL_PORT + 5 => 0x60,
        // Other serial ports - return 0
        p if (SERIAL_PORT..SERIAL_PORT + 8).contains(&p) => 0,
        // Unknown port - return all 1s
        _ => 0xFF,
    }
}

/// Handle port I/O write (guest OUT instruction).
#[cfg(target_arch = "x86_64")]
fn handle_pio_write(
    buf: &mut Vec<u8>,
    serial: Option<&dyn amla_core::backends::ConsoleBackend>,
    end: &VmEnd,
    port: u16,
    data: u32,
    size: u8,
) {
    // Keyboard controller reset: outb(0xFE, 0x64)
    // The guest agent uses this as a fast VM exit (avoids kernel device_shutdown hang).
    if port == 0x64 && size == 1 && (data & 0xFF) == 0xFE {
        log::debug!("Guest keyboard controller reset (port 0x64)");
        flush_serial(buf, serial);
        end.report(VmOutcome::CleanShutdown);
        return;
    }

    // Serial port data register
    if port == SERIAL_PORT && size == 1 {
        let byte = (data & 0xFF) as u8;
        append_serial(buf, serial, byte);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- PIO read tests (x86 only) --

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_read_serial_lsr() {
        // Line status register (SERIAL_PORT+5) should report TX empty + TX idle
        assert_eq!(handle_pio_read(SERIAL_PORT + 5), 0x60);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_read_serial_data() {
        // Serial data register returns 0 (no data available)
        assert_eq!(handle_pio_read(SERIAL_PORT), 0);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_read_serial_other_regs() {
        // All serial port registers (base through base+7) return 0 except LSR
        for offset in 0..8u16 {
            if offset == 5 {
                continue; // LSR tested above
            }
            assert_eq!(
                handle_pio_read(SERIAL_PORT + offset),
                0,
                "serial port offset {offset}"
            );
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_read_unknown_port() {
        // Unknown ports return 0xFF (all 1s)
        assert_eq!(handle_pio_read(0x80), 0xFF);
        assert_eq!(handle_pio_read(0x1234), 0xFF);
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_x86_platform_mmio_amd_fch_s5_reset_status() {
        assert_eq!(
            handle_x86_platform_mmio_read(AMD_FCH_S5_RESET_STATUS, 4),
            Some(0)
        );
        assert_eq!(
            handle_x86_platform_mmio_read(AMD_FCH_S5_RESET_STATUS, 1),
            None
        );
        assert_eq!(
            handle_x86_platform_mmio_read(AMD_FCH_S5_RESET_STATUS + 4, 4),
            None
        );
        assert!(handle_x86_platform_mmio_write(AMD_FCH_S5_RESET_STATUS, 4));
        assert!(!handle_x86_platform_mmio_write(AMD_FCH_S5_RESET_STATUS, 1));
        assert!(!handle_x86_platform_mmio_write(
            AMD_FCH_S5_RESET_STATUS + 4,
            4
        ));
    }

    // -- PIO write tests (x86 only) --

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_write_serial_to_console() {
        let console = crate::console_stream::ConsoleStream::new();
        let mut drainer = console.clone();
        let serial: &dyn amla_core::backends::ConsoleBackend = &console;
        let end = VmEnd::new();
        let mut buf = Vec::with_capacity(128);

        handle_pio_write(
            &mut buf,
            Some(serial),
            &end,
            SERIAL_PORT,
            u32::from(b'H'),
            1,
        );
        handle_pio_write(
            &mut buf,
            Some(serial),
            &end,
            SERIAL_PORT,
            u32::from(b'i'),
            1,
        );

        // Bytes are batched until newline -- not yet flushed.
        assert!(drainer.drain().is_empty());

        // Newline triggers flush.
        handle_pio_write(
            &mut buf,
            Some(serial),
            &end,
            SERIAL_PORT,
            u32::from(b'\n'),
            1,
        );
        assert_eq!(drainer.drain(), b"Hi\n");
    }

    #[cfg(target_arch = "x86_64")]
    #[test]
    fn test_pio_write_serial_non_byte_size_ignored() {
        let console = crate::console_stream::ConsoleStream::new();
        let mut drainer = console.clone();
        let serial: &dyn amla_core::backends::ConsoleBackend = &console;
        let end = VmEnd::new();
        let mut buf = Vec::with_capacity(128);

        // Only size==1 writes to serial are processed
        handle_pio_write(
            &mut buf,
            Some(serial),
            &end,
            SERIAL_PORT,
            u32::from(b'X'),
            2,
        );
        assert!(drainer.drain().is_empty());
    }

    #[test]
    fn exit_stats_display() {
        let stats = ExitStats {
            hlt: 100,
            mmio: 42,
            pio: 7,
            other: 3,
            total: 152,
        };
        assert_eq!(stats.to_string(), "hlt=100 mmio=42 pio=7 other=3 total=152");
    }

    // -- CpuOnBus tests --

    fn req(entry: u64) -> CpuOnRequest {
        CpuOnRequest {
            entry_point: entry,
            context_id: 0,
        }
    }

    fn with_bus<R>(
        vcpu_count: usize,
        f: impl FnOnce(
            &CpuOnBus<'_>,
            &mut [mpsc::Receiver<CpuOnRequest>],
            &amla_core::vm_state::VmState<'_>,
        ) -> R,
    ) -> R {
        let mmap = amla_core::vm_state::test_mmap_with_vcpus(vcpu_count as u32, 256 * 1024 * 1024);
        let state = amla_core::vm_state::make_test_vmstate(&mmap, 0);
        let (bus, mut receivers) = CpuOnBus::new(vcpu_count, state.psci_power_states());
        f(&bus, &mut receivers, &state)
    }

    fn psci_state(
        state: &amla_core::vm_state::VmState<'_>,
        index: usize,
    ) -> amla_core::vm_state::PsciPowerState {
        state
            .psci_power_states()
            .load(index, Ordering::Acquire)
            .unwrap()
    }

    #[test]
    fn cpu_on_bus_send_to_off_target_accepted_and_enqueued() {
        with_bus(4, |bus, receivers, state| {
            // vCPU 1 starts Off.
            assert_eq!(bus.send(1, req(0x1000)), CpuOnResult::Accepted);
            assert_eq!(
                psci_state(state, 1),
                amla_core::vm_state::PsciPowerState::OnPending
            );
            // The boot request was enqueued exactly once.
            let received = receivers[1].try_recv().unwrap();
            assert_eq!(received.entry_point, 0x1000);
            assert!(receivers[1].try_recv().is_err());
        });
    }

    #[test]
    fn cpu_on_bus_send_to_on_target_already_on_and_no_enqueue() {
        with_bus(4, |bus, receivers, _state| {
            // vCPU 0 starts On (BSP).
            assert_eq!(bus.send(0, req(0x1000)), CpuOnResult::AlreadyOn);
            // No boot request was queued.
            assert!(receivers[0].try_recv().is_err());
        });
    }

    #[test]
    fn cpu_on_bus_self_target_returns_already_on() {
        with_bus(4, |bus, _receivers, _state| {
            // BSP issuing CPU_ON(self) — its state is On, so reject.
            assert_eq!(bus.send(0, req(0x1000)), CpuOnResult::AlreadyOn);
        });
    }

    #[test]
    fn cpu_on_bus_second_send_before_consume_returns_on_pending() {
        with_bus(4, |bus, _receivers, _state| {
            assert_eq!(bus.send(1, req(0x1000)), CpuOnResult::Accepted);
            // Second CPU_ON before the target consumes the first must be
            // OnPending — not Accepted, and must not enqueue a second message.
            assert_eq!(bus.send(1, req(0x2000)), CpuOnResult::OnPending);
        });
    }

    #[test]
    fn cpu_on_bus_after_consume_target_is_on() {
        with_bus(4, |bus, receivers, state| {
            assert_eq!(bus.send(1, req(0x1000)), CpuOnResult::Accepted);
            // Receiver dequeues — simulates the CpuOff arm consuming.
            let _ = receivers[1].try_recv().unwrap();
            bus.mark_on(1);
            assert_eq!(
                psci_state(state, 1),
                amla_core::vm_state::PsciPowerState::On
            );
            // Now vCPU 1 is running. Another CPU_ON must report ALREADY_ON.
            assert_eq!(bus.send(1, req(0x2000)), CpuOnResult::AlreadyOn);
        });
    }

    #[test]
    fn cpu_on_bus_full_off_on_off_lifecycle() {
        with_bus(2, |bus, receivers, state| {
            // Off -> OnPending (accepted), drain, OnPending -> On.
            assert_eq!(bus.send(1, req(0x100)), CpuOnResult::Accepted);
            receivers[1].try_recv().unwrap();
            bus.mark_on(1);
            assert_eq!(bus.send(1, req(0x200)), CpuOnResult::AlreadyOn);
            // vCPU 1 hits CPU_OFF — On -> Off.
            bus.mark_off(1);
            assert_eq!(
                psci_state(state, 1),
                amla_core::vm_state::PsciPowerState::Off
            );
            // Off again, CPU_ON re-accepted.
            assert_eq!(bus.send(1, req(0x300)), CpuOnResult::Accepted);
            let received = receivers[1].try_recv().unwrap();
            assert_eq!(received.entry_point, 0x300);
        });
    }

    #[test]
    fn cpu_on_bus_mark_off_preserves_on_pending() {
        // AP first-boot race: peer sent CPU_ON before this vCPU's first
        // CpuOff exit. mark_off (CAS On->Off) must not clobber OnPending.
        with_bus(2, |bus, receivers, state| {
            assert_eq!(bus.send(1, req(0x100)), CpuOnResult::Accepted);
            bus.mark_off(1); // No-op because state is OnPending, not On.
            assert_eq!(
                psci_state(state, 1),
                amla_core::vm_state::PsciPowerState::OnPending
            );
            // Boot request still queued.
            let received = receivers[1].try_recv().unwrap();
            assert_eq!(received.entry_point, 0x100);
        });
    }

    #[test]
    fn cpu_on_bus_invalid_target() {
        with_bus(4, |bus, _receivers, _state| {
            assert_eq!(bus.send(99, req(0x1000)), CpuOnResult::InvalidTarget);
        });
    }

    #[test]
    fn cpu_on_bus_closed_receiver_reports_target_unavailable() {
        with_bus(4, |bus, receivers, state| {
            for receiver in receivers {
                receiver.close();
            }
            // Receiver gone — vCPU has exited. Send fails the try_send with
            // Closed; this is an internal delivery failure, not a power-state
            // observation.
            assert_eq!(bus.send(2, req(0x1000)), CpuOnResult::TargetUnavailable);
            assert_eq!(
                psci_state(state, 2),
                amla_core::vm_state::PsciPowerState::Off
            );
        });
    }

    #[test]
    fn cpu_on_bus_uses_persisted_running_ap_state() {
        let mmap = amla_core::vm_state::test_mmap_with_vcpus(4, 256 * 1024 * 1024);
        let mut state = amla_core::vm_state::make_test_vmstate(&mmap, 0);
        assert!(state.set_psci_power_state(1, amla_core::vm_state::PsciPowerState::On));
        let (bus, mut receivers) = CpuOnBus::new(4, state.psci_power_states());

        assert_eq!(bus.send(1, req(0x1000)), CpuOnResult::AlreadyOn);
        assert!(receivers[1].try_recv().is_err());
        assert_eq!(
            psci_state(&state, 1),
            amla_core::vm_state::PsciPowerState::On
        );
    }
}
