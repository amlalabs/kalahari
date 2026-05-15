// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! KVM shell types for pre-created VMs with hardware pre-registration.
//!
//! A `Shell` is a pre-created KVM VM with vCPU file descriptors and
//! pre-registered ioeventfds + irqfds. Shells are managed by
//! [`VmPools`](crate::VmPools) which keeps a ready queue stocked via
//! a background refill task.

use std::os::fd::AsRawFd;
use std::sync::Arc;

use kvm_ioctls::{IoEventAddress, Kvm, VcpuFd, VmFd};
use smallvec::SmallVec;
use vmm_sys_util::eventfd::{EFD_NONBLOCK, EventFd};

use amla_core::DeviceWakeIndex;

use crate::arch::InitialDeviceState;
use crate::error::{Result, VmmError};
#[cfg(target_arch = "x86_64")]
use crate::vcpu::is_terminal_halt;
use crate::vcpu::{
    KVM_RUN, KvmVcpuRunState, apply_response_to_kvm_run, block_sigusr1, exit_vcpu_thread,
    init_vcpu_thread, install_preempt_signal_handler, unblock_sigusr1_for_kvm_run,
};

// ============================================================================
// KVM thread loop -- one per vCPU, runs on a dedicated OS thread
// ============================================================================

/// Advance the guest PC by 4 bytes (one `AArch64` instruction).
///
/// Used to skip cache maintenance instructions (IC IVAU, DC CIVAC) that
/// trigger NISV data aborts on readonly KVM memslots. KVM handles this
/// internally for non-memslot regions (`kvm_vcpu_dabt_is_cm` path) but not
/// for readonly memslots, so we replicate the skip in userspace.
#[cfg(target_arch = "aarch64")]
fn skip_arm64_instruction(vcpu_fd: std::os::fd::RawFd) {
    const KVM_GET_ONE_REG: libc::Ioctl = 0x4010_aeab;
    const KVM_SET_ONE_REG: libc::Ioctl = 0x4010_aeac;
    const REG_PC: u64 = 0x6030_0000_0010_0040;

    let mut pc: u64 = 0;
    let reg = kvm_bindings::kvm_one_reg {
        id: REG_PC,
        addr: &raw mut pc as u64,
    };
    // SAFETY: vcpu_fd is valid; reg points to a valid u64.
    if unsafe { libc::ioctl(vcpu_fd, KVM_GET_ONE_REG, &reg) } != 0 {
        return;
    }
    pc = pc.wrapping_add(4);
    let reg = kvm_bindings::kvm_one_reg {
        id: REG_PC,
        addr: &raw const pc as u64,
    };
    // SAFETY: vcpu_fd is valid; reg points to a valid u64.
    unsafe { libc::ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg) };
}

#[allow(clippy::needless_pass_by_value, clippy::too_many_lines)]
pub fn kvm_thread_loop(
    vcpu: Arc<VcpuFd>,
    index: usize,
    kvm_run_size: usize,
    preempt_state: Arc<KvmVcpuRunState>,
    run_mutex: Arc<tokio::sync::Mutex<()>>,
    mut resume_rx: tokio::sync::mpsc::Receiver<Option<amla_core::VcpuResponse>>,
    exit_tx: tokio::sync::mpsc::Sender<amla_core::VcpuExit>,
) {
    use amla_core::VcpuExit;

    // The `vcpu: Arc<VcpuFd>` captured into this closure owns the VcpuFd for
    // the entire lifetime of this thread. The raw fd is therefore guaranteed
    // live from here until the closure returns and drops the Arc. This
    // replaces what was previously a load-bearing Drop-ordering contract in
    // `Shell::drop` with type-enforced ownership; the SIGUSR1-and-join dance
    // in `Shell::drop` remains as defense-in-depth for orderly shutdown.
    let raw_fd = vcpu.as_raw_fd();

    // SAFETY: `raw_fd` is owned by the `vcpu: Arc<VcpuFd>` captured into this
    // closure for the full duration of this thread; the BorrowedFd is used
    // only for the mmap call below and does not outlive the Arc.
    let borrowed_fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(raw_fd) };
    // SAFETY: null addr + SHARED with `kvm_run_size` from KVM_GET_VCPU_MMAP_SIZE
    // is the documented way to map the kvm_run page. The returned pointer is
    // used exclusively from this thread and unmapped on thread exit below.
    let kvm_run_ptr = match unsafe {
        rustix::mm::mmap(
            std::ptr::null_mut(),
            kvm_run_size,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::SHARED,
            borrowed_fd,
            0,
        )
    } {
        Ok(ptr) => ptr.cast::<kvm_bindings::kvm_run>(),
        Err(e) => {
            log::error!("kvm-vcpu-{index}: mmap kvm_run: {e}");
            return;
        }
    };

    // Set thread-local kvm_run pointer BEFORE installing the signal handler.
    crate::vcpu::set_thread_kvm_run_ptr(kvm_run_ptr);

    // Initialize per-vcpu-thread generation BEFORE blocking the signal and
    // installing the handler. Any SIGUSR1 racing with init will be blocked
    // in userspace until we unblock around KVM_RUN.
    init_vcpu_thread(&preempt_state);

    // Block SIGUSR1 on this thread; we unblock only around KVM_RUN below.
    // Combined with the tid-reuse generation check in the signal handler,
    // this ensures a stale tgkill cannot hit an unrelated thread occupying
    // this tid after the vcpu exits.
    if let Err(e) = block_sigusr1() {
        log::error!("kvm-vcpu-{index}: block SIGUSR1: {e}");
        exit_vcpu_thread(&preempt_state);
        return;
    }

    if let Err(e) = install_preempt_signal_handler() {
        log::error!("kvm-vcpu-{index}: signal handler: {e}");
        exit_vcpu_thread(&preempt_state);
        return;
    }

    log::debug!("kvm-vcpu-{index}: started");

    // Breadcrumb for unrecoverable-exit sends whose receiver has already
    // been dropped. Expected during teardown; logged at debug so the grep
    // pattern stays uniform across the error branches below. Every caller
    // is an error path — apply-response failure, ioctl failure, signal-
    // mask failure — so the outcome is always Unrecoverable.
    let send_unrecoverable = |tag: &str| {
        if let Err(e) = exit_tx.blocking_send(VcpuExit::Unrecoverable) {
            log::debug!("kvm-vcpu-{index}: exit_tx Unrecoverable ({tag}) failed: {e}");
        }
    };

    'outer: while let Some(response) = resume_rx.blocking_recv() {
        // Lock run_mutex for the entire active cycle (apply → KVM_RUN → send exit).
        // save_state() awaits this mutex to synchronize.
        let run_guard = run_mutex.blocking_lock();

        if let Some(resp) = response
            && let Err(e) = apply_response_to_kvm_run(kvm_run_ptr, kvm_run_size, resp)
        {
            log::error!("kvm-vcpu-{index}: apply response: {e}");
            send_unrecoverable("apply");
            break;
        }

        let exit = {
            let guard = preempt_state.lock();

            let tid = rustix::thread::gettid().as_raw_nonzero().get();
            preempt_state.mark_running_with_tid(tid);

            // Set immediate_exit from preempt flag. Only write when the
            // flag is set — a no-op write (|= 0) would be a non-atomic
            // read-modify-write that could clobber the signal handler's
            // concurrent write of 1.
            if preempt_state.swap_preempt() {
                // SAFETY: immediate_exit is a u8 field in the kvm_run mmap region
                // owned exclusively by this vcpu thread; volatile prevents reordering
                // relative to the KVM_RUN ioctl.
                unsafe { core::ptr::write_volatile(&raw mut (*kvm_run_ptr).immediate_exit, 1) };
            }

            // Unblock SIGUSR1 for the duration of KVM_RUN so a concurrent
            // tgkill can EINTR the ioctl. Outside this window SIGUSR1 is
            // blocked (see block_sigusr1 at thread entry), ensuring a stale
            // signal cannot hit an unrelated thread after this one exits.
            if let Err(e) = unblock_sigusr1_for_kvm_run() {
                log::error!("kvm-vcpu-{index}: unblock SIGUSR1: {e}");
                send_unrecoverable("unblock-sigusr1");
                break 'outer;
            }

            // Retry on EAGAIN and NISV cache-maintenance exits without
            // releasing the lock.
            let (ret, errno) = loop {
                // SAFETY: `raw_fd` is owned by `vcpu: Arc<VcpuFd>` above and is
                // a valid KVM vCPU fd for the full duration of this thread;
                // KVM_RUN takes no argument (0 is unused).
                let ret = unsafe { libc::ioctl(raw_fd, KVM_RUN, 0) };
                let errno = if ret == -1 {
                    std::io::Error::last_os_error().raw_os_error()
                } else {
                    None
                };
                if errno == Some(libc::EAGAIN) {
                    continue;
                }
                // Handle NISV cache maintenance exits by advancing PC and
                // re-entering KVM_RUN.
                //
                // The guest kernel does IC IVAU (icache invalidate) on
                // DAX-mapped executable pages whose backing KVM memslot is
                // readonly. KVM treats cache-maintenance ops as writes, so
                // readonly memslot + NISV syndrome = exit to userspace.
                // Skipping is safe: the data is readonly so icache coherency
                // is not affected.
                #[cfg(target_arch = "aarch64")]
                if ret == 0 {
                    // SAFETY: kvm_run_ptr valid for this thread.
                    let run = unsafe { &*kvm_run_ptr };
                    if run.exit_reason == kvm_bindings::KVM_EXIT_ARM_NISV {
                        // SAFETY: exit_reason == KVM_EXIT_ARM_NISV guarantees arm_nisv union.
                        let nisv = unsafe { &run.__bindgen_anon_1.arm_nisv };
                        if (nisv.esr_iss & (1 << 8)) != 0 {
                            skip_arm64_instruction(raw_fd);
                            continue;
                        }
                    }
                }
                break (ret, errno);
            };

            // Re-block SIGUSR1 immediately after KVM_RUN returns. Any
            // SIGUSR1 delivered after this point will be buffered until
            // the next unblock — or discarded when the thread exits.
            if let Err(e) = block_sigusr1() {
                log::error!("kvm-vcpu-{index}: re-block SIGUSR1: {e}");
                send_unrecoverable("block-sigusr1");
                break 'outer;
            }

            // Clear immediate_exit AFTER ioctl so the signal handler's
            // write survives through the ioctl entry.
            // SAFETY: immediate_exit is a u8 field in the kvm_run mmap region
            // owned exclusively by this vcpu thread; volatile prevents reordering
            // relative to the KVM_RUN ioctl.
            unsafe { core::ptr::write_volatile(&raw mut (*kvm_run_ptr).immediate_exit, 0) };

            preempt_state.mark_stopped_with_tid();
            drop(guard);

            match ret {
                0 => {
                    // SAFETY: `kvm_run_ptr` points to the KVM_RUN mmap region owned
                    // exclusively by this vcpu thread and populated by the ioctl above.
                    let run_ref = unsafe { &*kvm_run_ptr };
                    let exit =
                        crate::arch::map_exit(run_ref, kvm_run_ptr.cast::<u8>(), kvm_run_size);
                    #[cfg(target_arch = "x86_64")]
                    if matches!(exit, VcpuExit::Halt) && is_terminal_halt(raw_fd) {
                        // `cli; hlt` with IFLAG cleared is Linux's legacy
                        // poweroff path — intentional shutdown from guests
                        // that don't use the amla-guest port-0x64 fast exit.
                        VcpuExit::CleanShutdown
                    } else {
                        exit
                    }
                    #[cfg(not(target_arch = "x86_64"))]
                    exit
                }
                -1 if errno == Some(libc::EINTR) => VcpuExit::Interrupted,
                _ => {
                    // SAFETY: kvm_run_ptr is valid for the lifetime of this thread.
                    let run_ref = unsafe { &*kvm_run_ptr };
                    log::error!(
                        "kvm-vcpu-{index}: KVM_RUN failed: ret={ret} errno={errno:?} \
                         exit_reason={}",
                        run_ref.exit_reason
                    );
                    send_unrecoverable("KVM_RUN-fail");
                    break 'outer;
                }
            }
        };

        drop(run_guard);
        if exit_tx.blocking_send(exit).is_err() {
            break;
        }
    }

    log::debug!("kvm-vcpu-{index}: exiting");
    // Bump the generation and clear thread-local vcpu pointers BEFORE
    // munmap so any SIGUSR1 delivered to this tid after the vcpu is gone
    // (including one for a future thread that reuses the tid) no-ops in
    // the handler.
    exit_vcpu_thread(&preempt_state);
    // SAFETY: `kvm_run_ptr` was returned by the matching mmap above with
    // `kvm_run_size` and is no longer used after this call.
    if let Err(e) = unsafe { rustix::mm::munmap(kvm_run_ptr.cast(), kvm_run_size) } {
        log::warn!("kvm-vcpu-{index}: munmap kvm_run failed during teardown: {e}");
    }
}

// ============================================================================
// Shell Hardware — permanent eventfds for zero-ioctl spawn/freeze
// ============================================================================

/// Fixed device topology for shell hardware pre-registration.
///
/// Describes the MMIO notify addresses and GSIs for all device slots.
/// Computed once at the VMM layer from virtio-mmio constants and passed
/// to [`VmPools::new()`](crate::VmPools::new).
///
/// The layout is exact: every ioeventfd belongs to a concrete device queue
/// in the VM topology.
#[derive(Clone, Debug)]
pub struct HardwareLayout {
    /// Per-device IRQ layout.
    pub(crate) device_slots: Vec<DeviceSlotLayout>,
    /// Per-queue ioeventfd layout.
    pub(crate) io_slots: Vec<IoEventSlotLayout>,
}

impl HardwareLayout {
    /// Create an empty hardware layout (no pre-registered eventfds).
    ///
    /// Useful for tests and benchmarks that don't use virtio devices.
    /// Shells created with an empty layout still work — device setup
    /// falls through to the traditional per-VM eventfd registration path.
    pub const fn empty() -> Self {
        Self {
            device_slots: Vec::new(),
            io_slots: Vec::new(),
        }
    }

    /// Build a layout from per-device IRQ slots and per-queue ioeventfd slots.
    ///
    /// Used by VMM-layer code that knows the device topology but doesn't
    /// depend on KVM-specific types (`DeviceSlotLayout` is an implementation
    /// detail of this crate).
    pub fn from_device_and_queue_slots(
        device_slots: impl IntoIterator<Item = (u32, Option<DeviceWakeIndex>)>,
        io_slots: impl IntoIterator<Item = (usize, u64, u32, DeviceWakeIndex)>,
    ) -> Self {
        Self {
            device_slots: device_slots
                .into_iter()
                .map(|(gsi, resample_wake_idx)| DeviceSlotLayout {
                    gsi,
                    resample_wake_idx,
                })
                .collect(),
            io_slots: io_slots
                .into_iter()
                .map(
                    |(device_idx, mmio_notify_addr, queue_idx, wake_idx)| IoEventSlotLayout {
                        device_idx,
                        mmio_notify_addr,
                        queue_idx,
                        wake_idx,
                    },
                )
                .collect(),
        }
    }
}

/// Per-device-slot hardware layout.
#[derive(Clone, Copy, Debug)]
pub struct DeviceSlotLayout {
    /// GSI for this device's interrupt line.
    pub gsi: u32,
    /// Queue wake bit to set when this interrupt line receives guest EOI.
    pub resample_wake_idx: Option<DeviceWakeIndex>,
}

/// Per-queue ioeventfd layout.
#[derive(Clone, Copy, Debug)]
pub struct IoEventSlotLayout {
    /// Device slot that owns this queue notification.
    pub device_idx: usize,
    /// MMIO `QueueNotify` address that triggers ioeventfd.
    pub mmio_notify_addr: u64,
    /// `QueueNotify` datamatch value.
    pub queue_idx: u32,
    /// Global wake bit index to set when this ioeventfd fires.
    pub wake_idx: DeviceWakeIndex,
}

struct IoSlot {
    /// Eventfd registered with `KVM_IOEVENTFD` (permanent, lives for shell lifetime).
    /// `Arc` shared with the `KvmDeviceWaker` for zero-dup fd ownership.
    eventfd: Arc<EventFd>,
    /// Global wake bit index.
    wake_idx: DeviceWakeIndex,
}

struct IrqSlot {
    /// Eventfd registered with `KVM_IRQFD` (permanent).
    eventfd: EventFd,
    /// Resample eventfd registered with `KVM_IRQFD` (permanent).
    resamplefd: Arc<EventFd>,
    /// Set by the device waker when it consumes `resamplefd`.
    resample_pending: Arc<std::sync::atomic::AtomicBool>,
    /// GSI for this slot.
    gsi: u32,
    /// Queue wake bit to set when `resamplefd` fires.
    resample_wake_idx: Option<DeviceWakeIndex>,
}

/// Pre-registered hardware attached to a [`Shell`].
///
/// Eventfds are created and registered with KVM (`KVM_IOEVENTFD` + `KVM_IRQFD`)
/// once during shell creation. They persist for the shell's entire lifetime,
/// eliminating ~35 syscalls per freeze+spawn cycle.
///
/// # Lifecycle
///
/// 1. Created in [`Shell::new()`] when a [`HardwareLayout`] is provided
/// 2. Device waker created via [`create_device_waker()`](Self::create_device_waker) each spawn
/// 3. Dropped with the shell (KVM auto-unregisters on fd close)
pub struct ShellHardware {
    io_slots: Vec<IoSlot>,
    irq_slots: Vec<IrqSlot>,
}

impl ShellHardware {
    /// Create and register all hardware for the given layout.
    ///
    /// Both ioeventfds and irqfds are registered with KVM immediately.
    /// Shells in the pool are always in a "ready" state with irqfds
    /// registered. The bounce (unregister+register) happens on return
    /// to the pool, not on spawn.
    fn new(vm_fd: &VmFd, layout: &HardwareLayout) -> Result<Self> {
        let mut io_slots = Vec::with_capacity(layout.io_slots.len());
        let mut irq_slots = Vec::with_capacity(layout.device_slots.len());

        let device_count = layout.device_slots.len();
        for slot_layout in &layout.io_slots {
            if slot_layout.device_idx >= device_count {
                return Err(VmmError::Config(format!(
                    "io slot references device {} but layout has {device_count} devices",
                    slot_layout.device_idx
                )));
            }
            // --- ioeventfd ---
            let io_eventfd =
                EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("shell ioeventfd"))?;
            vm_fd
                .register_ioevent(
                    &io_eventfd,
                    &IoEventAddress::Mmio(slot_layout.mmio_notify_addr),
                    slot_layout.queue_idx,
                )
                .map_err(|e| VmmError::SystemCall {
                    operation: "KVM_IOEVENTFD register (shell)",
                    source: std::io::Error::from_raw_os_error(e.errno()),
                })?;

            io_slots.push(IoSlot {
                eventfd: Arc::new(io_eventfd),
                wake_idx: slot_layout.wake_idx,
            });
        }

        for slot_layout in &layout.device_slots {
            // --- irqfd with resample ---
            let irq_eventfd = EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("shell irqfd"))?;
            let resamplefd =
                Arc::new(EventFd::new(EFD_NONBLOCK).map_err(VmmError::sys("shell resamplefd"))?);
            vm_fd.register_irqfd_with_resample(&irq_eventfd, &resamplefd, slot_layout.gsi)?;

            irq_slots.push(IrqSlot {
                eventfd: irq_eventfd,
                resamplefd,
                resample_pending: Arc::new(std::sync::atomic::AtomicBool::new(false)),
                gsi: slot_layout.gsi,
                resample_wake_idx: slot_layout.resample_wake_idx,
            });
        }

        Ok(Self {
            io_slots,
            irq_slots,
        })
    }

    /// Create a [`KvmDeviceWaker`](crate::device_waker::KvmDeviceWaker) from the
    /// pre-registered ioeventfds.
    ///
    /// Each io slot's eventfd is paired with its positional device index.
    /// The waker polls these eventfds internally — no fds leave this crate.
    ///
    /// Must be called from a tokio runtime context (for `AsyncFd` registration).
    pub(crate) fn create_device_waker(&self) -> crate::Result<Arc<dyn amla_core::DeviceWaker>> {
        let entries: Vec<_> = self
            .io_slots
            .iter()
            .map(|slot| (Arc::clone(&slot.eventfd), slot.wake_idx, None))
            .chain(self.irq_slots.iter().filter_map(|slot| {
                let wake_idx = slot.resample_wake_idx?;
                Some((
                    Arc::clone(&slot.resamplefd),
                    wake_idx,
                    Some(Arc::clone(&slot.resample_pending)),
                ))
            }))
            .collect();
        Ok(Arc::new(crate::device_waker::KvmDeviceWaker::new(entries)?))
    }

    /// Get the eventfds for an IRQ at the given GSI.
    ///
    /// Returns `(eventfd, resamplefd)` references for cloning.
    pub(crate) fn irq_eventfds(
        &self,
        gsi: u32,
    ) -> Option<(&EventFd, &EventFd, Arc<std::sync::atomic::AtomicBool>)> {
        self.irq_slots.iter().find(|s| s.gsi == gsi).map(|s| {
            (
                &s.eventfd,
                s.resamplefd.as_ref(),
                Arc::clone(&s.resample_pending),
            )
        })
    }
}

impl std::fmt::Debug for ShellHardware {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ShellHardware")
            .field("io_slots", &self.io_slots.len())
            .field("irq_slots", &self.irq_slots.len())
            .finish_non_exhaustive()
    }
}

// ============================================================================
// vCPU thread handle — one per vCPU, owned by Shell
// ============================================================================

pub struct VcpuThreadHandle {
    join_handle: Option<std::thread::JoinHandle<()>>,
    pub(crate) resume_tx: tokio::sync::mpsc::Sender<Option<amla_core::VcpuResponse>>,
    pub(crate) exit_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<amla_core::VcpuExit>>,
    pub(crate) preempt_state: Arc<KvmVcpuRunState>,
    /// Locked by the OS thread during the active `KVM_RUN` cycle (apply → run → send).
    /// `save_state()` awaits this to synchronize with the thread.
    pub(crate) run_mutex: Arc<tokio::sync::Mutex<()>>,
}

// ============================================================================
// Shell — pre-created KVM VM with vCPU file descriptors
// ============================================================================

/// A pre-created KVM VM with vCPU file descriptors.
///
/// Contains all expensive-to-create KVM resources.
/// Managed by [`VmPools`](crate::VmPools) — dropped via `drop_shell()`.
pub struct Shell {
    /// KVM VM file descriptor.
    pub(crate) vm_fd: VmFd,
    /// Pre-created vCPU file descriptors.
    ///
    /// Stored as `Arc<VcpuFd>` so each vcpu OS thread can hold its own
    /// shared-ownership clone for the entire duration of the thread. This
    /// makes the fd's lifetime a type-enforced property of ownership rather
    /// than depending on `Shell::drop`'s join-before-field-drop ordering.
    pub(crate) vcpus: SmallVec<[Arc<VcpuFd>; 4]>,
    /// Initial device state captured after shell creation.
    /// On ARM64: stores `GICv3` `DeviceFd` for state save/restore.
    pub(crate) initial_device_state: InitialDeviceState,
    /// Pre-registered hardware (ioeventfds + irqfds) for zero-ioctl spawn/freeze.
    /// Always present — all VMs share the same fixed hardware shape.
    /// May have zero slots (from `HardwareLayout::empty()`) for tests.
    pub(crate) hardware: ShellHardware,
    /// Per-vCPU thread handles. None if threads haven't been spawned yet (test shells).
    vcpu_threads: Vec<VcpuThreadHandle>,
    /// Number of vCPUs. Stored explicitly so `vcpu_count()` returns `u32`
    /// without a `vcpus.len() as u32` narrow — matches the KVM/HVF ABI.
    vcpu_count: u32,
}

impl std::fmt::Debug for Shell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shell")
            .field("vm_fd", &self.vm_fd.as_raw_fd())
            .field("vcpu_count", &self.vcpus.len())
            .field("hardware", &self.hardware)
            .field("vcpu_threads", &self.vcpu_threads.len())
            .finish_non_exhaustive()
    }
}

/// Create a bare KVM VM with vCPU file descriptors.
///
/// Performs architecture-specific setup (x86: TSS, identity map, irqchip,
/// PIT, CPUID; ARM64: `GICv3`, `vcpu_init`) but does NOT register any
/// ioeventfds or irqfds.
///
/// Returns `(VmFd, vcpus, InitialDeviceState)`. `InitialDeviceState`
/// must be retained — on ARM64 it holds the GIC `DeviceFd` for state
/// save/restore. Used by [`Shell::new()`] (which adds hardware) and
/// the subprocess child worker (which registers irqfds separately).
pub fn create_raw_vm(
    kvm: &Kvm,
    vcpu_count: u32,
) -> Result<(VmFd, SmallVec<[VcpuFd; 4]>, InitialDeviceState)> {
    let vm_fd = kvm.create_vm()?;

    // Architecture-specific VM setup (x86: TSS, identity map, irqchip, PIT)
    crate::arch::setup_vm(&vm_fd)?;

    // Pre-create vCPUs
    let mut vcpus = SmallVec::with_capacity(vcpu_count as usize);
    for i in 0..vcpu_count {
        let vcpu_fd = vm_fd.create_vcpu(u64::from(i))?;
        vcpus.push(vcpu_fd);
    }

    // Architecture-specific per-vCPU setup
    // On x86: CPUID with APIC IDs (returns ())
    // On ARM64: GICv3 creation + vcpu_init (returns kvm_vcpu_init for reset)
    #[cfg_attr(target_arch = "x86_64", allow(clippy::let_unit_value))]
    let arch_state = crate::arch::setup_vcpus(kvm, &vm_fd, &vcpus)?;

    // Capture initial device state. On ARM64 this stores the GIC DeviceFd
    // for state save/restore. On x86_64 this is a no-op.
    let initial_device_state = crate::arch::capture_initial_state(&vm_fd, &vcpus, arch_state)?;

    Ok((vm_fd, vcpus, initial_device_state))
}

impl Shell {
    /// Create a new shell with the given vCPU count.
    ///
    /// Pre-registers ioeventfds and irqfds for the given device topology.
    /// Spawns one OS thread per vCPU for `KVM_RUN` execution.
    ///
    /// This is expensive (~3-5ms) due to KVM VM creation. Use `VmPools`
    /// to maintain a ready queue of pre-created shells.
    pub fn new(
        kvm: &Kvm,
        vcpu_count: u32,
        layout: &HardwareLayout,
        kvm_run_size: usize,
    ) -> Result<Self> {
        let vcpu_count_usz = vcpu_count as usize;
        let (vm_fd, raw_vcpus, initial_device_state) = create_raw_vm(kvm, vcpu_count)?;

        // Wrap each VcpuFd in an Arc so the spawned vcpu thread can co-own it
        // for the thread's entire lifetime (type-enforced fd lifetime).
        let vcpus: SmallVec<[Arc<VcpuFd>; 4]> = raw_vcpus.into_iter().map(Arc::new).collect();

        // Pre-register shell hardware (ioeventfds + irqfds).
        // Must happen AFTER irqchip setup (setup_vm) and vCPU creation.
        let hardware = ShellHardware::new(&vm_fd, layout)?;

        // Spawn one OS thread per vCPU.
        let mut vcpu_threads = Vec::with_capacity(vcpu_count_usz);
        for i in 0..vcpu_count {
            let i_usz = i as usize;
            let (resume_tx, resume_rx) = tokio::sync::mpsc::channel(1);
            let (exit_tx, exit_rx) = tokio::sync::mpsc::channel(1);
            let thread_vcpu = Arc::clone(&vcpus[i_usz]);
            let preempt_state = Arc::new(KvmVcpuRunState::default());
            let run_mutex = Arc::new(tokio::sync::Mutex::new(()));
            let thread_state = Arc::clone(&preempt_state);
            let thread_mutex = Arc::clone(&run_mutex);
            let join_handle = std::thread::Builder::new()
                .name(format!("kvm-vcpu-{i}"))
                .spawn(move || {
                    kvm_thread_loop(
                        thread_vcpu,
                        i_usz,
                        kvm_run_size,
                        thread_state,
                        thread_mutex,
                        resume_rx,
                        exit_tx,
                    );
                })
                .map_err(|e| VmmError::SystemCall {
                    operation: "spawn kvm thread",
                    source: std::io::Error::other(e.to_string()),
                })?;
            vcpu_threads.push(VcpuThreadHandle {
                join_handle: Some(join_handle),
                resume_tx,
                exit_rx: tokio::sync::Mutex::new(exit_rx),
                preempt_state,
                run_mutex,
            });
        }

        Ok(Self {
            vm_fd,
            vcpus,
            initial_device_state,
            hardware,
            vcpu_threads,
            vcpu_count,
        })
    }

    /// Get the VM file descriptor.
    pub const fn vm_fd(&self) -> &VmFd {
        &self.vm_fd
    }

    /// Get the number of vCPUs.
    pub const fn vcpu_count(&self) -> u32 {
        self.vcpu_count
    }

    /// Get the vCPU file descriptors.
    ///
    /// Each fd is wrapped in `Arc` so the per-vcpu OS thread co-owns its
    /// `VcpuFd`; callers typically auto-deref through `&Arc<VcpuFd>` to the
    /// underlying `VcpuFd` methods.
    pub fn vcpus(&self) -> &[Arc<VcpuFd>] {
        &self.vcpus
    }

    /// Get the pre-registered shell hardware.
    pub(crate) const fn hardware(&self) -> &ShellHardware {
        &self.hardware
    }

    /// Get a vCPU thread handle by index.
    pub(crate) fn vcpu_thread(&self, index: usize) -> &VcpuThreadHandle {
        &self.vcpu_threads[index]
    }
}

impl Drop for Shell {
    fn drop(&mut self) {
        // Close all channels -> KVM threads see closed recv -> exit loop.
        for t in &mut self.vcpu_threads {
            let (dead_tx, _) = tokio::sync::mpsc::channel(1);
            // Drop the previous sender immediately so the receiver observes close.
            drop(std::mem::replace(&mut t.resume_tx, dead_tx));
        }

        // Preempt + join all KVM threads.
        for t in &mut self.vcpu_threads {
            t.preempt_state.request_preempt();
            if let Some(handle) = t.join_handle.take()
                && let Err(e) = handle.join()
            {
                log::warn!("kvm shell drop: vcpu thread join panicked: {e:?}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shell_creation() {
        if Kvm::new().is_err() {
            eprintln!("KVM not available, skipping test");
            return;
        }

        let kvm = Kvm::new().unwrap();
        let kvm_run_size = kvm.get_vcpu_mmap_size().unwrap();
        let shell = Shell::new(&kvm, 1, &HardwareLayout::empty(), kvm_run_size).unwrap();
        assert_eq!(shell.vcpu_count(), 1);
        assert_eq!(shell.vcpus.len(), 1);
        assert_eq!(shell.vcpu_threads.len(), 1);
    }
}
