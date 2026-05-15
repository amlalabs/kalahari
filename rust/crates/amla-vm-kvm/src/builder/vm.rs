// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use std::os::fd::AsRawFd;
use std::sync::Arc;

use kvm_ioctls::VmFd;

use super::pools::VmPools;
use crate::arch::{VcpuSnapshot, VmStateSnapshot};
use crate::error::{Result, VmmError};
use crate::irq::ShellIrqLine;
use crate::shell::Shell;

// ============================================================================
// Types
// ============================================================================

struct LiveVmInner {
    pools: VmPools,
    shell: Shell,
}

/// A virtual machine backed by KVM.
pub struct Vm {
    inner: Option<Box<LiveVmInner>>,
    next_slot: u32,
    /// Mmaps kept alive for KVM memory slot validity. Dropped after KVM fd closes.
    maps: Vec<amla_mem::MmapSlice>,
}

// SAFETY: Shell contains fds (Send), channel endpoints are Send, JoinHandle is Send.
unsafe impl Send for Vm {}

/// Builder for creating VMs.
pub struct VmBuilder {
    pools: VmPools,
}

impl Vm {
    /// Create a VM builder.
    pub fn builder(pools: &VmPools) -> VmBuilder {
        VmBuilder {
            pools: pools.clone(),
        }
    }
}

// ============================================================================
// Build
// ============================================================================

impl VmBuilder {
    /// Build a VM: acquires a pre-warmed shell (with threads already running).
    pub async fn build_shell(self) -> Result<Vm> {
        let shell = self.pools.acquire_shell().await?;

        let live = Box::new(LiveVmInner {
            pools: self.pools,
            shell,
        });

        Ok(Vm {
            inner: Some(live),
            next_slot: 0,
            maps: Vec::new(),
        })
    }
}

// ============================================================================
// Helpers
// ============================================================================

impl Vm {
    #[inline]
    fn live(&self) -> Result<&LiveVmInner> {
        self.inner.as_deref().ok_or(VmmError::UseAfterDrop)
    }

    /// Close the VM and wait until KVM has dropped all writable mappings.
    pub async fn close(mut self) -> Result<()> {
        if let Some(live) = self.inner.take() {
            let maps = std::mem::take(&mut self.maps);
            let LiveVmInner { pools, shell } = *live;
            pools.close_shell_retaining(shell, maps).await?;
        }
        Ok(())
    }
}

// ============================================================================
// resume — the core vCPU execution API
// ============================================================================

impl Vm {
    /// Resume a vCPU: send response, await next exit.
    ///
    /// The caller must preempt via `preempt_vcpu` before dropping this
    /// future — there is no implicit cancellation guard.
    // Reason: the exit-rx async mutex guard must outlive the send-recv
    // round-trip; releasing it earlier would race with another caller
    // attempting to receive on the same channel.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn resume(
        &self,
        id: amla_core::VcpuId,
        info: Option<amla_core::VcpuResponse>,
    ) -> Result<amla_core::VcpuExit> {
        let t = self.live()?.shell.vcpu_thread(id.0 as usize);
        let mut rx = t.exit_rx.lock().await;

        t.resume_tx
            .send(info)
            .await
            .map_err(|_| VmmError::Config("KVM thread exited".into()))?;

        let exit = rx
            .recv()
            .await
            .ok_or_else(|| VmmError::Config("KVM thread exited".into()))?;

        Ok(exit)
    }

    /// Preempt a vCPU: set the preempt flag and send SIGUSR1 to kick
    /// the thread out of `KVM_RUN`. The next `resume()` call will return
    /// `VcpuExit::Interrupted`.
    pub fn preempt_vcpu(&self, id: amla_core::VcpuId) {
        if let Ok(inner) = self.live() {
            inner
                .shell
                .vcpu_thread(id.0 as usize)
                .preempt_state
                .request_preempt();
        }
    }

    /// Number of vCPUs.
    pub fn vcpu_count(&self) -> u32 {
        self.live().map_or(0, |inner| inner.shell.vcpu_count())
    }

    /// Drain buffered UART console output (no-op in direct mode — serial
    /// is handled synchronously in `vcpu_run_loop`).
    #[allow(clippy::unused_self)]
    pub const fn drain_console_output(&self) -> Vec<u8> {
        Vec::new()
    }
}

// ============================================================================
// Memory
// ============================================================================

impl Vm {
    /// Register guest memory with KVM.
    ///
    /// Mmaps each handle internally for KVM slot registration. The caller
    /// should create its own mmap from the same `MemHandles` if it needs
    /// host-side access (e.g. for `VmState`). Both mappings share the same
    /// underlying pages via `MAP_SHARED`.
    pub async fn map_memory(
        &mut self,
        handles: &[&amla_mem::MemHandle],
        mappings: &[amla_core::MemoryMapping],
    ) -> Result<()> {
        let handle_info = mapping_handle_info(handles);
        let mappings = amla_core::ValidatedMemoryMappings::new(mappings, &handle_info)
            .map_err(|e| VmmError::Config(e.to_string()))?;
        let mapping_count = memory_mapping_count(mappings.entries())?;
        self.next_slot
            .checked_add(mapping_count)
            .ok_or_else(|| VmmError::Config("KVM memslot index overflow".into()))?;

        let handle_maps = map_memory_handles(handles)?;
        let mut leaked_maps: Vec<amla_mem::MmapSlice> = Vec::new();
        let first_slot = self.next_slot;

        match self.register_memory_mappings(&handle_maps, mappings.entries(), &mut leaked_maps) {
            Ok(()) => {
                self.maps.extend(handle_maps);
                self.maps.extend(leaked_maps);
                Ok(())
            }
            Err(error) => {
                self.rollback_memory_slots(first_slot);
                Err(error)
            }
        }
    }

    fn register_memory_mappings(
        &mut self,
        handle_maps: &[amla_mem::MmapSlice],
        mappings: &[amla_core::ValidatedMemoryMapping],
        leaked_maps: &mut Vec<amla_mem::MmapSlice>,
    ) -> Result<()> {
        for mapping in mappings {
            let (host_ptr, leaked_map) = host_mapping(*mapping, handle_maps)?;
            let slot = self.next_slot;
            self.next_slot = self
                .next_slot
                .checked_add(1)
                .ok_or_else(|| VmmError::Config("KVM memslot index overflow".into()))?;
            register_memory_region(self.live()?.shell.vm_fd(), slot, *mapping, host_ptr)?;
            if let Some(map) = leaked_map {
                leaked_maps.push(map);
            }
        }
        Ok(())
    }

    fn rollback_memory_slots(&mut self, first_slot: u32) {
        if let Ok(inner) = self.live() {
            for slot in first_slot..self.next_slot {
                unregister_memory_region(inner.shell.vm_fd(), slot);
            }
        }
        self.next_slot = first_slot;
    }
}

fn mapping_handle_info(handles: &[&amla_mem::MemHandle]) -> Vec<amla_core::MappingHandleInfo> {
    handles
        .iter()
        .map(|handle| amla_core::MappingHandleInfo::from(*handle))
        .collect()
}

fn memory_mapping_count(mappings: &[amla_core::ValidatedMemoryMapping]) -> Result<u32> {
    u32::try_from(mappings.len())
        .map_err(|_| VmmError::Config(format!("too many mappings: {}", mappings.len())))
}

fn map_memory_handles(handles: &[&amla_mem::MemHandle]) -> Result<Vec<amla_mem::MmapSlice>> {
    handles
        .iter()
        .map(|h| amla_mem::map_handle(h).map_err(VmmError::from))
        .collect::<Result<_>>()
}

fn host_mapping(
    mapping: amla_core::ValidatedMemoryMapping,
    handle_maps: &[amla_mem::MmapSlice],
) -> Result<(std::ptr::NonNull<u8>, Option<amla_mem::MmapSlice>)> {
    match mapping.source() {
        amla_core::ValidatedMapSource::Handle {
            index,
            offset,
            offset_usize,
        } => {
            let ptr = handle_host_mapping(mapping, handle_maps, index, offset, offset_usize)?;
            Ok((ptr, None))
        }
        amla_core::ValidatedMapSource::AnonymousZero => {
            let size = mapping.size_usize();
            let zero = amla_mem::MmapSlice::anonymous(size)?;
            let ptr = std::ptr::NonNull::new(zero.as_ptr().cast_mut()).ok_or_else(|| {
                VmmError::Config(format!(
                    "anonymous mmap returned null at GPA {:#x}",
                    mapping.gpa()
                ))
            })?;
            Ok((ptr, Some(zero)))
        }
    }
}

fn handle_host_mapping(
    mapping: amla_core::ValidatedMemoryMapping,
    handle_maps: &[amla_mem::MmapSlice],
    index: usize,
    offset: u64,
    offset_usize: usize,
) -> Result<std::ptr::NonNull<u8>> {
    let region = handle_maps
        .get(index)
        .ok_or_else(|| VmmError::Config(format!("handle_maps index {index} out of range")))?;

    // SAFETY: the validated mapping token checked index, offset, size, handle
    // bounds, and writable capability before this host pointer is derived.
    unsafe { region.offset_mut_ptr(offset_usize) }.ok_or_else(|| {
        VmmError::Config(format!(
            "handle offset {offset:#x} out of bounds for mapping at GPA {:#x}",
            mapping.gpa()
        ))
    })
}

fn register_memory_region(
    vm_fd: &VmFd,
    slot: u32,
    mapping: amla_core::ValidatedMemoryMapping,
    host_ptr: std::ptr::NonNull<u8>,
) -> Result<()> {
    let flags = if mapping.readonly() {
        kvm_bindings::KVM_MEM_READONLY
    } else {
        0
    };
    let userspace_addr = u64::try_from(host_ptr.as_ptr().addr())
        .map_err(|_| VmmError::Config("host pointer does not fit in KVM userspace_addr".into()))?;
    let region = kvm_bindings::kvm_userspace_memory_region {
        slot,
        flags,
        guest_phys_addr: mapping.gpa(),
        memory_size: mapping.size(),
        userspace_addr,
    };
    // SAFETY: `region` describes a host userspace range that remains valid
    // for the lifetime of the KVM vm_fd. The caller stores backing mmaps in
    // `Vm::maps` and drops them only after the fd closes.
    unsafe {
        vm_fd.set_user_memory_region(region)?;
    }
    Ok(())
}

fn unregister_memory_region(vm_fd: &VmFd, slot: u32) {
    let empty = kvm_bindings::kvm_userspace_memory_region {
        slot,
        flags: 0,
        guest_phys_addr: 0,
        memory_size: 0,
        userspace_addr: 0,
    };
    // SAFETY: a zero-sized memory region unregisters the slot.
    if let Err(error) = unsafe { vm_fd.set_user_memory_region(empty) } {
        log::warn!("failed to unregister KVM memory slot {slot}: {error}");
    }
}

// ============================================================================
// State save/restore
// ============================================================================

impl Vm {
    /// Restore all VM state from `VmState` to KVM.
    #[allow(clippy::cast_possible_truncation)]
    pub async fn restore_state(&self, view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        let vcpu_count = self.vcpu_count();

        let irqchip_blob = view
            .irqchip()
            .arch_blob()
            .map_err(|e| VmmError::Config(format!("invalid irqchip blob: {e}")))?;
        if irqchip_blob.is_empty() {
            return Err(VmmError::InvalidState {
                expected: "irqchip arch blob written by write_boot_state() or save_state()",
                actual: "missing irqchip arch blob",
            });
        }

        let kvm_state = VmStateSnapshot::from_arch_blob(irqchip_blob)?;
        #[cfg(target_arch = "aarch64")]
        kvm_state.validate_vcpu_count(vcpu_count as usize)?;

        for i in 0..vcpu_count {
            let i_usz = i as usize;
            let snap = view
                .vcpu_slot_as::<VcpuSnapshot>(i_usz)
                .ok_or(VmmError::InvalidState {
                    expected: "valid vcpu index",
                    actual: "out of bounds",
                })?;
            snap.validate()?;
            self.set_vcpu_state(i_usz, snap)?;
        }

        self.restore_vm_state(&kvm_state, None)?;

        // Late-stage verification: dump CPUID leaf 1 EBX + LAPIC APIC ID
        // for each vCPU right before the VM starts running. If the values
        // here disagree with what the guest reads at runtime, the
        // mismatch is inside KVM (or its CPUID runtime override) rather
        // than our setup path.
        #[cfg(target_arch = "x86_64")]
        if log::log_enabled!(log::Level::Debug)
            && let Ok(live) = self.live()
        {
            let shell = &live.shell;
            for (i, vcpu_fd) in shell.vcpus().iter().enumerate() {
                let ebx31_24 = vcpu_fd
                    .get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
                    .ok()
                    .and_then(|cpuid| {
                        cpuid
                            .as_slice()
                            .iter()
                            .find(|e| e.function == 1)
                            .map(|e| e.ebx >> 24)
                    });
                let lapic_id = vcpu_fd.get_lapic().ok().map(|l| {
                    let id_bytes = [
                        l.regs[0x20].cast_unsigned(),
                        l.regs[0x21].cast_unsigned(),
                        l.regs[0x22].cast_unsigned(),
                        l.regs[0x23].cast_unsigned(),
                    ];
                    u32::from_le_bytes(id_bytes) >> 24
                });
                log::debug!(
                    "vCPU {i} pre-run: CPUID leaf1 EBX[31:24]={ebx31_24:?}, LAPIC APIC_ID={lapic_id:?}"
                );
            }
        }

        Ok(())
    }

    /// Save all VM state from KVM to `VmState`.
    ///
    /// Awaits each vCPU's run mutex to ensure no thread is in `KVM_RUN`,
    /// then captures registers + irqchip state. All guards are held until
    /// capture completes — callers must ensure no concurrent `resume()` calls
    /// (guaranteed by `drop(all_vcpus)` in `run()`).
    // Reason: lock guard scope intentionally spans the assertion
    // block to observe a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn save_state(&self, view: &mut amla_core::vm_state::VmState<'_>) -> Result<()> {
        let shell = &self.live()?.shell;
        // Acquire all run mutexes and hold them through state capture.
        // Reason: the `Vec` is never read again, but its job is to keep
        // every vCPU run mutex guard alive until end of scope. Dropping
        // it earlier would release every lock and race vCPU threads.
        #[allow(clippy::collection_is_never_read)]
        let mut guards = Vec::with_capacity(shell.vcpu_count() as usize);
        for i in 0..shell.vcpu_count() {
            guards.push(shell.vcpu_thread(i as usize).run_mutex.lock().await);
        }

        let snapshots = self.capture_all_vcpu_states()?;
        for (i, snap) in snapshots.iter().enumerate() {
            Self::write_vcpu_to_slot(view, i, snap)?;
        }

        let kvm_state = self.capture_vm_state()?;
        let irqchip = view.irqchip_mut();
        irqchip
            .write_arch_blob_with(|blob| kvm_state.write_arch_blob(blob))
            .map_err(|e| VmmError::Config(format!("invalid captured irqchip blob: {e}")))?;
        Ok(())
    }

    /// Write initial boot vCPU state.
    pub async fn write_boot_state(
        &self,
        view: &mut amla_core::vm_state::VmState<'_>,
        boot_result: &amla_boot::BootResult,
    ) -> Result<()> {
        let vcpu_count = self.vcpu_count();
        let bsp = VcpuSnapshot::for_boot(&boot_result.cpu_state);
        Self::write_vcpu_to_slot(view, 0, &bsp)?;
        for i in 1..vcpu_count {
            let i_usz = i as usize;
            let ap = VcpuSnapshot::for_init_received(i_usz)?;
            Self::write_vcpu_to_slot(view, i_usz, &ap)?;
        }
        view.set_boot_psci_power_states();

        let default = self.capture_default_irqchip()?;
        let irqchip = view.irqchip_mut();
        irqchip
            .write_arch_blob_with(|blob| default.write_boot_arch_blob(blob))
            .map_err(|e| VmmError::Config(format!("invalid default irqchip blob: {e}")))?;
        Ok(())
    }

    fn write_vcpu_to_slot(
        view: &mut amla_core::vm_state::VmState<'_>,
        index: usize,
        snapshot: &VcpuSnapshot,
    ) -> Result<()> {
        let slot = view.vcpu_slot_mut(index).ok_or(VmmError::InvalidState {
            expected: "valid vcpu index",
            actual: "out of bounds",
        })?;
        let snap_size = std::mem::size_of::<VcpuSnapshot>();
        assert!(
            slot.len() >= snap_size,
            "vcpu slot {index} too small: {} < {snap_size}",
            slot.len()
        );
        // SAFETY: asserted slot.len() >= snap_size above; source and destination
        // are disjoint (slot is a mutable view, snapshot is an immutable ref).
        unsafe {
            std::ptr::copy_nonoverlapping(
                std::ptr::from_ref(snapshot).cast::<u8>(),
                slot.as_mut_ptr(),
                snap_size,
            );
        }
        Ok(())
    }
}

// ============================================================================
// Internal state helpers (not part of public API)
// ============================================================================

impl Vm {
    fn set_vcpu_state(&self, idx: usize, snapshot: &VcpuSnapshot) -> Result<()> {
        let shell = &self.live()?.shell;
        if idx >= shell.vcpus().len() {
            return Err(VmmError::InvalidState {
                expected: "valid vcpu index",
                actual: "out of bounds",
            });
        }
        snapshot.restore(&shell.vcpus()[idx])
    }

    fn capture_all_vcpu_states(&self) -> Result<Vec<VcpuSnapshot>> {
        let shell = &self.live()?.shell;
        shell
            .vcpus()
            .iter()
            .map(|v| VcpuSnapshot::capture(v))
            .collect()
    }

    fn capture_vm_state(&self) -> Result<VmStateSnapshot> {
        let shell = &self.live()?.shell;
        VmStateSnapshot::capture(
            shell.vm_fd(),
            &shell.initial_device_state,
            shell.vcpus().len(),
        )
    }

    fn restore_vm_state(
        &self,
        state: &VmStateSnapshot,
        clock_offset_ns: Option<u64>,
    ) -> Result<()> {
        let shell = &self.live()?.shell;
        state.restore(shell.vm_fd(), clock_offset_ns, &shell.initial_device_state)
    }

    fn capture_default_irqchip(&self) -> Result<VmStateSnapshot> {
        self.capture_vm_state()
    }
}

// ============================================================================
// IRQ + device waker
// ============================================================================

impl Vm {
    /// Get the VM file descriptor.
    pub fn vm_fd(&self) -> Result<&VmFd> {
        Ok(self.live()?.shell.vm_fd())
    }

    /// Create a resampled IRQ line backed by shell eventfds.
    ///
    /// Returns a crate-private concrete type. External callers should use the
    /// `amla_core::IrqFactory` trait impl, which erases to `Box<dyn IrqLine>`.
    pub(crate) fn create_resampled_irq_line(&self, gsi: u32) -> Result<Box<ShellIrqLine>> {
        let hw = self.live()?.shell.hardware();
        let (efd, rfd, resample_pending) = hw.irq_eventfds(gsi).ok_or(VmmError::InvalidState {
            expected: "shell hardware for GSI",
            actual: "no slot",
        })?;
        Ok(Box::new(ShellIrqLine::new(
            efd.as_raw_fd(),
            rfd.as_raw_fd(),
            resample_pending,
        )))
    }

    /// Create a backend-specific device waker.
    pub async fn create_device_waker(&self) -> Result<Arc<dyn amla_core::DeviceWaker>> {
        self.live()?.shell.hardware().create_device_waker()
    }
}

impl amla_core::IrqFactory for Vm {
    fn create_resampled_irq_line(
        &self,
        gsi: u32,
    ) -> std::result::Result<Box<dyn amla_core::IrqLine>, Box<dyn std::error::Error + Send + Sync>>
    {
        Ok(self.create_resampled_irq_line(gsi)? as Box<dyn amla_core::IrqLine>)
    }
}

// ============================================================================
// Drop
// ============================================================================

impl Drop for Vm {
    fn drop(&mut self) {
        // Drop shell on background thread. Shell::drop joins vCPU threads + closes KVM fds.
        if let Some(live) = self.inner.take() {
            let maps = std::mem::take(&mut self.maps);
            live.pools.drop_shell_retaining(live.shell, maps);
        }
    }
}
