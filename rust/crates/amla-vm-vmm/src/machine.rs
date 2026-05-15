// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Core `VirtualMachine` type with typestate-enforced lifecycle.
//!
//! # Architecture
//!
//! Memory management is split between two layers:
//! - **`MemHandle`** (amla-mem): Owns the guest RAM backing (memfd/cowtree).
//!   Provides copy-on-write branching for freeze/spawn. No mappings -- just fds.
//! - **`BackendVm`** (backend): Hypervisor management (KVM/HVF/Hyper-V).
//!   Provides VM fd, vCPU fds, pre-registered hardware. `map_memory()` takes
//!   `MemHandle`s, mmaps them internally, and registers hypervisor memory slots.
//!   Returns the mapped regions; the caller stores them.
//!
//! This separation means freeze/spawn is:
//! - **freeze**: await backend close -> keep handles (state already in memfd)
//! - **spawn**: branch handles -> acquire fresh shell -> `map_memory()` -> restore state
//!
//! # Compiler-Enforced Safety
//!
//! - No unconstrained constructors: `create()` (fresh) or `freeze()` -> `spawn()` (zygote)
//! - Transitions consume `self`: can't use a VM after transitioning
//! - Devices are local to `run()`: no `Arc<Device>`, just scoped borrows
//! - `MachineState` is sealed: no external state implementations

#[cfg(not(target_pointer_width = "64"))]
compile_error!("amla-vmm requires a 64-bit target (u64 <-> usize casts assume this)");

use std::sync::Arc;
use std::sync::atomic::AtomicU64;

use amla_core::backends::NetBackend;
use amla_core::{GUEST_PHYS_ADDR, IrqFactory};

/// Monotonically-increasing spawn id, used to tag logs across a VM's lifetime
/// so that interleaved spawn activity (common in zygote tests) is attributable.
static SPAWN_COUNTER: AtomicU64 = AtomicU64::new(0);

const DEVICE_QUIESCE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

use crate::backend::{BackendPools, BackendVm};
use crate::config::{KernelCmdlineAtom, VmConfig, join_cmdline_atoms};
use crate::devices::DeviceLayout;
use crate::error::{ConfigError, DeviceError, Error, Result};
use crate::state::{MachineState, New, Parked, Ready, Zygote};

use crate::run_backends::{
    Backends, SpawnBackends, validate_load_backends, validate_spawn_backends,
};

/// A virtual machine with typestate-enforced lifecycle.
///
/// Type parameter `S` encodes the lifecycle state:
/// - [`New`]: Resources allocated, not yet configured
/// - [`Ready`]: Kernel loaded, devices wired, vCPUs stopped
/// - [`Zygote`]: Frozen template for fast spawning
///
/// Guest memory is stored as `Vec<MemHandle>` (fd-only, no mapping).
/// Mappings are ephemeral -- created at the start of each operation
/// and dropped when it completes. The underlying memfd retains data
/// written through `MAP_SHARED` mappings even after unmap.
pub struct VirtualMachine<S: MachineState> {
    /// Memory handles (fd-only). `handles[0]` is the unified VM-state region,
    /// `handles[1..]` are pmem image handles.
    handles: Vec<amla_mem::MemHandle>,

    /// Cached device layout (O(1) per-kind index lookup).
    device_layout: DeviceLayout,

    /// VM configuration.
    config: VmConfig,

    /// Typestate -- holds lifecycle-specific state.
    state: S,
}

impl<S: MachineState> VirtualMachine<S> {
    /// Get the VM configuration.
    pub const fn config(&self) -> &VmConfig {
        &self.config
    }

    fn validate_load_setup<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        &self,
        pools: &BackendPools,
        backends: &Backends<'_, F, N>,
    ) -> Result<()> {
        validate_load_backends(backends, &self.config)?;
        self.validate_pools(pools)
    }

    fn validate_spawn_setup<F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        &self,
        pools: &BackendPools,
        backends: &SpawnBackends<'_, F, N>,
    ) -> Result<()> {
        validate_spawn_backends(backends, &self.config)?;
        self.validate_pools(pools)
    }

    /// Validate that the backend pool matches this VM's durable layout.
    fn validate_pools(&self, pools: &BackendPools) -> Result<()> {
        if pools.vcpu_count() != self.config.vcpu_count {
            return Err(Error::Config(ConfigError::VcpuCountMismatch {
                pool: pools.vcpu_count() as usize,
                config: self.config.vcpu_count as usize,
            }));
        }
        if pools.device_layout() != &self.device_layout {
            return Err(Error::Config(ConfigError::DeviceLayoutMismatch {
                pool: pools.device_layout().diagnostic_entries(),
                config: self.device_layout.diagnostic_entries(),
            }));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Region initialization helpers (used by `create()`)
// ---------------------------------------------------------------------------

type ShellSetup = (
    Vec<Box<dyn amla_core::IrqLine>>,
    amla_core::vm_state::MappedVmState,
);

/// Register memory with the backend and create IRQ lines.
///
/// Common setup sequence shared by `load_kernel()` and `spawn()`.
/// Returns (`irq_lines`, regions) — caller-side mmaps for `VmState` access.
async fn setup_shell(
    shell: &mut BackendVm,
    handles: &[amla_mem::MemHandle],
    config: &VmConfig,
    device_layout: &DeviceLayout,
) -> Result<ShellSetup> {
    let (unified_handle, image_handles) = handles.split_first().ok_or_else(|| {
        Error::Core(amla_core::VmmError::DeviceConfig(
            "setup_shell: no unified handle".into(),
        ))
    })?;

    // Compute memory layout from VmState.
    let tmp_mappings = amla_core::vm_state::MappedVmState::new(
        amla_mem::map_handle(unified_handle)?,
        GUEST_PHYS_ADDR,
    )?;
    let view = tmp_mappings.view()?;
    let durable_device_layout = DeviceLayout::from_vm_state(&view)?;
    if &durable_device_layout != device_layout {
        return Err(Error::Core(amla_core::VmmError::DeviceConfig(format!(
            "carried device layout {:?} does not match durable device layout {:?}",
            device_layout.diagnostic_entries(),
            durable_device_layout.diagnostic_entries()
        ))));
    }
    crate::devices::validate_durable_device_state(&view, device_layout)?;
    let image_sizes: Vec<u64> = config
        .pmem_disks
        .iter()
        .flat_map(|d| d.images.iter().map(|img| img.image_size))
        .collect();
    let mappings = view.memory_mappings(&image_sizes)?;
    drop(view);
    drop(tmp_mappings);

    // Register memory with backend (backend creates its own internal mmaps).
    let all_handles: Vec<&amla_mem::MemHandle> = handles.iter().collect();
    shell.map_memory(&all_handles, &mappings).await?;

    // Create caller-side mmaps for VmState access (MAP_SHARED = same pages).
    let unified_region = amla_mem::map_handle(unified_handle)?;
    let extra_regions: Vec<amla_mem::MmapSlice> = image_handles
        .iter()
        .map(|h| amla_mem::map_handle(h).map_err(crate::error::Error::from))
        .collect::<Result<_>>()?;
    let regions = amla_core::vm_state::MappedVmState::with_pmem_images(
        unified_region,
        extra_regions,
        GUEST_PHYS_ADDR,
    )?;

    let irq_lines = {
        let irq_factory: &dyn IrqFactory = &*shell;
        crate::devices::create_irq_lines(irq_factory, &durable_device_layout)?
    };
    Ok((irq_lines, regions))
}

async fn close_shell_after_failed_operation(
    shell: BackendVm,
    operation: &'static str,
    source: Error,
) -> Error {
    match shell.close().await {
        Ok(_) => source,
        Err(close) => Error::VmOperationFailedAndBackendCloseFailed {
            operation,
            source: Box::new(source),
            close: Box::new(close),
        },
    }
}

async fn close_ready_parts_after_failed_operation(
    irq_lines: Vec<Box<dyn amla_core::IrqLine>>,
    shell: BackendVm,
    regions: amla_core::vm_state::MappedVmState,
    operation: &'static str,
    source: Error,
) -> Error {
    drop(irq_lines);
    let error = close_shell_after_failed_operation(shell, operation, source).await;
    drop(regions);
    error
}

fn ring_setup_error(reason: impl std::fmt::Display) -> Error {
    Error::Core(amla_core::VmmError::DeviceConfig(format!(
        "agent ring setup failed: {reason}"
    )))
}

fn ring_buffer_ptr(
    region: &amla_mem::MmapSlice,
    header: &amla_core::vm_state::VmStateHeader,
) -> Result<std::ptr::NonNull<u8>> {
    let offset = usize::try_from(header.ring_offset).map_err(|_| {
        ring_setup_error(format!(
            "ring offset {:#x} does not fit host address space",
            header.ring_offset
        ))
    })?;
    let ring_size = usize::try_from(header.ring_size).map_err(|_| {
        ring_setup_error(format!(
            "ring size {:#x} does not fit host address space",
            header.ring_size
        ))
    })?;
    let expected_size = amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE;
    if ring_size < expected_size {
        return Err(ring_setup_error(format!(
            "ring size {:#x} is smaller than required {expected_size:#x}",
            header.ring_size
        )));
    }
    let declared_end = offset.checked_add(ring_size).ok_or_else(|| {
        ring_setup_error(format!(
            "ring offset {:#x} + declared size {:#x} overflows host address space",
            header.ring_offset, header.ring_size
        ))
    })?;
    if declared_end > region.len() {
        return Err(ring_setup_error(format!(
            "declared ring range [{:#x}..{declared_end:#x}) exceeds unified region size {:#x}",
            header.ring_offset,
            region.len()
        )));
    }
    // SAFETY: `validate_layout` proved the ring range is in-bounds and
    // `machine::create` is initializing the ring before exposing it to any
    // device or guest vCPU.
    let ptr = unsafe { region.offset_mut_ptr(offset) }.ok_or_else(|| {
        ring_setup_error(format!(
            "ring offset {:#x} is outside the unified region",
            header.ring_offset
        ))
    })?;
    let align = std::mem::align_of::<amla_vm_ringbuf::HostGuestRingBuffer>();
    if !ptr.as_ptr().addr().is_multiple_of(align) {
        return Err(ring_setup_error(format!(
            "ring pointer {:#x} is not {align}-byte aligned",
            ptr.as_ptr().addr()
        )));
    }
    Ok(ptr)
}

fn init_ring_buffer(
    region: &amla_mem::MmapSlice,
    header: &amla_core::vm_state::VmStateHeader,
) -> Result<()> {
    let nn = ring_buffer_ptr(region, header)?;
    // SAFETY:
    // - `ring_buffer_ptr` verified `nn` points to at least
    //   `HostGuestRingBuffer::TOTAL_SIZE` bytes inside `region`.
    // - `ring_buffer_ptr` verified 64-byte alignment.
    // - `region` outlives this statement; the returned handle is not
    //   stored.
    // - SPSC: this is the one-shot initializer, called from `create()`
    //   before any other host or guest code touches the ring.
    let _ready = unsafe {
        amla_vm_ringbuf::HostGuestRingBufferHandle::attach(
            nn,
            amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE,
        )
    }
    .map_err(|e| ring_setup_error(format!("attach ring for init: {e}")))?
    .init();
    Ok(())
}

/// Write the initial Setup message into the ring buffer at create time.
///
/// The guest agent blocks until it reads Setup from the HG ring. Writing it
/// during `create()` means `run()` never needs to re-send it — the message
/// is already queued before the guest boots. For spawned VMs (from Zygote),
/// the Setup was consumed during the original boot and the guest agent is
/// already initialized, so no re-send is needed.
fn write_setup_message(
    region: &amla_mem::MmapSlice,
    header: &amla_core::vm_state::VmStateHeader,
    config: &VmConfig,
    device_layout: &DeviceLayout,
) -> Result<()> {
    let nn = ring_buffer_ptr(region, header)?;
    // SAFETY:
    // - `ring_buffer_ptr` verified `nn` points to at least
    //   `HostGuestRingBuffer::TOTAL_SIZE` bytes inside `region`.
    // - `ring_buffer_ptr` verified 64-byte alignment.
    // - `region` outlives `ring`; `ring` is dropped at end of scope.
    // - SPSC: called from `create()` after `init_ring_buffer`, before the
    //   guest is started. No other host writer exists yet, so the single-
    //   writer invariant for the host->guest direction holds.
    let ready = unsafe {
        amla_vm_ringbuf::HostGuestRingBufferHandle::attach(
            nn,
            amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE,
        )
    }
    .map_err(|e| ring_setup_error(format!("attach ring for Setup: {e}")))?
    .validate()
    .map_err(|e| ring_setup_error(format!("validate ring for Setup: {e}")))?;
    let endpoints = ready.split_host();
    let setup = amla_constants::protocol::AgentSetup {
        mounts: crate::devices::build_mount_ops(config, device_layout)?,
    };
    let msg = amla_constants::protocol::HostMessage::Setup(setup);
    let payload = postcard::to_allocvec(&msg)
        .map_err(|e| ring_setup_error(format!("serialize Setup: {e}")))?;
    match endpoints.to_guest.try_write(&payload) {
        Ok(true) => Ok(()),
        Ok(false) => Err(ring_setup_error("write Setup to ring: ring full")),
        Err(e) => Err(ring_setup_error(format!("write Setup to ring: {e}"))),
    }
}

fn build_cmdline(config: &VmConfig, device_layout: &DeviceLayout, ring_gpa: u64) -> Result<String> {
    // Boot tracing: set `AMLA_BOOT_TRACE=1` to drop `quiet`, enable
    // `initcall_debug` (every driver _init() logged with µs timing), and
    // `no_hash_pointers` (readable pointer values, so probe logs correlate).
    let trace = std::env::var_os("AMLA_BOOT_TRACE").is_some_and(|v| v != "0" && !v.is_empty());

    #[cfg(target_arch = "aarch64")]
    let mut atoms = vec![
        KernelCmdlineAtom::generated("earlycon")?,
        KernelCmdlineAtom::generated("console=hvc0")?,
        KernelCmdlineAtom::generated("printk.time=1")?,
    ];
    #[cfg(target_arch = "aarch64")]
    if trace {
        atoms.push(KernelCmdlineAtom::generated("initcall_debug")?);
        atoms.push(KernelCmdlineAtom::generated("no_hash_pointers")?);
    } else {
        atoms.push(KernelCmdlineAtom::generated("quiet")?);
    }
    // `rootwait` retries `mount_root` if the root blockdev isn't ready yet.
    // Under 2-vCPU fresh boot we hit a race where `kernel_init_freeable`
    // calls `wait_for_device_probe()` before virtio-pmem has registered
    // its probe, so the wait returns immediately, then `prepare_namespace`
    // can't find `/dev/pmem0` and panics. `rootwait` makes it poll until
    // the device appears. (Single-vCPU boot probed synchronously on CPU 0
    // and never hit this.)
    #[cfg(target_arch = "aarch64")]
    {
        atoms.push(KernelCmdlineAtom::generated("iomem=relaxed")?);
        atoms.push(KernelCmdlineAtom::generated("rootwait")?);
        atoms.push(KernelCmdlineAtom::generated("init=/bin/amla-guest")?);
    }

    #[cfg(not(target_arch = "aarch64"))]
    let mut atoms = vec![
        KernelCmdlineAtom::generated("console=hvc0")?,
        KernelCmdlineAtom::generated("printk.time=1")?,
        KernelCmdlineAtom::generated("oops=panic")?,
        KernelCmdlineAtom::generated("nopat")?,
    ];
    #[cfg(not(target_arch = "aarch64"))]
    if trace {
        atoms.push(KernelCmdlineAtom::generated("initcall_debug")?);
        atoms.push(KernelCmdlineAtom::generated("no_hash_pointers")?);
    } else {
        atoms.push(KernelCmdlineAtom::generated("quiet")?);
    }
    // x86: route the kernel console through virtio-console (hvc0) — same
    // transport as aarch64. The virtio-console device is always present
    // in the device layout, so the `virtio_mmio.device=...` fragment
    // appended below makes the kernel find it before userspace starts.
    // Early-boot messages (before virtio init) are still captured in the
    // printk buffer and visible via `dmesg` once the guest is up.
    #[cfg(not(target_arch = "aarch64"))]
    {
        atoms.push(KernelCmdlineAtom::generated("init=/bin/amla-guest")?);
    }

    atoms.extend(crate::devices::build_cmdline_fragment(
        config,
        device_layout,
    )?);
    atoms.push(KernelCmdlineAtom::generated(format!(
        "amla_ring={ring_gpa:#x}"
    ))?);
    atoms.extend(config.cmdline_extra.iter().cloned());
    Ok(join_cmdline_atoms(&atoms))
}

impl VirtualMachine<New> {
    /// Create a new VM in the New state.
    ///
    /// Allocates a unified region (header + ring buffer + guest RAM).
    /// Pool validation is deferred to `load_kernel()`.
    pub async fn create(config: VmConfig) -> Result<Self> {
        config.validate()?;
        let ram_size = (config.memory_mb * 1024 * 1024) as u64;
        let device_layout = DeviceLayout::from_config(&config)?;
        let data_sizes = config.pmem_data_sizes()?;
        let image_counts: Vec<u32> = config
            .pmem_disks
            .iter()
            .enumerate()
            .map(|(disk_index, d)| {
                u32::try_from(d.images.len()).map_err(|_| {
                    Error::Config(ConfigError::PmemDiskSizeInvalid {
                        disk_index,
                        size: u64::MAX,
                        reason: String::from("image count exceeds u32::MAX"),
                    })
                })
            })
            .collect::<Result<_>>()?;
        let mut header = amla_core::vm_state::VmStateHeader::compute(
            config.vcpu_count,
            device_layout.len() as u32,
            ram_size,
            &data_sizes,
            &image_counts,
        )
        .ok_or_else(|| {
            Error::Config(ConfigError::GpaLayoutOverflow {
                vcpu_count: config.vcpu_count as usize,
                device_count: device_layout.len(),
            })
        })?;
        device_layout.write_header(&mut header);

        let handle =
            amla_mem::MemHandle::allocate(c"amla-vm-unified", header.total_size() as usize)?;
        let mut region = amla_mem::map_handle(&handle)?;

        amla_core::vm_state::VmState::init_region(&mut region, header)?;
        let mappings = {
            let mappings = amla_core::vm_state::MappedVmState::new(region, GUEST_PHYS_ADDR)?;
            let mut vm_state = mappings.view()?;
            crate::devices::init_device_state(&config, &device_layout, &mut vm_state)?;
            drop(vm_state);
            mappings
        };
        init_ring_buffer(mappings.unified(), &header)?;
        write_setup_message(mappings.unified(), &header, &config, &device_layout)?;
        drop(mappings);

        Ok(Self {
            handles: vec![handle],
            device_layout,
            config,
            state: New,
        })
    }
    /// Load a kernel, acquire shell, and transition to Ready state.
    #[allow(clippy::too_many_lines)]
    pub async fn load_kernel<'a, F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        self,
        pools: &BackendPools,
        kernel: &[u8],
        backends: Backends<'a, F, N>,
    ) -> Result<VirtualMachine<Ready<'a, F, N>>> {
        self.validate_load_setup(pools, &backends)?;
        let Backends {
            console: console_backend,
            net: net_backend,
            fs: fs_backend,
            pmem: pmem_images,
        } = backends;

        // Destructure self -- load_kernel consumes the VM.
        let Self {
            mut handles,
            device_layout,
            config,
            state: _,
        } = self;

        // Combine the unified VM-state handle with pmem image handles.
        // handles[0] = unified VM-state region, handles[1..] = pmem images.
        handles.extend(pmem_images);

        // Temporarily map the unified region to write kernel + boot state.
        // This mmap is dropped before shell setup -- the backend creates its
        // own independent mmap from the same memfd in map_memory().
        let boot_result = {
            let tmp_mappings = amla_core::vm_state::MappedVmState::new(
                amla_mem::map_handle(&handles[0])?,
                GUEST_PHYS_ADDR,
            )?;
            let view = tmp_mappings.view()?;

            let ring_gpa = view.ring_gpa()?;
            let cmdline = build_cmdline(&config, &device_layout, ring_gpa)?;

            // Step 1: Load kernel into guest memory.
            #[cfg(target_arch = "aarch64")]
            let virtio_devs: Vec<amla_boot::VirtioMmioDtbDevice> = device_layout
                .kinds()
                .iter()
                .enumerate()
                .map(|(i, _)| -> Result<amla_boot::VirtioMmioDtbDevice> {
                    let base = amla_virtio_mmio::device_mmio_addr(i);
                    let irq = crate::devices::arm64_device_irq(i).map_err(|e| {
                        Error::Config(ConfigError::IrqAllocation {
                            reason: e.to_string(),
                        })
                    })?;
                    Ok(amla_boot::VirtioMmioDtbDevice {
                        base,
                        spi: irq.spi(),
                    })
                })
                .collect::<Result<_>>()?;

            #[cfg(not(target_arch = "aarch64"))]
            let virtio_devs: Vec<(u64, u32)> = device_layout
                .kinds()
                .iter()
                .enumerate()
                .map(|(i, _)| {
                    let base = amla_virtio_mmio::device_mmio_addr(i);
                    let gsi = amla_virtio_mmio::device_gsi(i);
                    (base, gsi)
                })
                .collect();
            let extra_mem = [(ring_gpa, view.header().ring_size)];

            #[cfg(target_arch = "x86_64")]
            let boot_builder = {
                // SAFETY: this temporary MAP_SHARED mapping is used exclusively
                // for boot setup in this block; the backend's independent mmap is
                // created only after the boot writes complete.
                let boot_mem = unsafe {
                    amla_boot::BootGuestMemory::from_vm_state(&view, tmp_mappings.unified())
                }
                .map_err(|e| Error::Config(ConfigError::BootSetup(e)))?;
                amla_boot::LinuxBootBuilder::new(boot_mem, kernel)
            };

            #[cfg(target_arch = "aarch64")]
            let boot_builder = {
                // SAFETY: this temporary MAP_SHARED mapping is used exclusively
                // for boot setup in this block; the backend's independent mmap is
                // created only after the boot writes complete.
                let boot_mem = unsafe {
                    amla_boot::BootGuestMemory::from_vm_state(&view, tmp_mappings.unified())
                }
                .map_err(|e| Error::Config(ConfigError::BootSetup(e)))?;
                amla_boot::LinuxBootBuilder::new(boot_mem, kernel)
            };

            // tmp_mappings drops at block end — writes persist via MAP_SHARED.
            boot_builder
                .cmdline(&cmdline)
                .num_cpus(config.vcpu_count as usize)
                .virtio_devices(&virtio_devs)
                .extra_memory(&extra_mem)
                .build()
                .map_err(|e| Error::Config(ConfigError::BootSetup(e)))?
        };

        // Acquire shell, map memory, write boot state, restore state.
        let mut shell = BackendVm::build(pools).await?;
        let (irq_lines, regions) = match setup_shell(&mut shell, &handles, &config, &device_layout)
            .await
        {
            Ok(setup) => setup,
            Err(error) => {
                return Err(
                    close_shell_after_failed_operation(shell, "load_kernel setup", error).await,
                );
            }
        };

        // Write boot state into the mapped regions (shared memory).
        // State is restored to the backend later, in run().
        let boot_state_result = async {
            let mut vm_state = regions.view()?;
            shell.write_boot_state(&mut vm_state, &boot_result).await
        }
        .await;
        if let Err(error) = boot_state_result {
            return Err(close_ready_parts_after_failed_operation(
                irq_lines,
                shell,
                regions,
                "load_kernel boot state",
                error,
            )
            .await);
        }

        // Extract serial console for PIO forwarding.
        let serial_console = console_backend.clone_writer();

        Ok(VirtualMachine {
            handles,
            device_layout,
            config,
            state: Ready {
                irq_lines,
                shell,
                regions,
                console: console_backend,
                net: net_backend,
                fs: fs_backend,
                serial_console,
            },
        })
    }
}

/// Borrowed state passed from [`VirtualMachine::run`] to [`VirtualMachine::run_inner`].
///
/// Bundled so `run_inner` takes three arguments (shell, ctx, user closure)
/// instead of eleven. All fields are borrowed for the `'s` lifetime of the
/// surrounding `run()` call.
struct RunInnerCtx<'s, F: amla_fuse::fuse::FsBackend, N: NetBackend> {
    regions: &'s amla_core::vm_state::MappedVmState,
    console: &'s dyn amla_core::backends::ConsoleBackend,
    fs: Option<&'s F>,
    net: Option<&'s N>,
    irq_lines: &'s [Box<dyn amla_core::IrqLine>],
    device_layout: &'s DeviceLayout,
    serial_console: Option<&'s dyn amla_core::backends::ConsoleBackend>,
    t0: std::time::Instant,
}

struct RunCancellationGuard<'s> {
    shell: &'s BackendVm,
    end: Arc<crate::shared_state::VmEnd>,
    vcpu_count: u32,
    active: bool,
}

impl RunCancellationGuard<'_> {
    const fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for RunCancellationGuard<'_> {
    fn drop(&mut self) {
        if !self.active {
            return;
        }

        self.end.stop();
        for i in 0..self.vcpu_count {
            self.shell.preempt_vcpu(amla_core::VcpuId(i));
        }
    }
}

impl<'a, F: amla_fuse::fuse::FsBackend, N: NetBackend> VirtualMachine<Ready<'a, F, N>> {
    /// Freeze the VM into a frozen template for fast spawning.
    ///
    /// Await backend teardown, then freeze the VM into a zygote template.
    ///
    /// State is already in the mmap from the last `run()` exit. This transition
    /// consumes all live backend resources and does not expose a `Zygote` until
    /// backend-owned writable mappings have been closed.
    pub async fn freeze(self) -> Result<VirtualMachine<Zygote>> {
        let VirtualMachine {
            handles,
            device_layout,
            config,
            state,
        } = self;
        let Ready {
            irq_lines,
            shell,
            regions,
            console: _,
            net: _,
            fs: _,
            serial_console: _serial_console,
        } = state;

        // IRQ lines own backend fds and must be dropped before closing the shell.
        drop(irq_lines);
        let backend_closed = shell.close().await?;
        drop(regions);

        Ok(VirtualMachine {
            handles,
            device_layout,
            config,
            state: Zygote::new(backend_closed),
        })
    }

    /// Park this VM by closing its backend shell while keeping the same memory
    /// handles for a later resume.
    ///
    /// This is the scheduler-friendly transition: guest/device state remains
    /// in the mmap-backed VM state, but no hypervisor VM, vCPU, memory slot, or
    /// IRQ line remains live after this future resolves.
    pub async fn park(self) -> Result<VirtualMachine<Parked>> {
        let VirtualMachine {
            handles,
            device_layout,
            config,
            state,
        } = self;
        let Ready {
            irq_lines,
            shell,
            regions,
            console: _,
            net: _,
            fs: _,
            serial_console: _serial_console,
        } = state;

        drop(irq_lines);
        let backend_closed = shell.close().await?;
        drop(regions);

        Ok(VirtualMachine {
            handles,
            device_layout,
            config,
            state: Parked::new(backend_closed),
        })
    }

    /// Run VM with async control handle.
    ///
    /// Device objects are created as locals and dropped when this returns.
    /// Shell, IRQ lines, and backends are persistent on `self.state`.
    /// vCPU threads are managed by the backend via `shell.resume()`.
    ///
    /// This consumes the healthy Ready VM and returns it only after guest state
    /// has been saved back into its memory snapshot. If `run()` fails, the VM is
    /// consumed and dropped, so a failed/partially torn-down VM cannot be
    /// frozen into a zygote.
    pub async fn run<Fn, R>(self, f: Fn) -> Result<(VirtualMachine<Ready<'a, F, N>>, R)>
    where
        Fn: AsyncFnOnce(crate::agent::VmHandle<'_, crate::agent::Paused>) -> R,
    {
        let VirtualMachine {
            handles,
            device_layout,
            config,
            mut state,
        } = self;
        let t0 = std::time::Instant::now();

        let run_result = Self::run_inner(
            &mut state.shell,
            RunInnerCtx {
                regions: &state.regions,
                console: state.console,
                fs: state.fs,
                net: state.net,
                irq_lines: &state.irq_lines,
                device_layout: &device_layout,
                serial_console: state.serial_console.as_deref(),
                t0,
            },
            f,
        )
        .await;

        let run_result = match run_result {
            Ok(run_result) => run_result,
            Err(run_error) => {
                return Err(Self::close_after_run_error(state, run_error).await);
            }
        };

        Ok((
            VirtualMachine {
                handles,
                device_layout,
                config,
                state,
            },
            run_result,
        ))
    }

    async fn close_after_run_error(state: Ready<'a, F, N>, run_error: Error) -> Error {
        let Ready {
            irq_lines,
            shell,
            regions,
            console: _,
            net: _,
            fs: _,
            serial_console: _,
        } = state;

        drop(irq_lines);
        let close_result = shell.close().await;
        drop(regions);

        match close_result {
            Ok(_) => run_error,
            Err(close_error) => Error::VmOperationFailedAndBackendCloseFailed {
                operation: "run",
                source: Box::new(run_error),
                close: Box::new(close_error),
            },
        }
    }

    // Reason: BackendVm's methods take `&self` and use interior mutability
    // (e.g. mutexes around the actual KVM/HVF shell). The borrow checker
    // can't see those mutations through the trait object, but the unique
    // `&mut` borrow is the correct architectural ownership signal.
    #[allow(clippy::needless_pass_by_ref_mut, clippy::too_many_lines)]
    async fn run_inner<'s, Fn, R>(
        shell: &'s mut BackendVm,
        ctx: RunInnerCtx<'s, F, N>,
        f: Fn,
    ) -> Result<R>
    where
        Fn: AsyncFnOnce(crate::agent::VmHandle<'_, crate::agent::Paused>) -> R,
    {
        let RunInnerCtx {
            regions,
            console,
            fs,
            net,
            irq_lines,
            device_layout,
            serial_console,
            t0,
        } = ctx;
        // Create device objects -- local, dropped when run() returns.
        let t_devices = std::time::Instant::now();

        let vm_state_for_devices = regions.view()?;
        let device_output = crate::devices::create_devices(
            console,
            fs,
            net,
            irq_lines,
            device_layout,
            &vm_state_for_devices,
        )?;
        log::trace!("[run] create_devices={:?}", t_devices.elapsed());
        let crate::devices::DeviceOutput {
            devices,
            agent_ring,
            agent_link,
            console_wake,
            net_rx_notify,
            rx_registrations: _rx_registrations,
        } = device_output;

        // Restore state from mmap -> KVM (after device config writes).
        let t1 = std::time::Instant::now();
        {
            let mut vm_state = regions.view()?;
            shell.restore_state(&mut vm_state).await?;
        }
        log::trace!("[run] state_restore={:?}", t1.elapsed());

        // Create backend-specific device waker.
        let waker: Arc<dyn amla_core::DeviceWaker> = shell.create_device_waker().await?;
        let queue_wakes = crate::devices::QueueWakeMap::new(device_layout)?;

        let console_notify = Some(crate::device_waker::DeviceNotify {
            wake_indices: queue_wakes
                .device_wake_indices(device_layout.console.index())
                .collect(),
            wake: Arc::clone(&console_wake),
            pending: Some(agent_link.host_pending()),
        });
        let net_notify = device_layout.net.zip(net_rx_notify).map(
            |(slot, crate::devices::NetRxNotify { wake, pending })| {
                crate::device_waker::DeviceNotify {
                    wake_indices: queue_wakes.device_wake_indices(slot.index()).collect(),
                    wake,
                    pending: Some(pending),
                }
            },
        );
        let agent_ring = crate::device::RingDevice::new(agent_ring);

        let serial_console =
            serial_console.and_then(amla_core::backends::ConsoleBackend::clone_writer);

        crate::devices::force_kick_all(&devices, &queue_wakes, &*waker);

        let vm_end = Arc::new(crate::shared_state::VmEnd::new());

        let vm_status = Arc::new(crate::shared_state::VmStatus::new());
        let start_gate = Arc::new(crate::shared_state::StartGate::new());
        agent_link.set_vm_status(Arc::clone(&vm_status));
        let exec_channels = agent_link.connect();

        // Run vcpu_run_loops as async futures.
        let serial_ref = serial_console
            .as_ref()
            .map(|c| c.as_ref() as &dyn amla_core::backends::ConsoleBackend);
        let vcpu_count = shell.vcpu_count();
        let vcpu_count_usz = vcpu_count as usize;
        let (cpu_on_bus, cpu_on_rxs) = crate::vcpu_loop::CpuOnBus::new(
            vcpu_count_usz,
            vm_state_for_devices.psci_power_states(),
        );
        let mut vcpu_futs = Vec::with_capacity(vcpu_count_usz);
        let vcpu_ctx = crate::vcpu_loop::VcpuLoopCtx {
            shell,
            devices: &devices,
            waker: &*waker as &dyn amla_core::DeviceWaker,
            queue_wakes: &queue_wakes,
            serial: serial_ref,
            end: &vm_end,
            cpu_on_bus: &cpu_on_bus,
        };
        for (i, rx) in (0..vcpu_count).zip(cpu_on_rxs) {
            vcpu_futs.push(crate::vcpu_loop::vcpu_run_loop(
                vcpu_ctx,
                amla_core::VcpuId(i),
                rx,
            ));
        }
        let mut all_vcpus = Box::pin(futures_util::future::join_all(vcpu_futs));

        let fs_wake = crate::device_waker::FsWake::new();
        let device_fut = crate::device_waker::device_loop(
            &*waker,
            &devices,
            &queue_wakes,
            &agent_ring,
            console_notify,
            net_notify,
            fs_wake.clone(),
            Arc::clone(&vm_end),
        );
        tokio::pin!(device_fut);
        let fs_fut = crate::device_waker::fs_worker_loop(&devices, fs_wake, Arc::clone(&vm_end));
        tokio::pin!(fs_fut);

        let vm_handle = crate::agent::VmHandle::new(
            exec_channels,
            Arc::clone(&vm_status),
            Arc::clone(&agent_link),
            Arc::clone(&start_gate),
        );

        // Run user closure + device loop, racing against vCPU exit.
        //
        // The discriminator is `vm_end.outcome()`: each vCPU reports its
        // terminal reason at the exit site (Fatal | Reboot | CleanShutdown),
        // and `run()` returns Err iff any vCPU reported Fatal. `shutdown_
        // requested` is no longer load-bearing for correctness; it stays a
        // host→guest signal.
        let user_fut = f(vm_handle);
        tokio::pin!(user_fut);
        // If the outer `run()` future is cancelled, this guard is dropped
        // before `all_vcpus` and preempts any in-flight `resume()` futures.
        let mut cancel_guard = RunCancellationGuard {
            shell,
            end: Arc::clone(&vm_end),
            vcpu_count,
            active: true,
        };
        let mut vcpus_exited = false;
        let mut device_exited = false;
        let mut fs_exited = false;
        let mut vm_started = false;
        let mut device_quiesce = crate::device_waker::QuiesceResult::Quiescent;

        let user_result: Result<R> = loop {
            tokio::select! {
                () = start_gate.wait_started(), if !vm_started => {
                    vm_started = true;
                    // Kick console after start: Setup was written to the ring
                    // at create() time, and future run cycles may inherit
                    // host-to-guest ring bytes whose previous doorbell was
                    // lost with the old backend. A spurious kick is harmless.
                    agent_ring.kick_peer();
                    agent_link.notify_host();
                }
                _ = &mut all_vcpus, if vm_started && !vcpus_exited => {
                    vcpus_exited = true;
                    vm_status.set_exited();
                    if vm_end.outcome() == Some(crate::shared_state::VmOutcome::Fatal) {
                        // Fatal vCPU exit — tear down and surface the error
                        // without waiting for the user closure.
                        agent_link.close_run_channels();
                        vm_end.stop();
                        if !device_exited {
                            device_quiesce = (&mut device_fut).await;
                        }
                        if !fs_exited {
                            match tokio::time::timeout(DEVICE_QUIESCE_TIMEOUT, &mut fs_fut).await {
                                Ok(()) => {}
                                Err(_) => {
                                    log::warn!(
                                        "virtio-fs did not quiesce within {DEVICE_QUIESCE_TIMEOUT:?} after fatal vCPU exit",
                                    );
                                }
                            }
                        }
                        break Err(Error::VcpuExitedEarly);
                    }
                    // CleanShutdown | Reboot | None — let the user closure
                    // finish (its wait_for_exit() resolves on set_exited).
                }
                r = &mut user_fut => {
                    vm_status.set_exited();
                    agent_link.close_run_channels();
                    vm_end.stop();
                    let was_started = vm_started || start_gate.is_started();
                    if was_started {
                        if !vcpus_exited { (&mut all_vcpus).await; }
                        if !device_exited {
                            device_quiesce = (&mut device_fut).await;
                        }
                        if !fs_exited {
                            tokio::time::timeout(DEVICE_QUIESCE_TIMEOUT, &mut fs_fut)
                                .await
                                .map_err(|_| {
                                    Error::Device(DeviceError::QuiesceTimeout {
                                        device: "virtio-fs",
                                        timeout_ms: DEVICE_QUIESCE_TIMEOUT.as_millis() as u64,
                                    })
                                })?;
                        }
                    }
                    // A vCPU may have reported Fatal before or after the
                    // user closure returned; either way, it's captured in
                    // outcome() and dominates a successful user return.
                    if vm_end.outcome() == Some(crate::shared_state::VmOutcome::Fatal) {
                        break Err(Error::VcpuExitedEarly);
                    }
                    break Ok(r);
                }
                quiesce = &mut device_fut, if vm_started && !device_exited => {
                    // device_loop returns when vm_end signals stop. With
                    // >1 vCPU, a vCPU-initiated report() can land here
                    // before all_vcpus finishes joining peers. Mark the
                    // arm consumed and loop back — the all_vcpus arm will
                    // fire as the remaining vCPUs exit, and it discriminates
                    // clean-vs-fatal from vm_end.outcome().
                    device_quiesce = quiesce;
                    device_exited = true;
                }
                () = &mut fs_fut, if vm_started && !fs_exited => {
                    fs_exited = true;
                }
            }
        };

        log::trace!("[run] total_run={:?}", t0.elapsed());

        let user_result = user_result?;
        device_quiesce.into_result()?;
        agent_ring.assert_snapshot_quiescent()?;
        cancel_guard.disarm();
        drop(cancel_guard);

        // Save vCPU + irqchip state from KVM to mmap.
        {
            let mut vm_state = regions.view()?;
            shell.save_state(&mut vm_state).await?;
        }

        Ok(user_result)
    }
}

impl VirtualMachine<Zygote> {
    /// Spawn a new VM from this zygote template.
    ///
    /// Creates a `CoW` branch of all memory handles, acquires a shell,
    /// maps memory, creates IRQ lines, and restores state.
    pub async fn spawn<'b, F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        &self,
        pools: &BackendPools,
        backends: SpawnBackends<'b, F, N>,
    ) -> Result<VirtualMachine<Ready<'b, F, N>>> {
        let spawn_id = SPAWN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        log::info!(
            "spawn#{spawn_id}: begin (parent_handles={}, vcpu_count={}, devices={})",
            self.handles.len(),
            self.config.vcpu_count,
            self.device_layout.len(),
        );
        self.validate_spawn_setup(pools, &backends)?;
        let SpawnBackends {
            console: console_backend,
            net: net_backend,
            fs: fs_backend,
        } = backends;

        // Branch all memory handles (CoW -- unified VM-state + pmem images).
        //
        // SAFETY: `Zygote` has no running vCPUs while spawning. The branched
        // handles are mapped into a fresh backend shell below, so no stale
        // writable mappings from the parent backend are reused by the child.
        let child_handles: Vec<amla_mem::MemHandle> = unsafe {
            self.handles
                .iter()
                .map(|handle| handle.branch())
                .collect::<amla_mem::error::Result<Vec<_>>>()?
        };
        log::info!(
            "spawn#{spawn_id}: branched {} handles (CoW from zygote)",
            child_handles.len()
        );

        let mut shell = BackendVm::build(pools).await?;
        log::info!("spawn#{spawn_id}: acquired shell");
        let (irq_lines, regions) = match setup_shell(
            &mut shell,
            &child_handles,
            &self.config,
            &self.device_layout,
        )
        .await
        {
            Ok(setup) => setup,
            Err(error) => {
                return Err(close_shell_after_failed_operation(shell, "spawn setup", error).await);
            }
        };
        log::info!(
            "spawn#{spawn_id}: shell set up (irq_lines={}, regions={})",
            irq_lines.len(),
            regions.mapping_count()
        );

        // State is restored to the backend later, in run().
        // The zygote's vCPU + GIC state lives in the CoW mmap and
        // is pushed to the worker at the start of each run() call.

        let serial_console = console_backend.clone_writer();

        Ok(VirtualMachine {
            handles: child_handles,
            device_layout: self.device_layout.clone(),
            config: self.config.clone(),
            state: Ready {
                irq_lines,
                shell,
                regions,
                console: console_backend,
                net: net_backend,
                fs: fs_backend,
                serial_console,
            },
        })
    }
}

impl VirtualMachine<Parked> {
    /// Resume this parked VM in a fresh backend shell.
    ///
    /// The same guest memory handles are moved into `Ready`; no `CoW` branch is
    /// created. Use [`VirtualMachine<Zygote>::spawn`] when the intent is to
    /// clone a frozen template.
    pub async fn resume<'b, F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        self,
        pools: &BackendPools,
        backends: SpawnBackends<'b, F, N>,
    ) -> std::result::Result<VirtualMachine<Ready<'b, F, N>>, ResumeParkedError> {
        self.resume_inner(pools, backends).await
    }

    async fn resume_inner<'b, F: amla_fuse::fuse::FsBackend, N: NetBackend>(
        self,
        pools: &BackendPools,
        backends: SpawnBackends<'b, F, N>,
    ) -> std::result::Result<VirtualMachine<Ready<'b, F, N>>, ResumeParkedError> {
        if let Err(error) = self.validate_spawn_setup(pools, &backends) {
            return Err(ResumeParkedError::from_recoverable(self, error));
        }
        let SpawnBackends {
            console: console_backend,
            net: net_backend,
            fs: fs_backend,
        } = backends;

        let mut shell = match BackendVm::build(pools).await {
            Ok(shell) => shell,
            Err(error) => return Err(ResumeParkedError::from_recoverable(self, error)),
        };

        let setup = setup_shell(&mut shell, &self.handles, &self.config, &self.device_layout).await;
        let (irq_lines, regions) = match setup {
            Ok(setup) => setup,
            Err(error) => {
                return match shell.close().await {
                    Ok(_) => Err(ResumeParkedError::from_recoverable(self, error)),
                    Err(close_error) => Err(ResumeParkedError::fatal(
                        Error::VmOperationFailedAndBackendCloseFailed {
                            operation: "resume setup",
                            source: Box::new(error),
                            close: Box::new(close_error),
                        },
                    )),
                };
            }
        };
        let serial_console = console_backend.clone_writer();

        let Self {
            handles,
            device_layout,
            config,
            state: _,
        } = self;

        Ok(VirtualMachine {
            handles,
            device_layout,
            config,
            state: Ready {
                irq_lines,
                shell,
                regions,
                console: console_backend,
                net: net_backend,
                fs: fs_backend,
                serial_console,
            },
        })
    }
}

/// Error returned when resuming a parked VM fails before ownership of the
/// parked VM should be discarded.
pub struct ResumeParkedError {
    vm: Option<VirtualMachine<Parked>>,
    error: Error,
}

impl ResumeParkedError {
    pub(crate) const fn from_recoverable(vm: VirtualMachine<Parked>, error: Error) -> Self {
        Self {
            vm: Some(vm),
            error,
        }
    }

    const fn fatal(error: Error) -> Self {
        Self { vm: None, error }
    }

    /// Borrow the underlying resume error.
    pub const fn error(&self) -> &Error {
        &self.error
    }

    /// Split into the still-parked VM, when recovery is safe, and the error
    /// that prevented resume.
    pub fn into_parts(self) -> (Option<VirtualMachine<Parked>>, Error) {
        (self.vm, self.error)
    }

    /// Discard the parked VM and return only the resume error.
    pub fn into_error(self) -> Error {
        self.error
    }
}

impl std::fmt::Debug for ResumeParkedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResumeParkedError")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ResumeParkedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to resume parked VM: {}", self.error)
    }
}

impl std::error::Error for ResumeParkedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

// SAFETY (Send):
// - `New` is a unit struct. `Parked` and `Zygote` carry only private
//   backend-closed proof tokens with no live backend resources; the `Send`
//   impls are straightforward (only needed
//   because `VirtualMachine<S>` wraps other fields that the compiler can't
//   auto-derive across generics).
// - `Ready<'a, F, N>` holds: `Vec<Box<dyn IrqLine>>` (IrqLine is `Send`), `BackendVm`
//   (hypervisor handle; backend crates document `Send`), `Vec<MmapSlice>`
//   (mmap'd pages are safe to migrate across threads on Unix/Windows),
//   `&'a dyn ConsoleBackend`, `&'a N: NetBackend`, `&'a F: FsBackend` (backend traits
//   require `Sync`, so `&T` is `Send`), and `Option<Box<dyn ConsoleBackend>>`.
//   Every field is `Send`; the lifetime parameter does not affect `Send`.
//
// SAFETY (Sync):
// - `Parked` and `Zygote` carry only private backend-closed proof tokens;
//   sharing references to them is thread-safe because no live backend shell or
//   host mmap view is present.
// - `New` and `Ready<'a>` intentionally do NOT implement `Sync`: `Ready`
//   owns hypervisor fds and per-vCPU state that are Send (ownership transfer)
//   but not Sync (no interior-mutability guarantees across shared refs).
//   Callers must move the machine between threads, not share references.
// SAFETY: see `SAFETY (Send)` block above.
unsafe impl Send for VirtualMachine<New> {}
// SAFETY: see `SAFETY (Send)` block above.
unsafe impl<F: amla_fuse::fuse::FsBackend, N: NetBackend> Send for VirtualMachine<Ready<'_, F, N>> {}
// SAFETY: see `SAFETY (Send)` block above.
unsafe impl Send for VirtualMachine<Parked> {}
// SAFETY: see `SAFETY (Send)` block above.
unsafe impl Send for VirtualMachine<Zygote> {}
// SAFETY: see `SAFETY (Sync)` block above — only shell-free states are Sync;
// `New`/`Ready` intentionally omit Sync.
unsafe impl Sync for VirtualMachine<Parked> {}
// SAFETY: see `SAFETY (Sync)` block above.
unsafe impl Sync for VirtualMachine<Zygote> {}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn test_region_and_header() -> (amla_mem::MmapSlice, amla_core::vm_state::VmStateHeader) {
        let region = amla_core::vm_state::test_mmap(amla_core::MIN_MEMORY_MB * 1024 * 1024);
        let mappings = amla_core::vm_state::MappedVmState::new(region, GUEST_PHYS_ADDR).unwrap();
        let view = mappings.view().unwrap();
        let header = *view.header();
        drop(view);
        let region = mappings.into_unified();
        (region, header)
    }

    fn corrupt_first_device_meta_kind(handle: &amla_mem::MemHandle) {
        let mappings = amla_core::vm_state::MappedVmState::new(
            amla_mem::map_handle(handle).unwrap(),
            GUEST_PHYS_ADDR,
        )
        .unwrap();
        let view = mappings.view().unwrap();
        let offset = view.header().device_meta_offset as usize;
        drop(view);
        let mut region = mappings.into_unified();
        // SAFETY: this test mutates durable metadata before constructing the
        // backend shell view that must reject it.
        unsafe {
            region.as_mut_slice()[offset] = amla_core::vm_state::DEVICE_KIND_NET;
        }
    }

    #[test]
    fn setup_message_fails_if_ring_was_not_initialized() {
        let (region, header) = test_region_and_header();
        let config = VmConfig::default();
        let device_layout = DeviceLayout::from_config(&config).unwrap();

        let err = write_setup_message(&region, &header, &config, &device_layout).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("agent ring setup failed"), "{msg}");
        assert!(msg.contains("validate ring for Setup"), "{msg}");
    }

    #[test]
    fn ring_setup_rejects_too_small_ring_size() {
        let (region, mut header) = test_region_and_header();
        header.ring_size = (amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE - 1) as u64;

        let err = init_ring_buffer(&region, &header).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("agent ring setup failed"), "{msg}");
        assert!(msg.contains("smaller than required"), "{msg}");
    }

    #[test]
    fn ring_setup_rejects_ring_range_outside_region() {
        let (region, mut header) = test_region_and_header();
        header.ring_offset = (region.len() - 64) as u64;
        header.ring_size = amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE as u64;

        let err = init_ring_buffer(&region, &header).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("agent ring setup failed"), "{msg}");
        assert!(msg.contains("exceeds unified region size"), "{msg}");
    }

    #[tokio::test]
    async fn pool_validation_rejects_same_kinds_different_queue_counts() {
        let vm_config =
            VmConfig::default().net(crate::config::NetConfig::default().queue_pairs(1).unwrap());
        let pool_config =
            VmConfig::default().net(crate::config::NetConfig::default().queue_pairs(3).unwrap());

        let vm = VirtualMachine::create(vm_config).await.unwrap();
        let pools = BackendPools::new(
            1,
            &pool_config,
            amla_core::WorkerProcessConfig::path("unused-test-worker"),
        )
        .unwrap();

        let err = vm.validate_pools(&pools).unwrap_err();
        let Error::Config(ConfigError::DeviceLayoutMismatch { pool, config }) = err else {
            panic!("expected DeviceLayoutMismatch");
        };
        assert_eq!(
            pool.iter().map(|(kind, _)| *kind).collect::<Vec<_>>(),
            config.iter().map(|(kind, _)| *kind).collect::<Vec<_>>()
        );
        assert_ne!(pool, config);
    }

    #[tokio::test]
    async fn run_error_closes_backend_explicitly() {
        let config = VmConfig::default();
        let vm = VirtualMachine::create(config.clone()).await.unwrap();
        let pools = BackendPools::new(
            1,
            &config,
            amla_core::WorkerProcessConfig::path("unused-test-worker"),
        )
        .unwrap();

        let VirtualMachine {
            handles,
            device_layout,
            config,
            state: _,
        } = vm;
        let mut shell = BackendVm::build(&pools).await.unwrap();
        let (irq_lines, regions) = setup_shell(&mut shell, &handles, &config, &device_layout)
            .await
            .unwrap();

        {
            let view = regions.view().unwrap();
            // SAFETY: this unit test intentionally corrupts the ring bytes
            // before `run()` creates the sole host ring owner.
            let ring = unsafe { view.ring_buffer_hva() }.unwrap();
            // SAFETY: `ring_buffer_hva` points at the initialized ring range;
            // zeroing the header makes the later validation fail.
            unsafe {
                ring.as_ptr().write_bytes(0, 64);
            }
        }

        let console = crate::console_stream::ConsoleStream::new();
        let ready_vm: VirtualMachine<Ready<'_, amla_fuse::NullFsBackend>> = VirtualMachine {
            handles,
            device_layout,
            config,
            state: Ready {
                irq_lines,
                shell,
                regions,
                console: &console,
                net: None,
                fs: None,
                serial_console: None,
            },
        };

        let result = ready_vm.run(async |_vm| ()).await;
        let err = result.err().expect("corrupt ring must fail run()");
        let msg = err.to_string();
        assert!(msg.contains("agent ring validation"), "{msg}");
        assert_eq!(pools.closed_shell_count(), 1);
    }

    #[tokio::test]
    async fn spawn_setup_error_closes_backend_explicitly() {
        let config = VmConfig::default();
        let vm = VirtualMachine::create(config.clone()).await.unwrap();
        let pools = BackendPools::new(
            1,
            &config,
            amla_core::WorkerProcessConfig::path("unused-test-worker"),
        )
        .unwrap();

        let VirtualMachine {
            handles,
            device_layout,
            config,
            state: _,
        } = vm;
        corrupt_first_device_meta_kind(&handles[0]);
        let zygote = VirtualMachine {
            handles,
            device_layout,
            config,
            state: Zygote::new(crate::state::BackendClosed::new()),
        };

        let console = crate::console_stream::ConsoleStream::new();
        let result = zygote
            .spawn(
                &pools,
                SpawnBackends {
                    console: &console,
                    net: Option::<&amla_core::backends::NullNetBackend>::None,
                    fs: Option::<&amla_fuse::NullFsBackend>::None,
                },
            )
            .await;
        let err = result.err().expect("corrupt metadata must fail spawn");
        let msg = err.to_string();
        assert!(msg.contains("device metadata"), "{msg}");
        assert_eq!(pools.closed_shell_count(), 1);
    }

    #[tokio::test]
    async fn parked_vm_resumes_with_same_handles_after_backend_close() {
        let config = VmConfig::default();
        let vm = VirtualMachine::create(config.clone()).await.unwrap();
        let pools = BackendPools::new(
            1,
            &config,
            amla_core::WorkerProcessConfig::path("unused-test-worker"),
        )
        .unwrap();

        let VirtualMachine {
            handles,
            device_layout,
            config,
            state: _,
        } = vm;
        let mut shell = BackendVm::build(&pools).await.unwrap();
        let (irq_lines, regions) = setup_shell(&mut shell, &handles, &config, &device_layout)
            .await
            .unwrap();
        let console = crate::console_stream::ConsoleStream::new();
        let ready_vm: VirtualMachine<Ready<'_, amla_fuse::NullFsBackend>> = VirtualMachine {
            handles,
            device_layout,
            config,
            state: Ready {
                irq_lines,
                shell,
                regions,
                console: &console,
                net: None,
                fs: None,
                serial_console: None,
            },
        };

        let parked = ready_vm.park().await.unwrap();
        assert_eq!(pools.closed_shell_count(), 1);

        let resumed = parked
            .resume(
                &pools,
                SpawnBackends {
                    console: &console,
                    net: Option::<&amla_core::backends::NullNetBackend>::None,
                    fs: Option::<&amla_fuse::NullFsBackend>::None,
                },
            )
            .await
            .unwrap();
        assert_eq!(resumed.config().vcpu_count, 1);
    }

    #[test]
    fn setup_message_writes_after_ring_init() {
        let (region, header) = test_region_and_header();
        let config = VmConfig::default();
        let device_layout = DeviceLayout::from_config(&config).unwrap();

        init_ring_buffer(&region, &header).unwrap();
        write_setup_message(&region, &header, &config, &device_layout).unwrap();

        let ring_ptr = ring_buffer_ptr(&region, &header).unwrap();
        // SAFETY: `ring_buffer_ptr` validated size and alignment for this region.
        let ready = unsafe {
            amla_vm_ringbuf::HostGuestRingBufferHandle::attach(
                ring_ptr,
                amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE,
            )
        }
        .unwrap()
        .validate()
        .unwrap();
        let mut guest = ready.split_guest();
        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("Setup should be queued on the host-to-guest ring");
        let msg: amla_constants::protocol::HostMessage = postcard::from_bytes(payload).unwrap();
        assert_eq!(
            msg,
            amla_constants::protocol::HostMessage::Setup(amla_constants::protocol::AgentSetup {
                mounts: crate::devices::build_mount_ops(&config, &device_layout).unwrap(),
            })
        );
        guest.from_host.advance().unwrap();
        assert!(guest.from_host.try_peek().unwrap().is_none());
    }
}
