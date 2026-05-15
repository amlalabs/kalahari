// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Linux boot support for vmlinux (ELF) kernels.
//!
//! This module provides everything needed to boot a Linux kernel in 64-bit long mode:
//! - ELF kernel loading (vmlinux format only, not bzImage)
//! - Boot parameters (zero page) with E820 memory map
//! - Identity-mapped page tables using 2MB huge pages
//! - 64-bit GDT with TSS for long mode
//! - MP table for SMP CPU discovery
//! - CPU register setup for `startup_64` entry
//!
//! # SMP Support
//!
//! This module supports multi-processor boot:
//! - MP table lists all CPUs with correct APIC IDs
//! - BSP (CPU 0) is marked as bootstrap processor
//! - APs are woken via SIPI by the kernel (handled by KVM's in-kernel irqchip)
//! - CPUID must be configured per-vCPU (done in shell.rs)
//!
//! # Memory Layout
//!
//! All addresses are physical (identity-mapped). The layout follows Linux boot
//! protocol conventions and avoids conflicts with legacy BIOS areas.
//!
//! ```text
//! Address       Size    Contents
//! ──────────────────────────────────────────────────────────
//! 0x0000_0500   48B     GDT (6 entries including 16-byte TSS)
//! 0x0000_7000   4KB     Zero page (boot_params structure)
//! 0x0000_8000   ~4KB    Initial stack (grows down from here)
//! 0x0000_9000   4KB     PML4 page table
//! 0x0000_a000   4KB     PDPT page table (low memory)
//! 0x0000_b000   16KB    PD page tables (4 tables for 4GB identity map)
//! 0x0000_f000   4KB     PDPT page table (higher-half kernel mapping)
//! 0x0002_0000   64KB    Kernel command line (null-terminated)
//! 0x0009_fc00   ~1KB    MP table (CPU and IOAPIC configuration)
//! 0x000a_0000   384KB   Reserved (legacy VGA/ROM area)
//! 0x0010_0000   varies  Kernel load address (1MB, per Linux boot protocol)
//! ```
//!
//! # Usage
//!
//! ```text
//! use amla_kvm::{boot, VcpuSnapshot};
//! use std::ptr::NonNull;
//!
//! let kernel = std::fs::read("vmlinux")?;
//! // mem_ptr comes from the MemoryNode's BranchedRegion (amla-vmm manages this)
//! let mem = NonNull::new(mem_ptr).unwrap();
//! let mem_size = 256 * 1024 * 1024; // from VmConfig
//! let num_cpus = 1u8;
//!
//! let result = boot::setup_linux_boot(
//!     mem,
//!     mem_size,
//!     &kernel,
//!     "console=ttyS0 init=/bin/guest_agent",
//!     num_cpus,
//! )?;
//!
//! // Set BSP (CPU 0) state for 64-bit entry
//! vm.set_vcpu_state(0, &VcpuSnapshot::for_boot(&result.regs, &result.sregs))?;
//!
//! // APs will be started by the kernel via SIPI
//! ```
//!
//! # SMP Boot Walkthrough (VMM Perspective)
//!
//! Getting SMP boot right requires careful coordination between the VMM, KVM, and Linux.
//! Here's what happens step-by-step:
//!
//! ## 1. VMM Setup (Before First `KVM_RUN`)
//!
//! The VMM must prepare:
//!
//! 1. **Create vCPUs**: Call `KVM_CREATE_VCPU` for each CPU (BSP first, then APs)
//! 2. **Configure CPUID**: Each vCPU needs CPUID with correct initial APIC ID in leaf 0x1 EBX\[31:24\]
//! 3. **MP Table**: Write MP table at 0x9fc00 with entries for all CPUs and I/O APIC
//! 4. **BSP State**: Set CPU 0 to long mode with `KVM_MP_STATE_RUNNABLE`
//! 5. **AP State**: Set CPUs 1+ to `KVM_MP_STATE_INIT_RECEIVED` (NOT `UNINITIALIZED`!)
//!
//! **Critical**: `KVM_MP_STATE_INIT_RECEIVED` (2) means "waiting for SIPI". This makes
//! `KVM_RUN` block until Linux sends a SIPI to wake the AP. Using `UNINITIALIZED` (1)
//! causes `KVM_RUN` to fail immediately, breaking SMP boot.
//!
//! ## 2. Linux Boot (BSP Running)
//!
//! Once BSP starts executing:
//!
//! 1. **Early boot**: Linux parses MP table, discovers N CPUs with APIC IDs 0..N-1
//! 2. **LAPIC init**: BSP initializes its Local APIC
//! 3. **SMP bringup**: For each AP, Linux:
//!    - Writes INIT-SIPI-SIPI sequence to LAPIC ICR
//!    - SIPI contains startup address (trampoline in low memory)
//!    - Waits for AP to respond
//!
//! ## 3. KVM Handling (Automatic with In-Kernel IRQCHIP)
//!
//! With `KVM_CAP_IRQCHIP` enabled, KVM handles LAPIC emulation automatically:
//!
//! - **SIPI interception**: When BSP writes ICR to send SIPI, KVM intercepts it
//! - **AP wakeup**: KVM transitions AP from `INIT_RECEIVED` to `RUNNABLE`
//! - **Entry point**: AP's RIP is set to the SIPI vector * 0x1000 (e.g., vector 0x88 → 0x88000)
//! - **Real mode**: AP starts in real mode (like real hardware SIPI behavior)
//!
//! The VMM doesn't need to handle SIPI—KVM does it all. The AP thread's `KVM_RUN`
//! unblocks automatically when the SIPI arrives.
//!
//! ## 4. AP Startup (Each AP)
//!
//! When AP receives SIPI and `KVM_RUN` unblocks:
//!
//! 1. **Real mode trampoline**: Executes at SIPI vector address (set up by Linux)
//! 2. **Switch to long mode**: Trampoline enables paging, enters 64-bit mode
//! 3. **Join scheduler**: AP registers with Linux scheduler
//! 4. **Idle loop**: AP enters HLT-based idle until given work
//!
//! ## Key Gotchas
//!
//! | Issue | Symptom | Solution |
//! |-------|---------|----------|
//! | Wrong MP state | `KVM_RUN` fails or returns immediately | Use `INIT_RECEIVED` for APs |
//! | Missing MP table | Linux sees only 1 CPU | Ensure MP table is at 0x9fc00 |
//! | APIC ID mismatch | CPUs don't match up | CPUID EBX\[31:24\] must match MP table |
//! | Low memory clobbered | SIPI trampoline fails | Don't overwrite 0x0-0x1000 area |
//! | Thread join blocks | Test hangs after exit | Poll for exit, don't wait for all threads |
//!
//! ## Memory Areas to Preserve
//!
//! Linux's SIPI trampoline uses low memory. The VMM must not place data at:
//! - 0x0000-0x0500: Real mode IVT and BIOS data area
//! - 0x88000-0x90000: Common SIPI trampoline range (varies by kernel)
//!
//! Our layout carefully avoids these: GDT at 0x500, page tables at 0x9000+.
//!
//! # Debugging Guide
//!
//! When SMP boot fails, check these in order:
//!
//! ## 1. Verify vCPU threads are running
//! ```text
//! // Log when each vCPU thread enters KVM_RUN
//! eprintln!("[vCPU {}] entering KVM_RUN with MP state: {:?}", idx, mp_state);
//! ```
//!
//! ## 2. Check MP state is correct
//! ```text
//! // BSP (CPU 0): Must be RUNNABLE (0)
//! // APs (CPU 1+): Must be INIT_RECEIVED (2), NOT UNINITIALIZED (1)!
//! use kvm_bindings::KVM_MP_STATE_INIT_RECEIVED;
//! vcpu.set_mp_state(kvm_mp_state { mp_state: KVM_MP_STATE_INIT_RECEIVED })?;
//! ```
//!
//! ## 3. Verify MP table is visible
//! Add kernel command line: `console=ttyS0 loglevel=8`
//! Look for in serial output:
//! ```text
//! Intel MultiProcessor Specification v1.4
//! MPTABLE: Processors: N  <-- Should match your vCPU count
//! ```
//!
//! ## 4. Check CPUID APIC IDs
//! ```text
//! // Each vCPU's CPUID leaf 0x1 EBX[31:24] must be its APIC ID (0, 1, 2, ...)
//! let cpuid = kvm.get_supported_cpuid()?;
//! for entry in cpuid.iter_mut() {
//!     if entry.function == 0x1 {
//!         entry.ebx = (entry.ebx & 0x00ffffff) | ((vcpu_idx as u32) << 24);
//!     }
//! }
//! vcpu.set_cpuid2(&cpuid)?;
//! ```
//!
//! ## 5. Log `VCpu` exits
//! ```text
//! match vcpu.run()? {
//!     VcpuExit::IoOut { port, data, size } => {
//!         eprintln!("[vCPU {}] IoOut port=0x{:x} size={}", idx, port, size);
//!     }
//!     VcpuExit::Halt => {
//!         eprintln!("[vCPU {}] HLT - waiting for interrupt", idx);
//!     }
//!     exit => eprintln!("[vCPU {}] Exit: {:?}", idx, exit),
//! }
//! ```
//!
//! ## 6. Test thread join behavior
//! When guest exits via debug port (0xF4), other vCPUs may be blocked in HLT.
//! Don't wait forever for all threads—poll for exit code instead:
//! ```text
//! loop {
//!     if exit_code.lock().is_some() {
//!         break; // Got exit code, stop polling
//!     }
//!     std::thread::sleep(Duration::from_millis(100));
//! }
//! ```
//!
//! # Complete SMP Boot Example
//!
//! ```ignore
//! # async fn example() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//! use amla_boot::LinuxBootBuilder;
//! use amla_kvm::{HardwareLayout, Vm, VmPools, VcpuSnapshot, boot};
//! use amla_core::{Vcpu, VcpuExit};
//! use std::ptr::NonNull;
//!
//! // Use 'static pools for thread spawning (4 shells, 4 vCPUs each)
//! let pools: &'static VmPools = Box::leak(Box::new(VmPools::new(4, 4, HardwareLayout::empty())?));
//! let vm = Vm::builder(pools)
//!     .build_shell()
//!     .await?;
//!
//! // Memory is registered via map_memory().
//! let memory_size: usize = 256 * 1024 * 1024;
//! # let mem = NonNull::dangling(); // placeholder
//!
//! // Load kernel into the memory region (amla-boot writes directly to guest memory)
//! let kernel = std::fs::read("vmlinux")?;
//! let boot_result = LinuxBootBuilder::new(mem, memory_size, &kernel)
//!     .cmdline("console=ttyS0 init=/test/smp")
//!     .num_cpus(4)
//!     .build()?;
//!
//! // Convert boot result to KVM registers and set BSP (CPU 0)
//! let (regs, sregs) = boot::x86_boot_state_to_kvm(&boot_result.cpu_state);
//! vm.set_vcpu_state(0, &VcpuSnapshot::for_boot(&regs, &sregs))?;
//!
//! // Set APs (CPUs 1-3) to wait for SIPI
//! for i in 1..4u8 {
//!     vm.set_vcpu_state(i as usize, &VcpuSnapshot::for_init_received(i))?;
//! }
//!
//! // Run vCPU 0 (BSP) - each vCPU would run in its own thread in production
//! let mut vcpu = vm.vcpu(0)?;
//! loop {
//!     match vcpu.run()? {
//!         VcpuExit::Halt => continue,  // Wait for interrupt
//!         VcpuExit::IoOut { port: 0xF4, data, .. } => {
//!             println!("Exit code: {}", data as u8);
//!             break;
//!         }
//!         _ => continue,
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # References
//!
//! - Linux Boot Protocol: Documentation/x86/boot.rst in kernel source
//! - Intel MP Specification 1.4
//! - AMD64 Architecture Programmer's Manual, Volume 2: System Programming
//! - KVM API: Documentation/virt/kvm/api.rst (MP state constants)

mod cpu_state;

pub use cpu_state::x86_boot_state_to_kvm;

pub use amla_boot::x86_64::consts::{IOAPIC_ADDR, LAPIC_ADDR, MPTABLE_START};

#[cfg(test)]
mod tests;
