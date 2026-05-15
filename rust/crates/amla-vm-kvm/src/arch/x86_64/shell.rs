// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` KVM VM and vCPU setup/reset.
//!
//! Handles architecture-specific VM initialization (TSS, identity map, irqchip,
//! PIT) and per-vCPU CPUID configuration.

use kvm_bindings::{KVM_PIT_SPEAKER_DUMMY, kvm_pit_config};
use kvm_ioctls::{Kvm, VcpuFd, VmFd};

use crate::error::{Result, VmmError};

/// Architecture-specific state returned by `setup_vcpus`.
/// On x86, this is unit — no state needs to be threaded through.
pub type ArchSetupState = ();

/// Initial device state captured after shell creation (`x86_64`).
///
/// On `x86_64`, no per-shell state needs to be threaded through — the irqchip
/// and PIT are created by `setup_vm` and their state is captured/restored
/// via `VmStateSnapshot`. This struct exists for arch parity with ARM64
/// (which stores the GIC `DeviceFd` here).
#[derive(Clone)]
pub struct InitialDeviceState;

impl std::fmt::Debug for InitialDeviceState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InitialDeviceState").finish()
    }
}

/// Capture initial device state after VM and vCPU creation.
///
/// On `x86_64`, this is a no-op — the irqchip/PIT state is managed via
/// `VmStateSnapshot` save/restore, not through this struct.
#[allow(clippy::unnecessary_wraps)] // signature must match ARM64 variant
pub const fn capture_initial_state(
    _vm_fd: &VmFd,
    _vcpus: &[VcpuFd],
    _arch_state: ArchSetupState,
) -> Result<InitialDeviceState> {
    Ok(InitialDeviceState)
}

/// Set up `x86_64` VM-level KVM devices.
///
/// Configures:
/// - TSS address and identity map (required for Intel real mode emulation)
/// - In-kernel irqchip (PIC master/slave + IOAPIC + per-vCPU LAPIC)
/// - PIT timer (8254) with speaker dummy mode
pub fn setup_vm(vm_fd: &VmFd) -> Result<()> {
    // Set up TSS and identity map (required for Intel real mode)
    vm_fd.set_tss_address(0xfffb_d000)?;
    vm_fd.set_identity_map_address(0xfffb_c000)?;

    // Create in-kernel irqchip (PIC + IOAPIC + LAPIC)
    vm_fd.create_irq_chip()?;

    // Create PIT (timer)
    vm_fd.create_pit2(kvm_pit_config {
        flags: KVM_PIT_SPEAKER_DUMMY,
        ..Default::default()
    })?;

    Ok(())
}

/// Set up CPUID for all vCPUs.
///
/// Gets the host-supported CPUID and applies it to each vCPU with the
/// correct APIC ID in CPUID leaves 0x1 (EBX[31:24]), 0xB and 0x1F (EDX).
/// This must match the MP table and LAPIC configuration for Linux to
/// recognize all CPUs without "APIC ID mismatch" warnings.
#[allow(clippy::too_many_lines)]
pub fn setup_vcpus(kvm: &Kvm, _vm_fd: &VmFd, vcpus: &[VcpuFd]) -> Result<ArchSetupState> {
    let supported = kvm
        .get_supported_cpuid(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        .map_err(|e| VmmError::SystemCall {
            operation: "get_supported_cpuid",
            source: std::io::Error::other(e.to_string()),
        })?;

    // Rebuild CPUID with synthesized valid leaf 0xB sub-leaves.
    //
    // KVM_GET_SUPPORTED_CPUID returns leaf 0xB sub-leaf 0 with
    // `ecx=0` (INVALID level type) and `ebx=0`, so Linux rejects it
    // and falls back to leaf 1 EBX[31:24] for initial_apicid. At that
    // point KVM's runtime CPUID override for EBX[31:24] appears to
    // return 0 for AP vCPUs despite our patched value, producing
    // "APIC ID mismatch. CPUID: 0x0000 APIC: 0x0001". Providing a
    // valid leaf 0xB (SMT + Core + terminator) makes Linux pick
    // `initial_apicid = sl.x2apic_id` from leaf 0xB EDX, which we
    // patch per-vCPU below — short-circuiting the broken fallback.
    let vcpu_count = u32::try_from(vcpus.len()).map_err(|_| VmmError::SystemCall {
        operation: "vCPU count to u32",
        source: std::io::Error::other("too many vCPUs"),
    })?;
    let core_shift = if vcpu_count <= 1 {
        0
    } else {
        vcpu_count.next_power_of_two().trailing_zeros()
    };

    let mut entries: Vec<kvm_bindings::kvm_cpuid_entry2> = supported
        .as_slice()
        .iter()
        .filter(|e| e.function != 0xB && e.function != 0x1F)
        .copied()
        .collect();

    // Leaf 0xB sub-leaf 0 — SMT level: 1 thread per core (no SMT).
    entries.push(kvm_bindings::kvm_cpuid_entry2 {
        function: 0xB,
        index: 0,
        flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        eax: 0,           // shift bits to next level = 0 (1 thread)
        ebx: 1,           // 1 logical processor at this level
        ecx: 0x0000_0100, // level=0, type=1 (SMT)
        edx: 0,           // x2APIC ID — patched per-vCPU below
        ..Default::default()
    });
    // Leaf 0xB sub-leaf 1 — Core level: all vCPUs per package.
    entries.push(kvm_bindings::kvm_cpuid_entry2 {
        function: 0xB,
        index: 1,
        flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        eax: core_shift,
        ebx: vcpu_count,
        ecx: 0x0000_0201, // level=1, type=2 (Core)
        edx: 0,           // patched per-vCPU below
        ..Default::default()
    });
    // Leaf 0xB sub-leaf 2 — terminator (type=0 signals end of list).
    entries.push(kvm_bindings::kvm_cpuid_entry2 {
        function: 0xB,
        index: 2,
        flags: kvm_bindings::KVM_CPUID_FLAG_SIGNIFCANT_INDEX,
        eax: 0,
        ebx: 0,
        ecx: 0x0000_0002, // level=2, type=0 (INVALID terminator)
        edx: 0,
        ..Default::default()
    });

    let mut cpuid =
        kvm_bindings::CpuId::from_entries(&entries).map_err(|e| VmmError::SystemCall {
            operation: "CpuId::from_entries",
            source: std::io::Error::other(format!("{e:?}")),
        })?;

    if log::log_enabled!(log::Level::Debug) {
        log::debug!("CPUID (synthesized): {} entries", cpuid.as_slice().len());
        for e in cpuid.as_slice() {
            if matches!(e.function, 0x1 | 0xB | 0x1F) {
                log::debug!(
                    "  leaf {:#x} idx={:#x}: eax={:#010x} ebx={:#010x} ecx={:#010x} edx={:#010x}",
                    e.function,
                    e.index,
                    e.eax,
                    e.ebx,
                    e.ecx,
                    e.edx
                );
            }
        }
    }

    for (i, vcpu_fd) in vcpus.iter().enumerate() {
        // Set APIC ID for this vCPU across all CPUID leaves that report it.
        // vCPU index bounded by pool limits (well under u32::MAX)
        let apic_id = u32::try_from(i).map_err(|_| VmmError::SystemCall {
            operation: "vCPU index to APIC ID",
            source: std::io::Error::other("vCPU index exceeds u32"),
        })?;

        // Leaf 0xB EDX is the primary source — Linux reads `initial_apicid`
        // from there once the level type is valid, which our synthesis
        // above guarantees. The leaf 1 EBX and leaf 0x1F EDX patches are
        // belt-and-suspenders: leaf 0x1F is currently absent on this host,
        // and observation shows KVM dynamically overrides leaf 1 EBX[31:24]
        // at emulation time anyway. Keeping the patches costs nothing and
        // preserves correctness if KVM's override policy changes.
        for entry in cpuid.as_mut_slice() {
            match entry.function {
                1 => {
                    // EBX bits [31:24] = Initial APIC ID
                    entry.ebx = (entry.ebx & 0x00FF_FFFF) | (apic_id << 24);
                }
                0xB | 0x1F => {
                    // Extended Topology / V2 Extended Topology: EDX = x2APIC ID.
                    entry.edx = apic_id;
                }
                _ => {}
            }
        }

        // Apply CPUID to this vCPU
        vcpu_fd
            .set_cpuid2(&cpuid)
            .map_err(|e| VmmError::SystemCall {
                operation: "set_cpuid",
                source: std::io::Error::other(e.to_string()),
            })?;

        // Verification: read back what KVM actually has for leaf 1 EBX.
        // KVM may override EBX[31:24] from `kvm_apic_id()` (the LAPIC ID
        // register) at runtime, so this confirms what the guest will
        // observe via CPUID at vcpu setup time.
        if log::log_enabled!(log::Level::Debug)
            && let Ok(stored) = vcpu_fd.get_cpuid2(kvm_bindings::KVM_MAX_CPUID_ENTRIES)
        {
            for e in stored.as_slice() {
                if e.function == 1 {
                    log::debug!(
                        "vCPU {i} after set_cpuid2: leaf 1 EBX={:#010x} (APIC ID={:#04x}, expected {:#04x})",
                        e.ebx,
                        e.ebx >> 24,
                        apic_id,
                    );
                }
            }
        }
    }

    Ok(())
}
