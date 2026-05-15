// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` vCPU and VM state snapshot types.
//!
//! Contains all architecture-specific register snapshot structures and their
//! capture/restore logic, plus the wire format serialization helpers for
//! `VmStateSnapshot` (PIC, IOAPIC, PIT, clock).
//!
//! # Endianness
//!
//! Snapshot serialization uses `ptr::copy_nonoverlapping` (raw memcpy).
//! This produces a native-endian (little-endian on `x86_64`) wire format.
//! Cross-architecture snapshot restore is not supported — snapshots are
//! only valid on the same architecture and ABI they were captured on.

use amla_core::x86_64::{MpState, SNAPSHOT_MSRS, msr};
use kvm_bindings::{
    KVM_IRQCHIP_IOAPIC, KVM_IRQCHIP_PIC_MASTER, KVM_IRQCHIP_PIC_SLAVE,
    KVM_VCPUEVENT_VALID_NMI_PENDING, KVM_VCPUEVENT_VALID_SHADOW, KVM_VCPUEVENT_VALID_SMM, Msrs,
    kvm_clock_data, kvm_debugregs, kvm_fpu, kvm_irqchip, kvm_lapic_state, kvm_msr_entry,
    kvm_pit_state2, kvm_regs, kvm_sregs, kvm_vcpu_events, kvm_xcrs, kvm_xsave,
};
use kvm_ioctls::VmFd;

use crate::error::{Result, VmmError};

/// Maximum number of MSRs we support in a snapshot.
pub const MAX_SNAPSHOT_MSRS: usize = 32;

/// Magic prefix for the `x86_64` arch blob wire format. "AKX1" = Amla KVM x86.
const ARCH_BLOB_MAGIC: [u8; 4] = *b"AKX1";

/// Arch blob format version. Bump for ANY layout change to the serialized
/// fields (new field, reordering, or a `kvm_bindings` struct growing because of
/// a new kernel). Same size across kernels is not the same as same layout.
const ARCH_BLOB_VERSION: u32 = 2;

const ARCH_BLOB_HAS_CLOCK: u32 = 1 << 0;
const ARCH_BLOB_KNOWN_FLAGS: u32 = ARCH_BLOB_HAS_CLOCK;

/// Bytes occupied by the magic + version + flags header.
const ARCH_BLOB_HEADER_SIZE: usize = 12;

// Compile-time check: SNAPSHOT_MSRS list + room for vendor-specific MSRs
// (currently 1: `MSR_K7_HWCR` on AMD) must fit in the fixed-size array.
const _: () = assert!(SNAPSHOT_MSRS.len() < MAX_SNAPSHOT_MSRS);

/// True if the host CPU is AMD or Hygon (which inherited AMD's MSR layout).
///
/// AMD family >= 0x11 with `CONSTANT_TSC` requires `MSR_K7_HWCR` bit 24
/// (`TscFreqSel`) to be set, otherwise the guest kernel warns
/// `[Firmware Bug] TSC doesn't count with P0 frequency!`. The MSR is
/// AMD/Hygon-specific; Intel KVM rejects `SET_MSRS` for it.
fn host_is_amd_family() -> bool {
    const AMD_EBX: u32 = u32::from_le_bytes(*b"Auth");
    const AMD_EDX: u32 = u32::from_le_bytes(*b"enti");
    const AMD_ECX: u32 = u32::from_le_bytes(*b"cAMD");
    const HYGON_EBX: u32 = u32::from_le_bytes(*b"Hygo");
    const HYGON_EDX: u32 = u32::from_le_bytes(*b"nGen");
    const HYGON_ECX: u32 = u32::from_le_bytes(*b"uine");
    // `__cpuid` is safe on any x86_64 CPU (and this file is gated to
    // target_arch = "x86_64"); leaf 0 is the vendor-string leaf and is
    // unconditionally available.
    let cpuid = std::arch::x86_64::__cpuid(0);
    (cpuid.ebx == AMD_EBX && cpuid.edx == AMD_EDX && cpuid.ecx == AMD_ECX)
        || (cpuid.ebx == HYGON_EBX && cpuid.edx == HYGON_EDX && cpuid.ecx == HYGON_ECX)
}

// XSAVE region size in u32 units (4096 bytes = 1024 u32s)
const XSAVE_REGION_SIZE: usize = 1024;

const VCPU_EVENTS_VALID_DEFAULT: u32 =
    KVM_VCPUEVENT_VALID_NMI_PENDING | KVM_VCPUEVENT_VALID_SHADOW | KVM_VCPUEVENT_VALID_SMM;

const SNAPSHOT_HAS_XCRS: u32 = 1 << 0;
const SNAPSHOT_HAS_XSAVE: u32 = 1 << 1;
const SNAPSHOT_HAS_DEBUGREGS: u32 = 1 << 2;
const SNAPSHOT_HAS_VCPU_EVENTS: u32 = 1 << 3;
const SNAPSHOT_KNOWN_FLAGS: u32 =
    SNAPSHOT_HAS_XCRS | SNAPSHOT_HAS_XSAVE | SNAPSHOT_HAS_DEBUGREGS | SNAPSHOT_HAS_VCPU_EVENTS;
const SNAPSHOT_CAPTURED_FLAGS: u32 = SNAPSHOT_KNOWN_FLAGS;

/// Snapshot of vCPU register state for suspend/resume and zygote spawning.
///
/// Captures all CPU state needed to save and restore a vCPU:
/// - General purpose registers (rax, rsp, rip, etc.)
/// - Segment registers (cs, ds, etc.) and control registers (cr0, cr3, cr4, efer)
/// - FPU/SSE/AVX state
/// - Local APIC state (for interrupt delivery)
/// - Model Specific Registers (TSC, syscall entry points, segment bases)
/// - MP state (critical for SMP - see below)
///
/// # MP State (Multi-Processor State)
///
/// The `mp_state` field is critical for SMP boot. KVM MP states:
///
/// | State | Value | Meaning | When to use |
/// |-------|-------|---------|-------------|
/// | `RUNNABLE` | 0 | vCPU can execute | BSP after boot setup |
/// | `UNINITIALIZED` | 1 | Not yet initialized | Never use for APs! |
/// | `INIT_RECEIVED` | 2 | Got INIT, waiting SIPI | APs before boot |
/// | `HALTED` | 3 | Executed HLT | After HLT instruction |
/// | `SIPI_RECEIVED` | 4 | Got SIPI, ready to run | Set by KVM automatically |
///
/// **Important**: For APs use `INIT_RECEIVED` (2), not `UNINITIALIZED` (1).
/// `UNINITIALIZED` causes `KVM_RUN` to fail immediately. `INIT_RECEIVED` makes
/// `KVM_RUN` block inside the kernel until the BSP sends a SIPI.
///
/// # Representation
///
/// This struct uses `#[repr(C)]` to ensure stable memory layout for raw
/// serialization during cross-process transfer. The layout must not change
/// between compilations.
#[derive(Clone, Copy)]
#[repr(C)]
pub struct VcpuSnapshot {
    /// General purpose registers (rax, rbx, ..., rsp, rip, rflags)
    pub regs: kvm_regs,
    /// Segment registers (cs, ds, ...) and control registers (cr0, cr3, cr4, efer)
    pub sregs: kvm_sregs,
    /// x87 FPU, SSE, and AVX state (legacy 512-byte area)
    pub fpu: kvm_fpu,
    /// Local APIC state (interrupt controller per-CPU)
    pub lapic: kvm_lapic_state,
    /// Extended Control Registers (XCR0 for XSAVE/XRSTOR)
    pub xcrs: kvm_xcrs,
    /// Debug registers (DR0-DR7) for hardware breakpoints/watchpoints
    pub debugregs: kvm_debugregs,
    /// Extended XSAVE state region (4096 bytes - AVX, AVX-512, MPX, PKRU, etc.)
    /// Stored as fixed array since `kvm_xsave` has a flexible array member.
    pub xsave_region: [u32; XSAVE_REGION_SIZE],
    /// Pending vCPU events (exceptions, interrupts, NMI state)
    /// Critical for capturing in-flight interrupt delivery.
    pub vcpu_events: kvm_vcpu_events,
    /// Model Specific Registers (TSC, SYSENTER, SYSCALL, segment bases, etc.)
    pub msrs: [kvm_msr_entry; MAX_SNAPSHOT_MSRS],
    /// Number of valid MSR entries in the msrs array
    pub msr_count: u32,
    /// MP state: RUNNABLE(0), UNINITIALIZED(1), `INIT_RECEIVED(2)`, HALTED(3)
    /// See struct docs for when to use each state.
    pub mp_state: u32,
    /// Presence flags for optional KVM state captured from a running vCPU.
    ///
    /// Boot seed snapshots intentionally leave these clear so first boot does
    /// not pretend to restore state that was never captured. Real captured
    /// snapshots set every supported bit and restore failures are fatal.
    pub snapshot_flags: u32,
    /// Explicit padding to keep the struct free of trailing padding.
    #[allow(clippy::pub_underscore_fields)]
    pub _pad_snapshot_flags: u32,
}

// SAFETY: VcpuSnapshot is #[repr(C)] with Copy. All kvm-bindings fields are
// #[repr(C)], Copy, contain only fixed-size numerics with explicit padding
// fields. The compile-time assertions below verify the layout has no implicit
// padding gaps, proving Pod soundness.
unsafe impl bytemuck::Zeroable for VcpuSnapshot {}
// SAFETY: see `Zeroable` impl above — all fields are `repr(C)` Pod with no
// implicit padding; the type is safe to transmute to/from bytes.
unsafe impl bytemuck::Pod for VcpuSnapshot {}

// Bindgen-version guard: Pod soundness for VcpuSnapshot requires each
// underlying kvm-bindings type to be gap-free. Hard-code the sizes we
// validated against so a kvm-bindings upgrade that grows any of these
// types is a compile error, not silent UB.
const _: () = assert!(std::mem::size_of::<kvm_fpu>() == 416);
const _: () = assert!(std::mem::size_of::<kvm_lapic_state>() == 1024);
const _: () = assert!(std::mem::size_of::<kvm_vcpu_events>() == 64);

// Compile-time layout assertions: prove that #[repr(C)] packs the fields
// contiguously with no implicit padding. These guarantee the Pod
// implementation is sound across compiler versions and kvm-bindings updates.
const _: () = {
    use std::mem::{offset_of, size_of};

    // Each field starts immediately after the previous one.
    assert!(offset_of!(VcpuSnapshot, regs) == 0);
    assert!(offset_of!(VcpuSnapshot, sregs) == size_of::<kvm_regs>());
    assert!(
        offset_of!(VcpuSnapshot, fpu) == offset_of!(VcpuSnapshot, sregs) + size_of::<kvm_sregs>()
    );
    assert!(
        offset_of!(VcpuSnapshot, lapic) == offset_of!(VcpuSnapshot, fpu) + size_of::<kvm_fpu>()
    );
    assert!(
        offset_of!(VcpuSnapshot, xcrs)
            == offset_of!(VcpuSnapshot, lapic) + size_of::<kvm_lapic_state>()
    );
    assert!(
        offset_of!(VcpuSnapshot, debugregs)
            == offset_of!(VcpuSnapshot, xcrs) + size_of::<kvm_xcrs>()
    );
    assert!(
        offset_of!(VcpuSnapshot, xsave_region)
            == offset_of!(VcpuSnapshot, debugregs) + size_of::<kvm_debugregs>()
    );
    assert!(
        offset_of!(VcpuSnapshot, vcpu_events)
            == offset_of!(VcpuSnapshot, xsave_region) + size_of::<[u32; XSAVE_REGION_SIZE]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, msrs)
            == offset_of!(VcpuSnapshot, vcpu_events) + size_of::<kvm_vcpu_events>()
    );
    assert!(
        offset_of!(VcpuSnapshot, msr_count)
            == offset_of!(VcpuSnapshot, msrs) + size_of::<[kvm_msr_entry; MAX_SNAPSHOT_MSRS]>()
    );
    assert!(
        offset_of!(VcpuSnapshot, mp_state)
            == offset_of!(VcpuSnapshot, msr_count) + size_of::<u32>()
    );
    assert!(
        offset_of!(VcpuSnapshot, snapshot_flags)
            == offset_of!(VcpuSnapshot, mp_state) + size_of::<u32>()
    );
    assert!(
        offset_of!(VcpuSnapshot, _pad_snapshot_flags)
            == offset_of!(VcpuSnapshot, snapshot_flags) + size_of::<u32>()
    );

    // Total size equals last field end — no trailing padding.
    assert!(
        size_of::<VcpuSnapshot>()
            == offset_of!(VcpuSnapshot, _pad_snapshot_flags) + size_of::<u32>()
    );
};

// Compile-time check: VcpuSnapshot must fit in a VCPU_SLOT_SIZE slot.
amla_core::assert_vcpu_fits!(VcpuSnapshot);

impl std::fmt::Debug for VcpuSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // GP registers
        f.debug_struct("VcpuSnapshot")
            .field("rax", &format_args!("{:#018x}", self.regs.rax))
            .field("rbx", &format_args!("{:#018x}", self.regs.rbx))
            .field("rcx", &format_args!("{:#018x}", self.regs.rcx))
            .field("rdx", &format_args!("{:#018x}", self.regs.rdx))
            .field("rsi", &format_args!("{:#018x}", self.regs.rsi))
            .field("rdi", &format_args!("{:#018x}", self.regs.rdi))
            .field("rbp", &format_args!("{:#018x}", self.regs.rbp))
            .field("rsp", &format_args!("{:#018x}", self.regs.rsp))
            .field("r8", &format_args!("{:#018x}", self.regs.r8))
            .field("r9", &format_args!("{:#018x}", self.regs.r9))
            .field("r10", &format_args!("{:#018x}", self.regs.r10))
            .field("r11", &format_args!("{:#018x}", self.regs.r11))
            .field("r12", &format_args!("{:#018x}", self.regs.r12))
            .field("r13", &format_args!("{:#018x}", self.regs.r13))
            .field("r14", &format_args!("{:#018x}", self.regs.r14))
            .field("r15", &format_args!("{:#018x}", self.regs.r15))
            .field("rip", &format_args!("{:#018x}", self.regs.rip))
            .field("rflags", &format_args!("{:#018x}", self.regs.rflags))
            // Segment selectors
            .field("cs", &format_args!("{:#06x}", self.sregs.cs.selector))
            .field("ds", &format_args!("{:#06x}", self.sregs.ds.selector))
            .field("es", &format_args!("{:#06x}", self.sregs.es.selector))
            .field("fs", &format_args!("{:#06x}", self.sregs.fs.selector))
            .field("gs", &format_args!("{:#06x}", self.sregs.gs.selector))
            .field("ss", &format_args!("{:#06x}", self.sregs.ss.selector))
            // Control registers
            .field("cr0", &format_args!("{:#018x}", self.sregs.cr0))
            .field("cr3", &format_args!("{:#018x}", self.sregs.cr3))
            .field("cr4", &format_args!("{:#018x}", self.sregs.cr4))
            .field("efer", &format_args!("{:#018x}", self.sregs.efer))
            .field("apic_base", &format_args!("{:#018x}", self.sregs.apic_base))
            // FPU control
            .field("fcw", &format_args!("{:#06x}", self.fpu.fcw))
            .field("mxcsr", &format_args!("{:#010x}", self.fpu.mxcsr))
            // MSRs
            .field("msr_count", &self.msr_count)
            .field("mp_state", &self.mp_state)
            .field(
                "snapshot_flags",
                &format_args!("{:#x}", self.snapshot_flags),
            )
            .finish_non_exhaustive()
    }
}

impl VcpuSnapshot {
    /// Validate snapshot fields that could cause out-of-bounds access or
    /// undefined KVM behavior if corrupted in the shared-memory slot.
    ///
    /// This catches corruption from truncated mappings, stale slots, or
    /// (in cross-trust-zone scenarios) tampered shared memory. It does NOT
    /// validate that register values make architectural sense — KVM itself
    /// rejects invalid register state via `set_regs`/`set_sregs`/etc.
    pub fn validate(&self) -> Result<()> {
        if self.msr_count as usize > MAX_SNAPSHOT_MSRS {
            return Err(VmmError::InvalidState {
                expected: "msr_count <= MAX_SNAPSHOT_MSRS (32)",
                actual: "msr_count out of range",
            });
        }
        if MpState::try_from(self.mp_state).is_err() {
            return Err(VmmError::InvalidState {
                expected: "mp_state in 0..=4",
                actual: "mp_state out of range",
            });
        }
        if self.snapshot_flags & !SNAPSHOT_KNOWN_FLAGS != 0 {
            return Err(VmmError::InvalidState {
                expected: "known x86 snapshot_flags bits only",
                actual: "snapshot_flags has unknown bits",
            });
        }
        Ok(())
    }

    /// Capture vCPU state from a KVM vCPU fd.
    ///
    /// Captures complete vCPU state including:
    /// - General purpose and segment registers
    /// - FPU/SSE state (legacy) and XSAVE state (extended)
    /// - LAPIC state for interrupt delivery
    /// - Debug registers (hardware breakpoints)
    /// - Pending vCPU events (in-flight exceptions/interrupts)
    /// - Model Specific Registers (TSC, syscall entry points, etc.)
    pub(crate) fn capture(vcpu: &kvm_ioctls::VcpuFd) -> Result<Self> {
        let mp = vcpu.get_mp_state()?;

        // Capture MSRs
        let (msrs, msr_count) = Self::capture_msrs(vcpu)?;

        let debugregs = vcpu.get_debug_regs()?;

        // Capture XSAVE state (extended FPU/SSE/AVX state)
        let xsave_region = vcpu.get_xsave().map(|xs| xs.region)?;

        // Capture pending vCPU events (exceptions, interrupts in flight)
        let vcpu_events = vcpu.get_vcpu_events()?;

        let snap = Self {
            regs: vcpu.get_regs()?,
            sregs: vcpu.get_sregs()?,
            fpu: vcpu.get_fpu()?,
            lapic: vcpu.get_lapic()?,
            xcrs: vcpu.get_xcrs()?,
            debugregs,
            xsave_region,
            vcpu_events,
            msrs,
            msr_count,
            mp_state: mp.mp_state,
            snapshot_flags: SNAPSHOT_CAPTURED_FLAGS,
            _pad_snapshot_flags: 0,
        };
        log::debug!(
            "vcpu capture: mp_state={} rip={:#x} cr3={:#x} rflags={:#x}",
            snap.mp_state,
            snap.regs.rip,
            snap.sregs.cr3,
            snap.regs.rflags,
        );
        Ok(snap)
    }

    /// Capture MSRs from a vCPU.
    fn capture_msrs(
        vcpu: &kvm_ioctls::VcpuFd,
    ) -> Result<([kvm_msr_entry; MAX_SNAPSHOT_MSRS], u32)> {
        // Build the MSR request with all indices we want to capture
        let entries: Vec<kvm_msr_entry> = SNAPSHOT_MSRS
            .iter()
            .map(|&index| kvm_msr_entry {
                index,
                reserved: 0,
                data: 0,
            })
            .collect();

        let mut kvm_msrs =
            Msrs::from_entries(&entries).map_err(|e| VmmError::MsrError(e.to_string()))?;

        // Get MSR values from KVM
        let count = vcpu
            .get_msrs(&mut kvm_msrs)
            .map_err(|e| VmmError::MsrError(format!("KVM_GET_MSRS failed: {e}")))?;

        // Copy results to fixed-size array
        let mut result = [kvm_msr_entry {
            index: 0,
            reserved: 0,
            data: 0,
        }; MAX_SNAPSHOT_MSRS];

        for (i, entry) in kvm_msrs.as_slice().iter().take(count).enumerate() {
            result[i] = *entry;
        }

        // count bounded by SNAPSHOT_MSRS.len() (≤ MAX_SNAPSHOT_MSRS = 32)
        let count = u32::try_from(count)
            .map_err(|_| VmmError::MsrError("MSR count does not fit in u32".into()))?;
        Ok((result, count))
    }

    /// Return a `kvm_lapic_state` with the SPIV register enabled (software enable + spurious vector 0xFF).
    fn default_lapic() -> kvm_lapic_state {
        let mut lapic = kvm_lapic_state::default();
        let spiv_offset = 0xF0usize;
        let spiv_value: u32 = 0x1FF; // APIC enabled + spurious vector 0xFF
        let spiv_bytes = spiv_value.to_le_bytes();
        lapic.regs[spiv_offset] = spiv_bytes[0].cast_signed();
        lapic.regs[spiv_offset + 1] = spiv_bytes[1].cast_signed();
        lapic.regs[spiv_offset + 2] = spiv_bytes[2].cast_signed();
        lapic.regs[spiv_offset + 3] = spiv_bytes[3].cast_signed();
        lapic
    }

    /// Return a `kvm_fpu` with standard x87 defaults (fcw=0x37f, mxcsr=0x1f80).
    pub(crate) fn default_fpu() -> kvm_fpu {
        kvm_fpu {
            fcw: 0x37f,
            mxcsr: 0x1f80,
            ..Default::default()
        }
    }

    /// Create a snapshot suitable for initial Linux boot.
    ///
    /// Converts the platform-agnostic boot state to KVM register types
    /// and sets sensible defaults for FPU, LAPIC, and MP state.
    pub fn for_boot(boot_state: &amla_boot::x86_64::X86BootState) -> Self {
        let (regs, sregs) = crate::boot::x86_boot_state_to_kvm(boot_state);
        let mut msrs = [kvm_msr_entry {
            index: 0,
            reserved: 0,
            data: 0,
        }; MAX_SNAPSHOT_MSRS];
        let msr_count = if host_is_amd_family() {
            msrs[0] = kvm_msr_entry {
                index: msr::MSR_K7_HWCR,
                reserved: 0,
                data: msr::MSR_K7_HWCR_TSCFREQSEL,
            };
            1u32
        } else {
            0u32
        };
        Self {
            regs,
            sregs,
            fpu: Self::default_fpu(),
            lapic: Self::default_lapic(),
            xcrs: kvm_xcrs::default(),
            debugregs: kvm_debugregs::default(),
            xsave_region: [0u32; XSAVE_REGION_SIZE],
            // Mark event subfields valid and cleared so KVM applies all fields.
            vcpu_events: kvm_vcpu_events {
                flags: VCPU_EVENTS_VALID_DEFAULT,
                ..Default::default()
            },
            msrs,
            msr_count,
            mp_state: 0, // KVM_MP_STATE_RUNNABLE
            snapshot_flags: 0,
            _pad_snapshot_flags: 0,
        }
    }

    /// Create a minimal snapshot for an AP waiting for SIPI.
    ///
    /// The AP will be in `INIT_RECEIVED` state, waiting for the BSP
    /// to send a SIPI via the LAPIC. `vcpu_index` is used as the APIC ID.
    ///
    /// # Errors
    ///
    /// Returns [`VmmError::ApicIdOverflow`] if `vcpu_index` does not fit in
    /// the xAPIC 8-bit APIC ID field (valid range 0..=254, since 255 is the
    /// broadcast destination). `MAX_VCPUS` is currently 64, so this cannot
    /// fire in practice — the check exists to prevent silent APIC ID aliasing
    /// if the limit is ever raised past 255.
    pub fn for_init_received(vcpu_index: usize) -> Result<Self> {
        let apic_id = u8::try_from(vcpu_index)
            .ok()
            .filter(|&id| id < 255)
            .ok_or(VmmError::ApicIdOverflow(vcpu_index))?;
        let (msrs, msr_count) = Self::default_ap_msrs();
        let mut lapic = Self::default_lapic();
        // xAPIC ID register at offset 0x20, bits [31:24] hold the APIC ID.
        let id_offset = 0x20usize;
        let id_value: u32 = u32::from(apic_id) << 24;
        let id_bytes = id_value.to_le_bytes();
        lapic.regs[id_offset] = id_bytes[0].cast_signed();
        lapic.regs[id_offset + 1] = id_bytes[1].cast_signed();
        lapic.regs[id_offset + 2] = id_bytes[2].cast_signed();
        lapic.regs[id_offset + 3] = id_bytes[3].cast_signed();

        Ok(Self {
            regs: kvm_regs::default(),
            sregs: kvm_sregs::default(),
            fpu: Self::default_fpu(),
            lapic,
            xcrs: kvm_xcrs::default(),
            debugregs: kvm_debugregs::default(),
            xsave_region: [0u32; XSAVE_REGION_SIZE],
            vcpu_events: kvm_vcpu_events {
                flags: VCPU_EVENTS_VALID_DEFAULT,
                ..Default::default()
            },
            msrs,
            msr_count,
            mp_state: MpState::InitReceived as u32,
            snapshot_flags: 0,
            _pad_snapshot_flags: 0,
        })
    }

    /// Create default MSR values for an AP (all zeros except PAT, plus
    /// `MSR_K7_HWCR` with `TscFreqSel` set on AMD/Hygon hosts).
    ///
    /// Returns the filled array and the count of initialized entries.
    fn default_ap_msrs() -> ([kvm_msr_entry; MAX_SNAPSHOT_MSRS], u32) {
        let mut msrs = [kvm_msr_entry {
            index: 0,
            reserved: 0,
            data: 0,
        }; MAX_SNAPSHOT_MSRS];

        for (i, &index) in SNAPSHOT_MSRS.iter().enumerate() {
            msrs[i] = kvm_msr_entry {
                index,
                reserved: 0,
                // PAT has a non-zero default; others start at 0
                data: if index == msr::IA32_PAT {
                    msr::IA32_PAT_DEFAULT
                } else {
                    0
                },
            };
        }
        let mut count = SNAPSHOT_MSRS.len();
        if host_is_amd_family() {
            msrs[count] = kvm_msr_entry {
                index: msr::MSR_K7_HWCR,
                reserved: 0,
                data: msr::MSR_K7_HWCR_TSCFREQSEL,
            };
            count += 1;
        }

        // count bounded by MAX_SNAPSHOT_MSRS (32) via the compile-time
        // check at the top of this file.
        #[allow(clippy::cast_possible_truncation)]
        let count_u32 = count as u32;
        (msrs, count_u32)
    }

    /// Restore vCPU state to a KVM vCPU fd.
    ///
    /// Follows Firecracker's proven restore ordering:
    ///   `mp_state` → regs → sregs → fpu → xsave → xcrs → `debug_regs`
    ///   → lapic → msrs → `vcpu_events` → `kvmclock_ctrl`
    ///
    /// Setting `mp_state` first tells KVM the vCPU's execution state before
    /// any register writes. `kvmclock_ctrl` at the end prevents the guest's
    /// soft lockup detector from panicking on the time discontinuity.
    pub(crate) fn restore(&self, vcpu: &kvm_ioctls::VcpuFd) -> Result<()> {
        log::debug!(
            "vcpu restore: mp_state={} rip={:#x} cr3={:#x} rflags={:#x}",
            self.mp_state,
            self.regs.rip,
            self.sregs.cr3,
            self.regs.rflags,
        );

        // MP state FIRST — tells KVM the vCPU's execution state before
        // any register writes (Firecracker ordering).
        vcpu.set_mp_state(kvm_bindings::kvm_mp_state {
            mp_state: self.mp_state,
        })?;

        // For APs in INIT_RECEIVED state (waiting for SIPI from BSP),
        // we still need to push the LAPIC state — specifically the APIC
        // ID register at offset 0x20 — because KVM's CPUID emulation for
        // leaf 1 EBX[31:24] reads from `kvm_apic_id()` (the LAPIC ID
        // register). Without this, the guest reads APIC ID=0 from
        // CPUID and warns "[Firmware Bug] APIC ID mismatch" against the
        // MADT-declared IDs. Other registers (regs/sregs/fpu/etc.) must
        // not be touched: KVM's default vCPU state is correct for
        // handling SIPI delivery, and overwriting it breaks SMP bringup.
        if self.mp_state == MpState::InitReceived as u32 {
            vcpu.set_lapic(&self.lapic)?;
            if log::log_enabled!(log::Level::Debug)
                && let Ok(stored) = vcpu.get_lapic()
            {
                let id_offset = 0x20usize;
                let id_bytes = [
                    stored.regs[id_offset].cast_unsigned(),
                    stored.regs[id_offset + 1].cast_unsigned(),
                    stored.regs[id_offset + 2].cast_unsigned(),
                    stored.regs[id_offset + 3].cast_unsigned(),
                ];
                let stored_id = u32::from_le_bytes(id_bytes) >> 24;
                log::debug!("AP vcpu after set_lapic: APIC ID register={stored_id:#04x}");
            }
            return Ok(());
        }

        // Core registers
        vcpu.set_regs(&self.regs)?;
        vcpu.set_sregs(&self.sregs)?;
        vcpu.set_fpu(&self.fpu)?;

        // Extended state. These fields are optional for boot seed snapshots,
        // but exact for captured snapshots: if a captured snapshot says a field
        // is present, failing to apply it is a restore failure.
        if self.snapshot_flags & SNAPSHOT_HAS_XCRS != 0 {
            vcpu.set_xcrs(&self.xcrs)?;
        }
        if self.snapshot_flags & SNAPSHOT_HAS_XSAVE != 0 {
            let xsave = kvm_xsave {
                region: self.xsave_region,
                ..Default::default()
            };
            vcpu.set_xsave(&xsave)?;
        }
        if self.snapshot_flags & SNAPSHOT_HAS_DEBUGREGS != 0 {
            vcpu.set_debug_regs(&self.debugregs)?;
        }

        // LAPIC state
        vcpu.set_lapic(&self.lapic)?;

        // MSRs
        self.restore_msrs(vcpu)?;

        // Pending vCPU events LAST (Firecracker ordering)
        if self.snapshot_flags & SNAPSHOT_HAS_VCPU_EVENTS != 0 {
            vcpu.set_vcpu_events(&self.vcpu_events)?;
        }

        // Notify guest pvclock was paused (prevents soft lockup panic).
        // This is not serialized guest state. Older kernels or guests that do
        // not use pvclock may reject it, so it remains a best-effort nudge.
        if let Err(e) = vcpu.kvmclock_ctrl() {
            log::trace!("kvmclock_ctrl failed (guest may not use pvclock): {e}");
        }

        Ok(())
    }

    /// Restore MSRs to a vCPU.
    fn restore_msrs(&self, vcpu: &kvm_ioctls::VcpuFd) -> Result<()> {
        // Defensive clamp: `msr_count` is deserialized from a VmState blob
        // and could exceed `MAX_SNAPSHOT_MSRS` if the blob is corrupted
        // or from a future build. Indexing without the clamp would panic
        // the host process — the same defensive pattern is already used
        // for `xcrs.nr_xcrs` below.
        let count = (self.msr_count as usize).min(MAX_SNAPSHOT_MSRS);
        if count == 0 {
            return Ok(());
        }

        let kvm_msrs = Msrs::from_entries(&self.msrs[..count])
            .map_err(|e| VmmError::MsrError(e.to_string()))?;

        let set_count = vcpu
            .set_msrs(&kvm_msrs)
            .map_err(|e| VmmError::MsrError(format!("KVM_SET_MSRS failed: {e}")))?;
        if set_count != count {
            return Err(VmmError::MsrError(format!(
                "set_msrs: only {set_count}/{count} MSRs applied"
            )));
        }

        Ok(())
    }

    /// Convert to the shared, serde-friendly snapshot type.
    ///
    /// # Errors
    ///
    /// Returns [`VmmError::UnknownMpState`] if the host kernel reported an
    /// `mp_state` value that does not map to any variant of
    /// [`MpState`](amla_core::x86_64::MpState). The previous implementation
    /// silently normalized such values to `Runnable`, which hid kernel/VMM
    /// state drift.
    #[expect(
        clippy::too_many_lines,
        reason = "one field per register — splitting hurts readability"
    )]
    pub fn to_shared(&self) -> Result<amla_core::x86_64::X86VcpuSnapshot> {
        use amla_core::x86_64::snapshot::{
            X86DebugRegs, X86DtReg, X86GeneralRegs, X86Segment, X86SegmentRegs,
        };

        let regs = X86GeneralRegs {
            rax: self.regs.rax,
            rbx: self.regs.rbx,
            rcx: self.regs.rcx,
            rdx: self.regs.rdx,
            rsi: self.regs.rsi,
            rdi: self.regs.rdi,
            rsp: self.regs.rsp,
            rbp: self.regs.rbp,
            r8: self.regs.r8,
            r9: self.regs.r9,
            r10: self.regs.r10,
            r11: self.regs.r11,
            r12: self.regs.r12,
            r13: self.regs.r13,
            r14: self.regs.r14,
            r15: self.regs.r15,
            rip: self.regs.rip,
            rflags: self.regs.rflags,
        };

        let convert_seg = |s: &kvm_bindings::kvm_segment| X86Segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            unusable: s.unusable,
        };
        let convert_dt = |d: &kvm_bindings::kvm_dtable| X86DtReg {
            base: d.base,
            limit: d.limit,
        };

        let sregs = X86SegmentRegs {
            cs: convert_seg(&self.sregs.cs),
            ds: convert_seg(&self.sregs.ds),
            es: convert_seg(&self.sregs.es),
            fs: convert_seg(&self.sregs.fs),
            gs: convert_seg(&self.sregs.gs),
            ss: convert_seg(&self.sregs.ss),
            tr: convert_seg(&self.sregs.tr),
            ldt: convert_seg(&self.sregs.ldt),
            gdt: convert_dt(&self.sregs.gdt),
            idt: convert_dt(&self.sregs.idt),
            cr0: self.sregs.cr0,
            cr2: self.sregs.cr2,
            cr3: self.sregs.cr3,
            cr4: self.sregs.cr4,
            cr8: self.sregs.cr8,
            efer: self.sregs.efer,
            apic_base: self.sregs.apic_base,
        };

        // FPU + LAPIC: serialize as raw bytes via the Pod representation of the
        // outer VcpuSnapshot. Since VcpuSnapshot is Pod, its entire byte
        // representation is well-defined, including these inner fields.
        let self_bytes = bytemuck::bytes_of(self);
        let fpu_offset = std::mem::offset_of!(Self, fpu);
        let fpu = self_bytes[fpu_offset..fpu_offset + std::mem::size_of::<kvm_fpu>()].to_vec();

        let lapic_offset = std::mem::offset_of!(Self, lapic);
        let lapic = self_bytes[lapic_offset..lapic_offset + std::mem::size_of::<kvm_lapic_state>()]
            .to_vec();

        // MSRs
        // Defensive clamp — see `restore_msrs` for rationale.
        let msr_count = (self.msr_count as usize).min(MAX_SNAPSHOT_MSRS);
        let msrs: Vec<(u32, u64)> = self.msrs[..msr_count]
            .iter()
            .map(|e| (e.index, e.data))
            .collect();

        // XCRs. Defensive clamp — corrupt `nr_xcrs` from a tampered or stale
        // snapshot slot would OOB-index `xcrs.xcrs`. Mirrors the MSR clamp at
        // line 705.
        let xcr_count = (self.xcrs.nr_xcrs as usize).min(self.xcrs.xcrs.len());
        let xcrs: Vec<(u32, u64)> = if self.snapshot_flags & SNAPSHOT_HAS_XCRS != 0 {
            (0..xcr_count)
                .map(|i| (self.xcrs.xcrs[i].xcr, self.xcrs.xcrs[i].value))
                .collect()
        } else {
            Vec::new()
        };

        // Debug regs
        let debugregs = X86DebugRegs {
            db: self.debugregs.db,
            dr6: self.debugregs.dr6,
            dr7: self.debugregs.dr7,
        };

        // XSAVE: serialize xsave_region as raw bytes if it was captured.
        let xsave = if self.snapshot_flags & SNAPSHOT_HAS_XSAVE != 0 {
            amla_core::bytemuck::cast_slice::<u32, u8>(&self.xsave_region).to_vec()
        } else {
            Vec::new()
        };

        // vcpu_events as raw bytes (via Pod representation of outer VcpuSnapshot)
        let events_offset = std::mem::offset_of!(Self, vcpu_events);
        let vcpu_events = if self.snapshot_flags & SNAPSHOT_HAS_VCPU_EVENTS != 0 {
            self_bytes[events_offset..events_offset + std::mem::size_of::<kvm_vcpu_events>()]
                .to_vec()
        } else {
            Vec::new()
        };

        let mp_state = MpState::try_from(self.mp_state).map_err(VmmError::UnknownMpState)?;

        Ok(amla_core::x86_64::X86VcpuSnapshot {
            regs,
            sregs,
            fpu,
            xsave,
            lapic,
            msrs,
            mp_state,
            xcrs,
            debugregs,
            vcpu_events,
        })
    }

    /// Create a KVM `VcpuSnapshot` from the shared serde-friendly type.
    ///
    /// This is the strict restore conversion: opaque KVM byte fields must be
    /// present at the exact expected sizes and variable-length arrays must fit
    /// without truncation. Boot seeding uses the arch-specific `for_boot` and
    /// `for_init_received` constructors instead.
    pub fn from_shared(shared: &amla_core::x86_64::X86VcpuSnapshot) -> Result<Self> {
        Self::try_from(shared)
    }
}

impl TryFrom<&amla_core::x86_64::X86VcpuSnapshot> for VcpuSnapshot {
    type Error = VmmError;

    #[expect(
        clippy::too_many_lines,
        reason = "one field per register — splitting hurts readability"
    )]
    #[allow(clippy::cast_possible_truncation)] // counts validated before casting
    fn try_from(shared: &amla_core::x86_64::X86VcpuSnapshot) -> Result<Self> {
        use amla_core::x86_64::snapshot::{X86DtReg, X86Segment};

        let regs = kvm_regs {
            rax: shared.regs.rax,
            rbx: shared.regs.rbx,
            rcx: shared.regs.rcx,
            rdx: shared.regs.rdx,
            rsi: shared.regs.rsi,
            rdi: shared.regs.rdi,
            rsp: shared.regs.rsp,
            rbp: shared.regs.rbp,
            r8: shared.regs.r8,
            r9: shared.regs.r9,
            r10: shared.regs.r10,
            r11: shared.regs.r11,
            r12: shared.regs.r12,
            r13: shared.regs.r13,
            r14: shared.regs.r14,
            r15: shared.regs.r15,
            rip: shared.regs.rip,
            rflags: shared.regs.rflags,
        };

        let convert_seg = |s: &X86Segment| kvm_bindings::kvm_segment {
            base: s.base,
            limit: s.limit,
            selector: s.selector,
            type_: s.type_,
            present: s.present,
            dpl: s.dpl,
            db: s.db,
            s: s.s,
            l: s.l,
            g: s.g,
            unusable: s.unusable,
            ..Default::default()
        };
        let convert_dt = |d: &X86DtReg| kvm_bindings::kvm_dtable {
            base: d.base,
            limit: d.limit,
            ..Default::default()
        };

        let sregs = kvm_sregs {
            cs: convert_seg(&shared.sregs.cs),
            ds: convert_seg(&shared.sregs.ds),
            es: convert_seg(&shared.sregs.es),
            fs: convert_seg(&shared.sregs.fs),
            gs: convert_seg(&shared.sregs.gs),
            ss: convert_seg(&shared.sregs.ss),
            tr: convert_seg(&shared.sregs.tr),
            ldt: convert_seg(&shared.sregs.ldt),
            gdt: convert_dt(&shared.sregs.gdt),
            idt: convert_dt(&shared.sregs.idt),
            cr0: shared.sregs.cr0,
            cr2: shared.sregs.cr2,
            cr3: shared.sregs.cr3,
            cr4: shared.sregs.cr4,
            cr8: shared.sregs.cr8,
            efer: shared.sregs.efer,
            apic_base: shared.sregs.apic_base,
            ..Default::default()
        };

        if shared.fpu.len() != std::mem::size_of::<kvm_fpu>() {
            return Err(VmmError::SizeMismatch {
                expected: std::mem::size_of::<kvm_fpu>(),
                actual: shared.fpu.len(),
            });
        }
        // SAFETY: The input slice has been validated to be exactly `size_of::<kvm_fpu>()`
        // bytes. `read_unaligned` is used because the byte buffer may not be properly
        // aligned for `kvm_fpu`.
        let fpu = unsafe { std::ptr::read_unaligned(shared.fpu.as_ptr().cast::<kvm_fpu>()) };

        if shared.lapic.len() != std::mem::size_of::<kvm_lapic_state>() {
            return Err(VmmError::SizeMismatch {
                expected: std::mem::size_of::<kvm_lapic_state>(),
                actual: shared.lapic.len(),
            });
        }
        // SAFETY: The input slice has been validated to be exactly
        // `size_of::<kvm_lapic_state>()` bytes. `read_unaligned` is used because the
        // byte buffer may not be properly aligned for `kvm_lapic_state`.
        let lapic =
            unsafe { std::ptr::read_unaligned(shared.lapic.as_ptr().cast::<kvm_lapic_state>()) };

        // MSRs
        if shared.msrs.len() > MAX_SNAPSHOT_MSRS {
            return Err(VmmError::InvalidState {
                expected: "msrs length <= MAX_SNAPSHOT_MSRS",
                actual: "too many MSRs",
            });
        }
        let mut msrs = [kvm_msr_entry {
            index: 0,
            reserved: 0,
            data: 0,
        }; MAX_SNAPSHOT_MSRS];
        let msr_count = shared.msrs.len() as u32;
        for (i, &(index, data)) in shared.msrs.iter().enumerate() {
            msrs[i] = kvm_msr_entry {
                index,
                reserved: 0,
                data,
            };
        }

        // XCRs
        let mut xcrs = kvm_xcrs::default();
        if shared.xcrs.len() > xcrs.xcrs.len() {
            return Err(VmmError::InvalidState {
                expected: "xcrs length <= KVM xcr array length",
                actual: "too many XCRs",
            });
        }
        let xcr_count = shared.xcrs.len();
        xcrs.nr_xcrs = xcr_count as u32;
        for (i, &(xcr, value)) in shared.xcrs.iter().enumerate() {
            xcrs.xcrs[i].xcr = xcr;
            xcrs.xcrs[i].value = value;
        }

        // Debug regs
        let debugregs = kvm_debugregs {
            db: shared.debugregs.db,
            dr6: shared.debugregs.dr6,
            dr7: shared.debugregs.dr7,
            ..Default::default()
        };

        if shared.xsave.len() != XSAVE_REGION_SIZE * 4 {
            return Err(VmmError::SizeMismatch {
                expected: XSAVE_REGION_SIZE * 4,
                actual: shared.xsave.len(),
            });
        }
        let mut xsave_region = [0u32; XSAVE_REGION_SIZE];
        for (slot, chunk) in xsave_region.iter_mut().zip(shared.xsave.chunks_exact(4)) {
            *slot = u32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        if shared.vcpu_events.len() != std::mem::size_of::<kvm_vcpu_events>() {
            return Err(VmmError::SizeMismatch {
                expected: std::mem::size_of::<kvm_vcpu_events>(),
                actual: shared.vcpu_events.len(),
            });
        }
        // SAFETY: The input slice has been validated to be exactly
        // `size_of::<kvm_vcpu_events>()` bytes. `read_unaligned` is used because the
        // byte buffer may not be properly aligned for `kvm_vcpu_events`.
        let vcpu_events = unsafe {
            std::ptr::read_unaligned(shared.vcpu_events.as_ptr().cast::<kvm_vcpu_events>())
        };

        Ok(Self {
            regs,
            sregs,
            fpu,
            lapic,
            xcrs,
            debugregs,
            xsave_region,
            vcpu_events,
            msrs,
            msr_count,
            mp_state: shared.mp_state as u32,
            snapshot_flags: SNAPSHOT_CAPTURED_FLAGS,
            _pad_snapshot_flags: 0,
        })
    }
}

// ============================================================================
// VmStateSnapshot - VM-level state (irqchip, timers, clock)
// ============================================================================

/// Snapshot of VM-level state (irqchip, timer, clock).
///
/// This captures state that is per-VM, not per-vCPU:
/// - PIC (8259A master/slave)
/// - IOAPIC
/// - PIT (8254 timer)
/// - Clock (kvmclock/TSC)
#[derive(Clone)]
pub struct VmStateSnapshot {
    /// Master 8259A PIC state.
    pub pic_master: kvm_irqchip,
    /// Slave 8259A PIC state.
    pub pic_slave: kvm_irqchip,
    /// IOAPIC state.
    pub ioapic: kvm_irqchip,
    /// 8254 PIT (timer) state.
    pub pit: kvm_pit_state2,
    /// kvmclock/TSC state.
    pub clock: kvm_clock_data,
    /// Whether `clock` came from a captured running VM and should be restored.
    ///
    /// Fresh boot blobs keep the typed irqchip state but clear this bit so a
    /// template clock captured at boot-state construction is never replayed
    /// into a later shell.
    pub clock_present: bool,
}

impl std::fmt::Debug for VmStateSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VmStateSnapshot").finish_non_exhaustive()
    }
}

impl VmStateSnapshot {
    /// Capture VM state from a KVM VM fd.
    pub(crate) fn capture(
        vm_fd: &VmFd,
        _device_state: &super::InitialDeviceState,
        _num_vcpus: usize,
    ) -> Result<Self> {
        let mut pic_master = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_MASTER,
            ..Default::default()
        };
        let mut pic_slave = kvm_irqchip {
            chip_id: KVM_IRQCHIP_PIC_SLAVE,
            ..Default::default()
        };
        let mut ioapic = kvm_irqchip {
            chip_id: KVM_IRQCHIP_IOAPIC,
            ..Default::default()
        };

        vm_fd.get_irqchip(&mut pic_master)?;
        vm_fd.get_irqchip(&mut pic_slave)?;
        vm_fd.get_irqchip(&mut ioapic)?;

        let pit = vm_fd.get_pit2()?;
        let clock = vm_fd.get_clock()?;

        Ok(Self {
            pic_master,
            pic_slave,
            ioapic,
            pit,
            clock,
            clock_present: true,
        })
    }

    /// Serialize the architecture-specific KVM state (PIC, IOAPIC, PIT, clock)
    /// into a byte buffer. Returns the number of bytes written.
    ///
    /// The blob is prefixed with a 12-byte envelope: 4-byte magic + 4-byte LE
    /// version + 4-byte LE flags. Bump `ARCH_BLOB_VERSION` whenever any serialized field's
    /// layout changes (new field added, `kvm_bindings` struct grown, etc.). Same
    /// size across kernel versions is not the same as same layout — the magic
    /// alone would miss that.
    pub fn write_arch_blob(&self, buf: &mut [u8]) -> usize {
        let flags = if self.clock_present {
            ARCH_BLOB_HAS_CLOCK
        } else {
            0
        };
        self.write_arch_blob_with_flags(buf, flags)
    }

    pub(crate) fn write_boot_arch_blob(&self, buf: &mut [u8]) -> usize {
        self.write_arch_blob_with_flags(buf, 0)
    }

    fn write_arch_blob_with_flags(&self, buf: &mut [u8], flags: u32) -> usize {
        assert!(
            buf.len() >= ARCH_BLOB_HEADER_SIZE,
            "arch blob buffer too small for header"
        );
        debug_assert_eq!(flags & !ARCH_BLOB_KNOWN_FLAGS, 0);
        buf[..4].copy_from_slice(&ARCH_BLOB_MAGIC);
        buf[4..8].copy_from_slice(&ARCH_BLOB_VERSION.to_le_bytes());
        buf[8..12].copy_from_slice(&flags.to_le_bytes());
        let mut offset = ARCH_BLOB_HEADER_SIZE;

        macro_rules! write_field {
            ($field:expr) => {{
                let size = std::mem::size_of_val(&$field);
                assert!(
                    offset + size <= buf.len(),
                    "arch blob buffer too small: need {} + {}, have {}",
                    offset,
                    size,
                    buf.len()
                );
                // SAFETY: $field is a valid KVM struct, buf is large enough (asserted above).
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        std::ptr::from_ref(&$field).cast::<u8>(),
                        buf[offset..].as_mut_ptr(),
                        size,
                    );
                }
                offset += size;
            }};
        }

        write_field!(self.pic_master);
        write_field!(self.pic_slave);
        write_field!(self.ioapic);
        write_field!(self.pit);
        write_field!(self.clock);
        offset
    }

    /// Deserialize architecture-specific KVM state from a byte buffer.
    ///
    /// Returns an error if the header magic or version does not match, or if
    /// the buffer is too short. No silent fallback for missing/mismatched
    /// envelopes — a cross-kernel-version restore attempt is a hard error.
    #[allow(unused_assignments)] // offset advances past last field for uniformity
    pub fn from_arch_blob(buf: &[u8]) -> Result<Self> {
        if buf.len() < ARCH_BLOB_HEADER_SIZE {
            return Err(VmmError::Config(format!(
                "from_arch_blob: buffer too short for header ({} bytes, need {ARCH_BLOB_HEADER_SIZE})",
                buf.len(),
            )));
        }
        // Buf length verified above, so these fixed-size array copies cannot panic.
        let magic = [buf[0], buf[1], buf[2], buf[3]];
        if magic != ARCH_BLOB_MAGIC {
            return Err(VmmError::Config(format!(
                "from_arch_blob: bad magic {magic:?}, expected {ARCH_BLOB_MAGIC:?}"
            )));
        }
        let version = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        if version != ARCH_BLOB_VERSION {
            return Err(VmmError::Config(format!(
                "from_arch_blob: version {version} does not match expected {ARCH_BLOB_VERSION}"
            )));
        }
        let flags = u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]);
        if flags & !ARCH_BLOB_KNOWN_FLAGS != 0 {
            return Err(VmmError::Config(format!(
                "from_arch_blob: unknown flags {:#x}",
                flags & !ARCH_BLOB_KNOWN_FLAGS
            )));
        }
        let mut offset = ARCH_BLOB_HEADER_SIZE;

        macro_rules! read_field {
            ($ty:ty) => {{
                let size = std::mem::size_of::<$ty>();
                if offset + size > buf.len() {
                    return Err(VmmError::Config(format!(
                        "from_arch_blob: buffer too short at offset {offset} for {} ({size} bytes, buf len {})",
                        std::any::type_name::<$ty>(),
                        buf.len(),
                    )));
                }
                // SAFETY: bounds checked above; header magic+version verified so
                // the following bytes are a write_arch_blob payload of this version.
                let val = unsafe { std::ptr::read_unaligned(buf[offset..].as_ptr().cast::<$ty>()) };
                offset += size;
                val
            }};
        }

        let pic_master = read_field!(kvm_irqchip);
        let pic_slave = read_field!(kvm_irqchip);
        let ioapic = read_field!(kvm_irqchip);
        let pit = read_field!(kvm_pit_state2);
        let clock = read_field!(kvm_clock_data);

        Ok(Self {
            pic_master,
            pic_slave,
            ioapic,
            pit,
            clock,
            clock_present: flags & ARCH_BLOB_HAS_CLOCK != 0,
        })
    }

    /// Restore VM state to a KVM VM fd.
    ///
    /// `clock_offset_ns` adjusts the kvmclock forward to compensate for wall-clock
    /// time elapsed since the snapshot was taken. Pass `None` for zygote spawns
    /// (ms-scale latency, no adjustment needed) or `Some(delta_ns)` for disk
    /// restores where the gap may be minutes/hours.
    ///
    /// Note: IRQ line state is restored separately via the irqchip state in the mmap region.
    pub(crate) fn restore(
        &self,
        vm_fd: &VmFd,
        clock_offset_ns: Option<u64>,
        _device_state: &super::InitialDeviceState,
    ) -> Result<()> {
        vm_fd.set_irqchip(&self.pic_master)?;
        vm_fd.set_irqchip(&self.pic_slave)?;
        vm_fd.set_irqchip(&self.ioapic)?;
        vm_fd.set_pit2(&self.pit)?;

        if self.clock_present {
            let mut clock = self.clock;
            if let Some(offset) = clock_offset_ns {
                clock.clock = clock.clock.saturating_add(offset);
            }
            // Clear ALL flags. When flags include KVM_CLOCK_REALTIME (0x4) or
            // KVM_CLOCK_HOST_TSC (0x8), KVM anchors the clock offset to the
            // saved realtime/host_tsc values from the original freeze, not the
            // current time. This causes clones to see wall_time_since_freeze
            // instead of wall_time_since_set_clock. Setting flags=0 forces KVM
            // to use the current host time as the base.
            clock.flags = 0;
            vm_fd.set_clock(&clock)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// Build a default `VmStateSnapshot` for testing (no KVM required).
    fn make_default_vm_state() -> VmStateSnapshot {
        VmStateSnapshot {
            pic_master: kvm_irqchip {
                chip_id: KVM_IRQCHIP_PIC_MASTER,
                ..Default::default()
            },
            pic_slave: kvm_irqchip {
                chip_id: KVM_IRQCHIP_PIC_SLAVE,
                ..Default::default()
            },
            ioapic: kvm_irqchip {
                chip_id: KVM_IRQCHIP_IOAPIC,
                ..Default::default()
            },
            pit: kvm_pit_state2::default(),
            clock: kvm_clock_data::default(),
            clock_present: true,
        }
    }

    #[test]
    fn arch_blob_roundtrip() {
        let original = make_default_vm_state();

        // Serialize
        let mut buf = vec![0u8; 8192];
        let written = original.write_arch_blob(&mut buf);
        assert!(written > 0);

        // Deserialize
        let restored = VmStateSnapshot::from_arch_blob(&buf[..written]).unwrap();

        // Verify key fields survive the roundtrip
        assert_eq!(restored.pic_master.chip_id, KVM_IRQCHIP_PIC_MASTER);
        assert_eq!(restored.pic_slave.chip_id, KVM_IRQCHIP_PIC_SLAVE);
        assert_eq!(restored.ioapic.chip_id, KVM_IRQCHIP_IOAPIC);
        assert!(restored.clock_present);
    }

    #[test]
    fn boot_arch_blob_marks_clock_absent() {
        let original = make_default_vm_state();
        let mut buf = vec![0u8; 8192];
        let written = original.write_boot_arch_blob(&mut buf);

        let restored = VmStateSnapshot::from_arch_blob(&buf[..written]).unwrap();

        assert!(!restored.clock_present);
    }

    #[test]
    fn from_arch_blob_truncated_returns_error() {
        let original = make_default_vm_state();

        let mut buf = vec![0u8; 8192];
        let written = original.write_arch_blob(&mut buf);

        // Truncate to half — must return error, not panic
        let result = VmStateSnapshot::from_arch_blob(&buf[..written / 2]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("buffer too short"), "unexpected error: {msg}");
    }

    #[test]
    fn from_arch_blob_empty_returns_error() {
        let result = VmStateSnapshot::from_arch_blob(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn from_arch_blob_bad_magic_rejected() {
        let original = make_default_vm_state();
        let mut buf = vec![0u8; 8192];
        let written = original.write_arch_blob(&mut buf);
        buf[0] = b'X'; // corrupt magic
        let result = VmStateSnapshot::from_arch_blob(&buf[..written]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("bad magic"));
    }

    #[test]
    fn from_arch_blob_bad_version_rejected() {
        let original = make_default_vm_state();
        let mut buf = vec![0u8; 8192];
        let written = original.write_arch_blob(&mut buf);
        let bogus = (ARCH_BLOB_VERSION + 99).to_le_bytes();
        buf[4..8].copy_from_slice(&bogus);
        let result = VmStateSnapshot::from_arch_blob(&buf[..written]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("version"));
    }

    #[test]
    fn from_arch_blob_bad_flags_rejected() {
        let original = make_default_vm_state();
        let mut buf = vec![0u8; 8192];
        let written = original.write_arch_blob(&mut buf);
        buf[8..12].copy_from_slice(&(1u32 << 31).to_le_bytes());
        let result = VmStateSnapshot::from_arch_blob(&buf[..written]);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("unknown flags"));
    }

    /// Helper: zeroed `VcpuSnapshot` with valid field values.
    fn make_valid_vcpu_snapshot() -> VcpuSnapshot {
        bytemuck::Zeroable::zeroed()
    }

    #[test]
    fn validate_accepts_valid_snapshot() {
        let snap = make_valid_vcpu_snapshot();
        snap.validate().unwrap();
    }

    #[test]
    fn validate_accepts_all_mp_states() {
        for mp in 0..=4u32 {
            let mut snap = make_valid_vcpu_snapshot();
            snap.mp_state = mp;
            snap.validate().unwrap();
        }
    }

    #[test]
    fn validate_rejects_bad_msr_count() {
        let mut snap = make_valid_vcpu_snapshot();
        snap.msr_count = u32::try_from(MAX_SNAPSHOT_MSRS).unwrap() + 1;
        assert!(snap.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_mp_state() {
        let mut snap = make_valid_vcpu_snapshot();
        snap.mp_state = 5;
        assert!(snap.validate().is_err());

        snap.mp_state = u32::MAX;
        assert!(snap.validate().is_err());
    }

    #[test]
    fn validate_rejects_unknown_snapshot_flags() {
        let mut snap = make_valid_vcpu_snapshot();
        snap.snapshot_flags = SNAPSHOT_KNOWN_FLAGS | (1 << 31);
        assert!(snap.validate().is_err());
    }

    #[test]
    fn from_shared_roundtrips_full_snapshot() {
        let mut snap = make_valid_vcpu_snapshot();
        snap.snapshot_flags = SNAPSHOT_CAPTURED_FLAGS;
        let shared = snap.to_shared().unwrap();
        let restored = VcpuSnapshot::from_shared(&shared).unwrap();
        assert_eq!(restored.snapshot_flags, SNAPSHOT_CAPTURED_FLAGS);
        assert_eq!(restored.msr_count, 0);
        assert_eq!(restored.mp_state, MpState::Runnable as u32);
    }

    #[test]
    fn from_shared_rejects_missing_opaque_state() {
        let shared = amla_core::x86_64::X86VcpuSnapshot::empty();
        let err = VcpuSnapshot::from_shared(&shared).unwrap_err().to_string();
        assert!(err.contains("size mismatch"), "unexpected error: {err}");
    }

    #[test]
    fn from_shared_rejects_too_many_msrs() {
        let mut snap = make_valid_vcpu_snapshot();
        snap.snapshot_flags = SNAPSHOT_CAPTURED_FLAGS;
        let mut shared = snap.to_shared().unwrap();
        shared.msrs = vec![(0, 0); MAX_SNAPSHOT_MSRS + 1];
        let err = VcpuSnapshot::from_shared(&shared).unwrap_err().to_string();
        assert!(err.contains("too many MSRs"), "unexpected error: {err}");
    }
}
