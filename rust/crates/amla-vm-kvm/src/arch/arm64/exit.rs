// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! ARM64 KVM vCPU exit decoding.
//!
//! On ARM64 KVM, exits are simpler than x86:
//! - No PIO exits (ARM has no port I/O)
//! - MMIO exits for device access (data provided directly by KVM)
//! - System events for PSCI shutdown/reboot
//! - HLT for WFI (Wait For Interrupt)

use amla_core::{ExitSource, VcpuExit};
use kvm_bindings::kvm_run;

/// Decode a KVM vCPU exit on ARM64.
///
/// KVM provides MMIO data directly in the `kvm_run.mmio` union, so we don't
/// need syndrome decoding here (that's for HVF). The mapping is straightforward.
pub(crate) fn map_exit(
    kvm_run: &kvm_run,
    _kvm_run_ptr: *const u8,
    _kvm_run_size: usize,
) -> VcpuExit {
    match kvm_run.exit_reason {
        kvm_bindings::KVM_EXIT_HLT => VcpuExit::Halt,
        // Raw KVM_EXIT_SHUTDOWN on ARM64 is rare — modern kernels route
        // clean power-off through KVM_EXIT_SYSTEM_EVENT_SHUTDOWN below.
        // When the legacy code path fires, the guest state is unclear
        // (machine check, unhandled PSCI call, etc.), so treat it as
        // unrecoverable rather than silently masking it as clean.
        kvm_bindings::KVM_EXIT_SHUTDOWN => VcpuExit::Unrecoverable,

        kvm_bindings::KVM_EXIT_MMIO => {
            // SAFETY: exit_reason == KVM_EXIT_MMIO guarantees the mmio union is active.
            let mmio = unsafe { &kvm_run.__bindgen_anon_1.mmio };
            let Some(mmio_size) = crate::arch::mmio::decode_mmio_size(mmio.len) else {
                log::warn!(
                    "MMIO exit with unexpected len {} at {:#x}",
                    mmio.len,
                    mmio.phys_addr,
                );
                return VcpuExit::Unknown {
                    code: -1,
                    source: ExitSource::Internal,
                };
            };
            if mmio.is_write == 0 {
                VcpuExit::MmioRead {
                    addr: mmio.phys_addr,
                    size: mmio_size.bytes(),
                }
            } else {
                VcpuExit::MmioWrite {
                    addr: mmio.phys_addr,
                    data: crate::arch::mmio::decode_mmio_write_data(mmio.data, mmio_size),
                    size: mmio_size.bytes(),
                }
            }
        }

        kvm_bindings::KVM_EXIT_SYSTEM_EVENT => {
            // SAFETY: exit_reason == KVM_EXIT_SYSTEM_EVENT guarantees system_event union.
            let event = unsafe { &kvm_run.__bindgen_anon_1.system_event };
            match event.type_ {
                kvm_bindings::KVM_SYSTEM_EVENT_SHUTDOWN => VcpuExit::CleanShutdown,
                kvm_bindings::KVM_SYSTEM_EVENT_RESET => VcpuExit::Reboot,
                _ => VcpuExit::Unknown {
                    code: i64::from(event.type_),
                    source: ExitSource::Hypervisor,
                },
            }
        }

        kvm_bindings::KVM_EXIT_ARM_NISV => {
            // SAFETY: exit_reason == KVM_EXIT_ARM_NISV guarantees the arm_nisv union is active.
            let nisv = unsafe { &kvm_run.__bindgen_anon_1.arm_nisv };
            log::error!(
                "ARM NISV data abort: fault_ipa={:#x} esr_iss={:#x}",
                nisv.fault_ipa,
                nisv.esr_iss,
            );
            VcpuExit::Unknown {
                code: i64::from(kvm_bindings::KVM_EXIT_ARM_NISV),
                source: ExitSource::Hypervisor,
            }
        }

        other => VcpuExit::Unknown {
            code: i64::from(other),
            source: ExitSource::Hypervisor,
        },
    }
}

#[cfg(test)]
mod tests {
    #![allow(unused_unsafe)]
    use super::*;

    /// Create a zeroed `kvm_run` and a raw pointer to it for testing.
    fn make_kvm_run() -> Box<kvm_run> {
        // SAFETY: kvm_run is a C struct; zero-init is valid.
        Box::new(unsafe { std::mem::zeroed() })
    }

    #[test]
    fn test_exit_hlt() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_HLT;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Halt
        );
    }

    #[test]
    fn test_exit_shutdown_is_unrecoverable() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_SHUTDOWN;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unrecoverable
        );
    }

    #[test]
    fn test_exit_mmio_read() {
        for (size, addr) in [
            (1u32, 0x0900_0000u64),
            (2, 0x0900_0010),
            (4, 0x0900_0020),
            (8, 0x0900_0030),
        ] {
            let mut run = make_kvm_run();
            run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
            // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
            unsafe {
                run.__bindgen_anon_1.mmio.phys_addr = addr;
                run.__bindgen_anon_1.mmio.len = size;
                run.__bindgen_anon_1.mmio.is_write = 0;
            }
            let ptr = (&raw const *run).cast::<u8>();
            assert_eq!(
                map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
                VcpuExit::MmioRead {
                    addr,
                    size: u8::try_from(size).unwrap(),
                },
                "MMIO read size={size}"
            );
        }
    }

    #[test]
    fn test_exit_mmio_write() {
        // 1-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.phys_addr = 0x0A00_0000;
            run.__bindgen_anon_1.mmio.len = 1;
            run.__bindgen_anon_1.mmio.is_write = 1;
            run.__bindgen_anon_1.mmio.data[0] = 0xAB;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0x0A00_0000,
                data: 0xAB,
                size: 1,
            }
        );

        // 2-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.phys_addr = 0x0A00_0002;
            run.__bindgen_anon_1.mmio.len = 2;
            run.__bindgen_anon_1.mmio.is_write = 1;
            run.__bindgen_anon_1.mmio.data[0] = 0xEF;
            run.__bindgen_anon_1.mmio.data[1] = 0xBE;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0x0A00_0002,
                data: 0xBEEF,
                size: 2,
            }
        );

        // 4-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        let bytes = 0xDEAD_BEEF_u32.to_le_bytes();
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.phys_addr = 0x0A00_0004;
            run.__bindgen_anon_1.mmio.len = 4;
            run.__bindgen_anon_1.mmio.is_write = 1;
            run.__bindgen_anon_1.mmio.data[..4].copy_from_slice(&bytes);
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0x0A00_0004,
                data: 0xDEAD_BEEF,
                size: 4,
            }
        );

        // 8-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        let bytes = 0x0123_4567_89AB_CDEF_u64.to_le_bytes();
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.phys_addr = 0x0A00_0008;
            run.__bindgen_anon_1.mmio.len = 8;
            run.__bindgen_anon_1.mmio.is_write = 1;
            run.__bindgen_anon_1.mmio.data.copy_from_slice(&bytes);
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0x0A00_0008,
                data: 0x0123_4567_89AB_CDEF,
                size: 8,
            }
        );
    }

    #[test]
    fn test_exit_mmio_invalid_size() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.phys_addr = 0x0A00_0000;
            run.__bindgen_anon_1.mmio.len = 3;
            run.__bindgen_anon_1.mmio.is_write = 1;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unknown {
                code: -1,
                source: ExitSource::Internal,
            }
        );
    }

    #[test]
    fn test_exit_system_event_shutdown() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_SYSTEM_EVENT;
        // SAFETY: exit_reason is KVM_EXIT_SYSTEM_EVENT, so system_event union is active.
        unsafe {
            run.__bindgen_anon_1.system_event.type_ = 1; // KVM_SYSTEM_EVENT_SHUTDOWN
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::CleanShutdown
        );
    }

    #[test]
    fn test_exit_system_event_reboot() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_SYSTEM_EVENT;
        // SAFETY: exit_reason is KVM_EXIT_SYSTEM_EVENT, so system_event union is active.
        unsafe {
            run.__bindgen_anon_1.system_event.type_ = 2; // KVM_SYSTEM_EVENT_RESET
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Reboot
        );
    }

    #[test]
    fn test_exit_system_event_unknown() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_SYSTEM_EVENT;
        // SAFETY: exit_reason is KVM_EXIT_SYSTEM_EVENT, so system_event union is active.
        unsafe {
            run.__bindgen_anon_1.system_event.type_ = 99;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unknown {
                code: 99,
                source: ExitSource::Hypervisor,
            }
        );
    }

    #[test]
    fn test_exit_unknown() {
        let mut run = make_kvm_run();
        run.exit_reason = 9999;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unknown {
                code: 9999,
                source: ExitSource::Hypervisor,
            }
        );
    }
}
