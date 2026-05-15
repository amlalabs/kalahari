// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `x86_64` KVM vCPU exit decoding.
//!
//! Maps KVM exit reasons to the architecture-neutral `VcpuExit` enum.
//! On `x86_64`, this includes PIO (port I/O), MMIO, HLT, and shutdown exits.

use amla_core::{ExitSource, VcpuExit};
use kvm_bindings::kvm_run;

/// Decode a KVM vCPU exit into the common `VcpuExit` enum.
///
/// Maps `kvm_run` `exit_reason` + io/mmio unions:
/// - `KVM_EXIT_IO`: Port I/O (in/out) with port, size, and data
/// - `KVM_EXIT_MMIO`: Memory-mapped I/O with address, size, and data
/// - `KVM_EXIT_HLT`: CPU halt instruction
/// - `KVM_EXIT_SHUTDOWN`: Triple fault — always `VcpuExit::Unrecoverable`
/// - Other: `VcpuExit::Unknown(exit_reason)`
///
/// # Safety
///
/// The `kvm_run` pointer must be valid and from a completed `KVM_RUN` ioctl.
/// The `kvm_run_ptr` is the raw pointer to the mmap'd `kvm_run` region, needed
/// for reading IO data at `data_offset`. `kvm_run_size` must be the size (in
/// bytes) of that mmap region, as returned by `KVM_GET_VCPU_MMAP_SIZE`.
#[allow(clippy::cast_possible_truncation)] // data_offset: u64→usize on 64-bit
pub fn map_exit(kvm_run: &kvm_run, kvm_run_ptr: *const u8, kvm_run_size: usize) -> VcpuExit {
    match kvm_run.exit_reason {
        kvm_bindings::KVM_EXIT_HLT => VcpuExit::Halt,
        kvm_bindings::KVM_EXIT_SHUTDOWN => VcpuExit::Unrecoverable,
        kvm_bindings::KVM_EXIT_IO => {
            // SAFETY: exit_reason == KVM_EXIT_IO guarantees io union variant is active
            let io = unsafe { &kvm_run.__bindgen_anon_1.io };
            let direction = u32::from(io.direction);
            let Some(io_size) = PioSize::new(io.size) else {
                log::warn!(
                    "IO exit with unsupported size {} on port {:#x}",
                    io.size,
                    io.port
                );
                return VcpuExit::Unknown {
                    code: -1,
                    source: ExitSource::Internal,
                };
            };
            if direction == kvm_bindings::KVM_EXIT_IO_IN {
                return VcpuExit::IoIn {
                    port: io.port,
                    size: io_size.bytes(),
                };
            }
            if direction != kvm_bindings::KVM_EXIT_IO_OUT {
                log::warn!(
                    "IO exit with unsupported direction {} on port {:#x}",
                    io.direction,
                    io.port
                );
                return VcpuExit::Unknown {
                    code: -1,
                    source: ExitSource::Internal,
                };
            }
            // Reject any data_offset/size combination that would read past
            // the end of the kvm_run mmap. KVM is expected to set a valid
            // offset, but this is a shared memory region the guest can
            // influence, so we bounds-check defensively — matching the
            // write path in apply_response_to_kvm_run.
            let Ok(data_offset) = usize::try_from(io.data_offset) else {
                log::warn!("IO out: data_offset {} out of range", io.data_offset);
                return VcpuExit::Unknown {
                    code: -1,
                    source: ExitSource::Internal,
                };
            };
            let read_size = io_size.bytes_usize();
            if data_offset
                .checked_add(read_size)
                .is_none_or(|end| end > kvm_run_size)
            {
                log::warn!(
                    "IO out: data_offset {data_offset} + size {read_size} exceeds kvm_run {kvm_run_size}"
                );
                return VcpuExit::Unknown {
                    code: -1,
                    source: ExitSource::Internal,
                };
            }
            let data_ptr = kvm_run_ptr.wrapping_add(data_offset);
            // SAFETY: bounds checked above: data_offset + read_size <= kvm_run_size.
            let data = unsafe { io_size.read_unchecked(data_ptr) };
            VcpuExit::IoOut {
                port: io.port,
                data,
                size: io_size.bytes(),
            }
        }
        kvm_bindings::KVM_EXIT_MMIO => {
            // SAFETY: exit_reason == KVM_EXIT_MMIO guarantees mmio union variant is active
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
        other => VcpuExit::Unknown {
            code: i64::from(other),
            source: ExitSource::Hypervisor,
        },
    }
}

#[derive(Clone, Copy)]
enum PioSize {
    One,
    Two,
    Four,
}

impl PioSize {
    const fn new(size: u8) -> Option<Self> {
        match size {
            1 => Some(Self::One),
            2 => Some(Self::Two),
            4 => Some(Self::Four),
            _ => None,
        }
    }

    const fn bytes(self) -> u8 {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    const fn bytes_usize(self) -> usize {
        match self {
            Self::One => 1,
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    unsafe fn read_unchecked(self, data_ptr: *const u8) -> u32 {
        match self {
            // SAFETY: caller guarantees enough readable bytes for this PIO size.
            Self::One => u32::from(unsafe { *data_ptr }),
            // SAFETY: caller guarantees enough readable bytes; unaligned source is allowed.
            Self::Two => u32::from(unsafe { std::ptr::read_unaligned(data_ptr.cast::<u16>()) }),
            // SAFETY: caller guarantees enough readable bytes; unaligned source is allowed.
            Self::Four => unsafe { std::ptr::read_unaligned(data_ptr.cast::<u32>()) },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn io_dir_in() -> u8 {
        u8::try_from(kvm_bindings::KVM_EXIT_IO_IN).unwrap()
    }
    fn io_dir_out() -> u8 {
        u8::try_from(kvm_bindings::KVM_EXIT_IO_OUT).unwrap()
    }

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
    fn test_exit_io_in_1byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        run.__bindgen_anon_1.io.direction = io_dir_in();
        run.__bindgen_anon_1.io.port = 0x3F8;
        run.__bindgen_anon_1.io.size = 1;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoIn {
                port: 0x3F8,
                size: 1,
            }
        );
    }

    #[test]
    fn test_exit_io_in_2byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        run.__bindgen_anon_1.io.direction = io_dir_in();
        run.__bindgen_anon_1.io.port = 0xCF8;
        run.__bindgen_anon_1.io.size = 2;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoIn {
                port: 0xCF8,
                size: 2,
            }
        );
    }

    #[test]
    fn test_exit_io_in_4byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        run.__bindgen_anon_1.io.direction = io_dir_in();
        run.__bindgen_anon_1.io.port = 0xCFC;
        run.__bindgen_anon_1.io.size = 4;
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoIn {
                port: 0xCFC,
                size: 4,
            }
        );
    }

    #[test]
    fn test_exit_io_in_invalid_size_rejected() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        run.__bindgen_anon_1.io.direction = io_dir_in();
        run.__bindgen_anon_1.io.port = 0x3F8;
        run.__bindgen_anon_1.io.size = 3;
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
    fn test_exit_io_invalid_direction_rejected() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        run.__bindgen_anon_1.io.direction = 42;
        run.__bindgen_anon_1.io.port = 0x3F8;
        run.__bindgen_anon_1.io.size = 1;
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
    fn test_exit_io_out_1byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        let ptr = (&raw const *run).cast::<u8>();
        // SAFETY: exit_reason is KVM_EXIT_IO, so the io union variant is active.
        // data_offset points within the kvm_run allocation.
        unsafe {
            run.__bindgen_anon_1.io.direction = io_dir_out();
            run.__bindgen_anon_1.io.port = 0x3F8;
            run.__bindgen_anon_1.io.size = 1;
            // data_offset points within the kvm_run struct; use offset of io.data_offset
            // area. We place data right after the io union fields — use a known safe offset.
            let data_offset = usize::try_from(run.__bindgen_anon_1.io.data_offset).unwrap();
            // Write test byte at data_offset within the struct
            let data_ptr = ptr.wrapping_add(data_offset).cast_mut();
            *data_ptr = 0x41; // 'A'
        }
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoOut {
                port: 0x3F8,
                data: 0x41,
                size: 1,
            }
        );
    }

    #[test]
    fn test_exit_io_out_2byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        let ptr = (&raw const *run).cast::<u8>();
        // SAFETY: exit_reason is KVM_EXIT_IO, so the io union variant is active.
        unsafe {
            run.__bindgen_anon_1.io.direction = io_dir_out();
            run.__bindgen_anon_1.io.port = 0xCF8;
            run.__bindgen_anon_1.io.size = 2;
            let data_offset = usize::try_from(run.__bindgen_anon_1.io.data_offset).unwrap();
            let data_ptr = ptr.wrapping_add(data_offset).cast_mut();
            // Write 0xBEEF in little-endian
            std::ptr::write_unaligned(data_ptr.cast::<u16>(), 0xBEEF_u16);
        }
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoOut {
                port: 0xCF8,
                data: 0xBEEF,
                size: 2,
            }
        );
    }

    #[test]
    fn test_exit_io_out_4byte() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        let ptr = (&raw const *run).cast::<u8>();
        // SAFETY: exit_reason is KVM_EXIT_IO, so the io union variant is active.
        unsafe {
            run.__bindgen_anon_1.io.direction = io_dir_out();
            run.__bindgen_anon_1.io.port = 0xCFC;
            run.__bindgen_anon_1.io.size = 4;
            let data_offset = usize::try_from(run.__bindgen_anon_1.io.data_offset).unwrap();
            let data_ptr = ptr.wrapping_add(data_offset).cast_mut();
            std::ptr::write_unaligned(data_ptr.cast::<u32>(), 0xDEAD_BEEF_u32);
        }
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::IoOut {
                port: 0xCFC,
                data: 0xDEAD_BEEF,
                size: 4,
            }
        );
    }

    #[test]
    fn test_exit_mmio_read() {
        for (size, addr) in [
            (1u32, 0xFEE0_0000u64),
            (2, 0xFEE0_0010),
            (4, 0xFEE0_0020),
            (8, 0xFEE0_0030),
        ] {
            let mut run = make_kvm_run();
            run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
            run.__bindgen_anon_1.mmio.phys_addr = addr;
            run.__bindgen_anon_1.mmio.len = size;
            run.__bindgen_anon_1.mmio.is_write = 0;
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
        run.__bindgen_anon_1.mmio.phys_addr = 0xD000_0000;
        run.__bindgen_anon_1.mmio.len = 1;
        run.__bindgen_anon_1.mmio.is_write = 1;
        // SAFETY: struct is zeroed; indexing into union data array requires unsafe
        unsafe {
            run.__bindgen_anon_1.mmio.data[0] = 0xAB;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0xD000_0000,
                data: 0xAB,
                size: 1
            }
        );

        // 2-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        run.__bindgen_anon_1.mmio.phys_addr = 0xD000_0002;
        run.__bindgen_anon_1.mmio.len = 2;
        run.__bindgen_anon_1.mmio.is_write = 1;
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.data[0] = 0xEF;
            run.__bindgen_anon_1.mmio.data[1] = 0xBE;
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0xD000_0002,
                data: 0xBEEF,
                size: 2
            }
        );

        // 4-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        run.__bindgen_anon_1.mmio.phys_addr = 0xD000_0004;
        run.__bindgen_anon_1.mmio.len = 4;
        run.__bindgen_anon_1.mmio.is_write = 1;
        let bytes = 0xDEAD_BEEF_u32.to_le_bytes();
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.data[..4].copy_from_slice(&bytes);
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0xD000_0004,
                data: 0xDEAD_BEEF,
                size: 4
            }
        );

        // 8-byte write
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        run.__bindgen_anon_1.mmio.phys_addr = 0xD000_0008;
        run.__bindgen_anon_1.mmio.len = 8;
        run.__bindgen_anon_1.mmio.is_write = 1;
        let bytes = 0x0123_4567_89AB_CDEFu64.to_le_bytes();
        // SAFETY: exit_reason is KVM_EXIT_MMIO, so the mmio union variant is active.
        unsafe {
            run.__bindgen_anon_1.mmio.data.copy_from_slice(&bytes);
        }
        let ptr = (&raw const *run).cast::<u8>();
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::MmioWrite {
                addr: 0xD000_0008,
                data: 0x0123_4567_89AB_CDEF,
                size: 8
            }
        );
    }

    #[test]
    fn test_exit_io_out_oob_data_offset_rejected() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        let ptr = (&raw const *run).cast::<u8>();
        run.__bindgen_anon_1.io.direction = io_dir_out();
        run.__bindgen_anon_1.io.port = 0x3F8;
        run.__bindgen_anon_1.io.size = 4;
        // data_offset + size walks past the end of the mmap region.
        run.__bindgen_anon_1.io.data_offset =
            u64::try_from(std::mem::size_of::<kvm_run>()).unwrap() - 2;
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unknown {
                code: -1,
                source: ExitSource::Internal,
            }
        );
    }

    #[test]
    fn test_exit_io_out_data_offset_overflow_rejected() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_IO;
        let ptr = (&raw const *run).cast::<u8>();
        run.__bindgen_anon_1.io.direction = io_dir_out();
        run.__bindgen_anon_1.io.port = 0x3F8;
        run.__bindgen_anon_1.io.size = 4;
        // data_offset = u64::MAX so checked_add(4) overflows.
        run.__bindgen_anon_1.io.data_offset = u64::MAX;
        assert_eq!(
            map_exit(&run, ptr, std::mem::size_of::<kvm_run>()),
            VcpuExit::Unknown {
                code: -1,
                source: ExitSource::Internal,
            }
        );
    }

    #[test]
    fn test_exit_mmio_invalid_size() {
        let mut run = make_kvm_run();
        run.exit_reason = kvm_bindings::KVM_EXIT_MMIO;
        run.__bindgen_anon_1.mmio.phys_addr = 0xD000_0000;
        run.__bindgen_anon_1.mmio.len = 3;
        run.__bindgen_anon_1.mmio.is_write = 1;
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
