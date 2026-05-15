// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used)]

use crate::{EntropyError, EntropySource, Rng};
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_virtio::{
    DEVICE_ID_RNG, Descriptor, QueueView, QueueViolation, RngState, VIRTIO_F_VERSION_1,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, VirtioDevice,
};
use bytemuck::Zeroable;

const MEM_SIZE: usize = TEST_RAM_SIZE;

fn make_test_memory() -> TestMmap {
    test_mmap(MEM_SIZE)
}

fn setup_queue(state: &mut RngState) {
    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;
}

struct FailingEntropy;

impl EntropySource for FailingEntropy {
    fn fill(&mut self, _dst: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError)
    }
}

// =============================================================================
// Identity
// =============================================================================

#[test]
fn test_device_id_and_features() {
    let rng = Rng::default();
    assert_eq!(VirtioDevice::<VmState<'_>>::device_id(&rng), DEVICE_ID_RNG);
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&rng), 1);
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_features(&rng),
        VIRTIO_F_VERSION_1
    );
}

// =============================================================================
// Basic operation
// =============================================================================

#[test]
fn test_rng_fills_writable_buffer() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    let desc = Descriptor {
        addr: 0x3000,
        len: 32,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 1);

    // Verify used ring reports correct bytes written
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 32);
}

#[test]
fn test_rng_returns_correct_bytes_written() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    let used_id: u32 = vm.read_obj(0x2004u64).unwrap();
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_id, 0);
    assert_eq!(used_len, 64);
}

#[test]
fn test_rng_empty_queue_is_noop() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);
    // Don't add any descriptors to avail ring

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 0);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn entropy_source_failure_is_a_device_error() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    let canary = [0xA5u8; 32];
    {
        let gw = vm.gpa_write(0x3000, canary.len()).unwrap();
        gw.write_from(&canary);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(canary.len()).unwrap(),
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::with_entropy(FailingEntropy);
    let err = QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        err,
        QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_RNG,
            operation: "entropy fill",
        }
    ));
    let observed = vm.gpa_read(0x3000, canary.len()).unwrap().to_vec();
    assert_eq!(observed.as_slice(), &canary);
    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

// =============================================================================
// Multiple descriptors
// =============================================================================

#[test]
fn test_rng_multiple_descriptors() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    // 3 independent writable descriptors
    for i in 0u16..3 {
        let desc = Descriptor {
            addr: 0x3000 + u64::from(i) * 0x100,
            len: 16,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        vm.write_obj(u64::from(i) * 16, &desc).unwrap();
        vm.write_obj(0x1004 + u64::from(i) * 2, &i).unwrap();
    }
    vm.write_obj(0x1002u64, &3u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 3);
    assert_eq!(state.queues[0].last_used_idx, 3);

    // Each used entry should show 16 bytes written
    for i in 0u64..3 {
        let used_len: u32 = vm.read_obj(0x2004 + i * 8 + 4).unwrap();
        assert_eq!(used_len, 16);
    }
}

#[test]
fn test_rng_chained_writable_descriptors() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    // 2 chained writable descriptors: 32 + 48 = 80 bytes total
    let desc0 = Descriptor {
        addr: 0x3000,
        len: 32,
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: 48,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();
    vm.write_obj(0x0010u64, &desc1).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 80);
}

#[test]
fn test_rng_readable_descriptor_skipped() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    // Readable descriptor (no WRITE flag) is a queue-schema violation for RNG.
    let desc = Descriptor {
        addr: 0x3000,
        len: 32,
        flags: 0, // readable
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    let err = QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap_err();
    assert!(matches!(
        err,
        QueueViolation::DescriptorUnexpectedReadable { head_index: 0 }
    ));

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn test_rng_malformed_chain_does_not_write_guest_memory() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    let canary = [0xA5u8; 32];
    {
        let gw = vm.gpa_write(0x3000, canary.len()).unwrap();
        gw.write_from(&canary);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(canary.len()).unwrap(),
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 99,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    assert!(
        QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| rng
            .process_queue(0, view),)
        .unwrap()
        .is_err()
    );
    let observed = vm.gpa_read(0x3000, canary.len()).unwrap().to_vec();
    assert_eq!(observed.as_slice(), &canary);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn test_rng_fills_large_descriptor() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    // Descriptor with len=512 — zero-copy fills the full buffer directly
    let desc = Descriptor {
        addr: 0x3000,
        len: 512,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    // Zero-copy: getrandom fills the full descriptor buffer directly.
    // No intermediate 256-byte cap — the entire 512-byte buffer is filled.
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 512);
}

// =============================================================================
// Regression: RNG must cap per-descriptor allocation
// =============================================================================
//
// `lib.rs:43` does `let n = slice.len as usize; let mut buf = vec![0u8; n]`
// with no cap. A guest-controlled `slice.len` can force a 4 GiB allocation.
// Post-fix (D2): the writable descriptor path must apply a structural
// cap — either via a chunked write API or a capped `guest_write`.

#[test]
fn rng_caps_oversized_writable_descriptor() {
    const BIG_MEM: usize = TEST_RAM_SIZE;
    const DESC_DATA_GPA: u64 = 0x8000;
    const OVERSIZED_LEN: u32 = 1_572_864; // 1.5 MiB

    let mmap = test_mmap(BIG_MEM);
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: RngState = Zeroable::zeroed();
    setup_queue(&mut state);

    let desc = Descriptor {
        addr: DESC_DATA_GPA,
        len: OVERSIZED_LEN,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut rng = Rng::default();
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        rng.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    // TODO(codex): cap value depends on D2 — likely a new constant like
    // `MAX_RNG_DESC_BYTES` or a shared writable descriptor cap. Here we assert
    // only that it is strictly less than the attacker-sized descriptor.
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert!(
        used_len < OVERSIZED_LEN,
        "RNG must not fill {OVERSIZED_LEN} bytes in one descriptor; reported {used_len}",
    );
}
