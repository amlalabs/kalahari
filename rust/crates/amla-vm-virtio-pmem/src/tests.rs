// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used)]

use crate::Pmem;
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_virtio::{
    DEVICE_ID_PMEM, Descriptor, PmemState, QueueView, QueueViolation, VIRTIO_F_VERSION_1,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, VirtioDevice,
};
use bytemuck::Zeroable;

const MEM_SIZE: usize = TEST_RAM_SIZE;

fn make_test_memory() -> TestMmap {
    test_mmap(MEM_SIZE)
}

fn setup_queue(state: &mut PmemState) {
    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;
}

fn setup_single_request(vm: &VmState<'_>, request_type: u32, request_len: u32, response_len: u32) {
    vm.write_obj(0x3000u64, &request_type).unwrap();
    let desc0 = Descriptor {
        addr: 0x3000,
        len: request_len,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();

    let desc1 = Descriptor {
        addr: 0x4000,
        len: response_len,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0010u64, &desc1).unwrap();

    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();
}

// =============================================================================
// Identity
// =============================================================================

#[test]
fn test_device_id_and_features() {
    let pmem = Pmem;
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_id(&pmem),
        DEVICE_ID_PMEM
    );
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&pmem), 1);
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_features(&pmem),
        VIRTIO_F_VERSION_1
    );
}

// =============================================================================
// Flush request
// =============================================================================

#[test]
fn test_flush_request_returns_ok() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: PmemState = Zeroable::zeroed();
    setup_queue(&mut state);

    setup_single_request(&vm, 0, 4, 4);

    let mut pmem = Pmem;
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        pmem.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 1);

    // Response should be VIRTIO_PMEM_RESP_TYPE_OK (0)
    let resp: u32 = vm.read_obj(0x4000u64).unwrap();
    assert_eq!(resp, 0);

    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 4);
}

#[test]
fn test_unknown_request_returns_error_response() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: PmemState = Zeroable::zeroed();
    setup_queue(&mut state);
    setup_single_request(&vm, 1, 4, 4);

    let mut pmem = Pmem;
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        pmem.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 1);
    let resp: u32 = vm.read_obj(0x4000u64).unwrap();
    assert_eq!(resp, 1);
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 4);
}

#[test]
fn test_multiple_flush_requests() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: PmemState = Zeroable::zeroed();
    setup_queue(&mut state);

    // 3 independent flush request chains
    for i in 0u16..3 {
        let base_desc = u64::from(i) * 32; // 2 descriptors per chain, 16 bytes each
        let data_gpa = 0x3000 + u64::from(i) * 0x100;
        let resp_gpa = 0x3000 + u64::from(i) * 0x100 + 0x80;

        // Readable: request type
        vm.write_obj(data_gpa, &0u32).unwrap();
        let desc_r = Descriptor {
            addr: data_gpa,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: i * 2 + 1,
        };
        vm.write_obj(base_desc, &desc_r).unwrap();

        // Writable: response
        let desc_w = Descriptor {
            addr: resp_gpa,
            len: 4,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        };
        vm.write_obj(base_desc + 16, &desc_w).unwrap();

        // Avail ring entry: head = i*2
        let head = i * 2;
        vm.write_obj(0x1004 + u64::from(i) * 2, &head).unwrap();
    }
    vm.write_obj(0x1002u64, &3u16).unwrap();

    let mut pmem = Pmem;
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        pmem.process_queue(0, view)
    })
    .unwrap()
    .unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 3);
    assert_eq!(state.queues[0].last_used_idx, 3);

    // All 3 responses should be OK (0)
    for i in 0u16..3 {
        let resp_gpa = 0x3000 + u64::from(i) * 0x100 + 0x80;
        let resp: u32 = vm.read_obj(resp_gpa).unwrap();
        assert_eq!(resp, 0);
    }
}

#[test]
fn test_writable_only_no_readable() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: PmemState = Zeroable::zeroed();
    setup_queue(&mut state);

    // Single writable descriptor, no readable (no request type)
    let desc = Descriptor {
        addr: 0x4000,
        len: 4,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut pmem = Pmem;
    assert_eq!(
        QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
            pmem.process_queue(0, view)
        },)
        .unwrap()
        .unwrap_err(),
        QueueViolation::DescriptorReadableCapacityTooSmall {
            head_index: 0,
            required: 4,
            available: 0,
        }
    );

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn test_small_writable_descriptor() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: PmemState = Zeroable::zeroed();
    setup_queue(&mut state);

    setup_single_request(&vm, 0, 4, 2);

    let mut pmem = Pmem;
    assert_eq!(
        QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
            pmem.process_queue(0, view)
        },)
        .unwrap()
        .unwrap_err(),
        QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index: 0,
            required: 4,
            available: 2,
        }
    );

    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 0);
}
