// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Unit tests for virtio queue API.

use crate::queue::QueueView;
use crate::{
    CONSOLE_PENDING_CTRL_CAPACITY, ConsoleControlState, Descriptor, QueueState, QueueViolation,
    ReadCap, VIRTIO_F_EVENT_IDX, VIRTIO_F_INDIRECT_DESC, VIRTIO_F_VERSION_1, VIRTQ_DESC_F_INDIRECT,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, VRING_AVAIL_F_NO_INTERRUPT,
};
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, test_mmap};
use bytemuck::Zeroable;
use std::num::NonZeroU32;

/// Generous cap for test I/O — every test payload fits in 64 KiB.
const TEST_READ_CAP: ReadCap = ReadCap::new(NonZeroU32::new(64 * 1024).unwrap());
// =============================================================================
// Test Memory Helpers
// =============================================================================

/// RAM size for queue tests.
const RAM_SIZE: usize = TEST_RAM_SIZE;

/// Create a test mmap with a valid `VmState` header and RAM section.
fn make_test_buf() -> TestMmap {
    test_mmap(RAM_SIZE)
}

/// Create a `VmState` view over the test mmap.
fn make_vm(mmap: &TestMmap) -> VmState<'_> {
    amla_core::vm_state::make_test_vmstate(mmap, 0)
}

fn assert_popped_chain_violation<M: GuestMemory>(
    chain: crate::PoppedDescriptorChain<'_, '_, M>,
    matches_expected: impl FnOnce(QueueViolation) -> bool,
    expected: &str,
) {
    match chain.into_split() {
        Err(v) if matches_expected(v) => {}
        Err(v) => panic!("expected {expected}, got {v:?}"),
        Ok(_) => panic!("expected {expected}, got valid chain"),
    }
}

// =============================================================================
// Queue Setup Helpers
// =============================================================================

/// Standard queue layout for testing.
/// Places rings at fixed GPA offsets within guest RAM.
struct TestQueue {
    queue_size: u16,
    desc_gpa: u64,
    avail_gpa: u64,
    used_gpa: u64,
}

impl TestQueue {
    fn new(queue_size: u16) -> Self {
        Self {
            queue_size,
            desc_gpa: 0x0000,
            avail_gpa: 0x1000,
            used_gpa: 0x2000,
        }
    }

    fn make_state(&self) -> QueueState {
        QueueState {
            size: self.queue_size,
            ready: 1,
            pad0: 0,
            desc_addr: self.desc_gpa,
            avail_addr: self.avail_gpa,
            used_addr: self.used_gpa,
            last_avail_idx: 0,
            last_used_idx: 0,
            generation: 0,
        }
    }

    fn write_desc(&self, vm: &VmState<'_>, idx: u16, desc: &Descriptor) {
        let gpa = self.desc_gpa + u64::from(idx) * 16;
        vm.write_obj(gpa, desc).unwrap();
    }

    fn write_avail_idx(&self, vm: &VmState<'_>, idx: u16) {
        vm.write_obj(self.avail_gpa + 2, &idx).unwrap();
    }

    fn write_avail_ring(&self, vm: &VmState<'_>, ring_idx: u16, desc_idx: u16) {
        let gpa = self.avail_gpa + 4 + u64::from(ring_idx) * 2;
        vm.write_obj(gpa, &desc_idx).unwrap();
    }

    fn write_avail_flags(&self, vm: &VmState<'_>, flags: u16) {
        vm.write_obj(self.avail_gpa, &flags).unwrap();
    }

    fn read_used_idx(&self, vm: &VmState<'_>) -> u16 {
        vm.read_obj(self.used_gpa + 2).unwrap()
    }

    fn read_used_entry(&self, vm: &VmState<'_>, ring_idx: u16) -> (u32, u32) {
        let gpa = self.used_gpa + 4 + u64::from(ring_idx) * 8;
        let id: u32 = vm.read_obj(gpa).unwrap();
        let len: u32 = vm.read_obj(gpa + 4).unwrap();
        (id, len)
    }

    fn write_used_event(&self, vm: &VmState<'_>, val: u16) {
        let gpa = self.avail_gpa + 4 + u64::from(self.queue_size) * 2;
        vm.write_obj(gpa, &val).unwrap();
    }

    fn read_avail_event(&self, vm: &VmState<'_>) -> u16 {
        let gpa = self.used_gpa + 4 + u64::from(self.queue_size) * 8;
        vm.read_obj(gpa).unwrap()
    }

    fn setup_single_desc(
        &self,
        vm: &VmState<'_>,
        desc_idx: u16,
        data: &[u8],
        writable: bool,
    ) -> u64 {
        let data_gpa = 0x3000 + u64::from(desc_idx) * 256;
        if !data.is_empty() {
            {
                let __gw = vm.gpa_write(data_gpa, data.len()).unwrap();
                __gw.write_from(data);
            };
        }
        let flags = if writable { VIRTQ_DESC_F_WRITE } else { 0 };
        self.write_desc(
            vm,
            desc_idx,
            &Descriptor {
                addr: data_gpa,
                len: u32::try_from(data.len()).unwrap(),
                flags,
                next: 0,
            },
        );
        data_gpa
    }

    fn publish_avail(&self, vm: &VmState<'_>, count: u16) {
        for i in 0..count {
            self.write_avail_ring(vm, i, i);
        }
        self.write_avail_idx(vm, count);
    }
}

#[derive(Clone)]
struct PermissiveRead(Vec<u8>);

impl GuestRead for PermissiveRead {
    fn read_to(&self, buf: &mut [u8]) {
        buf.copy_from_slice(&self.0);
    }

    fn to_vec(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn read_byte(&self, offset: usize) -> u8 {
        self.0[offset]
    }

    fn len(&self) -> usize {
        self.0.len()
    }

    fn offset(&self, off: usize, len: usize) -> Self {
        Self(self.0[off..off + len].to_vec())
    }

    fn extend_vec(&self, vec: &mut Vec<u8>) {
        vec.extend_from_slice(&self.0);
    }
}

#[derive(Clone)]
struct PermissiveWrite(usize);

impl GuestWrite for PermissiveWrite {
    fn write_from(&self, _data: &[u8]) {}

    fn write_at(&self, _off: usize, _data: &[u8]) {}

    fn write_byte(&self, _offset: usize, _val: u8) {}

    fn fill(&self, _val: u8) {}

    fn len(&self) -> usize {
        self.0
    }

    fn offset(self, _off: usize, len: usize) -> Self {
        Self(len)
    }
}

struct PermissiveMemory {
    u16_one_at: Option<u64>,
}

impl PermissiveMemory {
    fn with_u16_one_at(addr: u64) -> Self {
        Self {
            u16_one_at: Some(addr),
        }
    }
}

impl GuestMemory for PermissiveMemory {
    type Slice<'m>
        = PermissiveRead
    where
        Self: 'm;
    type SliceMut<'m>
        = PermissiveWrite
    where
        Self: 'm;

    fn gpa_read(&self, _addr: u64, len: usize) -> Result<Self::Slice<'_>, amla_core::VmmError> {
        Ok(PermissiveRead(vec![0; len]))
    }

    fn gpa_write(&self, _addr: u64, len: usize) -> Result<Self::SliceMut<'_>, amla_core::VmmError> {
        Ok(PermissiveWrite(len))
    }

    fn read_obj<T: bytemuck::Pod>(&self, _addr: u64) -> Result<T, amla_core::VmmError> {
        panic!("queue metadata must use typed little-endian scalar reads")
    }

    fn write_obj<T: bytemuck::NoUninit>(
        &self,
        _addr: u64,
        _val: &T,
    ) -> Result<(), amla_core::VmmError> {
        panic!("queue metadata must use typed little-endian scalar writes")
    }

    fn read_le_u16(&self, addr: u64) -> Result<u16, amla_core::VmmError> {
        Ok(u16::from(self.u16_one_at == Some(addr)))
    }

    fn read_le_u32(&self, _addr: u64) -> Result<u32, amla_core::VmmError> {
        Ok(0)
    }

    fn read_le_u64(&self, _addr: u64) -> Result<u64, amla_core::VmmError> {
        Ok(0)
    }

    fn write_le_u16(&self, _addr: u64, _val: u16) -> Result<(), amla_core::VmmError> {
        Ok(())
    }

    fn write_le_u32(&self, _addr: u64, _val: u32) -> Result<(), amla_core::VmmError> {
        Ok(())
    }

    fn write_le_u64(&self, _addr: u64, _val: u64) -> Result<(), amla_core::VmmError> {
        Ok(())
    }

    fn validate_read_range(&self, _addr: u64, _len: usize) -> Result<(), amla_core::VmmError> {
        Ok(())
    }

    fn validate_write_range(&self, _addr: u64, _len: usize) -> Result<(), amla_core::VmmError> {
        Ok(())
    }
}

// =============================================================================
// Basic Pop/Push Tests
// =============================================================================

#[test]
fn test_pop_empty_queue() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(view.pop().is_none());
}

#[test]
fn test_pop_faults_on_avail_idx_address_overflow() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    state.avail_addr = u64::MAX - 1;

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(matches!(
        view.pop_strict(),
        Err(QueueViolation::RingAddressOverflow {
            base,
            offset: 2,
        }) if base == u64::MAX - 1
    ));
}

#[test]
fn test_pop_faults_on_avail_ring_address_overflow() {
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    state.avail_addr = u64::MAX - 3;
    let memory = PermissiveMemory::with_u16_one_at(u64::MAX - 1);

    let mut view = QueueView::new(0, &mut state, &memory, VIRTIO_F_VERSION_1);
    assert!(matches!(
        view.pop_strict(),
        Err(QueueViolation::RingAddressOverflow {
            base,
            offset: 4,
        }) if base == u64::MAX - 3
    ));
}

#[test]
fn test_try_new_rejects_not_ready_queue() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    state.ready = 0;

    assert_eq!(
        QueueView::try_new(0, &mut state, &vm, VIRTIO_F_VERSION_1).err(),
        Some(QueueViolation::QueueNotReady)
    );
}

#[test]
fn test_try_new_rejects_invalid_queue_size() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(15);
    let mut state = tq.make_state();

    assert_eq!(
        QueueView::try_new(0, &mut state, &vm, VIRTIO_F_VERSION_1).err(),
        Some(QueueViolation::InvalidQueueSize { size: 15 })
    );
}

#[test]
fn test_pop_single_descriptor() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, b"hello", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().expect("should get a chain");
    assert_eq!(chain.head_index(), 0);

    let chain = chain.into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].len(), 5);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"hello"
    );

    view.push(chain.complete_zero()).unwrap();
    assert_eq!(tq.read_used_idx(&vm), 1);
    let (id, len) = tq.read_used_entry(&vm, 0);
    assert_eq!(id, 0);
    assert_eq!(len, 0);
    assert!(view.pop().is_none());
}

#[test]
fn test_pop_multiple_chains() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, b"first", false);
    tq.setup_single_desc(&vm, 1, b"second", false);
    tq.publish_avail(&vm, 2);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);

    let chain1 = view.pop().unwrap().into_readable().unwrap();
    assert_eq!(chain1.head_index(), 0);
    let slices1 = chain1.descriptors();
    assert_eq!(
        slices1[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"first"
    );
    view.push(chain1.complete_zero()).unwrap();

    let chain2 = view.pop().unwrap().into_readable().unwrap();
    assert_eq!(chain2.head_index(), 1);
    let slices2 = chain2.descriptors();
    assert_eq!(
        slices2[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"second"
    );
    view.push(chain2.complete_zero()).unwrap();

    assert!(view.pop().is_none());
    assert_eq!(tq.read_used_idx(&vm), 2);
    assert_eq!(state.last_avail_idx, 2);
    assert_eq!(state.last_used_idx, 2);
}

// =============================================================================
// Chained Descriptor Tests
// =============================================================================

#[test]
fn test_chained_descriptors() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let data_gpa0 = 0x3000u64;
    let data_gpa1 = 0x3100u64;
    let data_gpa2 = 0x3200u64;

    {
        let __gw = vm.gpa_write(data_gpa0, b"aaa".len()).unwrap();
        __gw.write_from(b"aaa");
    };
    {
        let __gw = vm.gpa_write(data_gpa1, b"bbb".len()).unwrap();
        __gw.write_from(b"bbb");
    };
    {
        let __gw = vm.gpa_write(data_gpa2, b"ccc".len()).unwrap();
        __gw.write_from(b"ccc");
    };

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: data_gpa0,
            len: 3,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    );
    tq.write_desc(
        &vm,
        1,
        &Descriptor {
            addr: data_gpa1,
            len: 3,
            flags: VIRTQ_DESC_F_NEXT,
            next: 2,
        },
    );
    tq.write_desc(
        &vm,
        2,
        &Descriptor {
            addr: data_gpa2,
            len: 3,
            flags: 0,
            next: 0,
        },
    );

    tq.write_avail_ring(&vm, 0, 0);
    tq.write_avail_idx(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap();
    assert_eq!(chain.head_index(), 0);

    let chain = chain.into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 3);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"aaa"
    );
    assert_eq!(
        slices[1].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"bbb"
    );
    assert_eq!(
        slices[2].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"ccc"
    );
}

#[test]
fn test_mixed_readable_writable_chain() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let data_gpa0 = 0x3000u64;
    let data_gpa1 = 0x3100u64;

    {
        let __gw = vm.gpa_write(data_gpa0, b"request".len()).unwrap();
        __gw.write_from(b"request");
    };

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: data_gpa0,
            len: 7,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    );
    tq.write_desc(
        &vm,
        1,
        &Descriptor {
            addr: data_gpa1,
            len: 64,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        },
    );

    tq.write_avail_ring(&vm, 0, 0);
    tq.write_avail_idx(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_split().unwrap();
    assert_eq!(chain.readable().len(), 1);
    assert_eq!(chain.writable().len(), 1);

    assert_eq!(
        chain.readable()[0]
            .guest_read(TEST_READ_CAP)
            .unwrap()
            .to_vec(),
        b"request"
    );

    let resp = b"response!";
    view.push_split_bytes(chain, resp).unwrap();

    let check = vm.gpa_read(data_gpa1, 9).unwrap().to_vec();
    assert_eq!(&check, b"response!");
}

// =============================================================================
// Writable Descriptor Tests
// =============================================================================

#[test]
fn test_writable_descriptor() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let data_gpa = tq.setup_single_desc(&vm, 0, &[0u8; 32], true);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_writable().unwrap();
    let slices = chain.descriptors();

    assert_eq!(slices.len(), 1);

    let data = b"written by device";
    assert_eq!(slices[0].len(), 32);
    view.push_writable_bytes(chain, data).unwrap();

    let read_buf = vm.gpa_read(data_gpa, data.len()).unwrap().to_vec();
    assert_eq!(&read_buf, data);
}

#[test]
fn test_writable_completion_rejects_oversized_used_len() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, &[0u8; 4], true);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_writable().unwrap();

    assert_eq!(
        chain.written_bytes(5).unwrap_err(),
        QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index: 0,
            required: 5,
            available: 4,
        }
    );

    view.push_writable_bytes(chain, &[1, 2, 3, 4]).unwrap();
    let (_id, len) = tq.read_used_entry(&vm, 0);
    assert_eq!(len, 4);
}

#[test]
fn test_writable_completion_rechecks_written_bytes_against_same_chain() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, &[0u8; 8], true);
    tq.setup_single_desc(&vm, 1, &[0u8; 4], true);
    tq.publish_avail(&vm, 2);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let larger_chain = view.pop().unwrap().into_writable().unwrap();
    let smaller_chain = view.pop().unwrap().into_writable().unwrap();

    assert_eq!(
        smaller_chain.written_bytes(8).unwrap_err(),
        QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index: 1,
            required: 8,
            available: 4,
        }
    );
    view.push(larger_chain.complete_zero()).unwrap();
}

#[test]
fn writable_completion_refuses_faulted_view_before_guest_write() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let data_gpa = tq.setup_single_desc(&vm, 0, &[0u8; 4], true);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_writable().unwrap();
    let prior = view.push_head(99, 0).unwrap_err();
    assert!(matches!(
        prior,
        QueueViolation::HeadIndexOutOfRange {
            index: 99,
            queue_size: 16,
        }
    ));

    let err = view.push_writable_bytes(chain, &[1, 2, 3, 4]).unwrap_err();

    assert_eq!(err, prior);
    assert_eq!(vm.gpa_read(data_gpa, 4).unwrap().to_vec(), [0, 0, 0, 0]);
    assert_eq!(tq.read_used_idx(&vm), 0);
}

// =============================================================================
// DescriptorRef Edge Cases
// =============================================================================

#[test]
fn test_guest_slice_read_larger_buffer() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, b"abc", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_readable().unwrap();
    let slices = chain.descriptors();

    let data = slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec();
    assert_eq!(data.len(), 3);
    assert_eq!(data, b"abc");
}

#[test]
fn test_guest_slice_write_truncation() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.setup_single_desc(&vm, 0, &[0u8; 4], true);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap().into_writable().unwrap();
    let data = b"0123456789";
    let n = chain.writable_len().min(data.len());
    assert_eq!(n, 4);
    view.push_writable_bytes(chain, &data[..n]).unwrap();
}

// =============================================================================
// Notification Suppression (Legacy Flags)
// =============================================================================

#[test]
fn test_needs_notification_legacy_default() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(view.needs_notification().unwrap());
}

#[test]
fn test_needs_notification_legacy_suppressed() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.write_avail_flags(&vm, VRING_AVAIL_F_NO_INTERRUPT);

    let view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(!view.needs_notification().unwrap());
}

// =============================================================================
// Notification Suppression (EVENT_IDX)
// =============================================================================

#[test]
fn test_needs_notification_event_idx() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_EVENT_IDX;

    tq.write_used_event(&vm, 0);
    tq.setup_single_desc(&vm, 0, b"x", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap().into_readable().unwrap();
    view.push(chain.complete_zero()).unwrap();

    assert!(view.needs_notification().unwrap());
}

#[test]
fn test_needs_notification_event_idx_address_overflow() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    state.avail_addr = u64::MAX - 3;

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_EVENT_IDX;
    let view = QueueView::new(0, &mut state, &vm, features);

    assert_eq!(
        view.needs_notification(),
        Err(QueueViolation::RingAddressOverflow {
            base: u64::MAX - 3,
            offset: 36,
        })
    );
}

#[test]
fn test_no_notification_event_idx_ahead() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_EVENT_IDX;

    tq.write_used_event(&vm, 5);
    tq.setup_single_desc(&vm, 0, b"x", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap().into_readable().unwrap();
    view.push(chain.complete_zero()).unwrap();

    assert!(!view.needs_notification().unwrap());
}

// =============================================================================
// EVENT_IDX: avail_event written on pop
// =============================================================================

#[test]
fn test_avail_event_written_on_pop() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_EVENT_IDX;

    tq.setup_single_desc(&vm, 0, b"x", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let _chain = view.pop().unwrap();

    let avail_event = tq.read_avail_event(&vm);
    assert_eq!(avail_event, 1);
}

#[test]
fn test_pop_faults_on_avail_event_address_overflow() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();
    state.used_addr = u64::MAX - 3;

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_EVENT_IDX;

    tq.setup_single_desc(&vm, 0, b"x", false);
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    assert!(matches!(
        view.pop_strict(),
        Err(QueueViolation::RingAddressOverflow {
            base,
            offset: 132,
        }) if base == u64::MAX - 3
    ));
}

// =============================================================================
// Indirect Descriptor Tests
// =============================================================================

#[test]
fn test_indirect_descriptor() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    let indirect_table_gpa = 0x4000u64;
    let data_gpa = 0x5000u64;

    {
        let __gw = vm.gpa_write(data_gpa, b"indirect_data".len()).unwrap();
        __gw.write_from(b"indirect_data");
    };

    let indirect_desc = Descriptor {
        addr: data_gpa,
        len: 13,
        flags: 0,
        next: 0,
    };
    vm.write_obj(indirect_table_gpa, &indirect_desc).unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: indirect_table_gpa,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.write_avail_ring(&vm, 0, 0);
    tq.write_avail_idx(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap();
    assert_eq!(chain.head_index(), 0);

    let chain = chain.into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 1);
    assert_eq!(slices[0].len(), 13);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"indirect_data"
    );
}

#[test]
fn test_indirect_multi_entry() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    let indirect_table_gpa = 0x4000u64;
    let data_gpa0 = 0x5000u64;
    let data_gpa1 = 0x5100u64;

    {
        let __gw = vm.gpa_write(data_gpa0, b"part1".len()).unwrap();
        __gw.write_from(b"part1");
    };
    {
        let __gw = vm.gpa_write(data_gpa1, b"part2".len()).unwrap();
        __gw.write_from(b"part2");
    };

    vm.write_obj(
        indirect_table_gpa,
        &Descriptor {
            addr: data_gpa0,
            len: 5,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    )
    .unwrap();
    vm.write_obj(
        indirect_table_gpa + 16,
        &Descriptor {
            addr: data_gpa1,
            len: 5,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: indirect_table_gpa,
            len: 32,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap().into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 2);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"part1"
    );
    assert_eq!(
        slices[1].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"part2"
    );
}

#[test]
fn test_indirect_non_sequential_chain() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    let indirect_table_gpa = 0x4000u64;
    let data_a = 0x5000u64;
    let data_b = 0x5100u64;
    let data_c = 0x5200u64;

    {
        let __gw = vm.gpa_write(data_a, b"AAAA".len()).unwrap();
        __gw.write_from(b"AAAA");
    };
    {
        let __gw = vm.gpa_write(data_b, b"BBBB".len()).unwrap();
        __gw.write_from(b"BBBB");
    };
    {
        let __gw = vm.gpa_write(data_c, b"CCCC".len()).unwrap();
        __gw.write_from(b"CCCC");
    };

    vm.write_obj(
        indirect_table_gpa,
        &Descriptor {
            addr: data_a,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 2,
        },
    )
    .unwrap();
    vm.write_obj(
        indirect_table_gpa + 16,
        &Descriptor {
            addr: data_b,
            len: 4,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();
    vm.write_obj(
        indirect_table_gpa + 32,
        &Descriptor {
            addr: data_c,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    )
    .unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: indirect_table_gpa,
            len: 48,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap().into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 3);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"AAAA"
    );
    assert_eq!(
        slices[1].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"CCCC"
    );
    assert_eq!(
        slices[2].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"BBBB"
    );
}

#[test]
fn test_indirect_stops_without_next_flag() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    let indirect_table_gpa = 0x4000u64;
    let data_a = 0x5000u64;
    let data_b = 0x5100u64;

    {
        let __gw = vm.gpa_write(data_a, b"first".len()).unwrap();
        __gw.write_from(b"first");
    };
    {
        let __gw = vm.gpa_write(data_b, b"second".len()).unwrap();
        __gw.write_from(b"second");
    };

    vm.write_obj(
        indirect_table_gpa,
        &Descriptor {
            addr: data_a,
            len: 5,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();
    vm.write_obj(
        indirect_table_gpa + 16,
        &Descriptor {
            addr: data_b,
            len: 6,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: indirect_table_gpa,
            len: 32,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap().into_readable().unwrap();
    let slices = chain.descriptors();
    assert_eq!(slices.len(), 1);
    assert_eq!(
        slices[0].guest_read(TEST_READ_CAP).unwrap().to_vec(),
        b"first"
    );
}

// =============================================================================
// Malicious Guest Tests
// =============================================================================

#[test]
fn test_indirect_not_negotiated() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1;

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x4000,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| {
            matches!(
                v,
                QueueViolation::IndirectDescriptorNotNegotiated { index: 0 }
            )
        },
        "IndirectDescriptorNotNegotiated",
    );
}

#[test]
fn test_indirect_bad_len() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x4000,
            len: 15,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| matches!(v, QueueViolation::IndirectTableInvalidLength { len: 15 }),
        "IndirectTableInvalidLength",
    );
}

#[test]
fn test_indirect_next_set() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x4000,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| matches!(v, QueueViolation::DescriptorNextAndIndirectSet { index: 0 }),
        "DescriptorNextAndIndirectSet",
    );
}

#[test]
fn test_descriptor_oob_address() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0xFFFF_0000,
            len: 256,
            flags: 0,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| {
            matches!(
                v,
                QueueViolation::DescriptorBufferOutOfRange {
                    addr: 0xFFFF_0000,
                    len: 256,
                }
            )
        },
        "DescriptorBufferOutOfRange",
    );
}

#[test]
fn test_descriptor_addr_overflow() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: u64::MAX - 10,
            len: 100,
            flags: 0,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| {
            matches!(
                v,
                QueueViolation::DescriptorBufferOutOfRange {
                    addr,
                    len: 100,
                } if addr == u64::MAX - 10
            )
        },
        "DescriptorBufferOutOfRange",
    );
}

#[test]
fn test_ring_address_overflow_pop() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state = QueueState {
        size: 16,
        ready: 1,
        pad0: 0,
        desc_addr: 0,
        avail_addr: u64::MAX,
        used_addr: 0,
        last_avail_idx: 0,
        last_used_idx: 0,
        generation: 0,
    };

    let mut view = QueueView::try_new(0, &mut state, &vm, VIRTIO_F_VERSION_1).unwrap();
    let res = view.pop_strict();
    let Err(violation) = res else {
        panic!("expected RingAddressOverflow violation, got Ok");
    };
    assert!(
        matches!(
            violation,
            QueueViolation::RingAddressOverflow {
                base: u64::MAX,
                offset: 2,
            }
        ),
        "expected RingAddressOverflow {{ base: u64::MAX, offset: 2 }}, got {violation:?}"
    );
    assert_eq!(view.violation(), Some(violation));
}

#[test]
fn test_ring_address_overflow_push() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state = QueueState {
        size: 16,
        ready: 1,
        pad0: 0,
        desc_addr: 0,
        avail_addr: 0x1000,
        used_addr: u64::MAX - 1,
        last_avail_idx: 0,
        last_used_idx: 0,
        generation: 0,
    };

    let mut view = QueueView::try_new(0, &mut state, &vm, VIRTIO_F_VERSION_1).unwrap();
    assert!(view.push_head(0, 0).is_err());
    match view.violation() {
        Some(QueueViolation::RingAddressOverflow { .. }) => {}
        other => panic!("expected RingAddressOverflow violation, got {other:?}"),
    }
}

#[test]
fn test_chain_cycle_protection() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(4);
    let mut state = tq.make_state();

    for i in 0..3u16 {
        tq.write_desc(
            &vm,
            i,
            &Descriptor {
                addr: 0x3000 + u64::from(i) * 256,
                len: 4,
                flags: VIRTQ_DESC_F_NEXT,
                next: (i + 1) % 3,
            },
        );
        {
            let __gw = vm
                .gpa_write(0x3000 + u64::from(i) * 256, b"data".len())
                .unwrap();
            __gw.write_from(b"data");
        };
    }
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| {
            matches!(
                v,
                QueueViolation::DescriptorChainTooLong {
                    head_index: 0,
                    queue_size: 4,
                }
            )
        },
        "DescriptorChainTooLong",
    );
}

#[test]
fn test_indirect_chain_cycle_protection() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    let features = VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC;

    let indirect_table_gpa = 0x4000u64;
    let data_a = 0x5000u64;
    let data_b = 0x5100u64;

    {
        let __gw = vm.gpa_write(data_a, b"aaaa".len()).unwrap();
        __gw.write_from(b"aaaa");
    };
    {
        let __gw = vm.gpa_write(data_b, b"bbbb".len()).unwrap();
        __gw.write_from(b"bbbb");
    };

    vm.write_obj(
        indirect_table_gpa,
        &Descriptor {
            addr: data_a,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
    )
    .unwrap();
    vm.write_obj(
        indirect_table_gpa + 16,
        &Descriptor {
            addr: data_b,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 0,
        },
    )
    .unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: indirect_table_gpa,
            len: 32,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, features);
    let chain = view.pop().unwrap();
    assert_popped_chain_violation(
        chain,
        |v| {
            matches!(
                v,
                QueueViolation::IndirectDescriptorChainTooLong { table_len: 2 }
            )
        },
        "IndirectDescriptorChainTooLong",
    );
}

#[test]
fn test_invalid_avail_index_jump() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.write_avail_idx(&vm, 100);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(view.pop().is_none());
    assert_eq!(
        view.violation(),
        Some(QueueViolation::AvailIndexJump {
            avail_idx: 100,
            last_avail_idx: 0,
            size: 16,
        })
    );
    assert_eq!(view.state().last_avail_idx, 0);
}

#[test]
fn test_invalid_descriptor_index_in_avail() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(16);
    let mut state = tq.make_state();

    tq.write_avail_ring(&vm, 0, 20);
    tq.write_avail_idx(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(view.pop().is_none());
    assert_eq!(
        view.violation(),
        Some(QueueViolation::DescriptorIndexOutOfRange {
            index: 20,
            queue_size: 16,
        })
    );
    assert_eq!(view.state().last_avail_idx, 0);
}

mod randomized_queue_fuzz {
    use super::*;
    use proptest::prelude::*;

    fn write_desc_le(vm: &VmState<'_>, desc_gpa: u64, idx: u16, desc: Descriptor) {
        let gpa = desc_gpa + u64::from(idx) * 16;
        vm.write_le_u64(gpa, desc.addr).unwrap();
        vm.write_le_u32(gpa + 8, desc.len).unwrap();
        vm.write_le_u16(gpa + 12, desc.flags).unwrap();
        vm.write_le_u16(gpa + 14, desc.next).unwrap();
    }

    proptest! {
        #[test]
        fn queue_view_randomized_guest_state_never_panics(
            avail_idx in any::<u16>(),
            last_avail_idx in any::<u16>(),
            last_used_idx in any::<u16>(),
            avail_entries in proptest::collection::vec(0u16..16, 8),
            descriptors in proptest::collection::vec(
                (any::<u64>(), any::<u32>(), any::<u16>(), any::<u16>()),
                8,
            ),
            event_idx in any::<u16>(),
            avail_flags in any::<u16>(),
            enable_event_idx in any::<bool>(),
            enable_indirect in any::<bool>(),
        ) {
            let buf = make_test_buf();
            let vm = make_vm(&buf);
            let tq = TestQueue::new(8);
            let mut state = tq.make_state();
            state.last_avail_idx = last_avail_idx;
            state.last_used_idx = last_used_idx;

            for (idx, (addr, len, flags, next)) in descriptors.into_iter().enumerate() {
                write_desc_le(
                    &vm,
                    tq.desc_gpa,
                    u16::try_from(idx).unwrap(),
                    Descriptor { addr, len, flags, next },
                );
            }
            for (idx, desc_idx) in avail_entries.into_iter().enumerate() {
                tq.write_avail_ring(&vm, u16::try_from(idx).unwrap(), desc_idx);
            }
            tq.write_avail_idx(&vm, avail_idx);
            tq.write_used_event(&vm, event_idx);
            tq.write_avail_flags(&vm, avail_flags);

            let mut features = VIRTIO_F_VERSION_1;
            if enable_event_idx {
                features |= VIRTIO_F_EVENT_IDX;
            }
            if enable_indirect {
                features |= VIRTIO_F_INDIRECT_DESC;
            }

            {
                let mut view = QueueView::new(0, &mut state, &vm, features);
                for _ in 0..8 {
                    let Some(chain) = view.pop() else {
                        break;
                    };
                    let Ok(chain) = chain.into_split() else {
                        break;
                    };
                    if view.push(chain.complete_zero()).is_err() {
                        break;
                    }
                }
                match view.needs_notification() {
                    Ok(_) | Err(_) => {}
                }
            }

            let consumed = state.last_avail_idx.wrapping_sub(last_avail_idx);
            let published = state.last_used_idx.wrapping_sub(last_used_idx);
            prop_assert!(consumed <= 8);
            prop_assert!(published <= consumed);
            if avail_idx.wrapping_sub(last_avail_idx) > 8 {
                prop_assert_eq!(consumed, 0);
                prop_assert_eq!(published, 0);
            }
        }
    }
}

// =============================================================================
// Zero-Size Queue and Edge Cases
// =============================================================================

#[test]
fn test_zero_size_queue() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state = QueueState {
        size: 0,
        ready: 1,
        ..bytemuck::Zeroable::zeroed()
    };

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    assert!(view.pop().is_none());
    assert!(!view.needs_notification().unwrap());
}

fn console_ctrl_msg(id: u32, event: u16, value: u16) -> [u8; 8] {
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&id.to_le_bytes());
    msg[4..6].copy_from_slice(&event.to_le_bytes());
    msg[6..8].copy_from_slice(&value.to_le_bytes());
    msg
}

#[test]
fn test_console_control_state_is_idempotent() {
    let mut state = ConsoleControlState::zeroed();

    assert_eq!(CONSOLE_PENDING_CTRL_CAPACITY, 5);
    assert!(state.push_back(console_ctrl_msg(0, 1, 1))); // PORT_ADD(0)
    assert!(state.push_back(console_ctrl_msg(1, 1, 1))); // PORT_ADD(1)
    assert!(state.push_back(console_ctrl_msg(0, 1, 1))); // duplicate
    assert_eq!(state.len(), 2);

    assert!(state.push_back(console_ctrl_msg(0, 4, 1))); // CONSOLE_PORT(0)
    assert!(state.push_back(console_ctrl_msg(0, 6, 1))); // PORT_OPEN(0)
    assert!(state.push_back(console_ctrl_msg(1, 6, 1))); // PORT_OPEN(1)
    assert_eq!(state.len(), 5);
    assert!(!state.push_back(console_ctrl_msg(2, 6, 1))); // unsupported port

    assert_eq!(state.pop_front(), Some(console_ctrl_msg(0, 1, 1)));
    assert_eq!(state.pop_front(), Some(console_ctrl_msg(1, 1, 1)));
    assert_eq!(state.pop_front(), Some(console_ctrl_msg(0, 4, 1)));
    assert_eq!(state.pop_front(), Some(console_ctrl_msg(0, 6, 1)));
    assert_eq!(state.pop_front(), Some(console_ctrl_msg(1, 6, 1)));
    assert_eq!(state.pop_front(), None);
}

#[test]
fn test_console_control_state_rejects_unknown_bits() {
    let state = ConsoleControlState {
        pending_mask: 1u8 << CONSOLE_PENDING_CTRL_CAPACITY,
        ..Zeroable::zeroed()
    };

    assert!(state.validate().is_err());
}

// =============================================================================
// Pod / Size Assertions
// =============================================================================

#[test]
fn test_state_sizes() {
    use crate::*;
    assert_eq!(size_of::<MmioTransportState>(), 40);
    assert_eq!(size_of::<QueueState>(), 40);
    assert_eq!(size_of::<ConsoleConfig>(), 12);
    assert_eq!(size_of::<NetConfig>(), 20);
    assert_eq!(size_of::<PmemConfig>(), 16);
    assert_eq!(size_of::<FsConfig>(), 40);
    assert_eq!(size_of::<Descriptor>(), 16);

    assert_eq!(size_of::<ConsoleState>(), 512);
    assert_eq!(size_of::<NetState>(), 512);
    assert_eq!(size_of::<RngState>(), 80);
    assert_eq!(size_of::<FsState>(), 512);
    assert_eq!(size_of::<PmemState>(), 96);
}

#[test]
fn test_state_from_bytes() {
    use crate::{RngState, state_from};
    let mut bytes = vec![0u8; 512];
    let state: &mut RngState = state_from(&mut bytes);

    assert_eq!(state.transport.status, 0);
    assert_eq!(state.queues[0].size, 0);

    state.transport.status = 0x0F;

    let state2: &mut RngState = state_from(&mut bytes);
    assert_eq!(state2.transport.status, 0x0F);
}

// =============================================================================
// Wrapping Index Arithmetic
// =============================================================================

#[test]
fn test_queue_index_wrapping() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(4);
    let mut state = tq.make_state();

    state.last_avail_idx = 0xFFFE;
    state.last_used_idx = 0xFFFE;

    for i in 0..4u16 {
        let byte = u8::try_from(i).unwrap();
        tq.setup_single_desc(&vm, i, &[byte; 4], false);
    }

    tq.write_avail_ring(&vm, 0xFFFE & 3, 0);
    tq.write_avail_ring(&vm, 3, 1);
    tq.write_avail_idx(&vm, 0u16);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);

    let chain0 = view.pop().unwrap().into_readable().unwrap();
    assert_eq!(chain0.head_index(), 0);
    view.push(chain0.complete_zero()).unwrap();

    let chain1 = view.pop().unwrap().into_readable().unwrap();
    assert_eq!(chain1.head_index(), 1);
    view.push(chain1.complete_zero()).unwrap();

    assert!(view.pop().is_none());
    assert_eq!(state.last_avail_idx, 0x0000);
    assert_eq!(state.last_used_idx, 0x0000);
}

// =============================================================================
// Regression tests: descriptor walk failures must not be acknowledged
// =============================================================================
//
// These tests describe the invariant that conversion from a raw popped chain
// into a typed completion chain returns `QueueViolation` for malformed
// descriptors. The raw chain cannot be passed to `push`, so a correct device
// cannot publish a used entry for a malformed chain.

/// Helper: pop a chain and walk it the way a correct device would —
/// stop on the first walker error and refuse to push. Returns the
/// violation if the walker emitted one.
fn drain_one_chain(
    view: &mut QueueView<'_, '_, '_, amla_core::vm_state::VmState<'_>>,
) -> Option<QueueViolation> {
    let chain = view.pop().expect("chain expected");
    match chain.into_split() {
        Ok(chain) => {
            view.push(chain.complete_zero()).unwrap();
            None
        }
        Err(v) => Some(v),
    }
}

#[test]
fn walker_next_index_out_of_range_poisons_queue() {
    // desc[0].NEXT → 99, but queue_size = 8. The walker must reject the
    // chain and record a violation naming the out-of-range next index.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x3000,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 99,
        },
    );
    {
        let __gw = vm.gpa_write(0x3000, 4).unwrap();
        __gw.write_from(b"data");
    };
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let violation = drain_one_chain(&mut view);

    // Walker-specific variant — do NOT reuse `DescriptorIndexOutOfRange`
    // (that one is reserved for malformed avail-ring entries, queue.rs:328).
    assert!(
        matches!(
            violation,
            Some(QueueViolation::DescriptorNextIndexOutOfRange {
                index: 99,
                queue_size: 8,
            }),
        ),
        "expected DescriptorNextIndexOutOfRange {{ index: 99, queue_size: 8 }}, got {violation:?}",
    );
    assert_eq!(
        tq.read_used_idx(&vm),
        0,
        "used ring must not advance on malformed chain"
    );
}

#[test]
fn walker_direct_chain_cycle_poisons_queue() {
    // desc[0..=3] form a cycle (queue_size = 4). Walker must drop after
    // `queue_size` steps and record a DescriptorChainCycle violation.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(4);
    let mut state = tq.make_state();

    for i in 0..4u16 {
        tq.write_desc(
            &vm,
            i,
            &Descriptor {
                addr: 0x3000 + u64::from(i) * 256,
                len: 4,
                flags: VIRTQ_DESC_F_NEXT,
                next: (i + 1) % 4, // cycle
            },
        );
        {
            let __gw = vm.gpa_write(0x3000 + u64::from(i) * 256, 4).unwrap();
            __gw.write_from(b"data");
        };
    }
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::DescriptorChainTooLong {
                head_index: 0,
                queue_size: 4,
            }),
        ),
        "expected DescriptorChainTooLong {{ head_index: 0, queue_size: 4 }}, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_next_and_indirect_combo_poisons_queue() {
    // desc[3] has both NEXT and INDIRECT set — forbidden by spec §2.7.5.3.1.
    // The violation must name the offending descriptor, not just the head.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    // Indirect table with a single valid entry (unused — chain should be
    // rejected before the table is ever read).
    let ind_table_gpa = 0x4000u64;
    vm.write_obj(
        ind_table_gpa,
        &Descriptor {
            addr: 0x5000,
            len: 4,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x3000,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 3,
        },
    );
    {
        let __gw = vm.gpa_write(0x3000, 4).unwrap();
        __gw.write_from(b"data");
    };
    tq.write_desc(
        &vm,
        3,
        &Descriptor {
            addr: ind_table_gpa,
            len: 16,
            flags: VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_INDIRECT,
            next: 1,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(
        0,
        &mut state,
        &vm,
        VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC,
    );
    let violation = drain_one_chain(&mut view);

    // INDIRECT takes precedence over NEXT in DescriptorChain::next(), so
    // enter_indirect() runs and rejects the combo.
    assert!(
        matches!(
            violation,
            Some(QueueViolation::DescriptorNextAndIndirectSet { index: 3 }),
        ),
        "expected DescriptorNextAndIndirectSet {{ index: 3 }}, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_descriptor_buffer_out_of_range_violation() {
    // Direct descriptor whose buffer escapes guest RAM.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0xFFFF_0000,
            len: 256,
            flags: 0,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::DescriptorBufferOutOfRange {
                addr: 0xFFFF_0000,
                len: 256
            }),
        ),
        "expected DescriptorBufferOutOfRange, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_indirect_not_negotiated_violation() {
    // Descriptor sets INDIRECT but VIRTIO_F_INDIRECT_DESC is NOT negotiated.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x4000,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    // Note: features = VIRTIO_F_VERSION_1 only; INDIRECT_DESC not set.
    let mut view = QueueView::new(0, &mut state, &vm, VIRTIO_F_VERSION_1);
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::IndirectDescriptorNotNegotiated { index: 0 }),
        ),
        "expected IndirectDescriptorNotNegotiated, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_indirect_table_out_of_range_violation() {
    // Indirect table GPA + len escapes guest RAM.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0xFFFF_0000,
            len: 32,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(
        0,
        &mut state,
        &vm,
        VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC,
    );
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::IndirectTableOutOfRange {
                addr: 0xFFFF_0000,
                len: 32
            }),
        ),
        "expected IndirectTableOutOfRange, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_indirect_table_too_large_violation() {
    // Indirect table claims to have more entries than MAX_INDIRECT_TABLE_LEN (128).
    // 129 entries × 16 bytes/entry = 2064 bytes.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: 0x4000,
            len: 129 * 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(
        0,
        &mut state,
        &vm,
        VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC,
    );
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::IndirectTableTooLarge {
                entries: 129,
                max_entries: 128
            }),
        ),
        "expected IndirectTableTooLarge {{ entries: 129, max_entries: 128 }}, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_nested_indirect_violation() {
    // Indirect table entry has INDIRECT flag — nesting forbidden by spec §2.7.5.3.1.
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    let outer_table_gpa = 0x4000u64;
    // Outer indirect descriptor pointing at a 1-entry table.
    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: outer_table_gpa,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    // Inner table entry that ALSO sets INDIRECT — illegal.
    vm.write_obj(
        outer_table_gpa,
        &Descriptor {
            addr: 0x5000,
            len: 16,
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    )
    .unwrap();
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(
        0,
        &mut state,
        &vm,
        VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC,
    );
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::NestedIndirectDescriptor { index: 0 }),
        ),
        "expected NestedIndirectDescriptor {{ index: 0 }}, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}

#[test]
fn walker_indirect_descriptor_index_out_of_range_violation() {
    // Indirect entry's NEXT pointer references an index outside the indirect
    // table. Table has 2 entries (so `steps_remaining` is 2 — enough for the
    // OOB check to fire before the chain-too-long check).
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let tq = TestQueue::new(8);
    let mut state = tq.make_state();

    let table_gpa = 0x4000u64;
    tq.write_desc(
        &vm,
        0,
        &Descriptor {
            addr: table_gpa,
            len: 32, // 2 entries
            flags: VIRTQ_DESC_F_INDIRECT,
            next: 0,
        },
    );
    // Entry 0 chains to a non-existent index 99.
    vm.write_obj(
        table_gpa,
        &Descriptor {
            addr: 0x5000,
            len: 4,
            flags: VIRTQ_DESC_F_NEXT,
            next: 99,
        },
    )
    .unwrap();
    // Entry 1 is unreferenced (walker bails on entry 0's NEXT before reaching it).
    vm.write_obj(
        table_gpa + 16,
        &Descriptor {
            addr: 0x5100,
            len: 4,
            flags: 0,
            next: 0,
        },
    )
    .unwrap();
    tq.publish_avail(&vm, 1);

    let mut view = QueueView::new(
        0,
        &mut state,
        &vm,
        VIRTIO_F_VERSION_1 | VIRTIO_F_INDIRECT_DESC,
    );
    let violation = drain_one_chain(&mut view);

    assert!(
        matches!(
            violation,
            Some(QueueViolation::IndirectDescriptorIndexOutOfRange {
                index: 99,
                table_len: 2
            }),
        ),
        "expected IndirectDescriptorIndexOutOfRange {{ index: 99, table_len: 2 }}, got {violation:?}",
    );
    assert_eq!(tq.read_used_idx(&vm), 0);
}
