// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used)]

use crate::{Net, VIRTIO_NET_BASE_HDR_SIZE, VIRTIO_NET_HDR_SIZE};
use amla_core::backends::{NetBackend, NetRxPacketLease, NoRxPacket};
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_virtio::{
    DEVICE_ID_NET, Descriptor, NetControlState, NetState, QueueView, QueueViolation,
    VIRTIO_F_VERSION_1, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, VirtioDevice,
};
use bytemuck::Zeroable;
use std::io::{self, IoSlice};
use std::sync::{Mutex, MutexGuard};

const RAM_SIZE: usize = TEST_RAM_SIZE;

fn make_test_buf() -> TestMmap {
    test_mmap(RAM_SIZE)
}

fn make_vm(mmap: &TestMmap) -> VmState<'_> {
    make_test_vmstate(mmap, 0)
}

fn make_net_control() -> NetControlState {
    NetControlState {
        active_queue_pairs: 1,
        pad: [0; 10],
    }
}

macro_rules! process_net_queue {
    ($state:expr, $queue_idx:expr, $vm:expr, $net:expr) => {
        QueueView::with(
            $queue_idx,
            &mut $state.queues[$queue_idx],
            $vm,
            VIRTIO_F_VERSION_1,
            |view| $net.process_queue($queue_idx, view),
        )
        .unwrap()
    };
}

/// Test network backend that captures sent packets and provides canned RX.
struct TestNetBackend {
    sent_packets: Mutex<Vec<Vec<u8>>>,
    rx_packet: Mutex<Option<Vec<u8>>>,
}

impl TestNetBackend {
    fn new() -> Self {
        Self {
            sent_packets: Mutex::new(Vec::new()),
            rx_packet: Mutex::new(None),
        }
    }

    fn with_rx(packet: &[u8]) -> Self {
        Self {
            sent_packets: Mutex::new(Vec::new()),
            rx_packet: Mutex::new(Some(packet.to_vec())),
        }
    }

    fn pending_rx_len(&self) -> Option<usize> {
        self.rx_packet.lock().unwrap().as_ref().map(Vec::len)
    }
}

impl NetBackend for TestNetBackend {
    type RxPacket<'a> = TestRxPacket<'a>;

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let packet: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
        self.sent_packets.lock().unwrap().push(packet);
        Ok(())
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        let guard = self.rx_packet.lock().unwrap();
        if guard.is_none() {
            Ok(None)
        } else {
            Ok(Some(TestRxPacket { guard }))
        }
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

struct TestRxPacket<'a> {
    guard: MutexGuard<'a, Option<Vec<u8>>>,
}

impl NetRxPacketLease<'_> for TestRxPacket<'_> {
    fn packet(&self) -> &[u8] {
        self.guard.as_ref().unwrap()
    }

    fn commit(mut self) -> io::Result<()> {
        let _ = self.guard.take();
        Ok(())
    }
}

/// Backend that fails while trying to deliver RX packets.
struct FailingRxBackend;

impl NetBackend for FailingRxBackend {
    type RxPacket<'a> = NoRxPacket;

    fn send(&self, _: &[IoSlice<'_>]) -> io::Result<()> {
        Ok(())
    }
    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Err(io::Error::other("lease failed"))
    }
    fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

struct FailingTxBackend;

impl NetBackend for FailingTxBackend {
    type RxPacket<'a> = NoRxPacket;

    fn send(&self, _: &[IoSlice<'_>]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "tx full"))
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Ok(None)
    }

    fn set_nonblocking(&self, _: bool) -> io::Result<()> {
        Ok(())
    }
}

// =============================================================================
// Device identity
// =============================================================================

#[test]
fn test_device_id_and_features() {
    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let net = Net::new(&backend, 1, &mut control);
    assert_eq!(VirtioDevice::<VmState<'_>>::device_id(&net), DEVICE_ID_NET);
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&net), 2);
    // VIRTIO_NET_F_MAC = 1 << 5
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_features(&net),
        VIRTIO_F_VERSION_1 | (1 << 5)
    );
}

// =============================================================================
// TX tests
// =============================================================================

#[test]
fn test_tx_gathers_chain_and_strips_header() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    // Descriptor 0: modern virtio-net header (no offloads, all zeros).
    let hdr = [0u8; VIRTIO_NET_HDR_SIZE];
    {
        let gw = vm.gpa_write(0x3000, hdr.len()).unwrap();
        gw.write_from(&hdr);
    };
    let desc0 = Descriptor {
        addr: 0x3000,
        len: u32::try_from(VIRTIO_NET_HDR_SIZE).unwrap(),
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();

    // Descriptor 1: ethernet frame payload
    let payload = b"test_payload_data";
    {
        let gw = vm.gpa_write(0x4000, payload.len()).unwrap();
        gw.write_from(payload);
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: u32::try_from(payload.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0010u64, &desc1).unwrap();

    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 1, &vm, net).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert_eq!(backend.sent_packets.lock().unwrap().len(), 1);
    assert_eq!(&backend.sent_packets.lock().unwrap()[0], payload);
}

#[test]
fn test_tx_ignores_unused_modern_header_tail_before_payload() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let ethernet_frame = [
        0x0a, 0x40, 0x7d, 0x12, 0x34, 0x56, // dst MAC starts non-zero
        0x02, 0x00, 0x00, 0x00, 0x00, 0x01, // src MAC
        0x08, 0x00, // IPv4 ethertype
        b'p', b'i', b'n', b'g',
    ];
    let mut packet = [0u8; VIRTIO_NET_HDR_SIZE + 18];
    // Linux sends the modern 12-byte header for VERSION_1 devices. Without
    // MRG_RXBUF, the tail is unused and may contain non-zero stale data.
    packet[VIRTIO_NET_BASE_HDR_SIZE..VIRTIO_NET_HDR_SIZE].copy_from_slice(&[0x02, 0x00]);
    packet[VIRTIO_NET_HDR_SIZE..].copy_from_slice(&ethernet_frame);
    {
        let gw = vm.gpa_write(0x3000, packet.len()).unwrap();
        gw.write_from(&packet);
    }
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(packet.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 1, &vm, net).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 1);
    let sent_snapshot: Vec<Vec<u8>> = backend.sent_packets.lock().unwrap().clone();
    assert_eq!(sent_snapshot.len(), 1);
    assert_eq!(sent_snapshot[0], ethernet_frame);
}

#[test]
fn test_tx_header_only_no_payload() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    // Single descriptor: exactly one virtio-net header, no payload.
    {
        let gw = vm.gpa_write(0x3000, VIRTIO_NET_HDR_SIZE).unwrap();
        gw.write_from(&[0u8; VIRTIO_NET_HDR_SIZE]);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(VIRTIO_NET_HDR_SIZE).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 1, &vm, net).unwrap();

    // Descriptor consumed but send() not called (offset == HDR_SIZE, not >)
    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert!(backend.sent_packets.lock().unwrap().is_empty());
}

#[test]
fn test_tx_backend_error_is_queue_violation() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let mut packet = [0u8; VIRTIO_NET_HDR_SIZE + 4];
    packet[VIRTIO_NET_HDR_SIZE..].copy_from_slice(b"fail");
    {
        let gw = vm.gpa_write(0x3000, packet.len()).unwrap();
        gw.write_from(&packet);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(packet.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = FailingTxBackend;
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    let err = process_net_queue!(state, 1, &vm, net).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_NET,
            operation: "net_tx_backend_send",
        }
    ));
    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert_eq!(state.queues[1].last_used_idx, 0);
}

#[test]
fn test_tx_short_header_is_queue_violation() {
    const SHORT_HDR_SIZE: usize = VIRTIO_NET_HDR_SIZE - 1;

    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    {
        let gw = vm.gpa_write(0x3000, SHORT_HDR_SIZE).unwrap();
        gw.write_from(&[0u8; SHORT_HDR_SIZE]);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(SHORT_HDR_SIZE).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    let err = process_net_queue!(state, 1, &vm, net).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DescriptorReadableCapacityTooSmall {
            head_index: 0,
            required: VIRTIO_NET_HDR_SIZE,
            available: SHORT_HDR_SIZE,
        }
    ));
    let used_idx: u16 = vm.read_obj(0x2002u64).unwrap();
    assert_eq!(used_idx, 0);
    assert!(backend.sent_packets.lock().unwrap().is_empty());
}

#[test]
fn test_tx_unsupported_header_is_dropped_before_backend_send() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let mut packet = [0u8; VIRTIO_NET_HDR_SIZE + 4];
    packet[0] = 1; // VIRTIO_NET_HDR_F_NEEDS_CSUM without CSUM negotiated.
    packet[VIRTIO_NET_HDR_SIZE..].copy_from_slice(b"drop");
    {
        let gw = vm.gpa_write(0x3000, packet.len()).unwrap();
        gw.write_from(&packet);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(packet.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 1, &vm, net).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 1);
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 0);
    assert!(backend.sent_packets.lock().unwrap().is_empty());
}

#[test]
fn test_tx_multiple_chains() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    // 3 independent single-descriptor packets (header + 4 bytes payload each)
    for i in 0u16..3 {
        let gpa = 0x3000 + u64::from(i) * 0x100;
        let mut data = [0u8; VIRTIO_NET_HDR_SIZE + 4];
        let tag = b'A' + u8::try_from(i).unwrap();
        data[VIRTIO_NET_HDR_SIZE..].copy_from_slice(&[tag; 4]);
        {
            let gw = vm.gpa_write(gpa, data.len()).unwrap();
            gw.write_from(&data);
        };

        let desc = Descriptor {
            addr: gpa,
            len: u32::try_from(data.len()).unwrap(),
            flags: 0,
            next: 0,
        };
        vm.write_obj(u64::from(i) * 16, &desc).unwrap();
        vm.write_obj(0x1004 + u64::from(i) * 2, &i).unwrap();
    }
    vm.write_obj(0x1002u64, &3u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 1, &vm, net).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 3);
    assert_eq!(backend.sent_packets.lock().unwrap().len(), 3);
    assert_eq!(&backend.sent_packets.lock().unwrap()[0], &[b'A'; 4]);
    assert_eq!(&backend.sent_packets.lock().unwrap()[1], &[b'B'; 4]);
    assert_eq!(&backend.sent_packets.lock().unwrap()[2], &[b'C'; 4]);
}

#[test]
fn test_tx_oversize_still_walks_malformed_tail() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x0000,
        len: 65_536,
        flags: VIRTQ_DESC_F_NEXT,
        next: 99,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    let err = process_net_queue!(state, 1, &vm, net).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DescriptorNextIndexOutOfRange {
            index: 99,
            queue_size: 16
        }
    ));
    let used_idx: u16 = vm.read_obj(0x2002u64).unwrap();
    assert_eq!(
        used_idx, 0,
        "malformed oversize chain must not be acknowledged"
    );
    assert!(backend.sent_packets.lock().unwrap().is_empty());
}

// =============================================================================
// RX tests
// =============================================================================

#[test]
fn test_rx_prepends_header_and_scatters_multi_descriptor() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    // 2 chained writable descriptors: first 16 bytes, second 1484 bytes
    let desc0 = Descriptor {
        addr: 0x3000,
        len: 16,
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: 1484,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();
    vm.write_obj(0x0010u64, &desc1).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let rx_packet = b"scattered_ethernet_frame";
    let backend = TestNetBackend::with_rx(rx_packet);
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 0, &vm, net).unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);

    // Total = virtio-net header + payload.
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    let expected = u32::try_from(VIRTIO_NET_HDR_SIZE + rx_packet.len()).unwrap();
    assert_eq!(used_len, expected);

    // First bytes in desc0's buffer = zeroed virtio-net header.
    let mut hdr = [0xFFu8; VIRTIO_NET_HDR_SIZE];
    vm.gpa_read(0x3000, hdr.len()).unwrap().read_to(&mut hdr);
    assert_eq!(hdr, [0u8; VIRTIO_NET_HDR_SIZE]);

    // Remaining bytes in desc0's buffer = first bytes of payload.
    let spill_len = 16 - VIRTIO_NET_HDR_SIZE;
    let mut spill = vec![0u8; spill_len];
    vm.gpa_read(
        0x3000 + u64::try_from(VIRTIO_NET_HDR_SIZE).unwrap(),
        spill.len(),
    )
    .unwrap()
    .read_to(&mut spill);
    assert_eq!(&spill, &rx_packet[..spill_len]);

    // Remaining payload in desc1's buffer
    let mut rest = vec![0u8; rx_packet.len() - spill_len];
    vm.gpa_read(0x4000, rest.len()).unwrap().read_to(&mut rest);
    assert_eq!(&rest, &rx_packet[spill_len..]);
}

#[test]
fn test_rx_skips_when_no_packet() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 1500,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new(); // no RX packet
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    process_net_queue!(state, 0, &vm, net).unwrap();

    // No RX lease means no descriptor is consumed.
    assert_eq!(state.queues[0].last_avail_idx, 0);
}

#[test]
fn test_rx_delivery_error_is_queue_violation() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 1500,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = FailingRxBackend;
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    let err = process_net_queue!(state, 0, &vm, net).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_NET,
            operation: "net_rx_backend_lease",
        }
    ));
    assert_eq!(state.queues[0].last_avail_idx, 0);
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn test_rx_rejects_packet_that_does_not_fit_guest_buffer() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    {
        let gw = vm.gpa_write(0x3000, 16).unwrap();
        gw.write_from(&[0xAA; 16]);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: 16,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::with_rx(b"too-wide");
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);
    let err = process_net_queue!(state, 0, &vm, net).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DescriptorWritableCapacityTooSmall { .. }
    ));
    assert_eq!(state.queues[0].last_avail_idx, 1);
    assert_eq!(state.queues[0].last_used_idx, 0);

    let mut guest_buf = [0u8; 16];
    vm.gpa_read(0x3000, guest_buf.len())
        .unwrap()
        .read_to(&mut guest_buf);
    assert_eq!(guest_buf, [0xAA; 16]);
    assert_eq!(backend.pending_rx_len(), Some(b"too-wide".len()));
}

// =============================================================================
// Control queue MQ payload validation (virtio 1.2 §5.1.6.5.4)
// =============================================================================

const VIRTIO_NET_CTRL_MQ: u8 = 4;
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;
const VIRTIO_NET_OK: u8 = 0;
const VIRTIO_NET_ERR: u8 = 1;

/// Run a single control-queue command and return the byte the device wrote
/// to its writable ACK descriptor.
///
/// Layout: desc 0 = class+cmd header (readable), desc 1 = payload bytes
/// (readable), desc 2 = ACK (writable). Mirrors how Linux's `virtio_net`
/// sends control commands as 3 separate sgs.
fn run_ctrl_cmd(queue_pairs: u16, header: &[u8], payload: &[u8]) -> (u8, u16) {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    let ctrl_idx = (2 * queue_pairs) as usize;
    state.queues[ctrl_idx].size = 16;
    state.queues[ctrl_idx].ready = 1;
    state.queues[ctrl_idx].desc_addr = 0x0000;
    state.queues[ctrl_idx].avail_addr = 0x1000;
    state.queues[ctrl_idx].used_addr = 0x2000;

    {
        let gw = vm.gpa_write(0x3000, header.len()).unwrap();
        gw.write_from(header);
    }

    // Build chain: header → (payload, if any) → ACK (writable).
    let header_desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(header.len()).unwrap(),
        flags: VIRTQ_DESC_F_NEXT,
        next: if payload.is_empty() { 2 } else { 1 },
    };
    vm.write_obj(0x0000u64, &header_desc).unwrap();

    if !payload.is_empty() {
        let gw = vm.gpa_write(0x3100, payload.len()).unwrap();
        gw.write_from(payload);
        let payload_desc = Descriptor {
            addr: 0x3100,
            len: u32::try_from(payload.len()).unwrap(),
            flags: VIRTQ_DESC_F_NEXT,
            next: 2,
        };
        vm.write_obj(0x0010u64, &payload_desc).unwrap();
    }

    // Pre-fill the ack byte with a sentinel so we can detect "not written".
    {
        let gw = vm.gpa_write(0x3200, 1).unwrap();
        gw.write_from(&[0xAB]);
    }
    let ack_desc = Descriptor {
        addr: 0x3200,
        len: 1,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0020u64, &ack_desc).unwrap();

    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    {
        let mut net = Net::new(&backend, queue_pairs, &mut state.control);
        process_net_queue!(state, ctrl_idx, &vm, net).unwrap();
    }

    let mut ack = [0xCDu8; 1];
    vm.gpa_read(0x3200, 1).unwrap().read_to(&mut ack);
    (ack[0], state.control.active_queue_pairs)
}

fn run_ctrl_cmd_ack(queue_pairs: u16, header: &[u8], payload: &[u8]) -> u8 {
    run_ctrl_cmd(queue_pairs, header, payload).0
}

#[test]
fn test_ctrl_mq_set_pairs_accepts_valid_value() {
    let header = [VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET];
    let payload = 2u16.to_le_bytes();
    let (ack, active_queue_pairs) = run_ctrl_cmd(2, &header, &payload);
    assert_eq!(ack, VIRTIO_NET_OK);
    assert_eq!(active_queue_pairs, 2);
}

#[test]
fn test_ctrl_mq_set_pairs_rejects_zero() {
    // virtio 1.2 §5.1.6.5.4: virtqueue_pairs MUST be ≥ 1.
    let header = [VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET];
    let payload = 0u16.to_le_bytes();
    assert_eq!(run_ctrl_cmd_ack(2, &header, &payload), VIRTIO_NET_ERR);
}

#[test]
fn test_ctrl_mq_set_pairs_rejects_above_max() {
    // virtio 1.2 §5.1.6.5.4: virtqueue_pairs MUST be ≤ max_virtqueue_pairs.
    let header = [VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET];
    let payload = 5u16.to_le_bytes();
    assert_eq!(run_ctrl_cmd_ack(2, &header, &payload), VIRTIO_NET_ERR);
}

#[test]
fn test_ctrl_mq_set_pairs_rejects_missing_payload() {
    // The bug this regresses: device used to ACK any class+cmd match
    // regardless of whether the 2-byte payload existed.
    let header = [VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET];
    assert_eq!(run_ctrl_cmd_ack(2, &header, &[]), VIRTIO_NET_ERR);
}

#[test]
fn test_ctrl_unknown_class_rejected() {
    let header = [0xFF, 0x00];
    let payload = 1u16.to_le_bytes();
    assert_eq!(run_ctrl_cmd_ack(2, &header, &payload), VIRTIO_NET_ERR);
}

#[test]
fn test_inactive_mq_data_queue_is_not_processed_until_selected() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[3].size = 16;
    state.queues[3].ready = 1;
    state.queues[3].desc_addr = 0x0000;
    state.queues[3].avail_addr = 0x1000;
    state.queues[3].used_addr = 0x2000;

    let mut packet = [0u8; VIRTIO_NET_HDR_SIZE + 4];
    packet[VIRTIO_NET_HDR_SIZE..].copy_from_slice(b"mq02");
    {
        let gw = vm.gpa_write(0x3000, packet.len()).unwrap();
        gw.write_from(&packet);
    }
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(packet.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestNetBackend::new();
    let mut control = make_net_control();

    {
        let mut net = Net::new(&backend, 2, &mut control);
        process_net_queue!(state, 3, &vm, net).unwrap();
    }
    assert_eq!(state.queues[3].last_avail_idx, 0);
    assert!(backend.sent_packets.lock().unwrap().is_empty());

    control.active_queue_pairs = 2;
    {
        let mut net = Net::new(&backend, 2, &mut control);
        process_net_queue!(state, 3, &vm, net).unwrap();
    }

    assert_eq!(state.queues[3].last_avail_idx, 1);
    assert_eq!(&backend.sent_packets.lock().unwrap()[0], b"mq02");
}

#[test]
fn test_invalid_queue_index() {
    let buf = make_test_buf();
    let vm = make_vm(&buf);
    let mut state: NetState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let backend = TestNetBackend::new();
    let mut control = make_net_control();
    let mut net = Net::new(&backend, 1, &mut control);

    // Queue index 5 → no-op
    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        net.process_queue(5, view)
    })
    .unwrap()
    .unwrap();
    assert_eq!(state.queues[0].last_avail_idx, 0);
}
