// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used)]

use crate::{Console, NullAgentPort};
use amla_core::backends::ConsoleBackend;
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_virtio::{
    ConsoleControlState, ConsoleState, DEVICE_ID_CONSOLE, Descriptor, QueueView, QueueViolation,
    VIRTIO_CONSOLE_F_MULTIPORT, VIRTIO_F_VERSION_1, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
    VirtioDevice,
};
use bytemuck::Zeroable;
use std::io;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const MEM_SIZE: usize = TEST_RAM_SIZE;

fn ctrl_msg(id: u32, event: u16, value: u16) -> [u8; 8] {
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&id.to_le_bytes());
    msg[4..6].copy_from_slice(&event.to_le_bytes());
    msg[6..8].copy_from_slice(&value.to_le_bytes());
    msg
}

fn ctrl_event(msg: [u8; 8]) -> u16 {
    u16::from_le_bytes([msg[4], msg[5]])
}

fn ctrl_id(msg: [u8; 8]) -> u32 {
    u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]])
}

macro_rules! process_console_queue {
    ($state:expr, $queue_idx:expr, $vm:expr, $console:expr) => {
        QueueView::with(
            $queue_idx,
            &mut $state.queues[$queue_idx],
            $vm,
            VIRTIO_F_VERSION_1,
            |view| $console.process_queue($queue_idx, view),
        )
        .unwrap()
    };
}

fn make_test_memory() -> TestMmap {
    test_mmap(MEM_SIZE)
}

/// Test console backend that captures output and provides canned input.
struct TestBackend {
    output: Mutex<Vec<u8>>,
    input: Vec<u8>,
    input_pos: AtomicUsize,
    emergency_char: AtomicU8,
}

impl TestBackend {
    fn new() -> Self {
        Self {
            output: Mutex::new(Vec::new()),
            input: Vec::new(),
            input_pos: AtomicUsize::new(0),
            emergency_char: AtomicU8::new(0),
        }
    }

    fn with_input(input: &[u8]) -> Self {
        Self {
            output: Mutex::new(Vec::new()),
            input: input.to_vec(),
            input_pos: AtomicUsize::new(0),
            emergency_char: AtomicU8::new(0),
        }
    }
}

struct RejectingWriteBackend {
    output: Mutex<Vec<u8>>,
}

impl RejectingWriteBackend {
    fn new() -> Self {
        Self {
            output: Mutex::new(Vec::new()),
        }
    }
}

impl ConsoleBackend for TestBackend {
    fn write(&self, data: &[u8]) -> io::Result<()> {
        self.output.lock().unwrap().extend_from_slice(data);
        Ok(())
    }

    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let pos = self.input_pos.load(Ordering::Relaxed);
        let remaining = &self.input[pos..];
        if remaining.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no input"));
        }
        let n = remaining.len().min(buf.len());
        buf[..n].copy_from_slice(&remaining[..n]);
        self.input_pos.store(pos + n, Ordering::Relaxed);
        Ok(n)
    }

    fn has_pending_input(&self) -> bool {
        self.input_pos.load(Ordering::Relaxed) < self.input.len()
    }

    fn emergency_write(&self, ch: u8) -> io::Result<()> {
        self.emergency_char.store(ch, Ordering::Relaxed);
        Ok(())
    }
}

impl ConsoleBackend for RejectingWriteBackend {
    fn write(&self, _data: &[u8]) -> io::Result<()> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "full"))
    }

    fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(io::ErrorKind::WouldBlock, "no input"))
    }
}

fn make_console<'a>(
    backend: &'a TestBackend,
    port1: &'a mut dyn crate::AgentPortBackend,
    ctrl: &'a mut ConsoleControlState,
) -> Console<'a> {
    Console::new(backend, port1, ctrl)
}

// =============================================================================
// Identity
// =============================================================================

#[test]
fn test_device_id_and_features() {
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let console = make_console(&backend, &mut port1, &mut ctrl);
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_id(&console),
        DEVICE_ID_CONSOLE
    );
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&console), 6);
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_features(&console),
        VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT
    );
}

#[test]
fn test_reset_clears_pending_control_messages() {
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    assert!(ctrl.push_back(ctrl_msg(0, 1, 1)));

    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        VirtioDevice::<VmState<'_>>::reset(&mut console);
    }

    assert_eq!(ctrl.len(), 0);
}

// =============================================================================
// TX tests (port 0)
// =============================================================================

#[test]
fn test_tx_writes_to_backend() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let msg = b"hello\n";
    {
        let gw = vm.gpa_write(0x3000, msg.len()).unwrap();
        gw.write_from(msg);
    };

    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(msg.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 1, &vm, console).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert_eq!(&*backend.output.lock().unwrap(), b"hello\n");
}

#[test]
fn test_tx_multi_descriptor_chain() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    // Descriptor 0: "hello"
    {
        let gw = vm.gpa_write(0x3000, b"hello".len()).unwrap();
        gw.write_from(b"hello");
    };
    let desc0 = Descriptor {
        addr: 0x3000,
        len: 5,
        flags: VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();

    // Descriptor 1: " world"
    {
        let gw = vm.gpa_write(0x4000, b" world".len()).unwrap();
        gw.write_from(b" world");
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: 6,
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0010u64, &desc1).unwrap();

    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 1, &vm, console).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert_eq!(&*backend.output.lock().unwrap(), b"hello world");
}

#[test]
fn test_tx_multiple_chains() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let messages = [b"aaa", b"bbb", b"ccc"];
    for (i, msg) in messages.iter().enumerate() {
        let i = u16::try_from(i).unwrap();
        let gpa = 0x3000 + u64::from(i) * 0x100;
        {
            let gw = vm.gpa_write(gpa, msg.len()).unwrap();
            gw.write_from(*msg);
        };
        let desc = Descriptor {
            addr: gpa,
            len: 3,
            flags: 0,
            next: 0,
        };
        vm.write_obj(u64::from(i) * 16, &desc).unwrap();
        vm.write_obj(0x1004 + u64::from(i) * 2, &i).unwrap();
    }
    vm.write_obj(0x1002u64, &3u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 1, &vm, console).unwrap();

    assert_eq!(state.queues[1].last_avail_idx, 3);
    assert_eq!(&*backend.output.lock().unwrap(), b"aaabbbccc");
}

#[test]
fn test_tx_backend_write_error_is_queue_violation() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let msg = b"abcdef";
    {
        let gw = vm.gpa_write(0x3000, msg.len()).unwrap();
        gw.write_from(msg);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(msg.len()).unwrap(),
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = RejectingWriteBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    let err = process_console_queue!(state, 1, &vm, console).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "console_port0_tx_backend_write",
        }
    ));
    assert_eq!(state.queues[1].last_avail_idx, 1);
    assert_eq!(state.queues[1].last_used_idx, 0);
    assert_eq!(&*backend.output.lock().unwrap(), b"");
}

#[test]
fn test_tx_malformed_chain_does_not_write_backend() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let msg = b"should not be written";
    {
        let gw = vm.gpa_write(0x3000, msg.len()).unwrap();
        gw.write_from(msg);
    };

    let desc = Descriptor {
        addr: 0x3000,
        len: u32::try_from(msg.len()).unwrap(),
        flags: VIRTQ_DESC_F_NEXT,
        next: 99,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    assert!(process_console_queue!(state, 1, &vm, console).is_err());
    assert_eq!(&*backend.output.lock().unwrap(), b"");
    assert_eq!(state.queues[1].last_used_idx, 0);
}

// =============================================================================
// RX tests (port 0)
// =============================================================================

#[test]
fn test_rx_fills_writable_buffer() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::with_input(b"world");
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 0, &vm, console).unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);

    let mut buf = [0u8; 5];
    vm.gpa_read(0x3000, buf.len()).unwrap().read_to(&mut buf);
    assert_eq!(&buf, b"world");

    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 5);
}

#[test]
fn test_rx_scatter_across_chained_descriptors() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    // 2 chained writable: first 4 bytes, second 64 bytes
    let desc0 = Descriptor {
        addr: 0x3000,
        len: 4,
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();
    vm.write_obj(0x0010u64, &desc1).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    // Input is 10 bytes — should span both descriptors
    let backend = TestBackend::with_input(b"0123456789");
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 0, &vm, console).unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 1);

    // First descriptor gets first 4 bytes
    let mut buf0 = [0u8; 4];
    vm.gpa_read(0x3000, buf0.len()).unwrap().read_to(&mut buf0);
    assert_eq!(&buf0, b"0123");

    // Second descriptor gets remaining 6 bytes
    let mut buf1 = [0u8; 6];
    vm.gpa_read(0x4000, buf1.len()).unwrap().read_to(&mut buf1);
    assert_eq!(&buf1, b"456789");
}

#[test]
fn test_rx_skips_when_no_input() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 0, &vm, console).unwrap();

    assert_eq!(state.queues[0].last_avail_idx, 0);
}

#[test]
fn test_rx_rejects_oversized_backend_read() {
    struct OversizedReadBackend;

    impl ConsoleBackend for OversizedReadBackend {
        fn write(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len() + 1)
        }

        fn has_pending_input(&self) -> bool {
            true
        }
    }

    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 8,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = OversizedReadBackend;
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    assert_eq!(
        process_console_queue!(state, 0, &vm, console),
        Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "port0 rx read",
        })
    );
    assert_eq!(state.queues[0].last_used_idx, 0);
}

#[test]
fn test_rx_propagates_backend_read_error() {
    struct FailingReadBackend;

    impl ConsoleBackend for FailingReadBackend {
        fn write(&self, _data: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn read(&self, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "rx failed"))
        }

        fn has_pending_input(&self) -> bool {
            true
        }
    }

    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 8,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = FailingReadBackend;
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    assert_eq!(
        process_console_queue!(state, 0, &vm, console),
        Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "console_port0_rx_backend_read",
        })
    );
    assert_eq!(state.queues[0].last_used_idx, 0);
}

// =============================================================================
// Emergency write (config path)
// =============================================================================

#[test]
fn test_emergency_write_via_config() {
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);

    let mut config = [0u8; 12]; // ConsoleConfig is 12 bytes
    VirtioDevice::<VmState<'_>>::write_config(&mut console, &mut config, 8, b"X");

    assert_eq!(backend.emergency_char.load(Ordering::Relaxed), b'X');
}

// =============================================================================
// Control protocol (MULTIPORT handshake)
// =============================================================================

#[test]
fn test_multiport_device_ready_queues_port_add() {
    let mut ctrl = ConsoleControlState::zeroed();
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);

    // Simulate guest sending DEVICE_READY (event=0, id=0, value=1)
    let msg = ctrl_msg(0, 0, 1);
    console.handle_ctrl_message(msg);

    assert_eq!(ctrl.len(), 2);

    // First: PORT_ADD(id=0)
    let m0 = ctrl.get(0).unwrap();
    assert_eq!(ctrl_id(m0), 0);
    assert_eq!(ctrl_event(m0), 1); // PORT_ADD

    // Second: PORT_ADD(id=1)
    let m1 = ctrl.get(1).unwrap();
    assert_eq!(ctrl_id(m1), 1);
    assert_eq!(ctrl_event(m1), 1); // PORT_ADD
}

#[test]
fn test_multiport_port_ready_queues_responses() {
    let mut ctrl = ConsoleControlState::zeroed();
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;

    // Guest sends PORT_READY for port 0 (id=0, event=3, value=1)
    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        let msg = ctrl_msg(0, 3, 1);
        console.handle_ctrl_message(msg);
    }

    assert_eq!(ctrl.len(), 2);

    // CONSOLE_PORT(id=0, value=1)
    let m0 = ctrl.get(0).unwrap();
    assert_eq!(ctrl_event(m0), 4); // CONSOLE_PORT

    // PORT_OPEN(id=0, value=1)
    let m1 = ctrl.get(1).unwrap();
    assert_eq!(ctrl_event(m1), 6); // PORT_OPEN

    // Now PORT_READY for port 1 — no CONSOLE_PORT, just PORT_OPEN
    ctrl.clear();
    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        let msg = ctrl_msg(1, 3, 1);
        console.handle_ctrl_message(msg);
    }

    assert_eq!(ctrl.len(), 1);
    let m = ctrl.get(0).unwrap();
    assert_eq!(ctrl_id(m), 1);
    assert_eq!(ctrl_event(m), 6); // PORT_OPEN
}

#[test]
fn test_multiport_duplicate_device_ready_is_idempotent() {
    let mut ctrl = ConsoleControlState::zeroed();
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;

    let msg = ctrl_msg(0, 0, 1);
    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        console.handle_ctrl_message(msg);
    }
    assert_eq!(ctrl.len(), 2);

    // Repeated DEVICE_READY should not grow the pending state with duplicates.
    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        console.handle_ctrl_message(msg);
    }
    assert_eq!(ctrl.len(), 2);
}

#[test]
fn test_multiport_duplicate_device_ready_cannot_crowd_out_port_ready() {
    let mut ctrl = ConsoleControlState::zeroed();
    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;

    {
        let mut console = Console::new(&backend, &mut port1, &mut ctrl);
        let device_ready = ctrl_msg(0, 0, 1);
        for _ in 0..32 {
            console.handle_ctrl_message(device_ready);
        }
        console.handle_ctrl_message(ctrl_msg(0, 3, 1));
    }

    assert_eq!(ctrl.len(), 4);
    assert_eq!(ctrl_event(ctrl.get(0).unwrap()), 1); // PORT_ADD(0)
    assert_eq!(ctrl_event(ctrl.get(1).unwrap()), 1); // PORT_ADD(1)
    assert_eq!(ctrl_event(ctrl.get(2).unwrap()), 4); // CONSOLE_PORT(0)
    assert_eq!(ctrl_event(ctrl.get(3).unwrap()), 6); // PORT_OPEN(0)
}

// =============================================================================
// Control RX delivery
// =============================================================================

#[test]
fn test_ctrl_rx_delivers_pending_message() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    // Queue 2 = ctrl RX (host→guest)
    state.queues[2].size = 16;
    state.queues[2].ready = 1;
    state.queues[2].desc_addr = 0x0000;
    state.queues[2].avail_addr = 0x1000;
    state.queues[2].used_addr = 0x2000;

    // Single 64-byte writable descriptor — plenty of room
    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    // Pre-queue a PORT_ADD(id=0) control message
    let mut ctrl = ConsoleControlState::zeroed();
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&0u32.to_le_bytes()); // id=0
    msg[4..6].copy_from_slice(&1u16.to_le_bytes()); // PORT_ADD
    msg[6..8].copy_from_slice(&1u16.to_le_bytes()); // value=1
    assert!(ctrl.push_back(msg));

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 2, &vm, console).unwrap();

    // Message delivered, ctrl queue drained
    assert_eq!(ctrl.len(), 0);
    assert_eq!(state.queues[2].last_avail_idx, 1);

    // Verify 8 bytes written
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 8);

    // Verify message content
    let mut buf = [0u8; 8];
    vm.gpa_read(0x3000, buf.len()).unwrap().read_to(&mut buf);
    assert_eq!(buf, msg);
}

#[test]
fn test_ctrl_rx_gathers_across_small_descriptors() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    // Queue 2 = ctrl RX
    state.queues[2].size = 16;
    state.queues[2].ready = 1;
    state.queues[2].desc_addr = 0x0000;
    state.queues[2].avail_addr = 0x1000;
    state.queues[2].used_addr = 0x2000;

    // Two chained 4-byte writable descriptors (8 bytes total, just enough)
    let desc0 = Descriptor {
        addr: 0x3000,
        len: 4,
        flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
        next: 1,
    };
    let desc1 = Descriptor {
        addr: 0x4000,
        len: 4,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc0).unwrap();
    vm.write_obj(0x0010u64, &desc1).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    // Pre-queue a control message
    let mut ctrl = ConsoleControlState::zeroed();
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&1u32.to_le_bytes()); // id=1
    msg[4..6].copy_from_slice(&6u16.to_le_bytes()); // PORT_OPEN
    msg[6..8].copy_from_slice(&1u16.to_le_bytes()); // value=1
    assert!(ctrl.push_back(msg));

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 2, &vm, console).unwrap();

    // Message delivered across two descriptors
    assert_eq!(ctrl.len(), 0);

    // First 4 bytes in descriptor 0
    let mut buf0 = [0u8; 4];
    vm.gpa_read(0x3000, buf0.len()).unwrap().read_to(&mut buf0);
    assert_eq!(buf0, msg[0..4]);

    // Last 4 bytes in descriptor 1
    let mut buf1 = [0u8; 4];
    vm.gpa_read(0x4000, buf1.len()).unwrap().read_to(&mut buf1);
    assert_eq!(buf1, msg[4..8]);
}

#[test]
fn test_ctrl_rx_keeps_pending_message_when_used_publish_fails() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[2].size = 16;
    state.queues[2].ready = 1;
    state.queues[2].desc_addr = 0x0000;
    state.queues[2].avail_addr = 0x1000;
    state.queues[2].used_addr = MEM_SIZE as u64;

    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let mut ctrl = ConsoleControlState::zeroed();
    let mut msg = [0u8; 8];
    msg[0..4].copy_from_slice(&1u32.to_le_bytes());
    msg[4..6].copy_from_slice(&6u16.to_le_bytes());
    msg[6..8].copy_from_slice(&1u16.to_le_bytes());
    assert!(ctrl.push_back(msg));

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    let (err, violation_recorded) =
        QueueView::with(2, &mut state.queues[2], &vm, VIRTIO_F_VERSION_1, |view| {
            let err = console.process_queue(2, view).unwrap_err();
            (err, view.violation())
        })
        .unwrap();

    assert_eq!(
        ctrl.front(),
        Some(msg),
        "control message should remain in mmap state until used-ring publish succeeds"
    );
    assert!(matches!(err, QueueViolation::UsedIdxWriteFailed { .. }));
    assert_eq!(violation_recorded, Some(err));
}

// =============================================================================
// Port 1 (agent channel)
// =============================================================================

#[test]
fn test_port1_tx_delivers_to_backend() {
    use crate::AgentPortBackend;

    struct RecordingPort {
        received: Vec<u8>,
    }
    impl AgentPortBackend for RecordingPort {
        fn has_pending_rx(&self) -> bool {
            false
        }
        fn read_rx(&mut self, _buf: &mut [u8]) -> usize {
            0
        }
        fn write_tx(&mut self, data: &[u8]) {
            self.received.extend_from_slice(data);
        }
    }

    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    // Queue 5 = port 1 TX
    state.queues[5].size = 16;
    state.queues[5].ready = 1;
    state.queues[5].desc_addr = 0x0000;
    state.queues[5].avail_addr = 0x1000;
    state.queues[5].used_addr = 0x2000;

    // Write a 1-byte kick signal
    {
        let gw = vm.gpa_write(0x3000, [1u8].len()).unwrap();
        gw.write_from(&[1u8]);
    };
    let desc = Descriptor {
        addr: 0x3000,
        len: 1,
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = RecordingPort {
        received: Vec::new(),
    };
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 5, &vm, console).unwrap();

    assert_eq!(state.queues[5].last_avail_idx, 1);
    assert_eq!(&port1.received, &[1u8]);
    let used_len: u32 = vm.read_obj(0x2008u64).unwrap();
    assert_eq!(used_len, 0);
}

#[test]
fn test_port1_rx_delivers_from_backend() {
    use crate::AgentPortBackend;

    struct DataPort {
        data: Vec<u8>,
        pos: usize,
    }
    impl AgentPortBackend for DataPort {
        fn has_pending_rx(&self) -> bool {
            self.pos < self.data.len()
        }
        fn read_rx(&mut self, buf: &mut [u8]) -> usize {
            let remaining = &self.data[self.pos..];
            let n = buf.len().min(remaining.len());
            buf[..n].copy_from_slice(&remaining[..n]);
            self.pos += n;
            n
        }
        fn write_tx(&mut self, _data: &[u8]) {}
    }

    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    // Queue 4 = port 1 RX
    state.queues[4].size = 16;
    state.queues[4].ready = 1;
    state.queues[4].desc_addr = 0x0000;
    state.queues[4].avail_addr = 0x1000;
    state.queues[4].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 64,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = DataPort {
        data: vec![0xAA, 0xBB],
        pos: 0,
    };
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    process_console_queue!(state, 4, &vm, console).unwrap();

    assert_eq!(state.queues[4].last_avail_idx, 1);

    let mut buf = [0u8; 2];
    vm.gpa_read(0x3000, buf.len()).unwrap().read_to(&mut buf);
    assert_eq!(buf, [0xAA, 0xBB]);
}

#[test]
fn test_port1_rx_rejects_oversized_backend_read() {
    use crate::AgentPortBackend;

    struct OversizedPort;

    impl AgentPortBackend for OversizedPort {
        fn has_pending_rx(&self) -> bool {
            true
        }

        fn read_rx(&mut self, buf: &mut [u8]) -> usize {
            buf.len() + 1
        }

        fn write_tx(&mut self, _data: &[u8]) {}
    }

    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[4].size = 16;
    state.queues[4].ready = 1;
    state.queues[4].desc_addr = 0x0000;
    state.queues[4].avail_addr = 0x1000;
    state.queues[4].used_addr = 0x2000;

    let desc = Descriptor {
        addr: 0x3000,
        len: 8,
        flags: VIRTQ_DESC_F_WRITE,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = OversizedPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = Console::new(&backend, &mut port1, &mut ctrl);
    assert_eq!(
        process_console_queue!(state, 4, &vm, console),
        Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "port1 rx read",
        })
    );
    assert_eq!(state.queues[4].last_used_idx, 0);
}

// =============================================================================
// Regression: TX must cap per-descriptor allocation
// =============================================================================
//
// A guest-controlled `slice.len` (u32, up to 4 GiB) flows directly into
// descriptor reads at lib.rs:164 and :459. The chain-wide
// `MAX_CHAIN_BYTES` check at the top of the loop only bounds *subsequent*
// iterations — the first descriptor is copied in full before any cap applies.
// Post-fix (D2): the per-descriptor copy must be bounded by a structural cap
// (e.g. descriptor chunking), regardless of how many
// descriptors the chain contains.

#[test]
fn port0_tx_caps_oversized_single_descriptor() {
    // Guest RAM large enough to host a 1.5 MiB descriptor.
    const BIG_MEM: usize = TEST_RAM_SIZE;
    // 1.5 MiB descriptor at 0x8000 — safely inside 2 MiB guest RAM.
    const DESC_DATA_GPA: u64 = 0x8000;
    const OVERSIZED_LEN: u32 = 1_572_864; // 1.5 MiB

    let mmap = test_mmap(BIG_MEM);
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: ConsoleState = Zeroable::zeroed();

    state.queues[1].size = 16;
    state.queues[1].ready = 1;
    state.queues[1].desc_addr = 0x0000;
    state.queues[1].avail_addr = 0x1000;
    state.queues[1].used_addr = 0x2000;

    let desc = Descriptor {
        addr: DESC_DATA_GPA,
        len: OVERSIZED_LEN,
        flags: 0,
        next: 0,
    };
    vm.write_obj(0x0000u64, &desc).unwrap();
    vm.write_obj(0x1004u64, &0u16).unwrap();
    vm.write_obj(0x1002u64, &1u16).unwrap();

    let backend = TestBackend::new();
    let mut port1 = NullAgentPort;
    let mut ctrl = ConsoleControlState::zeroed();
    let mut console = make_console(&backend, &mut port1, &mut ctrl);
    let err = process_console_queue!(state, 1, &vm, console).unwrap_err();

    assert!(matches!(
        err,
        QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "console_tx_chain_too_large",
        }
    ));
    assert!(backend.output.lock().unwrap().is_empty());
    assert_eq!(state.queues[1].last_used_idx, 0);
}
