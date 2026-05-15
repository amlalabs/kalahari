// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg(unix)]
//! Ring channel stress tests — cross-process IPC with the test helper binary.
//!
//! Exercises: ring-first ordering, handle-free fast path, handle-carrying
//! messages, high-throughput message streams, multiple child processes,
//! and edge cases.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::time::Duration;

use amla_ipc::{IpcMessage, RingBuffer, Subprocess};
use amla_mem::MemHandle;

// =========================================================================
// Wire protocol — must match ipc_test_helper.rs
// =========================================================================

#[derive(Debug, IpcMessage)]
enum TestMsg {
    Init {
        mode: String,
    },
    Ping {
        seq: u32,
        payload: String,
    },
    PingMem {
        seq: u32,
        #[ipc_resource]
        region: MemHandle,
    },
    PingMultiMem {
        seq: u32,
        #[ipc_resource]
        regions: Vec<MemHandle>,
    },
    Pong {
        seq: u32,
        payload: String,
    },
    PongMem {
        seq: u32,
        #[ipc_resource]
        region: MemHandle,
    },
    PongMultiMem {
        seq: u32,
        #[ipc_resource]
        regions: Vec<MemHandle>,
    },
    WriteMem {
        seq: u32,
        value: u8,
        #[ipc_resource]
        region: MemHandle,
    },
    Ok {
        seq: u32,
    },
    Shutdown,
}

// =========================================================================
// Helpers
// =========================================================================

fn helper_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ipc_test_helper"))
}

fn make_mem(size: usize, marker: u8) -> MemHandle {
    MemHandle::allocate_and_write(c"test", size, |slice| {
        slice[0] = marker;
        Ok(())
    })
    .unwrap()
}

fn read_marker(handle: &MemHandle) -> u8 {
    let mmap = amla_mem::map_handle(handle).unwrap();
    // SAFETY: test-local mapping; reads happen after writes are synchronized
    // by the test protocol.
    (unsafe { mmap.as_slice_unchecked() })[0]
}

struct TestChild {
    sender: amla_ipc::Sender<'static>,
    receiver: amla_ipc::Receiver<'static>,
    _ring: Box<RingBuffer>,
}

impl TestChild {
    async fn spawn() -> Self {
        let helper = helper_path();
        let child = Subprocess::spawn(&helper, &[], &[]).unwrap();
        let mut ring = Box::new(RingBuffer::establish(child).unwrap());

        // SAFETY: ring lives in the Box which we return alongside sender/receiver.
        let ring_ref: &'static mut RingBuffer = unsafe { &mut *(ring.as_mut() as *mut RingBuffer) };
        let (mut sender, receiver) = ring_ref.split(true).unwrap();

        // First message selects the mode.
        sender
            .send(TestMsg::Init {
                mode: "echo".into(),
            })
            .await
            .unwrap();

        Self {
            sender,
            receiver,
            _ring: ring,
        }
    }

    async fn ping(&mut self, seq: u32, payload: &str) -> (u32, String) {
        self.sender
            .send(TestMsg::Ping {
                seq,
                payload: payload.to_string(),
            })
            .await
            .unwrap();
        let resp = self.recv_timeout().await;
        match resp {
            TestMsg::Pong { seq, payload } => (seq, payload),
            other => panic!("expected Pong, got {other:?}"),
        }
    }

    async fn ping_mem(&mut self, seq: u32, marker: u8) -> (u32, u8) {
        let region = make_mem(4096, marker);
        self.sender
            .send(TestMsg::PingMem { seq, region })
            .await
            .unwrap();
        let resp = self.recv_timeout().await;
        match resp {
            TestMsg::PongMem { seq, region } => (seq, read_marker(&region)),
            other => panic!("expected PongMem, got {other:?}"),
        }
    }

    async fn shutdown(&mut self) {
        self.sender.send(TestMsg::Shutdown).await.unwrap();
    }

    async fn recv_timeout(&mut self) -> TestMsg {
        tokio::time::timeout(Duration::from_secs(10), self.receiver.recv::<TestMsg>())
            .await
            .expect("recv timed out")
            .expect("recv error")
    }
}

// =========================================================================
// Basic echo tests
// =========================================================================

/// Single ping-pong: verify basic round-trip.
#[tokio::test]
async fn echo_basic() {
    let mut child = TestChild::spawn().await;
    let (seq, payload) = child.ping(1, "hello").await;
    assert_eq!(seq, 1);
    assert_eq!(payload, "echo:hello");
    child.shutdown().await;
}

/// MemHandle round-trip: verify SCM_RIGHTS fd passing through the protocol.
#[tokio::test]
async fn echo_memhandle() {
    let mut child = TestChild::spawn().await;
    let (seq, marker) = child.ping_mem(1, 0x42).await;
    assert_eq!(seq, 1);
    assert_eq!(marker, 0x43); // child increments marker by 1
    child.shutdown().await;
}

/// Large payload: 32KB message to exercise ring backoff under pressure.
#[tokio::test]
async fn echo_large_payload() {
    let mut child = TestChild::spawn().await;
    let big = "X".repeat(32768);
    let (seq, payload) = child.ping(99, &big).await;
    assert_eq!(seq, 99);
    assert_eq!(payload, format!("echo:{big}"));
    child.shutdown().await;
}

/// Minimal payload: empty message.
#[tokio::test]
async fn echo_empty_payload() {
    let mut child = TestChild::spawn().await;
    let (seq, payload) = child.ping(0, "").await;
    assert_eq!(seq, 0);
    assert_eq!(payload, "echo:");
    child.shutdown().await;
}

// =========================================================================
// Handle interleaving tests
// =========================================================================

/// Interleaved handle-free and handle-carrying messages.
#[tokio::test]
async fn echo_interleaved_handles() {
    let mut child = TestChild::spawn().await;
    for i in 0..50u32 {
        if i % 7 == 0 {
            let (seq, marker) = child.ping_mem(i, i as u8).await;
            assert_eq!(seq, i);
            assert_eq!(marker, (i as u8).wrapping_add(1));
        } else {
            let (seq, _) = child.ping(i, &format!("msg-{i}")).await;
            assert_eq!(seq, i);
        }
    }
    child.shutdown().await;
}

/// Many consecutive handle-carrying messages.
#[tokio::test]
async fn echo_consecutive_handles() {
    let mut child = TestChild::spawn().await;
    for i in 0..10u32 {
        let (seq, marker) = child.ping_mem(i, (0x10 + i) as u8).await;
        assert_eq!(seq, i);
        assert_eq!(marker, (0x10 + i) as u8 + 1);
    }
    child.shutdown().await;
}

/// First message carries a handle.
#[tokio::test]
async fn echo_handle_first_message() {
    let mut child = TestChild::spawn().await;
    let (seq, marker) = child.ping_mem(42, 0xEE).await;
    assert_eq!(seq, 42);
    assert_eq!(marker, 0xEF);
    child.shutdown().await;
}

/// Multiple MemHandles in a single message.
#[tokio::test]
async fn echo_multi_mem() {
    let mut child = TestChild::spawn().await;
    let regions: Vec<MemHandle> = (0..3).map(|i| make_mem(4096, 0x30 + i)).collect();
    child
        .sender
        .send(TestMsg::PingMultiMem { seq: 7, regions })
        .await
        .unwrap();
    let resp = child.recv_timeout().await;
    match resp {
        TestMsg::PongMultiMem { seq, regions } => {
            assert_eq!(seq, 7);
            assert_eq!(regions.len(), 3);
            for (i, r) in regions.iter().enumerate() {
                assert_eq!(read_marker(r), 0x30 + i as u8 + 1);
            }
        }
        other => panic!("expected PongMultiMem, got {other:?}"),
    }
    child.shutdown().await;
}

/// WriteMem: child writes to a shared mapping, parent reads it back.
#[tokio::test]
async fn write_mem_shared() {
    let mut child = TestChild::spawn().await;
    let region = make_mem(4096, 0x00);
    child
        .sender
        .send(TestMsg::WriteMem {
            seq: 1,
            value: 0xBB,
            region: region.try_clone().unwrap(),
        })
        .await
        .unwrap();
    let resp = child.recv_timeout().await;
    assert!(matches!(resp, TestMsg::Ok { seq: 1 }));
    // The child wrote to the same backing memfd — verify parent sees it.
    assert_eq!(read_marker(&region), 0xBB);
    child.shutdown().await;
}

// =========================================================================
// Throughput / volume tests
// =========================================================================

/// 1000 rapid-fire ping-pongs: exercises sustained IPC throughput.
#[tokio::test]
async fn rapid_fire_1k() {
    let mut child = TestChild::spawn().await;
    for i in 0..1000u32 {
        let (seq, payload) = child.ping(i, "x").await;
        assert_eq!(seq, i);
        assert_eq!(payload, "echo:x");
    }
    child.shutdown().await;
}

// =========================================================================
// Multiple child processes
// =========================================================================

/// Multiple children running concurrently on independent channels.
#[tokio::test]
async fn multiple_children() {
    let mut children: Vec<TestChild> = Vec::new();
    for _ in 0..4 {
        children.push(TestChild::spawn().await);
    }

    for (i, child) in children.iter_mut().enumerate() {
        let (seq, payload) = child.ping(i as u32, &format!("child-{i}")).await;
        assert_eq!(seq, i as u32);
        assert_eq!(payload, format!("echo:child-{i}"));
    }

    for (i, child) in children.iter_mut().enumerate() {
        let (seq, marker) = child.ping_mem(100 + i as u32, (0x50 + i) as u8).await;
        assert_eq!(seq, 100 + i as u32);
        assert_eq!(marker, (0x50 + i) as u8 + 1);
    }

    for child in &mut children {
        child.shutdown().await;
    }
}

// =========================================================================
// Edge cases
// =========================================================================

/// Immediate shutdown: first and only message is Shutdown.
#[tokio::test]
async fn shutdown_immediate() {
    let mut child = TestChild::spawn().await;
    child.shutdown().await;
}

/// Rapid sequential children: spawn, use, shutdown, repeat.
#[tokio::test]
async fn rapid_child_lifecycle() {
    for i in 0..10u32 {
        let mut child = TestChild::spawn().await;
        let (seq, _) = child.ping(i, "life").await;
        assert_eq!(seq, i);
        child.shutdown().await;
    }
}
