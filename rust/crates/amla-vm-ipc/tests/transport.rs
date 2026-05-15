// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg(unix)]
//! Integration tests for amla-ipc: subprocess spawn + ring channel + MemHandle transfer.
//!
//! Spawns `ipc_test_helper` as a subprocess and exercises the full IPC path:
//! ring buffer data transfer + out-of-band MemHandle delivery (SCM_RIGHTS on
//! Linux, Mach port descriptors on macOS).
//!
//! These tests use only the cross-platform `amla-ipc` API and run unchanged
//! on both Linux and macOS.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;

use amla_ipc::{IpcMessage, RingBuffer, Subprocess};
use amla_mem::MemHandle;

// =========================================================================
// Wire protocol (must match ipc_test_helper.rs exactly)
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

    /// Ask the child to write `value` at offset 0 of `region`, then reply Ok.
    WriteMem {
        seq: u32,
        value: u8,
        #[ipc_resource]
        region: MemHandle,
    },

    /// Generic ok reply (no payload).
    Ok {
        seq: u32,
    },

    Shutdown,
}

// =========================================================================
// Helpers
// =========================================================================

/// Find the test helper binary built by Cargo for this integration test.
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

// =========================================================================
// Test-only owned split
// =========================================================================
//
// The real `RingBuffer::split(&mut self)` returns borrowed halves whose
// lifetime is tied to the ring. Tests need `'static` halves so they can
// cross `tokio::spawn`/`spawn_blocking` boundaries. Rather than leaking
// the ring (`Box::leak`), we heap-pin it in an `Arc<UnsafeCell<_>>` and
// attach an Arc clone to each returned half; when both halves drop, the
// last Arc release runs `RingBuffer::drop` and unmaps the region.

use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;

/// `RingBuffer` heap-pinned behind an `Arc` so both channel halves can
/// keep the backing mapping alive. `split_static` unsafely launders the
/// borrowed-half lifetime to `'static`; soundness rests on (a) `split`
/// being called at most once per fixture, and (b) both halves holding an
/// Arc clone so the ring outlives every ref.
struct RingCell(UnsafeCell<RingBuffer>);

// SAFETY: RingBuffer is Send; after split_static, the Sender and Receiver
// each serialize access to their own ring direction via atomics in the
// mmap region. The UnsafeCell wrapper only exists to let us take a
// one-shot &mut through the Arc.
unsafe impl Send for RingCell {}
unsafe impl Sync for RingCell {}

struct OwnedRing(Arc<RingCell>);

impl OwnedRing {
    fn new(ring: RingBuffer) -> Self {
        Self(Arc::new(RingCell(UnsafeCell::new(ring))))
    }

    fn split_static(&self, is_host: bool) -> (OwnedSender, OwnedReceiver) {
        // SAFETY: called exactly once per OwnedRing in these tests. No
        // concurrent access to the RingBuffer struct itself at this
        // moment — we hold the sole &self borrow.
        let r: &mut RingBuffer = unsafe { &mut *self.0.0.get() };
        let (sender, receiver) = r.split(is_host).unwrap();
        // SAFETY: lifetime of `sender`/`receiver` is tied to `r`, which
        // points into the Arc-owned UnsafeCell. The Arc clones stored in
        // the returned wrappers keep that storage alive for as long as
        // either half exists, so the `'static` relabel holds in practice.
        let sender: amla_ipc::Sender<'static> = unsafe { std::mem::transmute(sender) };
        let receiver: amla_ipc::Receiver<'static> = unsafe { std::mem::transmute(receiver) };
        (
            OwnedSender {
                inner: sender,
                _ring: Arc::clone(&self.0),
            },
            OwnedReceiver {
                inner: receiver,
                _ring: Arc::clone(&self.0),
            },
        )
    }
}

struct OwnedSender {
    inner: amla_ipc::Sender<'static>,
    _ring: Arc<RingCell>,
}

impl Deref for OwnedSender {
    type Target = amla_ipc::Sender<'static>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OwnedSender {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

struct OwnedReceiver {
    inner: amla_ipc::Receiver<'static>,
    _ring: Arc<RingCell>,
}

impl Deref for OwnedReceiver {
    type Target = amla_ipc::Receiver<'static>;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for OwnedReceiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

/// Spawn the helper and return (sender, receiver).
async fn spawn_echo() -> (OwnedSender, OwnedReceiver) {
    let path = helper_path();
    let child = Subprocess::spawn(&path, &[], &[]).unwrap();
    let ring = OwnedRing::new(RingBuffer::establish(child).unwrap());
    let (mut sender, receiver) = ring.split_static(true);
    // First message selects the mode.
    sender
        .send(TestMsg::Init {
            mode: "echo".into(),
        })
        .await
        .unwrap();
    (sender, receiver)
}

// =========================================================================
// Tests: basic IPC
// =========================================================================

#[tokio::test]
async fn pure_data_roundtrip() {
    let (mut sender, mut receiver) = spawn_echo().await;

    sender
        .send(TestMsg::Ping {
            seq: 1,
            payload: "hello".into(),
        })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::Pong { seq, payload } => {
            assert_eq!(seq, 1);
            assert_eq!(payload, "echo:hello");
        }
        other => panic!("expected Pong, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

#[tokio::test]
async fn single_memhandle_roundtrip() {
    let (mut sender, mut receiver) = spawn_echo().await;

    let region = make_mem(4096, 0x42);
    sender
        .send(TestMsg::PingMem { seq: 2, region })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 2);
            assert_eq!(read_marker(&region), 0x43);
            assert_eq!(*region.size(), amla_mem::page_size());
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

#[tokio::test]
async fn multiple_memhandle_roundtrip() {
    let (mut sender, mut receiver) = spawn_echo().await;

    let regions: Vec<_> = (0..3).map(|i| make_mem(4096, 0x10 + i)).collect();
    sender
        .send(TestMsg::PingMultiMem { seq: 3, regions })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::PongMultiMem { seq, regions } => {
            assert_eq!(seq, 3);
            assert_eq!(regions.len(), 3);
            for (i, region) in regions.iter().enumerate() {
                assert_eq!(read_marker(region), 0x11 + i as u8);
                assert_eq!(*region.size(), amla_mem::page_size());
            }
        }
        other => panic!("expected PongMultiMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

#[tokio::test]
async fn many_sequential_messages() {
    let (mut sender, mut receiver) = spawn_echo().await;

    for i in 0..50 {
        sender
            .send(TestMsg::Ping {
                seq: i,
                payload: format!("msg-{i}"),
            })
            .await
            .unwrap();

        let resp = receiver.recv::<TestMsg>().await.unwrap();
        match resp {
            TestMsg::Pong { seq, payload } => {
                assert_eq!(seq, i);
                assert_eq!(payload, format!("echo:msg-{i}"));
            }
            other => panic!("expected Pong for seq={i}, got {other:?}"),
        }
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

#[tokio::test]
async fn interleaved_data_and_mem() {
    let (mut sender, mut receiver) = spawn_echo().await;

    sender
        .send(TestMsg::Ping {
            seq: 10,
            payload: "first".into(),
        })
        .await
        .unwrap();
    let resp = receiver.recv::<TestMsg>().await.unwrap();
    assert!(matches!(resp, TestMsg::Pong { seq: 10, .. }));

    let region = make_mem(8192, 0xAA);
    sender
        .send(TestMsg::PingMem { seq: 11, region })
        .await
        .unwrap();
    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 11);
            assert_eq!(read_marker(&region), 0xAB);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender
        .send(TestMsg::Ping {
            seq: 12,
            payload: "third".into(),
        })
        .await
        .unwrap();
    let resp = receiver.recv::<TestMsg>().await.unwrap();
    assert!(matches!(resp, TestMsg::Pong { seq: 12, .. }));

    sender.send(TestMsg::Shutdown).await.unwrap();
}

#[tokio::test]
async fn zero_handles_message() {
    let (mut sender, mut receiver) = spawn_echo().await;

    sender
        .send(TestMsg::PingMultiMem {
            seq: 20,
            regions: vec![],
        })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::PongMultiMem { seq, regions } => {
            assert_eq!(seq, 20);
            assert!(regions.is_empty());
        }
        other => panic!("expected PongMultiMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

// =========================================================================
// Tests: shared memory visibility
// =========================================================================

/// Verify that a MemHandle transferred to the child maps the SAME physical
/// pages. The child writes to offset 0 and the parent sees the write
/// through its own mapping of the same handle.
#[tokio::test]
async fn shared_memory_write_visible_cross_process() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Allocate a region and keep a clone in the parent.
    let region = make_mem(4096, 0x00);
    let parent_clone = region.try_clone().unwrap();
    let parent_mmap = amla_mem::map_handle(&parent_clone).unwrap();

    // Confirm initial state.
    assert_eq!((unsafe { parent_mmap.as_slice_unchecked() })[0], 0x00);

    // Send to child with WriteMem — child writes value at offset 0.
    sender
        .send(TestMsg::WriteMem {
            seq: 40,
            value: 0xBE,
            region,
        })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    assert!(matches!(resp, TestMsg::Ok { seq: 40 }));

    // The child's write should be visible through the parent's mapping.
    assert_eq!((unsafe { parent_mmap.as_slice_unchecked() })[0], 0xBE);

    sender.send(TestMsg::Shutdown).await.unwrap();
}

// =========================================================================
// Tests: MemHandle branching
// =========================================================================

#[test]
fn branch_preserves_data() {
    let parent = make_mem(4096, 0xAA);
    // SAFETY: The test owns `parent` and has no active mappings or writers.
    let child = unsafe { parent.branch() }.unwrap();

    assert_eq!(read_marker(&child), 0xAA);
    assert_eq!(*child.size(), amla_mem::page_size());
}

#[test]
fn branch_cow_isolation() {
    let parent = MemHandle::allocate_and_write(c"test", 4096, |slice| {
        slice[0] = 0x11;
        slice[1] = 0x22;
        Ok(())
    })
    .unwrap();

    // SAFETY: Initial writes completed before branching; no mappings or other
    // writers are active while the branch is created.
    let child = unsafe { parent.branch() }.unwrap();

    // Write to child — should NOT affect parent (CoW).
    {
        let mmap = amla_mem::map_handle(&child).unwrap();
        let slice = unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), 4096) };
        slice[0] = 0xFF;
    }

    // Parent still has original data.
    let parent_mmap = amla_mem::map_handle(&parent).unwrap();
    assert_eq!((unsafe { parent_mmap.as_slice_unchecked() })[0], 0x11);
    assert_eq!((unsafe { parent_mmap.as_slice_unchecked() })[1], 0x22);

    // Child has modified data.
    let child_mmap = amla_mem::map_handle(&child).unwrap();
    assert_eq!((unsafe { child_mmap.as_slice_unchecked() })[0], 0xFF);
    assert_eq!((unsafe { child_mmap.as_slice_unchecked() })[1], 0x22);
}

#[test]
fn branch_can_rebranch() {
    let root = make_mem(4096, 0x01);
    // SAFETY: The test owns `root` and has no active mappings or writers.
    let child = unsafe { root.branch() }.unwrap();
    // SAFETY: The test owns `child` and has no active mappings or writers.
    let grandchild = unsafe { child.branch() }.unwrap();
    assert_eq!(read_marker(&grandchild), 0x01);
    assert_eq!(*grandchild.size(), amla_mem::page_size());
}

/// Branch a MemHandle, send the branch over IPC, verify the child process
/// can read the CoW snapshot and the parent is unaffected.
#[tokio::test]
async fn branch_sent_over_ipc() {
    let (mut sender, mut receiver) = spawn_echo().await;

    let parent = make_mem(4096, 0x77);
    // SAFETY: The test owns `parent` and has no active mappings or writers.
    let branch = unsafe { parent.branch() }.unwrap();

    sender
        .send(TestMsg::PingMem {
            seq: 30,
            region: branch,
        })
        .await
        .unwrap();

    let resp = receiver.recv::<TestMsg>().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 30);
            // Helper increments marker: 0x77 -> 0x78.
            assert_eq!(read_marker(&region), 0x78);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    // Parent should be unaffected.
    assert_eq!(read_marker(&parent), 0x77);

    sender.send(TestMsg::Shutdown).await.unwrap();
}

// =========================================================================
// Tests: multiple concurrent subprocesses
// =========================================================================

/// Spawn two subprocesses simultaneously, send/recv on each independently.
#[tokio::test]
async fn two_concurrent_subprocesses_pure_data() {
    let (mut s1, mut r1) = spawn_echo().await;
    let (mut s2, mut r2) = spawn_echo().await;

    // Send to both.
    s1.send(TestMsg::Ping {
        seq: 100,
        payload: "child1".into(),
    })
    .await
    .unwrap();
    s2.send(TestMsg::Ping {
        seq: 200,
        payload: "child2".into(),
    })
    .await
    .unwrap();

    // Receive from both — each should get its own response.
    let resp1 = r1.recv::<TestMsg>().await.unwrap();
    let resp2 = r2.recv::<TestMsg>().await.unwrap();

    match resp1 {
        TestMsg::Pong { seq, payload } => {
            assert_eq!(seq, 100);
            assert_eq!(payload, "echo:child1");
        }
        other => panic!("child1: expected Pong, got {other:?}"),
    }
    match resp2 {
        TestMsg::Pong { seq, payload } => {
            assert_eq!(seq, 200);
            assert_eq!(payload, "echo:child2");
        }
        other => panic!("child2: expected Pong, got {other:?}"),
    }

    s1.send(TestMsg::Shutdown).await.unwrap();
    s2.send(TestMsg::Shutdown).await.unwrap();
}

/// Spawn two subprocesses, send MemHandles to each, verify isolation.
#[tokio::test]
async fn two_concurrent_subprocesses_with_memhandles() {
    let (mut s1, mut r1) = spawn_echo().await;
    let (mut s2, mut r2) = spawn_echo().await;

    let region1 = make_mem(4096, 0xAA);
    let region2 = make_mem(4096, 0xBB);

    s1.send(TestMsg::PingMem {
        seq: 101,
        region: region1,
    })
    .await
    .unwrap();
    s2.send(TestMsg::PingMem {
        seq: 201,
        region: region2,
    })
    .await
    .unwrap();

    let resp1 = r1.recv::<TestMsg>().await.unwrap();
    let resp2 = r2.recv::<TestMsg>().await.unwrap();

    match resp1 {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 101);
            assert_eq!(read_marker(&region), 0xAB); // 0xAA + 1
        }
        other => panic!("child1: expected PongMem, got {other:?}"),
    }
    match resp2 {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 201);
            assert_eq!(read_marker(&region), 0xBC); // 0xBB + 1
        }
        other => panic!("child2: expected PongMem, got {other:?}"),
    }

    s1.send(TestMsg::Shutdown).await.unwrap();
    s2.send(TestMsg::Shutdown).await.unwrap();
}

/// Spawn three subprocesses, interleave messages with and without MemHandles.
#[tokio::test]
async fn three_subprocesses_interleaved() {
    let (mut s1, mut r1) = spawn_echo().await;
    let (mut s2, mut r2) = spawn_echo().await;
    let (mut s3, mut r3) = spawn_echo().await;

    // Pure data to each.
    for (i, s) in [&mut s1, &mut s2, &mut s3].iter_mut().enumerate() {
        s.send(TestMsg::Ping {
            seq: (i * 10) as u32,
            payload: format!("hello-{i}"),
        })
        .await
        .unwrap();
    }

    for (i, r) in [&mut r1, &mut r2, &mut r3].iter_mut().enumerate() {
        let resp = r.recv::<TestMsg>().await.unwrap();
        match resp {
            TestMsg::Pong { seq, payload } => {
                assert_eq!(seq, (i * 10) as u32);
                assert_eq!(payload, format!("echo:hello-{i}"));
            }
            other => panic!("subprocess {i}: expected Pong, got {other:?}"),
        }
    }

    // MemHandle to each.
    for (i, s) in [&mut s1, &mut s2, &mut s3].iter_mut().enumerate() {
        let region = make_mem(4096, (0x10 + i) as u8);
        s.send(TestMsg::PingMem {
            seq: (100 + i) as u32,
            region,
        })
        .await
        .unwrap();
    }

    for (i, r) in [&mut r1, &mut r2, &mut r3].iter_mut().enumerate() {
        let resp = r.recv::<TestMsg>().await.unwrap();
        match resp {
            TestMsg::PongMem { seq, region } => {
                assert_eq!(seq, (100 + i) as u32);
                assert_eq!(read_marker(&region), (0x11 + i) as u8);
            }
            other => panic!("subprocess {i}: expected PongMem, got {other:?}"),
        }
    }

    s1.send(TestMsg::Shutdown).await.unwrap();
    s2.send(TestMsg::Shutdown).await.unwrap();
    s3.send(TestMsg::Shutdown).await.unwrap();
}

/// Reproduce the VMM `create_shell` pattern: spawn a subprocess and do
/// the Init handshake from inside `spawn_blocking` with a nested tokio runtime.
#[tokio::test]
async fn init_handshake_from_spawn_blocking() {
    let result = tokio::task::spawn_blocking(|| {
        let path = helper_path();
        let child = Subprocess::spawn(&path, &[], &[]).unwrap();
        let ring = OwnedRing::new(RingBuffer::establish(child).unwrap());
        let (mut sender, mut receiver) = ring.split_static(true);

        // Nested runtime — same as create_shell does.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async {
            // First message selects the mode.
            sender
                .send(TestMsg::Init {
                    mode: "echo".into(),
                })
                .await
                .unwrap();

            sender
                .send(TestMsg::Ping {
                    seq: 999,
                    payload: "from_spawn_blocking".into(),
                })
                .await
                .unwrap();

            let resp = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                receiver.recv::<TestMsg>(),
            )
            .await
            .expect("timeout waiting for response")
            .unwrap();

            match resp {
                TestMsg::Pong { seq, payload } => {
                    assert_eq!(seq, 999);
                    assert_eq!(payload, "echo:from_spawn_blocking");
                }
                other => panic!("expected Pong, got {other:?}"),
            }

            sender.send(TestMsg::Shutdown).await.unwrap();
        });
    })
    .await;

    result.unwrap();
}
