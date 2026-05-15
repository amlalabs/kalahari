// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg(unix)]
#![cfg(target_os = "linux")]
//! Cancel-safety tests for the SendPermit reserve/commit API.
//!
//! Verifies:
//! - Abort before commit transfers nothing.
//! - Cancel during commit delivers a complete frame or nothing.
//! - Oversized FD batch is rejected before any transfer.
//! - Peer never observes a header without its promised FDs.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::cell::UnsafeCell;
use std::ops::{Deref, DerefMut};
use std::path::PathBuf;
use std::sync::Arc;
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
    MemHandle::allocate_and_write(c"test", size, |s| {
        s[0] = marker;
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
// Test-only owned split (same pattern as transport.rs)
// =========================================================================

struct RingCell(UnsafeCell<RingBuffer>);
unsafe impl Send for RingCell {}
unsafe impl Sync for RingCell {}

struct OwnedRing(Arc<RingCell>);

impl OwnedRing {
    fn new(ring: RingBuffer) -> Self {
        Self(Arc::new(RingCell(UnsafeCell::new(ring))))
    }

    fn split_static(&self, is_host: bool) -> (OwnedSender, OwnedReceiver) {
        let r: &mut RingBuffer = unsafe { &mut *self.0.0.get() };
        let (sender, receiver) = r.split(is_host).unwrap();
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

async fn spawn_echo() -> (OwnedSender, OwnedReceiver) {
    let path = helper_path();
    let child = Subprocess::spawn(&path, &[], &[]).unwrap();
    let ring = OwnedRing::new(RingBuffer::establish(child).unwrap());
    let (mut sender, receiver) = ring.split_static(true);
    sender
        .send(TestMsg::Init {
            mode: "echo".into(),
        })
        .await
        .unwrap();
    (sender, receiver)
}

// =========================================================================
// Tests
// =========================================================================

/// Cancel (abort) before commit leaves peer with no frame and no FDs.
#[tokio::test]
async fn abort_before_commit_transfers_nothing() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Reserve a send with a MemHandle, then abort.
    let mem = make_mem(4096, 0xAB);
    let permit = sender
        .reserve_send(TestMsg::PingMem {
            seq: 1,
            region: mem,
        })
        .await
        .unwrap();
    permit.abort();

    // Now send a real FD-bearing message and verify the peer responds to it
    // (not to any phantom from the aborted permit, and not with orphaned FDs).
    let real_mem = make_mem(4096, 0x10);
    sender
        .send(TestMsg::PingMem {
            seq: 2,
            region: real_mem,
        })
        .await
        .unwrap();

    let resp: TestMsg = receiver.recv().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 2);
            assert_eq!(read_marker(&region), 0x11);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

/// Drop the permit (implicit abort) also transfers nothing.
#[tokio::test]
async fn drop_permit_transfers_nothing() {
    let (mut sender, mut receiver) = spawn_echo().await;

    {
        let mem = make_mem(4096, 0xCD);
        let _permit = sender
            .reserve_send(TestMsg::PingMem {
                seq: 1,
                region: mem,
            })
            .await
            .unwrap();
        // _permit dropped here
    }

    let real_mem = make_mem(4096, 0x20);
    sender
        .send(TestMsg::PingMem {
            seq: 2,
            region: real_mem,
        })
        .await
        .unwrap();

    let resp: TestMsg = receiver.recv().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 2);
            assert_eq!(read_marker(&region), 0x21);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

/// Cancel during commit (via select!) either delivers a complete frame or
/// nothing — never a partial frame.
#[tokio::test]
async fn cancel_during_commit_is_atomic() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Try to cancel commit with a very short timeout.  Whether the
    // cancellation fires before or after the internal send_slots await,
    // the peer must either see a complete PingMem or see nothing.
    let mem = make_mem(4096, 0xEE);
    let permit = sender
        .reserve_send(TestMsg::PingMem {
            seq: 1,
            region: mem,
        })
        .await
        .unwrap();

    let committed = tokio::select! {
        biased;
        result = permit.commit() => {
            result.unwrap();
            true
        }
        _ = tokio::task::yield_now() => {
            // Cancelled before commit completed.
            false
        }
    };

    // Now send an FD-bearing sentinel and check what the peer saw.  If
    // the cancelled commit orphaned aux FDs, this send would trip the
    // seq/count validation on the peer.
    let sentinel_mem = make_mem(4096, 0x44);
    sender
        .send(TestMsg::PingMem {
            seq: 99,
            region: sentinel_mem,
        })
        .await
        .unwrap();

    if committed {
        // Expect PongMem(seq=1) then PongMem(seq=99).
        let resp: TestMsg = receiver.recv().await.unwrap();
        match resp {
            TestMsg::PongMem { seq, region } => {
                assert_eq!(seq, 1);
                assert_eq!(read_marker(&region), 0xEE + 1);
            }
            other => panic!("expected PongMem, got {other:?}"),
        }
    }
    // In either case the sentinel must arrive intact.
    let sentinel: TestMsg = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("timeout waiting for sentinel")
        .unwrap();
    match sentinel {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 99);
            assert_eq!(read_marker(&region), 0x45);
        }
        other => panic!("expected sentinel PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

/// Oversized FD batch is rejected before any FD transfer.
#[tokio::test]
async fn oversized_slot_batch_rejected() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Create a message with > 64 MemHandles.
    let regions: Vec<MemHandle> = (0..65).map(|i| make_mem(4096, i as u8)).collect();

    let result = sender
        .reserve_send(TestMsg::PingMultiMem { seq: 1, regions })
        .await;

    let err = match result {
        Err(e) => e,
        Ok(_permit) => panic!("expected error for >64 slots"),
    };
    let err_msg = format!("{err}");
    assert!(
        err_msg.contains("too many aux slots"),
        "unexpected error: {err_msg}"
    );

    // Channel should still be usable for FD-bearing messages after the rejection.
    let real_mem = make_mem(4096, 0x33);
    sender
        .send(TestMsg::PingMem {
            seq: 2,
            region: real_mem,
        })
        .await
        .unwrap();

    let resp: TestMsg = receiver.recv().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 2);
            assert_eq!(read_marker(&region), 0x34);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

/// Peer never observes a frame header without its promised FD count.
///
/// Sends a rapid mix of handle-carrying and handle-free messages,
/// verifying the receiver always gets matching seq + FDs.
#[tokio::test]
async fn peer_never_sees_header_without_fds() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Send interleaved handle/no-handle messages.
    for i in 0..20u32 {
        if i % 3 == 0 {
            let mem = make_mem(4096, i as u8);
            sender
                .send(TestMsg::PingMem {
                    seq: i,
                    region: mem,
                })
                .await
                .unwrap();
        } else {
            sender
                .send(TestMsg::Ping {
                    seq: i,
                    payload: format!("msg_{i}"),
                })
                .await
                .unwrap();
        }
    }

    // Verify all 20 responses arrive in order with correct FD counts.
    for i in 0..20u32 {
        let resp: TestMsg = tokio::time::timeout(Duration::from_secs(5), receiver.recv())
            .await
            .expect("recv timed out")
            .unwrap();
        if i % 3 == 0 {
            match resp {
                TestMsg::PongMem { seq, region } => {
                    assert_eq!(seq, i);
                    // Helper increments marker by 1.
                    assert_eq!(read_marker(&region), (i as u8).wrapping_add(1));
                }
                other => panic!("msg {i}: expected PongMem, got {other:?}"),
            }
        } else {
            match resp {
                TestMsg::Pong { seq, payload } => {
                    assert_eq!(seq, i);
                    assert_eq!(payload, format!("echo:msg_{i}"));
                }
                other => panic!("msg {i}: expected Pong, got {other:?}"),
            }
        }
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}

/// reserve_send + commit produces the same result as send.
#[tokio::test]
async fn reserve_then_commit_equivalent_to_send() {
    let (mut sender, mut receiver) = spawn_echo().await;

    // Use reserve/commit explicitly.
    let mem = make_mem(4096, 0x42);
    let permit = sender
        .reserve_send(TestMsg::PingMem {
            seq: 1,
            region: mem,
        })
        .await
        .unwrap();
    permit.commit().await.unwrap();

    let resp: TestMsg = receiver.recv().await.unwrap();
    match resp {
        TestMsg::PongMem { seq, region } => {
            assert_eq!(seq, 1);
            assert_eq!(read_marker(&region), 0x43);
        }
        other => panic!("expected PongMem, got {other:?}"),
    }

    sender.send(TestMsg::Shutdown).await.unwrap();
}
