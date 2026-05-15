// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! IPC subprocess test helper.
//!
//! Spawned by integration tests via `Subprocess::spawn`. The first IPC
//! message selects which protocol to run:
//!
//! - `Init { mode: "echo" }`: Read messages, echo them back with modifications.
//!
//! This binary is used by both Linux and macOS tests — it only uses the
//! cross-platform `amla-ipc` API.

#[cfg(unix)]
use amla_ipc::{IpcMessage, RingBuffer};
#[cfg(unix)]
use amla_mem::MemHandle;

// =========================================================================
// Wire protocol (shared with the test in roundtrip.rs)
// =========================================================================

#[cfg(unix)]
#[derive(Debug, IpcMessage)]
enum TestMsg {
    /// First message: selects the helper's behavior mode.
    Init { mode: String },

    /// Pure data, no MemHandles.
    Ping { seq: u32, payload: String },

    /// Carries a single MemHandle.
    PingMem {
        seq: u32,
        #[ipc_resource]
        region: MemHandle,
    },

    /// Carries multiple MemHandles.
    PingMultiMem {
        seq: u32,
        #[ipc_resource]
        regions: Vec<MemHandle>,
    },

    /// Echo responses.
    Pong { seq: u32, payload: String },

    /// Echo with MemHandle (marker byte incremented).
    PongMem {
        seq: u32,
        #[ipc_resource]
        region: MemHandle,
    },

    /// Echo with multiple MemHandles (marker bytes incremented).
    PongMultiMem {
        seq: u32,
        #[ipc_resource]
        regions: Vec<MemHandle>,
    },

    /// Write `value` at offset 0 of `region`, then reply Ok.
    WriteMem {
        seq: u32,
        value: u8,
        #[ipc_resource]
        region: MemHandle,
    },

    /// Generic ok reply.
    Ok { seq: u32 },

    /// Shutdown the helper.
    Shutdown,
}

// =========================================================================
// Entry point
// =========================================================================

fn main() {
    #[cfg(not(unix))]
    {
        eprintln!("ipc_test_helper: unix only");
        std::process::exit(1);
    }

    #[cfg(unix)]
    {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("tokio runtime");

        if let Err(e) = rt.block_on(run()) {
            eprintln!("ipc_test_helper error: {e}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut ring = RingBuffer::from_child_stdin()?;
    let (mut sender, mut receiver) = ring.split(false)?;

    // First message selects the mode.
    let msg = receiver.recv::<TestMsg>().await?;
    match msg {
        TestMsg::Init { mode } => match mode.as_str() {
            "echo" => echo_loop(&mut sender, &mut receiver).await,
            other => {
                eprintln!("ipc_test_helper: unknown mode {other:?}");
                std::process::exit(1);
            }
        },
        other => {
            eprintln!("ipc_test_helper: expected Init, got {other:?}");
            std::process::exit(1);
        }
    }
}

#[cfg(unix)]
async fn echo_loop(
    sender: &mut amla_ipc::Sender<'_>,
    receiver: &mut amla_ipc::Receiver<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    loop {
        let msg = receiver.recv::<TestMsg>().await?;

        match msg {
            TestMsg::Ping { seq, payload } => {
                sender
                    .send(TestMsg::Pong {
                        seq,
                        payload: format!("echo:{payload}"),
                    })
                    .await?;
            }

            TestMsg::PingMem { seq, region } => {
                let mmap = amla_mem::map_handle(&region)?;
                // SAFETY: helper owns this temporary mapping during message handling.
                let bytes = unsafe { mmap.as_slice_unchecked() };
                let marker = bytes[0];
                let new_region = MemHandle::allocate_and_write(c"echo", *region.size(), |slice| {
                    slice.copy_from_slice(bytes);
                    slice[0] = marker.wrapping_add(1);
                    Ok(())
                })?;
                sender
                    .send(TestMsg::PongMem {
                        seq,
                        region: new_region,
                    })
                    .await?;
            }

            TestMsg::PingMultiMem { seq, regions } => {
                let mut new_regions = Vec::with_capacity(regions.len());
                for region in &regions {
                    let mmap = amla_mem::map_handle(region)?;
                    // SAFETY: helper owns this temporary mapping during message handling.
                    let bytes = unsafe { mmap.as_slice_unchecked() };
                    let marker = bytes[0];
                    let new_region =
                        MemHandle::allocate_and_write(c"echo", *region.size(), |slice| {
                            slice.copy_from_slice(bytes);
                            slice[0] = marker.wrapping_add(1);
                            Ok(())
                        })?;
                    new_regions.push(new_region);
                }
                sender
                    .send(TestMsg::PongMultiMem {
                        seq,
                        regions: new_regions,
                    })
                    .await?;
            }

            TestMsg::WriteMem { seq, value, region } => {
                let mmap = amla_mem::map_handle(&region)?;
                let slice =
                    unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), *region.size()) };
                slice[0] = value;
                sender.send(TestMsg::Ok { seq }).await?;
            }

            TestMsg::Shutdown => {
                break;
            }

            _ => {
                eprintln!("ipc_test_helper: unexpected message");
            }
        }
    }

    Ok(())
}
