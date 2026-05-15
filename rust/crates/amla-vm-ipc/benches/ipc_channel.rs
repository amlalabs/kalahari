// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! IPC channel latency and throughput benchmark.
//!
//! Spawns `ipc_test_helper` as a subprocess and measures round-trip latency
//! and sustained throughput for various message sizes over the full IPC path:
//! ring buffer + doorbell + postcard serialization.
//!
//! Three benchmark modes:
//!
//! 1. **Latency** — sequential ping-pong, one message at a time, measures
//!    per-message RTT with percentile breakdown.
//!
//! 2. **Throughput** — sustained ping-pong burst for a fixed duration,
//!    measures messages/sec and bytes/sec.
//!
//! 3. **MemHandle latency** — round-trip through the aux channel (Mach ports
//!    on macOS, SCM_RIGHTS on Linux), which is a distinct cost path from
//!    the ring buffer.
//!
//! Run with: `cargo bench -p amla-ipc --bench ipc_channel`

fn main() {
    #[cfg(not(unix))]
    {
        eprintln!("ipc_channel bench: unix only");
        return;
    }

    #[cfg(unix)]
    bench::run();
}

#[cfg(unix)]
mod bench {
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use amla_ipc::{IpcMessage, RingBuffer, Subprocess};
    use amla_mem::MemHandle;
    use tabled::{Table, Tabled, settings::Style};

    // ========================================================================
    // Wire protocol (must match ipc_test_helper.rs variant order exactly —
    // postcard uses index-based enum encoding)
    // ========================================================================

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

    // ========================================================================
    // Table structs
    // ========================================================================

    #[derive(Tabled)]
    struct LatencyRow {
        #[tabled(rename = "Size")]
        size: String,
        #[tabled(rename = "n")]
        n: usize,
        #[tabled(rename = "Min")]
        min: String,
        #[tabled(rename = "p50")]
        p50: String,
        #[tabled(rename = "p95")]
        p95: String,
        #[tabled(rename = "p99")]
        p99: String,
        #[tabled(rename = "Mean")]
        mean: String,
    }

    #[derive(Tabled)]
    struct ThroughputRow {
        #[tabled(rename = "Size")]
        size: String,
        #[tabled(rename = "Messages")]
        messages: usize,
        #[tabled(rename = "Time")]
        time: String,
        #[tabled(rename = "Msg/sec")]
        msg_rate: String,
        #[tabled(rename = "Throughput")]
        throughput: String,
    }

    // ========================================================================
    // Helpers
    // ========================================================================

    fn helper_path() -> PathBuf {
        let exe = std::env::current_exe().unwrap();
        let dir = exe.parent().unwrap();
        let candidate = dir.join("ipc_test_helper");
        if candidate.exists() {
            return candidate;
        }
        let candidate = dir.parent().unwrap().join("ipc_test_helper");
        if candidate.exists() {
            return candidate;
        }
        panic!(
            "ipc_test_helper not found near {:?}. Run `cargo build` first.",
            dir
        );
    }

    // Heap-pin the RingBuffer behind an Arc so both channel halves can keep
    // it alive via cloned Arcs — avoids the earlier `Box::leak` while still
    // producing `'static` halves suitable for tokio spawns.
    use std::cell::UnsafeCell;
    use std::ops::{Deref, DerefMut};
    use std::sync::Arc;

    struct RingCell(UnsafeCell<RingBuffer>);

    // SAFETY: cross-process sync on the mmap region is by atomics; after
    // split_static each half serializes access to its own ring direction.
    unsafe impl Send for RingCell {}
    unsafe impl Sync for RingCell {}

    struct OwnedRing(Arc<RingCell>);

    impl OwnedRing {
        fn new(ring: RingBuffer) -> Self {
            Self(Arc::new(RingCell(UnsafeCell::new(ring))))
        }

        fn split_static(&self, is_host: bool) -> (OwnedSender, OwnedReceiver) {
            // SAFETY: called exactly once per fixture. No other refs exist
            // at this moment.
            let r: &mut RingBuffer = unsafe { &mut *self.0.0.get() };
            let (sender, receiver) = r.split(is_host).unwrap();
            // SAFETY: `sender`/`receiver` borrow the mmap owned by the Arc.
            // Both returned wrappers retain an Arc clone so the storage
            // outlives every relabelled `'static` ref.
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

    fn make_payload(size: usize) -> String {
        "A".repeat(size)
    }

    fn make_mem(size: usize) -> MemHandle {
        MemHandle::allocate_and_write(c"bench", size, |slice| {
            slice[0] = 0xBE;
            Ok(())
        })
        .unwrap()
    }

    fn format_duration(d: Duration) -> String {
        let micros = d.as_micros();
        if micros == 0 {
            format!("{}ns", d.as_nanos())
        } else if micros < 1_000 {
            format!("{micros}µs")
        } else if micros < 1_000_000 {
            let ms = d.as_secs_f64() * 1000.0;
            format!("{ms:.2}ms")
        } else {
            format!("{:.2}s", d.as_secs_f64())
        }
    }

    fn format_bytes(bytes: usize) -> String {
        if bytes < 1024 {
            format!("{bytes} B")
        } else if bytes < 1024 * 1024 {
            format!("{} KiB", bytes / 1024)
        } else {
            format!("{} MiB", bytes / (1024 * 1024))
        }
    }

    fn format_rate(bytes_per_sec: f64) -> String {
        if bytes_per_sec < 1024.0 * 1024.0 {
            format!("{:.1} KiB/s", bytes_per_sec / 1024.0)
        } else if bytes_per_sec < 1024.0 * 1024.0 * 1024.0 {
            format!("{:.1} MiB/s", bytes_per_sec / (1024.0 * 1024.0))
        } else {
            format!("{:.1} GiB/s", bytes_per_sec / (1024.0 * 1024.0 * 1024.0))
        }
    }

    /// Pre-sorted duration collection for efficient percentile queries.
    struct SortedDurations(Vec<Duration>);

    impl SortedDurations {
        fn new(mut data: Vec<Duration>) -> Self {
            data.sort();
            Self(data)
        }

        fn percentile(&self, p: f64) -> Duration {
            if self.0.is_empty() {
                return Duration::ZERO;
            }
            let len = self.0.len();
            let idx = (p * (len - 1) as f64 / 100.0).round();
            let idx = (idx as usize).min(len - 1);
            self.0[idx]
        }

        fn min(&self) -> Duration {
            self.0.first().copied().unwrap_or(Duration::ZERO)
        }

        fn mean(&self) -> Duration {
            if self.0.is_empty() {
                return Duration::ZERO;
            }
            let sum: Duration = self.0.iter().sum();
            sum / self.0.len() as u32
        }

        fn len(&self) -> usize {
            self.0.len()
        }
    }

    fn latency_row(label: String, sorted: &SortedDurations) -> LatencyRow {
        LatencyRow {
            size: label,
            n: sorted.len(),
            min: format_duration(sorted.min()),
            p50: format_duration(sorted.percentile(50.0)),
            p95: format_duration(sorted.percentile(95.0)),
            p99: format_duration(sorted.percentile(99.0)),
            mean: format_duration(sorted.mean()),
        }
    }

    // ========================================================================
    // Entry point
    // ========================================================================

    const PAYLOAD_SIZES: &[usize] = &[64, 256, 1024, 4096, 16384];
    const MEM_SIZES: &[usize] = &[4096, 65536, 1048576];
    const LATENCY_WARMUP: usize = 50;
    const LATENCY_ITERATIONS: usize = 1000;
    const THROUGHPUT_WARMUP: usize = 50;
    const THROUGHPUT_DURATION_SECS: u64 = 3;

    pub fn run() {
        let rt = tokio::runtime::Runtime::new().unwrap();

        println!("\n╔══════════════════════════════════════════════╗");
        println!("║          IPC Channel Benchmark               ║");
        println!("╠══════════════════════════════════════════════╣");
        println!("║  Transport: ring buffer + doorbell + postcard║");
        println!(
            "║  Latency:  {:<34}║",
            format!("{LATENCY_ITERATIONS} RTTs, {LATENCY_WARMUP} warmup")
        );
        println!(
            "║  Throughput: {:<32}║",
            format!("{THROUGHPUT_DURATION_SECS}s sustained")
        );
        println!(
            "║  Sizes:    {:<34}║",
            PAYLOAD_SIZES
                .iter()
                .map(|s| format_bytes(*s))
                .collect::<Vec<_>>()
                .join(", ")
        );
        println!("╚══════════════════════════════════════════════╝\n");

        // =====================================================================
        // 1. Data latency
        // =====================================================================
        println!("── Latency (sequential ping-pong) ──\n");

        let mut latency_rows = Vec::new();

        for &size in PAYLOAD_SIZES {
            eprint!("  {} ...", format_bytes(size));

            let latencies = rt.block_on(async {
                let (mut sender, mut receiver) = spawn_echo().await;
                let payload = make_payload(size);

                // Warmup
                for i in 0..LATENCY_WARMUP {
                    sender
                        .send(TestMsg::Ping {
                            seq: i as u32,
                            payload: payload.clone(),
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                }

                // Timed
                let mut latencies = Vec::with_capacity(LATENCY_ITERATIONS);
                for i in 0..LATENCY_ITERATIONS {
                    let t = Instant::now();
                    sender
                        .send(TestMsg::Ping {
                            seq: (LATENCY_WARMUP + i) as u32,
                            payload: payload.clone(),
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                    latencies.push(t.elapsed());
                }

                let _ = sender.send(TestMsg::Shutdown).await;
                latencies
            });

            let sorted = SortedDurations::new(latencies);
            eprintln!(" p50={}", format_duration(sorted.percentile(50.0)));
            latency_rows.push(latency_row(format_bytes(size), &sorted));
        }

        println!("\n{}\n", Table::new(&latency_rows).with(Style::rounded()));

        // =====================================================================
        // 2. MemHandle latency (aux channel)
        // =====================================================================
        println!("── MemHandle Latency (aux channel round-trip) ──\n");

        let mut mem_rows = Vec::new();

        for &size in MEM_SIZES {
            eprint!("  {} ...", format_bytes(size));

            let latencies = rt.block_on(async {
                let (mut sender, mut receiver) = spawn_echo().await;

                // Warmup
                for i in 0..LATENCY_WARMUP {
                    sender
                        .send(TestMsg::PingMem {
                            seq: i as u32,
                            region: make_mem(size),
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                }

                // Timed
                let mut latencies = Vec::with_capacity(LATENCY_ITERATIONS);
                for i in 0..LATENCY_ITERATIONS {
                    let region = make_mem(size);
                    let t = Instant::now();
                    sender
                        .send(TestMsg::PingMem {
                            seq: (LATENCY_WARMUP + i) as u32,
                            region,
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                    latencies.push(t.elapsed());
                }

                let _ = sender.send(TestMsg::Shutdown).await;
                latencies
            });

            let sorted = SortedDurations::new(latencies);
            eprintln!(" p50={}", format_duration(sorted.percentile(50.0)));
            mem_rows.push(latency_row(format_bytes(size), &sorted));
        }

        println!("\n{}\n", Table::new(&mem_rows).with(Style::rounded()));

        // =====================================================================
        // 3. Throughput
        // =====================================================================
        println!("── Throughput (sustained burst) ──\n");

        let mut throughput_rows = Vec::new();
        let duration = Duration::from_secs(THROUGHPUT_DURATION_SECS);

        for &size in PAYLOAD_SIZES {
            eprint!("  {} ...", format_bytes(size));

            let (count, elapsed) = rt.block_on(async {
                let (mut sender, mut receiver) = spawn_echo().await;
                let payload = make_payload(size);

                // Warmup
                for i in 0..THROUGHPUT_WARMUP {
                    sender
                        .send(TestMsg::Ping {
                            seq: i as u32,
                            payload: payload.clone(),
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                }

                // Sustained burst
                let start = Instant::now();
                let mut count = 0usize;
                let mut seq = THROUGHPUT_WARMUP as u32;
                while start.elapsed() < duration {
                    sender
                        .send(TestMsg::Ping {
                            seq,
                            payload: payload.clone(),
                        })
                        .await
                        .unwrap();
                    let _: TestMsg = receiver.recv().await.unwrap();
                    count += 1;
                    seq = seq.wrapping_add(1);
                }

                let _ = sender.send(TestMsg::Shutdown).await;
                (count, start.elapsed())
            });

            let msg_rate = count as f64 / elapsed.as_secs_f64();
            let byte_rate = msg_rate * size as f64;

            throughput_rows.push(ThroughputRow {
                size: format_bytes(size),
                messages: count,
                time: format_duration(elapsed),
                msg_rate: format!("{msg_rate:.0}"),
                throughput: format_rate(byte_rate),
            });

            eprintln!(" {:.0} msg/s, {}", msg_rate, format_rate(byte_rate));
        }

        println!(
            "\n{}\n",
            Table::new(&throughput_rows).with(Style::rounded())
        );
    }
}
