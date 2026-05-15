// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![allow(clippy::cast_precision_loss)]

//! Raw ring buffer throughput benchmark.
//!
//! Measures SPSC throughput in two modes:
//! 1. **Single-thread**: write N messages then read them all back (no contention).
//! 2. **Cross-thread**: producer and consumer on separate threads (realistic).
//!
//! Run with: `cargo bench -p amla-vm-ringbuf --bench throughput`

use amla_vm_ringbuf::RingBufferHandle;
use criterion::{Criterion, criterion_group, criterion_main};
use std::alloc::{Layout, alloc_zeroed, dealloc};
use std::hint::black_box;
use std::ptr::NonNull;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

// Use a smaller ring for benchmarks so it fits in cache hierarchy.
// 1 MiB per direction — large enough that wrapping exercises the hot path.
const BENCH_RING_SIZE: usize = 1024 * 1024; // 1 MiB
const BENCH_TOTAL_SIZE: usize =
    core::mem::size_of::<amla_vm_ringbuf::RingBuffer<BENCH_RING_SIZE>>();

/// RAII wrapper for a 64-byte-aligned heap allocation.
struct AlignedBuf {
    ptr: *mut u8,
    layout: Layout,
}

// SAFETY: AlignedBuf owns a heap allocation accessed only via `&self` in
// the benchmark harness; the inner `*mut u8` is not tied to any thread.
unsafe impl Send for AlignedBuf {}
// SAFETY: the benchmark hands the allocation to a RingBuffer whose
// internal SPSC discipline arbitrates all shared mutation; AlignedBuf
// itself exposes no mutation through `&self`.
unsafe impl Sync for AlignedBuf {}

impl AlignedBuf {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, 64).unwrap();
        // SAFETY: `layout` has non-zero size (caller passes a positive size).
        let ptr = unsafe { alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "allocation failed");
        Self { ptr, layout }
    }

    const fn as_ptr(&self) -> NonNull<u8> {
        NonNull::new(self.ptr).unwrap()
    }

    /// Zero the allocation so the next `init` observes an uninitialized
    /// region.
    const fn reset(&self) {
        // SAFETY: self owns `ptr` for `layout.size()` bytes.
        unsafe { std::ptr::write_bytes(self.ptr, 0, self.layout.size()) };
    }
}

impl Drop for AlignedBuf {
    fn drop(&mut self) {
        // SAFETY: `ptr`/`layout` came from the matching `alloc_zeroed` in `new`.
        unsafe { dealloc(self.ptr, self.layout) };
    }
}

// =============================================================================
// Single-thread: write all then read all
// =============================================================================

fn bench_single_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("ringbuf/single-thread");
    let buf = AlignedBuf::new(BENCH_TOTAL_SIZE);

    for msg_size in [64, 256, 1024, 4096, 16384, 65536] {
        let total_bytes: usize = 16 * 1024 * 1024; // 16 MiB per iteration
        let n_msgs = total_bytes / msg_size;
        let payload = vec![0xABu8; msg_size];

        group.throughput(criterion::Throughput::Bytes((n_msgs * msg_size) as u64));
        group.bench_function(format!("msg={}", format_size(msg_size)), |b| {
            b.iter(|| {
                // init() panics if already initialized, so zero the region
                // between iterations to give each iter a clean handshake.
                buf.reset();

                // Host side initializes the region and owns the host→guest
                // writer. Guest side validates the now-initialized header
                // and owns the host→guest reader.
                // SAFETY: `buf` is a freshly zeroed aligned region sized
                // for RingBuffer<BENCH_RING_SIZE>; this iteration uses one
                // writer and one reader, both single-threaded.
                let host = unsafe {
                    RingBufferHandle::<BENCH_RING_SIZE>::attach(buf.as_ptr(), BENCH_TOTAL_SIZE)
                }
                .unwrap();
                let writer = host.init().split_host().to_guest;
                // SAFETY: same allocation; SPSC discipline is upheld.
                let guest = unsafe {
                    RingBufferHandle::<BENCH_RING_SIZE>::attach(buf.as_ptr(), BENCH_TOTAL_SIZE)
                }
                .unwrap();
                let mut reader = guest.validate().unwrap().split_guest().from_host;

                let mut written = 0;
                let mut read = 0;

                while read < n_msgs {
                    // Write as many as we can
                    while written < n_msgs {
                        if writer.try_write(black_box(&payload)).unwrap() {
                            written += 1;
                        } else {
                            break;
                        }
                    }
                    // Read as many as we can
                    while read < written {
                        if reader.try_peek().unwrap().is_some() {
                            black_box(reader.try_peek().unwrap().unwrap());
                            reader.advance().unwrap();
                            read += 1;
                        } else {
                            break;
                        }
                    }
                }
            });
        });
    }
    group.finish();
}

// =============================================================================
// Cross-thread SPSC
// =============================================================================

fn bench_cross_thread(c: &mut Criterion) {
    let mut group = c.benchmark_group("ringbuf/cross-thread");

    for msg_size in [64, 256, 1024, 4096, 16384, 65536] {
        let total_bytes: usize = 16 * 1024 * 1024;
        let n_msgs = total_bytes / msg_size;

        group.throughput(criterion::Throughput::Bytes((n_msgs * msg_size) as u64));
        group.bench_function(format!("msg={}", format_size(msg_size)), |b| {
            b.iter(|| {
                let buf = Arc::new(AlignedBuf::new(BENCH_TOTAL_SIZE));
                buf.reset();

                let payload = vec![0xABu8; msg_size];
                let done = Arc::new(AtomicBool::new(false));

                // Producer thread initializes the ring and owns the writer.
                let buf_w = Arc::clone(&buf);
                let done_w = Arc::clone(&done);
                let producer = thread::spawn(move || {
                    // SAFETY: `buf_w` keeps the allocation alive for this
                    // thread; consumer holds another Arc<AlignedBuf>. SPSC
                    // per-direction is upheld by one writer + one reader.
                    let handle = unsafe {
                        RingBufferHandle::<BENCH_RING_SIZE>::attach(
                            buf_w.as_ptr(),
                            BENCH_TOTAL_SIZE,
                        )
                    }
                    .unwrap();
                    let writer = handle.init().split_host().to_guest;
                    for _ in 0..n_msgs {
                        while !writer.try_write(&payload).unwrap() {
                            std::hint::spin_loop();
                        }
                    }
                    done_w.store(true, Ordering::Release);
                });

                // Consumer on this thread: spin until the producer's init()
                // has published the magic, then validate and read.
                let mut reader = loop {
                    // SAFETY: see `buf_w` site above.
                    let handle = unsafe {
                        RingBufferHandle::<BENCH_RING_SIZE>::attach(buf.as_ptr(), BENCH_TOTAL_SIZE)
                    }
                    .unwrap();
                    match handle.validate() {
                        Ok(ready) => break ready.split_guest().from_host,
                        Err(_) => std::hint::spin_loop(),
                    }
                };
                let mut read = 0;
                while read < n_msgs {
                    if let Some(data) = reader.try_peek().unwrap() {
                        black_box(data);
                        reader.advance().unwrap();
                        read += 1;
                    } else {
                        std::hint::spin_loop();
                    }
                }

                producer.join().unwrap();
                assert!(done.load(Ordering::Acquire));
            });
        });
    }
    group.finish();
}

// =============================================================================
// Helpers
// =============================================================================

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes}B")
    } else if bytes < 1024 * 1024 {
        format!("{}K", bytes / 1024)
    } else {
        format!("{}M", bytes / (1024 * 1024))
    }
}

criterion_group!(benches, bench_single_thread, bench_cross_thread);
criterion_main!(benches);
