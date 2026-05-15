// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]

//! Ring buffer throughput benchmark using `@builtin:cat`.
//!
//! Measures end-to-end throughput of the host→guest→host data path:
//! host writes stdin chunks → ring buffer → guest agent → ring buffer → host reads stdout.
//!
//! `@builtin:cat` is an inline guest agent command that copies stdin to stdout
//! without forking, isolating pure ring buffer + virtio-console transport cost.
//!
//! Run with: `cargo bench -p amla-vmm --bench vmm_ringbuf`

mod common;

use std::time::{Duration, Instant};

use amla_mem::MemHandle;
use amla_vmm::{Backends, VirtualMachine, VmConfig};
use tabled::{Table, Tabled, settings::Style};

const MEMORY_MB: usize = 128;
const POOL_SLOTS: usize = 4;

// =============================================================================
// Results table
// =============================================================================

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Chunk")]
    chunk: String,
    #[tabled(rename = "Total")]
    total: String,
    #[tabled(rename = "Chunks")]
    chunks: usize,
    #[tabled(rename = "Time")]
    time: String,
    #[tabled(rename = "Throughput")]
    throughput: String,
}

// =============================================================================
// Helpers
// =============================================================================

fn make_config(image_size: u64) -> VmConfig {
    VmConfig::default()
        .memory_mb(MEMORY_MB)
        .vcpu_count(1)
        .pmem_root(image_size)
}

fn make_pmem(config: &VmConfig, rootfs: &MemHandle) -> Vec<MemHandle> {
    config
        .pmem_disks
        .iter()
        .map(|_| rootfs.try_clone().expect("clone rootfs"))
        .collect()
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

/// Run a guest command, returning a `CommandExecution` handle.
///
/// Wrapper to keep the benchmark code readable.
async fn guest_run(
    vm: &amla_vmm::VmHandle<'_, amla_vmm::Running>,
    argv: &[&str],
) -> amla_vmm::CommandExecution {
    vm.exec(argv).await.expect("guest command failed")
}

// =============================================================================
// Main
// =============================================================================

fn main() {
    if let Some(reason) = common::skip_checks() {
        eprintln!("{reason}, skipping benchmarks");
        return;
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error"))
        .format_timestamp_millis()
        .init();

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let rootfs = common::rootfs_handle();
    let kernel = amla_guest_rootfs::KERNEL;
    let config = make_config(rootfs.size().as_u64());
    let pools = common::backend_pools(POOL_SLOTS, &config);

    pools.prewarm(POOL_SLOTS).expect("prewarm");

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║       Ring Buffer Throughput (@builtin:cat)  ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Memory:   {:<34}║", format!("{MEMORY_MB} MB"));
    println!("║  Seccomp:  Disabled                          ║");
    println!("╚══════════════════════════════════════════════╝\n");

    // Boot a VM and verify it's responsive
    let vm = rt.block_on(VirtualMachine::create(config)).expect("create");
    let console = amla_vmm::ConsoleStream::new();
    let pmem = make_pmem(vm.config(), &rootfs);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = rt
        .block_on(vm.load_kernel(&pools, kernel, backends))
        .expect("load_kernel");
    let timeout = Duration::from_secs(30);

    // Chunk sizes to test (max ~32K due to ring buffer message size limit)
    let chunk_sizes: &[usize] = &[256, 1024, 4096, 16384, 32768];
    // Total data per test: 4 MiB
    let total_target: usize = 4 * 1024 * 1024;

    let (_vm, rows) = rt
        .block_on(vm.run(async move |vm| {
            let vm = vm.start();
            // Warmup: one echo round-trip to prove agent is ready
            let mut probe = guest_run(&vm, &["@builtin:echo", "ready"]).await;
            drop(probe.close_stdin().await);
            let mut stdout = Vec::new();
            let mut stdout_rx = probe.take_stdout().expect("stdout");
            while let Some(chunk) = stdout_rx.recv().await {
                stdout.extend_from_slice(&chunk);
            }
            drop(
                tokio::time::timeout(timeout, probe.wait())
                    .await
                    .expect("probe timed out"),
            );
            assert_eq!(stdout.trim_ascii(), b"ready");

            let mut rows = Vec::new();

            for &chunk_size in chunk_sizes {
                let n_chunks = total_target / chunk_size;
                let total_bytes = n_chunks * chunk_size;
                // Start @builtin:cat
                let mut cmd = guest_run(&vm, &["@builtin:cat"]).await;
                let writer = cmd.stdin_writer();

                let start = Instant::now();

                // Write stdin concurrently with reads to avoid ring buffer deadlock.
                let write_handle = tokio::spawn(async move {
                    for _ in 0..n_chunks {
                        writer
                            .write_owned(vec![0xABu8; chunk_size])
                            .await
                            .expect("write stdin");
                    }
                    writer.close().await.expect("close stdin");
                });

                // Read all stdout concurrently
                let mut received = 0usize;
                while let Some(data) = cmd.recv_stdout().await {
                    received += data.len();
                }

                let elapsed = start.elapsed();
                write_handle.await.expect("writer panicked");

                let bytes_per_sec = received as f64 / elapsed.as_secs_f64();

                rows.push(Row {
                    chunk: format_bytes(chunk_size),
                    total: format_bytes(total_bytes),
                    chunks: n_chunks,
                    time: common::format_duration(elapsed),
                    throughput: format_rate(bytes_per_sec),
                });

                eprintln!(
                    "  {}: sent {} in {} chunks, received {} bytes in {:?} = {}",
                    format_bytes(chunk_size),
                    format_bytes(total_bytes),
                    n_chunks,
                    received,
                    elapsed,
                    format_rate(bytes_per_sec),
                );
            }

            rows
        }))
        .expect("run VM");

    println!("\n{}\n", Table::new(&rows).with(Style::rounded()));
}
