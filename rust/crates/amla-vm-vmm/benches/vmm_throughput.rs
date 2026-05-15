// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss
)]
#![allow(clippy::too_many_lines)]

//! VMM spawn throughput and parallel scaling benchmark.
//!
//! Measures:
//! - Sustained single-threaded spawns/sec
//! - Multi-threaded scaling (2/4/8 threads, shared `mmap_lock`)
//!
//! Run with: `cargo bench -p amla-vmm --bench vmm_throughput`

mod common;

use std::time::{Duration, Instant};

use amla_mem::MemHandle;
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, SpawnBackends, VirtualMachine, VmConfig, Zygote};
use tabled::{Table, Tabled, settings::Style};

const MEMORY_MB: usize = 128;
const POOL_SLOTS: usize = 10;

const SUSTAIN_SECS: u64 = 3;

// =============================================================================
// Tables
// =============================================================================

#[derive(Tabled)]
struct ScalingRow {
    #[tabled(rename = "Mode")]
    mode: &'static str,
    #[tabled(rename = "Workers")]
    workers: usize,
    #[tabled(rename = "Total/sec")]
    total_rate: String,
    #[tabled(rename = "Per-worker")]
    per_worker: String,
    #[tabled(rename = "Efficiency")]
    efficiency: String,
    #[tabled(rename = "p50")]
    p50: String,
    #[tabled(rename = "p99")]
    p99: String,
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

fn cowtree_available() -> bool {
    std::path::Path::new("/dev/cowtree").exists()
}

fn create_zygote(
    rt: &tokio::runtime::Runtime,
    pools: &BackendPools,
    kernel: &[u8],
    config: VmConfig,
    rootfs: &MemHandle,
) -> VirtualMachine<Zygote> {
    rt.block_on(async {
        let vm = VirtualMachine::create(config).await.expect("create");
        let console = amla_vmm::ConsoleStream::new();
        let pmem = make_pmem(vm.config(), rootfs);
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem,
        };
        let vm = vm
            .load_kernel(pools, kernel, backends)
            .await
            .expect("load_kernel");
        let (vm, ()) = vm
            .run(async move |vm| {
                let vm = vm.start();
                let mut probe: amla_vmm::CommandExecution =
                    vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
                drop(probe.close_stdin().await);
                drop(
                    tokio::time::timeout(Duration::from_secs(30), probe.wait())
                        .await
                        .expect("timed out"),
                );
            })
            .await
            .expect("run");
        vm.freeze().await.expect("freeze")
    })
}

/// Run N threads for `duration`, each spawning from `zygote` in a loop.
/// Returns (wall time, per-thread latency vectors).
fn parallel_spawn(
    rt: &tokio::runtime::Runtime,
    zygote: &VirtualMachine<Zygote>,
    pools: &BackendPools,
    threads: usize,
    duration: Duration,
) -> (Duration, Vec<Vec<Duration>>) {
    let start = Instant::now();
    let results: Vec<Vec<Duration>> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut latencies = Vec::new();
                    while start.elapsed() < duration {
                        let t = Instant::now();
                        let console = amla_vmm::ConsoleStream::new();
                        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
                            console: &console,
                            net: None,
                            fs: None,
                        };
                        let vm = rt.block_on(zygote.spawn(pools, backends)).expect("spawn");
                        latencies.push(t.elapsed());
                        drop(vm);
                    }
                    latencies
                })
            })
            .collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    (start.elapsed(), results)
}

// =============================================================================
// Main benchmark
// =============================================================================

fn run_benchmark() {
    if let Some(reason) = common::skip_checks() {
        eprintln!("{reason}, skipping benchmarks");
        return;
    }

    let rt = tokio::runtime::Runtime::new().unwrap();
    let _guard = rt.enter();
    let rootfs = common::rootfs_handle();
    let kernel = amla_guest_rootfs::KERNEL;
    let config = make_config(rootfs.size().as_u64());
    let pools =
        BackendPools::new(POOL_SLOTS, &config, common::worker_config()).expect("create pools");

    // Prewarm the pool so spawns hit the fast path
    pools.prewarm(POOL_SLOTS).expect("prewarm");

    let zygote = create_zygote(
        &rt,
        &pools,
        kernel,
        make_config(rootfs.size().as_u64()),
        &rootfs,
    );

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║          VMM Spawn Throughput                ║");
    println!("╠══════════════════════════════════════════════╣");
    println!("║  Pool:     {:<34}║", format!("{POOL_SLOTS} shells"));
    println!("║  Memory:   {:<34}║", format!("{MEMORY_MB} MB / VM"));
    println!("║  Prewarm:  {:<34}║", format!("{POOL_SLOTS} shells"));
    println!(
        "║  Backend:  {:<34}║",
        if cowtree_available() {
            "CowTree"
        } else {
            "Memfd"
        }
    );
    println!("║  Sustain:  {:<34}║", format!("{SUSTAIN_SECS}s / config"));
    println!("╚══════════════════════════════════════════════╝\n");

    let mut rows = Vec::new();
    let duration = Duration::from_secs(SUSTAIN_SECS);

    // Warmup: one spawn+drop cycle to prime caches
    {
        let console = amla_vmm::ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let _warm = rt
            .block_on(zygote.spawn(&pools, backends))
            .expect("warmup spawn");
    }

    // =========================================================================
    // Baseline: 1 thread
    // =========================================================================
    println!("Measuring 1 thread...");
    let (elapsed, thread_results) = parallel_spawn(&rt, &zygote, &pools, 1, duration);
    let mut all: Vec<Duration> = thread_results.into_iter().flatten().collect();
    let baseline_rate = all.len() as f64 / elapsed.as_secs_f64();

    all.sort();
    rows.push(ScalingRow {
        mode: "Thread",
        workers: 1,
        total_rate: format!("{baseline_rate:.0}/s"),
        per_worker: format!("{baseline_rate:.0}/s"),
        efficiency: "100%".to_string(),
        p50: common::format_duration(common::percentile(&mut all, 50.0)),
        p99: common::format_duration(common::percentile(&mut all, 99.0)),
    });

    // =========================================================================
    // Multi-threaded: 2, 4, 8
    // =========================================================================
    for threads in [2, 4, 8] {
        println!("Measuring {threads} threads...");
        let (elapsed, thread_results) = parallel_spawn(&rt, &zygote, &pools, threads, duration);
        let mut all: Vec<Duration> = thread_results.into_iter().flatten().collect();
        let rate = all.len() as f64 / elapsed.as_secs_f64();
        let per_thread = rate / threads as f64;
        let efficiency = (rate / baseline_rate / threads as f64) * 100.0;

        all.sort();
        rows.push(ScalingRow {
            mode: "Thread",
            workers: threads,
            total_rate: format!("{rate:.0}/s"),
            per_worker: format!("{per_thread:.0}/s"),
            efficiency: format!("{efficiency:.0}%"),
            p50: common::format_duration(common::percentile(&mut all, 50.0)),
            p99: common::format_duration(common::percentile(&mut all, 99.0)),
        });
    }

    // =========================================================================
    // Results
    // =========================================================================
    println!("\n{}\n", Table::new(&rows).with(Style::rounded()));

    println!(
        "Baseline: {:.0} spawns/sec ({}/spawn)",
        baseline_rate,
        common::format_duration(Duration::from_secs_f64(1.0 / baseline_rate)),
    );
    println!();
    println!("Notes:");
    println!("  Thread mode: all spawns share single process mmap_lock");
    println!("  Efficiency = actual / (baseline x workers) x 100%");
}

// =============================================================================
// Entry point
// =============================================================================

fn main() {
    run_benchmark();
}
