// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_precision_loss)]

//! Consolidated VMM lifecycle latency benchmark.
//!
//! Measures p50/p95/p99 for every state machine transition:
//!
//! ```text
//!                        Boot path
//!   ┌──────────┐    ┌─────────────┐    ┌─────────┐
//!   │  create   │───▶│ load_kernel  │───▶│   run    │───▶ Ready
//!   └──────────┘    └─────────────┘    └─────────┘
//!                                           │
//!                                    freeze()
//!   ┌──────────┐◀───────────────────────────│
//!   │  Zygote  │
//!   └────┬─────┘
//!        │
//!   spawn()
//!        │
//!   ┌────▼─────┐
//!   │  Ready   │
//!   │ (clone)  │
//!   └──────────┘
//! ```
//!
//! Run with: `cargo bench -p amla-vmm --bench vmm_latency`

mod common;

use std::time::{Duration, Instant};

use amla_mem::MemHandle;
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, SpawnBackends, VirtualMachine, VmConfig, Zygote};
use tabled::{Table, Tabled, settings::Style};

const MEMORY_MB: usize = 128;
const POOL_SLOTS: usize = 10;

/// Collect all output from a streaming `CommandExecution` (bench helper).
async fn collect_output(mut exec: amla_vmm::CommandExecution) -> (i32, Vec<u8>, Vec<u8>) {
    drop(exec.close_stdin().await);
    let mut stdout_rx = exec.take_stdout().expect("stdout");
    let mut stderr_rx = exec.take_stderr().expect("stderr");
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        tokio::select! {
            Some(chunk) = stdout_rx.recv() => stdout.extend_from_slice(&chunk),
            Some(chunk) = stderr_rx.recv() => stderr.extend_from_slice(&chunk),
            else => break,
        }
    }
    let exit_code = exec.wait().await.expect("wait failed");
    (exit_code, stdout, stderr)
}

async fn run_true_probe(vm: &amla_vmm::VmHandle<'_>) {
    let cmd: amla_vmm::CommandExecution =
        vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
    let (exit_code, _, _) = collect_output(cmd).await;
    assert_eq!(exit_code, 0);
}

// =============================================================================
// Statistics table
// =============================================================================

#[derive(Tabled)]
struct Row {
    #[tabled(rename = "Stage")]
    stage: &'static str,
    #[tabled(rename = "n")]
    n: usize,
    #[tabled(rename = "p50")]
    p50: String,
    #[tabled(rename = "p95")]
    p95: String,
    #[tabled(rename = "p99")]
    p99: String,
}

fn row(stage: &'static str, times: &mut [Duration]) -> Row {
    Row {
        stage,
        n: times.len(),
        p50: common::format_duration(common::percentile(times, 50.0)),
        p95: common::format_duration(common::percentile(times, 95.0)),
        p99: common::format_duration(common::percentile(times, 99.0)),
    }
}

fn cowtree_available() -> bool {
    std::path::Path::new("/dev/cowtree").exists()
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

/// Boot a VM, run a probe, then freeze into a Zygote.
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
                run_true_probe(&vm).await;
            })
            .await
            .expect("run");
        vm.freeze().await.expect("freeze")
    })
}

// =============================================================================
// Main
// =============================================================================

#[allow(clippy::too_many_lines)]
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
    let pools =
        BackendPools::new(POOL_SLOTS, &config, common::worker_config()).expect("create pools");

    // Prewarm the pool so spawns hit the fast path
    pools.prewarm(POOL_SLOTS).expect("prewarm");

    println!("\n╔══════════════════════════════════════════════╗");
    println!("║          VMM Lifecycle Latency               ║");
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
    println!("║  Seccomp:  Disabled                          ║");
    println!("╚══════════════════════════════════════════════╝\n");

    let mut rows = Vec::new();

    // =========================================================================
    // Warmup: one full boot cycle to prime caches
    // =========================================================================
    {
        let _warmup = create_zygote(
            &rt,
            &pools,
            kernel,
            make_config(rootfs.size().as_u64()),
            &rootfs,
        );
    }

    // =========================================================================
    // 1-3. Boot breakdown: create / load / run-to-exit / total
    // =========================================================================
    let n = 1;
    println!("Boot ({n} samples)...");

    let mut create_t = Vec::with_capacity(n);
    let mut load_t = Vec::with_capacity(n);
    let mut run_t = Vec::with_capacity(n);
    let mut boot_t = Vec::with_capacity(n);

    for _ in 0..n {
        let t0 = Instant::now();

        let t = Instant::now();
        let vm = rt
            .block_on(VirtualMachine::create(make_config(rootfs.size().as_u64())))
            .expect("create");
        create_t.push(t.elapsed());

        let t = Instant::now();
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
        load_t.push(t.elapsed());

        let t = Instant::now();
        let (vm, ()) = rt
            .block_on(vm.run(async move |vm| {
                let vm = vm.start();
                let mut cmd: amla_vmm::CommandExecution =
                    vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
                drop(cmd.close_stdin().await);
                drop(
                    tokio::time::timeout(Duration::from_secs(30), cmd.wait())
                        .await
                        .expect("timed out"),
                );
            }))
            .expect("run");
        run_t.push(t.elapsed());

        boot_t.push(t0.elapsed());
        drop(vm);
    }

    rows.push(row("VM create", &mut create_t));
    rows.push(row("Kernel load", &mut load_t));
    rows.push(row("Boot to exit", &mut run_t));
    rows.push(row("Boot (total)", &mut boot_t));

    // =========================================================================
    // 4. Time to interactive (boot)
    //
    // Measures run() → exec "echo hello" → receive stdout.
    // Proves: kernel booted + guest_agent main() +
    //         ring buffer protocol + exec protocol + command round-trip.
    // =========================================================================
    let n = 1;
    println!("TTI via echo ({n} samples)...");

    let mut tti_t = Vec::with_capacity(n);
    for _ in 0..n {
        let vm = rt
            .block_on(VirtualMachine::create(make_config(rootfs.size().as_u64())))
            .expect("create");
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

        let t = Instant::now();
        let (vm, ()) = rt
            .block_on(vm.run(async move |vm| {
                let vm = vm.start();
                let cmd: amla_vmm::CommandExecution = vm
                    .exec(["/bin/amla-guest", "echo", "hello"])
                    .await
                    .expect("echo");
                let (exit_code, stdout, _) = collect_output(cmd).await;
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim_ascii(), b"hello");
            }))
            .expect("run");
        tti_t.push(t.elapsed());
        drop(vm);
    }
    rows.push(row("TTI (boot → echo)", &mut tti_t));

    // =========================================================================
    // 5. Freeze (in-memory snapshot)
    // =========================================================================
    let n = 1;
    println!("Freeze ({n} samples)...");

    let mut freeze_t = Vec::with_capacity(n);
    for _ in 0..n {
        // We need to measure just the freeze, so boot inline and time only freeze.
        let t = rt.block_on(async {
            let vm = VirtualMachine::create(make_config(rootfs.size().as_u64()))
                .await
                .expect("create");
            let console = amla_vmm::ConsoleStream::new();
            let pmem = make_pmem(vm.config(), &rootfs);
            let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
                console: &console,
                net: None,
                fs: None,
                pmem,
            };
            let vm = vm
                .load_kernel(&pools, kernel, backends)
                .await
                .expect("load_kernel");
            let (vm, ()) = vm
                .run(async move |vm| {
                    let vm = vm.start();
                    let mut probe: amla_vmm::CommandExecution =
                        vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
                    drop(probe.close_stdin().await);
                    drop(probe.wait().await);
                })
                .await
                .expect("run");
            let t = Instant::now();
            let _zygote = vm.freeze().await.expect("freeze");
            t.elapsed()
        });
        freeze_t.push(t);
    }
    rows.push(row("Freeze (in-memory)", &mut freeze_t));

    // =========================================================================
    // 5. Clone — clone spawn + resume to PTY-ready interactivity
    // =========================================================================
    let n = 1;
    println!("Clone (exec ready, {n} samples)...");

    let zygote = create_zygote(
        &rt,
        &pools,
        kernel,
        make_config(rootfs.size().as_u64()),
        &rootfs,
    );
    // Warmup clone
    {
        let console = amla_vmm::ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let warm = rt
            .block_on(zygote.spawn(&pools, backends))
            .expect("warmup spawn");
        let (warm, ()) = rt
            .block_on(warm.run(async |vm| {
                let vm = vm.start();
                run_true_probe(&vm).await;
            }))
            .expect("warmup run");
        drop(warm);
    }
    let mut clone_t = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let console = amla_vmm::ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let ready = rt.block_on(zygote.spawn(&pools, backends)).expect("spawn");
        let (ready, ()) = rt
            .block_on(ready.run(async |vm| {
                let vm = vm.start();
                run_true_probe(&vm).await;
            }))
            .expect("run");
        clone_t.push(t.elapsed());
        drop(ready);
    }
    rows.push(row("Clone (exec ready)", &mut clone_t));

    drop(zygote);

    // =========================================================================
    // 7. Clone TTI (echo round-trip)
    //
    // Boot a VM, freeze into zygote, then measure:
    // clone spawn → resume vCPU → exec "echo hello" → receive stdout.
    // =========================================================================
    let n = 10;
    println!("Clone TTI (echo, {n} samples)...");

    let tti_vm = rt
        .block_on(VirtualMachine::create(make_config(rootfs.size().as_u64())))
        .expect("create tti vm");
    let tti_console = amla_vmm::ConsoleStream::new();
    let tti_pmem = make_pmem(tti_vm.config(), &rootfs);
    let tti_backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &tti_console,
        net: None,
        fs: None,
        pmem: tti_pmem,
    };
    let tti_vm = rt
        .block_on(tti_vm.load_kernel(&pools, kernel, tti_backends))
        .expect("load_kernel tti");
    // Freeze AFTER the guest is fully interactive — run a probe echo to
    // prove the agent is booted, the ring protocol works, and the shell
    // is ready. Without this, the zygote is frozen mid-boot and clones
    // pay the full boot cost again.
    let (tti_vm, ()) = rt
        .block_on(tti_vm.run(async move |vm| {
            let vm = vm.start();
            let mut cmd: amla_vmm::CommandExecution = vm
                .exec(["/bin/amla-guest", "echo", "ready"])
                .await
                .expect("probe");
            drop(cmd.close_stdin().await);
            drop(cmd.wait().await);
        }))
        .expect("boot tti vm");
    let tti_zygote = rt.block_on(tti_vm.freeze()).expect("freeze tti");

    let mut clone_tti_t = Vec::with_capacity(n);
    for i in 0..n {
        let clone_console = amla_vmm::ConsoleStream::new();
        let clone_backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &clone_console,
            net: None,
            fs: None,
        };
        let clone = rt
            .block_on(tti_zygote.spawn(&pools, clone_backends))
            .expect("clone");
        let t = Instant::now();
        let (clone, ()) = rt
            .block_on(clone.run(async move |vm| {
                let vm = vm.start();
                let t_closure = Instant::now();
                let t_run = Instant::now();
                let cmd: amla_vmm::CommandExecution = vm
                    .exec(["/bin/amla-guest", "echo", "hello"])
                    .await
                    .expect("echo");
                let t_sent = Instant::now();
                let (exit_code, stdout, _) = collect_output(cmd).await;
                let t_recv = Instant::now();
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim_ascii(), b"hello");
                eprintln!(
                    "[tti:{i}] closure_start={:?} exec={:?} output_await={:?}",
                    t_run.duration_since(t_closure),
                    t_sent.duration_since(t_run),
                    t_recv.duration_since(t_sent),
                );
            }))
            .expect("clone tti run");
        clone_tti_t.push(t.elapsed());
        drop(clone);
    }
    rows.push(row("Clone TTI (spawn → echo)", &mut clone_tti_t));

    // =========================================================================
    // 7b. Clone TTI — @builtin:echo (ring protocol only, no fork/exec)
    //
    // Same as above but uses @builtin:echo which the guest agent handles
    // inline without posix_spawn. This isolates the ring buffer round-trip
    // from the fork/exec scheduling overhead.
    // =========================================================================
    let n_builtin = 10;
    println!("Clone TTI builtin (ring only, {n_builtin} samples)...");

    let mut clone_builtin_t = Vec::with_capacity(n_builtin);
    for i in 0..n_builtin {
        let clone_console = amla_vmm::ConsoleStream::new();
        let clone_backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &clone_console,
            net: None,
            fs: None,
        };
        let clone = rt
            .block_on(tti_zygote.spawn(&pools, clone_backends))
            .expect("clone");
        let t = Instant::now();
        let (clone, ()) = rt
            .block_on(clone.run(async move |vm| {
                let vm = vm.start();
                let t_closure = Instant::now();
                let t_run = Instant::now();
                let cmd: amla_vmm::CommandExecution = vm
                    .exec(["@builtin:echo", "hello"])
                    .await
                    .expect("builtin echo");
                let t_sent = Instant::now();
                let (exit_code, stdout, _) = collect_output(cmd).await;
                let t_recv = Instant::now();
                assert_eq!(exit_code, 0);
                assert_eq!(stdout.trim_ascii(), b"hello");
                eprintln!(
                    "[builtin:{i}] closure_start={:?} exec={:?} output_await={:?}",
                    t_run.duration_since(t_closure),
                    t_sent.duration_since(t_run),
                    t_recv.duration_since(t_sent),
                );
            }))
            .expect("clone builtin run");
        clone_builtin_t.push(t.elapsed());
        drop(clone);
    }
    rows.push(row("Clone TTI (builtin echo)", &mut clone_builtin_t));

    drop(tti_zygote);

    // =========================================================================
    // 8. Full cycle: boot → freeze → clone (start to first fork)
    // =========================================================================
    let n = 1;
    println!("Full cycle ({n} samples)...");

    let mut full_t = Vec::with_capacity(n);
    for _ in 0..n {
        let t = Instant::now();
        let z = create_zygote(
            &rt,
            &pools,
            kernel,
            make_config(rootfs.size().as_u64()),
            &rootfs,
        );
        let forked_console = amla_vmm::ConsoleStream::new();
        let forked_backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &forked_console,
            net: None,
            fs: None,
        };
        let forked = rt
            .block_on(z.spawn(&pools, forked_backends))
            .expect("spawn");
        let (forked, ()) = rt
            .block_on(forked.run(async |vm| {
                let vm = vm.start();
                run_true_probe(&vm).await;
            }))
            .expect("run");
        full_t.push(t.elapsed());
        drop(forked);
        drop(z);
    }
    rows.push(row(
        "Full cycle (boot→freeze→clone→exec ready)",
        &mut full_t,
    ));

    // =========================================================================
    // Results
    // =========================================================================
    println!("\n{}\n", Table::new(&rows).with(Style::rounded()));

    // Headlines
    let clone_p50 = common::percentile(&mut clone_t, 50.0);
    println!("Headlines:  clone = {}", common::format_duration(clone_p50));
}
