// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for the zygote spawn path.
//!
//! Exercises `freeze()` -> `spawn()` -> `run(...)` over many cycles
//! to verify pool capacity accounting and resource cleanup.

mod common;

use amla_vmm::SpawnBackends;

/// Config for spawn tests.
fn spawn_config() -> amla_vmm::VmConfig {
    common::test_vm_config()
        .memory_mb(256)
        .pmem_root(common::rootfs_handle().size().as_u64())
}

// =============================================================================
// Spawn Stress
// =============================================================================

/// Stress zygote spawns over many cycles.
///
/// Every spawn acquires a shell from the pool and creates fresh devices.
/// Catches regressions in pool capacity accounting and shell teardown.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_stress_cycles() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, spawn_config()).await;

    let cycles = if cfg!(target_arch = "aarch64") {
        20usize
    } else {
        60usize
    };

    let mut spawn_total = std::time::Duration::ZERO;
    let mut run_total = std::time::Duration::ZERO;
    let mut drop_total = std::time::Duration::ZERO;

    let timeout = common::boot_timeout();

    for i in 0..cycles {
        let t0 = std::time::Instant::now();
        let console = amla_vmm::ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let vm = zygote
            .spawn(pools, backends)
            .await
            .unwrap_or_else(|e| panic!("cycle {i} spawn failed: {e}"));
        let spawn_elapsed = t0.elapsed();
        spawn_total += spawn_elapsed;

        let t1 = std::time::Instant::now();
        let (vm, ()) = vm
            .run(async move |vm| {
                let vm = vm.start();
                common::run_true(&vm, timeout).await;
            })
            .await
            .unwrap_or_else(|e| panic!("cycle {i} run failed: {e}"));
        let run_elapsed = t1.elapsed();
        run_total += run_elapsed;

        let t2 = std::time::Instant::now();
        drop(vm);
        let drop_elapsed = t2.elapsed();
        drop_total += drop_elapsed;

        if i % 10 == 0 {
            eprintln!(
                "CYCLE {i}/{cycles}: spawn={spawn_elapsed:?} run={run_elapsed:?} drop={drop_elapsed:?}",
            );
        }
    }

    eprintln!(
        "\n=== TOTALS ({cycles} cycles) ===\n\
         spawn: {spawn_total:?} (avg {:?})\n\
         run:   {run_total:?} (avg {:?})\n\
         drop:  {drop_total:?} (avg {:?})",
        spawn_total / u32::try_from(cycles).unwrap(),
        run_total / u32::try_from(cycles).unwrap(),
        drop_total / u32::try_from(cycles).unwrap(),
    );
}
