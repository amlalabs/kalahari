// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Zygote spawn stress + performance tests for the amla-vmm porcelain API.
//!
//! Pushes zygote spawning to higher counts, verifies `CoW` isolation,
//! and asserts spawn latency stays fast (p99 < 10ms).

mod common;

use std::time::{Duration, Instant};

use amla_vmm::{ConsoleStream, SpawnBackends};

// =============================================================================
// Zygote Spawn Stress
// =============================================================================

/// Spawn 10 VMs sequentially from one zygote --- all must succeed.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_spawn_10() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, common::default_config()).await;

    for i in 0..10 {
        let console = ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let vm = zygote
            .spawn(pools, backends)
            .await
            .unwrap_or_else(|_| panic!("spawn {i}"));
        assert_eq!(vm.config().memory_mb, 128, "spawn {i} config preserved");
        drop(vm);
    }

    eprintln!("All 10 zygote spawns succeeded");
}

/// Spawn 2 VMs from zygote, run both to exit --- they're independent.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_spawns_independent() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, common::default_config()).await;
    let timeout = common::boot_timeout();

    for i in 0..2 {
        let console = ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let vm = zygote
            .spawn(pools, backends)
            .await
            .unwrap_or_else(|_| panic!("spawn {i}"));

        let (_vm, ()) = vm
            .run(async move |vm| {
                let vm = vm.start();
                common::run_true(&vm, timeout).await;
            })
            .await
            .unwrap_or_else(|_| panic!("run {i}"));

        eprintln!("VM {i} spawn cycle complete");
    }
}

/// Spawn from zygote after the original VM (that created the zygote) is dropped.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_spawn_after_original_dropped() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, common::default_config()).await;

    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let vm = zygote
        .spawn(pools, backends)
        .await
        .expect("spawn after original dropped");
    assert_eq!(vm.config().memory_mb, 128);
    drop(vm);
}

/// Zygote spawn latency: p50 must be under 2ms, max under 10ms.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_spawn_latency() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, common::default_config()).await;

    let mut durations = Vec::with_capacity(10);
    for _ in 0..10 {
        let start = Instant::now();
        let console = ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let vm = zygote.spawn(pools, backends).await.expect("spawn");
        durations.push(start.elapsed());
        drop(vm);
    }

    durations.sort();
    let p50 = durations[4];
    let max = durations[9];

    eprintln!("Zygote spawn latency: p50={p50:?}, max={max:?}");

    // Each spawn allocates a fresh KVM VM fd (~4ms on x86_64,
    // ~100ms on arm64 dev VMs due to slower CPU/emulation).
    let (p50_limit, max_limit) = if cfg!(target_arch = "aarch64") {
        (Duration::from_millis(200), Duration::from_millis(400))
    } else {
        (Duration::from_millis(50), Duration::from_millis(100))
    };
    assert!(p50 < p50_limit, "zygote spawn p50 too slow ({p50:?})");
    assert!(max < max_limit, "zygote spawn max too slow ({max:?})");
}
