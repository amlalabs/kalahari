// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Instant;

use amla_vmm::backend::BackendPools;
use amla_vmm::{ConsoleStream, SpawnBackends, VirtualMachine, Zygote};

/// Spawn a child VM from a zygote, run `echo <marker>`, verify output, freeze.
async fn spawn_echo_freeze(
    zygote: &VirtualMachine<Zygote>,
    pools: &BackendPools,
    marker: &str,
) -> VirtualMachine<Zygote> {
    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let vm = zygote.spawn(pools, backends).await.expect("spawn");

    let marker_owned = marker.to_string();
    let (vm, stdout): (_, String) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", &marker_owned])
                .await
                .expect("exec");
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                common::collect_output(cmd),
            )
            .await
            .expect("timed out");
            assert_eq!(output.exit_code, 0);
            output.stdout_str().trim().to_string()
        })
        .await
        .expect("run");

    assert_eq!(stdout, marker, "echo mismatch");
    vm.freeze().await.expect("freeze")
}

/// Single-depth spawn with a 5-second gap between freeze and spawn.
///
/// Validates that the deferred vtimer adjustment correctly handles large
/// time deltas — the guest clock should resume smoothly without a burst
/// of missed timer interrupts.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_delayed_spawn() {
    if common::skip() {
        return;
    }

    let pools = common::pools();
    let config = common::default_config().memory_mb(256);

    eprintln!("\n=== Delayed Spawn (5s gap) ===\n");

    let t = Instant::now();
    let zygote = common::create_zygote(pools, config).await;
    eprintln!("  root zygote: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    eprintln!("  sleeping 5s...");
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;

    let t = Instant::now();
    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let vm = zygote.spawn(pools, backends).await.expect("spawn");

    let (_vm, stdout): (_, String) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "echo", "DELAYED"])
                .await
                .expect("exec");
            let output = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                common::collect_output(cmd),
            )
            .await
            .expect("timed out after 10s");
            assert_eq!(output.exit_code, 0);
            output.stdout_str().trim().to_string()
        })
        .await
        .expect("run");

    assert_eq!(stdout, "DELAYED");
    eprintln!(
        "  delayed spawn+echo: {:.2}ms\n",
        t.elapsed().as_secs_f64() * 1000.0,
    );
}

/// Two-depth chain with all ancestors kept alive.
///
/// Validates `CoW` memory nesting: root → depth 1 → depth 2, each running
/// `echo` with a unique marker to verify data isolation.
#[tokio::test(flavor = "multi_thread")]
async fn test_nested_zygote_depth2() {
    if common::skip() {
        return;
    }

    let pools = common::pools();
    let config = common::default_config().memory_mb(256);

    eprintln!("\n=== Nested Zygote Depth 2 (parents alive) ===\n");

    let t = Instant::now();
    let zygote = common::create_zygote(pools, config).await;
    eprintln!("  root: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    let t = Instant::now();
    let z1 = spawn_echo_freeze(&zygote, pools, "D1").await;
    eprintln!("  depth=1: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    let t = Instant::now();
    let _z2 = spawn_echo_freeze(&z1, pools, "D2").await;
    eprintln!("  depth=2: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    eprintln!("\n  Depth 2 passed.\n");
}

/// Two-depth chain with the root zygote dropped before depth 2.
///
/// Validates that `CoW` memory remains valid after the ancestor is freed —
/// Mach VM (macOS) and memfd (Linux) both refcount physical pages.
#[tokio::test(flavor = "multi_thread")]
async fn test_nested_zygote_depth2_drop_root() {
    if common::skip() {
        return;
    }

    let pools = common::pools();
    let config = common::default_config().memory_mb(256);

    eprintln!("\n=== Nested Zygote Depth 2 (root dropped) ===\n");

    let t = Instant::now();
    let zygote = common::create_zygote(pools, config).await;
    eprintln!("  root: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    let t = Instant::now();
    let z1 = spawn_echo_freeze(&zygote, pools, "D1").await;
    eprintln!("  depth=1: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    eprintln!("  dropping root zygote...");
    drop(zygote);

    let t = Instant::now();
    let _z2 = spawn_echo_freeze(&z1, pools, "D2").await;
    eprintln!("  depth=2: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    eprintln!("\n  Depth 2 passed (root dropped).\n");
}

/// Linear chain to depth 5: root → L1 → L2 → L3 → L4 → L5.
#[tokio::test(flavor = "multi_thread")]
async fn test_nested_zygote_linear_chain() {
    if common::skip() {
        return;
    }

    let pools = common::pools();
    let config = common::default_config().memory_mb(256);

    eprintln!("\n=== Linear Zygote Chain (depth 5) ===\n");

    let t = Instant::now();
    let mut zygote = common::create_zygote(pools, config).await;
    eprintln!("  root: {:.2}ms", t.elapsed().as_secs_f64() * 1000.0);

    for depth in 1..=5 {
        let marker = format!("L{depth}");
        let t = Instant::now();
        zygote = spawn_echo_freeze(&zygote, pools, &marker).await;
        eprintln!(
            "  depth={depth}: spawn+echo+freeze={:.2}ms",
            t.elapsed().as_secs_f64() * 1000.0,
        );
    }

    eprintln!("\n  All 5 levels passed.\n");
}
