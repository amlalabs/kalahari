// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for zygote freeze/spawn lifecycle.
//!
//! Tests the zygote protocol:
//! - `VirtualMachine<Ready>::freeze()` captures KVM state
//! - `VirtualMachine<Zygote>::spawn()` restores state and returns `Ready`
//! - Net-enabled VMs require a net backend when loading or spawning

mod common;

use std::time::Duration;

use amla_vmm::{Backends, NetConfig, SpawnBackends, VirtualMachine};

// =============================================================================
// spawn() --- Full Round-Trip
// =============================================================================

/// `spawn()` produces a valid Ready VM that can start vCPUs.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_starts_vcpus() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config().memory_mb(256);
    let zygote = common::create_zygote(pools, config).await;

    let console = amla_vmm::ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let vm = zygote.spawn(pools, backends).await.expect("spawn");
    let (vm, _exit_code): (_, u8) = vm
        .run(async |_vm| {
            tokio::time::sleep(Duration::from_millis(500)).await;
            0u8
        })
        .await
        .expect("spawn restored VM");

    assert_eq!(
        vm.config().memory_mb,
        256,
        "config preserved after spawn+run"
    );
}

/// `spawn()` works multiple times from the same zygote.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_multiple_from_one_zygote() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let zygote = common::create_zygote(pools, common::default_config().memory_mb(256)).await;

    for i in 0..3 {
        let console = amla_vmm::ConsoleStream::new();
        let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
            console: &console,
            net: None,
            fs: None,
        };
        let vm = zygote
            .spawn(pools, backends)
            .await
            .unwrap_or_else(|e| panic!("spawn {i}: {e}"));

        let (_vm, _code): (_, u8) = vm
            .run(async |_vm| {
                tokio::time::sleep(Duration::from_millis(200)).await;
                0u8
            })
            .await
            .unwrap_or_else(|e| panic!("run {i}: {e}"));
    }
}

// =============================================================================
// Backend Mismatch at load_kernel() Time
// =============================================================================

// =============================================================================
// Multi-vCPU Zygote Spawn
// =============================================================================

/// Verify 2-vCPU first boot works (no freeze/spawn).
#[tokio::test(flavor = "multi_thread")]
async fn test_2vcpu_first_boot_nproc() {
    if common::skip() {
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(128)
        .vcpu_count(2)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(4, &config, common::worker_config())
        .expect("create pools");

    // boot_to_ready: first run with 2 vCPUs (runs `true`).
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = common::boot_to_ready(&pools, config, backends).await;
    // Second run: nproc to check CPU count.
    let timeout = Duration::from_secs(5);
    let start = std::time::Instant::now();
    let (_vm, nproc): (_, Vec<u8>) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd: amla_vmm::CommandExecution = vm
                .exec(["/bin/amla-guest", "nproc"])
                .await
                .expect("exec nproc");
            let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("nproc timed out");
            output.stdout
        })
        .await
        .expect("run VM");
    common::assert_not_timed_out(start, timeout, "2vcpu nproc");
    let nproc_str = String::from_utf8_lossy(&nproc);
    let nproc_str = nproc_str.trim();
    assert_eq!(nproc_str, "2", "Expected 2 CPUs, got: {nproc_str:?}");
    eprintln!("2-vCPU nproc={nproc_str}");
}

/// Spawn a 2-vCPU VM from a zygote and verify all CPUs are online.
///
/// This is the minimal reproduction for multi-vCPU zygote restore:
/// boot with 2 vCPUs -> freeze -> spawn -> run `nproc` -> expect "2".
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_multi_vcpu() {
    if common::skip() {
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(128)
        .vcpu_count(2)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(4, &config, common::worker_config())
        .expect("create pools");

    // Boot -> freeze -> spawn -> nproc.
    let zygote = common::create_zygote(&pools, config.clone()).await;
    let console = amla_vmm::ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let vm = zygote.spawn(&pools, backends).await.expect("spawn");
    let timeout = Duration::from_secs(30);
    let start = std::time::Instant::now();
    let (_vm, nproc): (_, Vec<u8>) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd: amla_vmm::CommandExecution = vm
                .exec(["/bin/amla-guest", "nproc"])
                .await
                .expect("exec nproc");
            let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("nproc timed out on spawn");
            output.stdout
        })
        .await
        .expect("run spawned VM");
    common::assert_not_timed_out(start, timeout, "multi-vcpu spawn");

    let nproc_str = String::from_utf8_lossy(&nproc);
    let nproc_str = nproc_str.trim();
    assert_eq!(nproc_str, "2", "Expected 2 CPUs online, got: {nproc_str:?}");
    eprintln!("Multi-vCPU zygote spawn: nproc={nproc_str}");
}

// =============================================================================
// Backend Mismatch at load_kernel() Time
// =============================================================================

/// Loading a net-enabled VM without a net backend -> `BackendMismatch` error.
///
/// Backends are validated at `load_kernel()` / `spawn()` time. Passing
/// `net: None` when config has net triggers the error.
#[tokio::test(flavor = "multi_thread")]
async fn test_net_enabled_vm_without_net_backend_errors() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config()
        .memory_mb(256)
        .net(NetConfig::default());

    let kernel = common::kernel();
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = amla_vmm::ConsoleStream::new();
    let pmem_images: Vec<amla_mem::MemHandle> = vm
        .config()
        .pmem_disks
        .iter()
        .map(|_| common::rootfs_handle())
        .collect();
    // Build backends without net --- should fail validation at load_kernel time.
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: pmem_images,
    };
    let result = vm.load_kernel(pools, kernel, backends).await;

    let err = result
        .err()
        .expect("load_kernel should fail: backend mismatch (None for Net)");
    let msg = err.to_string();
    assert!(
        msg.contains("mismatch") || msg.contains("backend"),
        "error should mention backend mismatch, got: {msg}"
    );
}
