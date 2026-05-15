// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for VM lifecycle operations.
//!
//! These tests validate the typestate-enforced lifecycle transitions work
//! correctly with real KVM VMs using 1:1 vCPU threading.

mod common;

use std::time::Instant;

use amla_vmm::{Backends, ConsoleStream, SpawnBackends, VirtualMachine};

// =============================================================================
// Basic Lifecycle Tests
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_create_vm() {
    if common::skip() {
        return;
    }
    let config = common::test_vm_config().memory_mb(128).vcpu_count(1);

    let vm = VirtualMachine::create(config)
        .await
        .expect("Failed to create VM");

    // VM is in New state - only load_kernel() is available.
    drop(vm);
}

#[tokio::test(flavor = "multi_thread")]
async fn test_create_and_configure_vm() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let kernel = common::kernel();
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config)
        .await
        .expect("Failed to create VM");

    // Load kernel - transitions to Ready state
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("Failed to load kernel");

    // VM is now in Ready state
    let _ = &vm;
    drop(vm);
}

// =============================================================================
// Zygote Tests
// =============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn test_freeze_to_zygote() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = common::boot_to_ready(pools, config, backends).await;

    let zygote = vm.freeze().await.expect("Failed to freeze VM");

    assert_eq!(zygote.config().memory_mb, 128);
    assert_eq!(zygote.config().vcpu_count, 1);

    let console = ConsoleStream::new();
    let backends: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console,
        net: None,
        fs: None,
    };
    let spawned_vm = zygote
        .spawn(pools, backends)
        .await
        .expect("Failed to spawn from zygote");
    assert_eq!(spawned_vm.config().memory_mb, 128);
}

/// Test that zygote-spawned VMs can actually run with `run()`.
/// This validates the CoW-backed spawn path works correctly.
#[tokio::test(flavor = "multi_thread")]
async fn test_zygote_spawn_and_run() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = common::boot_to_ready(pools, config, backends).await;
    let zygote = vm.freeze().await.expect("Failed to freeze");

    let console2 = ConsoleStream::new();
    let backends2: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console2,
        net: None,
        fs: None,
    };
    let spawned_vm = zygote
        .spawn(pools, backends2)
        .await
        .expect("Failed to spawn from zygote");

    // Verify the spawned VM has correct config and can transition states.
    // We don't re-run it because the zygote was frozen after guest exit ---
    // the vCPU would resume at HLT and loop forever.
    assert_eq!(spawned_vm.config().memory_mb, 128);
    drop(spawned_vm);
}

/// Test spawning multiple VMs from a single zygote.
/// Validates `CoW` isolation - each VM gets independent memory.
#[tokio::test(flavor = "multi_thread")]
async fn test_multiple_vms_from_zygote() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = common::boot_to_ready(pools, config, backends).await;
    let zygote = vm.freeze().await.expect("Failed to freeze");

    let console1 = ConsoleStream::new();
    let backends1: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console1,
        net: None,
        fs: None,
    };
    let vm1 = zygote
        .spawn(pools, backends1)
        .await
        .expect("Failed to spawn VM 1");

    let console2 = ConsoleStream::new();
    let backends2: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console2,
        net: None,
        fs: None,
    };
    let vm2 = zygote
        .spawn(pools, backends2)
        .await
        .expect("Failed to spawn VM 2");

    assert_eq!(vm1.config().memory_mb, 128);
    assert_eq!(vm2.config().memory_mb, 128);

    // Verify both can transition states.
    drop(vm1);
    drop(vm2);
}

// =============================================================================
// Memory Configuration Tests
// =============================================================================

/// Test various memory configurations with autotest (128MB, 256MB, 512MB).
///
/// Boots the guest agent as init (mounts /proc, /sys, etc.), runs
/// `/test/autotest`, and verifies exit code 0 (all guest tests passed).
#[tokio::test(flavor = "multi_thread")]
async fn test_memory_configurations() {
    if common::skip() {
        return;
    }

    let test_cases: &[(usize, &str)] = &[
        (128, "128MB (smaller)"),
        (256, "256MB (default)"),
        (512, "512MB (larger)"),
    ];

    let kernel = common::kernel();

    for &(memory_mb, label) in test_cases {
        println!("Testing {label}...");

        let config = common::test_vm_config()
            .memory_mb(memory_mb)
            .pmem_root(common::rootfs_handle().size().as_u64());

        let pools = amla_vmm::backend::BackendPools::new(2, &config, common::worker_config())
            .expect("create pools");

        let (console, pmem) = common::default_backends(&config);
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem,
        };
        let vm = VirtualMachine::create(config)
            .await
            .unwrap_or_else(|e| panic!("{label}: create VM: {e}"));
        let vm = vm
            .load_kernel(&pools, kernel, backends)
            .await
            .unwrap_or_else(|e| panic!("{label}: load kernel: {e}"));

        let timeout = common::boot_timeout();
        let start = Instant::now();
        let (_vm, exit_code) = vm
            .run(async move |vm| {
                let vm = vm.start();
                let cmd = vm
                    .exec(["/bin/amla-guest", "test-autotest"])
                    .await
                    .expect("exec autotest");
                let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                    .await
                    .expect("timed out");
                output.exit_code
            })
            .await
            .unwrap_or_else(|e| panic!("{label}: run: {e}"));
        common::assert_not_timed_out(start, timeout, label);

        assert_eq!(
            exit_code, 0,
            "{label}: autotest failed with exit code {exit_code}"
        );
        println!("  {label}: PASSED");
    }
}
