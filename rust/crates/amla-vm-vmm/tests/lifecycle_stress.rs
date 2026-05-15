// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Rapid lifecycle stress tests for the amla-vmm porcelain API.
//!
//! Pushes create/destroy, boot/exit, and pause/quiesce cycles to higher counts
//! to expose resource leaks and race conditions.

mod common;

use std::time::Instant;

use amla_vmm::{Backends, VirtualMachine};

// =============================================================================
// Rapid Create/Destroy
// =============================================================================

/// Create and drop 20 VMs (no running) --- tests pool allocation/deallocation.
#[tokio::test(flavor = "multi_thread")]
async fn test_rapid_create_destroy_20() {
    if common::skip() {
        return;
    }
    for i in 0..20 {
        let config = common::test_vm_config().memory_mb(128);
        let vm = VirtualMachine::create(config)
            .await
            .unwrap_or_else(|_| panic!("create VM {i}"));
        drop(vm);
    }
}

/// Boot and exit 10 VMs sequentially.
#[tokio::test(flavor = "multi_thread")]
async fn test_rapid_boot_exit_10() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let kernel = common::kernel();

    for i in 0..10 {
        let config = common::test_vm_config()
            .memory_mb(128)
            .pmem_root(common::rootfs_handle().size().as_u64());

        let (console, pmem) = common::default_backends(&config);
        let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
            console: &console,
            net: None,
            fs: None,
            pmem,
        };
        let vm = VirtualMachine::create(config)
            .await
            .unwrap_or_else(|_| panic!("create VM {i}"));
        let vm = vm
            .load_kernel(pools, kernel, backends)
            .await
            .unwrap_or_else(|_| panic!("load kernel {i}"));

        let start = Instant::now();
        let timeout = common::boot_timeout();
        let (_vm, ()) = vm
            .run(async move |vm| {
                let vm = vm.start();
                common::run_true(&vm, timeout).await;
            })
            .await
            .unwrap_or_else(|_| panic!("spawn {i}"));
        common::assert_not_timed_out(start, timeout, &format!("boot/exit cycle {i}"));
    }
}

/// One VM, 5 cycles of run -> Ready state transitions.
#[tokio::test(flavor = "multi_thread")]
async fn test_pause_cycle_5() {
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
    let mut vm = common::boot_to_ready(pools, config, backends).await;

    let timeout = common::boot_timeout();

    // 5 cycles of Ready -> run -> Ready
    for i in 0..5 {
        let (next_vm, ()) = vm
            .run(async move |vm| {
                let vm = vm.start();
                common::run_true(&vm, timeout).await;
            })
            .await
            .unwrap_or_else(|_| panic!("rerun {i}"));
        vm = next_vm;
    }
}

/// `tokio::join!` 3 `create()` calls --- concurrent VM creation.
#[tokio::test(flavor = "multi_thread")]
async fn test_concurrent_vm_creation_3() {
    if common::skip() {
        return;
    }
    let config1 = common::test_vm_config().memory_mb(128);
    let config2 = config1.clone();
    let config3 = config1.clone();

    let (r1, r2, r3) = tokio::join!(
        VirtualMachine::create(config1),
        VirtualMachine::create(config2),
        VirtualMachine::create(config3),
    );

    r1.expect("create VM 1");
    r2.expect("create VM 2");
    r3.expect("create VM 3");
}

/// Same pool, 1 slot: create -> boot -> drop -> create -> boot (pool capacity cycling).
#[tokio::test(flavor = "multi_thread")]
async fn test_pool_reuse_after_lifecycle() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let kernel = common::kernel();

    // First cycle
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config).await.expect("first create");
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("first load");

    let start = Instant::now();
    let timeout = common::boot_timeout();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("first spawn");
    common::assert_not_timed_out(start, timeout, "pool_reuse first spawn");
    drop(vm);

    // Second cycle --- pool capacity freed, new shell created
    let config2 = common::default_config();
    let (console2, pmem2) = common::default_backends(&config2);
    let backends2: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console2,
        net: None,
        fs: None,
        pmem: pmem2,
    };
    let vm2 = VirtualMachine::create(config2)
        .await
        .expect("second create (pool reuse)");
    let vm2 = vm2
        .load_kernel(pools, kernel, backends2)
        .await
        .expect("second load");

    let start2 = Instant::now();
    let (_vm2, ()) = vm2
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("second spawn (pool reuse)");
    common::assert_not_timed_out(start2, timeout, "pool_reuse second spawn");
}
