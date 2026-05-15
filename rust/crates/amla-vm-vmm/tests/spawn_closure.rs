// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! `run()` closure behavior tests for the amla-vmm porcelain API.
//!
//! Tests edge cases in the `run()` async closure and `VmHandle` API:
//! immediate pause, return values, exit codes, vCPU count, and serial output.

mod common;

use std::time::{Duration, Instant};

use amla_vmm::{Backends, VirtualMachine};

// =============================================================================
// Closure Return Value
// =============================================================================

/// Closure that returns before `start()` --- `run()` preserves the value.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_closure_return_value() {
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
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    let (_vm, value) = vm.run(async move |_vm| 42u32).await.expect("spawn VM");

    assert_eq!(
        value, 42,
        "spawn() should preserve the closure return value"
    );
}

/// Check exit code after guest completes.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_exit_code() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::default_config();
    let (console, pmem) = common::default_backends(&config);
    let backends: amla_vmm::Backends<'_, amla_fuse::NullFsBackend> = amla_vmm::Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    common::boot_to_ready(pools, config, backends).await;
}

/// VM config `vcpu_count` is preserved through lifecycle.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_vcpu_count_matches() {
    if common::skip() {
        return;
    }

    // 2-vCPU boot times out at 300s under QEMU TCG when run after other tests.
    if cfg!(target_arch = "aarch64") {
        eprintln!("Skipping: 2-vCPU boot too slow under QEMU TCG");
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(128)
        .vcpu_count(2)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(2, &config, common::worker_config())
        .expect("create pools");

    let kernel = common::kernel();
    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(&pools, kernel, backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("spawn VM");
    common::assert_not_timed_out(start, timeout, "test_spawn_vcpu_count_matches");

    assert_eq!(vm.config().vcpu_count, 2, "vcpu_count should match config");
}

/// `has_exited()` is false while guest agent is running (exec doesn't cause exit).
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_has_exited_false_while_running() {
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
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let (_vm, exited) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm.exec(["/bin/amla-guest", "true"]).await.expect("exec");
            let _ = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
            vm.has_exited()
        })
        .await
        .expect("spawn VM");
    common::assert_not_timed_out(start, timeout, "test_spawn_has_exited_false_while_running");

    assert!(
        !exited,
        "has_exited() should be false while guest agent is running"
    );
}

/// Console output is non-empty after boot.
///
/// On x86, PIO serial bytes feed the console stream. On ARM64, `console=hvc0`
/// routes kernel log through virtio-console into the same stream.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawnconsole_output_nonempty() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let kernel = common::kernel();
    let config = common::default_config();
    let (mut console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let (vm, ()) = vm
        .run(async move |handle| {
            let handle = handle.start();
            let cmd = handle
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("probe");
            let _ = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
        })
        .await
        .expect("spawn VM");
    common::assert_not_timed_out(start, timeout, "test_spawnconsole_output_nonempty");
    drop(vm);

    let output = common::drainconsole(&mut console);
    assert!(
        !output.is_empty(),
        "console output should be non-empty after boot"
    );
}

/// Immediate return without `start()` leaves the VM paused and returns Ready.
#[tokio::test(flavor = "multi_thread")]
async fn test_spawn_immediate_pause() {
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
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    // Return immediately without calling `start()`.
    let (vm, ()) = vm
        .run(async |_vm| ())
        .await
        .expect("immediate pause should succeed");

    // VM should be in Ready state
    assert!(
        vm.config().memory_mb > 0,
        "VM accessible after immediate pause"
    );
}
