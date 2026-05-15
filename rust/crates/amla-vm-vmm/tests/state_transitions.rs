// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Exhaustive typestate coverage tests for the amla-vmm porcelain API.
//!
//! Exercises every arrow in the VM state machine:
//! New -> Ready -> run -> Ready -> freeze -> Zygote -> spawn -> Ready
//! with all intermediate transitions and cycle combinations.

mod common;

use std::time::{Duration, Instant};

use amla_vmm::{Backends, ConsoleStream, SpawnBackends, VirtualMachine};

// =============================================================================
// Individual State Transitions
// =============================================================================

/// New -> Ready via `load_kernel()`.
#[tokio::test(flavor = "multi_thread")]
async fn test_new_to_ready() {
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

    assert_eq!(vm.config().memory_mb, 128);
    assert_eq!(vm.config().vcpu_count, 1);
}

/// Ready -> Ready via `run()`.
#[tokio::test(flavor = "multi_thread")]
async fn test_ready_run_returns_ready() {
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
    assert_eq!(vm.config().memory_mb, 128);
}

/// Ready -> Zygote via `freeze()`.
#[tokio::test(flavor = "multi_thread")]
async fn test_ready_to_zygote() {
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
    let zygote = vm.freeze().await.expect("freeze");
    assert_eq!(zygote.config().memory_mb, 128);
    assert_eq!(zygote.config().vcpu_count, 1);
}

/// Full state machine cycle: every transition in sequence.
///
/// New -> Ready -> run -> Ready -> run -> Ready -> freeze -> Zygote -> spawn -> Ready
#[tokio::test(flavor = "multi_thread")]
async fn test_full_state_machine_cycle() {
    if common::skip() {
        return;
    }
    let pools = common::pools();

    // Step 1-2: New -> Ready
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

    // Step 3: Ready -> run -> Ready
    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("first run");
    common::assert_not_timed_out(start, timeout, "full_cycle: first");

    // Step 4: Ready -> run -> Ready (second run)
    let start = Instant::now();
    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            common::run_true(&vm, timeout).await;
        })
        .await
        .expect("second run");
    common::assert_not_timed_out(start, timeout, "full_cycle: second");

    // Step 5: Ready -> Zygote (freeze)
    let zygote = vm.freeze().await.expect("freeze");

    // Step 6: Zygote -> Ready
    let console2 = ConsoleStream::new();
    let backends2: SpawnBackends<'_, amla_fuse::NullFsBackend> = SpawnBackends {
        console: &console2,
        net: None,
        fs: None,
    };
    let spawned = zygote.spawn(pools, backends2).await.expect("zygote spawn");
    assert_eq!(spawned.config().memory_mb, 128);
}
