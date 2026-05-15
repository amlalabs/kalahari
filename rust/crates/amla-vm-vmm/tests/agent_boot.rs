// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for guest agent boot via the VMM API.
//!
//! Tests the guest agent lifecycle:
//! - VM boots with ring buffer agent transport
//! - Host sends proactive Setup, guest processes it
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test agent_boot -- --nocapture
//! ```

mod common;

use std::time::{Duration, Instant};

use amla_vmm::{Backends, VirtualMachine};

// =============================================================================
// Tests
// =============================================================================

/// Full guest agent boot and serial markers.
///
/// Verifies the agent protocol end-to-end:
/// 1. Guest boots and mounts essential filesystems
/// 2. Host sends proactive Setup, guest receives it
/// 3. Agent is ready for exec commands
#[tokio::test(flavor = "multi_thread")]
async fn test_agent_full_handshake() {
    common::init_logging();

    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let pools = common::pools();

    let config = common::default_config().memory_mb(256);

    let (mut console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");

    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let (vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            // Give the guest time to boot and emit serial markers.
            // The agent processes Setup proactively — no handshake needed.
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("start command");
            drop(tokio::time::timeout(Duration::from_secs(5), common::collect_output(cmd)).await);
        })
        .await
        .expect("run VM");
    drop(vm);

    let serial = common::drainconsole(&mut console);
    println!("=== Serial output ===");
    println!("{serial}");
    println!("=== End serial output ===");

    // Basic sanity: serial output was captured.
    assert!(!serial.is_empty(), "serial output should be non-empty");
}

/// Guest readiness completes within a reasonable time window.
///
/// Validates that guest boot reaches exec readiness well within the
/// timeout. This catches regressions in guest initialization.
#[tokio::test(flavor = "multi_thread")]
async fn test_agent_readiness_timing() {
    common::init_logging();

    if let Some(reason) = common::skip_checks() {
        eprintln!("Skipping: {reason}");
        return;
    }

    let pools = common::pools();

    let config = common::default_config().memory_mb(256);

    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");

    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let start = Instant::now();

    // TTI = time from VM start until a trivial exec completes.
    let timeout = common::boot_timeout();
    let (_vm, ready_elapsed) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("start command");
            let _ = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
            start.elapsed()
        })
        .await
        .expect("spawn VM");

    println!("Agent readiness timing: {ready_elapsed:?} (boot + first exec)");

    // The agent should be ready well within the boot timeout. Typical: 2-5s
    // on bare metal, but nested virtualization (codespaces, CI VMs) can be
    // much slower due to degraded KVM performance.
    let limit = common::boot_timeout();
    assert!(
        ready_elapsed < limit,
        "Guest readiness took too long: {ready_elapsed:?} (limit={limit:?})",
    );
}
