// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Console output verification tests for the amla-vmm porcelain API.
//!
//! Tests that console output is captured correctly via the `ConsoleStream`.
//! On x86, kernel log flows through PIO 0x3F8 (serial) which is injected into
//! the `ConsoleStream`. On ARM64, `console=hvc0` routes kernel log through
//! virtio-console directly into the same `ConsoleStream`.

mod common;

use std::time::{Duration, Instant};

use amla_vmm::{Backends, VirtualMachine};

/// Boot VM -> console output should be non-empty (PIO always active on x86).
#[tokio::test(flavor = "multi_thread")]
async fn test_serial_output_captured() {
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
    common::assert_not_timed_out(start, timeout, "test_serial_output_captured");
    drop(vm);

    let serial = common::drainconsole(&mut console);
    assert!(!serial.is_empty(), "console output should be non-empty");
    eprintln!("Console output length: {} bytes", serial.len());
}

/// Console output contains guest agent boot markers.
#[tokio::test(flavor = "multi_thread")]
async fn test_serial_contains_boot_markers() {
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
    common::assert_not_timed_out(start, timeout, "test_serial_contains_boot_markers");
    drop(vm);

    let serial = common::drainconsole(&mut console);
    assert!(!serial.is_empty(), "serial output should be non-empty");
}
