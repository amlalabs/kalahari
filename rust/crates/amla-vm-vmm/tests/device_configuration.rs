// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Device configuration tests for the amla-vmm porcelain API.
//!
//! All standard devices (balloon, rng, console) are always enabled.
//! These tests verify boot, mmio bus access, and erofs root.

mod common;

use amla_vmm::{Backends, VirtualMachine};

// =============================================================================
// Boot with All Devices
// =============================================================================

/// Boot with all standard devices (balloon, rng, console) — always-on.
#[tokio::test(flavor = "multi_thread")]
async fn test_boot_all_devices() {
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
    common::boot_to_ready(pools, config, backends).await;
}

/// Load kernel with all devices — should not panic.
#[tokio::test(flavor = "multi_thread")]
async fn test_devices_accessible_after_load() {
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

    // Devices are set up during load_kernel (verified by success above)
    let _ = &vm;
}
