// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Error path integration tests for the amla-vmm porcelain API.
//!
//! Exercises every `Error` variant through the public API: backend mismatch,
//! corrupt kernel, empty kernel.

mod common;

use amla_vmm::{Backends, NetConfig, VirtualMachine};

// =============================================================================
// Backend Mismatch Errors
// =============================================================================

/// Net configured in `VmConfig` but no net backend provided -> `BackendMismatch`.
#[tokio::test(flavor = "multi_thread")]
async fn test_net_config_without_backend() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::test_vm_config()
        .memory_mb(128)
        .net(NetConfig::default());

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let kernel = common::kernel();

    // Build backends without net — should fail validation at load_kernel.
    let console = amla_vmm::ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![],
    };

    let result = vm.load_kernel(pools, kernel, backends).await;

    let err = result
        .err()
        .expect("load_kernel should fail without net backend");
    let msg = err.to_string();
    assert!(
        msg.contains("mismatch") || msg.contains("backend"),
        "Error should mention backend mismatch: {msg}"
    );
}

/// Pmem count mismatch -> `BackendMismatch`.
#[tokio::test(flavor = "multi_thread")]
async fn test_backend_pmem_count_mismatch() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::test_vm_config().memory_mb(128).pmem_root(4096);

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let kernel = common::kernel();

    // Pass empty pmem vec — count mismatch (config has 1 pmem disk).
    let console = amla_vmm::ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![],
    };

    let result = vm.load_kernel(pools, kernel, backends).await;

    let err = result
        .err()
        .expect("load_kernel should fail with wrong pmem count");
    let msg = err.to_string();
    assert!(
        msg.contains("pmem") || msg.contains("mismatch"),
        "Error should mention pmem mismatch: {msg}"
    );
}

// =============================================================================
// Kernel Loading Errors
// =============================================================================

/// Loading corrupt kernel bytes should fail.
#[tokio::test(flavor = "multi_thread")]
async fn test_load_kernel_corrupt_bytes() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::test_vm_config().memory_mb(128);

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let console = amla_vmm::ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![],
    };

    let result = vm
        .load_kernel(pools, &[0xDE, 0xAD, 0xBE, 0xEF], backends)
        .await;
    assert!(
        result.is_err(),
        "load_kernel with corrupt bytes should fail"
    );
}

/// Loading empty kernel bytes should fail.
#[tokio::test(flavor = "multi_thread")]
async fn test_load_kernel_empty_bytes() {
    if common::skip() {
        return;
    }
    let pools = common::pools();
    let config = common::test_vm_config().memory_mb(128);

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let console = amla_vmm::ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![],
    };

    let result = vm.load_kernel(pools, &[], backends).await;
    assert!(result.is_err(), "load_kernel with empty bytes should fail");
}
