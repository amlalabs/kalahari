// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Boundary configuration integration tests for the amla-vmm porcelain API.
//!
//! Tests extreme and boundary configuration values: defaults, zero configs,
//! large memory, SMP, all-devices-disabled, seccomp modes, and blocking API.

mod common;

use std::time::{Duration, Instant};

use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, ConsoleStream, VirtualMachine, VmConfig};

// =============================================================================
// Config Default Inspection
// =============================================================================

/// Verify `VmConfig::default()` produces the documented defaults.
#[test]
fn test_config_defaults_are_correct() {
    let config = VmConfig::default();
    assert_eq!(config.memory_mb, 256, "default memory should be 256 MB");
    assert_eq!(config.vcpu_count, 1, "default vcpu count should be 1");
    assert!(config.net.is_none(), "net should be disabled by default");
    assert!(config.fs.is_none(), "fs should be disabled by default");
    assert!(
        config.pmem_disks.is_empty(),
        "pmem_disks should be empty by default"
    );
}

// =============================================================================
// Boundary Value Tests
// =============================================================================

/// 4 GB memory --- should succeed or return a meaningful error about pool capacity.
#[tokio::test(flavor = "multi_thread")]
async fn test_config_large_memory_4gb() {
    if common::skip() {
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(4096)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(2, &config, common::worker_config())
        .expect("create pools");

    let vm = VirtualMachine::create(config).await;

    match vm {
        Ok(vm) => {
            let kernel = common::kernel();
            let console = ConsoleStream::new();
            let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
                console: &console,
                net: None,
                fs: None,
                pmem: vec![common::rootfs_handle()],
            };
            let result = vm.load_kernel(&pools, kernel, backends).await;
            assert!(result.is_ok(), "load_kernel should succeed with 4 GB");
        }
        Err(e) => {
            eprintln!("4 GB create failed (acceptable): {e}");
        }
    }
}

/// SMP with 4 vCPUs --- full boot cycle.
#[tokio::test(flavor = "multi_thread")]
async fn test_config_smp_4_vcpus() {
    if common::skip() {
        return;
    }

    // 4 vCPUs under QEMU TCG serializes all vCPU execution and takes >300s.
    if cfg!(target_arch = "aarch64") {
        eprintln!("Skipping: 4-vCPU SMP too slow under QEMU TCG");
        return;
    }

    let config = common::test_vm_config()
        .memory_mb(256)
        .vcpu_count(4)
        .pmem_root(common::rootfs_handle().size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(4, &config, common::worker_config())
        .expect("create pools");

    let (console, pmem) = common::default_backends(&config);
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem,
    };
    let vm = common::boot_to_ready(&pools, config, backends).await;
    drop(vm);
}

/// SMP guest sees correct CPU count via `nproc`.
///
/// Validates that the MP table declares all configured vCPUs so the guest
/// kernel brings up the right number of CPUs.
#[tokio::test(flavor = "multi_thread")]
async fn test_smp_guest_sees_all_cpus() {
    if common::skip() {
        return;
    }

    if cfg!(target_arch = "aarch64") {
        eprintln!("Skipping: SMP nproc test too slow under QEMU TCG");
        return;
    }

    let image = common::rootfs_handle();
    let config = common::test_vm_config()
        .memory_mb(256)
        .vcpu_count(4)
        .pmem_root(image.size().as_u64());

    let pools = amla_vmm::backend::BackendPools::new(4, &config, common::worker_config())
        .expect("create pools");

    let kernel = common::kernel();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![image],
    };
    let vm = VirtualMachine::create(config).await.expect("create VM");
    let vm = vm
        .load_kernel(&pools, kernel, backends)
        .await
        .expect("load kernel");

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let grep_result = vm
                .exec([
                    "/bin/amla-guest",
                    "grep",
                    "-c",
                    "^processor",
                    "/proc/cpuinfo",
                ])
                .await
                .expect("run grep cpuinfo");
            let output =
                tokio::time::timeout(common::boot_timeout(), common::collect_output(grep_result))
                    .await
                    .expect("cpuinfo grep timed out");

            assert_eq!(output.exit_code, 0, "grep cpuinfo should succeed");
            let stdout = output.stdout_str();
            let cpu_count: u32 = stdout.trim().parse().expect("parse cpu count");
            assert_eq!(cpu_count, 4, "guest should see 4 CPUs, got {cpu_count}");
        })
        .await
        .expect("run VM");
}

/// All optional devices disabled --- only fixed console/rng devices.
#[tokio::test(flavor = "multi_thread")]
async fn test_config_all_devices_disabled() {
    if common::skip() {
        return;
    }
    let config = common::test_vm_config().memory_mb(128);
    let pools = BackendPools::new(2, &config, common::worker_config()).expect("create pools");
    // No fs, no net, no pmem root. This only validates setup/kernel loading;
    // the guest is not expected to boot a userspace root filesystem.

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let kernel = common::kernel();
    let console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
        console: &console,
        net: None,
        fs: None,
        pmem: vec![],
    };
    if let Err(e) = vm.load_kernel(&pools, kernel, backends).await {
        panic!("load_kernel should succeed with all optional devices disabled: {e}");
    }
}

/// Async `VirtualMachine::create()` --- full boot cycle.
#[tokio::test(flavor = "multi_thread")]
async fn test_create_async_api() {
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
    let vm = VirtualMachine::create(config)
        .await
        .expect("create should succeed");

    let kernel = common::kernel();
    let vm = vm
        .load_kernel(pools, kernel, backends)
        .await
        .expect("load kernel");

    let timeout = Duration::from_secs(30);
    let start = Instant::now();
    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "true"])
                .await
                .expect("start run");
            let _ = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
        })
        .await
        .expect("run VM");
    common::assert_not_timed_out(start, timeout, "test_create_async_api");
}
