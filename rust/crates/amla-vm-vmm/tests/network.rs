// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

//! Network integration tests via the VMM porcelain API.
//!
//! Validates end-to-end networking with virtio-net and usernet:
//! - DHCP configuration via usernet's built-in DHCP server
//! - Network connectivity through NAT proxy
//! - Policy-based network filtering with metrics
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test network -- --nocapture
//! ```

mod common;

use std::net::Ipv4Addr;
use std::time::Instant;

use amla_constants::net::DEFAULT_GUEST_MAC;
use amla_policy_net::{Ipv4Subnet, NetworkPolicy, PolicyNetBackend};
use amla_usernet::{UserNetBackend, UserNetConfig};
use amla_vmm::{Backends, ConsoleStream, NetConfig, VirtualMachine};

// =============================================================================
// Test Infrastructure
// =============================================================================

const MAC: [u8; 6] = DEFAULT_GUEST_MAC;

// =============================================================================
// Tests
// =============================================================================

/// Basic network test: boot with virtio-net + usernet, verify DHCP and gateway ping.
#[tokio::test(flavor = "multi_thread")]
async fn test_network_dhcp() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: Network DHCP (VMM porcelain) ===");

    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let usernet = UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let mut console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend, _> = Backends {
        console: &console,
        net: Some(&usernet),
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();

    let (vm, exit_code) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "test-network"])
                .await
                .expect("start network test");
            let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
            output.exit_code
        })
        .await
        .expect("run VM");

    common::assert_not_timed_out(start, timeout, "test_network_dhcp");

    drop(vm);
    let serial = common::drainconsole(&mut console);
    println!("=== Console output ===");
    println!("{serial}");
    println!("=== End console output ===");

    assert_eq!(
        exit_code, 0,
        "network test failed with exit code {exit_code}"
    );
    assert!(
        serial.contains("NETIF:PASS"),
        "Network interface not detected\nConsole:\n{serial}",
    );
    assert!(
        serial.contains("NETWORK:PASS"),
        "Network configuration failed.\nConsole:\n{serial}",
    );
    assert!(
        serial.contains("NETWORK_TEST:PASS"),
        "Network test failed\nConsole:\n{serial}",
    );

    println!("Network DHCP test PASSED (VMM porcelain)");
}

/// Network with policy filtering: usernet wrapped in `PolicyNetBackend`.
///
/// Proves that `PolicyNetBackend` correctly passes through DHCP, DNS, and
/// ICMP traffic while the policy layer is active.
#[tokio::test(flavor = "multi_thread")]
async fn test_network_with_policy() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: Network with Policy (VMM porcelain) ===");

    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let policy = NetworkPolicy::builder()
        .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
        .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
        .allow_subnet(
            Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            &[80, 443],
        )
        .enable_dhcp()
        .enable_icmp()
        .build();

    let usernet = UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap();
    let filtered = PolicyNetBackend::new(usernet, policy.to_packet_policy());

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let mut console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend, _> = Backends {
        console: &console,
        net: Some(&filtered),
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();

    let (vm, exit_code) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "test-network"])
                .await
                .expect("start network test");
            let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
            output.exit_code
        })
        .await
        .expect("run VM");

    common::assert_not_timed_out(start, timeout, "test_network_with_policy");

    drop(vm);
    let serial = common::drainconsole(&mut console);
    println!("=== Console output ===");
    println!("{serial}");
    println!("=== End console output ===");

    assert_eq!(
        exit_code, 0,
        "network test failed with exit code {exit_code}"
    );
    assert!(
        serial.contains("NETIF:PASS"),
        "Network interface not detected\nConsole:\n{serial}",
    );
    assert!(
        serial.contains("NETWORK:PASS"),
        "Network configuration failed with policy.\nConsole:\n{serial}",
    );
    assert!(
        serial.contains("NETWORK_TEST:PASS"),
        "Network test failed with policy\nConsole:\n{serial}",
    );

    println!("Network with policy test PASSED (VMM porcelain)");
}

/// Policy metrics: verify allowed counter increments after DHCP + ping.
///
/// Grabs the `PolicyMetrics` handle before boot, then asserts `allowed > 0`
/// after the guest completes DHCP and gateway ping.
#[tokio::test(flavor = "multi_thread")]
async fn test_network_policy_metrics() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: Network Policy Metrics (VMM porcelain) ===");

    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let policy = NetworkPolicy::builder()
        .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
        .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
        .allow_subnet(
            Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0).unwrap(),
            &[80, 443],
        )
        .enable_dhcp()
        .enable_icmp()
        .build();

    let usernet = UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap();
    let filtered = PolicyNetBackend::new(usernet, policy.to_packet_policy());
    let metrics = filtered.metrics();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");

    let mut console = ConsoleStream::new();
    let backends: Backends<'_, amla_fuse::NullFsBackend, _> = Backends {
        console: &console,
        net: Some(&filtered),
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();

    let (vm, exit_code) = vm
        .run(async move |vm| {
            let vm = vm.start();
            let cmd = vm
                .exec(["/bin/amla-guest", "test-network"])
                .await
                .expect("start network test");
            let output = tokio::time::timeout(timeout, common::collect_output(cmd))
                .await
                .expect("timed out");
            output.exit_code
        })
        .await
        .expect("run VM");

    common::assert_not_timed_out(start, timeout, "test_network_policy_metrics");

    drop(vm);
    let serial = common::drainconsole(&mut console);
    println!("=== Console output ===");
    println!("{serial}");
    println!("=== End console output ===");

    assert_eq!(
        exit_code, 0,
        "network test failed with exit code {exit_code}"
    );
    assert!(
        serial.contains("NETIF:PASS"),
        "Network interface not detected\nConsole:\n{serial}",
    );
    assert!(
        serial.contains("NETWORK:PASS"),
        "Network configuration failed.\nConsole:\n{serial}",
    );

    // Verify policy metrics recorded traffic
    let snapshot = metrics.snapshot();
    println!("\n=== Policy Metrics ===");
    println!("  allowed: {}", snapshot.allowed);
    println!("  denied:  {}", snapshot.denied);
    println!("  bytes_allowed: {}", snapshot.bytes_allowed);
    println!("  bytes_denied:  {}", snapshot.bytes_denied);

    assert!(
        snapshot.allowed > 0,
        "Policy should have allowed DHCP/ICMP packets, but allowed count is 0.\n\
         Metrics: {snapshot:?}",
    );

    println!("Network policy metrics test PASSED (VMM porcelain)");
}
