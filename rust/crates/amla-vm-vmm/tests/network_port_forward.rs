// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Integration tests for inbound port forwarding (TCP and UDP).
//!
//! Tests boot a real KVM VM with virtio-net + usernet, start a listener
//! inside the guest via `exec`, then call `accept_inbound` /
//! `accept_inbound_udp` from the host side and verify data roundtrips
//! through the guest's TCP/UDP stack.

mod common;

use std::sync::Arc;
use std::time::{Duration, Instant};

use amla_constants::net::DEFAULT_GUEST_MAC;
use amla_usernet::{SharedBackend, UserNetBackend, UserNetConfig};
use amla_vmm::{
    Backends, CommandExecution, ConsoleStream, NetConfig, OutputEvent, Running, VirtualMachine,
    VmHandle,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAC: [u8; 6] = DEFAULT_GUEST_MAC;

async fn wait_for_guest_marker(cmd: &mut CommandExecution, marker: &str) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let event = tokio::time::timeout(Duration::from_secs(10), cmd.recv_output())
            .await
            .expect("guest readiness marker timed out")
            .expect("guest command disconnected before readiness marker");
        match event {
            OutputEvent::Stdout(bytes) => {
                stdout.extend_from_slice(&bytes);
                if String::from_utf8_lossy(&stdout).contains(marker) {
                    return;
                }
            }
            OutputEvent::Stderr(bytes) => stderr.extend_from_slice(&bytes),
            OutputEvent::Exit(code) => {
                panic!(
                    "guest command exited before readiness marker {marker:?}: code={code}, stdout={}, stderr={}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                );
            }
        }
    }
}

async fn udp_timeout_diagnostics(
    vm: &VmHandle<'_, Running>,
    echo: &mut CommandExecution,
    response_timeout: tokio::time::error::Elapsed,
) -> Vec<u8> {
    match tokio::time::timeout(Duration::from_secs(1), echo.collect_output()).await {
        Ok(Ok(output)) => {
            let arp = vm
                .exec(["/bin/amla-guest", "cat", "/proc/net/arp"])
                .await
                .expect("cat arp");
            let arp = common::collect_output(arp).await;
            let route = vm
                .exec(["/bin/amla-guest", "cat", "/proc/net/route"])
                .await
                .expect("cat route");
            let route = common::collect_output(route).await;
            panic!(
                "recv timed out ({response_timeout}); udp echo exited code={} stdout={} stderr={}\narp:\n{}\nroute:\n{}",
                output.exit_code,
                output.stdout_str(),
                output.stderr_str(),
                arp.stdout_str(),
                route.stdout_str(),
            );
        }
        Ok(Err(err)) => {
            panic!("recv timed out ({response_timeout}); udp echo collect failed: {err}")
        }
        Err(output_timeout) => {
            panic!("recv timed out ({response_timeout}); udp echo still running: {output_timeout}")
        }
    }
}

// =============================================================================
// TCP Port Forwarding
// =============================================================================

/// Boot a VM, start a TCP echo server on guest port 8080, then use
/// `accept_inbound` with a `DuplexStream` and verify data roundtrips
/// through the guest's TCP stack.
#[tokio::test(flavor = "multi_thread")]
async fn test_tcp_port_forward_echo() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: TCP Port Forward Echo ===");

    let image = common::rootfs_handle();
    // Wrap in Arc so we can share between run() and accept_inbound.
    // Arc<UserNetBackend> implements NetBackend via interior mutability.
    let usernet = Arc::new(UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap());
    let usernet_for_test = Arc::clone(&usernet);

    let pools = common::net_pools();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
    let net = SharedBackend(usernet);
    let backends: Backends<'_, amla_fuse::NullFsBackend, _> = Backends {
        console: &console,
        net: Some(&net),
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            // Wait for guest agent
            let mut probe = vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
            drop(probe.close_stdin().await);
            drop(tokio::time::timeout(timeout, probe.wait()).await);
            common::assert_not_timed_out(start, timeout, "boot");

            // Start TCP echo server in guest.
            let mut echo = vm
                .exec(["/bin/amla-guest", "tcp-echo", "8080"])
                .await
                .expect("start echo server");
            wait_for_guest_marker(&mut echo, "amla-guest tcp-echo ready 8080").await;

            // Create a DuplexStream — one end to accept_inbound, other is our host client
            let (guest_side, mut host_side) = tokio::io::duplex(4096);

            usernet_for_test
                .accept_inbound(Box::new(guest_side), 8080)
                .expect("accept_inbound");

            // Send data through the port forward
            host_side
                .write_all(b"hello port forward\n")
                .await
                .expect("write");

            // Read echo response
            let mut buf = vec![0u8; 256];
            let n = tokio::time::timeout(Duration::from_secs(10), host_side.read(&mut buf))
                .await
                .expect("read timed out")
                .expect("read failed");

            let response = String::from_utf8_lossy(&buf[..n]);
            println!("TCP response: [{response}]");
            assert!(
                response.contains("hello port forward"),
                "expected echo, got: {response}"
            );
            drop(host_side);
            let output = tokio::time::timeout(Duration::from_secs(10), echo.collect_output())
                .await
                .expect("echo exit timed out")
                .expect("collect echo output");
            assert_eq!(output.exit_code, 0, "tcp echo failed");

            println!("TCP port forward test PASSED");
        })
        .await
        .expect("run");
}

// =============================================================================
// UDP Port Forwarding
// =============================================================================

/// Boot a VM, start a UDP echo responder on guest port 5353,
/// then use `accept_inbound_udp` with channels and verify roundtrip.
#[tokio::test(flavor = "multi_thread")]
async fn test_udp_port_forward_echo() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: UDP Port Forward Echo ===");

    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let usernet = Arc::new(UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap());
    let usernet_for_test = Arc::clone(&usernet);
    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
    let net = SharedBackend(usernet);
    let backends: Backends<'_, amla_fuse::NullFsBackend, _> = Backends {
        console: &console,
        net: Some(&net),
        fs: None,
        pmem: vec![image],
    };
    let vm = vm
        .load_kernel(pools, common::kernel(), backends)
        .await
        .expect("load kernel");

    let timeout = common::boot_timeout();
    let start = Instant::now();

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            // Wait for guest agent
            let mut probe = vm.exec(["/bin/amla-guest", "true"]).await.expect("probe");
            drop(probe.close_stdin().await);
            drop(tokio::time::timeout(timeout, probe.wait()).await);
            common::assert_not_timed_out(start, timeout, "boot");

            // Start UDP echo responder.
            let mut echo = vm
                .exec(["/bin/amla-guest", "udp-echo", "5353"])
                .await
                .expect("start udp echo");
            wait_for_guest_marker(&mut echo, "amla-guest udp-echo ready 5353").await;

            // Create channels for UDP forwarding
            let (host_tx, host_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);
            let (guest_tx, mut guest_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(256);

            usernet_for_test
                .accept_inbound_udp(host_rx, guest_tx, 5353)
                .expect("accept_inbound_udp");

            host_tx
                .send(b"hello udp forward".to_vec())
                .await
                .expect("send");

            let response =
                match tokio::time::timeout(Duration::from_secs(10), guest_rx.recv()).await {
                    Ok(Some(response)) => response,
                    Ok(None) => panic!("channel closed"),
                    Err(response_timeout) => {
                        udp_timeout_diagnostics(&vm, &mut echo, response_timeout).await
                    }
                };

            let response_str = String::from_utf8_lossy(&response);
            println!("UDP response: [{response_str}]");
            assert!(
                response_str.contains("hello udp forward"),
                "expected echo, got: {response_str}"
            );
            let output = tokio::time::timeout(Duration::from_secs(10), echo.collect_output())
                .await
                .expect("udp echo exit timed out")
                .expect("collect udp echo output");
            assert_eq!(output.exit_code, 0, "udp echo failed");

            println!("UDP port forward test PASSED");
        })
        .await
        .expect("run");
}
