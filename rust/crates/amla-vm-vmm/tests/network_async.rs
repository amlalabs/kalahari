// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

//! Async network integration tests via the VMM porcelain API.
//!
//! Validates that the async virtio device pipeline (ioeventfd + `DeviceWorker`)
//! handles slow/delayed network responses correctly. The guest sends an HTTP
//! request, then sits idle (HLT) waiting for data that takes seconds to arrive.
//! RX data arriving asynchronously must be delivered without excessive latency.
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test network_async -- --nocapture
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::time::{Duration, Instant};

use amla_constants::net::DEFAULT_GUEST_MAC;
use amla_usernet::{UserNetBackend, UserNetConfig};
use amla_vmm::{Backends, ConsoleStream, NetConfig, VirtualMachine};

// =============================================================================
// Test Infrastructure
// =============================================================================

const MAC: [u8; 6] = DEFAULT_GUEST_MAC;

/// Boot a VM with usernet and a `net_test_url`, returning (`exec_stdout`, `elapsed_time`).
async fn boot_network_vm(test_url: &str) -> (String, Duration) {
    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let usernet = UserNetBackend::try_new(
        UserNetConfig::try_default()
            .unwrap()
            .with_unrestricted_egress(),
    )
    .unwrap();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC))
        .try_cmdline_extra(format!("net_test_url={test_url}"))
        .expect("valid cmdline extra");

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

    let (vm, _exit_code) = vm
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

    let elapsed = start.elapsed();
    drop(vm);
    let serial = common::drainconsole(&mut console);

    println!("=== Console output ===");
    println!("{serial}");
    println!("=== End console output ===");

    assert!(
        elapsed < timeout,
        "Test timed out after {} seconds",
        timeout.as_secs()
    );

    (serial, elapsed)
}

// =============================================================================
// Slow HTTP Servers
// =============================================================================

/// Start an HTTP server that delays `delay` before sending the response.
fn start_slow_http_server(delay: Duration) -> (std::thread::JoinHandle<()>, Ipv4Addr, u16) {
    let host_ip = common::get_host_ip();
    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind slow HTTP server");
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, addr)) = listener.accept() {
            println!("Slow server: accepted connection from {addr}");
            let mut buf = [0u8; 4096];
            drop(stream.read(&mut buf));
            println!("Slow server: sleeping {delay:?} before responding...");
            std::thread::sleep(delay);
            let body = "ECHO_RESPONSE:OK\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            drop(stream.write_all(response.as_bytes()));
            println!("Slow server: response sent");
        }
    });

    (handle, host_ip, port)
}

/// Start an HTTP server that sends a chunked response with delays between chunks.
fn start_chunked_slow_http_server(
    chunk_delay: Duration,
    chunks: &[&str],
) -> (std::thread::JoinHandle<()>, Ipv4Addr, u16) {
    let host_ip = common::get_host_ip();
    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind chunked HTTP server");
    let port = listener.local_addr().unwrap().port();

    let chunks: Vec<String> = chunks.iter().map(|s| (*s).to_string()).collect();
    let handle = std::thread::spawn(move || {
        if let Ok((mut stream, addr)) = listener.accept() {
            println!("Chunked server: accepted connection from {addr}");
            let mut buf = [0u8; 4096];
            drop(stream.read(&mut buf));

            // Send headers
            let headers =
                "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
            drop(stream.write_all(headers.as_bytes()));
            drop(stream.flush());
            println!(
                "Chunked server: headers sent, sending {} chunks with {chunk_delay:?} delay",
                chunks.len()
            );

            // Send chunks with delays
            for (i, chunk) in chunks.iter().enumerate() {
                std::thread::sleep(chunk_delay);
                let chunk_data = format!("{:x}\r\n{}\r\n", chunk.len(), chunk);
                drop(stream.write_all(chunk_data.as_bytes()));
                drop(stream.flush());
                println!("Chunked server: sent chunk {}/{}", i + 1, chunks.len());
            }

            // Final empty chunk
            drop(stream.write_all(b"0\r\n\r\n"));
            drop(stream.flush());
            println!("Chunked server: all chunks sent");
        }
    });

    (handle, host_ip, port)
}

// =============================================================================
// Tests
// =============================================================================

/// Slow HTTP response: server delays 3 seconds before responding.
///
/// Validates that the async virtio pipeline delivers RX data to a halted guest
/// without excessive latency. If the async path were broken, the guest would
/// need TCP retransmits (adding seconds) or poll timeouts to notice the data.
#[tokio::test(flavor = "multi_thread")]
async fn test_network_slow_response() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: Network Slow Response (async pipeline) ===");

    let server_delay = Duration::from_secs(3);
    let (_server_handle, host_ip, port) = start_slow_http_server(server_delay);
    println!("Slow server listening on {host_ip}:{port} (delay: {server_delay:?})");

    let test_url = format!("http://{host_ip}:{port}/slow");
    let (serial, elapsed) = boot_network_vm(&test_url).await;

    // Guest-side assertions
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    common::assert_serial(
        &serial,
        "NETWORK:PASS",
        "Network configuration failed (static netlink setup)",
    );
    common::assert_serial(&serial, "FETCH:PASS", "HTTP fetch failed");
    common::assert_serial(
        &serial,
        "ECHO_RESPONSE:OK",
        "Echo server response not received after delay",
    );
    common::assert_serial(&serial, "NETWORK_TEST:PASS", "Network test failed");

    // Timing assertion: boot + DHCP + server delay + margin.
    // x86_64 (native KVM): ~2-5s boot + ~1-2s DHCP + 3s delay → well under 20s.
    // aarch64 (QEMU TCG): ~60s+ boot + ~5s+ DHCP + 3s delay → needs ~120s.
    let max_allowed = if cfg!(target_arch = "aarch64") {
        Duration::from_mins(3)
    } else {
        Duration::from_secs(20)
    };
    println!("Total elapsed: {elapsed:?} (max allowed: {max_allowed:?})");
    assert!(
        elapsed < max_allowed,
        "Slow response took {elapsed:?}, expected < {max_allowed:?}. \
         Async pipeline may not be delivering RX data promptly.",
    );

    println!("Network slow response test PASSED ({elapsed:?})");
}

/// Chunked slow HTTP response: server sends body in chunks with delays.
///
/// Validates that the async pipeline handles streaming/partial responses where
/// data arrives in multiple waves with idle periods between them.
#[tokio::test(flavor = "multi_thread")]
async fn test_network_chunked_slow_response() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    println!("\n=== Test: Network Chunked Slow Response (async pipeline) ===");

    let chunk_delay = Duration::from_secs(1);
    let chunks = &[
        "CHUNK1:received\n",
        "CHUNK2:received\n",
        "ECHO_RESPONSE:OK\n",
    ];
    let (_server_handle, host_ip, port) = start_chunked_slow_http_server(chunk_delay, chunks);
    println!(
        "Chunked server listening on {host_ip}:{port} ({} chunks, {chunk_delay:?} delay each)",
        chunks.len()
    );

    let test_url = format!("http://{host_ip}:{port}/chunked");
    let (serial, elapsed) = boot_network_vm(&test_url).await;

    // Guest-side assertions
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    common::assert_serial(
        &serial,
        "NETWORK:PASS",
        "Network configuration failed (static netlink setup)",
    );
    common::assert_serial(&serial, "FETCH:PASS", "Chunked HTTP fetch failed");
    common::assert_serial(
        &serial,
        "ECHO_RESPONSE:OK",
        "Final chunk marker not received — chunked transfer may be incomplete",
    );
    common::assert_serial(&serial, "NETWORK_TEST:PASS", "Network test failed");

    // Timing: boot + DHCP + 3 chunks * 1s delay + margin
    let max_allowed = if cfg!(target_arch = "aarch64") {
        Duration::from_mins(3)
    } else {
        Duration::from_secs(20)
    };
    println!("Total elapsed: {elapsed:?} (max allowed: {max_allowed:?})");
    assert!(
        elapsed < max_allowed,
        "Chunked response took {elapsed:?}, expected < {max_allowed:?}. \
         Async pipeline may not be delivering RX data promptly.",
    );

    println!("Network chunked slow response test PASSED ({elapsed:?})");
}
