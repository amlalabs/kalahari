// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Full-stack HTTPS MITM integration test.
//!
//! Exercises TLS interception through the entire `UserNetBackend` → `NatProxy` →
//! `TcpConnectionTask` → `MitmInterceptor` pipeline using real TCP sockets.
//!
//! Key design decisions:
//! - Manual TCP guest (`TcpGuest`) keeps packet expectations deterministic.
//! - `intercept_port(server_port)` — ephemeral port, not 443.
//! - `with_host_tls_config` — MITM trusts test CA.
//! - Position-tracking `read_tls` pattern to avoid `has_seen_eof` issue.

// Test file — long integration test, intentional casts
#![allow(clippy::too_many_lines, clippy::cast_possible_truncation)]

mod common;

use std::io::{ErrorKind, IoSlice, Read, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use amla_core::backends::NetBackend;
use amla_tls_proxy_net::TlsMitmInterceptor;
use amla_tls_proxy_net::ca::CertificateAuthority;
use amla_tls_proxy_net::handler::{
    HttpMitmHandler, HttpRequestHeaders, HttpResponseHeaders, MitmAction, ResponseOutcome,
};
use amla_tls_proxy_net::policy::MitmPolicy;
use amla_usernet::packet_builder::{TCP_ACK, TCP_SYN};
use amla_usernet::{UserNetBackend, UserNetConfig};
use http::StatusCode;

use common::{TcpGuest, drive_backend, parse_tcp_response};

// =============================================================================
// Recording handler
// =============================================================================

struct RecordingHandler {
    events: Mutex<Vec<String>>,
}

impl RecordingHandler {
    const fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl HttpMitmHandler for RecordingHandler {
    // Reason: mutex guard spans both pushes so the events log records
    // the pair atomically.
    #[allow(clippy::significant_drop_tightening)]
    async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
        let path = req
            .uri
            .path_and_query()
            .map_or_else(|| req.uri.path(), http::uri::PathAndQuery::as_str);
        let mut events = self.events.lock().unwrap();
        events.push(format!("req_headers:{} {}", req.method, path));
        // Also emit the legacy `request:...` event so existing assertions pass.
        events.push(format!("request:{} {}", req.method, path));
        MitmAction::Forward
    }

    // Reason: mutex guard spans both pushes so the events log records
    // the pair atomically.
    #[allow(clippy::significant_drop_tightening)]
    async fn on_response_headers(
        &self,
        _req: &HttpRequestHeaders,
        resp: &mut HttpResponseHeaders,
    ) -> MitmAction {
        let status = resp.status.as_u16();
        let mut events = self.events.lock().unwrap();
        events.push(format!("resp_headers:{status}"));
        events.push(format!("response:{status}"));
        MitmAction::Forward
    }

    async fn on_complete(
        &self,
        _req: &HttpRequestHeaders,
        status: StatusCode,
        outcome: ResponseOutcome,
    ) {
        let tag = match outcome {
            ResponseOutcome::Completed => "complete",
            ResponseOutcome::Aborted => "aborted",
        };
        self.events
            .lock()
            .unwrap()
            .push(format!("{tag}:{}", status.as_u16()));
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// Collect TCP response payloads from the backend for our flow.
/// Updates `guest_tcp.ack` and sends ACKs for received data.
/// Returns concatenated payloads, or empty vec if nothing arrived within timeout.
fn collect_tcp_payloads<P>(
    backend: &UserNetBackend<P>,
    guest_tcp: &mut TcpGuest,
    timeout: Duration,
) -> Vec<u8>
where
    P: amla_usernet::interceptor::TcpConnectionPolicy,
{
    let mut payloads = Vec::new();
    let deadline = Instant::now() + timeout;
    let mut got_data = false;

    while Instant::now() < deadline {
        let packets = drive_backend(backend);
        for pkt in &packets {
            if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
                && !resp.payload.is_empty()
            {
                guest_tcp.ack = resp.seq.wrapping_add(resp.payload.len() as u32);
                payloads.extend_from_slice(&resp.payload);
                got_data = true;
            }
        }
        if got_data {
            // ACK the received data
            let ack_pkt = guest_tcp.build_ack();
            backend.send(&[IoSlice::new(&ack_pkt)]).unwrap();
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }
    payloads
}

/// Feed encrypted data to guest TLS using position-tracking pattern.
///
/// Loops `read_tls` → `process_new_packets` to handle deframer buffer limits
/// (starts at 4KB). Never lets `read_tls` see `Ok(0)` which would set
/// `has_seen_eof` permanently.
fn feed_guest_tls(conn: &mut rustls::ClientConnection, data: &[u8]) -> Result<(), rustls::Error> {
    let mut pos = 0;
    while pos < data.len() {
        let n = conn.read_tls(&mut &data[pos..]).expect("read_tls IO error");
        pos += n;
        conn.process_new_packets()?;
    }
    Ok(())
}

// =============================================================================
// TLS test server
// =============================================================================

fn spawn_tls_server(
    ca: &Arc<CertificateAuthority>,
    hostname: &str,
) -> (thread::JoinHandle<()>, u16) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();

    let leaf = ca.get_leaf_cert(hostname).unwrap();
    let cert_chain = vec![leaf.cert_der().clone(), ca.ca_cert_der().clone()];
    let key = leaf.key_der().clone_key();
    let config = Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap(),
    );

    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();

        let server_conn = rustls::ServerConnection::new(config).unwrap();
        let mut tls = rustls::StreamOwned::new(server_conn, stream);

        // Read HTTP request
        let mut buf = [0u8; 4096];
        let n = tls.read(&mut buf).unwrap();
        assert!(n > 0, "server: no HTTP request received");

        // Send HTTP response
        let body = "Hello from MITM test!";
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        tls.write_all(response.as_bytes()).unwrap();
        tls.flush().unwrap();

        // Graceful TLS close — best-effort; the test client may already have
        // closed the socket, in which case the close_notify can't be flushed.
        tls.conn.send_close_notify();
        if let Err(e) = tls.conn.write_tls(&mut tls.sock) {
            log::debug!("test tls server: write_tls(close_notify) failed: {e}");
        }
    });

    (handle, port)
}

// =============================================================================
// Main test
// =============================================================================

/// Documentation-range DNS placeholder; this MITM test never sends DNS.
const UNUSED_TEST_HOST_DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

fn tcp_test_config() -> UserNetConfig {
    UserNetConfig::default()
        .with_host_dns_server(UNUSED_TEST_HOST_DNS)
        .with_unrestricted_egress()
}

fn tcp_test_backend_with_policy<P>(policy: P) -> UserNetBackend<P>
where
    P: amla_usernet::interceptor::TcpConnectionPolicy,
{
    UserNetBackend::try_new_with_tcp_policy(tcp_test_config(), policy).unwrap()
}

async fn run_https_mitm_through_usernet() {
    // try_init returns Err if a logger is already installed by another test
    // running in the same process — benign, ignore.
    let _logger = env_logger::builder().is_test(true).try_init();
    // ── Phase 1: Setup ─────────────────────────────────────────────────
    let ca = Arc::new(CertificateAuthority::new().unwrap());
    let hostname = "api.example.com";
    let (server_handle, server_port) = spawn_tls_server(&ca, hostname);

    let handler = Arc::new(RecordingHandler::new());

    // Policy: intercept the server's ephemeral port (not 443)
    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();

    // Host TLS config: MITM's outbound rustls client trusts test CA
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca.ca_cert_der().clone()).unwrap();
    let host_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        ca.clone(),
        policy,
        handler.clone(),
        host_config,
    ));

    let backend = tcp_test_backend_with_policy(interceptor);

    let timeout = Duration::from_secs(5);
    let mut guest_tcp = TcpGuest::new(Ipv4Addr::LOCALHOST, server_port);

    // ── Phase 2: TCP handshake ─────────────────────────────────────────
    let syn = guest_tcp.build_syn();
    backend.send(&[IoSlice::new(&syn)]).unwrap();

    // Wait for SYN-ACK (NatProxy spawns tokio task that connects to server)
    let start = Instant::now();
    'syn_ack: loop {
        let packets = drive_backend(&backend);
        for pkt in &packets {
            if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
                && resp.flags & TCP_SYN != 0
                && resp.flags & TCP_ACK != 0
            {
                guest_tcp.ack = resp.seq.wrapping_add(1); // SYN consumes 1
                break 'syn_ack;
            }
        }
        assert!(start.elapsed() < timeout, "timed out waiting for SYN-ACK");
        thread::sleep(Duration::from_millis(1));
    }

    // Complete TCP handshake
    let ack = guest_tcp.build_ack();
    backend.send(&[IoSlice::new(&ack)]).unwrap();

    // ── Phase 3: TLS handshake ─────────────────────────────────────────
    let mut guest_root_store = rustls::RootCertStore::empty();
    guest_root_store.add(ca.ca_cert_der().clone()).unwrap();
    let guest_tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(guest_root_store)
            .with_no_client_auth(),
    );
    let server_name = rustls::pki_types::ServerName::try_from(hostname.to_string()).unwrap();
    let mut guest_tls = rustls::ClientConnection::new(guest_tls_config, server_name).unwrap();

    let tls_start = Instant::now();
    for round in 0..20 {
        // Guest → backend: flush any pending TLS handshake output. Errors
        // here mean rustls couldn't serialize a record (very unlikely in
        // this test setup) — log and continue.
        let mut tls_out = Vec::new();
        if let Err(e) = guest_tls.write_tls(&mut tls_out) {
            log::debug!("test guest_tls write_tls (round {round}): {e}");
        }
        if !tls_out.is_empty() {
            let pkt = guest_tcp.build_data(&tls_out);
            backend.send(&[IoSlice::new(&pkt)]).unwrap();
        }

        if !guest_tls.is_handshaking() {
            break;
        }

        // Backend → guest: collect TLS response data
        let payloads = collect_tcp_payloads(&backend, &mut guest_tcp, Duration::from_secs(2));
        if !payloads.is_empty() {
            feed_guest_tls(&mut guest_tls, &payloads)
                .unwrap_or_else(|e| panic!("TLS error at handshake round {round}: {e}"));
        }

        assert!(
            tls_start.elapsed() < timeout,
            "TLS handshake timed out at round {round}"
        );
    }
    assert!(
        !guest_tls.is_handshaking(),
        "TLS handshake did not complete within 20 rounds"
    );

    // ── Phase 4: HTTP request/response ─────────────────────────────────
    let http_request = format!(
        "GET /test HTTP/1.1\r\nHost: api.example.com:{server_port}\r\nContent-Length: 0\r\n\r\n"
    );
    guest_tls
        .writer()
        .write_all(http_request.as_bytes())
        .unwrap();

    let mut tls_out = Vec::new();
    guest_tls.write_tls(&mut tls_out).unwrap();
    let pkt = guest_tcp.build_data(&tls_out);
    backend.send(&[IoSlice::new(&pkt)]).unwrap();

    // Collect HTTP response from server through MITM. The MITM strips
    // Content-Length and always re-emits the body as chunked on the guest
    // leg (see amla-vm-tls-proxy-net/src/mitm/xlate.rs and handler.rs), so
    // headers and body land in two separate TLS records. We must keep
    // reading until the body content arrives — breaking on the first
    // plaintext byte sees only headers and races with the body chunk.
    let body_marker: &[u8] = b"Hello from MITM test!";
    let mut response_plaintext = Vec::new();
    let resp_start = Instant::now();
    while resp_start.elapsed() < timeout {
        let payloads = collect_tcp_payloads(&backend, &mut guest_tcp, Duration::from_millis(500));
        if !payloads.is_empty() {
            feed_guest_tls(&mut guest_tls, &payloads).expect("TLS error reading response");

            let mut buf = vec![0u8; 8192];
            match guest_tls.reader().read(&mut buf) {
                Ok(n) => response_plaintext.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::WouldBlock => {}
                Err(e) => panic!("plaintext read error: {e}"),
            }
        }
        if response_plaintext
            .windows(body_marker.len())
            .any(|w| w == body_marker)
        {
            break;
        }
        thread::sleep(Duration::from_millis(1));
    }

    let response_str = String::from_utf8_lossy(&response_plaintext);
    assert!(
        response_str.contains("200 OK"),
        "expected 200 OK in response, got: {response_str}"
    );
    assert!(
        response_str.contains("Hello from MITM test!"),
        "expected response body, got: {response_str}"
    );

    // ── Phase 5: Verify interception ───────────────────────────────────
    // `on_complete` fires on TappedBody's post-body poll, which the MITM
    // task runs a few microseconds after writing the last body frame to
    // the guest. We already broke out of the response-read loop on the
    // first guest-side byte, so the handler future may not have been
    // polled yet — spin-drive the backend briefly until it does.
    let complete_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < complete_deadline
        && !handler.events().iter().any(|e| e == "complete:200")
    {
        let _ = drive_backend(&backend);
        thread::sleep(Duration::from_millis(1));
    }

    let events = handler.events();
    assert!(
        events.iter().any(|e| e.starts_with("req_headers:GET")),
        "missing req_headers event: {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "request:GET /test"),
        "missing request event: {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "response:200"),
        "missing response event: {events:?}"
    );
    assert!(
        events.iter().any(|e| e == "complete:200"),
        "missing complete event: {events:?}"
    );

    // Cleanup
    server_handle.join().expect("server thread panicked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn https_mitm_through_usernet() {
    run_https_mitm_through_usernet().await;
}
