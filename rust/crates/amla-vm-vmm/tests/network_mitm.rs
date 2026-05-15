// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::cast_possible_truncation)]

//! MITM network integration tests via the VMM porcelain API.
//!
//! Each test boots a separate VM since the guest can only fetch one URL per boot
//! (single `net_test_url=` parameter). Tests cover:
//! - Full HTTPS MITM intercept (record + forward)
//! - Request blocking (403 response from MITM)
//! - SNI bypass (traffic on unintercepted ports flows through raw)
//! - Header injection (MITM modifies request before forwarding)
//! - End-to-end request/response body observation and mutation
//!
//! # Running
//!
//! ```bash
//! cargo test -p amla-vmm --test network_mitm -- --nocapture
//! ```

mod common;

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use amla_constants::net::DEFAULT_GUEST_MAC;
use amla_tls_proxy_net::TlsMitmInterceptor;
use amla_tls_proxy_net::ca::CertificateAuthority;
use amla_tls_proxy_net::handler::{
    HttpMitmHandler, HttpRequestHeaders, HttpResponseHeaders, MitmAction, ResponseOutcome,
};
use amla_tls_proxy_net::policy::MitmPolicy;
use amla_usernet::{UserNetBackend, UserNetConfig};
use amla_vmm::{Backends, ConsoleStream, NetConfig, VirtualMachine};
use http::{HeaderName, HeaderValue, StatusCode, Uri};
use tokio_util::bytes::{Bytes, BytesMut};

// =============================================================================
// Test Infrastructure
// =============================================================================

const MAC: [u8; 6] = DEFAULT_GUEST_MAC;
const MITM_TEST_HOST: &str = "mitm.test";
const FULL_DUPLEX_GUEST_BODY: &str = "guest-visible guest-secret tail";

// =============================================================================
// MITM Helpers
// =============================================================================

/// Start a local HTTPS echo server that responds with `ECHO_RESPONSE:OK`.
fn start_echo_server(
    ca: &CertificateAuthority,
    host_ip: Ipv4Addr,
    cert_host: &str,
) -> (std::thread::JoinHandle<()>, u16) {
    let leaf = ca.get_leaf_cert(cert_host).unwrap();
    let cert_chain = vec![leaf.cert_der().clone(), ca.ca_cert_der().clone()];
    let key = leaf.key_der().clone_key();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("create server TLS config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind echo server");
    let port = listener.local_addr().unwrap().port();

    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(false).expect("set blocking");
        let _ = listener.incoming().next().and_then(|stream| {
            let stream = stream.ok()?;
            stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(3))).ok();

            let mut tls_conn = rustls::ServerConnection::new(Arc::clone(&server_config)).ok()?;
            let mut sock = &stream;
            let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut sock);

            let mut buf = [0u8; 4096];
            drop(tls_stream.read(&mut buf));

            let body = "ECHO_RESPONSE:OK";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            drop(tls_stream.write_all(response.as_bytes()));
            drop(tls_stream.flush());

            tls_conn.send_close_notify();
            let mut out = Vec::new();
            drop(tls_conn.write_tls(&mut out));
            // `tls_stream` has been dropped by this point so `sock` is free to reuse.
            drop(sock.write_all(&out));

            Some(())
        });
    });

    (handle, port)
}

fn start_uncontacted_origin_probe(
    host_ip: Ipv4Addr,
) -> (
    std::thread::JoinHandle<()>,
    u16,
    Arc<AtomicUsize>,
    Arc<AtomicBool>,
) {
    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind origin probe");
    listener
        .set_nonblocking(true)
        .expect("set origin probe nonblocking");
    let port = listener.local_addr().unwrap().port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let accepts_for_thread = Arc::clone(&accepts);
    let stop_for_thread = Arc::clone(&stop);

    let handle = std::thread::spawn(move || {
        while !stop_for_thread.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((_stream, _addr)) => {
                    accepts_for_thread.fetch_add(1, Ordering::AcqRel);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    (handle, port, accepts, stop)
}

#[derive(Clone, Debug)]
struct RecordedHttpRequest {
    method: String,
    target: String,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl RecordedHttpRequest {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    fn body_text(&self) -> String {
        String::from_utf8_lossy(&self.body).to_string()
    }
}

/// Start a local HTTPS origin that records the exact MITM-forwarded request.
fn start_inspecting_https_server(
    ca: &CertificateAuthority,
    host_ip: Ipv4Addr,
    cert_host: &str,
) -> (
    std::thread::JoinHandle<()>,
    u16,
    Arc<Mutex<Option<RecordedHttpRequest>>>,
) {
    let leaf = ca.get_leaf_cert(cert_host).unwrap();
    let cert_chain = vec![leaf.cert_der().clone(), ca.ca_cert_der().clone()];
    let key = leaf.key_der().clone_key();

    let mut server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .expect("create server TLS config");
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let server_config = Arc::new(server_config);

    let listener = TcpListener::bind((host_ip, 0u16)).expect("bind inspecting server");
    let port = listener.local_addr().unwrap().port();
    let recorded = Arc::new(Mutex::new(None));
    let recorded_for_thread = Arc::clone(&recorded);

    let handle = std::thread::spawn(move || {
        listener.set_nonblocking(false).expect("set blocking");
        let _ = listener.incoming().next().and_then(|stream| {
            let stream = stream.ok()?;
            stream.set_read_timeout(Some(Duration::from_secs(3))).ok();
            stream.set_write_timeout(Some(Duration::from_secs(3))).ok();

            let mut tls_conn = rustls::ServerConnection::new(Arc::clone(&server_config)).ok()?;
            let mut sock = &stream;
            let mut tls_stream = rustls::Stream::new(&mut tls_conn, &mut sock);

            let raw = read_http_request(&mut tls_stream)?;
            let parsed = parse_http_request(&raw)?;
            *recorded_for_thread.lock().unwrap() = Some(parsed);

            let body = "origin-body: origin-secret";
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 X-Origin-Response: original\r\n\
                 Connection: close\r\n\r\n{}",
                body.len(),
                body
            );
            drop(tls_stream.write_all(response.as_bytes()));
            drop(tls_stream.flush());

            tls_conn.send_close_notify();
            let mut out = Vec::new();
            drop(tls_conn.write_tls(&mut out));
            drop(sock.write_all(&out));

            Some(())
        });
    });

    (handle, port, recorded)
}

fn read_http_request<R: Read>(reader: &mut R) -> Option<Vec<u8>> {
    let mut raw = Vec::new();
    let mut buf = [0u8; 1024];

    loop {
        if let Some(header_end) = find_header_end(&raw) {
            let header_block = String::from_utf8_lossy(&raw[..header_end - 4]);
            if let Some(len) = header_value(&header_block, "content-length")
                .and_then(|v| v.trim().parse::<usize>().ok())
            {
                if raw.len() >= header_end.saturating_add(len) {
                    return Some(raw);
                }
            } else if header_value(&header_block, "transfer-encoding")
                .is_some_and(|v| v.to_ascii_lowercase().contains("chunked"))
            {
                if decode_chunked_body(&raw[header_end..]).is_some() {
                    return Some(raw);
                }
            } else {
                return Some(raw);
            }
        }

        let n = reader.read(&mut buf).ok()?;
        if n == 0 {
            return Some(raw);
        }
        raw.extend_from_slice(&buf[..n]);
    }
}

fn parse_http_request(raw: &[u8]) -> Option<RecordedHttpRequest> {
    let header_end = find_header_end(raw)?;
    let header_block = String::from_utf8_lossy(&raw[..header_end - 4]);
    let mut lines = header_block.split("\r\n");
    let request_line = lines.next()?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next()?.to_string();
    let target = request_parts.next()?.to_string();

    let headers: Vec<_> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect();

    let body_wire = &raw[header_end..];
    let body = header_lookup(&headers, "transfer-encoding")
        .filter(|v| v.to_ascii_lowercase().contains("chunked"))
        .and_then(|_| decode_chunked_body(body_wire))
        .or_else(|| {
            header_lookup(&headers, "content-length")
                .and_then(|v| v.parse::<usize>().ok())
                .and_then(|len| body_wire.get(..len).map(<[u8]>::to_vec))
        })
        .unwrap_or_else(|| body_wire.to_vec());

    Some(RecordedHttpRequest {
        method,
        target,
        headers,
        body,
    })
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn header_value<'a>(header_block: &'a str, name: &str) -> Option<&'a str> {
    header_block
        .split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .find(|(k, _)| k.trim().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
}

fn header_lookup<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn decode_chunked_body(wire: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut pos = 0usize;

    loop {
        let line_end = find_crlf(wire.get(pos..)?)?;
        let size_line = std::str::from_utf8(wire.get(pos..pos + line_end)?).ok()?;
        let size_hex = size_line.split(';').next()?.trim();
        let size = usize::from_str_radix(size_hex, 16).ok()?;
        pos = pos.checked_add(line_end)?.checked_add(2)?;

        if wire.len() < pos.checked_add(size)?.checked_add(2)? {
            return None;
        }
        if size == 0 {
            return Some(out);
        }

        out.extend_from_slice(wire.get(pos..pos + size)?);
        pos = pos.checked_add(size)?;
        if wire.get(pos..pos + 2)? != b"\r\n" {
            return None;
        }
        pos = pos.checked_add(2)?;
    }
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|window| window == b"\r\n")
}

struct TestDnsResolver {
    name: String,
    ip: Ipv4Addr,
}

impl TestDnsResolver {
    fn new(name: &str, ip: Ipv4Addr) -> Self {
        Self {
            name: name.trim_end_matches('.').to_ascii_lowercase(),
            ip,
        }
    }

    fn response(&self, query: &[u8]) -> Option<Vec<u8>> {
        let (qname, question_end, qtype) = parse_dns_question(query)?;
        if qname != self.name {
            return None;
        }

        let mut response = Vec::with_capacity(question_end + 16);
        response.extend_from_slice(&query[0..2]);
        response.extend_from_slice(&[0x81, 0x80]); // response, recursion available, no error
        response.extend_from_slice(&[0x00, 0x01]); // one question
        response.extend_from_slice(if qtype == 1 {
            &[0x00, 0x01]
        } else {
            &[0x00, 0x00]
        });
        response.extend_from_slice(&[0x00, 0x00]); // authority
        response.extend_from_slice(&[0x00, 0x00]); // additional
        response.extend_from_slice(&query[12..question_end]);

        if qtype == 1 {
            response.extend_from_slice(&[0xC0, 0x0C]); // pointer to qname
            response.extend_from_slice(&[0x00, 0x01]); // A
            response.extend_from_slice(&[0x00, 0x01]); // IN
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&[0x00, 0x04]);
            response.extend_from_slice(&self.ip.octets());
        }

        Some(response)
    }
}

impl amla_interceptor::DnsInterceptor for TestDnsResolver {
    fn intercept<'a>(
        &'a self,
        query_payload: &'a [u8],
        _original_dest: SocketAddr,
        _guest_addr: SocketAddr,
        response_limit: amla_interceptor::DnsResponseLimit,
    ) -> Result<amla_interceptor::DnsAction<'a>, amla_interceptor::DnsActionError> {
        self.response(query_payload).map_or_else(
            || Ok(amla_interceptor::DnsAction::Pass),
            |response| amla_interceptor::DnsAction::respond(response_limit, response),
        )
    }
}

fn parse_dns_question(query: &[u8]) -> Option<(String, usize, u16)> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }

    let mut pos = 12usize;
    let mut labels = Vec::new();
    loop {
        let len = usize::from(*query.get(pos)?);
        pos += 1;
        if len == 0 {
            break;
        }
        let label = query.get(pos..pos.checked_add(len)?)?;
        labels.push(std::str::from_utf8(label).ok()?.to_ascii_lowercase());
        pos += len;
    }

    let qtype = u16::from_be_bytes([*query.get(pos)?, *query.get(pos + 1)?]);
    let question_end = pos.checked_add(4)?;
    if question_end > query.len() {
        return None;
    }
    Some((labels.join("."), question_end, qtype))
}

fn with_mitm_dns<P, D>(
    backend: UserNetBackend<P, D>,
    host_ip: Ipv4Addr,
) -> UserNetBackend<P, TestDnsResolver>
where
    P: amla_usernet::interceptor::TcpConnectionPolicy,
    D: amla_usernet::interceptor::DnsInterceptor,
{
    backend.with_dns_interceptor(TestDnsResolver::new(MITM_TEST_HOST, host_ip))
}

fn unrestricted_usernet_config() -> UserNetConfig {
    UserNetConfig::try_default()
        .expect("host DNS config")
        .with_unrestricted_egress()
}

/// Build host-facing TLS config that trusts our test CA.
fn host_tls_config(ca: &CertificateAuthority) -> rustls::ClientConfig {
    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(ca.ca_cert_der().clone())
        .expect("add CA cert to root store");
    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

/// Boot a VM with a net backend and return test stdout.
async fn boot_network_vm<P, D>(usernet: UserNetBackend<P, D>, test_url: &str) -> String
where
    P: amla_usernet::interceptor::TcpConnectionPolicy,
    D: amla_usernet::interceptor::DnsInterceptor,
{
    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC))
        .try_cmdline_extra(format!("net_test_url={test_url} net_no_verify=1"))
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

    drop(vm);
    let serial = common::drainconsole(&mut console);
    println!("=== Console output ===");
    println!("{serial}");
    println!("=== End console output ===");

    assert!(
        start.elapsed() < timeout,
        "Test timed out after {} seconds",
        timeout.as_secs()
    );

    serial
}

// =============================================================================
// Handler Implementations
// =============================================================================

/// Extract the request path as a `&str` for logging/assertions.
fn req_path(req: &HttpRequestHeaders) -> &str {
    req.uri
        .path_and_query()
        .map_or_else(|| req.uri.path(), http::uri::PathAndQuery::as_str)
}

/// Handler that blocks ALL requests with a given HTTP status code.
struct BlockingHandler {
    status_code: StatusCode,
    events: Mutex<Vec<String>>,
}

impl BlockingHandler {
    fn new(status_code: u16) -> Self {
        Self {
            status_code: StatusCode::from_u16(status_code).expect("valid HTTP status code"),
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl HttpMitmHandler for BlockingHandler {
    async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
        let event = format!(
            "blocked:{} {} host={}",
            req.method,
            req_path(req),
            req.hostname
        );
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
        MitmAction::block_status(self.status_code)
    }
}

/// Handler that records events and injects a custom header into requests.
struct HeaderInjectingHandler {
    header_name: HeaderName,
    header_value: HeaderValue,
    events: Mutex<Vec<String>>,
}

impl HeaderInjectingHandler {
    const fn new(name: &'static str, value: &'static str) -> Self {
        Self {
            header_name: HeaderName::from_static(name),
            header_value: HeaderValue::from_static(value),
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }
}

impl HttpMitmHandler for HeaderInjectingHandler {
    async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
        req.headers
            .insert(self.header_name.clone(), self.header_value.clone());
        let event = format!(
            "injected:{}={} for {} {} host={}",
            self.header_name.as_str(),
            self.header_value.to_str().unwrap_or(""),
            req.method,
            req_path(req),
            req.hostname
        );
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
        MitmAction::Forward
    }

    async fn on_response_headers(
        &self,
        req: &HttpRequestHeaders,
        resp: &mut HttpResponseHeaders,
    ) -> MitmAction {
        let event = format!(
            "response:{} for {} {}",
            resp.status.as_u16(),
            req.method,
            req.hostname
        );
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
        MitmAction::Forward
    }
}

/// Handler that records events (forwarding everything through).
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
    async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
        let event = format!(
            "request:{} {} host={}",
            req.method,
            req_path(req),
            req.hostname
        );
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
        MitmAction::Forward
    }

    async fn on_response_headers(
        &self,
        req: &HttpRequestHeaders,
        resp: &mut HttpResponseHeaders,
    ) -> MitmAction {
        let event = format!(
            "response:{} for {} {}",
            resp.status.as_u16(),
            req.method,
            req.hostname
        );
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
        MitmAction::Forward
    }
}

/// Handler that observes and mutates both request and response data paths.
struct FullDuplexMutatingHandler {
    events: Mutex<Vec<String>>,
}

impl FullDuplexMutatingHandler {
    const fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    fn push_event(&self, event: String) {
        println!("MITM: {event}");
        self.events.lock().unwrap().push(event);
    }
}

impl HttpMitmHandler for FullDuplexMutatingHandler {
    async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
        self.push_event(format!(
            "request_headers:{} {} host={}",
            req.method,
            req_path(req),
            req.hostname
        ));
        req.uri = Uri::from_static("/mutated?via=mitm");
        req.headers.insert(
            HeaderName::from_static("x-mitm-request"),
            HeaderValue::from_static("tx-injected"),
        );
        req.headers.remove("x-guest-remove");
        MitmAction::Forward
    }

    async fn on_request_chunk(&self, _req: &HttpRequestHeaders, chunk: &mut Bytes) {
        let original = String::from_utf8_lossy(chunk).to_string();
        self.push_event(format!("request_chunk:{original}"));
        let rewritten = original.replace("guest-secret", "mitm-redacted");
        *chunk = Bytes::from(format!("{rewritten}|tx-added"));
    }

    async fn on_response_headers(
        &self,
        req: &HttpRequestHeaders,
        resp: &mut HttpResponseHeaders,
    ) -> MitmAction {
        self.push_event(format!(
            "response_headers:{} for {} {}",
            resp.status.as_u16(),
            req.method,
            req.hostname
        ));
        resp.headers.insert(
            HeaderName::from_static("x-mitm-response"),
            HeaderValue::from_static("rx-injected"),
        );
        resp.headers.insert(
            HeaderName::from_static("x-origin-response"),
            HeaderValue::from_static("mitm-rewritten"),
        );
        MitmAction::Forward
    }

    async fn on_response_chunk(&self, _req: &HttpRequestHeaders, chunk: &mut Bytes) {
        let original = String::from_utf8_lossy(chunk).to_string();
        self.push_event(format!("response_chunk:{original}"));
        let rewritten = original.replace("origin-secret", "rx-redacted");
        *chunk = Bytes::from(format!("{rewritten}|rx-chunk-added"));
    }

    async fn on_response_end(&self, _req: &HttpRequestHeaders, trailing: &mut BytesMut) {
        self.push_event("response_end".to_string());
        trailing.extend_from_slice(b"|rx-end-added");
    }

    async fn on_complete(
        &self,
        _req: &HttpRequestHeaders,
        status: StatusCode,
        outcome: ResponseOutcome,
    ) {
        self.push_event(format!("complete:{}:{outcome:?}", status.as_u16()));
    }
}

// =============================================================================
// Tests
// =============================================================================

/// MITM request blocking: handler blocks ALL requests with 403.
///
/// The guest fetches from an echo server through the MITM proxy. The proxy
/// intercepts the TLS connection, sees the HTTP request, and returns a
/// synthetic 403 without ever contacting the echo server.
///
/// Guest side: `FETCH:PASS` (got a response) but no `ECHO_RESPONSE:OK` (blocked).
/// Host side: handler events confirm the request was intercepted and blocked.
#[tokio::test(flavor = "multi_thread")]
async fn test_mitm_request_blocking() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: MITM Request Blocking (VMM porcelain) ===");
    println!("Host IP: {host_ip}");

    // CA + origin probe. The listener must stay open while the guest runs so
    // the test can catch regressions that contact the origin before blocking.
    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));
    let (origin_handle, server_port, origin_accepts, origin_stop) =
        start_uncontacted_origin_probe(host_ip);
    println!("Origin probe listening on {host_ip}:{server_port}");

    // Blocking handler: returns 403 for every request
    let handler = Arc::new(BlockingHandler::new(403));

    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let usernet = with_mitm_dns(
        UserNetBackend::try_new_with_tcp_policy(UserNetConfig::try_default().unwrap(), interceptor)
            .unwrap(),
        host_ip,
    );

    let test_url = format!("https://{MITM_TEST_HOST}:{server_port}/blocked");
    let serial = boot_network_vm(usernet, &test_url).await;

    // --- Guest-side assertions ---
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    // The guest should have received a response (the 403 from MITM)
    common::assert_serial(&serial, "FETCH:PASS", "Guest did not receive any response");
    // The echo server response should NOT have reached the guest
    assert!(
        !serial.contains("ECHO_RESPONSE:OK"),
        "Echo server response should have been blocked by MITM.\nSerial output:\n{serial}",
    );

    // --- Host-side MITM assertions ---
    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }

    assert!(
        events.iter().any(|e| e.contains("blocked:GET /blocked")),
        "MITM handler should have blocked GET /blocked.\nEvents: {events:?}"
    );
    assert_eq!(
        origin_accepts.load(Ordering::Acquire),
        0,
        "request-header block should not contact the origin"
    );

    println!("\nMITM request blocking test PASSED (VMM porcelain)");

    origin_stop.store(true, Ordering::Release);
    drop(origin_handle.join());
}

/// MITM SNI bypass: traffic on unintercepted ports flows through raw.
///
/// Two echo servers run on different ports (A and B). MITM policy only
/// intercepts port A. Guest fetches from port B, which bypasses the MITM
/// entirely. The raw TLS connection goes directly to the echo server.
///
/// Guest side: `FETCH:PASS` + `ECHO_RESPONSE:OK` (fetch succeeds without MITM).
/// Host side: handler events are empty (port B was not intercepted).
#[tokio::test(flavor = "multi_thread")]
async fn test_mitm_sni_bypass() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: MITM SNI Bypass (VMM porcelain) ===");
    println!("Host IP: {host_ip}");

    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));

    // Port A: intercepted by MITM (we start a server but guest won't fetch from it)
    let (_handle_a, port_a) = start_echo_server(&ca, host_ip, &host_ip.to_string());
    println!("Echo server A (intercepted) on {host_ip}:{port_a}");

    // Port B: NOT intercepted — guest fetches from here
    let (handle_b, port_b) = start_echo_server(&ca, host_ip, &host_ip.to_string());
    println!("Echo server B (bypassed) on {host_ip}:{port_b}");

    // Handler records events (should see none since port B is bypassed)
    let handler = Arc::new(RecordingHandler::new());

    // Only intercept port A — port B traffic flows through raw
    let policy = MitmPolicy::builder()
        .intercept_port(port_a)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let tcp_policy = amla_interceptor::NetworkSecurityBuilder::new()
        .tcp_policy(interceptor)
        .allow_direct_tcp()
        .build_tcp_policy();
    let usernet =
        UserNetBackend::try_new_with_tcp_policy(unrestricted_usernet_config(), tcp_policy).unwrap();

    // Guest fetches from port B (NOT intercepted)
    let test_url = format!("https://{host_ip}:{port_b}/bypass-test");
    let serial = boot_network_vm(usernet, &test_url).await;

    // --- Guest-side assertions ---
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    common::assert_serial(
        &serial,
        "FETCH:PASS",
        "Guest fetch from bypassed port failed",
    );
    common::assert_serial(
        &serial,
        "ECHO_RESPONSE:OK",
        "Echo server response did not reach guest through bypass",
    );

    // --- Host-side MITM assertions ---
    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }

    assert!(
        events.is_empty(),
        "MITM handler should not see any events for bypassed port.\nEvents: {events:?}"
    );

    println!("\nMITM SNI bypass test PASSED (VMM porcelain)");

    drop(handle_b.join());
}

/// MITM header injection: handler injects a custom header into requests.
///
/// The handler adds `X-Amla-Test: injected` to every request before forwarding
/// to the echo server. The echo server responds with `ECHO_RESPONSE:OK`
/// regardless. Verification is host-side: handler events confirm the injection.
#[tokio::test(flavor = "multi_thread")]
async fn test_mitm_header_injection() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: MITM Header Injection (VMM porcelain) ===");
    println!("Host IP: {host_ip}");

    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));
    let (server_handle, server_port) = start_echo_server(&ca, host_ip, MITM_TEST_HOST);
    println!("Echo server listening on {host_ip}:{server_port}");

    // Handler injects X-Amla-Test header
    let handler = Arc::new(HeaderInjectingHandler::new("x-amla-test", "injected"));

    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let usernet = with_mitm_dns(
        UserNetBackend::try_new_with_tcp_policy(unrestricted_usernet_config(), interceptor)
            .unwrap(),
        host_ip,
    );

    let test_url = format!("https://{MITM_TEST_HOST}:{server_port}/inject-test");
    let serial = boot_network_vm(usernet, &test_url).await;

    // --- Guest-side assertions ---
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    common::assert_serial(
        &serial,
        "FETCH:PASS",
        "Guest HTTPS fetch through MITM failed",
    );
    common::assert_serial(
        &serial,
        "ECHO_RESPONSE:OK",
        "Echo server response did not reach guest through MITM",
    );

    // --- Host-side MITM assertions ---
    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }

    assert!(
        events
            .iter()
            .any(|e| e.contains("injected:x-amla-test=injected")),
        "MITM handler should have recorded header injection.\nEvents: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("response:200")),
        "MITM handler should see 200 response from echo server.\nEvents: {events:?}"
    );

    println!("\nMITM header injection test PASSED (VMM porcelain)");

    drop(server_handle.join());
}

/// Full-duplex MITM inspection: guest request headers/body are observed and
/// mutated before reaching the origin, and origin response headers/body are
/// observed and mutated before reaching the guest.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn test_mitm_full_duplex_observe_and_mutate() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: MITM Full-Duplex Observe/Mutate ===");
    println!("Host IP: {host_ip}");

    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));
    let (server_handle, server_port, origin_request) =
        start_inspecting_https_server(&ca, host_ip, MITM_TEST_HOST);
    println!("Inspecting origin listening on {host_ip}:{server_port}");

    let handler = Arc::new(FullDuplexMutatingHandler::new());
    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let usernet = with_mitm_dns(
        UserNetBackend::try_new_with_tcp_policy(unrestricted_usernet_config(), interceptor)
            .unwrap(),
        host_ip,
    );

    let image = common::rootfs_handle();
    let pools = common::net_pools();
    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
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
    let test_url = format!("https://{MITM_TEST_HOST}:{server_port}/original?from=guest");

    let (_vm, guest_stdout) = vm
        .run(async move |vm| {
            let vm = vm.start();

            let setup = vm
                .exec(["/bin/amla-guest", "test-network"])
                .await
                .expect("start network setup");
            let setup_out = tokio::time::timeout(timeout, common::collect_output(setup))
                .await
                .expect("network setup timed out");
            assert_eq!(
                setup_out.exit_code,
                0,
                "network setup failed: {}",
                setup_out.stderr_str()
            );

            let fetch = vm
                .exec([
                    "/bin/amla-guest",
                    "https-get",
                    &test_url,
                    "--method",
                    "POST",
                    "--header",
                    "x-guest-header: visible",
                    "--header",
                    "x-guest-remove: delete-me",
                    "--body",
                    FULL_DUPLEX_GUEST_BODY,
                ])
                .await
                .expect("start https_get");
            let fetch_out = tokio::time::timeout(timeout, common::collect_output(fetch))
                .await
                .expect("https_get timed out");
            let stdout = fetch_out.stdout_str().to_string();
            let stderr = fetch_out.stderr_str();
            println!("https_get stdout: {stdout}");
            println!("https_get stderr: {stderr}");
            assert_eq!(
                fetch_out.exit_code, 0,
                "https_get failed (exit {}).\nstderr: {stderr}",
                fetch_out.exit_code
            );
            stdout
        })
        .await
        .expect("run VM");

    let guest_stdout_lower = guest_stdout.to_ascii_lowercase();
    assert!(
        guest_stdout_lower.contains("x-mitm-response: rx-injected"),
        "guest must receive MITM-injected response header.\nstdout: {guest_stdout}",
    );
    assert!(
        guest_stdout_lower.contains("x-origin-response: mitm-rewritten"),
        "guest must receive MITM-rewritten response header.\nstdout: {guest_stdout}",
    );
    assert!(
        guest_stdout.contains("origin-body: rx-redacted"),
        "guest must receive MITM-mutated response body.\nstdout: {guest_stdout}",
    );
    assert!(
        guest_stdout.contains("rx-chunk-added") && guest_stdout.contains("rx-end-added"),
        "guest must receive response chunk and end mutations.\nstdout: {guest_stdout}",
    );
    assert!(
        !guest_stdout.contains("origin-secret"),
        "guest must not receive the unmodified origin secret.\nstdout: {guest_stdout}",
    );

    let observed_origin = origin_request
        .lock()
        .unwrap()
        .clone()
        .expect("origin should have received a request");
    assert_eq!(observed_origin.method, "POST");
    assert_eq!(observed_origin.target, "/mutated?via=mitm");
    assert_eq!(observed_origin.header("x-guest-header"), Some("visible"));
    assert_eq!(
        observed_origin.header("x-mitm-request"),
        Some("tx-injected")
    );
    assert!(
        observed_origin.header("x-guest-remove").is_none(),
        "origin must not see handler-removed guest header.\nrequest: {observed_origin:?}",
    );

    let origin_body = observed_origin.body_text();
    assert!(
        origin_body.contains("guest-visible"),
        "origin must receive the non-sensitive request body prefix.\nbody: {origin_body}",
    );
    assert!(
        origin_body.contains("mitm-redacted") && origin_body.contains("tx-added"),
        "origin must receive MITM-mutated request body.\nbody: {origin_body}",
    );
    assert!(
        !origin_body.contains("guest-secret"),
        "origin must not receive the original guest secret.\nbody: {origin_body}",
    );

    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }
    assert!(
        events
            .iter()
            .any(|e| e.contains("request_headers:POST /original?from=guest")),
        "MITM should observe original request headers before mutation.\nEvents: {events:?}",
    );
    assert!(
        events.iter().any(|e| e.contains(FULL_DUPLEX_GUEST_BODY)),
        "MITM should observe original request body bytes.\nEvents: {events:?}",
    );
    assert!(
        events
            .iter()
            .any(|e| e.contains("response_chunk:origin-body: origin-secret")),
        "MITM should observe original response body bytes.\nEvents: {events:?}",
    );
    assert!(
        events.iter().any(|e| e == "response_end")
            && events.iter().any(|e| e == "complete:200:Completed"),
        "MITM should observe response end and completion.\nEvents: {events:?}",
    );

    println!("\nMITM full-duplex observe/mutate test PASSED");

    drop(server_handle.join());
}

/// Guest-side CA validation through MITM: push a CA cert to the guest via
/// exec stdin, then fetch through the MITM proxy with cert validation enabled.
///
/// Unlike other MITM tests that use `net_no_verify=1`, this test exercises the
/// full TLS trust chain: guest validates the MITM-generated leaf cert against
/// a CA cert that was delivered out-of-band via `tee /tmp/ca.pem`.
#[tokio::test(flavor = "multi_thread")]
#[allow(clippy::too_many_lines)]
async fn test_mitm_guest_ca_validation() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: MITM Guest CA Validation ===");
    println!("Host IP: {host_ip}");

    // --- Setup: CA, echo server, MITM interceptor ---
    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));
    let (server_handle, server_port) = start_echo_server(&ca, host_ip, MITM_TEST_HOST);
    println!("Echo server listening on {host_ip}:{server_port}");

    let handler = Arc::new(RecordingHandler::new());

    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let usernet = with_mitm_dns(
        UserNetBackend::try_new_with_tcp_policy(unrestricted_usernet_config(), interceptor)
            .unwrap(),
        host_ip,
    );

    // --- Boot VM with network but NO net_no_verify ---
    let image = common::rootfs_handle();
    let pools = common::net_pools();

    let config = common::test_vm_config()
        .memory_mb(256)
        .pmem_root(image.size().as_u64())
        .net(NetConfig::default().mac(MAC));

    let vm = VirtualMachine::create(config).await.expect("create VM");
    let console = ConsoleStream::new();
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
    let ca_pem = ca.ca_cert_pem().to_string();
    let test_url = format!("https://{MITM_TEST_HOST}:{server_port}/ca-test");

    let (_vm, ()) = vm
        .run(async move |vm| {
            let vm = vm.start();
            // Step 1: Write CA cert to guest filesystem via stdin
            let write = vm
                .exec(["/bin/amla-guest", "tee", "/tmp/ca.pem"])
                .await
                .expect("start tee");
            write.write_stdin(&ca_pem).await.expect("write CA PEM");
            let write_out = tokio::time::timeout(timeout, common::collect_output(write))
                .await
                .expect("cat timed out");
            assert_eq!(
                write_out.exit_code, 0,
                "writing CA cert failed: {:?}",
                write_out.stderr
            );

            // Set guest clock — guest has no RTC and starts at epoch 0.
            // rustls rejects certificates whose notBefore is in the future.
            let date_cmd = vm
                .exec(["/bin/amla-guest", "date", "-s", "2025-01-01 00:00:00"])
                .await
                .expect("start date");
            let date_out = tokio::time::timeout(timeout, common::collect_output(date_cmd))
                .await
                .expect("date timed out");
            assert_eq!(date_out.exit_code, 0, "setting date failed");

            // Step 2: Fetch through MITM with correct CA — should succeed
            let fetch = vm
                .exec([
                    "/bin/amla-guest",
                    "https-get",
                    &test_url,
                    "--ca-cert",
                    "/tmp/ca.pem",
                ])
                .await
                .expect("start https_get");
            let fetch_out = tokio::time::timeout(timeout, common::collect_output(fetch))
                .await
                .expect("https_get timed out");

            let stdout = fetch_out.stdout_str();
            let stderr = fetch_out.stderr_str();
            println!("https_get stdout: {stdout}");
            println!("https_get stderr: {stderr}");
            println!("https_get exit code: {}", fetch_out.exit_code);

            assert_eq!(
                fetch_out.exit_code, 0,
                "https_get with CA validation failed (exit {}).\nstderr: {stderr}",
                fetch_out.exit_code
            );
            assert!(
                stdout.contains("ECHO_RESPONSE:OK"),
                "Expected ECHO_RESPONSE:OK in stdout.\nstdout: {stdout}\nstderr: {stderr}"
            );

            // Step 3: Negative control — fetch with WRONG CA cert should fail
            let wrong_ca = CertificateAuthority::new().expect("create wrong CA");
            let wrong_write = vm
                .exec(["/bin/amla-guest", "tee", "/tmp/wrong-ca.pem"])
                .await
                .expect("start tee (wrong CA)");
            wrong_write
                .write_stdin(wrong_ca.ca_cert_pem().as_bytes())
                .await
                .expect("write wrong CA PEM");
            let wrong_write_out =
                tokio::time::timeout(timeout, common::collect_output(wrong_write))
                    .await
                    .expect("cat (wrong CA) timed out");
            assert_eq!(wrong_write_out.exit_code, 0, "writing wrong CA cert failed");

            let bad_fetch = vm
                .exec([
                    "/bin/amla-guest",
                    "https-get",
                    &test_url,
                    "--ca-cert",
                    "/tmp/wrong-ca.pem",
                ])
                .await
                .expect("start https_get (wrong CA)");
            let bad_out = tokio::time::timeout(timeout, common::collect_output(bad_fetch))
                .await
                .expect("https_get (wrong CA) timed out");
            assert_ne!(
                bad_out.exit_code, 0,
                "https_get with WRONG CA cert should fail — cert validation not enforced"
            );
        })
        .await
        .expect("run VM");

    // --- Host-side MITM assertions ---
    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }

    assert!(
        events.iter().any(|e| e.contains("GET /ca-test")),
        "MITM handler should see decrypted GET /ca-test.\nEvents: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("response:200")),
        "MITM handler should see 200 response.\nEvents: {events:?}"
    );

    println!("\nMITM guest CA validation test PASSED");

    drop(server_handle.join());
}

/// Full HTTPS MITM intercept: guest fetches from a local echo server through
/// the usernet NAT, the MITM proxy decrypts, records, and re-encrypts.
#[tokio::test(flavor = "multi_thread")]
async fn test_https_mitm_intercept() {
    drop(env_logger::builder().is_test(true).try_init());

    if let Some(reason) = common::skip_checks() {
        println!("Skipping: {reason}");
        return;
    }

    let host_ip = common::get_host_ip();
    println!("\n=== Test: HTTPS MITM Intercept (VMM porcelain) ===");
    println!("Host IP: {host_ip}");

    let ca = Arc::new(CertificateAuthority::new().expect("create CA"));
    let (server_handle, server_port) = start_echo_server(&ca, host_ip, MITM_TEST_HOST);
    println!("Echo server listening on {host_ip}:{server_port}");

    let handler = Arc::new(RecordingHandler::new());

    let policy = MitmPolicy::builder()
        .intercept_port(server_port)
        .build()
        .unwrap();
    let interceptor = Arc::new(TlsMitmInterceptor::with_host_tls_config(
        Arc::clone(&ca),
        policy,
        Arc::clone(&handler),
        host_tls_config(&ca),
    ));

    let usernet = with_mitm_dns(
        UserNetBackend::try_new_with_tcp_policy(unrestricted_usernet_config(), interceptor)
            .unwrap(),
        host_ip,
    );

    let test_url = format!("https://{MITM_TEST_HOST}:{server_port}/test");
    let serial = boot_network_vm(usernet, &test_url).await;

    // --- Guest-side assertions ---
    common::assert_serial(&serial, "NETIF:PASS", "Network interface not detected");
    common::assert_serial(&serial, "FETCH:PASS", "Guest HTTPS fetch failed");
    common::assert_serial(
        &serial,
        "ECHO_RESPONSE:OK",
        "Echo server response did not reach guest",
    );

    // --- Host-side MITM assertions ---
    let events = handler.events();
    println!("\n=== MITM Events ({} total) ===", events.len());
    for event in &events {
        println!("  {event}");
    }

    assert!(
        events.iter().any(|e| e.contains("GET /test")),
        "MITM handler should see decrypted GET /test.\nEvents: {events:?}"
    );
    assert!(
        events.iter().any(|e| e.contains("response:200")),
        "MITM handler should see 200 response.\nEvents: {events:?}"
    );

    println!("\nHTTPS MITM intercept test PASSED (VMM porcelain)");

    drop(server_handle.join());
}
