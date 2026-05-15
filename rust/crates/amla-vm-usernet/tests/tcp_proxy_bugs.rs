// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Regression tests for TCP proxy bugs.
//!
//! Originally this tested mio interest registration gaps. After the mio→tokio
//! migration, this validates that large payloads flow correctly through the
//! async per-connection task model.

// Test file — intentional casts, long integration test
#![allow(clippy::cast_possible_truncation, clippy::too_many_lines)]

mod common;

use std::io::{ErrorKind, IoSlice, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use amla_core::backends::NetBackend;
use amla_usernet::interceptor::{
    BoxFuture, HostConnector, LocalSocket, TcpConnectionPolicy, TcpFlow, TcpOpenAction,
    TrustedTcpInterceptor,
};
use amla_usernet::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, EthernetHeader, IP_PROTO_TCP, Ipv4Header, TCP_ACK,
    TCP_HEADER_LEN, TCP_SYN, TcpHeader,
};
use amla_usernet::{DEFAULT_GATEWAY, UserNetBackend, UserNetConfig};
use tokio::io::{AsyncWriteExt, DuplexStream};

use common::{TcpGuest, drive_backend, parse_tcp_response, recv_into};

// =============================================================================
// Tests
// =============================================================================

/// Documentation-range DNS placeholder; these TCP tests never send DNS.
const UNUSED_TEST_HOST_DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

fn tcp_test_backend() -> UserNetBackend {
    let config = UserNetConfig::default().with_host_dns_server(UNUSED_TEST_HOST_DNS);
    UserNetBackend::try_new(config).unwrap()
}

fn direct_tcp_test_backend() -> UserNetBackend {
    let config = UserNetConfig::default()
        .with_host_dns_server(UNUSED_TEST_HOST_DNS)
        .with_unrestricted_egress();
    UserNetBackend::try_new(config).unwrap()
}

fn tcp_test_backend_with_policy<P>(policy: P) -> UserNetBackend<P>
where
    P: TcpConnectionPolicy,
{
    let config = UserNetConfig::default().with_host_dns_server(UNUSED_TEST_HOST_DNS);
    UserNetBackend::try_new_with_tcp_policy(config, policy).unwrap()
}

fn complete_guest_handshake<P>(
    backend: &UserNetBackend<P>,
    guest_tcp: &mut TcpGuest,
    timeout: Duration,
) -> u32
where
    P: TcpConnectionPolicy,
{
    let syn = guest_tcp.build_syn();
    backend.send(&[IoSlice::new(&syn)]).unwrap();

    let start = Instant::now();
    loop {
        let packets = drive_backend(backend);
        for pkt in &packets {
            if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
                && resp.flags & TCP_SYN != 0
                && resp.flags & TCP_ACK != 0
            {
                let next_seq = resp.seq.wrapping_add(1);
                guest_tcp.ack = next_seq;
                let ack = guest_tcp.build_ack();
                backend.send(&[IoSlice::new(&ack)]).unwrap();
                return next_seq;
            }
        }
        assert!(start.elapsed() < timeout, "timed out waiting for SYN-ACK");
        thread::sleep(Duration::from_millis(1));
    }
}

fn accept_server<P>(
    backend: &UserNetBackend<P>,
    listener: &TcpListener,
    timeout: Duration,
) -> TcpStream
where
    P: TcpConnectionPolicy,
{
    listener.set_nonblocking(true).unwrap();
    let start = Instant::now();
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                return stream;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                drive_backend(backend);
                assert!(start.elapsed() < timeout, "timed out waiting for accept");
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept: {e}"),
        }
    }
}

fn append_tcp_payload(received: &mut Vec<u8>, next_seq: &mut u32, seq: u32, payload: &[u8]) {
    if payload.is_empty() {
        return;
    }
    let expected = *next_seq;
    let end = seq.wrapping_add(payload.len() as u32);
    if seq == expected {
        received.extend_from_slice(payload);
        *next_seq = end;
    } else if seq < expected && end > expected {
        let offset = (expected - seq) as usize;
        received.extend_from_slice(&payload[offset..]);
        *next_seq = end;
    }
}

struct ParsedTcpPacket {
    src_port: u16,
    dst_port: u16,
    flags: u8,
    seq: u32,
    payload: Vec<u8>,
}

fn parse_tcp_packet(packet: &[u8]) -> Option<ParsedTcpPacket> {
    let eth = EthernetHeader::parse(packet)?;
    if eth.ether_type != ETH_TYPE_IPV4 {
        return None;
    }
    let ip = Ipv4Header::parse(packet.get(ETH_HEADER_LEN..)?)?;
    if ip.protocol != IP_PROTO_TCP {
        return None;
    }
    let tcp_start = ETH_HEADER_LEN + ip.header_len();
    if tcp_start + TCP_HEADER_LEN > packet.len() {
        return None;
    }
    let tcp = TcpHeader::parse(packet.get(tcp_start..)?)?;
    let payload_start = tcp_start + tcp.header_len();
    let payload_end = (ETH_HEADER_LEN + ip.total_length as usize).min(packet.len());
    let payload = packet
        .get(payload_start..payload_end)
        .unwrap_or_default()
        .to_vec();
    Some(ParsedTcpPacket {
        src_port: tcp.src_port,
        dst_port: tcp.dst_port,
        flags: tcp.flags,
        seq: tcp.seq_num,
        payload,
    })
}

fn drive_guest_receive<P>(
    backend: &UserNetBackend<P>,
    guest_tcp: &mut TcpGuest,
    next_seq: &mut u32,
    received: &mut Vec<u8>,
    ack: bool,
) where
    P: TcpConnectionPolicy,
{
    let packets = drive_backend(backend);
    let mut should_ack = false;
    for pkt in &packets {
        if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
            && !resp.payload.is_empty()
        {
            let before = *next_seq;
            append_tcp_payload(received, next_seq, resp.seq, &resp.payload);
            should_ack |= *next_seq != before;
        }
    }
    if ack && should_ack {
        guest_tcp.ack = *next_seq;
        let ack_pkt = guest_tcp.build_ack();
        backend.send(&[IoSlice::new(&ack_pkt)]).unwrap();
    }
}

fn wait_for_inbound_syn<P>(
    backend: &UserNetBackend<P>,
    guest_port: u16,
    timeout: Duration,
) -> ParsedTcpPacket
where
    P: TcpConnectionPolicy,
{
    let start = Instant::now();
    loop {
        let packets = drive_backend(backend);
        for pkt in &packets {
            if let Some(parsed) = parse_tcp_packet(pkt)
                && parsed.dst_port == guest_port
                && parsed.flags & TCP_SYN != 0
                && parsed.flags & TCP_ACK == 0
            {
                return parsed;
            }
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for inbound SYN"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn complete_inbound_handshake<P>(
    backend: &UserNetBackend<P>,
    guest_port: u16,
    timeout: Duration,
) -> (DuplexStream, TcpGuest, u32)
where
    P: TcpConnectionPolicy,
{
    let (host_stream, guest_stream) = tokio::io::duplex(64 * 1024);
    backend
        .accept_inbound(Box::new(guest_stream), guest_port)
        .unwrap();

    let syn = wait_for_inbound_syn(backend, guest_port, timeout);
    let next_seq = syn.seq.wrapping_add(1);
    let mut guest_tcp = TcpGuest {
        seq: 7000,
        ack: next_seq,
        guest_port,
        remote_port: syn.src_port,
        remote_ip: DEFAULT_GATEWAY,
    };
    let syn_ack = guest_tcp.build_packet(TCP_SYN | TCP_ACK, &[]);
    guest_tcp.seq = guest_tcp.seq.wrapping_add(1);
    backend.send(&[IoSlice::new(&syn_ack)]).unwrap();

    let start = Instant::now();
    loop {
        let packets = drive_backend(backend);
        for pkt in &packets {
            if let Some(parsed) = parse_tcp_packet(pkt)
                && parsed.src_port == guest_tcp.remote_port
                && parsed.dst_port == guest_port
                && parsed.flags == TCP_ACK
                && parsed.seq == next_seq
                && parsed.payload.is_empty()
            {
                return (host_stream, guest_tcp, next_seq);
            }
        }
        assert!(
            start.elapsed() < timeout,
            "timed out waiting for inbound handshake ACK"
        );
        thread::sleep(Duration::from_millis(1));
    }
}

fn collect_guest_payload<P>(
    backend: &UserNetBackend<P>,
    guest_tcp: &mut TcpGuest,
    next_seq: &mut u32,
    total: usize,
    timeout: Duration,
) -> Vec<u8>
where
    P: TcpConnectionPolicy,
{
    let mut received = Vec::with_capacity(total);
    let start = Instant::now();
    while received.len() < total {
        drive_guest_receive(backend, guest_tcp, next_seq, &mut received, true);
        assert!(
            start.elapsed() < timeout,
            "timed out receiving guest-bound payload: got {} of {total}",
            received.len()
        );
        thread::sleep(Duration::from_millis(1));
    }
    received
}

struct WritePayloadService {
    payload: Arc<Vec<u8>>,
}

impl amla_usernet::interceptor::LocalServiceHandler for WritePayloadService {
    fn handle(self: Box<Self>, mut socket: LocalSocket) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            socket.write_all(self.payload.as_slice()).await.unwrap();
            socket.shutdown().await.unwrap();
        })
    }
}

struct WritePayloadInterceptor {
    payload: Arc<Vec<u8>>,
}

impl TrustedTcpInterceptor for WritePayloadInterceptor {
    fn run(
        self: Box<Self>,
        mut guest: LocalSocket,
        _flow: TcpFlow,
        _connector: HostConnector,
    ) -> BoxFuture<'static, ()> {
        Box::pin(async move {
            guest.write_all(self.payload.as_slice()).await.unwrap();
            guest.shutdown().await.unwrap();
        })
    }
}

#[derive(Clone, Copy)]
enum PayloadPolicyMode {
    LocalService,
    TrustedInterceptor,
}

struct PayloadPolicy {
    addr: SocketAddr,
    payload: Arc<Vec<u8>>,
    mode: PayloadPolicyMode,
}

impl TcpConnectionPolicy for PayloadPolicy {
    fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
        if flow.remote_addr != self.addr {
            return TcpOpenAction::NoOpinion;
        }
        match self.mode {
            PayloadPolicyMode::LocalService => {
                TcpOpenAction::LocalService(Box::new(WritePayloadService {
                    payload: Arc::clone(&self.payload),
                }))
            }
            PayloadPolicyMode::TrustedInterceptor => {
                TcpOpenAction::Intercept(Box::new(WritePayloadInterceptor {
                    payload: Arc::clone(&self.payload),
                }))
            }
        }
    }
}

/// Sends 128KB of data through the TCP proxy to exercise async buffering and
/// flow-control behavior across repeated guest packets.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn large_payload_arrives_at_host() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_port = listener.local_addr().unwrap().port();

    let backend = direct_tcp_test_backend();
    let timeout = Duration::from_secs(10);
    let mut guest_tcp = TcpGuest::new(Ipv4Addr::LOCALHOST, server_port);

    // TCP handshake: SYN
    let syn = guest_tcp.build_syn();
    backend.send(&[IoSlice::new(&syn)]).unwrap();

    // Wait for SYN-ACK
    let start = Instant::now();
    'syn_ack: loop {
        let packets = drive_backend(&backend);
        for pkt in &packets {
            if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
                && resp.flags & TCP_SYN != 0
                && resp.flags & TCP_ACK != 0
            {
                guest_tcp.ack = resp.seq.wrapping_add(1);
                break 'syn_ack;
            }
        }
        assert!(start.elapsed() < timeout, "timed out waiting for SYN-ACK");
        thread::sleep(Duration::from_millis(1));
    }

    // Complete handshake: ACK
    let ack = guest_tcp.build_ack();
    backend.send(&[IoSlice::new(&ack)]).unwrap();

    // Accept on server side
    listener.set_nonblocking(true).unwrap();
    let start = Instant::now();
    let mut server_stream = loop {
        match listener.accept() {
            Ok((s, _)) => break s,
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                drive_backend(&backend);
                assert!(start.elapsed() < timeout, "timed out waiting for accept");
                thread::sleep(Duration::from_millis(1));
            }
            Err(e) => panic!("accept: {e}"),
        }
    };
    server_stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    server_stream.set_nonblocking(false).unwrap();

    // Send 128KB in mss-sized chunks
    let total: usize = 128 * 1024;
    let mss: usize = 1400;
    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();

    let mut sent = 0;
    while sent < total {
        let end = (sent + mss).min(total);
        let chunk = &payload[sent..end];
        let pkt = guest_tcp.build_data(chunk);
        backend.send(&[IoSlice::new(&pkt)]).unwrap();
        sent = end;

        // ACK any data from proxy + drive event loop
        let packets = drive_backend(&backend);
        for pkt in &packets {
            if let Some(resp) = parse_tcp_response(pkt, guest_tcp.guest_port, guest_tcp.remote_port)
                && !resp.payload.is_empty()
            {
                guest_tcp.ack = resp.seq.wrapping_add(resp.payload.len() as u32);
            }
        }
    }

    // Read all data from server in a background thread (avoids blocking the event loop)
    let reader_handle = thread::spawn(move || {
        let mut received = Vec::new();
        let mut buf = [0u8; 16384];
        loop {
            match server_stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => received.extend_from_slice(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::TimedOut => break,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("server read: {e}"),
            }
            if received.len() >= total {
                break;
            }
        }
        received
    });

    // Drive the backend event loop until the reader finishes
    let poll_start = Instant::now();
    while !reader_handle.is_finished() {
        drive_backend(&backend);
        // ACK any data coming back from proxy
        let mut buf = [0u8; 2000];
        while let Ok(len) = recv_into(&backend, &mut buf) {
            if let Some(resp) =
                parse_tcp_response(&buf[..len], guest_tcp.guest_port, guest_tcp.remote_port)
                && !resp.payload.is_empty()
            {
                guest_tcp.ack = resp.seq.wrapping_add(resp.payload.len() as u32);
                let ack_pkt = guest_tcp.build_ack();
                backend.send(&[IoSlice::new(&ack_pkt)]).unwrap();
            }
        }
        assert!(
            poll_start.elapsed() < timeout,
            "timed out driving backend while server reads"
        );
        thread::sleep(Duration::from_millis(1));
    }

    let received = reader_handle.join().expect("reader thread panicked");
    assert_eq!(
        received.len(),
        total,
        "expected {total} bytes at server, got {}",
        received.len()
    );
    assert_eq!(
        received,
        payload,
        "data mismatch: first differing byte at position {}",
        received
            .iter()
            .zip(payload.iter())
            .position(|(a, b)| a != b)
            .unwrap_or(received.len())
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_large_payload_arrives_at_guest() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let timeout = Duration::from_secs(15);

    let backend = direct_tcp_test_backend();
    let mut guest_tcp = TcpGuest::new(Ipv4Addr::LOCALHOST, server_port);
    let mut next_seq = complete_guest_handshake(&backend, &mut guest_tcp, timeout);
    let mut server_stream = accept_server(&backend, &listener, timeout);

    let total = 1024 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i % 251) as u8).collect();
    let writer_payload = payload.clone();
    let writer = thread::spawn(move || {
        server_stream.write_all(&writer_payload).unwrap();
    });

    let received = collect_guest_payload(&backend, &mut guest_tcp, &mut next_seq, total, timeout);
    writer.join().expect("writer thread panicked");
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn host_payload_survives_slow_guest_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_port = listener.local_addr().unwrap().port();
    let timeout = Duration::from_secs(15);

    let backend = direct_tcp_test_backend();
    let mut guest_tcp = TcpGuest::new(Ipv4Addr::LOCALHOST, server_port);
    let mut next_seq = complete_guest_handshake(&backend, &mut guest_tcp, timeout);
    let mut server_stream = accept_server(&backend, &listener, timeout);

    let total = 768 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i % 239) as u8).collect();
    let writer_payload = payload.clone();
    let writer = thread::spawn(move || {
        server_stream.write_all(&writer_payload).unwrap();
    });

    let mut received = Vec::with_capacity(total);
    let slow_until = Instant::now() + Duration::from_millis(250);
    while Instant::now() < slow_until {
        drive_guest_receive(
            &backend,
            &mut guest_tcp,
            &mut next_seq,
            &mut received,
            false,
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        received.len() < total,
        "guest should not receive the full payload before ACKing"
    );

    guest_tcp.ack = next_seq;
    let ack_pkt = guest_tcp.build_ack();
    backend.send(&[IoSlice::new(&ack_pkt)]).unwrap();
    let start = Instant::now();
    while received.len() < total {
        drive_guest_receive(&backend, &mut guest_tcp, &mut next_seq, &mut received, true);
        assert!(
            start.elapsed() < timeout,
            "timed out after delayed ACK: got {} of {total}",
            received.len()
        );
        thread::sleep(Duration::from_millis(1));
    }

    writer.join().expect("writer thread panicked");
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_large_payload_arrives_at_guest() {
    let timeout = Duration::from_secs(15);
    let backend = tcp_test_backend();
    let (mut host_stream, mut guest_tcp, mut next_seq) =
        complete_inbound_handshake(&backend, 8080, timeout);

    let total = 1024 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i % 241) as u8).collect();
    let writer_payload = payload.clone();
    let writer = tokio::spawn(async move {
        host_stream.write_all(&writer_payload).await.unwrap();
    });

    let received = collect_guest_payload(&backend, &mut guest_tcp, &mut next_seq, total, timeout);
    writer.await.expect("writer task panicked");
    assert_eq!(received, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inbound_payload_survives_slow_guest_reads() {
    let timeout = Duration::from_secs(15);
    let backend = tcp_test_backend();
    let (mut host_stream, mut guest_tcp, mut next_seq) =
        complete_inbound_handshake(&backend, 8080, timeout);

    let total = 768 * 1024;
    let payload: Vec<u8> = (0..total).map(|i| (i % 223) as u8).collect();
    let writer_payload = payload.clone();
    let writer = tokio::spawn(async move {
        host_stream.write_all(&writer_payload).await.unwrap();
    });

    let mut received = Vec::with_capacity(total);
    let slow_until = Instant::now() + Duration::from_millis(250);
    while Instant::now() < slow_until {
        drive_guest_receive(
            &backend,
            &mut guest_tcp,
            &mut next_seq,
            &mut received,
            false,
        );
        thread::sleep(Duration::from_millis(1));
    }
    assert!(
        received.len() < total,
        "guest should not receive the full inbound payload before ACKing"
    );

    guest_tcp.ack = next_seq;
    let ack_pkt = guest_tcp.build_ack();
    backend.send(&[IoSlice::new(&ack_pkt)]).unwrap();
    let start = Instant::now();
    while received.len() < total {
        drive_guest_receive(&backend, &mut guest_tcp, &mut next_seq, &mut received, true);
        assert!(
            start.elapsed() < timeout,
            "timed out after delayed ACK: got {} of {total}",
            received.len()
        );
        thread::sleep(Duration::from_millis(1));
    }

    writer.await.expect("writer task panicked");
    assert_eq!(received, payload);
}

async fn policy_output_arrives_under_backpressure(mode: PayloadPolicyMode) {
    let total = match mode {
        PayloadPolicyMode::LocalService => 5 * 1024 * 1024,
        PayloadPolicyMode::TrustedInterceptor => 1024 * 1024,
    };
    let payload: Arc<Vec<u8>> = Arc::new((0..total).map(|i| (i % 233) as u8).collect());
    let (remote_ip, remote_port) = match mode {
        PayloadPolicyMode::LocalService => (DEFAULT_GATEWAY, 8080),
        PayloadPolicyMode::TrustedInterceptor => (Ipv4Addr::new(198, 51, 100, 7), 9443),
    };
    let addr = SocketAddr::new(IpAddr::V4(remote_ip), remote_port);
    let policy = Arc::new(PayloadPolicy {
        addr,
        payload: Arc::clone(&payload),
        mode,
    });
    let backend = tcp_test_backend_with_policy(policy);
    let timeout = Duration::from_secs(20);
    let mut guest_tcp = TcpGuest::new(remote_ip, remote_port);
    let mut next_seq = complete_guest_handshake(&backend, &mut guest_tcp, timeout);

    let received = collect_guest_payload(&backend, &mut guest_tcp, &mut next_seq, total, timeout);
    assert_eq!(received.as_slice(), payload.as_slice());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn local_service_output_is_backpressured_without_truncation() {
    policy_output_arrives_under_backpressure(PayloadPolicyMode::LocalService).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn trusted_interceptor_output_is_backpressured_without_truncation() {
    policy_output_arrives_under_backpressure(PayloadPolicyMode::TrustedInterceptor).await;
}
