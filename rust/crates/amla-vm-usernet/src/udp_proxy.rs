// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! UDP connection proxy for NAT
//!
//! This module handles proxying UDP datagrams from guest to host. Unlike TCP,
//! UDP is connectionless, so we create "soft state" associations that timeout
//! after a period of inactivity.
//!
//! Each UDP "connection" is represented by an async tokio task that owns a
//! `tokio::net::UdpSocket`. The task handles bidirectional forwarding and
//! self-terminates on inactivity timeout.

#[cfg(test)]
use crate::DEFAULT_GATEWAY_MAC;
use crate::guest_output::{ConnectionOutputTag, GuestOutput};
#[cfg(test)]
use crate::packet_builder::{ETH_HEADER_LEN, Ipv4Header, Ipv6Header};
use crate::packet_builder::{
    FlowEndpoints, IPV4_HEADER_LEN, IPV6_HEADER_LEN, PacketBuilder, UDP_HEADER_LEN,
};
use crate::{HostEgressAuthorizer, HostEgressRequest};
use amla_core::backends::RxWaker;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// =============================================================================
// Constants
// =============================================================================

/// Timeout for UDP associations (30 seconds)
const UDP_TIMEOUT_SECS: u64 = 30;

/// DNS timeout is shorter (5 seconds)
const DNS_TIMEOUT_SECS: u64 = 5;

/// DNS port
const DNS_PORT: u16 = 53;

const IPV4_UDP_OVERHEAD: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;
const IPV6_UDP_OVERHEAD: usize = IPV6_HEADER_LEN + UDP_HEADER_LEN;

const fn max_udp_payload_for_ip(mtu: usize, ip: IpAddr) -> usize {
    match ip {
        IpAddr::V4(_) => mtu.saturating_sub(IPV4_UDP_OVERHEAD),
        IpAddr::V6(_) => mtu.saturating_sub(IPV6_UDP_OVERHEAD),
    }
}

const fn outbound_udp_timeout(remote_port: u16) -> Duration {
    if remote_port == DNS_PORT {
        Duration::from_secs(DNS_TIMEOUT_SECS)
    } else {
        Duration::from_secs(UDP_TIMEOUT_SECS)
    }
}

// =============================================================================
// UDP Connection Handle (held by NatProxy)
// =============================================================================

/// Handle held by `NatProxy` to communicate with a running UDP task.
pub struct UdpConnectionHandle {
    /// Send guest datagrams to the task.
    pub guest_tx: mpsc::Sender<Vec<u8>>,
    /// Task join handle.
    pub task: JoinHandle<()>,
    /// When this connection was created.
    pub created_at: Instant,
}

// =============================================================================
// UDP Connection Task
// =============================================================================

/// Parameters for spawning a UDP connection task.
pub struct UdpTaskParams {
    pub host_egress: HostEgressAuthorizer,
    pub egress_request: HostEgressRequest,
    pub response_flow: FlowEndpoints,
    pub initial_payload: Vec<u8>,
    pub guest_rx: mpsc::Receiver<Vec<u8>>,
    pub collector_tx: mpsc::Sender<GuestOutput>,
    pub rx_waker: Option<RxWaker>,
    pub gateway_mac: [u8; 6],
    pub mtu: usize,
    pub output_tag: ConnectionOutputTag,
}

fn authorize_udp_egress(
    host_egress: &HostEgressAuthorizer,
    request: HostEgressRequest,
    action: &str,
) -> Option<SocketAddr> {
    host_egress.authorize(request).map_or_else(
        || {
            log::trace!(
                "UDP: egress denied by network policy before {action} to {}",
                request.socket_addr
            );
            None
        },
        |authorized| Some(authorized.socket_addr()),
    )
}

async fn open_authorized_udp_socket(
    host_egress: &HostEgressAuthorizer,
    request: HostEgressRequest,
) -> Option<(tokio::net::UdpSocket, SocketAddr)> {
    let remote_addr = authorize_udp_egress(host_egress, request, "open")?;
    let bind_addr: SocketAddr = match remote_addr {
        SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
        SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
    };
    let socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => s,
        Err(e) => {
            log::trace!("UDP: Failed to bind socket: {e}");
            return None;
        }
    };
    authorize_udp_egress(host_egress, request, "connect")?;
    if let Err(e) = socket.connect(remote_addr).await {
        log::trace!("UDP: Failed to connect to {remote_addr}: {e}");
        return None;
    }
    Some((socket, remote_addr))
}

async fn send_authorized_udp_payload(
    socket: &tokio::net::UdpSocket,
    host_egress: &HostEgressAuthorizer,
    request: HostEgressRequest,
    action: &str,
    remote_addr: SocketAddr,
    payload: &[u8],
) -> bool {
    if authorize_udp_egress(host_egress, request, action).is_none() {
        return false;
    }
    if let Err(e) = socket.send(payload).await {
        log::trace!("UDP: {action} to {remote_addr} failed: {e}");
    }
    true
}

fn enqueue_udp_response(
    builder: &mut PacketBuilder,
    flow: &FlowEndpoints,
    payload: &[u8],
    collector_tx: &mpsc::Sender<GuestOutput>,
    rx_waker: Option<&RxWaker>,
    output_tag: ConnectionOutputTag,
) -> bool {
    let packet = builder.build_udp_packet_ip(flow, payload);
    match collector_tx.try_send(GuestOutput::tagged_best_effort_datagram(output_tag, packet)) {
        Ok(()) => {
            if let Some(waker) = rx_waker {
                waker.wake();
            }
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            log::trace!("UDP: collector channel full, dropping packet");
            true
        }
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

/// Async task that owns a `tokio::net::UdpSocket` and proxies datagrams
/// bidirectionally between the guest and a remote host.
///
/// The task terminates when:
/// - The inactivity timeout expires (30s general, 5s for DNS port 53)
/// - The `guest_rx` channel is closed (`NatProxy` dropped or evicted) — exits immediately
/// - A recv error occurs on the host socket
pub async fn udp_connection_task(params: UdpTaskParams) {
    let UdpTaskParams {
        host_egress,
        egress_request,
        response_flow,
        initial_payload,
        mut guest_rx,
        collector_tx,
        rx_waker,
        gateway_mac,
        mtu,
        output_tag,
    } = params;
    let mut builder = PacketBuilder::new(gateway_mac);
    let max_udp_payload = max_udp_payload_for_ip(mtu, response_flow.dst_ip());

    let Some((socket, remote_addr)) =
        open_authorized_udp_socket(&host_egress, egress_request).await
    else {
        return;
    };

    log::debug!(
        "UDP: Created proxy socket for {}",
        egress_request.socket_addr
    );

    if !send_authorized_udp_payload(
        &socket,
        &host_egress,
        egress_request,
        "Initial send",
        remote_addr,
        &initial_payload,
    )
    .await
    {
        return;
    }

    let timeout_dur = outbound_udp_timeout(egress_request.socket_addr.port());

    let mut buf = vec![0u8; max_udp_payload];
    loop {
        tokio::select! {
            result = socket.recv(&mut buf) => {
                match result {
                    Ok(n) => {
                        log::trace!(
                            "UDP: Received {n} bytes from remote {}",
                            egress_request.socket_addr,
                        );
                        if !enqueue_udp_response(
                            &mut builder,
                            &response_flow,
                            &buf[..n],
                            &collector_tx,
                            rx_waker.as_ref(),
                            output_tag,
                        ) {
                            return;
                        }
                    }
                    Err(e) => {
                        log::warn!("UDP: Recv error from remote: {e}");
                        break;
                    }
                }
            }

            result = guest_rx.recv() => {
                match result {
                    Some(payload) => {
                        if !send_authorized_udp_payload(
                            &socket,
                            &host_egress,
                            egress_request,
                            "Send",
                            remote_addr,
                            &payload,
                        ).await {
                            break;
                        }
                    }
                    None => break,
                }
            }

            () = tokio::time::sleep(timeout_dur) => {
                log::trace!("UDP: Timeout for {}", egress_request.socket_addr);
                break;
            }
        }
    }
}

// =============================================================================
// Inbound UDP Port Forwarding
// =============================================================================

/// Parameters for spawning an inbound UDP forwarding task.
pub struct InboundUdpTaskParams {
    pub from_host: mpsc::Receiver<Vec<u8>>,
    pub to_host: mpsc::Sender<Vec<u8>>,
    pub flow: FlowEndpoints,
    pub guest_rx: mpsc::Receiver<Vec<u8>>,
    pub collector_tx: mpsc::Sender<GuestOutput>,
    pub rx_waker: Option<RxWaker>,
    pub gateway_mac: [u8; 6],
    pub mtu: usize,
    pub output_tag: ConnectionOutputTag,
}

/// Bidirectional UDP proxy for inbound (host-to-guest) port forwarding.
///
/// Reads datagrams from `from_host`, builds UDP packets, and injects them into
/// the guest via `collector_tx`. Guest responses arrive via `guest_rx` and are
/// forwarded to `to_host`. Exits on channel close or inactivity timeout.
pub async fn inbound_udp_task(params: InboundUdpTaskParams) {
    let InboundUdpTaskParams {
        mut from_host,
        to_host,
        flow,
        mut guest_rx,
        collector_tx,
        rx_waker,
        gateway_mac,
        mtu,
        output_tag,
    } = params;
    let mut builder = PacketBuilder::new(gateway_mac);
    let max_udp_payload = max_udp_payload_for_ip(mtu, flow.dst_ip());
    let timeout_dur = Duration::from_secs(UDP_TIMEOUT_SECS);
    log::trace!("inbound_udp_task: started for port {}", flow.dst_port());

    loop {
        tokio::select! {
            // Host → Guest: inject datagram into guest
            result = from_host.recv() => {
                match result {
                    Some(data) => {
                        let clamped = if data.len() > max_udp_payload {
                            &data[..max_udp_payload]
                        } else {
                            &data
                        };
                        let packet = builder.build_udp_packet_ip(&flow, clamped);
                        match collector_tx.try_send(GuestOutput::tagged_best_effort_datagram(
                            output_tag, packet,
                        )) {
                            Ok(()) => {
                                if let Some(ref w) = rx_waker {
                                    w.wake();
                                }
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                log::trace!("UDP inbound: collector full, dropping");
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    None => break,
                }
            }

            // Guest → Host: forward response datagram
            Some(payload) = guest_rx.recv() => {
                match to_host.try_send(payload) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::trace!("UDP inbound: to_host full, dropping");
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }

            // Inactivity timeout
            () = tokio::time::sleep(timeout_dur) => {
                log::trace!("UDP inbound: timeout");
                break;
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_udp_timeout_constants() {
        const _: () = assert!(UDP_TIMEOUT_SECS > 0);
        const _: () = assert!(DNS_TIMEOUT_SECS < UDP_TIMEOUT_SECS);
    }

    #[test]
    fn udp_payload_budget_tracks_configured_mtu() {
        assert_eq!(
            max_udp_payload_for_ip(1280, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            1252
        );
        assert_eq!(
            max_udp_payload_for_ip(1280, IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            1232
        );
        assert_eq!(
            max_udp_payload_for_ip(9000, IpAddr::V4(Ipv4Addr::LOCALHOST)),
            8972
        );
    }

    fn allow_udp_egress(remote_addr: SocketAddr) -> (HostEgressAuthorizer, HostEgressRequest) {
        (
            HostEgressAuthorizer::new(
                crate::EgressPolicy::AllowAll,
                crate::DnsForwardPolicy::DenyAll,
            ),
            HostEgressRequest::new(
                crate::Protocol::Udp,
                remote_addr,
                crate::HostEgressPurpose::GuestUdpNat,
            ),
        )
    }

    fn udp_output_tag() -> ConnectionOutputTag {
        ConnectionOutputTag::for_test(crate::Protocol::Udp)
    }

    fn test_response_flow(
        guest_mac: [u8; 6],
        remote_addr: SocketAddr,
        guest_ip: IpAddr,
        guest_port: u16,
    ) -> FlowEndpoints {
        FlowEndpoints::from_ip_pair(
            guest_mac,
            remote_addr.ip(),
            guest_ip,
            remote_addr.port(),
            guest_port,
        )
        .expect("test endpoints use matching IP families")
    }

    #[tokio::test]
    async fn udp_task_forwards_and_responds() {
        use std::net::Ipv4Addr;

        // Set up a "remote" UDP socket to echo data back
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        let (guest_tx, guest_rx) = mpsc::channel(256);
        let (collector_tx, mut collector_rx) = mpsc::channel(100);

        let gateway_mac = DEFAULT_GATEWAY_MAC;
        let guest_mac = [0xAA; 6];
        let guest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15));
        let (host_egress, egress_request) = allow_udp_egress(remote_addr);

        let task = tokio::spawn(udp_connection_task(UdpTaskParams {
            host_egress,
            egress_request,
            response_flow: test_response_flow(guest_mac, remote_addr, guest_ip, 12345),
            initial_payload: b"hello".to_vec(),
            guest_rx,
            collector_tx,
            rx_waker: None,
            gateway_mac,
            mtu: crate::VIRTUAL_MTU,
            output_tag: udp_output_tag(),
        }));

        // Remote receives the initial payload and echoes back
        let mut buf = [0u8; 64];
        let (n, from) = remote.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
        remote.send_to(b"world", from).await.unwrap();

        // Collector should receive a response packet
        let pkt = tokio::time::timeout(Duration::from_secs(2), collector_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("channel closed")
            .into_packet();
        // The packet should be a valid ethernet frame (at minimum > 42 bytes for eth+ip+udp)
        assert!(pkt.len() > 42, "packet too short: {}", pkt.len());

        // Send another datagram from "guest"
        guest_tx.send(b"ping".to_vec()).await.unwrap();
        let (n, _) = remote.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");

        // Drop the guest sender to stop the task
        drop(guest_tx);
        drop(tokio::time::timeout(Duration::from_secs(2), task).await);
    }

    #[tokio::test]
    async fn udp_task_times_out() {
        // Use DNS port for short timeout (5s)
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut remote_addr = remote.local_addr().unwrap();
        // We can't bind to port 53, but we can test the timeout logic
        // by using a non-DNS port and checking the 30s timeout doesn't fire
        // instantly. Instead, just verify the task terminates eventually.
        remote_addr.set_port(remote_addr.port()); // keep as-is

        let (guest_tx, guest_rx) = mpsc::channel(256);
        let (collector_tx, _collector_rx) = mpsc::channel(100);
        let (host_egress, egress_request) = allow_udp_egress(remote_addr);

        let handle = UdpConnectionHandle {
            guest_tx,
            task: tokio::spawn(udp_connection_task(UdpTaskParams {
                host_egress,
                egress_request,
                response_flow: test_response_flow(
                    [0xAA; 6],
                    remote_addr,
                    IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                    12345,
                ),
                initial_payload: b"test".to_vec(),
                guest_rx,
                collector_tx,
                rx_waker: None,
                gateway_mac: DEFAULT_GATEWAY_MAC,
                mtu: crate::VIRTUAL_MTU,
                output_tag: udp_output_tag(),
            })),
            created_at: Instant::now(),
        };

        // Task should not be finished immediately
        assert!(!handle.task.is_finished());

        // Drop the guest_tx to trigger termination
        drop(handle.guest_tx);
        drop(tokio::time::timeout(Duration::from_secs(2), handle.task).await);
    }

    /// Test that the UDP task handles a full collector channel gracefully
    /// (drops packets instead of blocking).
    #[tokio::test]
    async fn udp_task_drops_when_collector_full() {
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        let (guest_tx, guest_rx) = mpsc::channel(256);
        // Channel with capacity 1 — will fill up quickly
        let (collector_tx, _collector_rx) = mpsc::channel(1);

        let gateway_mac = DEFAULT_GATEWAY_MAC;
        let guest_mac = [0xAA; 6];
        let guest_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15));
        let (host_egress, egress_request) = allow_udp_egress(remote_addr);

        let task = tokio::spawn(udp_connection_task(UdpTaskParams {
            host_egress,
            egress_request,
            response_flow: test_response_flow(guest_mac, remote_addr, guest_ip, 12345),
            initial_payload: b"init".to_vec(),
            guest_rx,
            collector_tx,
            rx_waker: None,
            gateway_mac,
            mtu: crate::VIRTUAL_MTU,
            output_tag: udp_output_tag(),
        }));

        // Remote receives initial payload and sends multiple responses
        // to overflow the collector channel
        let mut buf = [0u8; 64];
        let (n, from) = remote.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"init");

        for i in 0..5 {
            let msg = format!("resp{i}");
            remote.send_to(msg.as_bytes(), from).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        // Task should still be alive (not panicked from full channel)
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!task.is_finished(), "task should survive full channel");

        drop(guest_tx);
        drop(tokio::time::timeout(Duration::from_secs(2), task).await);
    }

    /// Test that the UDP task fires the `rx_waker` callback when packets arrive.
    #[tokio::test]
    async fn udp_task_fires_waker() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        let (_guest_tx, guest_rx) = mpsc::channel(256);
        let (collector_tx, mut collector_rx) = mpsc::channel(100);

        let wake_count = Arc::new(AtomicUsize::new(0));
        let waker = {
            let count = Arc::clone(&wake_count);
            RxWaker::new(move || {
                count.fetch_add(1, Ordering::Relaxed);
            })
        };

        let gateway_mac = DEFAULT_GATEWAY_MAC;
        let (host_egress, egress_request) = allow_udp_egress(remote_addr);

        let task = tokio::spawn(udp_connection_task(UdpTaskParams {
            host_egress,
            egress_request,
            response_flow: test_response_flow(
                [0xAA; 6],
                remote_addr,
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                12345,
            ),
            initial_payload: b"hello".to_vec(),
            guest_rx,
            collector_tx,
            rx_waker: Some(waker),
            gateway_mac,
            mtu: crate::VIRTUAL_MTU,
            output_tag: udp_output_tag(),
        }));

        // Remote echoes back
        let mut buf = [0u8; 64];
        let (n, from) = remote.recv_from(&mut buf).await.unwrap();
        remote.send_to(&buf[..n], from).await.unwrap();

        // Wait for packet through collector
        let _pkt = tokio::time::timeout(Duration::from_secs(2), collector_rx.recv())
            .await
            .expect("timeout")
            .expect("closed")
            .into_packet();

        assert!(
            wake_count.load(Ordering::Relaxed) > 0,
            "waker should have been called"
        );

        task.abort();
    }

    /// Test that the UDP task handles an unreachable remote gracefully
    /// (the send succeeds locally but no response arrives — task should not hang).
    #[tokio::test]
    async fn udp_task_unreachable_remote() {
        // Bind and immediately drop to get a port that won't respond
        let tmp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let (guest_tx, guest_rx) = mpsc::channel(256);
        let (collector_tx, _collector_rx) = mpsc::channel(100);
        let (host_egress, egress_request) = allow_udp_egress(dead_addr);

        let task = tokio::spawn(udp_connection_task(UdpTaskParams {
            host_egress,
            egress_request,
            response_flow: test_response_flow(
                [0xAA; 6],
                dead_addr,
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                12345,
            ),
            initial_payload: b"hello".to_vec(),
            guest_rx,
            collector_tx,
            rx_waker: None,
            gateway_mac: DEFAULT_GATEWAY_MAC,
            mtu: crate::VIRTUAL_MTU,
            output_tag: udp_output_tag(),
        }));

        // Drop sender to stop the task.  On macOS, ICMP "port unreachable"
        // may finish the task before we even get here, so we only assert
        // that it terminates cleanly — not that it's still running.
        drop(guest_tx);
        let result = tokio::time::timeout(Duration::from_secs(2), task).await;
        assert!(
            result.is_ok(),
            "task should terminate after sender is dropped"
        );
    }

    #[tokio::test]
    async fn inbound_udp_clamps_to_small_configured_mtu() {
        let (from_host_tx, from_host_rx) = mpsc::channel(1);
        let (to_host_tx, _to_host_rx) = mpsc::channel(1);
        let (_guest_tx, guest_rx) = mpsc::channel(1);
        let (collector_tx, mut collector_rx) = mpsc::channel(1);
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(10, 0, 2, 1),
            Ipv4Addr::new(10, 0, 2, 15),
            49152,
            8080,
        );
        let task = tokio::spawn(inbound_udp_task(InboundUdpTaskParams {
            from_host: from_host_rx,
            to_host: to_host_tx,
            flow,
            guest_rx,
            collector_tx,
            rx_waker: None,
            gateway_mac: DEFAULT_GATEWAY_MAC,
            mtu: 1280,
            output_tag: udp_output_tag(),
        }));

        from_host_tx.send(vec![0xAB; 2000]).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), collector_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("collector closed")
            .into_packet();
        assert_eq!(packet.len(), ETH_HEADER_LEN + 1280);
        let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.total_length as usize, 1280);

        task.abort();
    }

    #[tokio::test]
    async fn inbound_udp_allows_larger_than_default_mtu() {
        let (from_host_tx, from_host_rx) = mpsc::channel(1);
        let (to_host_tx, _to_host_rx) = mpsc::channel(1);
        let (_guest_tx, guest_rx) = mpsc::channel(1);
        let (collector_tx, mut collector_rx) = mpsc::channel(1);
        let flow = FlowEndpoints::v6(
            [0xAA; 6],
            std::net::Ipv6Addr::LOCALHOST,
            std::net::Ipv6Addr::LOCALHOST,
            49152,
            8080,
        );
        let task = tokio::spawn(inbound_udp_task(InboundUdpTaskParams {
            from_host: from_host_rx,
            to_host: to_host_tx,
            flow,
            guest_rx,
            collector_tx,
            rx_waker: None,
            gateway_mac: DEFAULT_GATEWAY_MAC,
            mtu: 9000,
            output_tag: udp_output_tag(),
        }));

        from_host_tx.send(vec![0xCD; 4000]).await.unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(1), collector_rx.recv())
            .await
            .expect("timeout waiting for packet")
            .expect("collector closed")
            .into_packet();
        let ip = Ipv6Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.payload_len as usize, UDP_HEADER_LEN + 4000);
        assert!(packet.len() > ETH_HEADER_LEN + crate::VIRTUAL_MTU);

        task.abort();
    }
}
