// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! DNS forwarder for guest configuration
//!
//! Extracts DNS queries (UDP port 53) from guest packets and forwards
//! them to the host's real DNS resolver. Responses are sent back to
//! the guest via the shared collector channel.
//!
//! Note: Only IPv4 UDP DNS forwarding is currently implemented. Unsupported
//! DNS transports are consumed fail-closed before generic NAT can proxy them.

use crate::guest_output::GuestOutput;
use crate::guest_packet::ValidatedGuestIpPacket;
#[cfg(test)]
use crate::packet_builder::{ETH_HEADER_LEN, EthernetHeader, parse_ip_packet};
use crate::packet_builder::{
    ETH_TYPE_IPV4, IP_PROTO_TCP, IP_PROTO_UDP, PacketBuilder, parse_tcp_segment, parse_udp_datagram,
};
use crate::{HostEgressAuthorizer, HostEgressRequest};
use amla_core::backends::RxWaker;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

const DNS_PORT: u16 = 53;
const DNS_TIMEOUT_SECS: u64 = 2;
const IPV4_UDP_OVERHEAD: usize = 28;

pub fn max_dns_response_len(mtu: usize) -> usize {
    mtu.saturating_sub(IPV4_UDP_OVERHEAD).max(1)
}

/// Metadata from a parsed DNS query packet.
#[derive(Debug)]
pub struct DnsQueryInfo<'a> {
    pub src_mac: [u8; 6],
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTransport {
    Udp,
    Tcp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsDropReason {
    UnsupportedTransport {
        transport: DnsTransport,
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    },
    EmptyUdpPayload {
        src_ip: IpAddr,
        dst_ip: IpAddr,
        dst_port: u16,
    },
}

pub enum ValidatedDnsTraffic<'a> {
    Ipv4UdpQuery(DnsQueryInfo<'a>),
    Drop(DnsDropReason),
    NotDns,
}

/// Extract DNS query info from an Ethernet frame containing UDP to port 53.
/// Returns None if the packet is not a UDP-to-port-53 packet.
#[cfg(test)]
pub fn extract_dns_query(packet: &[u8]) -> Option<DnsQueryInfo<'_>> {
    let eth = EthernetHeader::parse(packet)?;
    if eth.ether_type != ETH_TYPE_IPV4 {
        return None;
    }

    let ip = parse_ip_packet(eth.ether_type, &packet[ETH_HEADER_LEN..])?;
    if ip.protocol() != IP_PROTO_UDP {
        return None;
    }
    let (udp, payload) = parse_udp_datagram(ip.src_ip(), ip.dst_ip(), ip.transport_data())?;

    if udp.dst_port != DNS_PORT {
        return None;
    }

    if payload.is_empty() {
        return None;
    }

    Some(DnsQueryInfo {
        src_mac: eth.src_mac,
        src_ip: ip.src_ip(),
        src_port: udp.src_port,
        dst_ip: ip.dst_ip(),
        dst_port: udp.dst_port,
        payload,
    })
}

pub fn classify_validated_dns<'a>(packet: &ValidatedGuestIpPacket<'a>) -> ValidatedDnsTraffic<'a> {
    let eth = packet.ethernet();
    let ip = packet.ip();

    match ip.protocol() {
        IP_PROTO_UDP => {
            let Some((udp, payload)) =
                parse_udp_datagram(ip.src_ip(), ip.dst_ip(), ip.transport_data())
            else {
                return ValidatedDnsTraffic::NotDns;
            };
            if udp.dst_port != DNS_PORT {
                return ValidatedDnsTraffic::NotDns;
            }

            if eth.ether_type != ETH_TYPE_IPV4 {
                return ValidatedDnsTraffic::Drop(DnsDropReason::UnsupportedTransport {
                    transport: DnsTransport::Udp,
                    src_ip: ip.src_ip(),
                    dst_ip: ip.dst_ip(),
                    dst_port: udp.dst_port,
                });
            }

            if payload.is_empty() {
                return ValidatedDnsTraffic::Drop(DnsDropReason::EmptyUdpPayload {
                    src_ip: ip.src_ip(),
                    dst_ip: ip.dst_ip(),
                    dst_port: udp.dst_port,
                });
            }

            ValidatedDnsTraffic::Ipv4UdpQuery(DnsQueryInfo {
                src_mac: eth.src_mac,
                src_ip: ip.src_ip(),
                src_port: udp.src_port,
                dst_ip: ip.dst_ip(),
                dst_port: udp.dst_port,
                payload,
            })
        }
        IP_PROTO_TCP => {
            let Some((tcp, _payload)) =
                parse_tcp_segment(ip.src_ip(), ip.dst_ip(), ip.transport_data())
            else {
                return ValidatedDnsTraffic::NotDns;
            };
            if tcp.dst_port != DNS_PORT {
                return ValidatedDnsTraffic::NotDns;
            }
            ValidatedDnsTraffic::Drop(DnsDropReason::UnsupportedTransport {
                transport: DnsTransport::Tcp,
                src_ip: ip.src_ip(),
                dst_ip: ip.dst_ip(),
                dst_port: tcp.dst_port,
            })
        }
        _ => ValidatedDnsTraffic::NotDns,
    }
}

/// Check if a packet is DNS destined for the gateway (port 53).
#[cfg(test)]
pub fn is_dns_to_gateway(packet: &[u8], config: &crate::UserNetConfig) -> bool {
    extract_dns_query(packet).is_some_and(|query| {
        query.dst_ip == IpAddr::V4(config.gateway_ip)
            || query.dst_ip == IpAddr::V4(config.dns_server)
    })
}

pub fn query_targets_gateway(query: &DnsQueryInfo<'_>, config: &crate::UserNetConfig) -> bool {
    query.dst_ip == IpAddr::V4(config.gateway_ip) || query.dst_ip == IpAddr::V4(config.dns_server)
}

/// Spawn a tokio task that forwards a DNS query to a host resolver
/// and sends the response back to the guest via the collector channel.
///
/// The `semaphore` limits concurrent DNS tasks. If all permits are taken,
/// the query is silently dropped (guest will retry via DNS timeout).
#[allow(clippy::too_many_arguments)]
pub fn spawn_dns_forward(
    query: &DnsQueryInfo<'_>,
    reply_src_ip: IpAddr,
    host_egress: HostEgressAuthorizer,
    egress_request: HostEgressRequest,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    gateway_mac: [u8; 6],
    semaphore: Arc<tokio::sync::Semaphore>,
    mtu: usize,
) {
    // Try to acquire a permit without blocking. If the limit is reached,
    // silently drop the query — the guest will retry after DNS timeout.
    let Ok(permit) = semaphore.try_acquire_owned() else {
        log::debug!("DNS forward: concurrent task limit reached, dropping query");
        return;
    };

    let src_mac = query.src_mac;
    let src_ip = query.src_ip;
    let src_port = query.src_port;
    let payload = query.payload.to_vec();

    // lifetime: detached. Ends on any of:
    //   - DNS_TIMEOUT_SECS elapsed on socket.recv()
    //   - `collector_tx` closed (UserNetState dropped -> NatProxy dropped)
    // Concurrency bounded by `semaphore` (owned permit held as `_permit`
    // until task returns). No external abort; no JoinHandle retained.
    tokio::spawn(async move {
        let _permit = permit; // held for task lifetime, released on drop
        let Some(authorized) = host_egress.authorize(egress_request) else {
            log::trace!(
                "DNS forward: egress denied by network policy for {}",
                egress_request.socket_addr
            );
            return;
        };
        let forward_to = authorized.socket_addr();
        let mut builder = PacketBuilder::new(gateway_mac);

        let bind_addr: SocketAddr = match forward_to {
            SocketAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            SocketAddr::V6(_) => SocketAddr::from(([0u16; 8], 0)),
        };
        let Ok(socket) = tokio::net::UdpSocket::bind(bind_addr).await else {
            log::trace!("DNS forward: failed to bind socket");
            return;
        };
        // Connect to restrict recv to replies from the target only (prevents spoofing)
        if host_egress.authorize(egress_request).is_none() {
            log::trace!(
                "DNS forward: egress denied by network policy before connect to {}",
                egress_request.socket_addr
            );
            return;
        }
        if let Err(e) = socket.connect(forward_to).await {
            log::trace!("DNS forward: connect to {forward_to} failed: {e}");
            return;
        }

        if host_egress.authorize(egress_request).is_none() {
            log::trace!(
                "DNS forward: egress denied by network policy before send to {}",
                egress_request.socket_addr
            );
            return;
        }
        if let Err(e) = socket.send(&payload).await {
            log::trace!("DNS forward: send to {forward_to} failed: {e}");
            return;
        }

        let mut buf = vec![0u8; max_dns_response_len(mtu)];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(DNS_TIMEOUT_SECS),
            socket.recv(&mut buf),
        )
        .await;

        let n = match result {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => {
                log::trace!("DNS forward: recv error: {e}");
                return;
            }
            Err(_) => {
                log::trace!("DNS forward: timeout waiting for response from {forward_to}");
                return;
            }
        };

        let IpAddr::V4(src_v4) = reply_src_ip else {
            return;
        };
        let IpAddr::V4(dst_v4) = src_ip else {
            return;
        };

        let packet =
            builder.build_udp_packet(src_mac, src_v4, dst_v4, DNS_PORT, src_port, &buf[..n]);

        match collector_tx.try_send(GuestOutput::BestEffortDatagram(packet)) {
            Ok(()) => {
                if let Some(ref waker) = rx_waker {
                    waker.wake();
                }
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                log::trace!("DNS forward: collector channel full, dropping response");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {}
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UserNetConfig;
    use crate::packet_builder::{calculate_ip_checksum, calculate_udp_checksum};
    use std::net::Ipv4Addr;

    fn build_dns_test_packet(
        dns_payload: &[u8],
        src_port: u16,
        dst_port: u16,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_mac: [u8; 6],
    ) -> Vec<u8> {
        let total = 14 + 20 + 8 + dns_payload.len();
        let mut pkt = vec![0u8; total];
        // ETH
        pkt[0..6].copy_from_slice(&crate::DEFAULT_GATEWAY_MAC); // dst mac
        pkt[6..12].copy_from_slice(&src_mac);
        pkt[12..14].copy_from_slice(&[0x08, 0x00]);
        // IP
        pkt[14] = 0x45;
        let ip_total = u16::try_from(20 + 8 + dns_payload.len()).unwrap();
        pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
        pkt[23] = 17; // UDP
        pkt[26..30].copy_from_slice(&src_ip.octets());
        pkt[30..34].copy_from_slice(&dst_ip.octets());
        let ip_checksum = calculate_ip_checksum(&pkt[14..34]);
        pkt[24..26].copy_from_slice(&ip_checksum.to_be_bytes());
        // UDP
        pkt[34..36].copy_from_slice(&src_port.to_be_bytes());
        pkt[36..38].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = u16::try_from(8 + dns_payload.len()).unwrap();
        pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
        // Payload
        pkt[42..42 + dns_payload.len()].copy_from_slice(dns_payload);
        pkt
    }

    fn default_dns_packet(dns_payload: &[u8], dst_ip: Ipv4Addr) -> Vec<u8> {
        build_dns_test_packet(
            dns_payload,
            12345,
            53,
            Ipv4Addr::new(10, 0, 2, 15),
            dst_ip,
            crate::DEFAULT_GUEST_MAC,
        )
    }

    #[test]
    fn extract_dns_query_from_valid_packet() {
        let dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let pkt = default_dns_packet(dns_payload, crate::DEFAULT_GATEWAY);
        let info = extract_dns_query(&pkt).expect("should parse DNS query");
        assert_eq!(info.dst_port, 53);
        assert_eq!(info.payload, dns_payload);
    }

    #[test]
    fn non_dns_port_returns_none() {
        let pkt = build_dns_test_packet(
            b"data",
            12345,
            80,
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            crate::DEFAULT_GUEST_MAC,
        );
        assert!(extract_dns_query(&pkt).is_none());
    }

    #[test]
    fn is_dns_to_gateway_detects_gateway_dns() {
        let config = UserNetConfig::default();
        let pkt = default_dns_packet(b"query", config.gateway_ip);
        assert!(is_dns_to_gateway(&pkt, &config));
    }

    #[test]
    fn is_dns_to_gateway_accepts_dns_server() {
        let config = UserNetConfig::default().with_dns(Ipv4Addr::new(8, 8, 4, 4));
        let pkt = default_dns_packet(b"query", Ipv4Addr::new(8, 8, 4, 4));
        assert!(is_dns_to_gateway(&pkt, &config));
    }

    #[test]
    fn is_dns_to_gateway_ignores_external_dns() {
        let config = UserNetConfig::default();
        let pkt = default_dns_packet(b"query", Ipv4Addr::new(8, 8, 8, 8));
        assert!(!is_dns_to_gateway(&pkt, &config));
    }

    #[test]
    fn extract_dns_query_empty_payload_returns_none() {
        let pkt = default_dns_packet(b"", crate::DEFAULT_GATEWAY);
        assert!(extract_dns_query(&pkt).is_none());
    }

    #[test]
    fn extract_dns_query_preserves_src_mac() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0x12, 0x34];
        let pkt = build_dns_test_packet(
            b"q",
            9999,
            53,
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
            mac,
        );
        let info = extract_dns_query(&pkt).unwrap();
        assert_eq!(info.src_mac, mac);
    }

    #[test]
    fn extract_dns_query_clamps_to_udp_length() {
        // Build a packet with actual payload but extra bytes after (Ethernet padding)
        let dns_payload = b"\x00\x01\x01\x00";
        let mut pkt = default_dns_packet(dns_payload, crate::DEFAULT_GATEWAY);
        // Add padding bytes
        pkt.extend_from_slice(&[0u8; 20]);
        let info = extract_dns_query(&pkt).expect("should parse");
        assert_eq!(info.payload.len(), dns_payload.len());
    }

    #[test]
    fn extract_dns_query_udp_length_less_than_8_returns_none() {
        let mut pkt = default_dns_packet(b"x", crate::DEFAULT_GATEWAY);
        // Overwrite UDP length to 4 (less than 8-byte header)
        pkt[38..40].copy_from_slice(&4u16.to_be_bytes());
        assert!(extract_dns_query(&pkt).is_none());
    }

    #[test]
    fn extract_dns_query_rejects_invalid_ip_checksum() {
        let mut pkt = default_dns_packet(b"query", crate::DEFAULT_GATEWAY);
        pkt[24] ^= 0x80;
        assert!(extract_dns_query(&pkt).is_none());
    }

    #[test]
    fn extract_dns_query_rejects_invalid_udp_checksum() {
        let mut pkt = default_dns_packet(b"query", crate::DEFAULT_GATEWAY);
        let udp_checksum = calculate_udp_checksum(
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
            &pkt[34..42],
            b"query",
        );
        let bad_checksum: u16 = if udp_checksum == 0x1234 {
            0x5678
        } else {
            0x1234
        };
        pkt[40..42].copy_from_slice(&bad_checksum.to_be_bytes());
        assert!(extract_dns_query(&pkt).is_none());
    }

    fn allow_dns_egress(resolver_addr: SocketAddr) -> (HostEgressAuthorizer, HostEgressRequest) {
        (
            HostEgressAuthorizer::new(
                crate::EgressPolicy::DenyAll,
                crate::DnsForwardPolicy::AllowAll,
            ),
            HostEgressRequest::new(
                crate::Protocol::Udp,
                resolver_addr,
                crate::HostEgressPurpose::DnsForward,
            ),
        )
    }

    #[tokio::test]
    async fn forward_task_sends_response_to_collector() {
        let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();

        let (collector_tx, mut collector_rx) = mpsc::channel(100);
        let wake_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let waker = {
            let c = Arc::clone(&wake_count);
            RxWaker::new(move || {
                c.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            })
        };

        let query = DnsQueryInfo {
            src_mac: [0xAA; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            src_port: 44444,
            dst_ip: IpAddr::V4(crate::DEFAULT_GATEWAY),
            dst_port: 53,
            payload: b"test-query",
        };
        let (host_egress, egress_request) = allow_dns_egress(resolver_addr);

        spawn_dns_forward(
            &query,
            IpAddr::V4(crate::DEFAULT_GATEWAY),
            host_egress,
            egress_request,
            collector_tx,
            Some(waker),
            crate::DEFAULT_GATEWAY_MAC,
            Arc::new(tokio::sync::Semaphore::new(128)),
            crate::VIRTUAL_MTU,
        );

        // Resolver echoes back
        let mut buf = [0u8; 256];
        let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"test-query");
        resolver.send_to(b"test-response", from).await.unwrap();

        // Collector should receive packet
        let pkt = tokio::time::timeout(std::time::Duration::from_secs(2), collector_rx.recv())
            .await
            .unwrap()
            .unwrap()
            .into_packet();
        assert!(pkt.len() > 42); // ETH+IP+UDP headers

        assert!(wake_count.load(std::sync::atomic::Ordering::Relaxed) > 0);
    }

    #[tokio::test]
    async fn forward_task_handles_closed_collector() {
        let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver_addr = resolver.local_addr().unwrap();
        let (collector_tx, collector_rx) = mpsc::channel(1);
        drop(collector_rx);

        let query = DnsQueryInfo {
            src_mac: [0xAA; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            src_port: 44444,
            dst_ip: IpAddr::V4(crate::DEFAULT_GATEWAY),
            dst_port: 53,
            payload: b"closed-test",
        };
        let (host_egress, egress_request) = allow_dns_egress(resolver_addr);
        spawn_dns_forward(
            &query,
            IpAddr::V4(crate::DEFAULT_GATEWAY),
            host_egress,
            egress_request,
            collector_tx,
            None,
            crate::DEFAULT_GATEWAY_MAC,
            Arc::new(tokio::sync::Semaphore::new(128)),
            crate::VIRTUAL_MTU,
        );
        // Echo back from resolver
        let mut buf = [0u8; 64];
        let (n, from) = resolver.recv_from(&mut buf).await.unwrap();
        resolver.send_to(&buf[..n], from).await.unwrap();
        // Should not panic
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    #[tokio::test]
    async fn forward_task_handles_unreachable_resolver() {
        // Bind and drop to get a port that won't respond
        let tmp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = tmp.local_addr().unwrap();
        drop(tmp);

        let (collector_tx, mut collector_rx) = mpsc::channel(100);

        let query = DnsQueryInfo {
            src_mac: [0xAA; 6],
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            src_port: 44444,
            dst_ip: IpAddr::V4(crate::DEFAULT_GATEWAY),
            dst_port: 53,
            payload: b"unreachable-test",
        };
        let (host_egress, egress_request) = allow_dns_egress(dead_addr);

        spawn_dns_forward(
            &query,
            IpAddr::V4(crate::DEFAULT_GATEWAY),
            host_egress,
            egress_request,
            collector_tx,
            None,
            crate::DEFAULT_GATEWAY_MAC,
            Arc::new(tokio::sync::Semaphore::new(128)),
            crate::VIRTUAL_MTU,
        );

        // No response should arrive (the resolver is dead), and the task
        // should time out without panicking.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(4), // DNS timeout is 2s
            collector_rx.recv(),
        )
        .await;

        // Either timeout (no packet) or None (channel closed) — both acceptable
        match result {
            Err(_) | Ok(None) => {}
            Ok(Some(_)) => panic!("should not receive a response from dead resolver"),
        }
    }
}
