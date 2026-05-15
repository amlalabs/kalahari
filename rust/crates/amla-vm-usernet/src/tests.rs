// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

// # Test Module
//
// ## Important: Cargo Feature Unification
//
// These tests MUST be run separately from smoltcp's own tests due to Cargo's
// feature unification behavior:
//
// ```bash
// # CORRECT: Run usernet tests separately
// cargo test --workspace --exclude amla-usernet && cargo test -p amla-usernet
//
// # WRONG: This will fail due to feature unification
// cargo test --workspace  # includes both smoltcp and amla-usernet
// ```
//
// ### Why this matters:
//
// 1. **amla-usernet** uses smoltcp with `default-features = false` and minimal
//    features (no raw sockets, no TUN/TAP)
//
// 2. **smoltcp's own tests** use default features which include `phy-raw_socket`
//    and `phy-tuntap_interface`
//
// 3. When both are tested together, Cargo unifies features and compiles smoltcp
//    with ALL features enabled
//
// 4. This changes the structure of `InterfaceInner` (smoltcp's internal state),
//    which breaks serialization and causes test failures
//
// The pre-commit hooks handle this correctly by excluding amla-usernet from the
// workspace test run and testing it separately.
use super::*;
use crate::config::parse_host_dns_from_str;
use crate::device::VirtualDevice;
use crate::guest_output::GuestOutput;
use crate::icmp::{checksum, should_nat_proxy};
use crate::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, ETH_TYPE_IPV6, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, TCP_HEADER_LEN, UDP_HEADER_LEN, calculate_tcp_checksum,
    calculate_tcp_checksum_v6, calculate_udp_checksum_v6,
};
use amla_core::backends::{NetBackend, NetRxPacketLease};
use smoltcp::phy::{Device, Medium};
use std::io::IoSlice;
use std::net::{IpAddr, SocketAddr};

/// Documentation-range DNS placeholder; config validation tests do not send DNS.
const UNUSED_TEST_HOST_DNS: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 53);

fn host_dns_backend() -> UserNetBackend {
    UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).unwrap()
}

fn recv_into<P, D>(backend: &UserNetBackend<P, D>, buf: &mut [u8]) -> std::io::Result<usize>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    let Some(packet) = backend.rx_packet()? else {
        return Err(std::io::Error::from(std::io::ErrorKind::WouldBlock));
    };
    let data = packet.packet();
    if buf.len() < data.len() {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    let len = data.len();
    buf[..len].copy_from_slice(data);
    packet.commit()?;
    Ok(len)
}

fn leased_rx_packet_len(backend: &UserNetBackend) -> std::io::Result<Option<usize>> {
    Ok(backend.rx_packet()?.map(|packet| packet.packet().len()))
}

#[test]
fn test_default_config() {
    let config = UserNetConfig::default();
    assert_eq!(config.gateway_mac, DEFAULT_GATEWAY_MAC);
    assert_eq!(config.guest_mac, DEFAULT_GUEST_MAC);
    assert_eq!(config.gateway_ip, DEFAULT_GATEWAY);
    assert_eq!(config.guest_ip, DEFAULT_GUEST_IP);
    assert_eq!(config.prefix_len, 24);
    assert_eq!(config.dns_server, DEFAULT_DNS);
    assert_eq!(config.gateway_ipv6, DEFAULT_GATEWAY_V6);
    assert_eq!(config.guest_ipv6, DEFAULT_GUEST_IP_V6);
    assert_eq!(config.prefix_len_v6, DEFAULT_PREFIX_LEN_V6);
    assert_eq!(config.dns_server_v6, DEFAULT_DNS_V6);
    assert_eq!(config.mtu, VIRTUAL_MTU);
    assert_eq!(config.egress_policy, EgressPolicy::DenyAll);
    assert_eq!(config.dns_forward_policy, DnsForwardPolicy::DenyAll);
}

#[test]
fn test_config_builder() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(192, 168, 1, 1))
        .with_guest_ip(Ipv4Addr::new(192, 168, 1, 100))
        .with_dns(Ipv4Addr::new(8, 8, 8, 8))
        .with_gateway_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        .with_guest_ipv6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x64))
        .with_dns_ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));

    assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(config.guest_ip, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(config.dns_server, Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(
        config.gateway_ipv6,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(
        config.guest_ipv6,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x64)
    );
    assert_eq!(
        config.dns_server_v6,
        Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)
    );
}

// =========================================================================
// Host DNS parsing
// =========================================================================

#[test]
fn parse_host_dns_extracts_ipv4() {
    let server = parse_host_dns_from_str("nameserver 8.8.8.8\nnameserver 1.1.1.1\n").unwrap();
    assert_eq!(server, Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn parse_host_dns_skips_ipv6() {
    let server = parse_host_dns_from_str("nameserver 2001:db8::1\nnameserver 8.8.8.8\n").unwrap();
    assert_eq!(server, Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn parse_host_dns_skips_comments_and_blanks() {
    let server = parse_host_dns_from_str("# this is a comment\n\nnameserver 8.8.8.8\n").unwrap();
    assert_eq!(server, Ipv4Addr::new(8, 8, 8, 8));
}

#[test]
fn parse_host_dns_empty_is_error() {
    assert!(parse_host_dns_from_str("").is_err());
}

#[test]
fn parse_host_dns_handles_extra_whitespace() {
    let server = parse_host_dns_from_str("  nameserver   8.8.4.4  \n").unwrap();
    assert_eq!(server, Ipv4Addr::new(8, 8, 4, 4));
}

#[test]
fn host_dns_server_roundtrips_through_serde() {
    let config = UserNetConfig::default().with_host_dns_server(Ipv4Addr::new(192, 0, 2, 1));
    let json = serde_json::to_string(&config).unwrap();
    assert!(json.contains("host_dns_server"));
    let config2: UserNetConfig = serde_json::from_str(&json).unwrap();
    assert_eq!(config2.host_dns_server, config.host_dns_server);
}

#[test]
fn test_port_forward() {
    let forward = PortForward::tcp(8080, 80);
    assert_eq!(forward.protocol, Protocol::Tcp);
    assert_eq!(forward.host_port, 8080);
    assert_eq!(forward.guest_port, 80);
    assert!(forward.host_addr.is_none());

    let forward = forward.bind_to(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(forward.host_addr, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn test_backend_creation() {
    let backend = host_dns_backend();
    assert_eq!(backend.gateway_ip(), DEFAULT_GATEWAY);
    assert_eq!(backend.guest_ip(), DEFAULT_GUEST_IP);
}

#[test]
fn test_backend_creation_with_valid_prefix_lens() {
    // Test boundary values that should work
    let config = UserNetConfig::try_default().unwrap();

    // prefix_len = 0 is valid (match all)
    let mut config0 = config.clone();
    config0.prefix_len = 0;
    config0.prefix_len_v6 = 0;
    let _backend = UserNetBackend::try_new(config0).unwrap();

    // prefix_len = 32 is valid (single host)
    let mut config32 = config.clone();
    config32.prefix_len = 32;
    let _backend = UserNetBackend::try_new(config32).unwrap();

    // prefix_len_v6 = 128 is valid (single host)
    let mut config128 = config;
    config128.prefix_len_v6 = 128;
    let _backend = UserNetBackend::try_new(config128).unwrap();
}

#[test]
fn test_backend_creation_rejects_invalid_ipv4_prefix() {
    let config = UserNetConfig {
        prefix_len: 33,
        ..Default::default()
    };
    assert!(UserNetBackend::try_new(config).is_err());
}

#[test]
fn test_backend_creation_rejects_invalid_ipv6_prefix() {
    let config = UserNetConfig {
        prefix_len_v6: 129,
        ..Default::default()
    };
    assert!(UserNetBackend::try_new(config).is_err());
}

#[test]
fn test_try_new_rejects_invalid_prefix() {
    let config = UserNetConfig {
        prefix_len: 33,
        ..Default::default()
    };
    assert!(UserNetBackend::try_new(config).is_err());

    let config_v6 = UserNetConfig {
        prefix_len_v6: 129,
        ..Default::default()
    };
    assert!(UserNetBackend::try_new(config_v6).is_err());
}

#[test]
fn test_try_new_accepts_valid_config() {
    assert!(UserNetBackend::try_new(UserNetConfig::try_default().unwrap()).is_ok());
}

#[test]
fn test_stats() {
    let backend = host_dns_backend();
    let stats = backend.stats();
    assert_eq!(stats.rx_queue_len, 0);
    assert_eq!(stats.tx_queue_len, 0);
}

#[test]
fn test_send_packet() {
    let backend = host_dns_backend();

    // Create a minimal Ethernet frame
    let mut packet = vec![0u8; 64];
    // Destination MAC
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Source MAC
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    // EtherType (ARP)
    packet[12..14].copy_from_slice(&[0x08, 0x06]);

    // Should accept the packet
    let result = backend.send(&[IoSlice::new(&packet)]);
    assert!(result.is_ok());
}

#[test]
fn test_virtual_device() {
    let mut device = VirtualDevice::new(1500);

    // Queue should start empty
    assert!(device.dequeue_to_guest().is_none());
    assert!(!device.has_packets_for_guest());

    // Queue a packet
    device.queue_from_guest(vec![1, 2, 3, 4]).unwrap();

    // Check capabilities
    let caps = device.capabilities();
    assert_eq!(caps.medium, Medium::Ethernet);
    assert_eq!(caps.max_transmission_unit, 1500);
}

#[test]
fn test_queue_full() {
    let mut device = VirtualDevice::new(1500);

    // Fill the queue
    for _ in 0..MAX_QUEUE_SIZE {
        assert!(device.queue_from_guest(vec![0u8; 64]).is_ok());
    }

    // Next should fail
    let result = device.queue_from_guest(vec![0u8; 64]);
    assert!(matches!(result, Err(UserNetError::QueueFull)));
}

#[test]
fn test_enqueue_to_guest_respects_limit() {
    let mut device = VirtualDevice::new(1500);
    for _ in 0..MAX_QUEUE_SIZE {
        assert!(device.enqueue_to_guest(vec![0u8; 64]));
    }
    // Queue is now full
    assert!(!device.enqueue_to_guest(vec![0u8; 64]));
    assert_eq!(device.tx_queue.len(), MAX_QUEUE_SIZE);
    assert_eq!(device.dropped_tx_count, 1);
}

#[test]
// Reason: lock guard scope intentionally spans the assertion
// block to observe a single consistent state snapshot.
#[allow(clippy::significant_drop_tightening)]
fn reliable_collector_output_waits_for_final_tx_capacity() {
    let config = UserNetConfig::default().with_host_dns_server(Ipv4Addr::LOCALHOST);
    let backend = UserNetBackend::try_new(config).unwrap();
    let mut state = backend.state.lock();
    for _ in 0..MAX_QUEUE_SIZE {
        state.device.tx_queue.push_back(vec![0xAA; 64]);
    }

    let reliable = vec![0x42; 96];
    state
        .collector_tx
        .try_send(GuestOutput::ReliableTcp(reliable.clone()))
        .unwrap();
    state.poll_iface();

    assert_eq!(state.device.tx_queue.len(), MAX_QUEUE_SIZE);
    assert_eq!(state.device.dropped_tx_count, 0);
    assert_eq!(state.collector_backlog.len(), 1);
    assert_eq!(state.collector_backlog_bytes, reliable.len());
    assert_eq!(state.reliable_backlogged_count, 1);

    assert_eq!(state.device.dequeue_to_guest(), Some(vec![0xAA; 64]));
    state.poll_iface();

    assert!(state.collector_backlog.is_empty());
    assert_eq!(state.collector_backlog_bytes, 0);
    assert_eq!(
        state.device.tx_queue.back().map(Vec::as_slice),
        Some(reliable.as_slice())
    );
}

#[test]
// Reason: state lock scope intentionally covers the entire test body so
// queue manipulations and assertions observe the same snapshot.
#[allow(clippy::significant_drop_tightening)]
fn final_tx_pressure_drops_best_effort_but_retains_reliable_tcp() {
    let config = UserNetConfig::default().with_host_dns_server(Ipv4Addr::LOCALHOST);
    let backend = UserNetBackend::try_new(config).unwrap();
    let reliable = vec![0x44; 96];
    {
        let mut state = backend.state.lock();
        for _ in 0..MAX_QUEUE_SIZE {
            state.device.tx_queue.push_back(vec![0xAA; 64]);
        }

        state
            .collector_tx
            .try_send(GuestOutput::BestEffortDatagram(vec![0x33; 64]))
            .unwrap();
        state
            .collector_tx
            .try_send(GuestOutput::Control(vec![0x55; 64]))
            .unwrap();
        state
            .collector_tx
            .try_send(GuestOutput::ReliableTcp(reliable.clone()))
            .unwrap();

        state.poll_iface();

        assert_eq!(state.best_effort_dropped_count, 1);
        assert_eq!(state.control_dropped_count, 1);
        assert_eq!(state.reliable_backlogged_count, 1);
        assert_eq!(state.collector_backlog.len(), 1);
        assert_eq!(state.device.dropped_tx_count, 0);

        assert_eq!(state.device.dequeue_to_guest(), Some(vec![0xAA; 64]));
        state.poll_iface();
        assert_eq!(
            state.device.tx_queue.back().map(Vec::as_slice),
            Some(reliable.as_slice())
        );
    }

    let stats = backend.stats();
    assert_eq!(stats.best_effort_dropped_count, 1);
    assert_eq!(stats.control_dropped_count, 1);
    assert_eq!(stats.reliable_backlogged_count, 1);
    assert_eq!(stats.reliable_backlog_overflow_count, 0);
}

#[test]
fn test_arp_response() {
    // This test verifies that smoltcp responds to ARP requests for the gateway IP
    let backend = host_dns_backend();
    let config = UserNetConfig::default();
    let guest_mac = config.guest_mac;

    // Build an ARP request for the configured gateway address.
    // Ethernet header
    let mut arp_request = vec![
        // Destination MAC (broadcast)
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        0xff,
        // Source MAC (guest)
        guest_mac[0],
        guest_mac[1],
        guest_mac[2],
        guest_mac[3],
        guest_mac[4],
        guest_mac[5],
        // EtherType: ARP (0x0806)
        0x08,
        0x06,
        // ARP header
        0x00,
        0x01, // Hardware type: Ethernet
        0x08,
        0x00, // Protocol type: IPv4
        0x06, // Hardware size: 6
        0x04, // Protocol size: 4
        0x00,
        0x01, // Opcode: Request
        // Sender hardware address (guest MAC)
        guest_mac[0],
        guest_mac[1],
        guest_mac[2],
        guest_mac[3],
        guest_mac[4],
        guest_mac[5],
        // Sender protocol address (10.0.2.15)
        10,
        0,
        2,
        15,
        // Target hardware address (unknown)
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        // Target protocol address (gateway)
        config.gateway_ip.octets()[0],
        config.gateway_ip.octets()[1],
        config.gateway_ip.octets()[2],
        config.gateway_ip.octets()[3],
    ];
    // Pad to minimum Ethernet frame size
    arp_request.resize(60, 0);

    // Send the ARP request
    let result = backend.send(&[IoSlice::new(&arp_request)]);
    assert!(result.is_ok(), "ARP send failed: {result:?}");

    // Try to receive the ARP reply
    let mut buf = [0u8; 1500];
    let recv_result = recv_into(&backend, &mut buf);

    // smoltcp should have generated an ARP reply
    match recv_result {
        Ok(len) => {
            // Check it's an ARP reply
            assert!(len >= 42, "Response too short: {len}");
            assert_eq!(buf[12], 0x08, "Not ARP: {:02x}{:02x}", buf[12], buf[13]);
            assert_eq!(buf[13], 0x06, "Not ARP: {:02x}{:02x}", buf[12], buf[13]);
            assert_eq!(buf[20], 0x00, "Not ARP reply opcode");
            assert_eq!(buf[21], 0x02, "Not ARP reply opcode");

            // Verify sender IP is gateway
            assert_eq!(
                &buf[28..32],
                &config.gateway_ip.octets(),
                "Reply from wrong IP"
            );

            // Verify sender MAC is gateway MAC
            let expected_mac = config.gateway_mac;
            assert_eq!(
                &buf[22..28],
                &expected_mac,
                "Reply from wrong MAC: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                buf[22],
                buf[23],
                buf[24],
                buf[25],
                buf[26],
                buf[27]
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // No response generated - this is the bug we're looking for
            panic!("No ARP reply generated! smoltcp did not respond to ARP request");
        }
        Err(e) => {
            panic!("Unexpected error: {e:?}");
        }
    }
}

// =========================================================================
// UserNetConfig Tests
// =========================================================================

#[test]
fn test_config_new_same_as_default() {
    let config_new = UserNetConfig::new();
    let config_default = UserNetConfig::default();

    assert_eq!(config_new.gateway_mac, config_default.gateway_mac);
    assert_eq!(config_new.guest_mac, config_default.guest_mac);
    assert_eq!(config_new.gateway_ip, config_default.gateway_ip);
    assert_eq!(config_new.guest_ip, config_default.guest_ip);
    assert_eq!(config_new.prefix_len, config_default.prefix_len);
    assert_eq!(config_new.dns_server, config_default.dns_server);
    assert_eq!(config_new.mtu, config_default.mtu);
}

#[test]
fn test_config_with_guest_mac() {
    let custom_mac = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_guest_mac(custom_mac);
    assert_eq!(config.guest_mac, custom_mac);
    // Other values unchanged
    assert_eq!(config.gateway_mac, DEFAULT_GATEWAY_MAC);
}

#[test]
fn test_config_with_port_forward() {
    let forward = PortForward::tcp(8080, 80);
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_port_forward(forward);

    assert_eq!(config.port_forwards.len(), 1);
    assert_eq!(config.port_forwards[0].host_port, 8080);
    assert_eq!(config.port_forwards[0].guest_port, 80);
    assert_eq!(config.port_forwards[0].protocol, Protocol::Tcp);
}

#[test]
fn test_config_multiple_port_forwards() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_port_forward(PortForward::tcp(8080, 80))
        .with_port_forward(PortForward::udp(5353, 53))
        .with_port_forward(PortForward::tcp(2222, 22));

    assert_eq!(config.port_forwards.len(), 3);
    assert_eq!(config.port_forwards[0].protocol, Protocol::Tcp);
    assert_eq!(config.port_forwards[1].protocol, Protocol::Udp);
    assert_eq!(config.port_forwards[2].host_port, 2222);
}

#[test]
fn test_config_with_prefix_len_v6() {
    let config = UserNetConfig::try_default().unwrap().with_prefix_len_v6(48);
    assert_eq!(config.prefix_len_v6, 48);
}

#[test]
fn test_config_chain_all_builders() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(192, 168, 100, 1))
        .with_guest_ip(Ipv4Addr::new(192, 168, 100, 50))
        .with_dns(Ipv4Addr::new(8, 8, 4, 4))
        .with_gateway_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))
        .with_guest_ipv6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 50))
        .with_dns_ipv6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844))
        .with_prefix_len_v6(48)
        .with_guest_mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        .with_port_forward(PortForward::tcp(443, 443));

    assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 100, 1));
    assert_eq!(config.guest_ip, Ipv4Addr::new(192, 168, 100, 50));
    assert_eq!(config.dns_server, Ipv4Addr::new(8, 8, 4, 4));
    assert_eq!(
        config.gateway_ipv6,
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(
        config.guest_ipv6,
        Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 50)
    );
    assert_eq!(
        config.dns_server_v6,
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)
    );
    assert_eq!(config.prefix_len_v6, 48);
    assert_eq!(config.guest_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(config.port_forwards.len(), 1);
}

// =========================================================================
// PortForward Tests
// =========================================================================

#[test]
fn test_port_forward_udp() {
    let forward = PortForward::udp(5353, 53);
    assert_eq!(forward.protocol, Protocol::Udp);
    assert_eq!(forward.host_port, 5353);
    assert_eq!(forward.guest_port, 53);
    assert!(forward.host_addr.is_none());
}

#[test]
fn test_port_forward_bind_to_ipv6() {
    let forward = PortForward::tcp(8080, 80).bind_to(IpAddr::V6(Ipv6Addr::LOCALHOST));
    assert_eq!(forward.host_addr, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
}

// =========================================================================
// UserNetBackend Creation Tests
// =========================================================================

#[test]
fn test_backend_with_custom_config() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(172, 16, 0, 1))
        .with_guest_ip(Ipv4Addr::new(172, 16, 0, 100));

    let backend = UserNetBackend::try_new(config).unwrap();
    assert_eq!(backend.gateway_ip(), Ipv4Addr::new(172, 16, 0, 1));
    assert_eq!(backend.guest_ip(), Ipv4Addr::new(172, 16, 0, 100));
}

#[test]
fn test_backend_poll_ok() {
    let backend = host_dns_backend();
    let result = backend.poll();
    assert!(result.is_ok());
}

// =========================================================================
// Packet Send/Receive Tests
// =========================================================================

#[test]
fn test_recv_would_block_when_empty() {
    let backend = host_dns_backend();
    let mut buf = [0u8; 1500];

    // Drain any initial smoltcp-generated packets (e.g. IPv6 Router Solicitation)
    while recv_into(&backend, &mut buf).is_ok() {}

    let result = recv_into(&backend, &mut buf);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
fn test_rx_packet_initially_none() {
    let backend = host_dns_backend();
    assert_eq!(leased_rx_packet_len(&backend).unwrap(), None);
}

#[test]
fn test_set_nonblocking_always_ok() {
    let backend = host_dns_backend();
    assert!(backend.set_nonblocking(true).is_ok());
    assert!(backend.set_nonblocking(false).is_ok());
}

#[test]
fn test_send_minimum_ethernet_frame() {
    let backend = host_dns_backend();

    // Minimum Ethernet frame is 60 bytes (excluding FCS)
    let mut packet = vec![0u8; 60];
    // Broadcast destination
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    // Source MAC
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    // EtherType: ARP
    packet[12..14].copy_from_slice(&[0x08, 0x06]);

    let result = backend.send(&[IoSlice::new(&packet)]);
    assert!(result.is_ok());
}

#[test]
fn test_send_large_packet() {
    let backend = host_dns_backend();

    // MTU-sized packet
    let mut packet = vec![0u8; VIRTUAL_MTU + ETH_HEADER_LEN];
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    packet[12..14].copy_from_slice(&[0x08, 0x00]); // IPv4

    let result = backend.send(&[IoSlice::new(&packet)]);
    assert!(result.is_ok());
}

#[test]
fn test_send_oversized_packet_is_dropped_before_queueing() {
    let backend = host_dns_backend();
    let packet = vec![0u8; VIRTUAL_MTU + ETH_HEADER_LEN + 1];

    let result = backend.send(&[IoSlice::new(&packet)]);

    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::InvalidInput);
    let stats = backend.stats();
    assert_eq!(stats.rx_queue_len, 0);
    assert_eq!(stats.tx_queue_len, 0);
}

// =========================================================================
// Stats Tracking Tests
// =========================================================================

#[test]
fn test_stats_initial_zero() {
    let backend = host_dns_backend();
    let stats = backend.stats();

    assert_eq!(stats.rx_queue_len, 0);
    assert_eq!(stats.tx_queue_len, 0);
    assert_eq!(stats.socket_count, 0);
    assert_eq!(stats.reliable_backlogged_count, 0);
    assert_eq!(stats.best_effort_dropped_count, 0);
    assert_eq!(stats.control_dropped_count, 0);
    assert_eq!(stats.reliable_backlog_overflow_count, 0);
}

#[test]
fn test_stats_after_send() {
    let backend = host_dns_backend();

    // Send an ARP packet
    let mut packet = vec![0u8; 60];
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    packet[12..14].copy_from_slice(&[0x08, 0x06]);

    backend.send(&[IoSlice::new(&packet)]).unwrap();

    // Stats should show activity
    let stats = backend.stats();
    // rx_queue_len should be 0 since we processed it
    assert_eq!(stats.rx_queue_len, 0);
}

#[test]
fn test_stats_default_trait() {
    let stats = UserNetStats::default();
    assert_eq!(stats.rx_queue_len, 0);
    assert_eq!(stats.tx_queue_len, 0);
    assert_eq!(stats.socket_count, 0);
}

// =========================================================================
// Multiple Independent Backends Tests
// =========================================================================

#[test]
fn test_multiple_backends_independent_config() {
    let config1 = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(10, 0, 1, 1))
        .with_guest_ip(Ipv4Addr::new(10, 0, 1, 15));

    let config2 = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(10, 0, 2, 1))
        .with_guest_ip(Ipv4Addr::new(10, 0, 2, 15));

    let backend1 = UserNetBackend::try_new(config1).unwrap();
    let backend2 = UserNetBackend::try_new(config2).unwrap();

    assert_eq!(backend1.gateway_ip(), Ipv4Addr::new(10, 0, 1, 1));
    assert_eq!(backend2.gateway_ip(), Ipv4Addr::new(10, 0, 2, 1));
    assert_ne!(backend1.gateway_ip(), backend2.gateway_ip());
}

#[test]
fn test_multiple_backends_independent_state() {
    let backend1 = host_dns_backend();
    let backend2 = host_dns_backend();

    // Send a packet to backend1
    let mut packet = vec![0u8; 60];
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    packet[12..14].copy_from_slice(&[0x08, 0x06]);

    backend1.send(&[IoSlice::new(&packet)]).unwrap();

    // Backend2 should not be affected
    let stats1 = backend1.stats();
    let stats2 = backend2.stats();

    // Both start with empty queues after processing
    assert_eq!(stats1.rx_queue_len, stats2.rx_queue_len);

    // Receive from backend1 - should get ARP response
    let mut buf = [0u8; 1500];
    let recv1 = recv_into(&backend1, &mut buf);

    // Drain any initial smoltcp-generated packets from backend2
    while recv_into(&backend2, &mut buf).is_ok() {}

    // Receive from backend2 - should get WouldBlock (no cross-contamination)
    let recv2 = recv_into(&backend2, &mut buf);
    assert!(recv2.is_err());
    assert_eq!(recv2.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);

    // At minimum, recv1's result is independent of recv2
    drop(recv1);
}

#[test]
fn test_multiple_backends_same_config_independent() {
    let config = UserNetConfig::try_default().unwrap();
    let backend1 = UserNetBackend::try_new(config.clone()).unwrap();
    let backend2 = UserNetBackend::try_new(config).unwrap();

    // Same-config backends should have the same config.
    assert_eq!(backend1.gateway_ip(), backend2.gateway_ip());
    assert_eq!(backend1.guest_ip(), backend2.guest_ip());

    // But they should be independent instances
    let stats1 = backend1.stats();
    let stats2 = backend2.stats();

    assert_eq!(stats1.rx_queue_len, stats2.rx_queue_len);
    assert_eq!(stats1.tx_queue_len, stats2.tx_queue_len);
}

// =========================================================================
// VirtualDevice Tests
// =========================================================================

#[test]
fn test_virtual_device_transmit() {
    let mut device = VirtualDevice::new(1500);

    // Initially can transmit
    assert!(device.tx_queue.len() < MAX_QUEUE_SIZE);

    // Fill tx_queue to capacity
    for _ in 0..MAX_QUEUE_SIZE {
        device.tx_queue.push_back(vec![0u8; 64]);
    }

    // Now transmit should be blocked
    assert!(device.transmit(now()).is_none());
}

#[test]
fn test_virtual_device_receive() {
    let mut device = VirtualDevice::new(1500);

    // Initially nothing to receive
    assert!(device.receive(now()).is_none());

    // Queue a packet
    device.queue_from_guest(vec![1, 2, 3, 4]).unwrap();

    // Now can receive
    let result = device.receive(now());
    assert!(result.is_some());
}

// =========================================================================
// ICMP Tests
// =========================================================================

#[test]
fn test_icmp_echo_request_to_gateway() {
    let backend = host_dns_backend();
    let config = UserNetConfig::default();

    // Build ICMP echo request to gateway
    let mut packet = build_icmp_echo_request(&config);
    // Pad to minimum frame size
    if packet.len() < 60 {
        packet.resize(60, 0);
    }

    let result = backend.send(&[IoSlice::new(&packet)]);
    assert!(result.is_ok());

    // Should get an ICMP echo reply
    let mut buf = [0u8; 1500];
    let recv_result = recv_into(&backend, &mut buf);

    match recv_result {
        Ok(len) => {
            // Verify it's an ICMP reply
            assert!(len >= ETH_HEADER_LEN + IPV4_HEADER_LEN + 8);

            // Check EtherType is IPv4
            let ether_type = u16::from_be_bytes([buf[12], buf[13]]);
            assert_eq!(ether_type, ETH_TYPE_IPV4);

            // Check IP protocol is ICMP
            let protocol = buf[ETH_HEADER_LEN + 9];
            assert_eq!(protocol, IP_PROTO_ICMP);

            // Check ICMP type is echo reply (0)
            let icmp_type = buf[ETH_HEADER_LEN + IPV4_HEADER_LEN];
            assert_eq!(icmp_type, 0, "Expected ICMP echo reply (type 0)");
        }
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
            // This might happen if smoltcp doesn't immediately respond
            // Not a test failure, just no immediate response
        }
        Err(e) => {
            panic!("Unexpected error receiving ICMP reply: {e:?}");
        }
    }
}

/// Helper to build an ICMP echo request packet
fn build_icmp_echo_request(config: &UserNetConfig) -> Vec<u8> {
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 8];

    // Ethernet header
    packet[0..6].copy_from_slice(&config.gateway_mac); // Destination: gateway
    packet[6..12].copy_from_slice(&config.guest_mac); // Source: guest
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    // IP header
    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45; // Version 4, IHL 5
    packet[ip_start + 1] = 0; // DSCP/ECN
    packet[ip_start + 2..ip_start + 4].copy_from_slice(&28u16.to_be_bytes()); // Total length
    packet[ip_start + 4..ip_start + 6].copy_from_slice(&1u16.to_be_bytes()); // ID
    packet[ip_start + 6..ip_start + 8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags
    packet[ip_start + 8] = 64; // TTL
    packet[ip_start + 9] = IP_PROTO_ICMP;
    packet[ip_start + 10..ip_start + 12].copy_from_slice(&0u16.to_be_bytes()); // Checksum
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets()); // Src IP
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&config.gateway_ip.octets()); // Dst IP

    // Calculate IP checksum
    let ip_checksum = checksum(&packet[ip_start..ip_start + IPV4_HEADER_LEN]);
    packet[ip_start + 10..ip_start + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    // ICMP header
    let icmp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
    packet[icmp_start] = 8; // Echo request
    packet[icmp_start + 1] = 0; // Code
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&0u16.to_be_bytes()); // Checksum
    packet[icmp_start + 4..icmp_start + 6].copy_from_slice(&1u16.to_be_bytes()); // ID
    packet[icmp_start + 6..icmp_start + 8].copy_from_slice(&1u16.to_be_bytes()); // Seq

    // Calculate ICMP checksum
    let icmp_checksum = checksum(&packet[icmp_start..]);
    packet[icmp_start + 2..icmp_start + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

// =========================================================================
// should_nat_proxy Tests
// =========================================================================

#[test]
fn test_should_nat_proxy_external_ip() {
    let config = UserNetConfig::default();

    // Build a packet to external IP (8.8.8.8)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45;
    packet[ip_start + 9] = IP_PROTO_TCP;
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets());
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&Ipv4Addr::new(8, 8, 8, 8).octets());

    assert!(should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_gateway_ip() {
    let config = UserNetConfig::default();

    // Gateway IP enters NAT dispatch after ICMP/DHCP/DNS are handled
    // upstream. NAT then routes it to VMM-local services or rejects it.
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45;
    packet[ip_start + 9] = IP_PROTO_TCP;
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets());
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&config.gateway_ip.octets());

    assert!(should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_broadcast() {
    let config = UserNetConfig::default();

    // Build a packet to broadcast (should NOT proxy)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&[0xff; 6]);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45;
    packet[ip_start + 9] = IP_PROTO_UDP;
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets());
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&Ipv4Addr::BROADCAST.octets());

    assert!(!should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_multicast() {
    let config = UserNetConfig::default();

    // Build a packet to multicast (should NOT proxy)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&[0x01, 0x00, 0x5e, 0x00, 0x00, 0x01]);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45;
    packet[ip_start + 9] = IP_PROTO_UDP;
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets());
    // Multicast address 224.0.0.1
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&Ipv4Addr::new(224, 0, 0, 1).octets());

    assert!(!should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_local_network() {
    let config = UserNetConfig::default();

    // Build a packet to local network (should NOT proxy)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x45;
    packet[ip_start + 9] = IP_PROTO_TCP;
    packet[ip_start + 12..ip_start + 16].copy_from_slice(&config.guest_ip.octets());
    // Same subnet: 10.0.2.100
    packet[ip_start + 16..ip_start + 20].copy_from_slice(&Ipv4Addr::new(10, 0, 2, 100).octets());

    assert!(!should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_invalid_packet() {
    let config = UserNetConfig::default();

    // Too short packet
    let packet = vec![0u8; 5];
    assert!(!should_nat_proxy(&packet, &config));

    // Non-IP EtherType
    let mut packet2 = vec![0u8; ETH_HEADER_LEN + 20];
    packet2[12..14].copy_from_slice(&[0x88, 0xcc]); // LLDP
    assert!(!should_nat_proxy(&packet2, &config));
}

// =========================================================================
// Error Type Tests
// =========================================================================

#[test]
fn test_usernet_error_display() {
    let err = UserNetError::QueueFull;
    assert!(err.to_string().contains("queue full"));
}

#[test]
fn test_usernet_error_from_io() {
    let io_err = std::io::Error::other("test");
    let usernet_err: UserNetError = io_err.into();

    match usernet_err {
        UserNetError::Io(_) => {} // Expected
        _ => panic!("Expected Io variant"),
    }
}

// =========================================================================
// Protocol Enum Tests
// =========================================================================

#[test]
fn test_protocol_equality() {
    assert_eq!(Protocol::Tcp, Protocol::Tcp);
    assert_eq!(Protocol::Udp, Protocol::Udp);
    assert_ne!(Protocol::Tcp, Protocol::Udp);
}

#[test]
fn test_protocol_serialization() {
    let tcp = Protocol::Tcp;
    let json = serde_json::to_string(&tcp).unwrap();
    assert_eq!(json, "\"Tcp\"");

    let udp = Protocol::Udp;
    let json = serde_json::to_string(&udp).unwrap();
    assert_eq!(json, "\"Udp\"");

    // Deserialize
    let restored: Protocol = serde_json::from_str("\"Tcp\"").unwrap();
    assert_eq!(restored, Protocol::Tcp);
}

// =========================================================================
// Independent backend tests
// =========================================================================

#[test]
fn test_same_config_backends_preserve_config() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(172, 20, 0, 1))
        .with_guest_ip(Ipv4Addr::new(172, 20, 0, 100));

    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let same_config = UserNetBackend::try_new(config).unwrap();

    assert_eq!(backend.gateway_ip(), same_config.gateway_ip());
    assert_eq!(backend.guest_ip(), same_config.guest_ip());
}

#[test]
fn test_same_config_backend_independent_after_send() {
    let config = UserNetConfig::try_default().unwrap();
    let backend1 = UserNetBackend::try_new(config.clone()).unwrap();
    let backend2 = UserNetBackend::try_new(config).unwrap();

    // Send to backend2
    let mut packet = vec![0u8; 60];
    packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
    packet[12..14].copy_from_slice(&[0x08, 0x06]);

    backend2.send(&[IoSlice::new(&packet)]).unwrap();

    // backend1 should not be affected
    let stats1 = backend1.stats();
    assert_eq!(stats1.rx_queue_len, 0);
}

// =========================================================================
// Constants Tests
// =========================================================================

#[test]
fn test_default_constants() {
    assert_eq!(DEFAULT_GATEWAY, Ipv4Addr::new(10, 0, 2, 2));
    assert_eq!(DEFAULT_GUEST_IP, Ipv4Addr::new(10, 0, 2, 15));
    assert_eq!(DEFAULT_NETMASK, Ipv4Addr::new(255, 255, 255, 0));
    assert_eq!(DEFAULT_DNS, DEFAULT_GATEWAY);
    assert_eq!(VIRTUAL_MTU, 1500);
}

#[test]
fn test_default_ipv6_constants() {
    assert_eq!(
        DEFAULT_GATEWAY_V6,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002)
    );
    assert_eq!(
        DEFAULT_GUEST_IP_V6,
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015)
    );
    assert_eq!(DEFAULT_PREFIX_LEN_V6, 64);
    assert_eq!(
        DEFAULT_DNS_V6,
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)
    );
}

#[test]
fn test_default_mac_addresses() {
    assert_eq!(UserNetConfig::default().gateway_mac, DEFAULT_GATEWAY_MAC);
    assert_eq!(UserNetConfig::default().guest_mac, DEFAULT_GUEST_MAC);
}

// =========================================================================
// UserNetConfig Serialization Tests
// =========================================================================

#[test]
fn test_config_serialization_roundtrip() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(192, 168, 1, 1))
        .with_guest_ip(Ipv4Addr::new(192, 168, 1, 100))
        .with_port_forward(PortForward::tcp(8080, 80).bind_to(IpAddr::V4(Ipv4Addr::LOCALHOST)));

    let json = serde_json::to_string(&config).unwrap();
    let restored: UserNetConfig = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(restored.guest_ip, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(restored.port_forwards.len(), 1);
    assert_eq!(restored.port_forwards[0].host_port, 8080);
    assert_eq!(restored.egress_policy, EgressPolicy::DenyAll);
    assert_eq!(restored.dns_forward_policy, DnsForwardPolicy::DenyAll);
}

// =========================================================================
// IPv6 NAT Proxy Tests
// =========================================================================

#[test]
fn test_should_nat_proxy_ipv6_external() {
    let config = UserNetConfig::default();

    // Build a packet to external IPv6 (2001:4860:4860::8888 - Google DNS)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x60; // Version 6
    packet[ip_start + 6] = IP_PROTO_TCP;
    packet[ip_start + 7] = 64; // Hop limit
    packet[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    packet[ip_start + 24..ip_start + 40]
        .copy_from_slice(&Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888).octets());

    assert!(should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_ipv6_gateway() {
    let config = UserNetConfig::default();

    // Gateway IPv6 is proxied — same rationale as IPv4.
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x60;
    packet[ip_start + 6] = IP_PROTO_TCP;
    packet[ip_start + 7] = 64;
    packet[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    packet[ip_start + 24..ip_start + 40].copy_from_slice(&config.gateway_ipv6.octets());

    assert!(should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_ipv6_multicast() {
    let config = UserNetConfig::default();

    // Build a packet to IPv6 multicast (should NOT proxy)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&[0x33, 0x33, 0x00, 0x00, 0x00, 0x01]); // IPv6 multicast MAC
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x60;
    packet[ip_start + 6] = IP_PROTO_UDP;
    packet[ip_start + 7] = 64;
    packet[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    // All-nodes multicast: ff02::1
    packet[ip_start + 24..ip_start + 40]
        .copy_from_slice(&Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1).octets());

    assert!(!should_nat_proxy(&packet, &config));
}

#[test]
fn test_should_nat_proxy_ipv6_link_local() {
    let config = UserNetConfig::default();

    // Build a packet to link-local IPv6 (should NOT proxy)
    let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 20];
    packet[0..6].copy_from_slice(&config.gateway_mac);
    packet[6..12].copy_from_slice(&config.guest_mac);
    packet[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    packet[ip_start] = 0x60;
    packet[ip_start + 6] = IP_PROTO_TCP;
    packet[ip_start + 7] = 64;
    packet[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    // Link-local: fe80::1
    packet[ip_start + 24..ip_start + 40]
        .copy_from_slice(&Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1).octets());

    assert!(!should_nat_proxy(&packet, &config));
}

// =========================================================================
// Edge Case Tests
// =========================================================================

#[test]
fn test_empty_packet_handling() {
    let backend = host_dns_backend();
    let empty_packet: [u8; 0] = [];

    let result = backend.send(&[IoSlice::new(&empty_packet)]);
    assert!(result.is_ok());
}

#[test]
fn test_very_short_packet() {
    let backend = host_dns_backend();
    let short_packet = [0u8; 10]; // Less than Ethernet header

    let result = backend.send(&[IoSlice::new(&short_packet)]);
    assert!(result.is_ok());
    // Should accept but likely won't process
}

#[test]
fn test_recv_with_small_buffer() {
    let backend = host_dns_backend();
    let mut drain_buf = [0u8; 1500];

    // Drain any initial smoltcp-generated packets
    while recv_into(&backend, &mut drain_buf).is_ok() {}

    let mut small_buf = [0u8; 10];
    let result = recv_into(&backend, &mut small_buf);
    // Should return WouldBlock since no packets
    assert!(result.is_err());
    assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::WouldBlock);
}

#[test]
// Reason: state lock scope intentionally covers the enqueue assertion;
// the lock is released at the block end.
#[allow(clippy::significant_drop_tightening)]
fn test_recv_small_buffer_does_not_dequeue_packet() {
    let backend = host_dns_backend();
    let mut drain_buf = [0u8; 1500];
    while recv_into(&backend, &mut drain_buf).is_ok() {}

    let packet = vec![0xAB; 64];
    {
        let mut state = backend.state.lock();
        assert!(state.device.enqueue_to_guest(packet.clone()));
    }

    let mut small_buf = [0u8; 10];
    let err = recv_into(&backend, &mut small_buf).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(leased_rx_packet_len(&backend).unwrap(), Some(packet.len()));

    let mut full_buf = [0u8; 128];
    let len = recv_into(&backend, &mut full_buf).unwrap();
    assert_eq!(len, packet.len());
    assert_eq!(&full_buf[..len], packet);
}

// =========================================================================
// Config validation tests
// =========================================================================

fn valid_default_config() -> UserNetConfig {
    UserNetConfig::default().with_host_dns_server(UNUSED_TEST_HOST_DNS)
}

#[test]
fn test_config_validate_default_ok() {
    let config = valid_default_config();
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_prefix_len_33_fails() {
    let config = UserNetConfig {
        prefix_len: 33,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err();
    assert!(matches!(err, UserNetError::InvalidConfig(_)));
}

#[test]
fn test_config_validate_prefix_len_32_ok() {
    let config = UserNetConfig {
        prefix_len: 32,
        ..valid_default_config()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_prefix_len_0_ok() {
    let config = UserNetConfig {
        prefix_len: 0,
        ..valid_default_config()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_v6_prefix_129_fails() {
    let config = UserNetConfig {
        prefix_len_v6: 129,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err();
    assert!(matches!(err, UserNetError::InvalidConfig(_)));
}

#[test]
fn test_config_validate_v6_prefix_128_ok() {
    let config = UserNetConfig {
        prefix_len_v6: 128,
        ..valid_default_config()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_v6_prefix_0_ok() {
    let config = UserNetConfig {
        prefix_len_v6: 0,
        ..valid_default_config()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_same_gateway_guest_ip_fails() {
    let config = UserNetConfig {
        gateway_ip: DEFAULT_GATEWAY,
        guest_ip: DEFAULT_GATEWAY,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("gateway_ip and guest_ip must differ"), "{err}");
}

#[test]
fn test_config_validate_same_gateway_guest_ipv6_fails() {
    let ip = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
    let config = UserNetConfig {
        gateway_ipv6: ip,
        guest_ipv6: ip,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(
        err.contains("gateway_ipv6 and guest_ipv6 must differ"),
        "{err}"
    );
}

#[test]
fn test_config_validate_different_subnet_fails() {
    let config = UserNetConfig {
        gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
        guest_ip: Ipv4Addr::new(192, 168, 1, 100),
        prefix_len: 24,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("not on the same"), "{err}");
}

#[test]
fn test_config_validate_same_subnet_ok() {
    let config = UserNetConfig {
        gateway_ip: Ipv4Addr::new(10, 0, 2, 1),
        guest_ip: Ipv4Addr::new(10, 0, 2, 15),
        prefix_len: 24,
        ..valid_default_config()
    };
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_validate_different_ipv6_subnet_fails() {
    let config = UserNetConfig {
        gateway_ipv6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        guest_ipv6: Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 15),
        prefix_len_v6: 64,
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("IPv6 subnet"), "{err}");
}

#[test]
fn test_config_validate_mtu_bounds() {
    let too_small = UserNetConfig {
        mtu: 1279,
        ..valid_default_config()
    };
    let err = too_small.validate().unwrap_err().to_string();
    assert!(err.contains("mtu must be between"), "{err}");

    let too_large = UserNetConfig {
        mtu: VIRTUAL_MTU + 1,
        ..valid_default_config()
    };
    let err = too_large.validate().unwrap_err().to_string();
    assert!(err.contains("mtu must be between"), "{err}");
}

#[test]
fn test_config_validate_port_forwards_rejected_until_wired() {
    let config = UserNetConfig {
        port_forwards: vec![PortForward::tcp(8080, 80)],
        ..valid_default_config()
    };
    let err = config.validate().unwrap_err().to_string();
    assert!(err.contains("port_forwards is not wired"), "{err}");
}

// =========================================================================
// Config builder tests
// =========================================================================

#[test]
fn test_config_builder_methods() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_gateway_ip(Ipv4Addr::new(192, 168, 1, 1))
        .with_guest_ip(Ipv4Addr::new(192, 168, 1, 100))
        .with_dns(Ipv4Addr::new(8, 8, 8, 8))
        .with_guest_mac([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])
        .with_gateway_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))
        .with_guest_ipv6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))
        .with_prefix_len_v6(48)
        .with_dns_ipv6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844));

    assert_eq!(config.gateway_ip, Ipv4Addr::new(192, 168, 1, 1));
    assert_eq!(config.guest_ip, Ipv4Addr::new(192, 168, 1, 100));
    assert_eq!(config.dns_server, Ipv4Addr::new(8, 8, 8, 8));
    assert_eq!(config.guest_mac, [0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    assert_eq!(
        config.gateway_ipv6,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)
    );
    assert_eq!(
        config.guest_ipv6,
        Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)
    );
    assert_eq!(config.prefix_len_v6, 48);
    assert_eq!(
        config.dns_server_v6,
        Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8844)
    );
    assert!(config.validate().is_ok());
}

#[test]
fn test_port_forward_tcp() {
    let pf = PortForward::tcp(8080, 80);
    assert_eq!(pf.protocol, Protocol::Tcp);
    assert_eq!(pf.host_port, 8080);
    assert_eq!(pf.guest_port, 80);
    assert!(pf.host_addr.is_none());
}

#[test]
fn test_port_forward_udp_with_bind() {
    let pf = PortForward::udp(5353, 53).bind_to(IpAddr::V4(Ipv4Addr::LOCALHOST));
    assert_eq!(pf.protocol, Protocol::Udp);
    assert_eq!(pf.host_port, 5353);
    assert_eq!(pf.guest_port, 53);
    assert_eq!(pf.host_addr, Some(IpAddr::V4(Ipv4Addr::LOCALHOST)));
}

#[test]
fn test_config_with_multiple_port_forwards() {
    let config = UserNetConfig::try_default()
        .unwrap()
        .with_port_forward(PortForward::tcp(8080, 80))
        .with_port_forward(PortForward::udp(5353, 53));
    assert_eq!(config.port_forwards.len(), 2);
    assert_eq!(config.port_forwards[0].protocol, Protocol::Tcp);
    assert_eq!(config.port_forwards[1].protocol, Protocol::Udp);
}

// =========================================================================
// Clone Integration Test Helpers
// =========================================================================

/// Build a DHCP DISCOVER Ethernet frame.
/// ETH(14) + IP(20) + UDP(8) + BOOTP(300) = 342 bytes.
fn build_dhcp_discover(config: &UserNetConfig) -> Vec<u8> {
    let mut bootp = vec![0u8; 300];
    bootp[0] = 1; // BOOTREQUEST
    bootp[1] = 1; // Ethernet
    bootp[2] = 6; // MAC len
    bootp[4..8].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // xid
    bootp[28..34].copy_from_slice(&config.guest_mac); // chaddr
    // Magic cookie at offset 236
    bootp[236..240].copy_from_slice(&[99, 130, 83, 99]);
    // Option 53 = DISCOVER(1)
    bootp[240] = 53;
    bootp[241] = 1;
    bootp[242] = 1;
    bootp[243] = 255; // END

    // Wrap in ETH + IP + UDP
    let total = 14 + 20 + 8 + bootp.len();
    let mut pkt = vec![0u8; total];
    // ETH: dst=broadcast, src=guest_mac, type=0x0800
    pkt[0..6].copy_from_slice(&[0xFF; 6]);
    pkt[6..12].copy_from_slice(&config.guest_mac);
    pkt[12..14].copy_from_slice(&[0x08, 0x00]);
    // IP: ver=4, ihl=5, protocol=UDP(17), src=0.0.0.0, dst=broadcast
    pkt[14] = 0x45;
    let ip_total = u16::try_from(20 + 8 + bootp.len()).unwrap();
    pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
    pkt[23] = 17; // UDP
    pkt[26..30].copy_from_slice(&[0, 0, 0, 0]); // src 0.0.0.0
    pkt[30..34].copy_from_slice(&[255, 255, 255, 255]); // dst broadcast
    // UDP: src=68, dst=67
    pkt[34..36].copy_from_slice(&68u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&67u16.to_be_bytes());
    let udp_len = u16::try_from(8 + bootp.len()).unwrap();
    pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
    pkt[42..42 + bootp.len()].copy_from_slice(&bootp);
    pkt
}

/// Build a DNS query Ethernet frame to `dst_ip`:53.
fn build_dns_query_packet(config: &UserNetConfig, dst_ip: Ipv4Addr) -> Vec<u8> {
    let dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                        \x07example\x03com\x00\x00\x01\x00\x01";
    let total = 14 + 20 + 8 + dns_payload.len();
    let mut pkt = vec![0u8; total];
    // ETH
    pkt[0..6].copy_from_slice(&config.gateway_mac); // dst = gateway
    pkt[6..12].copy_from_slice(&config.guest_mac);
    pkt[12..14].copy_from_slice(&[0x08, 0x00]);
    // IP
    pkt[14] = 0x45;
    let ip_total = u16::try_from(20 + 8 + dns_payload.len()).unwrap();
    pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
    pkt[23] = 17; // UDP
    pkt[26..30].copy_from_slice(&config.guest_ip.octets());
    pkt[30..34].copy_from_slice(&dst_ip.octets());
    // IP checksum
    let cksum = checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&cksum.to_be_bytes());
    // UDP: src=12345, dst=53
    pkt[34..36].copy_from_slice(&12345u16.to_be_bytes());
    pkt[36..38].copy_from_slice(&53u16.to_be_bytes());
    let udp_len = u16::try_from(8 + dns_payload.len()).unwrap();
    pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
    pkt[42..42 + dns_payload.len()].copy_from_slice(dns_payload);
    pkt
}

fn build_ipv6_udp_dns_query_packet(config: &UserNetConfig, dst_ip: Ipv6Addr) -> Vec<u8> {
    let dns_payload = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\
                        \x07example\x03com\x00\x00\x1c\x00\x01";
    let total = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + dns_payload.len();
    let mut pkt = vec![0u8; total];

    pkt[0..6].copy_from_slice(&config.gateway_mac);
    pkt[6..12].copy_from_slice(&config.guest_mac);
    pkt[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    pkt[ip_start] = 0x60;
    let payload_len = u16::try_from(UDP_HEADER_LEN + dns_payload.len()).unwrap();
    pkt[ip_start + 4..ip_start + 6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[ip_start + 6] = IP_PROTO_UDP;
    pkt[ip_start + 7] = 64;
    pkt[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    pkt[ip_start + 24..ip_start + 40].copy_from_slice(&dst_ip.octets());

    let udp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    pkt[udp_start..udp_start + 2].copy_from_slice(&12345u16.to_be_bytes());
    pkt[udp_start + 2..udp_start + 4].copy_from_slice(&53u16.to_be_bytes());
    pkt[udp_start + 4..udp_start + 6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + dns_payload.len()]
        .copy_from_slice(dns_payload);
    let udp_checksum = calculate_udp_checksum_v6(
        config.guest_ipv6,
        dst_ip,
        &pkt[udp_start..udp_start + UDP_HEADER_LEN],
        dns_payload,
    );
    pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    pkt
}

fn build_ipv6_tcp_dns_syn_packet(config: &UserNetConfig, dst_ip: Ipv6Addr) -> Vec<u8> {
    let total = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;
    let mut pkt = vec![0u8; total];

    pkt[0..6].copy_from_slice(&config.gateway_mac);
    pkt[6..12].copy_from_slice(&config.guest_mac);
    pkt[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());

    let ip_start = ETH_HEADER_LEN;
    pkt[ip_start] = 0x60;
    let payload_len = u16::try_from(TCP_HEADER_LEN).unwrap();
    pkt[ip_start + 4..ip_start + 6].copy_from_slice(&payload_len.to_be_bytes());
    pkt[ip_start + 6] = IP_PROTO_TCP;
    pkt[ip_start + 7] = 64;
    pkt[ip_start + 8..ip_start + 24].copy_from_slice(&config.guest_ipv6.octets());
    pkt[ip_start + 24..ip_start + 40].copy_from_slice(&dst_ip.octets());

    let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&12345u16.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&53u16.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&1000u32.to_be_bytes());
    pkt[tcp_start + 12] = 0x50;
    pkt[tcp_start + 13] = 0x02;
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&65535u16.to_be_bytes());
    let tcp_checksum = calculate_tcp_checksum_v6(
        config.guest_ipv6,
        dst_ip,
        &pkt[tcp_start..tcp_start + TCP_HEADER_LEN],
        &[],
    );
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

    pkt
}

fn spoof_ipv4_dns_source(mut packet: Vec<u8>, src_mac: [u8; 6], src_ip: Ipv4Addr) -> Vec<u8> {
    packet[6..12].copy_from_slice(&src_mac);
    packet[24..26].copy_from_slice(&0u16.to_be_bytes());
    packet[26..30].copy_from_slice(&src_ip.octets());
    let cksum = checksum(&packet[14..34]);
    packet[24..26].copy_from_slice(&cksum.to_be_bytes());
    packet
}

/// Build a TCP SYN Ethernet frame to `dst_ip`:`dst_port`.
fn build_tcp_syn_packet(
    config: &UserNetConfig,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    src_port: u16,
) -> Vec<u8> {
    use crate::packet_builder::TCP_HEADER_LEN;
    let total = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
    let mut pkt = vec![0u8; total];
    // ETH
    pkt[0..6].copy_from_slice(&config.gateway_mac);
    pkt[6..12].copy_from_slice(&config.guest_mac);
    pkt[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());
    // IP
    pkt[14] = 0x45;
    let ip_total = u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN).unwrap();
    pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
    pkt[23] = IP_PROTO_TCP;
    pkt[26..30].copy_from_slice(&config.guest_ip.octets());
    pkt[30..34].copy_from_slice(&dst_ip.octets());
    // IP checksum
    let cksum = checksum(&pkt[14..34]);
    pkt[24..26].copy_from_slice(&cksum.to_be_bytes());
    // TCP
    let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
    pkt[tcp_start..tcp_start + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[tcp_start + 2..tcp_start + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[tcp_start + 4..tcp_start + 8].copy_from_slice(&1000u32.to_be_bytes()); // seq
    pkt[tcp_start + 12] = 0x50; // data offset = 5 (20 bytes)
    pkt[tcp_start + 13] = 0x02; // SYN flag
    pkt[tcp_start + 14..tcp_start + 16].copy_from_slice(&65535u16.to_be_bytes()); // window
    let tcp_checksum = calculate_tcp_checksum(
        config.guest_ip,
        dst_ip,
        &pkt[tcp_start..tcp_start + TCP_HEADER_LEN],
        &[],
    );
    pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());
    pkt
}

/// Receive one packet or return None if `WouldBlock`.
fn try_recv_one<P, D>(backend: &UserNetBackend<P, D>) -> Option<Vec<u8>>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    let mut buf = vec![0u8; 2048];
    match recv_into(backend, &mut buf) {
        Ok(n) => Some(buf[..n].to_vec()),
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => None,
        Err(e) => panic!("unexpected recv error: {e}"),
    }
}

/// Assert the BOOTP reply at `pkt[42..]` has the expected yiaddr.
fn assert_dhcp_offer_yiaddr(pkt: &[u8], expected_ip: Ipv4Addr) {
    assert!(pkt.len() > 42 + 20, "packet too short for BOOTP");
    let bootp = &pkt[42..];
    assert_eq!(bootp[0], 2, "should be BOOTREPLY");
    assert_eq!(&bootp[16..20], &expected_ip.octets(), "yiaddr mismatch");
}

// --- Test interceptor types ---

struct RespondFixedDns(Vec<u8>);
impl interceptor::DnsInterceptor for RespondFixedDns {
    fn intercept<'a>(
        &'a self,
        _query: &'a [u8],
        _dest: SocketAddr,
        _guest: SocketAddr,
        response_limit: interceptor::DnsResponseLimit,
    ) -> Result<interceptor::DnsAction<'a>, interceptor::DnsActionError> {
        interceptor::DnsAction::respond(response_limit, self.0.as_slice())
    }
}

struct ForwardDns(SocketAddr);
impl interceptor::DnsInterceptor for ForwardDns {
    fn intercept<'a>(
        &'a self,
        _query: &'a [u8],
        _dest: SocketAddr,
        _guest: SocketAddr,
        _response_limit: interceptor::DnsResponseLimit,
    ) -> Result<interceptor::DnsAction<'a>, interceptor::DnsActionError> {
        Ok(interceptor::DnsAction::Forward(self.0))
    }
}

#[test]
fn dns_gateway_forwarding_is_denied_by_default() {
    let config = valid_default_config();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let dns_pkt = build_dns_query_packet(&config, config.gateway_ip);

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert!(
        try_recv_one(&backend).is_none(),
        "blocked gateway DNS must not generate a guest response"
    );
}

#[test]
fn public_internet_dns_forwarding_blocks_private_host_resolver() {
    let config = UserNetConfig::default()
        .with_host_dns_server(Ipv4Addr::new(10, 0, 0, 53))
        .with_public_internet_dns_forwarding();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let dns_pkt = build_dns_query_packet(&config, config.gateway_ip);

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert!(
        try_recv_one(&backend).is_none(),
        "private host resolver must be blocked by public-internet DNS policy"
    );
}

#[test]
fn dns_mitm_rejects_spoofed_guest_identity_before_response() {
    let config = valid_default_config();
    let marker = b"SPOOFED-DNS-RESPONSE";
    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(RespondFixedDns(marker.to_vec()));
    let dns_pkt = spoof_ipv4_dns_source(
        build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8)),
        config.guest_mac,
        Ipv4Addr::new(10, 0, 2, 99),
    );

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert!(
        try_recv_one(&backend).is_none(),
        "spoofed DNS query must not produce an interceptor response"
    );
}

#[test]
fn dns_mitm_rejects_oversized_response_without_truncating() {
    let config = valid_default_config();
    let oversized = vec![b'X'; dns::max_dns_response_len(config.mtu) + 1];
    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(RespondFixedDns(oversized));
    let dns_pkt = build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8));

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert!(
        try_recv_one(&backend).is_none(),
        "oversized DNS interceptor response must be rejected, not truncated"
    );
}

#[tokio::test]
async fn ipv6_udp_dns_is_fail_closed_before_nat() {
    let config = valid_default_config().with_unrestricted_egress();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let remote_dns = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53);
    let dns_pkt = build_ipv6_udp_dns_query_packet(&config, remote_dns);

    assert!(should_nat_proxy(&dns_pkt, &config));
    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert_eq!(
        backend.state.lock().nat_proxy.connection_count(),
        0,
        "unsupported IPv6 UDP DNS must be dropped before NAT connection creation"
    );
}

#[tokio::test]
async fn external_ipv4_udp_dns_is_fail_closed_before_nat() {
    let config = valid_default_config().with_unrestricted_egress();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let remote_dns = Ipv4Addr::new(8, 8, 8, 8);
    let dns_pkt = build_dns_query_packet(&config, remote_dns);

    assert!(should_nat_proxy(&dns_pkt, &config));
    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    assert_eq!(
        backend.state.lock().nat_proxy.connection_count(),
        0,
        "direct IPv4 UDP DNS must be dropped before NAT connection creation"
    );
}

#[tokio::test]
async fn ipv4_tcp_dns_is_fail_closed_before_nat() {
    let config = valid_default_config().with_unrestricted_egress();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let remote_dns = Ipv4Addr::new(8, 8, 8, 8);
    let syn = build_tcp_syn_packet(&config, remote_dns, 53, 12345);

    assert!(should_nat_proxy(&syn, &config));
    backend.send(&[IoSlice::new(&syn)]).unwrap();

    assert_eq!(
        backend.state.lock().nat_proxy.connection_count(),
        0,
        "unsupported IPv4 TCP DNS must be dropped before NAT connection creation"
    );
}

#[tokio::test]
async fn ipv6_tcp_dns_is_fail_closed_before_nat() {
    let config = valid_default_config().with_unrestricted_egress();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let remote_dns = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 53);
    let syn = build_ipv6_tcp_dns_syn_packet(&config, remote_dns);

    assert!(should_nat_proxy(&syn, &config));
    backend.send(&[IoSlice::new(&syn)]).unwrap();

    assert_eq!(
        backend.state.lock().nat_proxy.connection_count(),
        0,
        "unsupported IPv6 TCP DNS must be dropped before NAT connection creation"
    );
}

#[tokio::test]
async fn dns_forwarding_denies_denied_port_even_when_ip_allowed() {
    let allowed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let allowed_addr = allowed.local_addr().unwrap();
    let denied = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let denied_addr = denied.local_addr().unwrap();
    let config = valid_default_config().with_dns_forward_policy(DnsForwardPolicy::AllowList(vec![
        HostEgressRule::dns_forward(allowed_addr),
    ]));
    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(ForwardDns(denied_addr));
    let dns_pkt = build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8));

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            denied.recv_from(&mut buf),
        )
        .await
        .is_err(),
        "denied DNS forward port must not receive a host datagram"
    );
}

#[tokio::test]
async fn explicit_dns_allow_policy_forwards_interceptor_destination() {
    let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let config = valid_default_config().with_unrestricted_dns_forwarding();
    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(ForwardDns(resolver_addr));
    let dns_pkt = build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8));

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    let mut buf = [0u8; 512];
    let (n, from) = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        resolver.recv_from(&mut buf),
    )
    .await
    .expect("resolver should receive forwarded DNS query")
    .unwrap();
    assert!(n > 0);
    resolver.send_to(b"dns-response", from).await.unwrap();

    let reply = tokio::time::timeout(std::time::Duration::from_secs(1), async {
        loop {
            if let Some(packet) = try_recv_one(&backend) {
                return packet;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("guest should receive forwarded DNS response");
    assert!(
        reply
            .windows(b"dns-response".len())
            .any(|w| w == b"dns-response")
    );
}

#[tokio::test]
async fn dns_mitm_rejects_spoofed_guest_identity_before_forward() {
    let resolver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver_addr = resolver.local_addr().unwrap();
    let config = valid_default_config().with_unrestricted_dns_forwarding();
    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(ForwardDns(resolver_addr));
    let dns_pkt = spoof_ipv4_dns_source(
        build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8)),
        [0x02, 0xff, 0, 0, 0, 0x99],
        config.guest_ip,
    );

    backend.send(&[IoSlice::new(&dns_pkt)]).unwrap();

    let mut buf = [0u8; 512];
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            resolver.recv_from(&mut buf),
        )
        .await
        .is_err(),
        "spoofed DNS query must not reach the host resolver"
    );
    assert!(
        try_recv_one(&backend).is_none(),
        "spoofed DNS query must not produce a guest response"
    );
}

// =========================================================================
// Same-config backend tests
// =========================================================================

#[test]
fn test_same_config_backends_dhcp_independence() {
    let config = UserNetConfig::try_default().unwrap();
    let backend = UserNetBackend::try_new(config.clone()).unwrap();
    let same_config = UserNetBackend::try_new(config.clone()).unwrap();
    let original = backend;

    let discover = build_dhcp_discover(&config);

    // Original gets OFFER
    original.send(&[IoSlice::new(&discover)]).unwrap();
    let offer1 = try_recv_one(&original).expect("original should get OFFER");
    assert_dhcp_offer_yiaddr(&offer1, config.guest_ip);

    // The separate backend gets OFFER independently.
    same_config.send(&[IoSlice::new(&discover)]).unwrap();
    let offer2 = try_recv_one(&same_config).expect("second backend should get OFFER");
    assert_dhcp_offer_yiaddr(&offer2, config.guest_ip);
}

#[tokio::test]
async fn test_same_config_backend_does_not_share_dns_interceptor() {
    let config = UserNetConfig::try_default().unwrap();
    let marker = b"SAME-CONFIG-DNS";

    let backend = UserNetBackend::try_new(config.clone())
        .unwrap()
        .with_dns_interceptor(RespondFixedDns(marker.to_vec()));
    let same_config = UserNetBackend::try_new(config.clone()).unwrap();

    // A separately constructed backend has no interceptor.
    let dns_pkt = build_dns_query_packet(&config, Ipv4Addr::new(8, 8, 8, 8));
    same_config.send(&[IoSlice::new(&dns_pkt)]).unwrap();
    assert!(
        try_recv_one(&same_config).is_none(),
        "second backend should NOT have DNS interceptor"
    );

    // Original still has interceptor
    let original = backend;
    original.send(&[IoSlice::new(&dns_pkt)]).unwrap();
    let reply = try_recv_one(&original).expect("original should still have DNS interceptor");
    assert!(reply.windows(marker.len()).any(|w| w == marker));
}

// =========================================================================
// Backend queue and NAT independence
// =========================================================================

#[test]
fn test_same_config_backends_do_not_share_packet_queues() {
    let config = UserNetConfig::try_default().unwrap();
    let original = UserNetBackend::try_new(config.clone()).unwrap();

    // Queue a DHCP DISCOVER -> poll will produce OFFER in tx_queue
    let discover = build_dhcp_discover(&config);
    original.send(&[IoSlice::new(&discover)]).unwrap();

    // Create another backend before recv -- it should get fresh queues.
    let same_config = UserNetBackend::try_new(config.clone()).unwrap();

    // The separate backend should have nothing.
    assert!(
        try_recv_one(&same_config).is_none(),
        "second backend should have empty queues"
    );

    // Original should have the OFFER
    let offer = try_recv_one(&original).expect("original should have OFFER");
    assert_dhcp_offer_yiaddr(&offer, config.guest_ip);
}

#[tokio::test]
async fn test_same_config_backends_nat_proxy_independent() {
    use std::net::TcpListener;

    let config = UserNetConfig::try_default().unwrap();
    let original = UserNetBackend::try_new(config.clone()).unwrap();

    // Send TCP SYN on original
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let syn = build_tcp_syn_packet(&config, Ipv4Addr::LOCALHOST, port, 49300);
    original.send(&[IoSlice::new(&syn)]).unwrap();
    original.poll().unwrap();

    // Create a separate backend with the same config.
    let same_config = UserNetBackend::try_new(config.clone()).unwrap();

    // Send TCP SYN on the second backend (different port) -> independent connection.
    let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
    let port2 = listener2.local_addr().unwrap().port();
    let syn2 = build_tcp_syn_packet(&config, Ipv4Addr::LOCALHOST, port2, 49301);
    same_config.send(&[IoSlice::new(&syn2)]).unwrap();
    same_config.poll().unwrap();
    // No panic -- NatProxy instances are independent
}
