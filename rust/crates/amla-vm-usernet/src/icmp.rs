// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use crate::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, ETH_TYPE_IPV6, EthernetHeader, IP_PROTO_ICMP, IP_PROTO_ICMPV6,
    IPV4_HEADER_LEN, IPV6_HEADER_LEN, Ipv4Header, Ipv6Header, checksum_fold, mtu_bounded_u16,
    mtu_bounded_u32, parse_ip_packet,
};
use crate::{UserNetConfig, ipv4_mask, ipv6_mask};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Check if a packet should be NAT proxied.
///
/// Returns true for any non-local IP destination. Gateway IP is included
/// because ICMP/DHCP/DNS are already handled by earlier stages in
/// `handle_guest_packet()` — remaining gateway-destined traffic (TCP/UDP)
/// is dispatched by `NatProxy` to VMM-provided gateway services or rejected
/// locally. It must not leak to the host network namespace as a socket
/// connection to the guest-visible gateway address.
pub fn should_nat_proxy(packet: &[u8], config: &UserNetConfig) -> bool {
    // Parse Ethernet header
    let Some(eth) = EthernetHeader::parse(packet) else {
        return false;
    };

    if eth.ether_type == ETH_TYPE_IPV4 {
        // Parse IP header to get destination
        if packet.len() < ETH_HEADER_LEN + 20 {
            return false;
        }

        let ip_start = ETH_HEADER_LEN;
        // Destination IP is at offset 16 in IP header
        let dst_ip = Ipv4Addr::new(
            packet[ip_start + 16],
            packet[ip_start + 17],
            packet[ip_start + 18],
            packet[ip_start + 19],
        );

        // Check if destination is outside our local network
        let dst_bits = u32::from(dst_ip);
        let gateway_bits = u32::from(config.gateway_ip);
        let mask_bits = ipv4_mask(config.prefix_len);

        // Exclude broadcasts and multicast - these should be handled locally by smoltcp
        // Limited broadcast (255.255.255.255) is used for DHCP
        // Subnet-directed broadcast (e.g., 10.0.2.255) for local services
        // Multicast (224.0.0.0/4) for mDNS, IGMP, etc.
        let subnet_broadcast = (gateway_bits & mask_bits) | !mask_bits;
        if dst_ip == Ipv4Addr::BROADCAST || dst_bits == subnet_broadcast || dst_ip.is_multicast() {
            return false;
        }

        let should_proxy =
            (dst_bits & mask_bits) != (gateway_bits & mask_bits) || dst_ip == config.gateway_ip;

        if should_proxy {
            log::trace!("NAT proxy: intercepting packet to {dst_ip}");
        }

        should_proxy
    } else if eth.ether_type == ETH_TYPE_IPV6 {
        if packet.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
            return false;
        }

        let Some(ip) = Ipv6Header::parse(&packet[ETH_HEADER_LEN..]) else {
            return false;
        };

        let dst_ip = ip.dst_ip;
        if dst_ip.is_multicast()
            || dst_ip.is_unspecified()
            || dst_ip.is_loopback()
            || dst_ip.is_unicast_link_local()
        {
            return false;
        }

        let mask_bits = ipv6_mask(config.prefix_len_v6);
        let dst_bits = u128::from(dst_ip);
        let gateway_bits = u128::from(config.gateway_ipv6);

        let should_proxy =
            (dst_bits & mask_bits) != (gateway_bits & mask_bits) || dst_ip == config.gateway_ipv6;

        if should_proxy {
            log::trace!("NAT proxy: intercepting packet to {dst_ip}");
        }

        should_proxy
    } else {
        false
    }
}

pub fn maybe_build_icmp_echo_reply(packet: &[u8], config: &UserNetConfig) -> Option<Vec<u8>> {
    let eth = EthernetHeader::parse(packet)?;
    match eth.ether_type {
        ETH_TYPE_IPV4 => build_icmpv4_echo_reply(packet, &eth, config),
        ETH_TYPE_IPV6 => build_icmpv6_echo_reply(packet, &eth, config),
        _ => None,
    }
}

pub fn maybe_build_icmpv6_neighbor_advertisement(
    packet: &[u8],
    config: &UserNetConfig,
) -> Option<Vec<u8>> {
    let eth = EthernetHeader::parse(packet)?;
    if eth.ether_type != ETH_TYPE_IPV6 {
        return None;
    }
    if packet.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN + 24 {
        return None;
    }
    let ip = Ipv6Header::parse(&packet[ETH_HEADER_LEN..])?;
    if ip.next_header != IP_PROTO_ICMPV6 {
        return None;
    }
    if ip.src_ip.is_unspecified() {
        return None;
    }
    let icmp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let icmp_len = ip.payload_len as usize;
    if icmp_len < 24 || packet.len() < icmp_start + icmp_len {
        return None;
    }
    let req_type = packet[icmp_start];
    let req_code = packet[icmp_start + 1];
    if req_type != 135 || req_code != 0 {
        return None;
    }
    let target_start = icmp_start + 8;
    if packet.len() < target_start + 16 {
        return None;
    }
    let mut target = [0u8; 16];
    target.copy_from_slice(&packet[target_start..target_start + 16]);
    let target_ip = Ipv6Addr::from(target);
    if target_ip != config.gateway_ipv6 {
        return None;
    }

    let icmp_reply_len: usize = 32;
    let mut reply = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + icmp_reply_len];

    let eth_reply = EthernetHeader {
        dst_mac: eth.src_mac,
        src_mac: config.gateway_mac,
        ether_type: ETH_TYPE_IPV6,
    };
    eth_reply.write(&mut reply[0..ETH_HEADER_LEN]);

    let ip_reply = Ipv6Header {
        payload_len: mtu_bounded_u16(icmp_reply_len),
        next_header: IP_PROTO_ICMPV6,
        hop_limit: 255,
        src_ip: config.gateway_ipv6,
        dst_ip: ip.src_ip,
    };
    ip_reply.write(&mut reply[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

    let icmp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    reply[icmp_offset] = 136; // Neighbor Advertisement
    reply[icmp_offset + 1] = 0;
    let flags: u32 = 0xE000_0000;
    reply[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&flags.to_be_bytes());
    reply[icmp_offset + 8..icmp_offset + 24].copy_from_slice(&config.gateway_ipv6.octets());
    reply[icmp_offset + 24] = 2; // Target Link-Layer Address option
    reply[icmp_offset + 25] = 1; // length (8 bytes)
    reply[icmp_offset + 26..icmp_offset + 32].copy_from_slice(&config.gateway_mac);

    let icmp_checksum = checksum_icmpv6(
        config.gateway_ipv6,
        ip.src_ip,
        &reply[icmp_offset..icmp_offset + icmp_reply_len],
    );
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    if reply.len() < 60 {
        reply.resize(60, 0);
    }

    Some(reply)
}

fn build_icmpv4_echo_reply(
    packet: &[u8],
    eth: &EthernetHeader,
    config: &UserNetConfig,
) -> Option<Vec<u8>> {
    if packet.len() < ETH_HEADER_LEN + IPV4_HEADER_LEN {
        return None;
    }

    let ip_data = &packet[ETH_HEADER_LEN..];
    let parsed = parse_ip_packet(ETH_TYPE_IPV4, ip_data)?;
    let (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) = (parsed.src_ip(), parsed.dst_ip()) else {
        return None;
    };
    let ip = Ipv4Header::parse(ip_data)?;
    if parsed.protocol() != IP_PROTO_ICMP || dst_ip != config.gateway_ip {
        return None;
    }

    let icmp = parsed.transport_data();
    if icmp.len() < 8 || checksum(icmp) != 0 {
        return None;
    }
    let req_type = icmp[0];
    let req_code = icmp[1];
    if req_type != 8 || req_code != 0 {
        return None;
    }

    let icmp_len = icmp.len();
    let mut reply = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + icmp_len];

    let eth_reply = EthernetHeader {
        dst_mac: eth.src_mac,
        src_mac: config.gateway_mac,
        ether_type: ETH_TYPE_IPV4,
    };
    eth_reply.write(&mut reply[0..ETH_HEADER_LEN]);

    let ip_reply = Ipv4Header {
        version_ihl: 0x45,
        dscp_ecn: 0,
        total_length: mtu_bounded_u16(IPV4_HEADER_LEN + icmp_len),
        identification: ip.identification,
        flags_fragment: 0x4000,
        ttl: 64,
        protocol: IP_PROTO_ICMP,
        checksum: 0,
        src_ip: config.gateway_ip,
        dst_ip: src_ip,
    };
    ip_reply.write(&mut reply[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

    let ip_checksum = checksum(&reply[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
    reply[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&ip_checksum.to_be_bytes());

    let icmp_offset = ETH_HEADER_LEN + IPV4_HEADER_LEN;
    reply[icmp_offset] = 0;
    reply[icmp_offset + 1] = 0;
    reply[icmp_offset + 4..icmp_offset + icmp_len].copy_from_slice(&icmp[4..icmp_len]);

    let icmp_checksum = checksum(&reply[icmp_offset..icmp_offset + icmp_len]);
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    if reply.len() < 60 {
        reply.resize(60, 0);
    }

    Some(reply)
}

fn build_icmpv6_echo_reply(
    packet: &[u8],
    eth: &EthernetHeader,
    config: &UserNetConfig,
) -> Option<Vec<u8>> {
    if packet.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
        return None;
    }

    let ip = Ipv6Header::parse(&packet[ETH_HEADER_LEN..])?;
    if ip.next_header != IP_PROTO_ICMPV6 || ip.dst_ip != config.gateway_ipv6 {
        return None;
    }

    let icmp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    let icmp_len = ip.payload_len as usize;
    if icmp_len < 8 || packet.len() < icmp_start + icmp_len {
        return None;
    }
    if checksum_icmpv6(
        ip.src_ip,
        ip.dst_ip,
        &packet[icmp_start..icmp_start + icmp_len],
    ) != 0
    {
        return None;
    }
    let req_type = packet[icmp_start];
    let req_code = packet[icmp_start + 1];
    if req_type != 128 || req_code != 0 {
        return None;
    }

    let mut reply = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + icmp_len];

    let eth_reply = EthernetHeader {
        dst_mac: eth.src_mac,
        src_mac: config.gateway_mac,
        ether_type: ETH_TYPE_IPV6,
    };
    eth_reply.write(&mut reply[0..ETH_HEADER_LEN]);

    let ip_reply = Ipv6Header {
        payload_len: mtu_bounded_u16(icmp_len),
        next_header: IP_PROTO_ICMPV6,
        hop_limit: 64,
        src_ip: config.gateway_ipv6,
        dst_ip: ip.src_ip,
    };
    ip_reply.write(&mut reply[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

    let icmp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    reply[icmp_offset] = 129;
    reply[icmp_offset + 1] = 0;
    reply[icmp_offset + 4..icmp_offset + icmp_len]
        .copy_from_slice(&packet[icmp_start + 4..icmp_start + icmp_len]);

    let icmp_checksum = checksum_icmpv6(
        config.gateway_ipv6,
        ip.src_ip,
        &reply[icmp_offset..icmp_offset + icmp_len],
    );
    reply[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&icmp_checksum.to_be_bytes());

    if reply.len() < 60 {
        reply.resize(60, 0);
    }

    Some(reply)
}

pub fn checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(byte) << 8);
    }
    checksum_fold(sum)
}

fn checksum_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum = 0u32;

    for chunk in src.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    for chunk in dst.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }

    let len = mtu_bounded_u32(icmp.len());
    sum = sum.wrapping_add(len >> 16);
    sum = sum.wrapping_add(len & 0xffff);
    sum = sum.wrapping_add(u32::from(IP_PROTO_ICMPV6));

    let mut chunks = icmp.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&byte) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(byte) << 8);
    }

    checksum_fold(sum)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_builder::{
        ETH_HEADER_LEN, ETH_TYPE_IPV4, ETH_TYPE_IPV6, IP_PROTO_ICMP, IP_PROTO_ICMPV6, IP_PROTO_TCP,
        IPV4_HEADER_LEN, IPV6_HEADER_LEN,
    };
    use crate::{DEFAULT_GATEWAY_MAC, DEFAULT_GUEST_MAC};

    fn test_config() -> UserNetConfig {
        UserNetConfig::default()
    }

    /// Build a minimal IPv4 packet with given protocol, src, dst, and payload.
    fn make_ipv4_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        protocol: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = u16::try_from(IPV4_HEADER_LEN + payload.len()).unwrap();
        let mut pkt = vec![0u8; ETH_HEADER_LEN + IPV4_HEADER_LEN + payload.len()];

        // Ethernet: dst → src, type IPv4
        pkt[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        pkt[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        pkt[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        pkt[ip] = 0x45;
        pkt[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        pkt[ip + 6..ip + 8].copy_from_slice(&[0x40, 0x00]); // DF
        pkt[ip + 8] = 64;
        pkt[ip + 9] = protocol;
        pkt[ip + 12..ip + 16].copy_from_slice(&src_ip.octets());
        pkt[ip + 16..ip + 20].copy_from_slice(&dst_ip.octets());
        let cksum = checksum(&pkt[ip..ip + IPV4_HEADER_LEN]);
        pkt[ip + 10..ip + 12].copy_from_slice(&cksum.to_be_bytes());
        pkt[ip + IPV4_HEADER_LEN..].copy_from_slice(payload);
        pkt
    }

    fn make_ipv6_packet(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        next_header: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut pkt = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
        pkt[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        pkt[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        pkt[12..14].copy_from_slice(&ETH_TYPE_IPV6.to_be_bytes());
        let ip = ETH_HEADER_LEN;
        pkt[ip] = 0x60;
        pkt[ip + 4..ip + 6].copy_from_slice(&u16::try_from(payload.len()).unwrap().to_be_bytes());
        pkt[ip + 6] = next_header;
        pkt[ip + 7] = 64;
        pkt[ip + 8..ip + 24].copy_from_slice(&src_ip.octets());
        pkt[ip + 24..ip + 40].copy_from_slice(&dst_ip.octets());
        pkt[ip + IPV6_HEADER_LEN..].copy_from_slice(payload);
        pkt
    }

    fn icmpv4_echo_request(id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + data.len()];
        icmp[0] = 8; // Echo Request
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        icmp[8..].copy_from_slice(data);
        let cksum = checksum(&icmp);
        icmp[2..4].copy_from_slice(&cksum.to_be_bytes());
        icmp
    }

    fn icmpv6_echo_request(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut icmp = vec![0u8; 8 + data.len()];
        icmp[0] = 128;
        icmp[4..6].copy_from_slice(&id.to_be_bytes());
        icmp[6..8].copy_from_slice(&seq.to_be_bytes());
        icmp[8..].copy_from_slice(data);
        let cksum = checksum_icmpv6(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&cksum.to_be_bytes());
        icmp
    }

    fn icmpv6_neighbor_solicitation(src: Ipv6Addr, target: Ipv6Addr) -> Vec<u8> {
        let mut icmp = vec![0u8; 24];
        icmp[0] = 135;
        icmp[8..24].copy_from_slice(&target.octets());
        // NS uses solicited-node multicast as dst for checksum, but we
        // use the target directly for simplicity in tests — the function
        // under test doesn't verify the NS checksum.
        let cksum = checksum_icmpv6(src, target, &icmp);
        icmp[2..4].copy_from_slice(&cksum.to_be_bytes());
        icmp
    }

    // ── should_nat_proxy ───────────────────────────────────────────────

    #[test]
    fn nat_proxy_external_ipv4() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(
            config.guest_ip,
            Ipv4Addr::new(1, 2, 3, 4),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_local_ipv4_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(
            config.guest_ip,
            Ipv4Addr::new(10, 0, 2, 100),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_gateway_enters_nat_dispatch() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_TCP, &tcp_hdr);
        assert!(should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_broadcast_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(config.guest_ip, Ipv4Addr::BROADCAST, IP_PROTO_TCP, &tcp_hdr);
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_subnet_broadcast_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(
            config.guest_ip,
            Ipv4Addr::new(10, 0, 2, 255),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_multicast_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv4_packet(
            config.guest_ip,
            Ipv4Addr::new(224, 0, 0, 1),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_external_ipv6() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let ext = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let pkt = make_ipv6_packet(config.guest_ipv6, ext, IP_PROTO_TCP, &tcp_hdr);
        assert!(should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_local_ipv6_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let local = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0099);
        let pkt = make_ipv6_packet(config.guest_ipv6, local, IP_PROTO_TCP, &tcp_hdr);
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_gateway_ipv6_enters_nat_dispatch() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            config.gateway_ipv6,
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_multicast_ipv6_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_link_local_ipv6_not_proxied() {
        let config = test_config();
        let tcp_hdr = vec![0u8; 20];
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            IP_PROTO_TCP,
            &tcp_hdr,
        );
        assert!(!should_nat_proxy(&pkt, &config));
    }

    #[test]
    fn nat_proxy_too_short() {
        assert!(!should_nat_proxy(&[0u8; 5], &test_config()));
    }

    #[test]
    fn nat_proxy_non_ip_ether_type() {
        let mut pkt = vec![0u8; 60];
        pkt[12] = 0x08;
        pkt[13] = 0x06; // ARP
        assert!(!should_nat_proxy(&pkt, &test_config()));
    }

    // ── ICMPv4 echo reply ──────────────────────────────────────────────

    #[test]
    fn icmpv4_echo_reply_to_gateway() {
        let config = test_config();
        let echo = icmpv4_echo_request(0x1234, 1, b"ping");
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMP, &echo);
        let reply = maybe_build_icmp_echo_reply(&pkt, &config).expect("should reply");
        let icmp_off = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        assert_eq!(reply[icmp_off], 0, "type=Echo Reply");
        assert_eq!(
            &reply[icmp_off + 4..icmp_off + 8],
            &echo[4..8],
            "id+seq preserved"
        );
    }

    #[test]
    fn icmpv4_echo_reply_rejects_bad_ip_checksum() {
        let config = test_config();
        let echo = icmpv4_echo_request(0x1234, 1, b"ping");
        let mut pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMP, &echo);
        pkt[ETH_HEADER_LEN + 10] ^= 0x80;

        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    #[test]
    fn icmpv4_echo_reply_rejects_bad_icmp_checksum() {
        let config = test_config();
        let mut echo = icmpv4_echo_request(0x1234, 1, b"ping");
        echo[2] ^= 0x80;
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMP, &echo);

        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    #[test]
    fn icmpv4_echo_not_to_gateway() {
        let config = test_config();
        let echo = icmpv4_echo_request(0x1234, 1, b"ping");
        let pkt = make_ipv4_packet(
            config.guest_ip,
            Ipv4Addr::new(8, 8, 8, 8),
            IP_PROTO_ICMP,
            &echo,
        );
        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    #[test]
    fn icmpv4_non_echo_request() {
        let config = test_config();
        let mut icmp = vec![0u8; 8];
        icmp[0] = 3; // Destination Unreachable
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMP, &icmp);
        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    #[test]
    fn icmpv4_too_short() {
        let config = test_config();
        let icmp = vec![8, 0, 0, 0]; // only 4 bytes
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMP, &icmp);
        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    // ── ICMPv6 echo reply ──────────────────────────────────────────────

    #[test]
    fn icmpv6_echo_reply_to_gateway() {
        let config = test_config();
        let echo = icmpv6_echo_request(config.guest_ipv6, config.gateway_ipv6, 0x5678, 2, b"ping6");
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            config.gateway_ipv6,
            IP_PROTO_ICMPV6,
            &echo,
        );
        let reply = maybe_build_icmp_echo_reply(&pkt, &config).expect("should reply");
        let icmp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        assert_eq!(reply[icmp_off], 129, "type=ICMPv6 Echo Reply");
    }

    #[test]
    fn icmpv6_echo_not_to_gateway() {
        let config = test_config();
        let ext = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let echo = icmpv6_echo_request(config.guest_ipv6, ext, 0x5678, 2, b"ping6");
        let pkt = make_ipv6_packet(config.guest_ipv6, ext, IP_PROTO_ICMPV6, &echo);
        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    #[test]
    fn icmpv6_non_echo_type() {
        let config = test_config();
        let mut icmp = vec![0u8; 8];
        icmp[0] = 1; // Destination Unreachable
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            config.gateway_ipv6,
            IP_PROTO_ICMPV6,
            &icmp,
        );
        assert!(maybe_build_icmp_echo_reply(&pkt, &config).is_none());
    }

    // ── Neighbor Advertisement ──────────────────────────────────────────

    #[test]
    fn na_for_gateway() {
        let config = test_config();
        let ns = icmpv6_neighbor_solicitation(config.guest_ipv6, config.gateway_ipv6);
        let pkt = make_ipv6_packet(config.guest_ipv6, config.gateway_ipv6, IP_PROTO_ICMPV6, &ns);
        let reply = maybe_build_icmpv6_neighbor_advertisement(&pkt, &config).expect("should reply");
        let icmp_off = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        assert_eq!(reply[icmp_off], 136, "type=NA");
        assert_eq!(&reply[icmp_off + 26..icmp_off + 32], &config.gateway_mac);
    }

    #[test]
    fn na_not_for_gateway() {
        let config = test_config();
        let other = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x99);
        let ns = icmpv6_neighbor_solicitation(config.guest_ipv6, other);
        let pkt = make_ipv6_packet(config.guest_ipv6, other, IP_PROTO_ICMPV6, &ns);
        assert!(maybe_build_icmpv6_neighbor_advertisement(&pkt, &config).is_none());
    }

    #[test]
    fn na_wrong_type() {
        let config = test_config();
        let mut icmp = vec![0u8; 24];
        icmp[0] = 136; // NA, not NS
        icmp[8..24].copy_from_slice(&config.gateway_ipv6.octets());
        let pkt = make_ipv6_packet(
            config.guest_ipv6,
            config.gateway_ipv6,
            IP_PROTO_ICMPV6,
            &icmp,
        );
        assert!(maybe_build_icmpv6_neighbor_advertisement(&pkt, &config).is_none());
    }

    #[test]
    fn na_ipv4_returns_none() {
        let config = test_config();
        let ns = icmpv6_neighbor_solicitation(config.guest_ipv6, config.gateway_ipv6);
        let pkt = make_ipv4_packet(config.guest_ip, config.gateway_ip, IP_PROTO_ICMPV6, &ns);
        assert!(maybe_build_icmpv6_neighbor_advertisement(&pkt, &config).is_none());
    }

    #[test]
    fn na_unspecified_src() {
        let config = test_config();
        let ns = icmpv6_neighbor_solicitation(Ipv6Addr::UNSPECIFIED, config.gateway_ipv6);
        let pkt = make_ipv6_packet(
            Ipv6Addr::UNSPECIFIED,
            config.gateway_ipv6,
            IP_PROTO_ICMPV6,
            &ns,
        );
        assert!(maybe_build_icmpv6_neighbor_advertisement(&pkt, &config).is_none());
    }

    // ── Checksums ──────────────────────────────────────────────────────

    #[test]
    fn checksum_empty_is_ffff() {
        assert_eq!(checksum(&[]), 0xFFFF);
    }

    #[test]
    fn checksum_odd_length() {
        let r = checksum(&[0xAB]);
        assert_eq!(r, !0xAB00u16);
    }

    #[test]
    fn icmpv6_checksum_round_trip() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let mut icmp = vec![0u8; 8];
        icmp[0] = 128;
        let cksum = checksum_icmpv6(src, dst, &icmp);
        icmp[2..4].copy_from_slice(&cksum.to_be_bytes());
        assert_eq!(checksum_icmpv6(src, dst, &icmp), 0);
    }
}
