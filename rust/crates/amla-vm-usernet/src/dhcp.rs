// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Minimal DHCP server for guest configuration
//!
//! Responds to DISCOVER and REQUEST from udhcpc with OFFER and ACK
//! containing the guest's IP, gateway, subnet mask, and DNS server.
//! Always broadcasts replies (single-client virtual network).

use crate::UserNetConfig;
use crate::ipv4_mask;
use crate::packet_builder::{ETH_HEADER_LEN, ETH_TYPE_IPV4, IP_PROTO_UDP};
use crate::packet_builder::{EthernetHeader, Ipv4Header, PacketBuilder, UdpHeader};
use std::net::Ipv4Addr;

const DHCP_SERVER_PORT: u16 = 67;
const DHCP_CLIENT_PORT: u16 = 68;
const DHCP_MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];

// BOOTP header offsets (relative to start of BOOTP payload, after UDP header)
const BOOTP_OP: usize = 0;
const BOOTP_HTYPE: usize = 1;
const BOOTP_HLEN: usize = 2;
const BOOTP_XID: usize = 4;
const BOOTP_YIADDR: usize = 16;
const BOOTP_SIADDR: usize = 20;
const BOOTP_CHADDR: usize = 28;
const BOOTP_OPTIONS: usize = 236;

// DHCP option codes
const OPT_SUBNET_MASK: u8 = 1;
const OPT_ROUTER: u8 = 3;
const OPT_DNS: u8 = 6;
const OPT_LEASE_TIME: u8 = 51;
const OPT_MSG_TYPE: u8 = 53;
const OPT_SERVER_ID: u8 = 54;
const OPT_END: u8 = 255;

// DHCP message types
const DHCPDISCOVER: u8 = 1;
const DHCPOFFER: u8 = 2;
const DHCPREQUEST: u8 = 3;
const DHCPACK: u8 = 5;

/// Try to build a DHCP reply for a DHCP request packet.
/// Returns None if the packet is not a valid DHCP DISCOVER or REQUEST.
pub fn maybe_build_dhcp_reply(
    packet: &[u8],
    config: &UserNetConfig,
    gateway_mac: [u8; 6],
) -> Option<Vec<u8>> {
    let eth = EthernetHeader::parse(packet)?;
    if eth.ether_type != ETH_TYPE_IPV4 {
        return None;
    }

    let ip_data = &packet[ETH_HEADER_LEN..];
    let ip = Ipv4Header::parse(ip_data)?;
    if ip.protocol != IP_PROTO_UDP {
        return None;
    }

    let ip_hdr_len = ip.header_len();
    // Clamp to IP total_length to exclude Ethernet padding bytes.
    let ip_payload_end = (ip.total_length as usize).min(ip_data.len());
    let udp_data = ip_data.get(ip_hdr_len..ip_payload_end)?;
    let udp = UdpHeader::parse(udp_data)?;

    if udp.src_port != DHCP_CLIENT_PORT || udp.dst_port != DHCP_SERVER_PORT {
        return None;
    }

    // Accept broadcast or gateway-directed
    if ip.dst_ip != Ipv4Addr::BROADCAST && ip.dst_ip != config.gateway_ip {
        return None;
    }

    // BOOTP payload starts after 8-byte UDP header, clamped to declared UDP length.
    let udp_payload_end = (udp.length as usize).min(udp_data.len());
    let bootp = udp_data.get(8..udp_payload_end)?;
    if bootp.len() < BOOTP_OPTIONS + 4 {
        return None;
    }

    if bootp[BOOTP_OP] != 1 || bootp[BOOTP_HTYPE] != 1 || bootp[BOOTP_HLEN] != 6 {
        return None;
    }

    if bootp[BOOTP_OPTIONS..BOOTP_OPTIONS + 4] != DHCP_MAGIC_COOKIE {
        return None;
    }

    let xid: [u8; 4] = bootp[BOOTP_XID..BOOTP_XID + 4].try_into().ok()?;
    let chaddr: [u8; 6] = bootp[BOOTP_CHADDR..BOOTP_CHADDR + 6].try_into().ok()?;

    let msg_type = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_MSG_TYPE)?
        .first()
        .copied()?;

    let reply_type = match msg_type {
        DHCPDISCOVER => DHCPOFFER,
        DHCPREQUEST => DHCPACK,
        _ => return None,
    };

    let reply_payload = build_bootp_reply(config, xid, chaddr, reply_type);

    let mut builder = PacketBuilder::new(gateway_mac);
    let packet = builder.build_udp_packet(
        [0xFF; 6],
        config.gateway_ip,
        Ipv4Addr::BROADCAST,
        DHCP_SERVER_PORT,
        DHCP_CLIENT_PORT,
        &reply_payload,
    );

    Some(packet)
}

/// Scan DHCP options (TLV format) for a specific option code.
fn find_dhcp_option(options: &[u8], code: u8) -> Option<&[u8]> {
    let mut i = 0;
    while i < options.len() {
        let opt_code = options[i];
        if opt_code == OPT_END {
            break;
        }
        if opt_code == 0 {
            i += 1;
            continue;
        } // pad option
        if i + 1 >= options.len() {
            break;
        }
        let opt_len = options[i + 1] as usize;
        if i + 2 + opt_len > options.len() {
            break;
        }
        if opt_code == code {
            return Some(&options[i + 2..i + 2 + opt_len]);
        }
        i += 2 + opt_len;
    }
    None
}

/// Build the BOOTP/DHCP reply payload (everything after UDP header).
/// Padded to >= 300 bytes per RFC1542.
fn build_bootp_reply(
    config: &UserNetConfig,
    xid: [u8; 4],
    chaddr: [u8; 6],
    msg_type: u8,
) -> Vec<u8> {
    let mut buf = vec![0u8; 300];

    buf[BOOTP_OP] = 2; // BOOTREPLY
    buf[BOOTP_HTYPE] = 1;
    buf[BOOTP_HLEN] = 6;
    buf[BOOTP_XID..BOOTP_XID + 4].copy_from_slice(&xid);
    buf[BOOTP_YIADDR..BOOTP_YIADDR + 4].copy_from_slice(&config.guest_ip.octets());
    buf[BOOTP_SIADDR..BOOTP_SIADDR + 4].copy_from_slice(&config.gateway_ip.octets());
    buf[BOOTP_CHADDR..BOOTP_CHADDR + 6].copy_from_slice(&chaddr);
    buf[BOOTP_OPTIONS..BOOTP_OPTIONS + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);

    let mut pos = BOOTP_OPTIONS + 4;

    // Option 53: DHCP Message Type
    buf[pos] = OPT_MSG_TYPE;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;

    // Option 54: Server Identifier
    buf[pos] = OPT_SERVER_ID;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&config.gateway_ip.octets());
    pos += 6;

    // Option 51: Lease Time (86400 = 1 day)
    buf[pos] = OPT_LEASE_TIME;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&86400u32.to_be_bytes());
    pos += 6;

    // Option 1: Subnet Mask
    let mask = ipv4_mask(config.prefix_len);
    buf[pos] = OPT_SUBNET_MASK;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&mask.to_be_bytes());
    pos += 6;

    // Option 3: Router
    buf[pos] = OPT_ROUTER;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&config.gateway_ip.octets());
    pos += 6;

    // Option 6: DNS Server (use configured dns_server address)
    buf[pos] = OPT_DNS;
    buf[pos + 1] = 4;
    buf[pos + 2..pos + 6].copy_from_slice(&config.dns_server.octets());
    pos += 6;

    // Option 255: End
    buf[pos] = OPT_END;

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{DEFAULT_GATEWAY_MAC, UserNetConfig};

    fn make_bootp_request(config: &UserNetConfig, msg_type: u8, xid: [u8; 4]) -> Vec<u8> {
        let mut bootp = vec![0u8; 300];
        bootp[BOOTP_OP] = 1; // BOOTREQUEST
        bootp[BOOTP_HTYPE] = 1;
        bootp[BOOTP_HLEN] = 6;
        bootp[BOOTP_XID..BOOTP_XID + 4].copy_from_slice(&xid);
        bootp[BOOTP_CHADDR..BOOTP_CHADDR + 6].copy_from_slice(&config.guest_mac);
        bootp[BOOTP_OPTIONS..BOOTP_OPTIONS + 4].copy_from_slice(&DHCP_MAGIC_COOKIE);
        bootp[BOOTP_OPTIONS + 4] = OPT_MSG_TYPE;
        bootp[BOOTP_OPTIONS + 5] = 1;
        bootp[BOOTP_OPTIONS + 6] = msg_type;
        bootp[BOOTP_OPTIONS + 7] = OPT_END;
        bootp
    }

    fn wrap_bootp_in_packet(bootp: &[u8], config: &UserNetConfig) -> Vec<u8> {
        let total = 14 + 20 + 8 + bootp.len();
        let mut pkt = vec![0u8; total];
        // ETH: dst=broadcast, src=guest_mac, type=0x0800
        pkt[0..6].copy_from_slice(&[0xFF; 6]);
        pkt[6..12].copy_from_slice(&config.guest_mac);
        pkt[12..14].copy_from_slice(&[0x08, 0x00]);
        // IP: version=4, ihl=5, protocol=UDP, src=0.0.0.0, dst=broadcast
        pkt[14] = 0x45;
        let ip_total = u16::try_from(20 + 8 + bootp.len()).unwrap();
        pkt[16..18].copy_from_slice(&ip_total.to_be_bytes());
        pkt[23] = 17; // UDP
        pkt[26..30].copy_from_slice(&[0, 0, 0, 0]);
        pkt[30..34].copy_from_slice(&[255, 255, 255, 255]);
        // UDP: src=68, dst=67
        pkt[34..36].copy_from_slice(&68u16.to_be_bytes());
        pkt[36..38].copy_from_slice(&67u16.to_be_bytes());
        let udp_len = u16::try_from(8 + bootp.len()).unwrap();
        pkt[38..40].copy_from_slice(&udp_len.to_be_bytes());
        // BOOTP payload
        pkt[42..42 + bootp.len()].copy_from_slice(bootp);
        pkt
    }

    fn make_discover_packet(config: &UserNetConfig) -> Vec<u8> {
        let bootp = make_bootp_request(config, DHCPDISCOVER, [0xDE, 0xAD, 0xBE, 0xEF]);
        wrap_bootp_in_packet(&bootp, config)
    }

    #[test]
    fn discover_produces_offer() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC);
        assert!(reply.is_some(), "should produce OFFER for DISCOVER");

        let reply = reply.unwrap();
        let bootp = &reply[42..];
        assert_eq!(bootp[BOOTP_OP], 2); // BOOTREPLY
        assert_eq!(&bootp[BOOTP_XID..BOOTP_XID + 4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            &bootp[BOOTP_YIADDR..BOOTP_YIADDR + 4],
            &config.guest_ip.octets()
        );
        let msg_type = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_MSG_TYPE).unwrap();
        assert_eq!(msg_type, &[DHCPOFFER]);
    }

    #[test]
    fn request_produces_ack() {
        let config = UserNetConfig::default();
        let bootp = make_bootp_request(&config, DHCPREQUEST, [0xCA, 0xFE, 0xBA, 0xBE]);
        let pkt = wrap_bootp_in_packet(&bootp, &config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp_reply = &reply[42..];
        let msg_type = find_dhcp_option(&bootp_reply[BOOTP_OPTIONS + 4..], OPT_MSG_TYPE).unwrap();
        assert_eq!(msg_type, &[DHCPACK]);
    }

    #[test]
    fn dns_option_is_dns_server() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        let dns = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_DNS).unwrap();
        assert_eq!(dns, &config.dns_server.octets());
    }

    #[test]
    fn non_dhcp_returns_none() {
        let config = UserNetConfig::default();
        // TCP packet
        let mut pkt = vec![0u8; 64];
        pkt[0..6].copy_from_slice(&[0xFF; 6]);
        pkt[6..12].copy_from_slice(&config.guest_mac);
        pkt[12..14].copy_from_slice(&[0x08, 0x00]);
        pkt[14] = 0x45;
        pkt[23] = 6; // TCP, not UDP
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }

    #[test]
    fn truncated_returns_none() {
        let config = UserNetConfig::default();
        // Too short to contain BOOTP options
        let pkt = vec![0u8; 50];
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }

    #[test]
    fn reply_is_at_least_300_bytes_bootp() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        assert!(
            reply.len() - 42 >= 300,
            "BOOTP payload must be >= 300 bytes"
        );
    }

    #[test]
    fn dhcp_ignores_other_message_types() {
        let config = UserNetConfig::default();
        for msg_type in [4, 5, 6, 7, 8] {
            let bootp = make_bootp_request(&config, msg_type, [0, 0, 0, 1]);
            let pkt = wrap_bootp_in_packet(&bootp, &config);
            assert!(
                maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none(),
                "msg_type {msg_type} should return None"
            );
        }
    }

    #[test]
    fn reply_has_correct_subnet_mask() {
        let config = UserNetConfig::default(); // prefix_len=24
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        let mask = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_SUBNET_MASK).unwrap();
        assert_eq!(mask, &[255, 255, 255, 0]);
    }

    #[test]
    fn reply_has_correct_router() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        let router = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_ROUTER).unwrap();
        assert_eq!(router, &config.gateway_ip.octets());
    }

    #[test]
    fn reply_has_correct_server_id() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        let server_id = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_SERVER_ID).unwrap();
        assert_eq!(server_id, &config.gateway_ip.octets());
    }

    #[test]
    fn reply_has_lease_time() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        let lease = find_dhcp_option(&bootp[BOOTP_OPTIONS + 4..], OPT_LEASE_TIME).unwrap();
        assert_eq!(u32::from_be_bytes(lease.try_into().unwrap()), 86400);
    }

    #[test]
    fn echoes_xid_and_chaddr() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        let bootp = &reply[42..];
        assert_eq!(&bootp[BOOTP_XID..BOOTP_XID + 4], &[0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(&bootp[BOOTP_CHADDR..BOOTP_CHADDR + 6], &config.guest_mac);
    }

    #[test]
    fn wrong_magic_cookie_returns_none() {
        let config = UserNetConfig::default();
        let mut bootp = make_bootp_request(&config, DHCPDISCOVER, [0, 0, 0, 1]);
        bootp[BOOTP_OPTIONS..BOOTP_OPTIONS + 4].copy_from_slice(&[0, 0, 0, 0]);
        let pkt = wrap_bootp_in_packet(&bootp, &config);
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }

    #[test]
    fn bootreply_returns_none() {
        let config = UserNetConfig::default();
        let mut bootp = make_bootp_request(&config, DHCPDISCOVER, [0, 0, 0, 1]);
        bootp[BOOTP_OP] = 2; // BOOTREPLY, not REQUEST
        let pkt = wrap_bootp_in_packet(&bootp, &config);
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }

    #[test]
    fn broadcast_reply_mac() {
        let config = UserNetConfig::default();
        let pkt = make_discover_packet(&config);
        let reply = maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).unwrap();
        assert_eq!(&reply[0..6], &[0xFF; 6]);
    }

    #[test]
    fn find_dhcp_option_with_pad_options() {
        let options = [0u8, 0, OPT_MSG_TYPE, 1, 1, 0, 0, OPT_END];
        let result = find_dhcp_option(&options, OPT_MSG_TYPE);
        assert_eq!(result, Some([1u8].as_slice()));
    }

    #[test]
    fn find_dhcp_option_missing() {
        let options = [OPT_MSG_TYPE, 1, 1, OPT_END];
        assert!(find_dhcp_option(&options, OPT_DNS).is_none());
    }

    #[test]
    fn find_dhcp_option_truncated_length() {
        // Option claims 10 bytes of data but only 1 byte follows before END
        let options = [OPT_MSG_TYPE, 10, 1, OPT_END];
        assert!(find_dhcp_option(&options, OPT_MSG_TYPE).is_none());
    }

    #[test]
    fn find_dhcp_option_code_at_end_no_length() {
        // Option code present but no room for a length byte
        let options = [OPT_MSG_TYPE];
        assert!(find_dhcp_option(&options, OPT_MSG_TYPE).is_none());
    }

    #[test]
    fn find_dhcp_option_empty() {
        assert!(find_dhcp_option(&[], OPT_MSG_TYPE).is_none());
    }

    #[test]
    fn test_dhcp_rejects_wrong_htype() {
        let config = UserNetConfig::default();
        let mut pkt = make_discover_packet(&config);
        // BOOTP htype is at offset ETH(14) + IP(20) + UDP(8) + BOOTP_HTYPE(1)
        pkt[14 + 20 + 8 + BOOTP_HTYPE] = 6; // IEEE 802 instead of Ethernet
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }

    #[test]
    fn test_dhcp_rejects_wrong_hlen() {
        let config = UserNetConfig::default();
        let mut pkt = make_discover_packet(&config);
        pkt[14 + 20 + 8 + BOOTP_HLEN] = 8; // wrong hardware address length
        assert!(maybe_build_dhcp_reply(&pkt, &config, DEFAULT_GATEWAY_MAC).is_none());
    }
}
