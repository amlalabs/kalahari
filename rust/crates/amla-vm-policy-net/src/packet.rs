// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Packet parsing for policy enforcement
//!
//! Parses Ethernet frames containing IPv4/IPv6 packets with TCP/UDP/ICMP payloads.
//! All parsing follows a fail-closed model - malformed packets result in errors.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =============================================================================
// IP Protocol
// =============================================================================

/// IP protocol number
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpProtocol {
    /// ICMP (protocol 1)
    Icmp,
    /// `ICMPv6` (protocol 58)
    Icmpv6,
    /// TCP (protocol 6)
    Tcp,
    /// UDP (protocol 17)
    Udp,
    /// Unknown protocol
    Unknown(u8),
}

impl IpProtocol {
    /// Create from protocol number
    pub const fn from_number(n: u8) -> Self {
        match n {
            1 => Self::Icmp,
            58 => Self::Icmpv6,
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Unknown(other),
        }
    }

    /// Convert to protocol number
    pub const fn to_number(self) -> u8 {
        match self {
            Self::Icmp => 1,
            Self::Icmpv6 => 58,
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Unknown(n) => n,
        }
    }

    pub const fn is_icmp(self) -> bool {
        matches!(self, Self::Icmp | Self::Icmpv6)
    }
}

// =============================================================================
// Parsed Packet
// =============================================================================

/// A parsed Ethernet/IP packet
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    /// Source IP address
    pub src_ip: IpAddr,
    /// Destination IP address
    pub dst_ip: IpAddr,
    /// Source port (TCP/UDP only)
    pub src_port: u16,
    /// Destination port (TCP/UDP only)
    pub dst_port: u16,
    /// IP protocol
    pub protocol: IpProtocol,
    /// Whether packet is fragmented
    pub is_fragmented: bool,
    /// Whether IP checksum is valid
    pub ip_checksum_valid: bool,
    /// Total packet length
    pub total_len: usize,
    /// TCP flags byte (offset 13 of TCP header), `None` for non-TCP
    pub tcp_flags: Option<u8>,
    /// Byte offset into the full Ethernet frame where the transport header
    /// starts (TCP/UDP header). For IPv4 this is `ETH + ip_header_len`; for
    /// IPv6 it's `ETH + IPV6_HEADER_LEN + extension_header_lengths`. Zero
    /// for non-TCP/UDP packets where the concept doesn't apply.
    pub transport_offset: usize,
}

// =============================================================================
// Parse Error
// =============================================================================

/// Packet parsing error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// Packet too short
    TooShort { expected: usize, got: usize },
    /// Not an IPv4/IPv6 packet (wrong `EtherType`)
    NotIp { ethertype: u16 },
    /// Invalid IP version
    InvalidIpVersion { version: u8 },
    /// Invalid IP header length
    InvalidIpHeaderLen { ihl: u8 },
    /// IP total length mismatch
    IpLengthMismatch { header: u16, actual: usize },
    /// Invalid TCP data-offset/header length
    InvalidTcpHeaderLen { data_offset: u8 },
    /// Invalid UDP length field
    InvalidUdpLength { length: u16 },
    /// Transport length field does not match the available IP payload
    TransportLengthMismatch {
        protocol: IpProtocol,
        header: u16,
        actual: usize,
    },
    /// Unsupported IPv6 extension header
    UnsupportedIpv6Extension { next_header: u8 },
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort { expected, got } => {
                write!(f, "packet too short: expected {expected} bytes, got {got}")
            }
            Self::NotIp { ethertype } => {
                write!(f, "not IP packet: EtherType 0x{ethertype:04x}")
            }
            Self::InvalidIpVersion { version } => {
                write!(f, "invalid IP version: {version}")
            }
            Self::InvalidIpHeaderLen { ihl } => {
                write!(f, "invalid IP header length: {ihl} (must be >= 5)")
            }
            Self::IpLengthMismatch { header, actual } => {
                write!(
                    f,
                    "IP length mismatch: header says {header}, got {actual} after Ethernet"
                )
            }
            Self::InvalidTcpHeaderLen { data_offset } => {
                write!(f, "invalid TCP data offset: {data_offset} (must be >= 5)")
            }
            Self::InvalidUdpLength { length } => {
                write!(f, "invalid UDP length: {length} (must be >= 8)")
            }
            Self::TransportLengthMismatch {
                protocol,
                header,
                actual,
            } => {
                let protocol = match protocol {
                    IpProtocol::Icmp => "ICMP",
                    IpProtocol::Icmpv6 => "ICMPv6",
                    IpProtocol::Tcp => "TCP",
                    IpProtocol::Udp => "UDP",
                    IpProtocol::Unknown(_) => "unknown transport",
                };
                write!(
                    f,
                    "{protocol} length mismatch: header says {header}, got {actual}"
                )
            }
            Self::UnsupportedIpv6Extension { next_header } => {
                write!(f, "unsupported IPv6 extension header: {next_header}")
            }
        }
    }
}

impl std::error::Error for ParseError {}

// =============================================================================
// Ethernet Constants
// =============================================================================

/// Ethernet header size
const ETH_HEADER_LEN: usize = 14;
/// Minimum IP header size (no options)
const IP_MIN_HEADER_LEN: usize = 20;
/// IPv6 header size
const IPV6_HEADER_LEN: usize = 40;
/// TCP header minimum size
const TCP_MIN_HEADER_LEN: usize = 20;
/// UDP header size
const UDP_HEADER_LEN: usize = 8;

/// `EtherType` for IPv4
const ETHERTYPE_IPV4: u16 = 0x0800;
/// `EtherType` for IPv6
const ETHERTYPE_IPV6: u16 = 0x86DD;
/// `EtherType` for ARP (used in tests)
#[cfg(test)]
const ETHERTYPE_ARP: u16 = 0x0806;

// =============================================================================
// Parsing Functions
// =============================================================================

/// Parse an Ethernet frame containing an IPv4/IPv6 packet
///
/// Returns parsed packet information or error if malformed.
/// This follows a fail-closed model - any parsing issue returns an error.
pub fn parse_ethernet_frame(frame: &[u8]) -> Result<ParsedPacket, ParseError> {
    // Check minimum size for Ethernet + IPv4 header
    if frame.len() < ETH_HEADER_LEN + IP_MIN_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: ETH_HEADER_LEN + IP_MIN_HEADER_LEN,
            got: frame.len(),
        });
    }

    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
    match ethertype {
        ETHERTYPE_IPV4 => parse_ipv4_frame(frame),
        ETHERTYPE_IPV6 => parse_ipv6_frame(frame),
        _ => Err(ParseError::NotIp { ethertype }),
    }
}

/// Parse an IPv4 packet from an Ethernet frame
///
/// Validates the IPv4 header (version, IHL, total length, checksum),
/// detects fragmentation, and extracts TCP/UDP ports from the transport layer.
fn parse_ipv4_frame(frame: &[u8]) -> Result<ParsedPacket, ParseError> {
    let ip_data = &frame[ETH_HEADER_LEN..];
    let version_ihl = ip_data[0];
    let version = version_ihl >> 4;
    let ihl = version_ihl & 0x0F;

    if version != 4 {
        return Err(ParseError::InvalidIpVersion { version });
    }

    if ihl < 5 {
        return Err(ParseError::InvalidIpHeaderLen { ihl });
    }

    let ip_header_len = (ihl as usize) * 4;
    if ip_data.len() < ip_header_len {
        return Err(ParseError::TooShort {
            expected: ETH_HEADER_LEN + ip_header_len,
            got: frame.len(),
        });
    }

    let total_length = u16::from_be_bytes([ip_data[2], ip_data[3]]);
    let flags_fragment = u16::from_be_bytes([ip_data[6], ip_data[7]]);
    let protocol = IpProtocol::from_number(ip_data[9]);
    let src_ip = Ipv4Addr::new(ip_data[12], ip_data[13], ip_data[14], ip_data[15]);
    let dst_ip = Ipv4Addr::new(ip_data[16], ip_data[17], ip_data[18], ip_data[19]);

    if (total_length as usize) > ip_data.len() {
        return Err(ParseError::IpLengthMismatch {
            header: total_length,
            actual: ip_data.len(),
        });
    }

    let more_fragments = (flags_fragment & 0x2000) != 0;
    let fragment_offset = flags_fragment & 0x1FFF;
    let is_fragmented = more_fragments || fragment_offset != 0;

    let ip_checksum_valid = verify_ip_checksum(&ip_data[..ip_header_len]);

    // Guard: total_length must cover at least the IP header
    if (total_length as usize) < ip_header_len {
        return Err(ParseError::IpLengthMismatch {
            header: total_length,
            actual: ip_data.len(),
        });
    }
    // Bound ip_data to the declared IP total_length to exclude frame padding
    let ip_data = &ip_data[..total_length as usize];

    // Non-first fragments don't carry transport headers at the expected
    // offset — what looks like "ports" would be payload bytes. Return zeros
    // so audit/logging doesn't surface junk values that could mislead a
    // future conntrack path if it ever stops rejecting fragments.
    let (src_port, dst_port, tcp_flags) = if is_fragmented && fragment_offset != 0 {
        (0u16, 0u16, None)
    } else {
        parse_transport_ports(
            protocol,
            &ip_data[ip_header_len..],
            ETH_HEADER_LEN + ip_header_len,
        )?
    };

    Ok(ParsedPacket {
        src_ip: IpAddr::V4(src_ip),
        dst_ip: IpAddr::V4(dst_ip),
        src_port,
        dst_port,
        protocol,
        is_fragmented,
        ip_checksum_valid,
        total_len: frame.len(),
        tcp_flags,
        transport_offset: ETH_HEADER_LEN + ip_header_len,
    })
}

/// Parse an IPv6 packet from an Ethernet frame
///
/// Validates the IPv6 header (version, payload length), walks extension headers
/// (Hop-by-Hop, Routing, Destination Options, Fragment), and extracts TCP/UDP
/// ports from the transport layer.
fn parse_ipv6_frame(frame: &[u8]) -> Result<ParsedPacket, ParseError> {
    if frame.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
        return Err(ParseError::TooShort {
            expected: ETH_HEADER_LEN + IPV6_HEADER_LEN,
            got: frame.len(),
        });
    }

    let ip_data = &frame[ETH_HEADER_LEN..];
    let version = ip_data[0] >> 4;
    if version != 6 {
        return Err(ParseError::InvalidIpVersion { version });
    }

    let payload_len_u16 = u16::from_be_bytes([ip_data[4], ip_data[5]]);
    let payload_len = payload_len_u16 as usize;
    if payload_len > ip_data.len().saturating_sub(IPV6_HEADER_LEN) {
        return Err(ParseError::IpLengthMismatch {
            header: payload_len_u16,
            actual: ip_data.len(),
        });
    }
    let ip_end = IPV6_HEADER_LEN + payload_len;
    let ip_data = &ip_data[..ip_end];

    let mut next_header = ip_data[6];
    let mut offset = IPV6_HEADER_LEN;
    let mut is_fragmented = false;
    loop {
        match next_header {
            0 | 43 | 60 => {
                // Hop-by-Hop, Routing, Destination Options
                if ip_data.len() < offset + 2 {
                    return Err(ParseError::TooShort {
                        expected: ETH_HEADER_LEN + offset + 2,
                        got: frame.len(),
                    });
                }
                let hdr_ext_len = ip_data[offset + 1] as usize;
                let header_len = (hdr_ext_len + 1) * 8;
                if ip_data.len() < offset + header_len {
                    return Err(ParseError::TooShort {
                        expected: ETH_HEADER_LEN + offset + header_len,
                        got: frame.len(),
                    });
                }
                next_header = ip_data[offset];
                offset += header_len;
            }
            44 => {
                // Fragment header (fixed 8 bytes)
                if ip_data.len() < offset + 8 {
                    return Err(ParseError::TooShort {
                        expected: ETH_HEADER_LEN + offset + 8,
                        got: frame.len(),
                    });
                }
                is_fragmented = true;
                next_header = ip_data[offset];
                offset += 8;
            }
            _ => break,
        }
        if offset >= ip_data.len() {
            break;
        }
    }

    // Exact 16-byte slices from validated IPv6 header
    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&ip_data[8..24]);
    let src_ip = Ipv6Addr::from(src_bytes);
    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&ip_data[24..40]);
    let dst_ip = Ipv6Addr::from(dst_bytes);
    let protocol = IpProtocol::from_number(next_header);

    let transport = if offset <= ip_data.len() {
        &ip_data[offset..]
    } else {
        &[]
    };

    let min_header_offset = ETH_HEADER_LEN + offset;
    let (src_port, dst_port, tcp_flags) =
        parse_transport_ports(protocol, transport, min_header_offset)?;

    Ok(ParsedPacket {
        src_ip: IpAddr::V6(src_ip),
        dst_ip: IpAddr::V6(dst_ip),
        src_port,
        dst_port,
        protocol,
        is_fragmented,
        ip_checksum_valid: true,
        total_len: frame.len(),
        tcp_flags,
        transport_offset: ETH_HEADER_LEN + offset,
    })
}

/// Extract TCP/UDP source and destination ports (and TCP flags) from the transport layer
///
/// Returns `(0, 0, None)` for non-TCP/UDP protocols (e.g., ICMP).
fn parse_transport_ports(
    protocol: IpProtocol,
    transport_data: &[u8],
    min_expected: usize,
) -> Result<(u16, u16, Option<u8>), ParseError> {
    match protocol {
        IpProtocol::Tcp => {
            if transport_data.len() < TCP_MIN_HEADER_LEN {
                return Err(ParseError::TooShort {
                    expected: min_expected + TCP_MIN_HEADER_LEN,
                    got: min_expected + transport_data.len(),
                });
            }
            let src = u16::from_be_bytes([transport_data[0], transport_data[1]]);
            let dst = u16::from_be_bytes([transport_data[2], transport_data[3]]);
            let data_offset = transport_data[12] >> 4;
            if data_offset < 5 {
                return Err(ParseError::InvalidTcpHeaderLen { data_offset });
            }
            let tcp_header_len = (data_offset as usize) * 4;
            if transport_data.len() < tcp_header_len {
                return Err(ParseError::TooShort {
                    expected: min_expected + tcp_header_len,
                    got: min_expected + transport_data.len(),
                });
            }
            let flags = transport_data[13]; // TCP flags byte
            Ok((src, dst, Some(flags)))
        }
        IpProtocol::Udp => {
            if transport_data.len() < UDP_HEADER_LEN {
                return Err(ParseError::TooShort {
                    expected: min_expected + UDP_HEADER_LEN,
                    got: min_expected + transport_data.len(),
                });
            }
            let src = u16::from_be_bytes([transport_data[0], transport_data[1]]);
            let dst = u16::from_be_bytes([transport_data[2], transport_data[3]]);
            let udp_len = u16::from_be_bytes([transport_data[4], transport_data[5]]);
            if usize::from(udp_len) < UDP_HEADER_LEN {
                return Err(ParseError::InvalidUdpLength { length: udp_len });
            }
            if transport_data.len() != udp_len as usize {
                return Err(ParseError::TransportLengthMismatch {
                    protocol,
                    header: udp_len,
                    actual: transport_data.len(),
                });
            }
            Ok((src, dst, None))
        }
        _ => Ok((0, 0, None)),
    }
}

/// Verify IP header checksum (RFC 1071)
fn verify_ip_checksum(header: &[u8]) -> bool {
    if header.len() < IP_MIN_HEADER_LEN || !header.len().is_multiple_of(2) {
        return false;
    }

    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(u32::from(word));
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Valid checksum results in 0xFFFF after summing.
    // After folding, sum fits in 16 bits.
    (sum & 0xFFFF) == 0xFFFF
}

/// Calculate IP header checksum (for generating test packets)
#[cfg(test)]
fn calculate_ip_checksum(header: &mut [u8]) {
    // Zero out checksum field first
    header[10] = 0;
    header[11] = 0;

    let mut sum: u32 = 0;
    for chunk in header.chunks(2) {
        let word = u16::from_be_bytes([chunk[0], chunk[1]]);
        sum = sum.wrapping_add(u32::from(word));
    }

    // Fold 32-bit sum to 16 bits
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // One's complement (after folding, sum fits in 16 bits)
    #[allow(clippy::cast_possible_truncation)]
    let checksum = !(sum as u16);
    let bytes = checksum.to_be_bytes();
    header[10] = bytes[0];
    header[11] = bytes[1];
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
pub mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )]
    use amla_constants::net::{DEFAULT_GATEWAY_MAC, DEFAULT_GUEST_MAC};

    use super::*;

    /// Create a synthetic TCP packet for testing
    ///
    /// This creates a minimal valid Ethernet/IPv4/TCP packet.
    pub fn make_tcp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IP_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN];

        // Ethernet header (14 bytes)
        // Destination MAC
        packet[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        // Source MAC
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        // EtherType (IPv4)
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // IP header (20 bytes)
        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset] = 0x45; // Version 4, IHL 5
        packet[ip_offset + 1] = 0x00; // DSCP/ECN
        let total_len: u16 = (IP_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN) as u16;
        packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&total_len.to_be_bytes());
        packet[ip_offset + 4..ip_offset + 6].copy_from_slice(&[0x00, 0x00]); // ID
        packet[ip_offset + 6..ip_offset + 8].copy_from_slice(&[0x40, 0x00]); // Flags (DF), Fragment
        packet[ip_offset + 8] = 64; // TTL
        packet[ip_offset + 9] = 6; // Protocol (TCP)
        // Checksum at [10..12] - filled in below
        packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip);
        packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip);

        // Calculate IP checksum
        calculate_ip_checksum(&mut packet[ip_offset..ip_offset + IP_MIN_HEADER_LEN]);

        // TCP header (20 bytes minimum)
        let tcp_offset = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp_offset + 4..tcp_offset + 8].copy_from_slice(&[0, 0, 0, 0]); // Seq
        packet[tcp_offset + 8..tcp_offset + 12].copy_from_slice(&[0, 0, 0, 0]); // Ack
        packet[tcp_offset + 12] = 0x50; // Data offset (5), reserved
        packet[tcp_offset + 13] = 0x02; // Flags: SYN
        packet[tcp_offset + 14..tcp_offset + 16].copy_from_slice(&[0xFF, 0xFF]); // Window
        // Checksum and urgent pointer left as 0

        packet
    }

    /// Create a UDP packet for testing
    pub fn make_udp_packet(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IP_MIN_HEADER_LEN + UDP_HEADER_LEN];

        // Ethernet header
        packet[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // IP header
        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset] = 0x45; // Version 4, IHL 5
        let total_len: u16 = (IP_MIN_HEADER_LEN + UDP_HEADER_LEN) as u16;
        packet[ip_offset + 2..ip_offset + 4].copy_from_slice(&total_len.to_be_bytes());
        packet[ip_offset + 6..ip_offset + 8].copy_from_slice(&[0x40, 0x00]); // Flags (DF)
        packet[ip_offset + 8] = 64; // TTL
        packet[ip_offset + 9] = 17; // Protocol (UDP)
        packet[ip_offset + 12..ip_offset + 16].copy_from_slice(&src_ip);
        packet[ip_offset + 16..ip_offset + 20].copy_from_slice(&dst_ip);
        calculate_ip_checksum(&mut packet[ip_offset..ip_offset + IP_MIN_HEADER_LEN]);

        // UDP header
        let udp_offset = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len: u16 = UDP_HEADER_LEN as u16;
        packet[udp_offset + 4..udp_offset + 6].copy_from_slice(&udp_len.to_be_bytes());

        packet
    }

    /// Create a fragmented packet for testing
    pub fn make_fragmented_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let mut packet = make_tcp_packet(src_ip, dst_ip, 12345, 443);

        // Set More Fragments flag
        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset + 6] = 0x20; // MF flag set

        // Recalculate checksum
        calculate_ip_checksum(&mut packet[ip_offset..ip_offset + IP_MIN_HEADER_LEN]);

        packet
    }

    /// Create a packet with bad checksum
    pub fn make_bad_checksum_packet(src_ip: [u8; 4], dst_ip: [u8; 4]) -> Vec<u8> {
        let mut packet = make_tcp_packet(src_ip, dst_ip, 12345, 443);

        // Corrupt the checksum
        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset + 10] = 0xBA;
        packet[ip_offset + 11] = 0xAD;

        packet
    }

    #[test]
    fn test_parse_tcp_packet() {
        let packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let parsed = parse_ethernet_frame(&packet).unwrap();

        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert!(!parsed.is_fragmented);
        assert!(parsed.ip_checksum_valid);
    }

    #[test]
    fn test_parse_udp_packet() {
        let packet = make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 54321, 53);
        let parsed = parse_ethernet_frame(&packet).unwrap();

        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)));
        assert_eq!(parsed.src_port, 54321);
        assert_eq!(parsed.dst_port, 53);
        assert_eq!(parsed.protocol, IpProtocol::Udp);
        assert!(parsed.ip_checksum_valid);
    }

    #[test]
    fn test_fragmented_packet_detected() {
        let packet = make_fragmented_packet([10, 0, 2, 15], [1, 2, 3, 4]);
        let parsed = parse_ethernet_frame(&packet).unwrap();

        assert!(parsed.is_fragmented);
        assert!(parsed.ip_checksum_valid);
    }

    #[test]
    fn test_bad_checksum_detected() {
        let packet = make_bad_checksum_packet([10, 0, 2, 15], [1, 2, 3, 4]);
        let parsed = parse_ethernet_frame(&packet).unwrap();

        assert!(!parsed.ip_checksum_valid);
    }

    #[test]
    fn test_too_short_packet() {
        let packet = vec![0u8; 10]; // Too short
        let result = parse_ethernet_frame(&packet);

        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_non_ipv4_rejected() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IP_MIN_HEADER_LEN + TCP_MIN_HEADER_LEN];
        // Set EtherType to ARP
        packet[12..14].copy_from_slice(&ETHERTYPE_ARP.to_be_bytes());

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::NotIp { ethertype: 0x0806 })
        ));
    }

    #[test]
    fn test_ipv6_parsed() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset] = 0x60; // Version 6
        let payload_len = (TCP_MIN_HEADER_LEN as u16).to_be_bytes();
        packet[ip_offset + 4] = payload_len[0];
        packet[ip_offset + 5] = payload_len[1];
        packet[ip_offset + 6] = 6; // TCP
        packet[ip_offset + 7] = 64; // Hop limit
        // src/dst IPv6
        packet[ip_offset + 8..ip_offset + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip_offset + 24..ip_offset + 40]
            .copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());

        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp_offset + 12] = 0x50; // Data offset 5

        let result = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(result.src_ip, IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(
            result.dst_ip,
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1))
        );
    }

    #[test]
    fn test_ip_checksum_algorithm() {
        // RFC 1071 example
        let mut header = vec![
            0x45, 0x00, 0x00, 0x73, // Version, IHL, TOS, Total Length
            0x00, 0x00, 0x40, 0x00, // ID, Flags, Fragment
            0x40, 0x11, 0x00, 0x00, // TTL, Protocol, Checksum (zeroed)
            0xc0, 0xa8, 0x00, 0x01, // Source IP: 192.168.0.1
            0xc0, 0xa8, 0x00, 0xc7, // Dest IP: 192.168.0.199
        ];

        calculate_ip_checksum(&mut header);
        assert!(verify_ip_checksum(&header));
    }

    #[test]
    fn test_protocol_numbers() {
        assert_eq!(IpProtocol::from_number(1), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_number(58), IpProtocol::Icmpv6);
        assert_eq!(IpProtocol::from_number(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_number(17), IpProtocol::Udp);
        assert_eq!(IpProtocol::from_number(132), IpProtocol::Unknown(132)); // SCTP

        assert_eq!(IpProtocol::Tcp.to_number(), 6);
        assert_eq!(IpProtocol::Unknown(47).to_number(), 47); // GRE
    }

    #[test]
    fn test_ipv4_frame_with_ethernet_padding() {
        // Create a valid TCP packet (54 bytes: 14 ETH + 20 IP + 20 TCP)
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        assert_eq!(packet.len(), 54);

        // Extend to 64 bytes with garbage padding (simulating Ethernet minimum frame)
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34]);
        assert_eq!(packet.len(), 64);

        // IP total_length is 40 (correct: 20 IP + 20 TCP), frame is 64
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 443);
    }

    #[test]
    fn test_ipv4_total_length_shorter_than_frame_with_fake_ports() {
        // Create a valid TCP packet
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        // Extend with padding that contains fake port numbers
        // Fake src_port=0xDEAD, dst_port=0xBEEF at padding offset
        packet.extend_from_slice(&[
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);

        let parsed = parse_ethernet_frame(&packet).unwrap();
        // Should read real ports, not fake padding ports
        assert_eq!(parsed.src_port, 12345);
        assert_eq!(parsed.dst_port, 443);
    }

    #[test]
    fn test_ipv4_total_length_less_than_ip_header() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let ip_offset = ETH_HEADER_LEN;
        // Set total_length to 15 (less than 20-byte IP header with IHL=5)
        packet[ip_offset + 2] = 0;
        packet[ip_offset + 3] = 15;
        calculate_ip_checksum(&mut packet[ip_offset..ip_offset + IP_MIN_HEADER_LEN]);

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::IpLengthMismatch { .. })));
    }

    #[test]
    fn test_ipv6_frame_with_padding() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset] = 0x60; // Version 6
        let payload_len = (TCP_MIN_HEADER_LEN as u16).to_be_bytes();
        packet[ip_offset + 4] = payload_len[0];
        packet[ip_offset + 5] = payload_len[1];
        packet[ip_offset + 6] = 6; // TCP
        packet[ip_offset + 7] = 64;
        packet[ip_offset + 8..ip_offset + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip_offset + 24..ip_offset + 40]
            .copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());

        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp_offset + 12] = 0x50; // Data offset 5

        // Add 10 bytes of garbage padding
        packet.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34]);

        let result = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(result.src_port, 1234);
        assert_eq!(result.dst_port, 443);
    }

    #[test]
    fn test_ipv6_payload_len_too_small_for_tcp() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset] = 0x60; // Version 6
        // payload_len = 10 (less than TCP_MIN_HEADER_LEN=20)
        let payload_len = 10u16.to_be_bytes();
        packet[ip_offset + 4] = payload_len[0];
        packet[ip_offset + 5] = payload_len[1];
        packet[ip_offset + 6] = 6; // TCP
        packet[ip_offset + 7] = 64;
        packet[ip_offset + 8..ip_offset + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip_offset + 24..ip_offset + 40]
            .copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());

        let tcp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[tcp_offset..tcp_offset + 2].copy_from_slice(&1234u16.to_be_bytes());
        packet[tcp_offset + 2..tcp_offset + 4].copy_from_slice(&443u16.to_be_bytes());

        let result = parse_ethernet_frame(&packet);
        // Transport slice is only 10 bytes, not enough for TCP header
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ip_length_mismatch_rejected() {
        // Create a valid packet, then corrupt the IP total length
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        // Set IP total length to larger than actual data (claims 1000 bytes, actual is 40)
        let ip_offset = ETH_HEADER_LEN;
        packet[ip_offset + 2] = 0x03; // 1000 >> 8
        packet[ip_offset + 3] = 0xE8; // 1000 & 0xFF

        // Recalculate checksum
        calculate_ip_checksum(&mut packet[ip_offset..ip_offset + IP_MIN_HEADER_LEN]);

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::IpLengthMismatch { .. })));
    }

    // =========================================================================
    // IpProtocol coverage
    // =========================================================================

    #[test]
    fn test_ip_protocol_is_icmp() {
        assert!(IpProtocol::Icmp.is_icmp());
        assert!(IpProtocol::Icmpv6.is_icmp());
        assert!(!IpProtocol::Tcp.is_icmp());
        assert!(!IpProtocol::Udp.is_icmp());
        assert!(!IpProtocol::Unknown(99).is_icmp());
    }

    #[test]
    fn test_ip_protocol_roundtrip() {
        for n in [1u8, 6, 17, 58, 0, 255] {
            let proto = IpProtocol::from_number(n);
            assert_eq!(proto.to_number(), n);
        }
    }

    // =========================================================================
    // ParseError Display coverage
    // =========================================================================

    #[test]
    fn test_parse_error_display() {
        let e = ParseError::TooShort {
            expected: 34,
            got: 10,
        };
        assert!(e.to_string().contains("34"));
        assert!(e.to_string().contains("10"));

        let e = ParseError::NotIp { ethertype: 0x0806 };
        assert!(e.to_string().contains("0806"));

        let e = ParseError::InvalidIpVersion { version: 3 };
        assert!(e.to_string().contains('3'));

        let e = ParseError::InvalidIpHeaderLen { ihl: 2 };
        assert!(e.to_string().contains('2'));

        let e = ParseError::IpLengthMismatch {
            header: 1000,
            actual: 40,
        };
        assert!(e.to_string().contains("1000"));

        let e = ParseError::InvalidTcpHeaderLen { data_offset: 4 };
        assert!(e.to_string().contains('4'));

        let e = ParseError::InvalidUdpLength { length: 7 };
        assert!(e.to_string().contains('7'));

        let e = ParseError::TransportLengthMismatch {
            protocol: IpProtocol::Udp,
            header: 12,
            actual: 8,
        };
        assert!(e.to_string().contains("UDP"));

        let e = ParseError::UnsupportedIpv6Extension { next_header: 99 };
        assert!(e.to_string().contains("99"));
    }

    #[test]
    fn test_parse_error_is_error_trait() {
        let e: Box<dyn std::error::Error> = Box::new(ParseError::TooShort {
            expected: 1,
            got: 0,
        });
        assert!(e.to_string().contains("too short"));
    }

    // =========================================================================
    // IPv4 edge cases
    // =========================================================================

    #[test]
    fn test_ipv4_with_ip_options() {
        // IHL = 6 → 24-byte IP header (4 bytes of options)
        let ip_header_len = 24;
        let mut packet = vec![0u8; ETH_HEADER_LEN + ip_header_len + TCP_MIN_HEADER_LEN];

        // Ethernet
        packet[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        // IP header with IHL=6
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x46; // Version 4, IHL 6
        let total_len = (ip_header_len + TCP_MIN_HEADER_LEN) as u16;
        packet[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        packet[ip + 6..ip + 8].copy_from_slice(&[0x40, 0x00]); // DF
        packet[ip + 8] = 64; // TTL
        packet[ip + 9] = 6; // TCP
        packet[ip + 12..ip + 16].copy_from_slice(&[10, 0, 2, 15]);
        packet[ip + 16..ip + 20].copy_from_slice(&[1, 2, 3, 4]);
        // Options (NOP padding)
        packet[ip + 20..ip + 24].copy_from_slice(&[0x01, 0x01, 0x01, 0x01]);
        calculate_ip_checksum(&mut packet[ip..ip + ip_header_len]);

        // TCP header
        let tcp = ETH_HEADER_LEN + ip_header_len;
        packet[tcp..tcp + 2].copy_from_slice(&8080u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 12] = 0x50; // Data offset 5

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.src_port, 8080);
        assert_eq!(parsed.dst_port, 443);
        assert!(parsed.ip_checksum_valid);
    }

    #[test]
    fn test_ipv4_ihl_too_small() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x43; // Version 4, IHL 3 (invalid)
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::InvalidIpHeaderLen { ihl: 3 })
        ));
    }

    #[test]
    fn test_ipv4_wrong_version() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x35; // Version 3, IHL 5
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::InvalidIpVersion { version: 3 })
        ));
    }

    #[test]
    fn test_ipv4_fragment_offset_nonzero() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let ip = ETH_HEADER_LEN;
        // Set fragment offset = 100 (no MF flag)
        packet[ip + 6] = 0x00;
        packet[ip + 7] = 100;
        calculate_ip_checksum(&mut packet[ip..ip + IP_MIN_HEADER_LEN]);

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert!(parsed.is_fragmented, "nonzero fragment offset → fragmented");
    }

    #[test]
    fn test_ipv4_icmp_protocol() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 0, 0);
        let ip = ETH_HEADER_LEN;
        packet[ip + 9] = 1; // ICMP
        calculate_ip_checksum(&mut packet[ip..ip + IP_MIN_HEADER_LEN]);

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Icmp);
        // ICMP has no ports
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
    }

    #[test]
    fn test_ipv4_ihl_exceeds_frame_len() {
        // Create packet with IHL=15 (60 bytes) but frame is only 54 bytes total
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x4F; // IHL=15 → 60 byte header, but data after ETH is only 40 bytes
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv4_tcp_header_too_short() {
        // Create a frame where IP says TCP but not enough bytes for TCP header
        let mut packet = vec![0u8; ETH_HEADER_LEN + IP_MIN_HEADER_LEN + 4]; // only 4 bytes of TCP
        packet[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x45;
        let total_len = (IP_MIN_HEADER_LEN + 4) as u16;
        packet[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        packet[ip + 6..ip + 8].copy_from_slice(&[0x40, 0x00]);
        packet[ip + 8] = 64;
        packet[ip + 9] = 6; // TCP
        packet[ip + 12..ip + 16].copy_from_slice(&[10, 0, 2, 15]);
        packet[ip + 16..ip + 20].copy_from_slice(&[1, 2, 3, 4]);
        calculate_ip_checksum(&mut packet[ip..ip + IP_MIN_HEADER_LEN]);

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv4_udp_header_too_short() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IP_MIN_HEADER_LEN + 4]; // only 4 bytes of UDP
        packet[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV4.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x45;
        let total_len = (IP_MIN_HEADER_LEN + 4) as u16;
        packet[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        packet[ip + 6..ip + 8].copy_from_slice(&[0x40, 0x00]);
        packet[ip + 8] = 64;
        packet[ip + 9] = 17; // UDP
        packet[ip + 12..ip + 16].copy_from_slice(&[10, 0, 2, 15]);
        packet[ip + 16..ip + 20].copy_from_slice(&[1, 2, 3, 4]);
        calculate_ip_checksum(&mut packet[ip..ip + IP_MIN_HEADER_LEN]);

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv4_tcp_data_offset_too_small() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let tcp = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[tcp + 12] = 0x40; // data offset = 4 (16 bytes), below TCP minimum

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::InvalidTcpHeaderLen { data_offset: 4 })
        ));
    }

    #[test]
    fn test_ipv4_tcp_data_offset_exceeds_payload() {
        let mut packet = make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let tcp = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[tcp + 12] = 0x60; // data offset = 6 (24 bytes), but only 20 bytes available

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv4_udp_length_too_small() {
        let mut packet = make_udp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 53);
        let udp = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[udp + 4..udp + 6].copy_from_slice(&7u16.to_be_bytes());

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::InvalidUdpLength { length: 7 })
        ));
    }

    #[test]
    fn test_ipv4_udp_length_exceeds_payload() {
        let mut packet = make_udp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 53);
        let udp = ETH_HEADER_LEN + IP_MIN_HEADER_LEN;
        packet[udp + 4..udp + 6].copy_from_slice(&12u16.to_be_bytes());

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::TransportLengthMismatch {
                protocol: IpProtocol::Udp,
                header: 12,
                actual: 8,
            })
        ));
    }

    #[test]
    fn test_ipv4_udp_length_shorter_than_payload() {
        let mut packet = make_udp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 53);
        packet.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd]);

        let ip = ETH_HEADER_LEN;
        let total_len = (IP_MIN_HEADER_LEN + UDP_HEADER_LEN + 4) as u16;
        packet[ip + 2..ip + 4].copy_from_slice(&total_len.to_be_bytes());
        calculate_ip_checksum(&mut packet[ip..ip + IP_MIN_HEADER_LEN]);

        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::TransportLengthMismatch {
                protocol: IpProtocol::Udp,
                header: 8,
                actual: 12,
            })
        ));
    }

    // =========================================================================
    // IPv6 edge cases
    // =========================================================================

    fn make_ipv6_frame(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60; // Version 6
        let payload_len = (payload.len() as u16).to_be_bytes();
        packet[ip + 4] = payload_len[0];
        packet[ip + 5] = payload_len[1];
        packet[ip + 6] = next_header;
        packet[ip + 7] = 64; // Hop limit
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1).octets());
        let transport = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[transport..transport + payload.len()].copy_from_slice(payload);
        packet
    }

    #[test]
    fn test_ipv6_udp() {
        let mut udp_data = [0u8; UDP_HEADER_LEN];
        udp_data[0..2].copy_from_slice(&5353u16.to_be_bytes());
        udp_data[2..4].copy_from_slice(&53u16.to_be_bytes());
        udp_data[4..6].copy_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());

        let packet = make_ipv6_frame(17, &udp_data); // UDP
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Udp);
        assert_eq!(parsed.src_port, 5353);
        assert_eq!(parsed.dst_port, 53);
        assert!(parsed.ip_checksum_valid); // IPv6 always true
    }

    #[test]
    fn test_ipv6_icmpv6() {
        let icmp_data = [0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01]; // echo request
        let packet = make_ipv6_frame(58, &icmp_data); // ICMPv6
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Icmpv6);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
    }

    #[test]
    fn test_ipv6_wrong_version() {
        let tcp_data = [0u8; TCP_MIN_HEADER_LEN];
        let mut packet = make_ipv6_frame(6, &tcp_data);
        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x40; // Version 4 in IPv6 frame
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(
            result,
            Err(ParseError::InvalidIpVersion { version: 4 })
        ));
    }

    #[test]
    fn test_ipv6_payload_len_overflow() {
        let tcp_data = [0u8; TCP_MIN_HEADER_LEN];
        let mut packet = make_ipv6_frame(6, &tcp_data);
        let ip = ETH_HEADER_LEN;
        // Set payload_len to 60000 (way larger than actual)
        packet[ip + 4] = 0xEA;
        packet[ip + 5] = 0x60;
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::IpLengthMismatch { .. })));
    }

    #[test]
    fn test_ipv6_too_short_for_header() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + 20]; // Less than 40-byte IPv6 header
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv6_udp_too_short() {
        // Payload is only 4 bytes (need 8 for UDP)
        let udp_data = [0u8; 4];
        let packet = make_ipv6_frame(17, &udp_data);
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv6_tcp_too_short() {
        // Payload is only 10 bytes (need 20 for TCP)
        let tcp_data = [0u8; 10];
        let packet = make_ipv6_frame(6, &tcp_data);
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    #[test]
    fn test_ipv6_fragment_header() {
        // Fragment header (next_header=44), then TCP
        // Fragment header: 8 bytes [next_header, reserved, frag_offset_flags, identification]
        let mut payload = vec![0u8; 8 + TCP_MIN_HEADER_LEN];
        payload[0] = 6; // Next header after fragment = TCP
        payload[1] = 0; // Reserved
        // Fragment offset + M flag
        payload[2] = 0;
        payload[3] = 0;
        // TCP ports
        let tcp_start = 8;
        payload[tcp_start..tcp_start + 2].copy_from_slice(&9999u16.to_be_bytes());
        payload[tcp_start + 2..tcp_start + 4].copy_from_slice(&80u16.to_be_bytes());
        payload[tcp_start + 12] = 0x50;

        let packet = make_ipv6_frame(44, &payload); // 44 = Fragment
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert!(parsed.is_fragmented);
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert_eq!(parsed.src_port, 9999);
        assert_eq!(parsed.dst_port, 80);
    }

    #[test]
    fn test_ipv6_hop_by_hop_extension() {
        // Hop-by-hop (0) extension header, then TCP
        // Extension: [next_header, hdr_ext_len, ...padding...]
        // hdr_ext_len=0 → (0+1)*8 = 8 bytes
        let mut payload = vec![0u8; 8 + TCP_MIN_HEADER_LEN];
        payload[0] = 6; // Next header = TCP
        payload[1] = 0; // hdr_ext_len = 0 → 8 bytes total
        // TCP ports
        let tcp_start = 8;
        payload[tcp_start..tcp_start + 2].copy_from_slice(&4444u16.to_be_bytes());
        payload[tcp_start + 2..tcp_start + 4].copy_from_slice(&443u16.to_be_bytes());
        payload[tcp_start + 12] = 0x50;

        let packet = make_ipv6_frame(0, &payload); // 0 = Hop-by-Hop
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert_eq!(parsed.src_port, 4444);
        assert_eq!(parsed.dst_port, 443);
        assert!(!parsed.is_fragmented);
    }

    #[test]
    fn test_ipv6_routing_extension() {
        // Routing (43) extension header, then UDP
        let mut payload = vec![0u8; 8 + UDP_HEADER_LEN];
        payload[0] = 17; // Next header = UDP
        payload[1] = 0; // hdr_ext_len = 0 → 8 bytes
        let udp_start = 8;
        payload[udp_start..udp_start + 2].copy_from_slice(&7777u16.to_be_bytes());
        payload[udp_start + 2..udp_start + 4].copy_from_slice(&53u16.to_be_bytes());
        payload[udp_start + 4..udp_start + 6]
            .copy_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());

        let packet = make_ipv6_frame(43, &payload); // 43 = Routing
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Udp);
        assert_eq!(parsed.src_port, 7777);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn test_ipv6_destination_options_extension() {
        // Destination Options (60) extension header, then TCP
        let mut payload = vec![0u8; 8 + TCP_MIN_HEADER_LEN];
        payload[0] = 6; // Next header = TCP
        payload[1] = 0; // hdr_ext_len = 0 → 8 bytes
        let tcp_start = 8;
        payload[tcp_start..tcp_start + 2].copy_from_slice(&2222u16.to_be_bytes());
        payload[tcp_start + 2..tcp_start + 4].copy_from_slice(&80u16.to_be_bytes());
        payload[tcp_start + 12] = 0x50;

        let packet = make_ipv6_frame(60, &payload); // 60 = Destination Options
        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert_eq!(parsed.src_port, 2222);
        assert_eq!(parsed.dst_port, 80);
    }

    #[test]
    fn test_ipv6_extension_too_short() {
        // Hop-by-hop extension but only 1 byte of payload
        let payload = [0u8; 1];
        let packet = make_ipv6_frame(0, &payload);
        let result = parse_ethernet_frame(&packet);
        assert!(matches!(result, Err(ParseError::TooShort { .. })));
    }

    // =========================================================================
    // IP checksum edge cases
    // =========================================================================

    #[test]
    fn test_verify_ip_checksum_too_short() {
        let header = [0u8; 10]; // Less than 20 bytes
        assert!(!verify_ip_checksum(&header));
    }

    #[test]
    fn test_verify_ip_checksum_odd_length() {
        let header = [0u8; 21]; // Not multiple of 2
        assert!(!verify_ip_checksum(&header));
    }

    // =========================================================================
    // IPv6 extension header coverage
    // =========================================================================

    /// Build a minimal IPv6 packet with given `next_header` and optional extension
    fn make_ipv6_tcp_packet(src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_MIN_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60; // Version 6
        let payload_len = (TCP_MIN_HEADER_LEN as u16).to_be_bytes();
        packet[ip + 4] = payload_len[0];
        packet[ip + 5] = payload_len[1];
        packet[ip + 6] = 6; // TCP next_header
        packet[ip + 7] = 64; // Hop limit
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let tcp = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[tcp..tcp + 2].copy_from_slice(&src_port.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&dst_port.to_be_bytes());
        packet[tcp + 12] = 0x50; // Data offset 5
        packet[tcp + 13] = 0x02; // SYN
        packet
    }

    #[test]
    fn test_ipv6_with_hop_by_hop_extension() {
        // Build: IPv6 (next_header=0 Hop-by-Hop) → Extension (next_header=6 TCP) → TCP
        let ext_len = 8; // Minimum extension header size (hdr_ext_len=0 → (0+1)*8=8)
        let tcp_len = TCP_MIN_HEADER_LEN;
        let payload_len = ext_len + tcp_len;

        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[ip + 6] = 0; // Next header: Hop-by-Hop (0)
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        // Hop-by-Hop extension header
        let ext = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[ext] = 6; // Next header: TCP
        packet[ext + 1] = 0; // Hdr ext len: 0 → 8 bytes total

        // TCP header
        let tcp = ext + ext_len;
        packet[tcp..tcp + 2].copy_from_slice(&4321u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 12] = 0x50;
        packet[tcp + 13] = 0x02; // SYN

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.src_port, 4321);
        assert_eq!(parsed.dst_port, 443);
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert!(!parsed.is_fragmented);
    }

    #[test]
    fn test_ipv6_with_routing_extension() {
        // IPv6 (next_header=43 Routing) → Extension → TCP
        let ext_len = 8;
        let tcp_len = TCP_MIN_HEADER_LEN;
        let payload_len = ext_len + tcp_len;

        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[ip + 6] = 43; // Routing header
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let ext = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[ext] = 6; // Next: TCP
        packet[ext + 1] = 0;

        let tcp = ext + ext_len;
        packet[tcp..tcp + 2].copy_from_slice(&5555u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&80u16.to_be_bytes());
        packet[tcp + 12] = 0x50;

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.src_port, 5555);
        assert_eq!(parsed.dst_port, 80);
    }

    #[test]
    fn test_ipv6_with_fragment_header() {
        // IPv6 (next_header=44 Fragment) → Fragment hdr (8 bytes) → TCP
        let frag_len = 8;
        let tcp_len = TCP_MIN_HEADER_LEN;
        let payload_len = frag_len + tcp_len;

        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&(payload_len as u16).to_be_bytes());
        packet[ip + 6] = 44; // Fragment header
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let frag = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[frag] = 6; // Next: TCP
        // rest of fragment header is zeros (offset=0, M=0)

        let tcp = frag + frag_len;
        packet[tcp..tcp + 2].copy_from_slice(&7777u16.to_be_bytes());
        packet[tcp + 2..tcp + 4].copy_from_slice(&443u16.to_be_bytes());
        packet[tcp + 12] = 0x50;

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert!(
            parsed.is_fragmented,
            "fragment header should set is_fragmented"
        );
        assert_eq!(parsed.src_port, 7777);
        assert_eq!(parsed.dst_port, 443);
    }

    #[test]
    fn test_ipv6_extension_header_truncated() {
        // IPv6 with Hop-by-Hop but not enough bytes for the extension header
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 1]; // only 1 byte after IPv6
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&1u16.to_be_bytes()); // payload_len = 1
        packet[ip + 6] = 0; // Hop-by-Hop
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let result = parse_ethernet_frame(&packet);
        assert!(
            matches!(result, Err(ParseError::TooShort { .. })),
            "truncated extension header should fail"
        );
    }

    #[test]
    fn test_ipv6_extension_header_body_truncated() {
        // IPv6 with Hop-by-Hop that claims larger size than available
        // Extension header: next=6, hdr_ext_len=2 → (2+1)*8=24 bytes needed, but only 8 available
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 8];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&8u16.to_be_bytes());
        packet[ip + 6] = 0; // Hop-by-Hop
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let ext = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[ext] = 6; // Next: TCP
        packet[ext + 1] = 2; // hdr_ext_len=2 → needs 24 bytes, but only 8 available

        let result = parse_ethernet_frame(&packet);
        assert!(
            matches!(result, Err(ParseError::TooShort { .. })),
            "extension body larger than frame should fail"
        );
    }

    #[test]
    fn test_ipv6_fragment_header_truncated() {
        // IPv6 with fragment header (44) but only 4 bytes after IPv6 (need 8)
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + 4];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&4u16.to_be_bytes());
        packet[ip + 6] = 44; // Fragment header
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let result = parse_ethernet_frame(&packet);
        assert!(
            matches!(result, Err(ParseError::TooShort { .. })),
            "truncated fragment header should fail"
        );
    }

    #[test]
    fn test_ipv6_tcp_flags_extracted() {
        let packet = make_ipv6_tcp_packet(12345, 443);
        let parsed = parse_ethernet_frame(&packet).unwrap();
        // SYN flag is at TCP offset 13 = 0x02
        assert_eq!(parsed.tcp_flags, Some(0x02));
    }

    #[test]
    fn test_ipv6_udp_has_no_tcp_flags() {
        let mut packet = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN];
        packet[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());

        let ip = ETH_HEADER_LEN;
        packet[ip] = 0x60;
        packet[ip + 4..ip + 6].copy_from_slice(&(UDP_HEADER_LEN as u16).to_be_bytes());
        packet[ip + 6] = 17; // UDP
        packet[ip + 7] = 64;
        packet[ip + 8..ip + 24].copy_from_slice(&Ipv6Addr::LOCALHOST.octets());
        packet[ip + 24..ip + 40]
            .copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let udp = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        packet[udp..udp + 2].copy_from_slice(&54321u16.to_be_bytes());
        packet[udp + 2..udp + 4].copy_from_slice(&53u16.to_be_bytes());
        let udp_len = (UDP_HEADER_LEN as u16).to_be_bytes();
        packet[udp + 4..udp + 6].copy_from_slice(&udp_len);

        let parsed = parse_ethernet_frame(&packet).unwrap();
        assert_eq!(parsed.tcp_flags, None, "UDP should not have tcp_flags");
        assert_eq!(parsed.protocol, IpProtocol::Udp);
    }
}
