// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Packet construction utilities for NAT proxy
//!
//! This module provides functions to parse and build Ethernet/IP/TCP/UDP packets
//! for proxying guest traffic through host sockets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =============================================================================
// Constants
// =============================================================================

/// Ethernet header size
pub const ETH_HEADER_LEN: usize = 14;
/// IPv4 header size (without options)
pub const IPV4_HEADER_LEN: usize = 20;
/// IPv6 header size
pub const IPV6_HEADER_LEN: usize = 40;
/// TCP header size (without options)
pub const TCP_HEADER_LEN: usize = 20;
/// UDP header size
pub const UDP_HEADER_LEN: usize = 8;

/// IP protocol numbers
pub const IP_PROTO_ICMP: u8 = 1;
pub const IP_PROTO_TCP: u8 = 6;
pub const IP_PROTO_UDP: u8 = 17;
pub const IP_PROTO_ICMPV6: u8 = 58;

/// Ethernet type for IPv4
pub const ETH_TYPE_IPV4: u16 = 0x0800;
/// Ethernet type for IPv6
pub const ETH_TYPE_IPV6: u16 = 0x86DD;

/// TCP flags
pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_PSH: u8 = 0x08;
pub const TCP_ACK: u8 = 0x10;

// =============================================================================
// Packet Parsing
// =============================================================================

/// Parsed Ethernet frame header
#[derive(Debug, Clone)]
pub struct EthernetHeader {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ether_type: u16,
}

impl EthernetHeader {
    /// Parse Ethernet header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < ETH_HEADER_LEN {
            return None;
        }
        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);
        let ether_type = u16::from_be_bytes([data[12], data[13]]);
        Some(Self {
            dst_mac,
            src_mac,
            ether_type,
        })
    }

    /// Write header to buffer
    pub fn write(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.dst_mac);
        buf[6..12].copy_from_slice(&self.src_mac);
        buf[12..14].copy_from_slice(&self.ether_type.to_be_bytes());
    }
}

/// Parsed IPv4 header
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version_ihl: u8,
    pub dscp_ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}

impl Ipv4Header {
    /// Parse IPv4 header from bytes (starting after Ethernet header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV4_HEADER_LEN {
            return None;
        }
        let version_ihl = data[0];
        // Check version is 4
        if (version_ihl >> 4) != 4 {
            return None;
        }
        // Validate IHL >= 5 (minimum 20-byte header) and fits in data
        let ihl = version_ihl & 0x0F;
        if ihl < 5 {
            return None;
        }
        let header_byte_len = (ihl as usize) * 4;
        if header_byte_len > data.len() {
            return None;
        }
        Some(Self {
            version_ihl,
            dscp_ecn: data[1],
            total_length: u16::from_be_bytes([data[2], data[3]]),
            identification: u16::from_be_bytes([data[4], data[5]]),
            flags_fragment: u16::from_be_bytes([data[6], data[7]]),
            ttl: data[8],
            protocol: data[9],
            checksum: u16::from_be_bytes([data[10], data[11]]),
            src_ip: Ipv4Addr::new(data[12], data[13], data[14], data[15]),
            dst_ip: Ipv4Addr::new(data[16], data[17], data[18], data[19]),
        })
    }

    /// Get header length in bytes
    pub const fn header_len(&self) -> usize {
        ((self.version_ihl & 0x0F) as usize) * 4
    }

    /// Check if packet is fragmented
    pub const fn is_fragmented(&self) -> bool {
        // MF flag set OR fragment offset non-zero
        (self.flags_fragment & 0x2000) != 0 || (self.flags_fragment & 0x1FFF) != 0
    }

    /// Write header to buffer (checksum calculated separately)
    pub fn write(&self, buf: &mut [u8]) {
        buf[0] = self.version_ihl;
        buf[1] = self.dscp_ecn;
        buf[2..4].copy_from_slice(&self.total_length.to_be_bytes());
        buf[4..6].copy_from_slice(&self.identification.to_be_bytes());
        buf[6..8].copy_from_slice(&self.flags_fragment.to_be_bytes());
        buf[8] = self.ttl;
        buf[9] = self.protocol;
        buf[10..12].copy_from_slice(&self.checksum.to_be_bytes());
        buf[12..16].copy_from_slice(&self.src_ip.octets());
        buf[16..20].copy_from_slice(&self.dst_ip.octets());
    }
}

/// Parsed IPv6 header
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub payload_len: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: Ipv6Addr,
    pub dst_ip: Ipv6Addr,
}

impl Ipv6Header {
    /// Parse IPv6 header from bytes (starting after Ethernet header)
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < IPV6_HEADER_LEN {
            return None;
        }
        let version = data[0] >> 4;
        if version != 6 {
            return None;
        }
        let payload_len = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];
        let mut src = [0u8; 16];
        let mut dst = [0u8; 16];
        src.copy_from_slice(&data[8..24]);
        dst.copy_from_slice(&data[24..40]);
        Some(Self {
            payload_len,
            next_header,
            hop_limit,
            src_ip: Ipv6Addr::from(src),
            dst_ip: Ipv6Addr::from(dst),
        })
    }

    /// Write header to buffer
    pub fn write(&self, buf: &mut [u8]) {
        // Version (6), Traffic Class + Flow Label = 0
        buf[0] = 0x60;
        buf[1] = 0;
        buf[2] = 0;
        buf[3] = 0;
        buf[4..6].copy_from_slice(&self.payload_len.to_be_bytes());
        buf[6] = self.next_header;
        buf[7] = self.hop_limit;
        buf[8..24].copy_from_slice(&self.src_ip.octets());
        buf[24..40].copy_from_slice(&self.dst_ip.octets());
    }
}

/// Parsed TCP header
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Parse TCP header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < TCP_HEADER_LEN {
            return None;
        }
        let data_offset = data[12] >> 4;
        // Validate data_offset >= 5 (minimum 20-byte header)
        if data_offset < 5 {
            return None;
        }
        let header_len = (data_offset as usize) * 4;
        if header_len > data.len() {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            seq_num: u32::from_be_bytes([data[4], data[5], data[6], data[7]]),
            ack_num: u32::from_be_bytes([data[8], data[9], data[10], data[11]]),
            data_offset,
            flags: data[13],
            window: u16::from_be_bytes([data[14], data[15]]),
            checksum: u16::from_be_bytes([data[16], data[17]]),
            urgent_ptr: u16::from_be_bytes([data[18], data[19]]),
        })
    }

    /// Get header length in bytes
    pub const fn header_len(&self) -> usize {
        (self.data_offset as usize) * 4
    }

    /// Check if SYN flag is set
    pub const fn is_syn(&self) -> bool {
        (self.flags & TCP_SYN) != 0 && (self.flags & TCP_ACK) == 0
    }

    /// Check if ACK flag is set
    pub const fn is_ack(&self) -> bool {
        (self.flags & TCP_ACK) != 0
    }

    /// Check if FIN flag is set
    pub const fn is_fin(&self) -> bool {
        (self.flags & TCP_FIN) != 0
    }

    /// Check if RST flag is set
    pub const fn is_rst(&self) -> bool {
        (self.flags & TCP_RST) != 0
    }

    /// Check if this is a SYN-ACK
    pub const fn is_syn_ack(&self) -> bool {
        (self.flags & TCP_SYN) != 0 && (self.flags & TCP_ACK) != 0
    }

    /// Check if the control flag combination is valid enough to proxy.
    pub const fn has_valid_flag_combination(&self) -> bool {
        let syn = (self.flags & TCP_SYN) != 0;
        let fin = (self.flags & TCP_FIN) != 0;
        let rst = (self.flags & TCP_RST) != 0;

        !(syn && (fin || rst)) && !(fin && rst)
    }

    /// Write header to buffer (checksum calculated separately)
    pub fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..8].copy_from_slice(&self.seq_num.to_be_bytes());
        buf[8..12].copy_from_slice(&self.ack_num.to_be_bytes());
        buf[12] = self.data_offset << 4; // Reserved bits
        buf[13] = self.flags;
        buf[14..16].copy_from_slice(&self.window.to_be_bytes());
        buf[16..18].copy_from_slice(&self.checksum.to_be_bytes());
        buf[18..20].copy_from_slice(&self.urgent_ptr.to_be_bytes());
    }
}

/// Parsed UDP header
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse UDP header from bytes
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < UDP_HEADER_LEN {
            return None;
        }
        let length = u16::from_be_bytes([data[4], data[5]]);
        let length_usize = length as usize;
        if !(UDP_HEADER_LEN..=data.len()).contains(&length_usize) {
            return None;
        }
        Some(Self {
            src_port: u16::from_be_bytes([data[0], data[1]]),
            dst_port: u16::from_be_bytes([data[2], data[3]]),
            length,
            checksum: u16::from_be_bytes([data[6], data[7]]),
        })
    }

    /// Write header to buffer
    pub fn write(&self, buf: &mut [u8]) {
        buf[0..2].copy_from_slice(&self.src_port.to_be_bytes());
        buf[2..4].copy_from_slice(&self.dst_port.to_be_bytes());
        buf[4..6].copy_from_slice(&self.length.to_be_bytes());
        buf[6..8].copy_from_slice(&self.checksum.to_be_bytes());
    }
}

/// Validated IP packet metadata and exact transport bytes.
pub(crate) enum ParsedIpPacket<'a> {
    /// Validated IPv4 packet.
    V4 {
        /// Source IPv4 address.
        src_ip: Ipv4Addr,
        /// Destination IPv4 address.
        dst_ip: Ipv4Addr,
        /// Whether the IPv4 packet is fragmented.
        is_fragmented: bool,
        /// Transport protocol number.
        protocol: u8,
        /// Exact transport bytes covered by the IP packet length.
        transport_data: &'a [u8],
    },
    /// Validated IPv6 packet.
    V6 {
        /// Source IPv6 address.
        src_ip: Ipv6Addr,
        /// Destination IPv6 address.
        dst_ip: Ipv6Addr,
        /// Transport protocol number.
        protocol: u8,
        /// Exact transport bytes covered by the IP packet length.
        transport_data: &'a [u8],
    },
}

impl<'a> ParsedIpPacket<'a> {
    /// Source IP address.
    pub(crate) const fn src_ip(&self) -> IpAddr {
        match *self {
            Self::V4 { src_ip, .. } => IpAddr::V4(src_ip),
            Self::V6 { src_ip, .. } => IpAddr::V6(src_ip),
        }
    }

    /// Destination IP address.
    pub(crate) const fn dst_ip(&self) -> IpAddr {
        match *self {
            Self::V4 { dst_ip, .. } => IpAddr::V4(dst_ip),
            Self::V6 { dst_ip, .. } => IpAddr::V6(dst_ip),
        }
    }

    /// Whether the packet is fragmented.
    pub(crate) const fn is_fragmented(&self) -> bool {
        match *self {
            Self::V4 { is_fragmented, .. } => is_fragmented,
            Self::V6 { .. } => false,
        }
    }

    /// Transport protocol number.
    pub(crate) const fn protocol(&self) -> u8 {
        match *self {
            Self::V4 { protocol, .. } | Self::V6 { protocol, .. } => protocol,
        }
    }

    /// Exact transport bytes covered by the IP packet length.
    pub(crate) const fn transport_data(&self) -> &'a [u8] {
        match *self {
            Self::V4 { transport_data, .. } | Self::V6 { transport_data, .. } => transport_data,
        }
    }

    /// Build a response flow from this packet's destination back to its source.
    pub(crate) const fn response_flow(
        &self,
        dst_mac: [u8; 6],
        src_port: u16,
        dst_port: u16,
    ) -> FlowEndpoints {
        match *self {
            Self::V4 { src_ip, dst_ip, .. } => {
                FlowEndpoints::v4(dst_mac, dst_ip, src_ip, src_port, dst_port)
            }
            Self::V6 { src_ip, dst_ip, .. } => {
                FlowEndpoints::v6(dst_mac, dst_ip, src_ip, src_port, dst_port)
            }
        }
    }
}

/// Parse an IPv4/IPv6 packet after the Ethernet header with strict lengths.
pub(crate) fn parse_ip_packet(ether_type: u16, data: &[u8]) -> Option<ParsedIpPacket<'_>> {
    match ether_type {
        ETH_TYPE_IPV4 => {
            let ip = Ipv4Header::parse(data)?;
            let header_len = ip.header_len();
            let total_len = ip.total_length as usize;
            if total_len < header_len || total_len > data.len() {
                return None;
            }
            if calculate_ip_checksum(&data[..header_len]) != ip.checksum {
                return None;
            }
            Some(ParsedIpPacket::V4 {
                src_ip: ip.src_ip,
                dst_ip: ip.dst_ip,
                is_fragmented: ip.is_fragmented(),
                protocol: ip.protocol,
                transport_data: &data[header_len..total_len],
            })
        }
        ETH_TYPE_IPV6 => {
            let ip = Ipv6Header::parse(data)?;
            let total_len = IPV6_HEADER_LEN + ip.payload_len as usize;
            if total_len > data.len() {
                return None;
            }
            Some(ParsedIpPacket::V6 {
                src_ip: ip.src_ip,
                dst_ip: ip.dst_ip,
                protocol: ip.next_header,
                transport_data: &data[IPV6_HEADER_LEN..total_len],
            })
        }
        _ => None,
    }
}

/// Parse and validate a full TCP segment before host-side effects.
pub(crate) fn parse_tcp_segment(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    data: &[u8],
) -> Option<(TcpHeader, &[u8])> {
    let tcp = TcpHeader::parse(data)?;
    if !tcp.has_valid_flag_combination() {
        return None;
    }
    let header_len = tcp.header_len();
    let payload = &data[header_len..];
    let expected = match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            calculate_tcp_checksum(src, dst, &data[..header_len], payload)
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            calculate_tcp_checksum_v6(src, dst, &data[..header_len], payload)
        }
        _ => return None,
    };
    if tcp.checksum != expected {
        return None;
    }
    Some((tcp, payload))
}

/// Parse and validate a full UDP datagram before host-side effects.
pub(crate) fn parse_udp_datagram(
    src_ip: IpAddr,
    dst_ip: IpAddr,
    data: &[u8],
) -> Option<(UdpHeader, &[u8])> {
    let udp = UdpHeader::parse(data)?;
    let udp_len = udp.length as usize;
    if udp_len != data.len() {
        return None;
    }
    let payload = &data[UDP_HEADER_LEN..udp_len];
    match (src_ip, dst_ip) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            if udp.checksum != 0 {
                let expected = calculate_udp_checksum(src, dst, &data[..UDP_HEADER_LEN], payload);
                if udp.checksum != expected {
                    return None;
                }
            }
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            if udp.checksum == 0 {
                return None;
            }
            let expected = calculate_udp_checksum_v6(src, dst, &data[..UDP_HEADER_LEN], payload);
            if udp.checksum != expected {
                return None;
            }
        }
        _ => return None,
    }
    Some((udp, payload))
}

// =============================================================================
// Checksum Calculation
// =============================================================================

/// Calculate IP header checksum (RFC 1071).
pub fn calculate_ip_checksum(header: &[u8]) -> u16 {
    if header.len() < IPV4_HEADER_LEN {
        return 0;
    }
    let ihl = (header[0] & 0x0F) as usize;
    let header_len = (ihl * 4).min(header.len());
    if header_len < IPV4_HEADER_LEN {
        return 0;
    }
    let mut sum: u32 = 0;

    for i in (0..header_len).step_by(2) {
        if i == 10 {
            // Skip checksum field
            continue;
        }
        let word = if i + 1 < header_len {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }

    checksum_fold(sum)
}

/// Narrow a `usize` length to `u16`.
///
/// All packet lengths in our builder are bounded by MTU (1500) and thus
/// well under `u16::MAX` (65535). This centralizes the truncation cast
/// instead of scattering `#[allow(cast_possible_truncation)]` at each site.
///
/// Saturates to `u16::MAX` if the value overflows (should not happen for
/// MTU-bounded packets, but is safe in all cases).
pub(crate) fn mtu_bounded_u16(len: usize) -> u16 {
    u16::try_from(len).unwrap_or(u16::MAX)
}

/// Narrow a `usize` length to `u32`.
///
/// Used for pseudo-header length fields which sum header + payload sizes.
///
/// Saturates to `u32::MAX` if the value overflows.
pub(crate) fn mtu_bounded_u32(len: usize) -> u32 {
    u32::try_from(len).unwrap_or(u32::MAX)
}

/// Compute one's complement sum of a header (skipping `checksum_offset..checksum_offset+2`)
/// and payload, then fold and complement. `pseudo_header_sum` is the pre-computed
/// pseudo-header contribution.
fn checksum_with_pseudo_header(
    pseudo_header_sum: u32,
    header: &[u8],
    checksum_offset: usize,
    payload: &[u8],
) -> u16 {
    let mut sum = pseudo_header_sum;

    for i in (0..header.len()).step_by(2) {
        if i == checksum_offset {
            continue;
        }
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }

    for i in (0..payload.len()).step_by(2) {
        let word = if i + 1 < payload.len() {
            u16::from_be_bytes([payload[i], payload[i + 1]])
        } else {
            u16::from_be_bytes([payload[i], 0])
        };
        sum = sum.wrapping_add(u32::from(word));
    }

    checksum_fold(sum)
}

/// Build the IPv4 pseudo-header sum for TCP/UDP checksum calculation.
fn ipv4_pseudo_header_sum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    protocol: u8,
    transport_len: usize,
) -> u32 {
    let src = src_ip.octets();
    let dst = dst_ip.octets();
    let mut sum: u32 = 0;
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[0], src[1]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([src[2], src[3]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[0], dst[1]])));
    sum = sum.wrapping_add(u32::from(u16::from_be_bytes([dst[2], dst[3]])));
    sum = sum.wrapping_add(u32::from(protocol));
    sum = sum.wrapping_add(mtu_bounded_u32(transport_len));
    sum
}

/// Build the IPv6 pseudo-header sum for TCP/UDP checksum calculation.
fn ipv6_pseudo_header_sum(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    protocol: u8,
    transport_len: usize,
) -> u32 {
    let mut sum: u32 = 0;
    for chunk in src_ip.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    for chunk in dst_ip.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    let len = mtu_bounded_u32(transport_len);
    sum = sum.wrapping_add(len >> 16);
    sum = sum.wrapping_add(len & 0xFFFF);
    sum = sum.wrapping_add(u32::from(protocol));
    sum
}

/// Calculate TCP checksum with pseudo-header (RFC 1071).
pub fn calculate_tcp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    tcp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let total_len = tcp_header.len() + payload.len();
    let pseudo = ipv4_pseudo_header_sum(src_ip, dst_ip, IP_PROTO_TCP, total_len);
    checksum_with_pseudo_header(pseudo, tcp_header, 16, payload)
}

/// Calculate UDP checksum with pseudo-header (RFC 1071).
pub fn calculate_udp_checksum(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    udp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let total_len = udp_header.len() + payload.len();
    let pseudo = ipv4_pseudo_header_sum(src_ip, dst_ip, IP_PROTO_UDP, total_len);
    let checksum = checksum_with_pseudo_header(pseudo, udp_header, 6, payload);
    // UDP checksum of 0 means "no checksum", use 0xFFFF instead
    if checksum == 0 { 0xFFFF } else { checksum }
}

/// Fold a 32-bit one's complement sum to 16 bits and complement.
///
/// After the fold loop, `sum` is guaranteed to fit in 16 bits.
pub(crate) const fn checksum_fold(mut sum: u32) -> u16 {
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    // After folding, sum <= 0xFFFF — the loop guarantees upper 16 bits are 0.
    #[allow(clippy::cast_possible_truncation)]
    let folded = sum as u16;
    !folded
}

/// Calculate TCP checksum with IPv6 pseudo-header (RFC 1071).
pub fn calculate_tcp_checksum_v6(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    tcp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let total_len = tcp_header.len() + payload.len();
    let pseudo = ipv6_pseudo_header_sum(src_ip, dst_ip, IP_PROTO_TCP, total_len);
    checksum_with_pseudo_header(pseudo, tcp_header, 16, payload)
}

/// Calculate UDP checksum with IPv6 pseudo-header
pub fn calculate_udp_checksum_v6(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    udp_header: &[u8],
    payload: &[u8],
) -> u16 {
    let total_len = udp_header.len() + payload.len();
    let pseudo = ipv6_pseudo_header_sum(src_ip, dst_ip, IP_PROTO_UDP, total_len);
    let checksum = checksum_with_pseudo_header(pseudo, udp_header, 6, payload);
    if checksum == 0 { 0xFFFF } else { checksum }
}

// =============================================================================
// Packet Building
// =============================================================================

/// Network flow endpoint addresses used for packet construction.
pub enum FlowEndpoints {
    /// IPv4 flow endpoints.
    V4 {
        /// Destination Ethernet MAC.
        dst_mac: [u8; 6],
        /// Source IPv4 address.
        src_ip: Ipv4Addr,
        /// Destination IPv4 address.
        dst_ip: Ipv4Addr,
        /// Source transport port.
        src_port: u16,
        /// Destination transport port.
        dst_port: u16,
    },
    /// IPv6 flow endpoints.
    V6 {
        /// Destination Ethernet MAC.
        dst_mac: [u8; 6],
        /// Source IPv6 address.
        src_ip: Ipv6Addr,
        /// Destination IPv6 address.
        dst_ip: Ipv6Addr,
        /// Source transport port.
        src_port: u16,
        /// Destination transport port.
        dst_port: u16,
    },
}

impl FlowEndpoints {
    /// Create IPv4 flow endpoints.
    pub const fn v4(
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self::V4 {
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

    /// Create IPv6 flow endpoints.
    pub const fn v6(
        dst_mac: [u8; 6],
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
    ) -> Self {
        Self::V6 {
            dst_mac,
            src_ip,
            dst_ip,
            src_port,
            dst_port,
        }
    }

    /// Create flow endpoints from dynamically typed IP addresses.
    pub const fn from_ip_pair(
        dst_mac: [u8; 6],
        src_ip: IpAddr,
        dst_ip: IpAddr,
        src_port: u16,
        dst_port: u16,
    ) -> Option<Self> {
        match (src_ip, dst_ip) {
            (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => {
                Some(Self::v4(dst_mac, src_ip, dst_ip, src_port, dst_port))
            }
            (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => {
                Some(Self::v6(dst_mac, src_ip, dst_ip, src_port, dst_port))
            }
            _ => None,
        }
    }

    /// Destination Ethernet MAC.
    pub const fn dst_mac(&self) -> [u8; 6] {
        match *self {
            Self::V4 { dst_mac, .. } | Self::V6 { dst_mac, .. } => dst_mac,
        }
    }

    /// Source transport port.
    pub const fn src_port(&self) -> u16 {
        match *self {
            Self::V4 { src_port, .. } | Self::V6 { src_port, .. } => src_port,
        }
    }

    /// Destination transport port.
    pub const fn dst_port(&self) -> u16 {
        match *self {
            Self::V4 { dst_port, .. } | Self::V6 { dst_port, .. } => dst_port,
        }
    }

    /// Destination IP address.
    pub const fn dst_ip(&self) -> IpAddr {
        match *self {
            Self::V4 { dst_ip, .. } => IpAddr::V4(dst_ip),
            Self::V6 { dst_ip, .. } => IpAddr::V6(dst_ip),
        }
    }
}

/// TCP segment parameters for internal packet construction.
struct TcpSegment<'a> {
    src_port: u16,
    dst_port: u16,
    seq_num: u32,
    ack_num: u32,
    flags: u8,
    window: u16,
    payload: &'a [u8],
}

/// Dispatch a `FlowEndpoints` to IPv4 or IPv6 code paths.
///
/// Usage: `dispatch_ip!(flow, |v4_src, v4_dst| { ... }, |v6_src, v6_dst| { ... })`
///
/// Both arms must return the same type.
macro_rules! dispatch_ip {
    ($flow:expr, |$v4s:ident, $v4d:ident| $v4:expr, |$v6s:ident, $v6d:ident| $v6:expr) => {
        match *$flow {
            FlowEndpoints::V4 {
                src_ip: $v4s,
                dst_ip: $v4d,
                ..
            } => $v4,
            FlowEndpoints::V6 {
                src_ip: $v6s,
                dst_ip: $v6d,
                ..
            } => $v6,
        }
    };
}

/// Builder for constructing response packets
pub struct PacketBuilder {
    /// Gateway MAC address (what we send from)
    pub gateway_mac: [u8; 6],
    /// IP identification counter
    ip_id: u16,
}

impl PacketBuilder {
    /// Create a new packet builder
    pub const fn new(gateway_mac: [u8; 6]) -> Self {
        Self {
            gateway_mac,
            ip_id: 1,
        }
    }

    /// Get next IP identification number
    const fn next_ip_id(&mut self) -> u16 {
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        id
    }

    /// Build a TCP SYN-ACK packet in response to a SYN (test convenience wrapper)
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_tcp_syn_ack(
        &mut self,
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        ack_num: u32,
        seq_num: u32,
        window: u16,
    ) -> Vec<u8> {
        self.build_tcp_v4(
            dst_mac,
            src_ip,
            dst_ip,
            &TcpSegment {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                flags: TCP_SYN | TCP_ACK,
                window,
                payload: &[],
            },
        )
    }

    /// Build a TCP ACK packet (test convenience wrapper)
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_tcp_ack(
        &mut self,
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        window: u16,
    ) -> Vec<u8> {
        self.build_tcp_v4(
            dst_mac,
            src_ip,
            dst_ip,
            &TcpSegment {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                flags: TCP_ACK,
                window,
                payload: &[],
            },
        )
    }

    /// Build a TCP data packet (test convenience wrapper)
    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn build_tcp_data(
        &mut self,
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq_num: u32,
        ack_num: u32,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        self.build_tcp_v4(
            dst_mac,
            src_ip,
            dst_ip,
            &TcpSegment {
                src_port,
                dst_port,
                seq_num,
                ack_num,
                flags: TCP_ACK | TCP_PSH,
                window,
                payload,
            },
        )
    }

    /// Build a TCP RST packet without ACK flag for IPv4 or IPv6
    pub fn build_tcp_rst_only_ip(&mut self, flow: &FlowEndpoints, seq_num: u32) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num: 0,
            flags: TCP_RST,
            window: 0,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP SYN packet for IPv4 or IPv6 (inbound port forwarding).
    pub fn build_tcp_syn_ip(&mut self, flow: &FlowEndpoints, seq_num: u32, window: u16) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num: 0,
            flags: TCP_SYN,
            window,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP SYN-ACK packet for IPv4 or IPv6
    pub fn build_tcp_syn_ack_ip(
        &mut self,
        flow: &FlowEndpoints,
        ack_num: u32,
        seq_num: u32,
        window: u16,
    ) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num,
            flags: TCP_SYN | TCP_ACK,
            window,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP ACK packet for IPv4 or IPv6
    pub fn build_tcp_ack_ip(
        &mut self,
        flow: &FlowEndpoints,
        seq_num: u32,
        ack_num: u32,
        window: u16,
    ) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num,
            flags: TCP_ACK,
            window,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP data packet for IPv4 or IPv6
    pub fn build_tcp_data_ip(
        &mut self,
        flow: &FlowEndpoints,
        seq_num: u32,
        ack_num: u32,
        window: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num,
            flags: TCP_ACK | TCP_PSH,
            window,
            payload,
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP FIN packet for IPv4 or IPv6
    pub fn build_tcp_fin_ip(
        &mut self,
        flow: &FlowEndpoints,
        seq_num: u32,
        ack_num: u32,
        window: u16,
    ) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num,
            flags: TCP_FIN | TCP_ACK,
            window,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a TCP RST packet for IPv4 or IPv6
    pub fn build_tcp_rst_ip(
        &mut self,
        flow: &FlowEndpoints,
        seq_num: u32,
        ack_num: u32,
    ) -> Vec<u8> {
        let seg = TcpSegment {
            src_port: flow.src_port(),
            dst_port: flow.dst_port(),
            seq_num,
            ack_num,
            flags: TCP_RST | TCP_ACK,
            window: 0,
            payload: &[],
        };
        dispatch_ip!(
            flow,
            |src, dst| self.build_tcp_v4(flow.dst_mac(), src, dst, &seg),
            |src, dst| self.build_tcp_v6(flow.dst_mac(), src, dst, &seg)
        )
    }

    /// Build a generic IPv4 TCP packet.
    fn build_tcp_v4(
        &mut self,
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        seg: &TcpSegment<'_>,
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + seg.payload.len();
        let mut packet = vec![0u8; total_len];

        // Ethernet header
        let eth = EthernetHeader {
            dst_mac,
            src_mac: self.gateway_mac,
            ether_type: ETH_TYPE_IPV4,
        };
        eth.write(&mut packet[0..ETH_HEADER_LEN]);

        // IP header — total length bounded by MTU (well under u16::MAX)
        let ip_total_len = mtu_bounded_u16(IPV4_HEADER_LEN + TCP_HEADER_LEN + seg.payload.len());
        let ip = Ipv4Header {
            version_ihl: 0x45, // IPv4, 5 words (20 bytes)
            dscp_ecn: 0,
            total_length: ip_total_len,
            identification: self.next_ip_id(),
            flags_fragment: 0x4000, // Don't fragment
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip,
            dst_ip,
        };
        ip.write(&mut packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        // Calculate and set IP checksum
        let ip_checksum =
            calculate_ip_checksum(&packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        packet[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12]
            .copy_from_slice(&ip_checksum.to_be_bytes());

        // TCP header
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let tcp = TcpHeader {
            src_port: seg.src_port,
            dst_port: seg.dst_port,
            seq_num: seg.seq_num,
            ack_num: seg.ack_num,
            data_offset: 5, // 20 bytes
            flags: seg.flags,
            window: seg.window,
            checksum: 0,
            urgent_ptr: 0,
        };
        tcp.write(&mut packet[tcp_start..tcp_start + TCP_HEADER_LEN]);

        // Copy payload
        let payload_start = tcp_start + TCP_HEADER_LEN;
        packet[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

        // Calculate and set TCP checksum
        let tcp_checksum = calculate_tcp_checksum(
            src_ip,
            dst_ip,
            &packet[tcp_start..tcp_start + TCP_HEADER_LEN],
            seg.payload,
        );
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    /// Build a generic IPv6 TCP packet.
    fn build_tcp_v6(
        &self,
        dst_mac: [u8; 6],
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        seg: &TcpSegment<'_>,
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN + seg.payload.len();
        let mut packet = vec![0u8; total_len];

        let eth = EthernetHeader {
            dst_mac,
            src_mac: self.gateway_mac,
            ether_type: ETH_TYPE_IPV6,
        };
        eth.write(&mut packet[0..ETH_HEADER_LEN]);

        let ipv6 = Ipv6Header {
            payload_len: mtu_bounded_u16(TCP_HEADER_LEN + seg.payload.len()),
            next_header: IP_PROTO_TCP,
            hop_limit: 64,
            src_ip,
            dst_ip,
        };
        ipv6.write(&mut packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader {
            src_port: seg.src_port,
            dst_port: seg.dst_port,
            seq_num: seg.seq_num,
            ack_num: seg.ack_num,
            data_offset: 5,
            flags: seg.flags,
            window: seg.window,
            checksum: 0,
            urgent_ptr: 0,
        };
        tcp.write(&mut packet[tcp_start..tcp_start + TCP_HEADER_LEN]);

        let payload_start = tcp_start + TCP_HEADER_LEN;
        packet[payload_start..payload_start + seg.payload.len()].copy_from_slice(seg.payload);

        let tcp_checksum = calculate_tcp_checksum_v6(
            src_ip,
            dst_ip,
            &packet[tcp_start..tcp_start + TCP_HEADER_LEN],
            seg.payload,
        );
        packet[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_checksum.to_be_bytes());

        packet
    }

    /// Build a UDP response packet
    pub fn build_udp_packet(
        &mut self,
        dst_mac: [u8; 6],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut packet = vec![0u8; total_len];

        // Ethernet header
        let eth = EthernetHeader {
            dst_mac,
            src_mac: self.gateway_mac,
            ether_type: ETH_TYPE_IPV4,
        };
        eth.write(&mut packet[0..ETH_HEADER_LEN]);

        // IP header — total length bounded by MTU (well under u16::MAX)
        let ip_total_len = mtu_bounded_u16(IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len());
        let ip = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: ip_total_len,
            identification: self.next_ip_id(),
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_UDP,
            checksum: 0,
            src_ip,
            dst_ip,
        };
        ip.write(&mut packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        // Calculate and set IP checksum
        let ip_checksum =
            calculate_ip_checksum(&packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        packet[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12]
            .copy_from_slice(&ip_checksum.to_be_bytes());

        // UDP header
        let udp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let udp_len = mtu_bounded_u16(UDP_HEADER_LEN + payload.len());
        let udp = UdpHeader {
            src_port,
            dst_port,
            length: udp_len,
            checksum: 0,
        };
        udp.write(&mut packet[udp_start..udp_start + UDP_HEADER_LEN]);

        // Copy payload
        let payload_start = udp_start + UDP_HEADER_LEN;
        packet[payload_start..payload_start + payload.len()].copy_from_slice(payload);

        // Calculate and set UDP checksum
        let udp_checksum = calculate_udp_checksum(
            src_ip,
            dst_ip,
            &packet[udp_start..udp_start + UDP_HEADER_LEN],
            payload,
        );
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

        packet
    }

    /// Build a UDP packet for IPv4 or IPv6
    pub fn build_udp_packet_ip(&mut self, flow: &FlowEndpoints, payload: &[u8]) -> Vec<u8> {
        let (mac, sp, dp) = (flow.dst_mac(), flow.src_port(), flow.dst_port());
        dispatch_ip!(
            flow,
            |src, dst| self.build_udp_packet(mac, src, dst, sp, dp, payload),
            |src, dst| self.build_udp_packet_v6(mac, src, dst, sp, dp, payload)
        )
    }

    fn build_udp_packet_v6(
        &self,
        dst_mac: [u8; 6],
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut packet = vec![0u8; total_len];

        let eth = EthernetHeader {
            dst_mac,
            src_mac: self.gateway_mac,
            ether_type: ETH_TYPE_IPV6,
        };
        eth.write(&mut packet[0..ETH_HEADER_LEN]);

        let ipv6 = Ipv6Header {
            payload_len: mtu_bounded_u16(UDP_HEADER_LEN + payload.len()),
            next_header: IP_PROTO_UDP,
            hop_limit: 64,
            src_ip,
            dst_ip,
        };
        ipv6.write(&mut packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let udp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp_len = mtu_bounded_u16(UDP_HEADER_LEN + payload.len());
        let udp = UdpHeader {
            src_port,
            dst_port,
            length: udp_len,
            checksum: 0,
        };
        udp.write(&mut packet[udp_start..udp_start + UDP_HEADER_LEN]);

        let payload_start = udp_start + UDP_HEADER_LEN;
        packet[payload_start..payload_start + payload.len()].copy_from_slice(payload);

        let udp_checksum = calculate_udp_checksum_v6(
            src_ip,
            dst_ip,
            &packet[udp_start..udp_start + UDP_HEADER_LEN],
            payload,
        );
        packet[udp_start + 6..udp_start + 8].copy_from_slice(&udp_checksum.to_be_bytes());

        packet
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DEFAULT_GATEWAY_MAC;

    #[test]
    fn test_ethernet_header_parse() {
        let mut data = [
            0, 0, 0, 0, 0, 0, // dst mac
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // src mac
            0x08, 0x00, // ethertype IPv4
        ];
        data[0..6].copy_from_slice(&DEFAULT_GATEWAY_MAC);
        let eth = EthernetHeader::parse(&data).unwrap();
        assert_eq!(eth.dst_mac, DEFAULT_GATEWAY_MAC);
        assert_eq!(eth.src_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(eth.ether_type, ETH_TYPE_IPV4);
    }

    #[test]
    fn test_ipv4_header_parse() {
        let data = [
            0x45, 0x00, // version, ihl, dscp, ecn
            0x00, 0x28, // total length
            0x00, 0x00, // identification
            0x40, 0x00, // flags, fragment offset
            0x40, 0x06, // ttl, protocol (TCP)
            0x00, 0x00, // checksum (placeholder)
            0x0a, 0x00, 0x02, 0x0f, // src ip 10.0.2.15
            0x08, 0x08, 0x08, 0x08, // dst ip 8.8.8.8
        ];
        let ip = Ipv4Header::parse(&data).unwrap();
        assert_eq!(ip.src_ip, Ipv4Addr::new(10, 0, 2, 15));
        assert_eq!(ip.dst_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip.protocol, IP_PROTO_TCP);
        assert_eq!(ip.header_len(), 20);
        assert!(!ip.is_fragmented());
    }

    #[test]
    fn test_is_fragmented_mf_flag_only() {
        let mut data = [0u8; 20];
        data[0] = 0x45; // version 4, IHL 5
        data[6..8].copy_from_slice(&0x2000u16.to_be_bytes()); // MF flag, offset 0
        let ip = Ipv4Header::parse(&data).unwrap();
        assert!(ip.is_fragmented());
    }

    #[test]
    fn test_is_fragmented_offset_only() {
        let mut data = [0u8; 20];
        data[0] = 0x45;
        data[6..8].copy_from_slice(&0x0001u16.to_be_bytes()); // no MF, offset 1
        let ip = Ipv4Header::parse(&data).unwrap();
        assert!(ip.is_fragmented());
    }

    #[test]
    fn test_is_fragmented_both_mf_and_offset() {
        let mut data = [0u8; 20];
        data[0] = 0x45;
        data[6..8].copy_from_slice(&0x20FFu16.to_be_bytes()); // MF + offset 0xFF
        let ip = Ipv4Header::parse(&data).unwrap();
        assert!(ip.is_fragmented());
    }

    #[test]
    fn test_is_fragmented_df_only_not_fragmented() {
        let mut data = [0u8; 20];
        data[0] = 0x45;
        data[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // DF flag only
        let ip = Ipv4Header::parse(&data).unwrap();
        assert!(!ip.is_fragmented());
    }

    #[test]
    fn test_is_fragmented_zero_flags_not_fragmented() {
        let mut data = [0u8; 20];
        data[0] = 0x45;
        // flags_fragment = 0x0000
        let ip = Ipv4Header::parse(&data).unwrap();
        assert!(!ip.is_fragmented());
    }

    #[test]
    fn test_tcp_header_parse() {
        let data = [
            0x04, 0x00, // src port 1024
            0x00, 0x50, // dst port 80
            0x00, 0x00, 0x00, 0x01, // seq
            0x00, 0x00, 0x00, 0x00, // ack
            0x50, 0x02, // data offset, flags (SYN)
            0xff, 0xff, // window
            0x00, 0x00, // checksum
            0x00, 0x00, // urgent
        ];
        let tcp = TcpHeader::parse(&data).unwrap();
        assert_eq!(tcp.src_port, 1024);
        assert_eq!(tcp.dst_port, 80);
        assert!(tcp.is_syn());
        assert!(!tcp.is_ack());
    }

    #[test]
    fn test_build_tcp_syn_ack() {
        let mut builder = PacketBuilder::new(DEFAULT_GATEWAY_MAC);

        let packet = builder.build_tcp_syn_ack(
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
            1, // ack_num = ISN + 1
            1000,
            65535,
        );

        // Parse the built packet
        let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        let tcp_start = ETH_HEADER_LEN + ip.header_len();
        let tcp = TcpHeader::parse(&packet[tcp_start..tcp_start + TCP_HEADER_LEN]).unwrap();
        assert!(tcp.is_syn_ack());
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 1024);
        assert_eq!(tcp.ack_num, 1);
        assert_eq!(tcp.seq_num, 1000);
    }

    #[test]
    fn test_ip_checksum() {
        // Example IP header
        let header = [
            0x45, 0x00, 0x00, 0x28, 0x00, 0x01, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 0x0a, 0x00,
            0x02, 0x0f, 0x08, 0x08, 0x08, 0x08,
        ];
        let checksum = calculate_ip_checksum(&header);
        // Verify checksum is non-zero (actual value depends on header)
        assert_ne!(checksum, 0);
    }

    #[test]
    fn test_ipv4_parse_rejects_invalid_ihl() {
        let mut data = [0u8; 20];
        // IHL=0, version=4
        data[0] = 0x40;
        assert!(Ipv4Header::parse(&data).is_none());
        // IHL=1, version=4
        data[0] = 0x41;
        assert!(Ipv4Header::parse(&data).is_none());
        // IHL=3, version=4
        data[0] = 0x43;
        assert!(Ipv4Header::parse(&data).is_none());
        // IHL=4, version=4 (16 bytes, still < 20 minimum)
        data[0] = 0x44;
        assert!(Ipv4Header::parse(&data).is_none());
        // IHL=5 with exactly 20 bytes -- should succeed
        data[0] = 0x45;
        assert!(Ipv4Header::parse(&data).is_some());
        // IHL=6 but only 20 bytes available -- should fail (24 > 20)
        data[0] = 0x46;
        assert!(Ipv4Header::parse(&data).is_none());
        // IHL=15 with only 20 bytes -- should fail (60 > 20)
        data[0] = 0x4F;
        assert!(Ipv4Header::parse(&data).is_none());
    }

    #[test]
    fn test_tcp_parse_rejects_invalid_data_offset() {
        let mut data = [0u8; 20];
        // Valid TCP header with data_offset=5 (0x50)
        data[12] = 0x50;
        data[13] = TCP_SYN;
        assert!(TcpHeader::parse(&data).is_some());

        // data_offset=0 -- should fail
        data[12] = 0x00;
        assert!(TcpHeader::parse(&data).is_none());
        // data_offset=1 -- should fail
        data[12] = 0x10;
        assert!(TcpHeader::parse(&data).is_none());
        // data_offset=4 -- should fail (< 5 minimum)
        data[12] = 0x40;
        assert!(TcpHeader::parse(&data).is_none());
        // data_offset=6 but only 20 bytes available -- should fail (24 > 20)
        data[12] = 0x60;
        assert!(TcpHeader::parse(&data).is_none());
    }

    #[test]
    fn test_ip_checksum_rejects_short_input() {
        // Empty input
        assert_eq!(calculate_ip_checksum(&[]), 0);
        // Too short (< 20 bytes)
        assert_eq!(calculate_ip_checksum(&[0x45; 10]), 0);
        // IHL=3 (12 bytes header, < 20 minimum) even with 20 bytes of data
        let mut data = [0u8; 20];
        data[0] = 0x43;
        assert_eq!(calculate_ip_checksum(&data), 0);
    }

    // =========================================================================
    // IPv6 Header Parsing
    // =========================================================================

    #[test]
    fn test_ipv6_header_parse_valid() {
        let mut data = [0u8; IPV6_HEADER_LEN];
        // Version 6, traffic class 0, flow label 0
        data[0] = 0x60;
        // Payload length = 20 (TCP header)
        data[4..6].copy_from_slice(&20u16.to_be_bytes());
        // Next header = TCP
        data[6] = IP_PROTO_TCP;
        // Hop limit
        data[7] = 64;
        // src: fd00::15
        data[8..24].copy_from_slice(&Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15).octets());
        // dst: 2001:db8::1
        data[24..40].copy_from_slice(&Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets());

        let ip = Ipv6Header::parse(&data).unwrap();
        assert_eq!(ip.payload_len, 20);
        assert_eq!(ip.next_header, IP_PROTO_TCP);
        assert_eq!(ip.hop_limit, 64);
        assert_eq!(ip.src_ip, Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15));
        assert_eq!(ip.dst_ip, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
    }

    #[test]
    fn test_ipv6_header_parse_truncated() {
        // Too short
        assert!(Ipv6Header::parse(&[0x60; 39]).is_none());
        assert!(Ipv6Header::parse(&[]).is_none());
    }

    #[test]
    fn test_ipv6_header_parse_wrong_version() {
        let mut data = [0u8; IPV6_HEADER_LEN];
        data[0] = 0x40; // version 4, not 6
        assert!(Ipv6Header::parse(&data).is_none());
    }

    #[test]
    fn test_ipv6_header_write_roundtrip() {
        let original = Ipv6Header {
            payload_len: 100,
            next_header: IP_PROTO_UDP,
            hop_limit: 128,
            src_ip: Ipv6Addr::new(0xfe80, 0, 0, 0, 1, 2, 3, 4),
            dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        };
        let mut buf = [0u8; IPV6_HEADER_LEN];
        original.write(&mut buf);
        let parsed = Ipv6Header::parse(&buf).unwrap();
        assert_eq!(parsed.payload_len, original.payload_len);
        assert_eq!(parsed.next_header, original.next_header);
        assert_eq!(parsed.hop_limit, original.hop_limit);
        assert_eq!(parsed.src_ip, original.src_ip);
        assert_eq!(parsed.dst_ip, original.dst_ip);
    }

    // =========================================================================
    // UDP Header Parsing
    // =========================================================================

    #[test]
    fn test_udp_header_parse_valid() {
        let mut data = vec![
            0x04, 0x00, // src port 1024
            0x00, 0x35, // dst port 53 (DNS)
            0x00, 0x1C, // length 28
            0xAB, 0xCD, // checksum
        ];
        data.resize(28, 0);
        let udp = UdpHeader::parse(&data).unwrap();
        assert_eq!(udp.src_port, 1024);
        assert_eq!(udp.dst_port, 53);
        assert_eq!(udp.length, 28);
        assert_eq!(udp.checksum, 0xABCD);
    }

    #[test]
    fn test_udp_header_parse_truncated() {
        assert!(UdpHeader::parse(&[0; 7]).is_none());
        assert!(UdpHeader::parse(&[]).is_none());
        let mut short_len = [0u8; UDP_HEADER_LEN];
        short_len[4..6].copy_from_slice(&7u16.to_be_bytes());
        assert!(UdpHeader::parse(&short_len).is_none());
        let mut long_len = [0u8; UDP_HEADER_LEN];
        long_len[4..6].copy_from_slice(&9u16.to_be_bytes());
        assert!(UdpHeader::parse(&long_len).is_none());
    }

    #[test]
    fn test_udp_header_write_roundtrip() {
        let original = UdpHeader {
            src_port: 5000,
            dst_port: 8080,
            length: 42,
            checksum: 0x1234,
        };
        let mut buf = vec![0u8; original.length as usize];
        original.write(&mut buf[..UDP_HEADER_LEN]);
        let parsed = UdpHeader::parse(&buf).unwrap();
        assert_eq!(parsed.src_port, original.src_port);
        assert_eq!(parsed.dst_port, original.dst_port);
        assert_eq!(parsed.length, original.length);
        assert_eq!(parsed.checksum, original.checksum);
    }

    // =========================================================================
    // IPv6 Checksum Functions
    // =========================================================================

    /// Helper: verify a TCP checksum by computing it, inserting into header,
    /// then recomputing (should yield 0 for valid packet).
    fn verify_tcp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, tcp_header: &mut [u8], payload: &[u8]) {
        let checksum = calculate_tcp_checksum_v6(src, dst, tcp_header, payload);
        tcp_header[16..18].copy_from_slice(&checksum.to_be_bytes());
        // Recompute over the packet with checksum filled in — should fold to 0xFFFF
        let mut sum: u32 = 0;
        for chunk in src.octets().chunks_exact(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        for chunk in dst.octets().chunks_exact(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
        }
        let total = u32::try_from(tcp_header.len() + payload.len()).unwrap();
        sum = sum.wrapping_add(total >> 16);
        sum = sum.wrapping_add(total & 0xFFFF);
        sum = sum.wrapping_add(u32::from(IP_PROTO_TCP));
        for i in (0..tcp_header.len()).step_by(2) {
            let word = if i + 1 < tcp_header.len() {
                u16::from_be_bytes([tcp_header[i], tcp_header[i + 1]])
            } else {
                u16::from_be_bytes([tcp_header[i], 0])
            };
            sum = sum.wrapping_add(u32::from(word));
        }
        for i in (0..payload.len()).step_by(2) {
            let word = if i + 1 < payload.len() {
                u16::from_be_bytes([payload[i], payload[i + 1]])
            } else {
                u16::from_be_bytes([payload[i], 0])
            };
            sum = sum.wrapping_add(u32::from(word));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(
            u16::try_from(sum).unwrap(),
            0xFFFF,
            "TCP checksum verification failed"
        );
    }

    #[test]
    fn test_tcp_checksum_v6_empty_payload() {
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut tcp_header = [0u8; TCP_HEADER_LEN];
        tcp_header[0..2].copy_from_slice(&1024u16.to_be_bytes());
        tcp_header[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp_header[12] = 0x50; // data_offset=5
        tcp_header[13] = TCP_SYN;
        verify_tcp_checksum_v6(src, dst, &mut tcp_header, &[]);
    }

    #[test]
    fn test_tcp_checksum_v6_with_payload() {
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut tcp_header = [0u8; TCP_HEADER_LEN];
        tcp_header[0..2].copy_from_slice(&1024u16.to_be_bytes());
        tcp_header[2..4].copy_from_slice(&80u16.to_be_bytes());
        tcp_header[12] = 0x50;
        tcp_header[13] = TCP_ACK | TCP_PSH;
        let payload = b"Hello, IPv6 world!";
        verify_tcp_checksum_v6(src, dst, &mut tcp_header, payload);
    }

    #[test]
    fn test_tcp_checksum_v6_odd_length_payload() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;
        let mut tcp_header = [0u8; TCP_HEADER_LEN];
        tcp_header[12] = 0x50;
        tcp_header[13] = TCP_ACK;
        // Odd-length payload exercises the padding branch
        let payload = [0xAA; 13];
        verify_tcp_checksum_v6(src, dst, &mut tcp_header, &payload);
    }

    #[test]
    fn test_udp_checksum_v6_basic() {
        let src = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let mut udp_header = [0u8; UDP_HEADER_LEN];
        udp_header[0..2].copy_from_slice(&5000u16.to_be_bytes());
        udp_header[2..4].copy_from_slice(&53u16.to_be_bytes());
        let payload = b"dns query";
        let udp_len = u16::try_from(UDP_HEADER_LEN + payload.len()).unwrap();
        udp_header[4..6].copy_from_slice(&udp_len.to_be_bytes());

        let checksum = calculate_udp_checksum_v6(src, dst, &udp_header, payload);
        // UDP checksum of 0 must be encoded as 0xFFFF (RFC 2460)
        assert_ne!(checksum, 0, "UDP/IPv6 checksum must never be 0");
    }

    #[test]
    fn test_ipv4_checksum_all_zeros() {
        // All-zeros header with valid IHL=5
        let mut header = [0u8; 20];
        header[0] = 0x45;
        let checksum = calculate_ip_checksum(&header);
        // For a header with version_ihl=0x45 and rest zeros:
        // sum = 0x4500, complement = ~0x4500 = 0xBAFF
        assert_eq!(checksum, 0xBAFF);
    }

    #[test]
    fn test_ipv4_checksum_validates_built_packet() {
        // Build a full packet and verify its IP checksum is valid
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let packet = builder.build_tcp_syn_ack(
            [0xBB; 6],
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(10, 0, 2, 15),
            443,
            5000,
            1,
            100,
            32768,
        );
        // Re-compute checksum over the IP header — result should be 0 (valid)
        let ip_header = &packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
        let mut sum: u32 = 0;
        for i in (0..IPV4_HEADER_LEN).step_by(2) {
            sum = sum.wrapping_add(u32::from(u16::from_be_bytes([
                ip_header[i],
                ip_header[i + 1],
            ])));
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(
            u16::try_from(sum).unwrap(),
            0xFFFF,
            "IP checksum of built packet should verify"
        );
    }

    // =========================================================================
    // IPv6 TCP Packet Building
    // =========================================================================

    #[test]
    fn test_build_tcp_syn_ack_v6() {
        let mut builder = PacketBuilder::new(DEFAULT_GATEWAY_MAC);
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15);

        let packet = builder.build_tcp_syn_ack_ip(
            &FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024),
            1,    // ack
            5000, // seq
            65535,
        );

        // Parse Ethernet
        let eth = EthernetHeader::parse(&packet).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV6);

        // Parse IPv6
        let ip = Ipv6Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.next_header, IP_PROTO_TCP);
        assert_eq!(ip.src_ip, src);
        assert_eq!(ip.dst_ip, dst);

        // Parse TCP
        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_syn_ack());
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 1024);
        assert_eq!(tcp.seq_num, 5000);
        assert_eq!(tcp.ack_num, 1);
    }

    #[test]
    fn test_build_tcp_data_v6() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15);
        let payload = b"Hello IPv6";

        let packet = builder.build_tcp_data_ip(
            &FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024),
            100,
            200,
            32768,
            payload,
        );

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_ack());
        assert_eq!(tcp.flags & TCP_PSH, TCP_PSH);

        // Verify payload appears after TCP header
        let payload_start = tcp_start + TCP_HEADER_LEN;
        assert_eq!(&packet[payload_start..], payload);
    }

    #[test]
    fn test_build_tcp_fin_v6() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;

        let packet = builder.build_tcp_fin_ip(
            &FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024),
            300,
            400,
            16384,
        );

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_fin());
        assert!(tcp.is_ack());
        assert_eq!(tcp.seq_num, 300);
        assert_eq!(tcp.ack_num, 400);
    }

    #[test]
    fn test_build_tcp_rst_v6() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;

        let packet =
            builder.build_tcp_rst_ip(&FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024), 500, 600);

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_rst());
        assert!(tcp.is_ack());
    }

    #[test]
    fn test_build_tcp_ack_v6() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;

        let packet = builder.build_tcp_ack_ip(
            &FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024),
            100,
            200,
            65535,
        );

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_ack());
        assert!(!tcp.is_syn());
        assert!(!tcp.is_fin());
        assert!(!tcp.is_rst());
    }

    #[test]
    fn test_build_tcp_rst_only_v6() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::LOCALHOST;

        let packet =
            builder.build_tcp_rst_only_ip(&FlowEndpoints::v6([0xBB; 6], src, dst, 80, 1024), 42);

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
        assert!(tcp.is_rst());
        assert!(!tcp.is_ack());
        assert_eq!(tcp.seq_num, 42);
    }

    #[test]
    fn test_flow_endpoints_reject_tcp_ip_family_mismatch() {
        assert!(
            FlowEndpoints::from_ip_pair(
                [0xBB; 6],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                80,
                1024,
            )
            .is_none()
        );
    }

    // =========================================================================
    // UDP Packet Building
    // =========================================================================

    #[test]
    fn test_build_udp_packet_v4_roundtrip() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let payload = b"DNS response payload";

        let packet = builder.build_udp_packet(
            [0xBB; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            53,
            5000,
            payload,
        );

        // Parse Ethernet
        let eth = EthernetHeader::parse(&packet).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV4);

        // Parse IP
        let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.protocol, IP_PROTO_UDP);
        assert_eq!(ip.src_ip, Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ip.dst_ip, Ipv4Addr::new(10, 0, 2, 15));

        // Parse UDP
        let udp_start = ETH_HEADER_LEN + ip.header_len();
        let udp = UdpHeader::parse(&packet[udp_start..]).unwrap();
        assert_eq!(udp.src_port, 53);
        assert_eq!(udp.dst_port, 5000);
        assert_eq!(
            udp.length,
            u16::try_from(UDP_HEADER_LEN + payload.len()).unwrap()
        );

        // Verify payload
        let payload_start = udp_start + UDP_HEADER_LEN;
        assert_eq!(&packet[payload_start..], payload);
    }

    #[test]
    fn test_build_udp_packet_v6_roundtrip() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15);
        let payload = b"IPv6 UDP payload";

        let packet =
            builder.build_udp_packet_ip(&FlowEndpoints::v6([0xBB; 6], src, dst, 5000, 53), payload);

        // Parse Ethernet
        let eth = EthernetHeader::parse(&packet).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV6);

        // Parse IPv6
        let ip = Ipv6Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.next_header, IP_PROTO_UDP);
        assert_eq!(ip.src_ip, src);
        assert_eq!(ip.dst_ip, dst);

        // Parse UDP
        let udp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let udp = UdpHeader::parse(&packet[udp_start..]).unwrap();
        assert_eq!(udp.src_port, 5000);
        assert_eq!(udp.dst_port, 53);

        // Verify payload
        let payload_start = udp_start + UDP_HEADER_LEN;
        assert_eq!(&packet[payload_start..], payload);
    }

    #[test]
    fn test_flow_endpoints_reject_udp_ip_family_mismatch() {
        assert!(
            FlowEndpoints::from_ip_pair(
                [0xBB; 6],
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                5000,
                53,
            )
            .is_none()
        );
    }

    // =========================================================================
    // TCP Data Packet with Payload (IPv4)
    // =========================================================================

    #[test]
    fn test_build_tcp_data_v4_payload_and_checksum() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let payload = b"GET / HTTP/1.1\r\n\r\n";

        let packet = builder.build_tcp_data(
            [0xBB; 6],
            crate::DEFAULT_GATEWAY,
            crate::DEFAULT_GUEST_IP,
            80,
            1024,
            1000,
            2000,
            65535,
            payload,
        );

        let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
        let tcp_start = ETH_HEADER_LEN + ip.header_len();
        let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();

        // Verify payload
        let payload_start = tcp_start + TCP_HEADER_LEN;
        assert_eq!(&packet[payload_start..], payload);

        // Verify TCP checksum is valid by recomputing
        let recomputed = calculate_tcp_checksum(
            ip.src_ip,
            ip.dst_ip,
            &packet[tcp_start..tcp_start + TCP_HEADER_LEN],
            payload,
        );
        assert_eq!(tcp.checksum, recomputed);
    }

    #[test]
    fn test_ip_id_increments() {
        let mut builder = PacketBuilder::new([0xAA; 6]);
        let mac = [0xBB; 6];
        let src = Ipv4Addr::LOCALHOST;
        let dst = Ipv4Addr::LOCALHOST;

        let p1 = builder.build_tcp_ack(mac, src, dst, 80, 80, 0, 0, 0);
        let p2 = builder.build_tcp_ack(mac, src, dst, 80, 80, 0, 0, 0);

        let ip1 = Ipv4Header::parse(&p1[ETH_HEADER_LEN..]).unwrap();
        let ip2 = Ipv4Header::parse(&p2[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip2.identification, ip1.identification + 1);
    }

    // =========================================================================
    // Property-based tests (proptest)
    // =========================================================================

    mod proptests {
        use super::*;
        use proptest::prelude::*;

        const UDP_HEADER_LEN_U16: u16 = 8;

        fn mac_strategy() -> impl Strategy<Value = [u8; 6]> {
            prop::array::uniform6(any::<u8>())
        }

        fn ipv4_strategy() -> impl Strategy<Value = Ipv4Addr> {
            (any::<u8>(), any::<u8>(), any::<u8>(), any::<u8>())
                .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
        }

        fn ipv6_strategy() -> impl Strategy<Value = Ipv6Addr> {
            prop::array::uniform16(any::<u8>()).prop_map(Ipv6Addr::from)
        }

        proptest! {
            /// EthernetHeader write/parse roundtrip preserves all fields.
            #[test]
            fn ethernet_header_roundtrip(
                dst_mac in mac_strategy(),
                src_mac in mac_strategy(),
                ether_type in any::<u16>(),
            ) {
                let header = EthernetHeader { dst_mac, src_mac, ether_type };
                let mut buf = [0u8; ETH_HEADER_LEN];
                header.write(&mut buf);
                let parsed = EthernetHeader::parse(&buf).unwrap();
                prop_assert_eq!(parsed.dst_mac, dst_mac);
                prop_assert_eq!(parsed.src_mac, src_mac);
                prop_assert_eq!(parsed.ether_type, ether_type);
            }

            /// Ipv4Header write/parse roundtrip preserves all fields (IHL=5, no options).
            #[test]
            fn ipv4_header_roundtrip(
                dscp_ecn in any::<u8>(),
                total_length in any::<u16>(),
                identification in any::<u16>(),
                flags_fragment in any::<u16>(),
                ttl in any::<u8>(),
                protocol in any::<u8>(),
                checksum in any::<u16>(),
                src_ip in ipv4_strategy(),
                dst_ip in ipv4_strategy(),
            ) {
                let header = Ipv4Header {
                    version_ihl: 0x45, // IPv4, IHL=5
                    dscp_ecn,
                    total_length,
                    identification,
                    flags_fragment,
                    ttl,
                    protocol,
                    checksum,
                    src_ip,
                    dst_ip,
                };
                let mut buf = [0u8; IPV4_HEADER_LEN];
                header.write(&mut buf);
                let parsed = Ipv4Header::parse(&buf).unwrap();
                prop_assert_eq!(parsed.version_ihl, 0x45);
                prop_assert_eq!(parsed.dscp_ecn, dscp_ecn);
                prop_assert_eq!(parsed.total_length, total_length);
                prop_assert_eq!(parsed.identification, identification);
                prop_assert_eq!(parsed.flags_fragment, flags_fragment);
                prop_assert_eq!(parsed.ttl, ttl);
                prop_assert_eq!(parsed.protocol, protocol);
                prop_assert_eq!(parsed.checksum, checksum);
                prop_assert_eq!(parsed.src_ip, src_ip);
                prop_assert_eq!(parsed.dst_ip, dst_ip);
            }

            /// Ipv6Header write/parse roundtrip preserves all fields.
            #[test]
            fn ipv6_header_roundtrip(
                payload_len in any::<u16>(),
                next_header in any::<u8>(),
                hop_limit in any::<u8>(),
                src_ip in ipv6_strategy(),
                dst_ip in ipv6_strategy(),
            ) {
                let header = Ipv6Header {
                    payload_len,
                    next_header,
                    hop_limit,
                    src_ip,
                    dst_ip,
                };
                let mut buf = [0u8; IPV6_HEADER_LEN];
                header.write(&mut buf);
                let parsed = Ipv6Header::parse(&buf).unwrap();
                prop_assert_eq!(parsed.payload_len, payload_len);
                prop_assert_eq!(parsed.next_header, next_header);
                prop_assert_eq!(parsed.hop_limit, hop_limit);
                prop_assert_eq!(parsed.src_ip, src_ip);
                prop_assert_eq!(parsed.dst_ip, dst_ip);
            }

            /// TcpHeader write/parse roundtrip preserves all fields (data_offset=5).
            #[test]
            fn tcp_header_roundtrip(
                src_port in any::<u16>(),
                dst_port in any::<u16>(),
                seq_num in any::<u32>(),
                ack_num in any::<u32>(),
                flags in any::<u8>(),
                window in any::<u16>(),
                checksum in any::<u16>(),
                urgent_ptr in any::<u16>(),
            ) {
                let header = TcpHeader {
                    src_port,
                    dst_port,
                    seq_num,
                    ack_num,
                    data_offset: 5, // minimum valid
                    flags,
                    window,
                    checksum,
                    urgent_ptr,
                };
                let mut buf = [0u8; TCP_HEADER_LEN];
                header.write(&mut buf);
                let parsed = TcpHeader::parse(&buf).unwrap();
                prop_assert_eq!(parsed.src_port, src_port);
                prop_assert_eq!(parsed.dst_port, dst_port);
                prop_assert_eq!(parsed.seq_num, seq_num);
                prop_assert_eq!(parsed.ack_num, ack_num);
                prop_assert_eq!(parsed.data_offset, 5);
                prop_assert_eq!(parsed.flags, flags);
                prop_assert_eq!(parsed.window, window);
                prop_assert_eq!(parsed.checksum, checksum);
                prop_assert_eq!(parsed.urgent_ptr, urgent_ptr);
            }

            /// UdpHeader write/parse roundtrip preserves all fields.
            #[test]
            fn udp_header_roundtrip(
                src_port in any::<u16>(),
                dst_port in any::<u16>(),
                length in UDP_HEADER_LEN_U16..=2048u16,
                checksum in any::<u16>(),
            ) {
                let header = UdpHeader { src_port, dst_port, length, checksum };
                let mut buf = vec![0u8; length as usize];
                header.write(&mut buf[..UDP_HEADER_LEN]);
                let parsed = UdpHeader::parse(&buf).unwrap();
                prop_assert_eq!(parsed.src_port, src_port);
                prop_assert_eq!(parsed.dst_port, dst_port);
                prop_assert_eq!(parsed.length, length);
                prop_assert_eq!(parsed.checksum, checksum);
            }

            /// Arbitrary bytes never panic EthernetHeader::parse.
            #[test]
            fn ethernet_parse_no_panic(data in prop::collection::vec(any::<u8>(), 0..30)) {
                let _ = EthernetHeader::parse(&data);
            }

            /// Arbitrary bytes never panic Ipv4Header::parse.
            #[test]
            fn ipv4_parse_no_panic(data in prop::collection::vec(any::<u8>(), 0..60)) {
                let _ = Ipv4Header::parse(&data);
            }

            /// Arbitrary bytes never panic Ipv6Header::parse.
            #[test]
            fn ipv6_parse_no_panic(data in prop::collection::vec(any::<u8>(), 0..60)) {
                let _ = Ipv6Header::parse(&data);
            }

            /// Arbitrary bytes never panic TcpHeader::parse.
            #[test]
            fn tcp_parse_no_panic(data in prop::collection::vec(any::<u8>(), 0..60)) {
                let _ = TcpHeader::parse(&data);
            }

            /// Arbitrary bytes never panic UdpHeader::parse.
            #[test]
            fn udp_parse_no_panic(data in prop::collection::vec(any::<u8>(), 0..30)) {
                let _ = UdpHeader::parse(&data);
            }

            /// Built IPv4 TCP packets always have valid IP and TCP checksums.
            #[test]
            fn built_tcp_v4_checksums_valid(
                src_ip in ipv4_strategy(),
                dst_ip in ipv4_strategy(),
                src_port in any::<u16>(),
                dst_port in any::<u16>(),
                seq_num in any::<u32>(),
                ack_num in any::<u32>(),
                window in any::<u16>(),
                payload in prop::collection::vec(any::<u8>(), 0..200),
            ) {
                let mut builder = PacketBuilder::new([0xAA; 6]);
                let packet = builder.build_tcp_data(
                    [0xBB; 6], src_ip, dst_ip,
                    src_port, dst_port, seq_num, ack_num, window, &payload,
                );

                // Verify IP checksum
                let ip_header = &packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
                let mut sum: u32 = 0;
                for i in (0..IPV4_HEADER_LEN).step_by(2) {
                    sum = sum.wrapping_add(u32::from(
                        u16::from_be_bytes([ip_header[i], ip_header[i + 1]])
                    ));
                }
                while (sum >> 16) != 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                prop_assert_eq!(
                    u16::try_from(sum).unwrap(), 0xFFFF,
                    "IP checksum invalid"
                );

                // Verify TCP checksum
                let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
                let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..]).unwrap();
                let recomputed = calculate_tcp_checksum(
                    ip.src_ip, ip.dst_ip,
                    &packet[tcp_start..tcp_start + TCP_HEADER_LEN],
                    &payload,
                );
                let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
                prop_assert_eq!(tcp.checksum, recomputed, "TCP checksum mismatch");
            }

            /// Built IPv6 TCP packets always have valid TCP checksums.
            #[test]
            fn built_tcp_v6_checksums_valid(
                src_ip in ipv6_strategy(),
                dst_ip in ipv6_strategy(),
                src_port in any::<u16>(),
                dst_port in any::<u16>(),
                seq_num in any::<u32>(),
                ack_num in any::<u32>(),
                window in any::<u16>(),
                payload in prop::collection::vec(any::<u8>(), 0..200),
            ) {
                let mut builder = PacketBuilder::new([0xAA; 6]);
                let packet = builder.build_tcp_data_ip(
                    &FlowEndpoints::v6([0xBB; 6], src_ip, dst_ip, src_port, dst_port),
                    seq_num, ack_num, window, &payload,
                );

                let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
                let recomputed = calculate_tcp_checksum_v6(
                    src_ip, dst_ip,
                    &packet[tcp_start..tcp_start + TCP_HEADER_LEN],
                    &payload,
                );
                let tcp = TcpHeader::parse(&packet[tcp_start..]).unwrap();
                prop_assert_eq!(tcp.checksum, recomputed, "IPv6 TCP checksum mismatch");
            }

            /// Built IPv4 UDP packets always have valid IP and UDP checksums.
            #[test]
            fn built_udp_v4_checksums_valid(
                src_ip in ipv4_strategy(),
                dst_ip in ipv4_strategy(),
                src_port in any::<u16>(),
                dst_port in any::<u16>(),
                payload in prop::collection::vec(any::<u8>(), 0..200),
            ) {
                let mut builder = PacketBuilder::new([0xAA; 6]);
                let packet = builder.build_udp_packet(
                    [0xBB; 6], src_ip, dst_ip, src_port, dst_port, &payload,
                );

                // Verify IP checksum
                let ip_header = &packet[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
                let mut sum: u32 = 0;
                for i in (0..IPV4_HEADER_LEN).step_by(2) {
                    sum = sum.wrapping_add(u32::from(
                        u16::from_be_bytes([ip_header[i], ip_header[i + 1]])
                    ));
                }
                while (sum >> 16) != 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                prop_assert_eq!(
                    u16::try_from(sum).unwrap(), 0xFFFF,
                    "UDP packet IP checksum invalid"
                );

                // Verify UDP checksum
                let udp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
                let recomputed = calculate_udp_checksum(
                    src_ip, dst_ip,
                    &packet[udp_start..udp_start + UDP_HEADER_LEN],
                    &payload,
                );
                let udp = UdpHeader::parse(&packet[udp_start..]).unwrap();
                prop_assert_eq!(udp.checksum, recomputed, "UDP checksum mismatch");
            }

            /// IP checksum: computing checksum, inserting it, then verifying
            /// the entire header sums to 0xFFFF.
            #[test]
            fn ip_checksum_self_consistent(
                dscp_ecn in any::<u8>(),
                total_length in any::<u16>(),
                identification in any::<u16>(),
                flags_fragment in any::<u16>(),
                ttl in any::<u8>(),
                protocol in any::<u8>(),
                src_ip in ipv4_strategy(),
                dst_ip in ipv4_strategy(),
            ) {
                let header = Ipv4Header {
                    version_ihl: 0x45,
                    dscp_ecn,
                    total_length,
                    identification,
                    flags_fragment,
                    ttl,
                    protocol,
                    checksum: 0,
                    src_ip,
                    dst_ip,
                };
                let mut buf = [0u8; IPV4_HEADER_LEN];
                header.write(&mut buf);
                let checksum = calculate_ip_checksum(&buf);
                buf[10..12].copy_from_slice(&checksum.to_be_bytes());

                // Verify: sum of all 16-bit words should be 0xFFFF
                let mut sum: u32 = 0;
                for i in (0..IPV4_HEADER_LEN).step_by(2) {
                    sum = sum.wrapping_add(u32::from(
                        u16::from_be_bytes([buf[i], buf[i + 1]])
                    ));
                }
                while (sum >> 16) != 0 {
                    sum = (sum & 0xFFFF) + (sum >> 16);
                }
                prop_assert_eq!(u16::try_from(sum).unwrap(), 0xFFFF);
            }
        }
    }
}
