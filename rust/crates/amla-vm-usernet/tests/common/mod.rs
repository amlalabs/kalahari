// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Shared test utilities for amla-usernet integration tests.

#![allow(clippy::cast_possible_truncation)]

use std::io::ErrorKind;
use std::net::Ipv4Addr;

use amla_core::backends::{NetBackend, NetRxPacketLease};
use amla_usernet::interceptor::TcpConnectionPolicy;
use amla_usernet::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, EthernetHeader, IP_PROTO_TCP, IPV4_HEADER_LEN, Ipv4Header,
    TCP_ACK, TCP_HEADER_LEN, TCP_PSH, TCP_SYN, TcpHeader, calculate_ip_checksum,
    calculate_tcp_checksum,
};
use amla_usernet::{DEFAULT_GATEWAY_MAC, DEFAULT_GUEST_IP, DEFAULT_GUEST_MAC, UserNetBackend};

// =============================================================================
// TcpGuest — raw TCP guest packet builder
// =============================================================================

/// Minimal guest packet builder for raw Ethernet+IPv4+TCP packets.
///
/// Uses fixed guest MAC/IP and a deterministic ISN. Never retransmits, keeping
/// integration-test packet expectations deterministic.
pub struct TcpGuest {
    pub seq: u32,
    pub ack: u32,
    pub guest_port: u16,
    pub remote_port: u16,
    pub remote_ip: Ipv4Addr,
}

impl TcpGuest {
    pub const fn new(remote_ip: Ipv4Addr, remote_port: u16) -> Self {
        Self {
            seq: 1000,
            ack: 0,
            guest_port: 49152,
            remote_port,
            remote_ip,
        }
    }

    pub fn build_packet(&self, flags: u8, payload: &[u8]) -> Vec<u8> {
        let tcp_len = TCP_HEADER_LEN + payload.len();
        let ip_total_len = (IPV4_HEADER_LEN + tcp_len) as u16;
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + tcp_len;
        let mut pkt = vec![0u8; total_len];

        EthernetHeader {
            dst_mac: DEFAULT_GATEWAY_MAC,
            src_mac: DEFAULT_GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[..ETH_HEADER_LEN]);

        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: ip_total_len,
            identification: 0,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: DEFAULT_GUEST_IP,
            dst_ip: self.remote_ip,
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        let ip_cksum =
            calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&ip_cksum.to_be_bytes());

        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        TcpHeader {
            src_port: self.guest_port,
            dst_port: self.remote_port,
            seq_num: self.seq,
            ack_num: self.ack,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
        .write(&mut pkt[tcp_start..tcp_start + TCP_HEADER_LEN]);

        if !payload.is_empty() {
            pkt[tcp_start + TCP_HEADER_LEN..].copy_from_slice(payload);
        }

        let tcp_cksum = calculate_tcp_checksum(
            DEFAULT_GUEST_IP,
            self.remote_ip,
            &pkt[tcp_start..tcp_start + TCP_HEADER_LEN],
            payload,
        );
        pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        pkt
    }

    pub fn build_syn(&mut self) -> Vec<u8> {
        let pkt = self.build_packet(TCP_SYN, &[]);
        self.seq = self.seq.wrapping_add(1); // SYN consumes 1
        pkt
    }

    pub fn build_ack(&self) -> Vec<u8> {
        self.build_packet(TCP_ACK, &[])
    }

    pub fn build_data(&mut self, payload: &[u8]) -> Vec<u8> {
        let pkt = self.build_packet(TCP_PSH | TCP_ACK, payload);
        self.seq = self.seq.wrapping_add(payload.len() as u32);
        pkt
    }
}

// =============================================================================
// Packet parsing
// =============================================================================

pub struct TcpResponse {
    pub flags: u8,
    pub seq: u32,
    pub payload: Vec<u8>,
}

pub fn parse_tcp_response(packet: &[u8], guest_port: u16, remote_port: u16) -> Option<TcpResponse> {
    let eth = EthernetHeader::parse(packet)?;
    if eth.ether_type != ETH_TYPE_IPV4 {
        return None;
    }
    let ip = Ipv4Header::parse(&packet[ETH_HEADER_LEN..])?;
    if ip.protocol != IP_PROTO_TCP {
        return None;
    }
    let tcp_start = ETH_HEADER_LEN + ip.header_len();
    if tcp_start + TCP_HEADER_LEN > packet.len() {
        return None;
    }
    let tcp = TcpHeader::parse(&packet[tcp_start..])?;

    if tcp.src_port != remote_port || tcp.dst_port != guest_port {
        return None;
    }

    let payload_start = tcp_start + tcp.header_len();
    let ip_total = ETH_HEADER_LEN + ip.total_length as usize;
    let payload_end = ip_total.min(packet.len());
    let payload = if payload_start < payload_end {
        packet[payload_start..payload_end].to_vec()
    } else {
        vec![]
    };

    Some(TcpResponse {
        flags: tcp.flags,
        seq: tcp.seq_num,
        payload,
    })
}

// =============================================================================
// Backend helpers
// =============================================================================

/// Poll backend and drain all pending packets.
pub fn drive_backend<P>(backend: &UserNetBackend<P>) -> Vec<Vec<u8>>
where
    P: TcpConnectionPolicy,
{
    backend.poll().unwrap();
    let mut packets = vec![];
    let mut buf = [0u8; 2000];
    loop {
        match recv_into(backend, &mut buf) {
            Ok(len) => packets.push(buf[..len].to_vec()),
            Err(e) if e.kind() == ErrorKind::WouldBlock => break,
            Err(e) => panic!("recv: {e}"),
        }
    }
    packets
}

/// Copy the next leased packet into `buf` and commit it.
pub fn recv_into<P>(backend: &UserNetBackend<P>, buf: &mut [u8]) -> std::io::Result<usize>
where
    P: TcpConnectionPolicy,
{
    let Some(packet) = backend.rx_packet()? else {
        return Err(std::io::Error::from(ErrorKind::WouldBlock));
    };
    let data = packet.packet();
    if buf.len() < data.len() {
        return Err(std::io::Error::from(ErrorKind::InvalidInput));
    }
    let len = data.len();
    buf[..len].copy_from_slice(data);
    packet.commit()?;
    Ok(len)
}
