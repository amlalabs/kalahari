// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! NAT proxy for user-mode networking
//!
//! This module provides the main NAT proxy that manages TCP and UDP connections
//! from the guest to external hosts. It intercepts outbound packets, spawns
//! per-connection tokio tasks, and collects response packets via a bounded channel.

use crate::guest_output::{ConnectionGeneration, ConnectionKey, ConnectionOutputTag, GuestOutput};
use crate::guest_packet::ValidatedGuestIpPacket;
use crate::interceptor::{DirectTcpPolicy, TcpConnectionPolicy, TcpFlow, TcpOpenAction};
use crate::ipv6_mask;
#[cfg(test)]
use crate::packet_builder::{ETH_HEADER_LEN, parse_ip_packet};
use crate::packet_builder::{
    EthernetHeader, FlowEndpoints, IP_PROTO_TCP, IP_PROTO_UDP, PacketBuilder, ParsedIpPacket,
    TCP_FIN, TCP_SYN, TcpHeader, parse_tcp_segment, parse_udp_datagram,
};
use crate::tcp_proxy::{
    GuestPacket, HostConnectAccess, InboundStream, InboundTarget, TCP_FIXED_BUFFER_BYTES,
    TcpConnectionHandle, TcpConnectionMode, TcpStackConfig, inbound_tcp_task, tcp_connection_task,
};
use crate::udp_proxy::{
    InboundUdpTaskParams, UdpConnectionHandle, UdpTaskParams, inbound_udp_task, udp_connection_task,
};
#[cfg(test)]
use crate::{DnsForwardPolicy, EgressPolicy, HostEgressRule};
use crate::{HostEgressAuthorizer, HostEgressPurpose, HostEgressRequest};
use crate::{UserNetError, UserNetResult};
use amla_core::backends::RxWaker;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};

// =============================================================================
// Constants
// =============================================================================

/// Maximum number of concurrent NAT connections.
///
/// Matches `amla_vm_policy_net::ConnectionTable`'s default (65 536) so neither
/// layer becomes the silent bottleneck. Hitting this cap evicts the oldest
/// connection via `evict_oldest` — with 65 536 slots that will only happen
/// under genuinely pathological guest behaviour, not normal bursts.
const MAX_CONNECTIONS: usize = 65_536;

/// Fixed TCP smoltcp socket-buffer budget across live TCP tasks.
const MAX_TCP_FIXED_BUFFER_BUDGET: usize = 512 * 1024 * 1024;

/// Maximum concurrent TCP connections.
const MAX_TCP_CONNECTIONS: usize = MAX_TCP_FIXED_BUFFER_BUDGET / TCP_FIXED_BUFFER_BYTES;

/// Maximum concurrent UDP associations.
///
/// Each outbound UDP flow owns a host UDP socket and relay task, so UDP uses a
/// much smaller cap than the total tombstone-friendly NAT table. New UDP fails
/// closed at capacity instead of evicting an unrelated reliable TCP flow.
const MAX_UDP_CONNECTIONS: usize = 256;

/// Per-connection channel capacity for guest→task packets.
/// With ~1500-byte packets, each connection caps at ~384 KB.
const GUEST_CHANNEL_CAPACITY: usize = 256;

/// Time allowed for an evicted TCP task to run its close path.
const TCP_EVICTION_CLOSE_TIMEOUT: Duration = Duration::from_millis(250);

const EPHEMERAL_PORT_START: u16 = 49152;
const EPHEMERAL_PORT_RANGE: u16 = 16384;

/// Maximum pending packets queued for the guest before dropping new ones.
/// With ~1500-byte packets this caps memory at ~15 MB.
#[cfg(test)]
const MAX_PENDING_PACKETS: usize = 10_000;

// Re-use the crate-level Protocol enum (which now derives Hash)
use crate::Protocol;

// =============================================================================
// Connection Handle
// =============================================================================

/// A handle to a proxied connection task (TCP or UDP)
enum ConnectionHandle {
    Tcp(TcpConnectionHandle),
    Udp(UdpConnectionHandle),
}

struct ReservedInboundPort {
    released: oneshot::Receiver<()>,
    expires_at: Instant,
}

impl ConnectionHandle {
    const fn created_at(&self) -> Instant {
        match self {
            Self::Tcp(h) => h.created_at,
            Self::Udp(h) => h.created_at,
        }
    }

    fn is_finished(&self) -> bool {
        match self {
            Self::Tcp(h) => h.task.is_finished(),
            Self::Udp(h) => h.task.is_finished(),
        }
    }

    fn abort(&self) {
        match self {
            Self::Tcp(h) => h.task.abort(),
            Self::Udp(h) => h.task.abort(),
        }
    }

    fn evict(self, key: ConnectionKey) -> Option<oneshot::Receiver<()>> {
        match self {
            Self::Tcp(tcp) => {
                let (released_tx, released_rx) = oneshot::channel();
                if let Err(e) = tcp.guest_tx.try_send(GuestPacket::Close) {
                    log::debug!(
                        "usernet evict close-notification failed for {key:?}; aborting task: {e}",
                    );
                    tcp.task.abort();
                    released_tx.send(()).ok();
                    return Some(released_rx);
                }

                let mut task = tcp.task;
                tokio::spawn(async move {
                    if tokio::time::timeout(TCP_EVICTION_CLOSE_TIMEOUT, &mut task)
                        .await
                        .is_err()
                    {
                        task.abort();
                        log::debug!("usernet evict close timed out for {key:?}; aborted task");
                    }
                    released_tx.send(()).ok();
                });
                Some(released_rx)
            }
            Self::Udp(udp) => {
                udp.task.abort();
                None
            }
        }
    }
}

// =============================================================================
// NAT Proxy
// =============================================================================

/// Build the correct RST packet per RFC 793 section 3.4.
/// Returns None if the incoming segment is itself a RST (never RST a RST).
fn build_rst_for_segment(
    builder: &mut PacketBuilder,
    flow: &FlowEndpoints,
    tcp: &TcpHeader,
    payload_len: usize,
) -> Option<Vec<u8>> {
    // RFC 793: "An incoming segment containing a RST is not acknowledged"
    if tcp.is_rst() {
        return None;
    }
    if tcp.is_ack() {
        // "If the incoming segment has an ACK field, the reset takes
        //  its sequence number from the ACK field of the segment"
        Some(builder.build_tcp_rst_only_ip(flow, tcp.ack_num))
    } else {
        // "Otherwise the reset has sequence number zero and the ACK field
        //  is set to the sum of the sequence number and segment length"
        let mut seg_len = crate::packet_builder::mtu_bounded_u32(payload_len);
        if (tcp.flags & TCP_SYN) != 0 {
            seg_len += 1;
        }
        if (tcp.flags & TCP_FIN) != 0 {
            seg_len += 1;
        }
        Some(builder.build_tcp_rst_ip(flow, 0, tcp.seq_num.wrapping_add(seg_len)))
    }
}

/// Configuration for creating a `NatProxy`.
pub struct NatConfig {
    pub gateway_mac: [u8; 6],
    #[cfg(test)]
    pub guest_mac: [u8; 6],
    pub gateway_ip: Ipv4Addr,
    #[cfg(test)]
    pub guest_ip: Ipv4Addr,
    pub gateway_ipv6: Ipv6Addr,
    #[cfg(test)]
    pub guest_ipv6: Ipv6Addr,
    pub prefix_len: u8,
    pub network_prefix: Ipv4Addr,
    pub network_mask: Ipv4Addr,
    pub network_prefix_v6: Ipv6Addr,
    pub prefix_len_v6: u8,
    pub mtu: usize,
    pub host_egress: HostEgressAuthorizer,
    pub collector_tx: mpsc::Sender<GuestOutput>,
}

/// NAT proxy for managing guest → host connections
pub struct NatProxy<P = DirectTcpPolicy>
where
    P: TcpConnectionPolicy,
{
    /// Active connections (TCP and UDP task handles)
    connections: HashMap<ConnectionKey, ConnectionHandle>,
    /// Current generation for each active connection key.
    connection_generations: HashMap<ConnectionKey, ConnectionGeneration>,
    /// Last retired generation for keys whose old producers may still emit.
    connection_tombstones: HashMap<ConnectionKey, ConnectionGeneration>,
    /// Monotonic source for new connection generations.
    next_connection_generation: u64,
    /// Test override for the total connection cap.
    #[cfg(test)]
    connection_capacity: usize,
    /// Recently evicted inbound TCP ports that an old task may still emit from.
    reserved_inbound_ports: HashMap<(Protocol, IpAddr, u16), ReservedInboundPort>,
    /// Sender clone passed to new tasks (shared with DNS forwarder)
    collector_tx: mpsc::Sender<GuestOutput>,
    /// RX waker callback, cloned into tasks
    rx_waker: Option<RxWaker>,
    /// Gateway MAC (passed to tasks for per-task `PacketBuilder`)
    gateway_mac: [u8; 6],
    /// Configured guest MAC accepted for outbound NAT.
    #[cfg(test)]
    guest_mac: [u8; 6],
    /// `NatProxy`'s own builder (for synchronous RST packets)
    builder: PacketBuilder,
    /// Gateway IP address (for local routing)
    gateway_ip: Ipv4Addr,
    /// Configured guest IPv4 address accepted for outbound NAT.
    #[cfg(test)]
    guest_ip: Ipv4Addr,
    /// Gateway IPv6 address (for local routing)
    gateway_ipv6: Ipv6Addr,
    /// Configured guest IPv6 address accepted for outbound NAT.
    #[cfg(test)]
    guest_ipv6: Ipv6Addr,
    /// IPv4 prefix length
    prefix_len: u8,
    /// Network prefix (e.g., 10.0.2.0)
    network_prefix: Ipv4Addr,
    /// Network mask (e.g., 255.255.255.0)
    network_mask: Ipv4Addr,
    /// IPv6 network prefix
    network_prefix_v6: Ipv6Addr,
    /// IPv6 prefix length
    prefix_len_v6: u8,
    /// Virtual MTU
    mtu: usize,
    /// Typed authorizer for all outbound host socket egress.
    host_egress: HostEgressAuthorizer,
    /// Owned stream TCP policy.
    tcp_policy: P,
    /// Per-instance ephemeral port counter (avoids cross-VM collisions).
    next_ephemeral: u16,
}

impl<P> NatProxy<P>
where
    P: TcpConnectionPolicy,
{
    /// Create a new NAT proxy.
    ///
    /// The `collector_tx` channel is shared with other packet producers
    /// (e.g. DNS forwarder). The matching `collector_rx` is owned by
    /// `UserNetState` which drains it in `poll_iface`.
    pub fn new_with_tcp_policy(config: NatConfig, tcp_policy: P) -> Self {
        Self {
            connections: HashMap::new(),
            connection_generations: HashMap::new(),
            connection_tombstones: HashMap::new(),
            next_connection_generation: 0,
            #[cfg(test)]
            connection_capacity: MAX_CONNECTIONS,
            reserved_inbound_ports: HashMap::new(),
            collector_tx: config.collector_tx,
            rx_waker: None,
            gateway_mac: config.gateway_mac,
            #[cfg(test)]
            guest_mac: config.guest_mac,
            builder: PacketBuilder::new(config.gateway_mac),
            gateway_ip: config.gateway_ip,
            #[cfg(test)]
            guest_ip: config.guest_ip,
            gateway_ipv6: config.gateway_ipv6,
            #[cfg(test)]
            guest_ipv6: config.guest_ipv6,
            prefix_len: config.prefix_len,
            network_prefix: config.network_prefix,
            network_mask: config.network_mask,
            network_prefix_v6: config.network_prefix_v6,
            prefix_len_v6: config.prefix_len_v6,
            mtu: config.mtu,
            host_egress: config.host_egress,
            tcp_policy,
            next_ephemeral: 0,
        }
    }

    /// Set the RX waker callback that tasks fire after sending packets to the collector.
    pub fn set_rx_waker(&mut self, waker: Option<RxWaker>) {
        if let Some(old) = std::mem::replace(&mut self.rx_waker, waker) {
            old.cancel();
        }
    }

    #[cfg(test)]
    pub(crate) fn connection_count(&self) -> usize {
        self.connections.len()
    }

    /// Check if an IP is within the local virtual network
    fn is_local_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_bits = u32::from(ipv4);
                let prefix_bits = u32::from(self.network_prefix);
                let mask_bits = u32::from(self.network_mask);
                (ip_bits & mask_bits) == (prefix_bits & mask_bits)
            }
            IpAddr::V6(ipv6) => {
                let mask_bits = ipv6_mask(self.prefix_len_v6);
                let ip_bits = u128::from(ipv6);
                let prefix_bits = u128::from(self.network_prefix_v6);
                (ip_bits & mask_bits) == (prefix_bits & mask_bits)
            }
        }
    }

    /// Check if packet should be NAT proxied
    ///
    /// Returns true if the destination is outside our local network.
    /// Excludes multicast and broadcast addresses — those should be
    /// handled locally by smoltcp, not forwarded to external hosts.
    fn should_proxy(&self, dst_ip: IpAddr) -> bool {
        match dst_ip {
            IpAddr::V4(ipv4) => {
                if ipv4.is_broadcast() || ipv4.is_multicast() {
                    return false;
                }
                // Gateway IP is allowed through — ICMP/DHCP/DNS are handled
                // upstream in handle_guest_packet(), so remaining gateway
                // traffic (TCP/UDP) can be dispatched to VMM-local services
                // or rejected locally. It is never a host socket address.
                !self.is_local_ip(dst_ip) || ipv4 == self.gateway_ip
            }
            IpAddr::V6(ipv6) => {
                if ipv6.is_multicast() {
                    return false;
                }
                !self.is_local_ip(dst_ip) || ipv6 == self.gateway_ipv6
            }
        }
    }

    fn is_gateway_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => ipv4 == self.gateway_ip,
            IpAddr::V6(ipv6) => ipv6 == self.gateway_ipv6,
        }
    }

    #[cfg(test)]
    fn is_configured_guest_source(&self, eth: &EthernetHeader, src_ip: IpAddr) -> bool {
        if eth.src_mac != self.guest_mac {
            return false;
        }
        match src_ip {
            IpAddr::V4(src) => src == self.guest_ip,
            IpAddr::V6(src) => src == self.guest_ipv6,
        }
    }

    const fn tcp_nat_request(remote_addr: SocketAddr) -> HostEgressRequest {
        HostEgressRequest::new(Protocol::Tcp, remote_addr, HostEgressPurpose::GuestTcpNat)
    }

    const fn udp_nat_request(remote_addr: SocketAddr) -> HostEgressRequest {
        HostEgressRequest::new(Protocol::Udp, remote_addr, HostEgressPurpose::GuestUdpNat)
    }

    fn allows_host_egress(&self, request: HostEgressRequest) -> bool {
        self.host_egress.authorize(request).is_some()
    }

    fn begin_connection_generation(&mut self, key: ConnectionKey) -> ConnectionOutputTag {
        self.next_connection_generation = self.next_connection_generation.wrapping_add(1);
        if self.next_connection_generation == 0 {
            self.next_connection_generation = 1;
        }

        let generation = ConnectionGeneration(self.next_connection_generation);
        self.connection_generations.insert(key, generation);
        self.connection_tombstones.remove(&key);
        ConnectionOutputTag { key, generation }
    }

    fn retire_connection_generation(&mut self, key: ConnectionKey) {
        if let Some(generation) = self.connection_generations.remove(&key) {
            self.connection_tombstones.insert(key, generation);
        }
    }

    pub(crate) fn output_is_current(&self, output: &GuestOutput) -> bool {
        let Some(tag) = output.connection_tag() else {
            return true;
        };

        self.connection_generations.get(&tag.key).copied() == Some(tag.generation)
    }

    #[cfg(test)]
    fn at_connection_capacity(&self) -> bool {
        self.connections.len() >= self.connection_capacity
    }

    #[cfg(not(test))]
    fn at_connection_capacity(&self) -> bool {
        self.connections.len() >= MAX_CONNECTIONS
    }

    fn tcp_rst_response(
        &mut self,
        flow: &FlowEndpoints,
        tcp: &TcpHeader,
        payload_len: usize,
    ) -> Vec<Vec<u8>> {
        build_rst_for_segment(&mut self.builder, flow, tcp, payload_len)
            .map_or_else(Vec::new, |rst| vec![rst])
    }

    /// Process an outbound packet from the guest
    ///
    /// Returns any immediate response packets (e.g., RST for failed connections)
    #[cfg(test)]
    pub fn process_outbound(&mut self, packet: &[u8]) -> Vec<Vec<u8>> {
        // Parse the packet
        let Some(eth) = EthernetHeader::parse(packet) else {
            return Vec::new();
        };

        let Some(ip_packet) = parse_ip_packet(eth.ether_type, &packet[ETH_HEADER_LEN..]) else {
            return Vec::new();
        };

        if !self.is_configured_guest_source(&eth, ip_packet.src_ip()) {
            log::warn!(
                "NAT: dropping packet from unconfigured guest identity mac={:02x?} ip={}",
                eth.src_mac,
                ip_packet.src_ip(),
            );
            return Vec::new();
        }

        self.process_validated_parts(packet, &eth, &ip_packet)
    }

    pub(crate) fn process_validated_outbound(
        &mut self,
        packet: &ValidatedGuestIpPacket<'_>,
    ) -> Vec<Vec<u8>> {
        self.process_validated_parts(packet.frame(), packet.ethernet(), packet.ip())
    }

    fn process_validated_parts(
        &mut self,
        packet: &[u8],
        eth: &EthernetHeader,
        ip_packet: &ParsedIpPacket<'_>,
    ) -> Vec<Vec<u8>> {
        if !self.should_proxy(ip_packet.dst_ip()) {
            return Vec::new();
        }

        if ip_packet.is_fragmented() {
            log::trace!("NAT: Dropping fragmented packet to {}", ip_packet.dst_ip());
            return Vec::new();
        }

        match ip_packet.protocol() {
            IP_PROTO_TCP => {
                self.process_tcp_packet(packet, eth, ip_packet, ip_packet.transport_data())
            }
            IP_PROTO_UDP => self.process_udp_packet(eth, ip_packet, ip_packet.transport_data()),
            _ => {
                log::trace!("NAT: Unsupported protocol {}", ip_packet.protocol());
                Vec::new()
            }
        }
    }

    /// Process a TCP packet from the guest (unified IPv4/IPv6)
    #[allow(clippy::too_many_lines)]
    fn process_tcp_packet(
        &mut self,
        packet: &[u8],
        eth: &EthernetHeader,
        ip_packet: &ParsedIpPacket<'_>,
        data: &[u8],
    ) -> Vec<Vec<u8>> {
        let src_ip = ip_packet.src_ip();
        let dst_ip = ip_packet.dst_ip();
        let Some((tcp, payload)) = parse_tcp_segment(src_ip, dst_ip, data) else {
            return Vec::new();
        };
        let rst_flow = ip_packet.response_flow(eth.src_mac, tcp.dst_port, tcp.src_port);

        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(src_ip, tcp.src_port),
            remote_addr: SocketAddr::new(dst_ip, tcp.dst_port),
        };

        // Existing connection → forward via channel (unless task is dead)
        if let Some(handle) = self.connections.get(&key) {
            if handle.is_finished() {
                // Task is dead — remove stale entry and fall through.
                // If this is a SYN, we'll create a new connection below.
                // If not, we'll send RST below.
                self.connections.remove(&key);
            } else if let ConnectionHandle::Tcp(tcp_handle) = handle {
                match tcp_handle
                    .guest_tx
                    .try_send(GuestPacket::TcpFrame(packet.to_vec()))
                {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        log::warn!(
                            "usernet tcp guest→task channel full for {}:{} -> {}:{}; closing stream",
                            src_ip,
                            tcp.src_port,
                            dst_ip,
                            tcp.dst_port,
                        );
                        tcp_handle.task.abort();
                        self.connections.remove(&key);
                        return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        self.connections.remove(&key);
                        return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
                    }
                }
                return Vec::new();
            }
        }

        // New connection — must be SYN
        if !tcp.is_syn() {
            log::trace!(
                "NAT: TCP packet without SYN for non-existent connection {}:{} -> {}:{}",
                src_ip,
                tcp.src_port,
                dst_ip,
                tcp.dst_port
            );
            return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
        }

        let remote_addr = SocketAddr::new(dst_ip, tcp.dst_port);
        let host_egress_request = Self::tcp_nat_request(remote_addr);

        log::trace!(
            "NAT: New TCP connection {}:{} -> {}:{}",
            src_ip,
            tcp.src_port,
            dst_ip,
            tcp.dst_port
        );

        let is_gateway = self.is_gateway_ip(dst_ip);

        let flow = TcpFlow::new(SocketAddr::new(src_ip, tcp.src_port), remote_addr);

        // Select a transport execution mode. Direct is an explicit allow that
        // dials immediately, LocalService never dials, and TrustedInterceptor
        // gets a LocalSocket plus a lazy HostConnector. A policy that has no
        // opinion is fail-closed; pass-through must be an explicit Direct
        // decision from composition.
        let mode = match self.tcp_policy.open_tcp(flow) {
            TcpOpenAction::NoOpinion => {
                log::trace!(
                    "NAT: TCP policy had no decision for {}:{} -> {}:{}; default-deny",
                    src_ip,
                    tcp.src_port,
                    dst_ip,
                    tcp.dst_port,
                );
                return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
            }
            TcpOpenAction::Deny(reason) => {
                log::trace!(
                    "NAT: TCP policy denied {}:{} -> {}:{}: {reason:?}",
                    src_ip,
                    tcp.src_port,
                    dst_ip,
                    tcp.dst_port,
                );
                return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
            }
            TcpOpenAction::Direct => TcpConnectionMode::Direct {
                host_egress: self.host_egress.clone(),
                request: host_egress_request,
            },
            TcpOpenAction::LocalService(handler) => TcpConnectionMode::LocalService(handler),
            TcpOpenAction::Intercept(interceptor) => TcpConnectionMode::TrustedInterceptor {
                interceptor,
                host_connect: if is_gateway {
                    HostConnectAccess::Denied { remote_addr }
                } else {
                    HostConnectAccess::Authorized {
                        host_egress: self.host_egress.clone(),
                        request: host_egress_request,
                    }
                },
            },
        };

        match &mode {
            TcpConnectionMode::LocalService(_) | TcpConnectionMode::TrustedInterceptor { .. } => {}
            TcpConnectionMode::Direct { request, .. } => {
                if is_gateway {
                    log::warn!(
                        "NAT: gateway TCP {}:{} requested direct host mode; gateway services must use LocalService or Intercept",
                        dst_ip,
                        tcp.dst_port,
                    );
                    return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
                }
                if !self.allows_host_egress(*request) {
                    log::warn!(
                        "NAT: TCP egress denied for {}:{} -> {}:{}",
                        src_ip,
                        tcp.src_port,
                        dst_ip,
                        tcp.dst_port,
                    );
                    return self.tcp_rst_response(&rst_flow, &tcp, payload.len());
                }
            }
        }

        // Clean up finished tasks before checking limit to avoid stale entries
        // inflating the count and evicting live connections. This must happen
        // after gateway-service admission, otherwise a gateway SYN that we
        // reject locally can evict an unrelated live flow before returning RST.
        if self.tcp_connection_count() >= MAX_TCP_CONNECTIONS {
            self.cleanup_finished();
        }

        if self.tcp_connection_count() >= MAX_TCP_CONNECTIONS {
            log::warn!("NAT: TCP connection limit reached, evicting oldest TCP connection");
            self.evict_oldest_protocol(Protocol::Tcp);
        }

        if self.at_connection_capacity() {
            self.cleanup_finished();
        }

        if self.at_connection_capacity() {
            log::warn!("NAT: Connection limit reached, evicting oldest");
            self.evict_oldest();
        }

        // Create channel and spawn task
        let (guest_tx, guest_rx) = mpsc::channel(GUEST_CHANNEL_CAPACITY);
        let collector_tx = self.collector_tx.clone();
        let rx_waker = self.rx_waker.clone();
        let output_tag = self.begin_connection_generation(key);

        let task = tokio::spawn(tcp_connection_task(
            flow,
            packet.to_vec(),
            self.stack_config(),
            guest_rx,
            collector_tx,
            rx_waker,
            mode,
            output_tag,
        ));

        self.connections.insert(
            key,
            ConnectionHandle::Tcp(TcpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        Vec::new()
    }

    const fn stack_config(&self) -> TcpStackConfig {
        TcpStackConfig {
            gateway_mac: self.gateway_mac,
            gateway_ip: self.gateway_ip,
            gateway_ipv6: self.gateway_ipv6,
            prefix_len: self.prefix_len,
            prefix_len_v6: self.prefix_len_v6,
            mtu: self.mtu,
        }
    }

    /// Process a UDP packet from the guest (unified IPv4/IPv6)
    fn process_udp_packet(
        &mut self,
        eth: &EthernetHeader,
        ip_packet: &ParsedIpPacket<'_>,
        data: &[u8],
    ) -> Vec<Vec<u8>> {
        let src_ip = ip_packet.src_ip();
        let dst_ip = ip_packet.dst_ip();
        let Some((udp, payload)) = parse_udp_datagram(src_ip, dst_ip, data) else {
            return Vec::new();
        };

        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(src_ip, udp.src_port),
            remote_addr: SocketAddr::new(dst_ip, udp.dst_port),
        };

        // Existing connection → forward via channel (unless task is dead)
        if let Some(handle) = self.connections.get(&key) {
            if handle.is_finished() {
                // Task is dead — remove stale entry and create fresh connection below.
                self.connections.remove(&key);
            } else if let ConnectionHandle::Udp(udp_handle) = handle {
                if let Err(e) = udp_handle.guest_tx.try_send(payload.to_vec()) {
                    log::warn!(
                        "usernet udp guest→task channel full, dropping datagram {}:{} -> {}:{}: {e}",
                        src_ip,
                        udp.src_port,
                        dst_ip,
                        udp.dst_port,
                    );
                }
                return Vec::new();
            }
        }

        if self.is_gateway_ip(dst_ip) {
            log::trace!(
                "NAT: no VMM gateway UDP service registered for {}:{}",
                dst_ip,
                udp.dst_port,
            );
            return Vec::new();
        }

        let remote_addr = SocketAddr::new(dst_ip, udp.dst_port);
        let host_egress_request = Self::udp_nat_request(remote_addr);

        if !self.allows_host_egress(host_egress_request) {
            log::warn!(
                "NAT: UDP egress denied for {}:{} -> {}:{}",
                src_ip,
                udp.src_port,
                dst_ip,
                udp.dst_port,
            );
            return Vec::new();
        }

        // Capacity admission happens after policy admission so denied UDP
        // packets cannot mutate unrelated NAT state. New UDP fails closed at
        // capacity because evicting an unrelated TCP flow is a worse outcome.
        if !self.prepare_new_udp_connection() {
            return Vec::new();
        }

        log::trace!(
            "NAT: New UDP connection {}:{} -> {}:{}",
            src_ip,
            udp.src_port,
            dst_ip,
            udp.dst_port
        );

        let (guest_tx, guest_rx) = mpsc::channel(GUEST_CHANNEL_CAPACITY);
        let collector_tx = self.collector_tx.clone();
        let rx_waker = self.rx_waker.clone();
        let gateway_mac = self.gateway_mac;
        let output_tag = self.begin_connection_generation(key);
        let response_flow = ip_packet.response_flow(eth.src_mac, udp.dst_port, udp.src_port);

        let task = tokio::spawn(udp_connection_task(UdpTaskParams {
            host_egress: self.host_egress.clone(),
            egress_request: host_egress_request,
            response_flow,
            initial_payload: payload.to_vec(),
            guest_rx,
            collector_tx,
            rx_waker,
            gateway_mac,
            mtu: self.mtu,
            output_tag,
        }));

        self.connections.insert(
            key,
            ConnectionHandle::Udp(UdpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        Vec::new()
    }

    /// Clean up finished task handles
    pub(crate) fn cleanup_finished(&mut self) {
        let mut retired = Vec::new();
        self.connections.retain(|key, handle| {
            if handle.is_finished() {
                log::trace!(
                    "NAT: Cleaned up {:?} connection {:?} -> {:?}",
                    key.protocol,
                    key.guest_addr,
                    key.remote_addr
                );
                retired.push(*key);
                false
            } else {
                true
            }
        });
        for key in retired {
            self.retire_connection_generation(key);
        }
        self.cleanup_reserved_inbound_ports();
    }

    /// Evict the oldest connection to make room for new ones
    fn evict_oldest(&mut self) {
        self.evict_oldest_matching(|_| true);
    }

    fn evict_oldest_protocol(&mut self, protocol: Protocol) {
        self.evict_oldest_matching(|key| key.protocol == protocol);
    }

    fn evict_oldest_matching(&mut self, matches: impl Fn(&ConnectionKey) -> bool) {
        let oldest_key = self
            .connections
            .iter()
            .filter(|(key, _)| matches(key))
            .min_by_key(|(_, handle)| handle.created_at())
            .map(|(key, _)| *key);

        if let Some(key) = oldest_key
            && let Some(handle) = self.connections.remove(&key)
        {
            self.retire_connection_generation(key);
            if let Some(released) = handle.evict(key) {
                self.reserve_inbound_port(key, released);
            }
            log::trace!("NAT: Evicted connection {key:?}");
        }
    }

    fn tcp_connection_count(&self) -> usize {
        self.connections
            .keys()
            .filter(|key| key.protocol == Protocol::Tcp)
            .count()
    }

    fn udp_connection_count(&self) -> usize {
        self.connections
            .keys()
            .filter(|key| key.protocol == Protocol::Udp)
            .count()
    }

    fn prepare_new_udp_connection(&mut self) -> bool {
        if self.udp_connection_count() >= MAX_UDP_CONNECTIONS || self.at_connection_capacity() {
            self.cleanup_finished();
        }

        if self.udp_connection_count() >= MAX_UDP_CONNECTIONS {
            log::warn!("NAT: UDP connection limit reached, dropping new UDP association");
            return false;
        }

        if self.at_connection_capacity() {
            log::warn!("NAT: total connection limit reached, dropping new UDP association");
            return false;
        }

        true
    }

    fn require_new_udp_connection_capacity(&mut self) -> UserNetResult<()> {
        self.prepare_new_udp_connection().then_some(()).ok_or(
            UserNetError::ConnectionLimitReached {
                protocol: Protocol::Udp,
            },
        )
    }

    fn inbound_reservation_key(&self, key: ConnectionKey) -> Option<(Protocol, IpAddr, u16)> {
        let ip = key.remote_addr.ip();
        let port = key.remote_addr.port();
        if key.protocol == Protocol::Tcp
            && (ip == IpAddr::V4(self.gateway_ip) || ip == IpAddr::V6(self.gateway_ipv6))
            && (EPHEMERAL_PORT_START..=u16::MAX).contains(&port)
        {
            Some((key.protocol, ip, port))
        } else {
            None
        }
    }

    fn reserve_inbound_port(&mut self, key: ConnectionKey, released: oneshot::Receiver<()>) {
        if let Some(reservation_key) = self.inbound_reservation_key(key) {
            self.reserved_inbound_ports.insert(
                reservation_key,
                ReservedInboundPort {
                    released,
                    expires_at: Instant::now() + TCP_EVICTION_CLOSE_TIMEOUT,
                },
            );
        }
    }

    fn cleanup_reserved_inbound_ports(&mut self) {
        let now = Instant::now();
        self.reserved_inbound_ports.retain(|_, reservation| {
            if now >= reservation.expires_at {
                return false;
            }
            !matches!(
                reservation.released.try_recv(),
                Ok(()) | Err(oneshot::error::TryRecvError::Closed)
            )
        });
    }

    // =========================================================================
    // Inbound Port Forwarding
    // =========================================================================

    /// Ephemeral port counter for inbound connections (49152–65535).
    ///
    /// Returns `None` when every candidate in the range collides with a live
    /// connection. The caller MUST surface this as an error rather than reuse
    /// a port: `HashMap::insert` on a live key silently replaces the handle
    /// and strands the old proxy task still emitting packets under that
    /// 5-tuple, cross-wiring two flows.
    fn next_ephemeral_port(&mut self, protocol: Protocol, gateway_ip: IpAddr) -> Option<u16> {
        self.cleanup_reserved_inbound_ports();
        for _ in 0..EPHEMERAL_PORT_RANGE {
            let counter = self.next_ephemeral;
            self.next_ephemeral = self.next_ephemeral.wrapping_add(1);
            let port = EPHEMERAL_PORT_START + (counter % EPHEMERAL_PORT_RANGE);
            let collides = self
                .connections
                .keys()
                .any(|k| k.remote_addr.port() == port && k.remote_addr.ip() == gateway_ip);
            let reserved = self
                .reserved_inbound_ports
                .contains_key(&(protocol, gateway_ip, port));
            if !collides && !reserved {
                return Some(port);
            }
        }
        None
    }

    /// Register an inbound (host-to-guest) connection.
    ///
    /// Spawns a smoltcp-backed proxy task and inserts the connection handle.
    ///
    /// Returns `Err(EphemeralPortExhausted)` when the NAT has no free
    /// ephemeral port available; the caller drops the stream.
    pub(crate) fn register_inbound(
        &mut self,
        stream: Box<dyn InboundStream + 'static>,
        guest_port: u16,
        guest_mac: [u8; 6],
        guest_ip: IpAddr,
        gateway_ip: IpAddr,
    ) -> UserNetResult<ConnectionKey> {
        self.cleanup_finished();

        if self.tcp_connection_count() >= MAX_TCP_CONNECTIONS {
            log::warn!("NAT: TCP connection limit reached for inbound, evicting oldest TCP");
            self.evict_oldest_protocol(Protocol::Tcp);
        }

        if self.at_connection_capacity() {
            log::warn!("NAT: Connection limit reached for inbound, evicting oldest");
            self.evict_oldest();
        }

        let ephemeral_port = self
            .next_ephemeral_port(Protocol::Tcp, gateway_ip)
            .ok_or(UserNetError::EphemeralPortExhausted)?;
        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(guest_ip, guest_port),
            remote_addr: SocketAddr::new(gateway_ip, ephemeral_port),
        };

        let (guest_tx, guest_rx) = mpsc::channel(GUEST_CHANNEL_CAPACITY);
        let output_tag = self.begin_connection_generation(key);
        let task = tokio::spawn(inbound_tcp_task(
            stream,
            InboundTarget::new(guest_mac, guest_ip, guest_port, gateway_ip, ephemeral_port),
            self.stack_config(),
            guest_rx,
            self.collector_tx.clone(),
            self.rx_waker.clone(),
            output_tag,
        ));

        self.connections.insert(
            key,
            ConnectionHandle::Tcp(TcpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        Ok(key)
    }

    /// Register an inbound UDP (host-to-guest) datagram association.
    ///
    /// Spawns a task that relays datagrams between the caller's channels
    /// and the guest. Guest responses are matched by `ConnectionKey` in
    /// `process_udp_packet` and forwarded to `to_host`.
    pub(crate) fn register_inbound_udp(
        &mut self,
        from_host: mpsc::Receiver<Vec<u8>>,
        to_host: mpsc::Sender<Vec<u8>>,
        guest_port: u16,
        guest_mac: [u8; 6],
        guest_ip: IpAddr,
        gateway_ip: IpAddr,
    ) -> UserNetResult<ConnectionKey> {
        self.cleanup_finished();

        self.require_new_udp_connection_capacity()?;

        let ephemeral_port = self
            .next_ephemeral_port(Protocol::Udp, gateway_ip)
            .ok_or(UserNetError::EphemeralPortExhausted)?;
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(guest_ip, guest_port),
            remote_addr: SocketAddr::new(gateway_ip, ephemeral_port),
        };
        let flow = FlowEndpoints::from_ip_pair(
            guest_mac,
            gateway_ip,
            guest_ip,
            ephemeral_port,
            guest_port,
        )
        .ok_or_else(|| UserNetError::InvalidConfig("UDP endpoint IP family mismatch".into()))?;
        let (guest_tx, guest_rx) = mpsc::channel(GUEST_CHANNEL_CAPACITY);
        let output_tag = self.begin_connection_generation(key);
        let task = tokio::spawn(inbound_udp_task(InboundUdpTaskParams {
            from_host,
            to_host,
            flow,
            guest_rx,
            collector_tx: self.collector_tx.clone(),
            rx_waker: self.rx_waker.clone(),
            gateway_mac: self.gateway_mac,
            mtu: self.mtu,
            output_tag,
        }));
        self.connections.insert(
            key,
            ConnectionHandle::Udp(UdpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );
        Ok(key)
    }
}

impl<P> Drop for NatProxy<P>
where
    P: TcpConnectionPolicy,
{
    fn drop(&mut self) {
        for (_, handle) in self.connections.drain() {
            handle.abort();
        }
        self.connection_generations.clear();
        self.connection_tombstones.clear();
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_nat_config(collector_tx: mpsc::Sender<GuestOutput>) -> NatConfig {
        NatConfig {
            gateway_mac: GATEWAY_MAC,
            guest_mac: GUEST_MAC,
            gateway_ip: crate::DEFAULT_GATEWAY,
            guest_ip: Ipv4Addr::new(10, 0, 2, 15),
            gateway_ipv6: crate::DEFAULT_GATEWAY_V6,
            guest_ipv6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            prefix_len: 24,
            network_prefix: Ipv4Addr::new(10, 0, 2, 0),
            network_mask: Ipv4Addr::new(255, 255, 255, 0),
            network_prefix_v6: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0),
            prefix_len_v6: 64,
            mtu: crate::VIRTUAL_MTU,
            host_egress: HostEgressAuthorizer::new(
                EgressPolicy::AllowAll,
                DnsForwardPolicy::DenyAll,
            ),
            collector_tx,
        }
    }

    fn make_proxy() -> NatProxy {
        let (collector_tx, _collector_rx) = mpsc::channel(MAX_PENDING_PACKETS);
        NatProxy::new_with_tcp_policy(test_nat_config(collector_tx), DirectTcpPolicy)
    }

    fn make_proxy_with_rx() -> (NatProxy, mpsc::Receiver<GuestOutput>) {
        let (collector_tx, collector_rx) = mpsc::channel(MAX_PENDING_PACKETS);
        let proxy = NatProxy::new_with_tcp_policy(test_nat_config(collector_tx), DirectTcpPolicy);
        (proxy, collector_rx)
    }

    fn make_proxy_with_policy<P>(policy: P) -> NatProxy<P>
    where
        P: TcpConnectionPolicy,
    {
        let (collector_tx, _collector_rx) = mpsc::channel(MAX_PENDING_PACKETS);
        NatProxy::new_with_tcp_policy(test_nat_config(collector_tx), policy)
    }

    fn make_proxy_with_policy_rx<P>(policy: P) -> (NatProxy<P>, mpsc::Receiver<GuestOutput>)
    where
        P: TcpConnectionPolicy,
    {
        let (collector_tx, collector_rx) = mpsc::channel(MAX_PENDING_PACKETS);
        let proxy = NatProxy::new_with_tcp_policy(test_nat_config(collector_tx), policy);
        (proxy, collector_rx)
    }

    fn allow_public_egress<P>(proxy: &mut NatProxy<P>)
    where
        P: TcpConnectionPolicy,
    {
        proxy.host_egress =
            HostEgressAuthorizer::new(EgressPolicy::PublicInternetOnly, DnsForwardPolicy::DenyAll);
    }

    const GATEWAY_MAC: [u8; 6] = crate::DEFAULT_GATEWAY_MAC;
    const GUEST_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];

    struct PendingLocalService;

    impl crate::interceptor::LocalServiceHandler for PendingLocalService {
        fn handle(
            self: Box<Self>,
            _socket: crate::interceptor::LocalSocket,
        ) -> crate::interceptor::BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
    }

    struct GatewayServiceInterceptor {
        addr: SocketAddr,
    }

    impl TcpConnectionPolicy for GatewayServiceInterceptor {
        fn open_tcp(&self, flow: TcpFlow) -> TcpOpenAction {
            if flow.remote_addr == self.addr {
                TcpOpenAction::LocalService(Box::new(PendingLocalService))
            } else {
                TcpOpenAction::NoOpinion
            }
        }
    }

    struct DenyAllTcpPolicy;

    impl TcpConnectionPolicy for DenyAllTcpPolicy {
        fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
            TcpOpenAction::Deny(crate::interceptor::DenyReason::DefaultDeny)
        }
    }

    struct PendingTrustedInterceptor;

    impl crate::interceptor::TrustedTcpInterceptor for PendingTrustedInterceptor {
        fn run(
            self: Box<Self>,
            _guest: crate::interceptor::LocalSocket,
            _flow: TcpFlow,
            _connector: crate::interceptor::HostConnector,
        ) -> crate::interceptor::BoxFuture<'static, ()> {
            Box::pin(std::future::pending())
        }
    }

    struct InterceptAllTcpPolicy;

    impl TcpConnectionPolicy for InterceptAllTcpPolicy {
        fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
            TcpOpenAction::Intercept(Box::new(PendingTrustedInterceptor))
        }
    }

    struct ConnectorProbe {
        result_tx: oneshot::Sender<std::io::ErrorKind>,
    }

    impl crate::interceptor::TrustedTcpInterceptor for ConnectorProbe {
        fn run(
            self: Box<Self>,
            _guest: crate::interceptor::LocalSocket,
            _flow: TcpFlow,
            connector: crate::interceptor::HostConnector,
        ) -> crate::interceptor::BoxFuture<'static, ()> {
            Box::pin(async move {
                let kind = match connector.connect().await {
                    Ok(_) => std::io::ErrorKind::Other,
                    Err(err) => err.kind(),
                };
                self.result_tx.send(kind).ok();
            })
        }
    }

    struct ConnectorProbePolicy {
        result_tx: std::sync::Mutex<Option<oneshot::Sender<std::io::ErrorKind>>>,
    }

    impl TcpConnectionPolicy for ConnectorProbePolicy {
        fn open_tcp(&self, _flow: TcpFlow) -> TcpOpenAction {
            let result_tx = self
                .result_tx
                .lock()
                .expect("connector probe mutex poisoned")
                .take()
                .expect("connector probe used once");
            TcpOpenAction::Intercept(Box::new(ConnectorProbe { result_tx }))
        }
    }

    const _: () = assert!(
        MAX_TCP_CONNECTIONS * TCP_FIXED_BUFFER_BYTES <= MAX_TCP_FIXED_BUFFER_BUDGET,
        "TCP fixed buffer budget exceeded",
    );
    const _: () = assert!(
        MAX_TCP_CONNECTIONS < MAX_CONNECTIONS,
        "TCP cap must stay below the UDP-friendly total NAT capacity",
    );
    const _: () = assert!(
        MAX_UDP_CONNECTIONS <= MAX_CONNECTIONS,
        "UDP cap must fit inside total NAT capacity",
    );

    #[test]
    fn tcp_connection_cap_bounds_fixed_socket_buffer_budget() {
        assert_eq!(
            TCP_FIXED_BUFFER_BYTES,
            2 * crate::tcp_proxy::TCP_SOCKET_BUFFER
        );
    }

    #[test]
    fn test_is_local_ip() {
        let proxy = make_proxy();

        // Local IPs
        assert!(proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 1))));
        assert!(proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15))));
        assert!(proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 255))));

        // External IPs
        assert!(!proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 3, 1))));
        assert!(!proxy.is_local_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn test_should_proxy() {
        let proxy = make_proxy();

        // Should proxy external IPs
        assert!(proxy.should_proxy(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(proxy.should_proxy(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));

        // Should not proxy local subnet IPs (except gateway)
        assert!(!proxy.should_proxy(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15))));
        // Gateway IS proxied (ICMP/DHCP/DNS handled upstream)
        assert!(proxy.should_proxy(IpAddr::V4(crate::DEFAULT_GATEWAY)));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn next_ephemeral_port_surfaces_exhaustion_as_error() {
        // Every ephemeral port (49152..=65535) against the gateway is taken,
        // so the counter can never find a free port. Previously the function
        // silently returned a colliding port and `register_inbound_udp` then
        // overwrote the live handle via HashMap::insert, leaving the old
        // task still writing packets under that 5-tuple.
        let mut proxy = make_proxy();
        let gateway_ip = IpAddr::V4(proxy.gateway_ip);
        for port in 49152u16..=65535 {
            let key = ConnectionKey {
                protocol: Protocol::Tcp,
                guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), port),
                remote_addr: SocketAddr::new(gateway_ip, port),
            };
            let (guest_tx, _rx) = mpsc::channel(1);
            let task = tokio::spawn(std::future::pending::<()>());
            proxy.connections.insert(
                key,
                ConnectionHandle::Tcp(TcpConnectionHandle {
                    guest_tx,
                    task,
                    created_at: Instant::now(),
                }),
            );
        }

        assert_eq!(proxy.next_ephemeral_port(Protocol::Udp, gateway_ip), None);

        let (_from_host_tx, from_host_rx) = mpsc::channel(1);
        let (to_host_tx, _to_host_rx) = mpsc::channel(1);
        let result = proxy.register_inbound_udp(
            from_host_rx,
            to_host_tx,
            8080,
            GUEST_MAC,
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            gateway_ip,
        );
        assert!(
            matches!(result, Err(UserNetError::EphemeralPortExhausted)),
            "expected EphemeralPortExhausted, got {result:?}",
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn next_ephemeral_port_checks_requested_gateway_family() {
        let mut proxy = make_proxy();
        let gateway_ip = IpAddr::V6(proxy.gateway_ipv6);
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15)),
                8080,
            ),
            remote_addr: SocketAddr::new(gateway_ip, 49152),
        };
        let (guest_tx, _rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        proxy.connections.insert(
            key,
            ConnectionHandle::Udp(UdpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        assert_eq!(
            proxy.next_ephemeral_port(Protocol::Udp, gateway_ip),
            Some(49153)
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn inbound_registration_reclaims_finished_ephemeral_handle_before_allocating() {
        let mut proxy = make_proxy();
        let gateway_ip = IpAddr::V4(proxy.gateway_ip);
        let stale_key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 8081),
            remote_addr: SocketAddr::new(gateway_ip, 49152),
        };
        let (stale_guest_tx, _stale_rx) = mpsc::channel(1);
        let stale_task = tokio::spawn(std::future::ready(()));
        proxy.connections.insert(
            stale_key,
            ConnectionHandle::Udp(UdpConnectionHandle {
                guest_tx: stale_guest_tx,
                task: stale_task,
                created_at: Instant::now(),
            }),
        );
        tokio::task::yield_now().await;

        let (_from_host_tx, from_host_rx) = mpsc::channel(1);
        let (to_host_tx, _to_host_rx) = mpsc::channel(1);
        let key = proxy
            .register_inbound_udp(
                from_host_rx,
                to_host_tx,
                8080,
                GUEST_MAC,
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                gateway_ip,
            )
            .expect("finished inbound handle should be reclaimed");

        assert_eq!(key.remote_addr, SocketAddr::new(gateway_ip, 49152));
        assert!(!proxy.connections.contains_key(&stale_key));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn evicted_inbound_tcp_port_is_quarantined_before_reuse() {
        let mut proxy = make_proxy();
        let gateway_ip = IpAddr::V4(proxy.gateway_ip);
        let old_key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 8081),
            remote_addr: SocketAddr::new(gateway_ip, 49152),
        };
        let (guest_tx, _guest_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        proxy.connections.insert(
            old_key,
            ConnectionHandle::Tcp(TcpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        proxy.evict_oldest_protocol(Protocol::Tcp);
        assert!(!proxy.connections.contains_key(&old_key));
        assert_eq!(
            proxy.next_ephemeral_port(Protocol::Tcp, gateway_ip),
            Some(49153),
            "recently evicted inbound TCP port must remain reserved"
        );

        proxy.next_ephemeral = 0;
        let (stream, _peer) = tokio::io::duplex(64);
        let key = proxy
            .register_inbound(
                Box::new(stream),
                8080,
                GUEST_MAC,
                IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                gateway_ip,
            )
            .expect("inbound registration should skip quarantined port");
        assert_eq!(key.remote_addr, SocketAddr::new(gateway_ip, 49153));
    }

    #[test]
    fn test_connection_key() {
        let key1 = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1024),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80),
        };
        let key2 = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1024),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80),
        };
        let key3 = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1024),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80),
        };

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_rst_for_ack_segment_uses_seq_from_ack() {
        use crate::packet_builder::{TCP_ACK, TCP_RST};
        let mut builder = PacketBuilder::new(GATEWAY_MAC);
        let tcp = TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 100,
            ack_num: 42,
            data_offset: 5,
            flags: TCP_ACK,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
        );
        let rst = build_rst_for_segment(&mut builder, &flow, &tcp, 0).expect("should return RST");
        // Parse the RST packet — skip ETH_HEADER_LEN + IPV4_HEADER_LEN to get TCP
        let tcp_start = crate::packet_builder::ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let rst_tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();
        // RST-only (no ACK flag) with seq = incoming ack_num
        assert_eq!(rst_tcp.flags, TCP_RST);
        assert_eq!(rst_tcp.seq_num, 42);
    }

    #[test]
    fn test_rst_for_syn_segment_uses_ack_with_seq_plus_one() {
        use crate::packet_builder::{TCP_ACK, TCP_RST};
        let mut builder = PacketBuilder::new(GATEWAY_MAC);
        let tcp = TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 100,
            ack_num: 0,
            data_offset: 5,
            flags: TCP_SYN,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
        );
        let rst = build_rst_for_segment(&mut builder, &flow, &tcp, 0).expect("should return RST");
        let tcp_start = crate::packet_builder::ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let rst_tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();
        // RST+ACK with seq=0, ack = seq + 1 (SYN consumes 1)
        assert_eq!(rst_tcp.flags, TCP_RST | TCP_ACK);
        assert_eq!(rst_tcp.seq_num, 0);
        assert_eq!(rst_tcp.ack_num, 101);
    }

    #[test]
    fn test_rst_for_fin_segment() {
        use crate::packet_builder::{TCP_ACK, TCP_RST};
        let mut builder = PacketBuilder::new(GATEWAY_MAC);
        let tcp = TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 200,
            ack_num: 0,
            data_offset: 5,
            flags: TCP_FIN,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
        );
        let rst = build_rst_for_segment(&mut builder, &flow, &tcp, 0).expect("should return RST");
        let tcp_start = crate::packet_builder::ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let rst_tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();
        assert_eq!(rst_tcp.flags, TCP_RST | TCP_ACK);
        assert_eq!(rst_tcp.seq_num, 0);
        assert_eq!(rst_tcp.ack_num, 201); // seq(200) + FIN(1)
    }

    #[test]
    fn test_rst_for_fin_with_payload() {
        let mut builder = PacketBuilder::new(GATEWAY_MAC);
        let tcp = TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 300,
            ack_num: 0,
            data_offset: 5,
            flags: TCP_FIN,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        };
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
        );
        let rst = build_rst_for_segment(&mut builder, &flow, &tcp, 10).expect("should return RST");
        let tcp_start = crate::packet_builder::ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let rst_tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();
        assert_eq!(rst_tcp.ack_num, 311); // seq(300) + payload(10) + FIN(1)
    }

    #[test]
    fn test_is_local_ip_v6() {
        let proxy = make_proxy();

        // Same /64 prefix → local
        assert!(proxy.is_local_ip(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0099))));
        // Different prefix → external
        assert!(!proxy.is_local_ip(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_should_proxy_v6() {
        let proxy = make_proxy();

        // External IPv6 should proxy
        assert!(proxy.should_proxy(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));
        // Gateway IPv6 IS proxied (ICMP/DHCP/DNS handled upstream)
        assert!(proxy.should_proxy(IpAddr::V6(crate::DEFAULT_GATEWAY_V6)));
        // Local IPv6 should NOT proxy
        assert!(!proxy.should_proxy(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0099))));
    }

    #[test]
    fn test_no_rst_for_incoming_rst() {
        use crate::packet_builder::TCP_RST;
        let mut builder = PacketBuilder::new(GATEWAY_MAC);
        let tcp = TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 100,
            ack_num: 0,
            data_offset: 5,
            flags: TCP_RST,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        };
        let flow = FlowEndpoints::v4(
            [0xAA; 6],
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 2, 15),
            80,
            1024,
        );
        let result = build_rst_for_segment(&mut builder, &flow, &tcp, 0);
        assert!(result.is_none(), "should not RST a RST");
    }

    // =========================================================================
    // Helpers for building raw Ethernet frames
    // =========================================================================

    use crate::packet_builder::{
        ETH_TYPE_IPV4, ETH_TYPE_IPV6, IP_PROTO_ICMP, IPV4_HEADER_LEN, IPV6_HEADER_LEN, Ipv4Header,
        Ipv6Header, TCP_HEADER_LEN, UDP_HEADER_LEN, UdpHeader, calculate_ip_checksum,
        calculate_tcp_checksum, calculate_udp_checksum,
    };

    /// Build an Ethernet+IPv4+TCP frame from the guest.
    fn build_guest_tcp_frame(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];

        // Ethernet: guest→gateway
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        // IPv4
        let ip = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip,
            dst_ip,
        };
        ip.write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let cksum = calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&cksum.to_be_bytes());

        // TCP
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        TcpHeader {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
        .write(&mut pkt[tcp_start..tcp_start + TCP_HEADER_LEN]);
        let tcp_cksum = calculate_tcp_checksum(
            src_ip,
            dst_ip,
            &pkt[tcp_start..tcp_start + TCP_HEADER_LEN],
            &[],
        );
        pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        pkt
    }

    /// Build an Ethernet+IPv4+UDP frame from the guest.
    fn build_guest_udp_frame(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut pkt = vec![0u8; total_len];

        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        let ip = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len()).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_UDP,
            checksum: 0,
            src_ip,
            dst_ip,
        };
        ip.write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let cksum = calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&cksum.to_be_bytes());

        let udp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let udp_len = u16::try_from(UDP_HEADER_LEN + payload.len()).unwrap();
        UdpHeader {
            src_port,
            dst_port,
            length: udp_len,
            checksum: 0,
        }
        .write(&mut pkt[udp_start..udp_start + UDP_HEADER_LEN]);
        pkt[udp_start + UDP_HEADER_LEN..].copy_from_slice(payload);
        let udp_cksum = calculate_udp_checksum(
            src_ip,
            dst_ip,
            &pkt[udp_start..udp_start + UDP_HEADER_LEN],
            payload,
        );
        pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

        pkt
    }

    // =========================================================================
    // process_outbound dispatch tests
    // =========================================================================

    #[tokio::test]
    async fn test_process_outbound_invalid_ethertype_dropped() {
        let mut proxy = make_proxy();
        // Build a frame with ARP ethertype (not IPv4/IPv6)
        let mut frame = [0u8; 42];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: 0x0806, // ARP
        }
        .write(&mut frame[0..ETH_HEADER_LEN]);

        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty(), "ARP frames should be silently dropped");
    }

    #[tokio::test]
    async fn test_process_outbound_local_destined_not_proxied() {
        let mut proxy = make_proxy();
        // TCP SYN to a local address (10.0.2.15) — should NOT be proxied
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(10, 0, 2, 100), // local network
            1024,
            80,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(
            result.is_empty(),
            "local-destined packet should not be proxied"
        );
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_rejects_spoofed_guest_ipv4_source() {
        let mut proxy = make_proxy();
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 99),
            Ipv4Addr::new(1, 1, 1, 1),
            5000,
            53,
            b"dns query",
        );

        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_rejects_spoofed_guest_mac() {
        let mut proxy = make_proxy();
        let mut frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 1, 1, 1),
            5000,
            53,
            b"dns query",
        );
        frame[6..12].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0, 1]);

        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_public_egress_denies_tcp_to_loopback() {
        let mut proxy = make_proxy();
        allow_public_egress(&mut proxy);
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            443,
            TCP_SYN,
            1000,
            0,
        );

        let result = proxy.process_outbound(&frame);

        assert_eq!(result.len(), 1);
        assert!(proxy.connections.is_empty());
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        assert!(TcpHeader::parse(&result[0][tcp_start..]).unwrap().is_rst());
    }

    #[tokio::test]
    async fn test_public_egress_denies_udp_to_private_network() {
        let mut proxy = make_proxy();
        allow_public_egress(&mut proxy);
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(192, 168, 1, 1),
            5000,
            123,
            b"ntp",
        );

        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_allowlist_denies_tcp_denied_port_even_when_ip_allowed() {
        let mut proxy = make_proxy();
        let allowed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let allowed_addr = allowed_listener.local_addr().unwrap();
        let denied_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let denied_addr = denied_listener.local_addr().unwrap();
        proxy.host_egress = HostEgressAuthorizer::new(
            EgressPolicy::AllowList(vec![HostEgressRule::tcp_nat(allowed_addr)]),
            DnsForwardPolicy::DenyAll,
        );

        let IpAddr::V4(denied_ip) = denied_addr.ip() else {
            panic!("test listener should be IPv4");
        };
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            denied_ip,
            5000,
            denied_addr.port(),
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);

        assert_eq!(result.len(), 1, "denied TCP port should RST");
        assert!(proxy.connections.is_empty());
        assert!(
            tokio::time::timeout(Duration::from_millis(100), denied_listener.accept())
                .await
                .is_err(),
            "denied TCP port must not receive a host connection"
        );
    }

    #[tokio::test]
    async fn test_allowlist_denies_udp_denied_port_even_when_ip_allowed() {
        let mut proxy = make_proxy();
        let allowed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let allowed_addr = allowed.local_addr().unwrap();
        let denied = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let denied_addr = denied.local_addr().unwrap();
        proxy.host_egress = HostEgressAuthorizer::new(
            EgressPolicy::AllowList(vec![HostEgressRule::udp_nat(allowed_addr)]),
            DnsForwardPolicy::DenyAll,
        );

        let IpAddr::V4(denied_ip) = denied_addr.ip() else {
            panic!("test socket should be IPv4");
        };
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            denied_ip,
            5000,
            denied_addr.port(),
            b"blocked",
        );
        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
        let mut buf = [0u8; 32];
        assert!(
            tokio::time::timeout(Duration::from_millis(100), denied.recv_from(&mut buf))
                .await
                .is_err(),
            "denied UDP port must not receive a host datagram"
        );
    }

    #[tokio::test]
    async fn test_denied_udp_does_not_evict_live_connection_at_capacity() {
        let mut proxy = make_proxy();
        allow_public_egress(&mut proxy);
        proxy.connection_capacity = 1;

        let existing_key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 4000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        };
        let (guest_tx, _guest_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        proxy.connections.insert(
            existing_key,
            ConnectionHandle::Udp(UdpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(192, 168, 1, 1),
            5001,
            123,
            b"ntp",
        );
        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);
        assert!(proxy.connections.contains_key(&existing_key));
    }

    #[tokio::test]
    async fn test_new_udp_does_not_evict_tcp_at_total_capacity() {
        let mut proxy = make_proxy();
        proxy.connection_capacity = 1;

        let existing_key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 4000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        };
        let (guest_tx, _guest_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        proxy.connections.insert(
            existing_key,
            ConnectionHandle::Tcp(TcpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            5001,
            123,
            b"ntp",
        );
        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);
        assert!(proxy.connections.contains_key(&existing_key));
    }

    #[tokio::test]
    async fn test_inbound_udp_does_not_evict_tcp_at_total_capacity() {
        let mut proxy = make_proxy();
        proxy.connection_capacity = 1;

        let existing_key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 4000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
        };
        let (guest_tx, _guest_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending::<()>());
        proxy.connections.insert(
            existing_key,
            ConnectionHandle::Tcp(TcpConnectionHandle {
                guest_tx,
                task,
                created_at: Instant::now(),
            }),
        );

        let (_from_host_tx, from_host_rx) = mpsc::channel(1);
        let (to_host_tx, _to_host_rx) = mpsc::channel(1);
        let result = proxy.register_inbound_udp(
            from_host_rx,
            to_host_tx,
            8080,
            GUEST_MAC,
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            IpAddr::V4(proxy.gateway_ip),
        );

        assert!(matches!(
            result,
            Err(UserNetError::ConnectionLimitReached {
                protocol: Protocol::Udp
            })
        ));
        assert_eq!(proxy.connections.len(), 1);
        assert!(proxy.connections.contains_key(&existing_key));
    }

    #[tokio::test]
    async fn test_public_egress_denies_trusted_interceptor_host_connector_to_loopback() {
        let (result_tx, result_rx) = oneshot::channel();
        let (mut proxy, _collector_rx) = make_proxy_with_policy_rx(ConnectorProbePolicy {
            result_tx: std::sync::Mutex::new(Some(result_tx)),
        });
        allow_public_egress(&mut proxy);
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            443,
            TCP_SYN,
            1000,
            0,
        );

        let result = proxy.process_outbound(&frame);

        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);
        let kind = tokio::time::timeout(Duration::from_secs(1), result_rx)
            .await
            .expect("connector probe timed out")
            .expect("connector probe dropped");
        assert_eq!(kind, std::io::ErrorKind::PermissionDenied);
    }

    #[tokio::test]
    async fn test_process_outbound_gateway_destined_without_service_gets_rst() {
        let mut proxy = make_proxy();
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
            1024,
            80,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert_eq!(result.len(), 1, "unserved gateway TCP should RST");
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let tcp = TcpHeader::parse(&result[0][tcp_start..]).unwrap();
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 1024);
        assert!(tcp.is_rst());
        assert!(tcp.is_ack());
        assert_eq!(tcp.ack_num, 1001);
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_gateway_destined_local_service_is_registered() {
        let service_addr = SocketAddr::new(IpAddr::V4(crate::DEFAULT_GATEWAY), 8080);
        let mut proxy = make_proxy_with_policy(GatewayServiceInterceptor { addr: service_addr });

        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
            1024,
            8080,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);

        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1024),
            remote_addr: service_addr,
        };
        assert!(proxy.connections.contains_key(&key));
    }

    #[tokio::test]
    async fn test_tcp_policy_deny_rsts_without_spawning_task() {
        let mut proxy = make_proxy_with_policy(DenyAllTcpPolicy);

        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            443,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert_eq!(result.len(), 1);
        assert!(proxy.connections.is_empty());

        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let tcp = TcpHeader::parse(&result[0][tcp_start..]).unwrap();
        assert_eq!(
            tcp.flags,
            crate::packet_builder::TCP_RST | crate::packet_builder::TCP_ACK
        );
        assert_eq!(tcp.ack_num, 1001);
    }

    #[tokio::test(flavor = "current_thread")]
    async fn test_trusted_interceptor_does_not_dial_before_connector_use() {
        let (mut proxy, mut collector_rx) = make_proxy_with_policy_rx(InterceptAllTcpPolicy);
        proxy.host_egress =
            HostEgressAuthorizer::new(EgressPolicy::DenyAll, DnsForwardPolicy::DenyAll);

        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            9,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);

        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut saw_syn_ack = false;
        let mut saw_rst = false;
        while let Ok(output) = collector_rx.try_recv() {
            let frame = output.into_packet();
            let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
            let Some(tcp) = TcpHeader::parse(&frame[tcp_start..]) else {
                continue;
            };
            saw_syn_ack |= tcp.flags & (TCP_SYN | crate::packet_builder::TCP_ACK)
                == (TCP_SYN | crate::packet_builder::TCP_ACK);
            saw_rst |= tcp.flags & crate::packet_builder::TCP_RST != 0;
        }

        assert!(
            saw_syn_ack,
            "trusted interceptor should accept the guest-side TCP handshake"
        );
        assert!(
            !saw_rst,
            "trusted interceptor must not eagerly connect and RST before using HostConnector"
        );
    }

    #[tokio::test]
    async fn test_process_outbound_gateway_udp_without_service_is_dropped() {
        let mut proxy = make_proxy();
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
            5000,
            12345,
            b"payload",
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_non_syn_tcp_gets_rst() {
        let mut proxy = make_proxy();
        // ACK to external address without existing connection → should get RST
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            1024,
            80,
            crate::packet_builder::TCP_ACK,
            1000,
            500,
        );
        let result = proxy.process_outbound(&frame);
        // Should return a RST packet
        assert_eq!(result.len(), 1, "should return exactly one RST packet");
        let rst = &result[0];
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();
        assert!(tcp.is_rst());
    }

    #[tokio::test]
    async fn test_process_outbound_tcp_syn_creates_connection() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        // Bind a local listener so the connect() in process_outbound succeeds.
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // SYN to 127.0.0.1:port — this IS external from the proxy's POV
        // (not in 10.0.2.0/24)
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        // Successful SYN spawns a task, returns empty (SYN-ACK comes later via collector)
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);

        drop(listener);
    }

    #[tokio::test]
    async fn test_process_outbound_udp_creates_connection() {
        let mut proxy = make_proxy();

        // UDP to external address
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            5000,
            53,
            b"dns query",
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);
    }

    #[tokio::test]
    async fn test_process_outbound_truncated_packet_dropped() {
        let mut proxy = make_proxy();
        // Too short for Ethernet header
        let result = proxy.process_outbound(&[0; 10]);
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_fragmented_ipv4_dropped() {
        let mut proxy = make_proxy();
        // Build frame with MF flag set (fragmented)
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        let ip = Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN).unwrap(),
            identification: 1,
            flags_fragment: 0x2000, // MF flag set (fragmented)
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        };
        ip.write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "fragmented packets should be dropped");
    }

    #[tokio::test]
    async fn test_process_outbound_unsupported_protocol_dropped() {
        let mut proxy = make_proxy();
        // Build an IPv4 frame with ICMP protocol (not TCP/UDP)
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + 8;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + 8).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_ICMP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "ICMP should be silently dropped");
    }

    // =========================================================================
    // evict_oldest
    // =========================================================================

    #[tokio::test]
    async fn test_evict_oldest_removes_oldest_connection() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        // Create two connections with a time gap
        let listener1 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port1 = listener1.local_addr().unwrap().port();
        let frame1 = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port1,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&frame1);
        assert_eq!(proxy.connections.len(), 1);

        let listener2 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        let frame2 = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1025,
            port2,
            TCP_SYN,
            2000,
            0,
        );
        proxy.process_outbound(&frame2);
        assert_eq!(proxy.connections.len(), 2);

        // Evict oldest — should remove the first connection
        proxy.evict_oldest();
        assert_eq!(proxy.connections.len(), 1);

        // Remaining connection should be the newer one (port2)
        let remaining_key = proxy.connections.keys().next().unwrap();
        assert_eq!(remaining_key.remote_addr.port(), port2);

        drop(listener1);
        drop(listener2);
    }

    #[test]
    fn test_evict_oldest_empty_is_noop() {
        let mut proxy = make_proxy();
        // Should not panic
        proxy.evict_oldest();
        assert!(proxy.connections.is_empty());
    }

    // =========================================================================
    // IPv6 helpers
    // =========================================================================

    use crate::packet_builder::{calculate_tcp_checksum_v6, calculate_udp_checksum_v6};

    /// Build an Ethernet+IPv6+TCP frame from the guest.
    fn build_guest_tcp_frame_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];

        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        Ipv6Header {
            payload_len: u16::try_from(TCP_HEADER_LEN).unwrap(),
            next_header: IP_PROTO_TCP,
            hop_limit: 64,
            src_ip,
            dst_ip,
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        TcpHeader {
            src_port,
            dst_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
        .write(&mut pkt[tcp_start..tcp_start + TCP_HEADER_LEN]);
        let tcp_cksum = calculate_tcp_checksum_v6(
            src_ip,
            dst_ip,
            &pkt[tcp_start..tcp_start + TCP_HEADER_LEN],
            &[],
        );
        pkt[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());

        pkt
    }

    /// Build an Ethernet+IPv6+UDP frame from the guest.
    fn build_guest_udp_frame_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + UDP_HEADER_LEN + payload.len();
        let mut pkt = vec![0u8; total_len];

        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);

        let udp_total = UDP_HEADER_LEN + payload.len();
        Ipv6Header {
            payload_len: u16::try_from(udp_total).unwrap(),
            next_header: IP_PROTO_UDP,
            hop_limit: 64,
            src_ip,
            dst_ip,
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let udp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        UdpHeader {
            src_port,
            dst_port,
            length: u16::try_from(udp_total).unwrap(),
            checksum: 0,
        }
        .write(&mut pkt[udp_start..udp_start + UDP_HEADER_LEN]);
        pkt[udp_start + UDP_HEADER_LEN..].copy_from_slice(payload);
        let udp_cksum = calculate_udp_checksum_v6(
            src_ip,
            dst_ip,
            &pkt[udp_start..udp_start + UDP_HEADER_LEN],
            payload,
        );
        pkt[udp_start + 6..udp_start + 8].copy_from_slice(&udp_cksum.to_be_bytes());

        pkt
    }

    // =========================================================================
    // IPv6 process_outbound tests
    // =========================================================================

    #[tokio::test]
    async fn test_process_outbound_ipv6_tcp_syn_creates_connection() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        // Bind a listener on [::1] so the connect() succeeds
        let listener = TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            2048,
            port,
            TCP_SYN,
            5000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);

        // Verify the key is IPv6
        let key = proxy.connections.keys().next().unwrap();
        assert!(key.guest_addr.ip().is_ipv6());
        assert!(key.remote_addr.ip().is_ipv6());

        drop(listener);
    }

    #[tokio::test]
    async fn test_process_outbound_ipv6_non_syn_gets_rst() {
        let mut proxy = make_proxy();

        // ACK to external IPv6 without existing connection → should get RST
        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            2048,
            80,
            crate::packet_builder::TCP_ACK,
            3000,
            500,
        );
        let result = proxy.process_outbound(&frame);
        assert_eq!(result.len(), 1, "should return exactly one RST packet");
    }

    #[tokio::test]
    async fn test_process_outbound_ipv6_udp_creates_connection() {
        let mut proxy = make_proxy();

        let frame = build_guest_udp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            6000,
            53,
            b"dns6 query",
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(proxy.connections.len(), 1);
    }

    #[tokio::test]
    async fn test_process_outbound_ipv6_local_not_proxied() {
        let mut proxy = make_proxy();

        // Destination in same /64 prefix — should NOT be proxied
        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0099),
            2048,
            80,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_ipv6_gateway_without_service_gets_rst() {
        let mut proxy = make_proxy();

        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            crate::DEFAULT_GATEWAY_V6,
            2048,
            80,
            TCP_SYN,
            1000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert_eq!(result.len(), 1, "unserved IPv6 gateway TCP should RST");
        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&result[0][tcp_start..]).unwrap();
        assert_eq!(tcp.src_port, 80);
        assert_eq!(tcp.dst_port, 2048);
        assert!(tcp.is_rst());
        assert!(tcp.is_ack());
        assert_eq!(tcp.ack_num, 1001);
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_process_outbound_ipv6_unsupported_protocol_dropped() {
        let mut proxy = make_proxy();

        // Build IPv6 frame with ICMPv6 next_header
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + 8;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv6Header {
            payload_len: 8,
            next_header: 58, // ICMPv6
            hop_limit: 64,
            src_ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty());
    }

    // =========================================================================
    // collector_rx draining
    // =========================================================================

    #[tokio::test]
    async fn test_collector_rx_receives_packets() {
        use std::net::TcpListener;
        let (mut proxy, mut collector_rx) = make_proxy_with_rx();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Create TCP connection (SYN spawns a task that will send packets)
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&frame);

        // Give the async task a moment to send packets
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Drain collector_rx directly (as poll_iface would)
        let mut count = 0;
        while collector_rx.try_recv().is_ok() {
            count += 1;
        }
        // At least verify the drain succeeds without panic
        let _ = count;

        drop(listener);
    }

    // =========================================================================
    // Duplicate connection reuse
    // =========================================================================

    #[tokio::test]
    async fn test_duplicate_syn_reuses_connection() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // First SYN
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        // Second SYN with same 4-tuple goes to existing connection via channel
        let frame2 = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port,
            TCP_SYN,
            2000,
            0,
        );
        proxy.process_outbound(&frame2);
        // Should still be 1 connection (reused via channel, not duplicated)
        assert_eq!(proxy.connections.len(), 1);

        drop(listener);
    }

    // =========================================================================
    // Truncated transport headers
    // =========================================================================

    #[tokio::test]
    async fn test_process_outbound_truncated_tcp_header() {
        let mut proxy = make_proxy();

        // Build frame with IPv4 but only 10 bytes of TCP (need 20)
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + 10;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + 10).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let cksum = calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&cksum.to_be_bytes());

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "truncated TCP header should be dropped");
    }

    #[tokio::test]
    async fn test_process_outbound_truncated_udp_header() {
        let mut proxy = make_proxy();

        // Build frame with IPv4 but only 4 bytes of UDP (need 8)
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + 4;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + 4).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_UDP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let cksum = calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&cksum.to_be_bytes());

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "truncated UDP header should be dropped");
    }

    // =========================================================================
    // Regression: NAT clamps transport data to IP length (bug #1)
    // =========================================================================

    #[tokio::test]
    async fn test_udp_trailing_ethernet_padding_stripped() {
        let mut proxy = make_proxy();
        let payload = b"ABCD";
        let mut frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            5000,
            53,
            payload,
        );

        // Simulate Ethernet padding: append 20 zero bytes (as a NIC would)
        frame.extend_from_slice(&[0u8; 20]);

        let _result = proxy.process_outbound(&frame);

        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 5000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        };
        assert!(
            proxy.connections.contains_key(&key),
            "UDP connection should be created even with padded frame"
        );
    }

    #[tokio::test]
    async fn test_tcp_trailing_ethernet_padding_stripped() {
        let mut proxy = make_proxy();
        let mut frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(93, 184, 216, 34), // example.com
            5001,
            80,
            TCP_SYN,
            1000,
            0,
        );

        // Pad to 64-byte Ethernet minimum (frame is 54 bytes: 14+20+20)
        while frame.len() < 64 {
            frame.push(0);
        }

        // Should work — the padding bytes must not confuse the TCP parser
        let _result = proxy.process_outbound(&frame);
    }

    // =========================================================================
    // Regression: collector channel cap prevents OOM (bug #5)
    // =========================================================================

    #[test]
    fn test_collector_channel_is_bounded() {
        // The collector channel is bounded to MAX_PENDING_PACKETS.
        // When full, try_send returns Full (not OOM).
        let (tx, _rx) = mpsc::channel::<GuestOutput>(MAX_PENDING_PACKETS);
        for i in 0..MAX_PENDING_PACKETS {
            assert!(
                tx.try_send(GuestOutput::Control(vec![0u8; 10])).is_ok(),
                "send {i} should succeed"
            );
        }
        // Channel is now full
        assert!(
            tx.try_send(GuestOutput::Control(vec![0xAA; 10])).is_err(),
            "channel should be full"
        );
    }

    // =========================================================================
    // Per-connection channel backpressure (HIGH-1 regression tests)
    // =========================================================================

    // Compile-time verification that GUEST_CHANNEL_CAPACITY is sensible.
    const _: () = assert!(
        GUEST_CHANNEL_CAPACITY >= 64,
        "capacity too small for bursty traffic"
    );
    const _: () = assert!(
        GUEST_CHANNEL_CAPACITY <= 4096,
        "capacity too large, defeats backpressure purpose"
    );

    #[tokio::test]
    async fn test_tcp_channel_applies_backpressure() {
        use std::net::TcpListener;

        let (mut proxy, _collector_rx) = make_proxy_with_rx();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Create TCP connection with SYN
        let frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        // The guest_tx channel is bounded. Flood it with packets and verify
        // that try_send eventually returns Full (instead of growing unbounded).
        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 1024),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        };
        if let Some(ConnectionHandle::Tcp(handle)) = proxy.connections.get(&key) {
            // Fill the channel to capacity
            let mut sent = 0;
            for _ in 0..GUEST_CHANNEL_CAPACITY + 100 {
                let frame = build_guest_tcp_frame(
                    Ipv4Addr::new(10, 0, 2, 15),
                    Ipv4Addr::LOCALHOST,
                    1024,
                    port,
                    crate::packet_builder::TCP_ACK,
                    2000 + u32::try_from(sent).unwrap(),
                    0,
                );
                match handle
                    .guest_tx
                    .try_send(crate::tcp_proxy::GuestPacket::TcpFrame(frame))
                {
                    Ok(()) => sent += 1,
                    Err(_) => break,
                }
            }
            // Should have sent exactly GUEST_CHANNEL_CAPACITY before hitting Full
            assert_eq!(
                sent, GUEST_CHANNEL_CAPACITY,
                "channel should accept exactly {GUEST_CHANNEL_CAPACITY} packets, got {sent}"
            );
        } else {
            panic!("expected TCP connection handle");
        }

        drop(listener);
    }

    #[tokio::test]
    async fn test_udp_channel_applies_backpressure() {
        let (mut proxy, _collector_rx) = make_proxy_with_rx();

        // Create UDP connection
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            5000,
            9999,
            b"init",
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 5000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9999),
        };
        if let Some(ConnectionHandle::Udp(handle)) = proxy.connections.get(&key) {
            let mut sent = 0;
            for _ in 0..GUEST_CHANNEL_CAPACITY + 100 {
                match handle.guest_tx.try_send(vec![0xCD; 100]) {
                    Ok(()) => sent += 1,
                    Err(_) => break,
                }
            }
            assert_eq!(
                sent, GUEST_CHANNEL_CAPACITY,
                "UDP channel should accept exactly {GUEST_CHANNEL_CAPACITY} packets, got {sent}"
            );
        } else {
            panic!("expected UDP connection handle");
        }
    }

    #[tokio::test]
    async fn test_process_outbound_closes_on_full_tcp_channel() {
        use std::net::TcpListener;

        let (mut proxy, _collector_rx) = make_proxy_with_rx();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Create TCP connection
        let syn = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            2048,
            port,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&syn);

        // Fill the per-connection channel by injecting directly
        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 2048),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
        };
        if let Some(ConnectionHandle::Tcp(handle)) = proxy.connections.get(&key) {
            for _ in 0..GUEST_CHANNEL_CAPACITY {
                let frame = build_guest_tcp_frame(
                    Ipv4Addr::new(10, 0, 2, 15),
                    Ipv4Addr::LOCALHOST,
                    2048,
                    port,
                    crate::packet_builder::TCP_ACK,
                    5000,
                    0,
                );
                drop(
                    handle
                        .guest_tx
                        .try_send(crate::tcp_proxy::GuestPacket::TcpFrame(frame)),
                );
            }
        }

        // Now send another packet via process_outbound. A saturated TCP task
        // cannot be synchronously backpressured from `NetBackend::send`, so the
        // stream is closed intentionally instead of dropping the segment.
        let data_frame = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            2048,
            port,
            crate::packet_builder::TCP_ACK,
            2000,
            0,
        );
        let result = proxy.process_outbound(&data_frame);
        assert_eq!(result.len(), 1, "full TCP channel should return a reset");
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        let tcp = TcpHeader::parse(&result[0][tcp_start..]).unwrap();
        assert!(tcp.is_rst());
        assert!(proxy.connections.is_empty());

        drop(listener);
    }

    #[tokio::test]
    async fn test_process_outbound_drops_on_full_udp_channel() {
        let (mut proxy, _collector_rx) = make_proxy_with_rx();

        // Create UDP connection
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            6000,
            8888,
            b"init",
        );
        proxy.process_outbound(&frame);

        // Fill the channel
        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 6000),
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8888),
        };
        if let Some(ConnectionHandle::Udp(handle)) = proxy.connections.get(&key) {
            for _ in 0..GUEST_CHANNEL_CAPACITY {
                drop(handle.guest_tx.try_send(vec![0xEE; 10]));
            }
        }

        // Another UDP packet via process_outbound should be silently dropped
        let frame2 = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            6000,
            8888,
            b"overflow",
        );
        let result = proxy.process_outbound(&frame2);
        assert!(
            result.is_empty(),
            "full UDP channel should cause silent drop"
        );
    }

    // =========================================================================
    // UDP task: channel close exits promptly (MEDIUM-3 regression test)
    // =========================================================================

    #[tokio::test]
    async fn test_udp_task_exits_on_channel_close() {
        let remote = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote_addr = remote.local_addr().unwrap();

        let (guest_tx, guest_rx) = mpsc::channel(256);
        let (collector_tx, _collector_rx) = mpsc::channel(100);
        let host_egress =
            HostEgressAuthorizer::new(EgressPolicy::AllowAll, DnsForwardPolicy::DenyAll);
        let egress_request =
            HostEgressRequest::new(Protocol::Udp, remote_addr, HostEgressPurpose::GuestUdpNat);

        let task = tokio::spawn(crate::udp_proxy::udp_connection_task(
            crate::udp_proxy::UdpTaskParams {
                host_egress,
                egress_request,
                response_flow: FlowEndpoints::from_ip_pair(
                    [0xAA; 6],
                    remote_addr.ip(),
                    IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
                    remote_addr.port(),
                    12345,
                )
                .expect("test endpoints use matching IP families"),
                initial_payload: b"hello".to_vec(),
                guest_rx,
                collector_tx,
                rx_waker: None,
                gateway_mac: GATEWAY_MAC,
                mtu: crate::VIRTUAL_MTU,
                output_tag: ConnectionOutputTag::for_test(Protocol::Udp),
            },
        ));

        // Wait a bit for task to start
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(!task.is_finished(), "task should be running");

        // Close the channel — task should exit promptly (not wait for timeout)
        drop(guest_tx);

        // The task should exit within 1s (not the 30s timeout)
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
        assert!(
            result.is_ok(),
            "task should exit promptly when channel closes, not wait for timeout"
        );
    }

    // =========================================================================
    // Connection reuse regression tests
    // =========================================================================

    #[tokio::test]
    async fn test_udp_existing_connection_reuse_v4() {
        let mut proxy = make_proxy();

        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            5000,
            53,
            b"query1",
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        // Second UDP to same 4-tuple reuses connection
        let frame2 = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            5000,
            53,
            b"query2",
        );
        proxy.process_outbound(&frame2);
        assert_eq!(
            proxy.connections.len(),
            1,
            "should reuse existing UDP v4 connection"
        );
    }

    #[tokio::test]
    async fn test_tcp_existing_connection_reuse_v6() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        let listener = TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // SYN creates v6 connection
        let syn = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            2048,
            port,
            TCP_SYN,
            5000,
            0,
        );
        proxy.process_outbound(&syn);
        assert_eq!(proxy.connections.len(), 1);

        // Subsequent ACK forwards (no RST), still 1 connection
        let ack = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            2048,
            port,
            crate::packet_builder::TCP_ACK,
            5001,
            1000,
        );
        let result = proxy.process_outbound(&ack);
        assert!(
            result.is_empty(),
            "ACK to existing v6 connection should not produce RST"
        );
        assert_eq!(
            proxy.connections.len(),
            1,
            "should reuse existing TCP v6 connection"
        );

        drop(listener);
    }

    #[tokio::test]
    async fn test_udp_existing_connection_reuse_v6() {
        let mut proxy = make_proxy();

        let frame = build_guest_udp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            6000,
            53,
            b"query1",
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        // Second UDP to same v6 4-tuple reuses connection
        let frame2 = build_guest_udp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            6000,
            53,
            b"query2",
        );
        proxy.process_outbound(&frame2);
        assert_eq!(
            proxy.connections.len(),
            1,
            "should reuse existing UDP v6 connection"
        );
    }

    // =========================================================================
    // Cross-version isolation
    // =========================================================================

    #[tokio::test]
    async fn test_v4_and_v6_connections_are_distinct() {
        use std::net::TcpListener;
        let mut proxy = make_proxy();

        let listener4 = TcpListener::bind("127.0.0.1:0").unwrap();
        let port4 = listener4.local_addr().unwrap().port();
        let listener6 = TcpListener::bind("[::1]:0").unwrap();
        let port6 = listener6.local_addr().unwrap().port();

        // TCP SYN on v4
        let frame4 = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            1024,
            port4,
            TCP_SYN,
            1000,
            0,
        );
        proxy.process_outbound(&frame4);
        assert_eq!(proxy.connections.len(), 1);

        // TCP SYN on v6 with same src/dst ports but different address family
        let frame6 = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            1024,
            port6,
            TCP_SYN,
            2000,
            0,
        );
        proxy.process_outbound(&frame6);
        assert_eq!(
            proxy.connections.len(),
            2,
            "v4 and v6 should be distinct connections"
        );

        drop(listener4);
        drop(listener6);
    }

    // =========================================================================
    // IPv6 RST verification
    // =========================================================================

    #[tokio::test]
    async fn test_ipv6_rst_for_ack_verifies_fields() {
        use crate::packet_builder::TCP_RST;
        let mut proxy = make_proxy();

        // ACK to non-existent v6 connection → RST
        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            2048,
            80,
            crate::packet_builder::TCP_ACK,
            3000,
            500,
        );
        let result = proxy.process_outbound(&frame);
        assert_eq!(result.len(), 1);

        let rst = &result[0];

        // Verify ETH_TYPE_IPV6
        let eth = EthernetHeader::parse(rst).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV6, "RST should be IPv6");

        // Parse TCP after IPv6 header
        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let rst_tcp = TcpHeader::parse(&rst[tcp_start..]).unwrap();

        // RST-only (no ACK), seq = incoming ack_num
        assert_eq!(rst_tcp.flags, TCP_RST, "RST for ACK should be RST-only");
        assert_eq!(rst_tcp.seq_num, 500, "seq should equal incoming ack_num");

        // Ports should be swapped
        assert_eq!(
            rst_tcp.src_port, 80,
            "src_port should be the original dst_port"
        );
        assert_eq!(
            rst_tcp.dst_port, 2048,
            "dst_port should be the original src_port"
        );
    }

    #[tokio::test]
    async fn test_ipv6_no_rst_for_rst_segment() {
        let mut proxy = make_proxy();

        // RST to non-existent v6 connection → empty (RFC 793: never RST a RST)
        let frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            2048,
            80,
            crate::packet_builder::TCP_RST,
            3000,
            0,
        );
        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty(), "should not RST a RST (RFC 793)");
    }

    // =========================================================================
    // Truncated headers for IPv6
    // =========================================================================

    #[tokio::test]
    async fn test_truncated_tcp_header_v6() {
        let mut proxy = make_proxy();

        // IPv6 frame with only 10 bytes of TCP (need 20)
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + 10;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv6Header {
            payload_len: 10,
            next_header: IP_PROTO_TCP,
            hop_limit: 64,
            src_ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "truncated TCP v6 header should be dropped"
        );
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_truncated_udp_header_v6() {
        let mut proxy = make_proxy();

        // IPv6 frame with only 4 bytes of UDP (need 8)
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + 4;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv6Header {
            payload_len: 4,
            next_header: IP_PROTO_UDP,
            hop_limit: 64,
            src_ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "truncated UDP v6 header should be dropped"
        );
        assert!(proxy.connections.is_empty());
    }

    // =========================================================================
    // Ethernet padding for IPv6
    // =========================================================================

    #[tokio::test]
    async fn test_tcp_trailing_ethernet_padding_stripped_v6() {
        let mut proxy = make_proxy();

        let mut frame = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            2048,
            80,
            TCP_SYN,
            5000,
            0,
        );
        // Append 20 padding bytes
        frame.extend_from_slice(&[0u8; 20]);

        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(
            proxy.connections.len(),
            1,
            "TCP SYN v6 with padding should create connection"
        );
    }

    #[tokio::test]
    async fn test_udp_trailing_ethernet_padding_stripped_v6() {
        let mut proxy = make_proxy();

        let mut frame = build_guest_udp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            6000,
            53,
            b"ABCD",
        );
        // Append 20 padding bytes
        frame.extend_from_slice(&[0u8; 20]);

        let result = proxy.process_outbound(&frame);
        assert!(result.is_empty());
        assert_eq!(
            proxy.connections.len(),
            1,
            "UDP v6 with padding should create connection"
        );
    }

    // =========================================================================
    // Fragmentation preservation
    // =========================================================================

    #[tokio::test]
    async fn test_fragmented_ipv4_udp_dropped() {
        let mut proxy = make_proxy();

        // Build IPv4+UDP frame with MF flag set
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + UDP_HEADER_LEN + 4;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + UDP_HEADER_LEN + 4).unwrap(),
            identification: 1,
            flags_fragment: 0x2000, // MF flag set
            ttl: 64,
            protocol: IP_PROTO_UDP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "fragmented IPv4 UDP should be dropped");
        assert!(proxy.connections.is_empty());
    }

    // =========================================================================
    // Channel backpressure for IPv6
    // =========================================================================

    #[tokio::test]
    async fn test_tcp_channel_backpressure_v6() {
        use std::net::TcpListener;
        let (mut proxy, _collector_rx) = make_proxy_with_rx();

        let listener = TcpListener::bind("[::1]:0").unwrap();
        let port = listener.local_addr().unwrap().port();

        // Create TCP v6 connection
        let syn = build_guest_tcp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            2048,
            port,
            TCP_SYN,
            5000,
            0,
        );
        proxy.process_outbound(&syn);
        assert_eq!(proxy.connections.len(), 1);

        let key = ConnectionKey {
            protocol: Protocol::Tcp,
            guest_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015)),
                2048,
            ),
            remote_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        };
        if let Some(ConnectionHandle::Tcp(handle)) = proxy.connections.get(&key) {
            let mut sent = 0;
            for _ in 0..GUEST_CHANNEL_CAPACITY + 100 {
                let frame = build_guest_tcp_frame_v6(
                    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
                    Ipv6Addr::LOCALHOST,
                    2048,
                    port,
                    crate::packet_builder::TCP_ACK,
                    5001 + u32::try_from(sent).unwrap(),
                    0,
                );
                match handle.guest_tx.try_send(GuestPacket::TcpFrame(frame)) {
                    Ok(()) => sent += 1,
                    Err(_) => break,
                }
            }
            assert_eq!(
                sent, GUEST_CHANNEL_CAPACITY,
                "v6 TCP channel should cap at {GUEST_CHANNEL_CAPACITY}"
            );
        } else {
            panic!("expected TCP v6 connection handle");
        }

        drop(listener);
    }

    #[tokio::test]
    async fn test_udp_channel_backpressure_v6() {
        let (mut proxy, _collector_rx) = make_proxy_with_rx();

        let frame = build_guest_udp_frame_v6(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            Ipv6Addr::LOCALHOST,
            6000,
            9999,
            b"init",
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        let key = ConnectionKey {
            protocol: Protocol::Udp,
            guest_addr: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015)),
                6000,
            ),
            remote_addr: SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 9999),
        };
        if let Some(ConnectionHandle::Udp(handle)) = proxy.connections.get(&key) {
            let mut sent = 0;
            for _ in 0..GUEST_CHANNEL_CAPACITY + 100 {
                match handle.guest_tx.try_send(vec![0xCD; 100]) {
                    Ok(()) => sent += 1,
                    Err(_) => break,
                }
            }
            assert_eq!(
                sent, GUEST_CHANNEL_CAPACITY,
                "v6 UDP channel should cap at {GUEST_CHANNEL_CAPACITY}"
            );
        } else {
            panic!("expected UDP v6 connection handle");
        }
    }

    // =========================================================================
    // Parse failure tests
    // =========================================================================

    #[tokio::test]
    async fn test_parse_failure_invalid_ipv4_version() {
        let mut proxy = make_proxy();

        // Build a frame with ETH_TYPE_IPV4 but version nibble = 3
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        // Write a valid-looking IPv4 header but with version = 3
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        // Override the version nibble to 3
        pkt[ETH_HEADER_LEN] = 0x35; // version=3, IHL=5

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "invalid IPv4 version should be dropped");
    }

    #[tokio::test]
    async fn test_parse_failure_invalid_ipv6_version() {
        let mut proxy = make_proxy();

        // Build a frame with ETH_TYPE_IPV6 but version nibble = 5
        let total_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv6Header {
            payload_len: u16::try_from(TCP_HEADER_LEN).unwrap(),
            next_header: IP_PROTO_TCP,
            hop_limit: 64,
            src_ip: Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015),
            dst_ip: Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);
        // Override the version nibble to 5 (byte 0 of IPv6 header: version is top 4 bits)
        pkt[ETH_HEADER_LEN] = (5 << 4) | (pkt[ETH_HEADER_LEN] & 0x0F);

        let result = proxy.process_outbound(&pkt);
        assert!(result.is_empty(), "invalid IPv6 version should be dropped");
    }

    #[tokio::test]
    async fn test_parse_failure_tcp_invalid_data_offset() {
        let mut proxy = make_proxy();

        // Build a valid IPv4 frame but with TCP data_offset = 3 (min is 5)
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;
        let mut pkt = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: GATEWAY_MAC,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut pkt[0..ETH_HEADER_LEN]);
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN).unwrap(),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip: Ipv4Addr::new(10, 0, 2, 15),
            dst_ip: Ipv4Addr::new(8, 8, 8, 8),
        }
        .write(&mut pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let cksum = calculate_ip_checksum(&pkt[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        pkt[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&cksum.to_be_bytes());

        // Write TCP header then corrupt data_offset
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        TcpHeader {
            src_port: 1024,
            dst_port: 80,
            seq_num: 1000,
            ack_num: 0,
            data_offset: 5,
            flags: TCP_SYN,
            window: 65535,
            checksum: 0,
            urgent_ptr: 0,
        }
        .write(&mut pkt[tcp_start..tcp_start + TCP_HEADER_LEN]);
        // Override data_offset to 3 (byte 12 of TCP: top 4 bits)
        pkt[tcp_start + 12] = (3 << 4) | (pkt[tcp_start + 12] & 0x0F);

        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "TCP with data_offset=3 should be dropped"
        );
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_parse_failure_tcp_data_offset_past_segment_end() {
        let mut proxy = make_proxy();
        let mut pkt = build_guest_tcp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            1024,
            80,
            TCP_SYN,
            1000,
            0,
        );
        let tcp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;
        pkt[tcp_start + 12] = 0x60;

        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "TCP with data_offset beyond segment should be dropped"
        );
        assert!(proxy.connections.is_empty());
    }

    #[tokio::test]
    async fn test_parse_failure_udp_length_outside_datagram() {
        let mut proxy = make_proxy();
        let mut pkt = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            1024,
            53,
            b"abcd",
        );
        let udp_start = ETH_HEADER_LEN + IPV4_HEADER_LEN;

        pkt[udp_start + 4..udp_start + 6].copy_from_slice(&7u16.to_be_bytes());
        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "UDP with length below header size should be dropped"
        );
        assert!(proxy.connections.is_empty());

        pkt[udp_start + 4..udp_start + 6].copy_from_slice(&13u16.to_be_bytes());
        let result = proxy.process_outbound(&pkt);
        assert!(
            result.is_empty(),
            "UDP with length beyond IP payload should be dropped"
        );
        assert!(proxy.connections.is_empty());
    }

    // =========================================================================
    // Cleanup lifecycle
    // =========================================================================

    #[tokio::test]
    async fn test_cleanup_finished_removes_completed_tasks() {
        let mut proxy = make_proxy();

        // Create a UDP connection to a non-listening port — task will fail quickly
        let frame = build_guest_udp_frame(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::LOCALHOST,
            7000,
            1, // port 1 — unlikely to have a listener
            b"data",
        );
        proxy.process_outbound(&frame);
        assert_eq!(proxy.connections.len(), 1);

        // Wait for the task to finish (UDP tasks finish on timeout or error)
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // If the task is finished, cleanup should remove it
        let any_finished = proxy
            .connections
            .values()
            .any(super::ConnectionHandle::is_finished);
        proxy.cleanup_finished();
        if any_finished {
            assert_eq!(
                proxy.connections.len(),
                0,
                "cleanup should remove finished tasks"
            );
        } else {
            // If not finished yet (e.g. slow CI), at least verify cleanup
            // doesn't remove running tasks.
            assert_eq!(
                proxy.connections.len(),
                1,
                "cleanup should not remove running tasks"
            );
        }
    }
}
