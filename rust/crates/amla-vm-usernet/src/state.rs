// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

use amla_core::backends::RxWaker;
use smoltcp::iface::Interface;
use smoltcp::iface::SocketSet;

use crate::MAX_RELIABLE_COLLECTOR_BACKLOG_BYTES;
use crate::config::{HostEgressPurpose, HostEgressRequest, Protocol, UserNetConfig};
use crate::device::VirtualDevice;
use crate::dns;
use crate::guest_output::{GuestOutput, GuestOutputClass};
use crate::guest_packet::{GuestIpPacketValidation, ValidatedGuestIpPacket};
use crate::icmp::{
    maybe_build_icmp_echo_reply, maybe_build_icmpv6_neighbor_advertisement, should_nat_proxy,
};
use crate::interceptor;
use crate::nat::NatProxy;
use crate::now;
use crate::packet_builder;

/// Internal state of the network stack
pub struct UserNetState<P = interceptor::DirectTcpPolicy, D = interceptor::NoDnsInterceptor>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    /// smoltcp interface (handles ARP, local traffic)
    pub(crate) iface: Interface,

    /// Socket set for connections
    pub(crate) sockets: SocketSet<'static>,

    /// Virtual device (queues packets between guest and smoltcp)
    pub(crate) device: VirtualDevice,

    /// NAT proxy (handles external TCP/UDP connections)
    pub(crate) nat_proxy: NatProxy<P>,

    /// Configuration
    pub(crate) config: UserNetConfig,

    /// RX waker callback -- signaled when packets are available for the guest.
    pub(crate) rx_waker: Option<RxWaker>,

    /// DNS interceptor for UDP port 53 MITM.
    pub(crate) dns_interceptor: D,

    /// Shared collector channel sender (cloned to NAT proxy tasks + DNS forwarder)
    pub(crate) collector_tx: mpsc::Sender<GuestOutput>,

    /// Shared collector channel receiver (drained by `poll_iface`)
    pub(crate) collector_rx: mpsc::Receiver<GuestOutput>,

    /// Reliable packets retained after the final guest TX queue fills.
    pub(crate) collector_backlog: VecDeque<GuestOutput>,

    /// Bytes currently retained in `collector_backlog`.
    pub(crate) collector_backlog_bytes: usize,

    /// Number of reliable collector packets retained due to final queue pressure.
    pub(crate) reliable_backlogged_count: u64,

    /// Number of best-effort collector packets intentionally dropped under pressure.
    pub(crate) best_effort_dropped_count: u64,

    /// Number of collector control packets intentionally dropped under pressure.
    pub(crate) control_dropped_count: u64,

    /// Number of reliable collector packets dropped because the bounded backlog was exceeded.
    pub(crate) reliable_backlog_overflow_count: u64,

    /// Limits concurrent DNS forward tasks to prevent a malicious guest
    /// from exhausting host sockets and memory via DNS query floods.
    pub(crate) dns_semaphore: Arc<tokio::sync::Semaphore>,
}

impl<P, D> UserNetState<P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    pub(crate) fn with_dns_interceptor<D2>(self, dns_interceptor: D2) -> UserNetState<P, D2>
    where
        D2: interceptor::DnsInterceptor,
    {
        UserNetState {
            iface: self.iface,
            sockets: self.sockets,
            device: self.device,
            nat_proxy: self.nat_proxy,
            config: self.config,
            rx_waker: self.rx_waker,
            dns_interceptor,
            collector_tx: self.collector_tx,
            collector_rx: self.collector_rx,
            collector_backlog: self.collector_backlog,
            collector_backlog_bytes: self.collector_backlog_bytes,
            reliable_backlogged_count: self.reliable_backlogged_count,
            best_effort_dropped_count: self.best_effort_dropped_count,
            control_dropped_count: self.control_dropped_count,
            reliable_backlog_overflow_count: self.reliable_backlog_overflow_count,
            dns_semaphore: self.dns_semaphore,
        }
    }

    /// Poll the network interface, DHCP server, DNS forwarder, and NAT proxy.
    ///
    /// # Panics
    ///
    /// Panics if called outside an active tokio runtime context, because new
    /// TCP/UDP/DNS connections use `tokio::spawn` internally.
    pub(crate) fn poll_iface(&mut self) {
        let timestamp = now();

        let rx_count = self.device.rx_queue.len();
        if rx_count > 0 {
            log::trace!("usernet: poll_iface: {rx_count} guest packets to process");
        }

        let mut local_packets = VecDeque::new();
        let mut builder = packet_builder::PacketBuilder::new(self.config.gateway_mac);

        while let Some(packet) = self.device.rx_queue.pop_front() {
            if self.handle_guest_packet(&packet, &mut builder) {
                continue;
            }
            local_packets.push_back(packet);
        }

        // Put local packets back for smoltcp
        self.device.rx_queue = local_packets;

        self.drain_collector_to_guest();

        // Clean up finished task handles
        self.nat_proxy.cleanup_finished();

        // Poll smoltcp for local traffic (ARP, etc.)
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
    }

    fn drain_collector_to_guest(&mut self) {
        if !self.flush_collector_backlog() {
            return;
        }

        while let Ok(output) = self.collector_rx.try_recv() {
            if !self.nat_proxy.output_is_current(&output) {
                log::trace!("usernet: dropping stale NAT output");
                continue;
            }

            if self.device.can_enqueue_to_guest() {
                let enqueued = self.device.enqueue_to_guest(output.into_packet());
                debug_assert!(enqueued);
                continue;
            }

            match output.class() {
                GuestOutputClass::Reliable => {
                    self.backlog_reliable_tcp(output);
                    return;
                }
                GuestOutputClass::BestEffort => {
                    self.best_effort_dropped_count += 1;
                    log::trace!("usernet: final tx_queue full, dropping best-effort datagram");
                }
                GuestOutputClass::Control => {
                    self.control_dropped_count += 1;
                    log::trace!("usernet: final tx_queue full, dropping control packet");
                }
            }
        }
    }

    fn flush_collector_backlog(&mut self) -> bool {
        while self.device.can_enqueue_to_guest() {
            let Some(output) = self.collector_backlog.pop_front() else {
                return true;
            };
            self.collector_backlog_bytes = self
                .collector_backlog_bytes
                .saturating_sub(output.packet_len());
            debug_assert!(output.is_reliable());
            if !self.nat_proxy.output_is_current(&output) {
                log::trace!("usernet: dropping stale backlogged NAT output");
                continue;
            }
            let enqueued = self.device.enqueue_to_guest(output.into_packet());
            debug_assert!(enqueued);
        }

        self.collector_backlog.is_empty()
    }

    fn backlog_reliable_tcp(&mut self, output: GuestOutput) {
        debug_assert!(output.is_reliable());
        let packet_len = output.packet_len();
        if self.collector_backlog_bytes.saturating_add(packet_len)
            <= MAX_RELIABLE_COLLECTOR_BACKLOG_BYTES
        {
            self.collector_backlog.push_back(output);
            self.collector_backlog_bytes += packet_len;
            self.reliable_backlogged_count += 1;
            log::trace!(
                "usernet: final tx_queue full, backlogged reliable TCP packet ({packet_len} bytes)"
            );
        } else {
            self.reliable_backlog_overflow_count += 1;
            log::error!(
                "usernet: reliable TCP collector backlog exceeded {MAX_RELIABLE_COLLECTOR_BACKLOG_BYTES} bytes; dropping packet"
            );
        }
    }

    /// Handle a single guest packet through the protocol stack.
    ///
    /// Returns `true` if the packet was handled (ICMP, DHCP, DNS, or NAT),
    /// `false` if it should be forwarded to smoltcp for local processing.
    fn handle_guest_packet(
        &mut self,
        packet: &[u8],
        builder: &mut packet_builder::PacketBuilder,
    ) -> bool {
        // 1. DHCP reply -- source IP is legitimately 0.0.0.0 before the
        // guest has accepted its lease, so DHCP is the only IP path before
        // configured guest identity validation.
        if let Some(reply) =
            crate::dhcp::maybe_build_dhcp_reply(packet, &self.config, self.config.gateway_mac)
        {
            self.device.enqueue_to_guest(reply);
            return true;
        }

        let packet = match ValidatedGuestIpPacket::validate(packet, &self.config) {
            GuestIpPacketValidation::Valid(packet) => packet,
            GuestIpPacketValidation::InvalidIdentity { src_mac, src_ip } => {
                log::warn!(
                    "usernet: dropping IP packet from unconfigured guest identity mac={src_mac:02x?} ip={src_ip}"
                );
                return true;
            }
            GuestIpPacketValidation::MalformedIp { ether_type } => {
                log::warn!("usernet: dropping malformed IP packet ethertype={ether_type:#06x}");
                return true;
            }
            GuestIpPacketValidation::NotIp => return false,
        };

        // 2. ICMPv6 Neighbor Advertisement
        if let Some(reply) = maybe_build_icmpv6_neighbor_advertisement(packet.frame(), &self.config)
        {
            self.device.enqueue_to_guest(reply);
            return true;
        }

        // 3. ICMP Echo Reply
        if let Some(reply) = maybe_build_icmp_echo_reply(packet.frame(), &self.config) {
            self.device.enqueue_to_guest(reply);
            return true;
        }

        // 4. DNS policy/MITM/gateway handling. Unsupported DNS shapes are
        // consumed fail-closed here so they cannot fall through to generic NAT.
        if self.handle_dns(&packet, builder) {
            return true;
        }

        // 5. NAT proxy (external connections)
        if should_nat_proxy(packet.frame(), &self.config) {
            let responses = self.nat_proxy.process_validated_outbound(&packet);
            for response in responses {
                self.device.enqueue_to_guest(response);
            }
            return true;
        }

        // Not handled -- caller will forward to smoltcp
        false
    }

    /// Handle DNS traffic. Returns `true` if the packet was consumed.
    fn handle_dns(
        &mut self,
        packet: &ValidatedGuestIpPacket<'_>,
        builder: &mut packet_builder::PacketBuilder,
    ) -> bool {
        let query = match dns::classify_validated_dns(packet) {
            dns::ValidatedDnsTraffic::Ipv4UdpQuery(query) => query,
            dns::ValidatedDnsTraffic::Drop(reason) => {
                log::warn!("usernet: dropping unsupported DNS traffic: {reason:?}");
                return true;
            }
            dns::ValidatedDnsTraffic::NotDns => return false,
        };

        let Some(query) = self.handle_dns_mitm(query, builder) else {
            return true;
        };

        self.handle_dns_gateway(&query);
        true
    }

    /// Handle DNS MITM interception. Returns the query if it should continue to
    /// gateway/NAT processing; returns `None` when the query was consumed.
    fn handle_dns_mitm<'a>(
        &mut self,
        query: dns::DnsQueryInfo<'a>,
        builder: &mut packet_builder::PacketBuilder,
    ) -> Option<dns::DnsQueryInfo<'a>> {
        let original_dest = SocketAddr::new(query.dst_ip, query.dst_port);
        let guest_addr = SocketAddr::new(query.src_ip, query.src_port);
        let response_limit =
            interceptor::DnsResponseLimit::new(dns::max_dns_response_len(self.config.mtu));
        match self.dns_interceptor.intercept(
            query.payload,
            original_dest,
            guest_addr,
            response_limit,
        ) {
            Ok(interceptor::DnsAction::Pass) => Some(query),
            Ok(interceptor::DnsAction::Drop) => None,
            Ok(interceptor::DnsAction::Respond(response)) => {
                let IpAddr::V4(src_v4) = query.dst_ip else {
                    return None;
                };
                let IpAddr::V4(dst_v4) = query.src_ip else {
                    return None;
                };
                let reply = builder.build_udp_packet(
                    query.src_mac,
                    src_v4,
                    dst_v4,
                    53,
                    query.src_port,
                    response.as_bytes(),
                );
                self.device.enqueue_to_guest(reply);
                None
            }
            Ok(interceptor::DnsAction::Forward(new_dest)) => {
                let egress_request = Self::dns_forward_request(new_dest);
                if !self.allows_dns_forward(egress_request) {
                    log::warn!(
                        "DNS forward denied by {:?} for interceptor destination {}",
                        self.config.dns_forward_policy,
                        new_dest,
                    );
                    return None;
                }
                let reply_src_ip = query.dst_ip;
                dns::spawn_dns_forward(
                    &query,
                    reply_src_ip,
                    self.config.host_egress_authorizer(),
                    egress_request,
                    self.collector_tx.clone(),
                    self.rx_waker.clone(),
                    self.config.gateway_mac,
                    Arc::clone(&self.dns_semaphore),
                    self.config.mtu,
                );
                None
            }
            Err(error) => {
                log::warn!("DNS interceptor rejected action: {error}");
                None
            }
        }
    }

    /// Handle DNS queries after MITM. All classified DNS is consumed here;
    /// only gateway/configured-DNS destinations can forward to the host
    /// resolver, and only when allowed by `DnsForwardPolicy`.
    fn handle_dns_gateway(&self, query: &dns::DnsQueryInfo<'_>) {
        if !dns::query_targets_gateway(query, &self.config) {
            log::warn!(
                "DNS direct egress denied for destination {}:{}",
                query.dst_ip,
                query.dst_port
            );
            return;
        }

        let host_dns = self.config.host_dns_server;
        let forward_to = SocketAddr::new(IpAddr::V4(host_dns), 53);
        let egress_request = Self::dns_forward_request(forward_to);
        if !self.allows_dns_forward(egress_request) {
            log::warn!(
                "DNS forward denied by {:?} for host resolver {}",
                self.config.dns_forward_policy,
                forward_to,
            );
            return;
        }
        // Reply from the IP the guest originally addressed (gateway or dns_server)
        let reply_src_ip = query.dst_ip;
        dns::spawn_dns_forward(
            query,
            reply_src_ip,
            self.config.host_egress_authorizer(),
            egress_request,
            self.collector_tx.clone(),
            self.rx_waker.clone(),
            self.config.gateway_mac,
            Arc::clone(&self.dns_semaphore),
            self.config.mtu,
        );
    }

    const fn dns_forward_request(forward_to: SocketAddr) -> HostEgressRequest {
        HostEgressRequest::new(Protocol::Udp, forward_to, HostEgressPurpose::DnsForward)
    }

    fn allows_dns_forward(&self, request: HostEgressRequest) -> bool {
        self.config.host_egress_authorizer().allows(request)
    }
}
