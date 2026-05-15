// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use super::{
    CONNECT_TIMEOUT_SECS, FIN_WAIT2_TIMEOUT_SECS, MAX_GUEST_BOUND_BUFFER, MAX_GUEST_BUFFER,
    TCP_SOCKET_BUFFER, TIME_WAIT_CLEANUP_SECS,
};
use crate::guest_output::{ConnectionOutputTag, GuestOutput};
use crate::interceptor::{
    BoxFuture, BoxHostStream, HostConnector, LocalSocket, TcpFlow, TrustedTcpInterceptor,
};
use crate::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, ETH_TYPE_IPV6, EthernetHeader, FlowEndpoints, IP_PROTO_ICMPV6,
    IPV6_HEADER_LEN, Ipv4Header, Ipv6Header, PacketBuilder, TCP_FIN, TCP_SYN, TcpHeader,
    checksum_fold,
};
use crate::{HostEgressAuthorizer, HostEgressRequest, MAX_QUEUE_SIZE, now};
use amla_core::backends::RxWaker;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet, SocketStorage};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::tcp::{RecvError, Socket, SocketBuffer, State as TcpSocketState};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv6Address, Ipv6Cidr};
use socket2::SockRef;
use std::collections::VecDeque;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

// =============================================================================
// Async Types
// =============================================================================

/// Per-flow smoltcp configuration copied from `NatProxy`.
#[derive(Clone, Copy)]
pub struct TcpStackConfig {
    /// Gateway MAC address used as the Ethernet source for guest-bound frames.
    pub gateway_mac: [u8; 6],
    /// Gateway IPv4 address.
    pub gateway_ip: Ipv4Addr,
    /// Gateway IPv6 address.
    pub gateway_ipv6: Ipv6Addr,
    /// IPv4 prefix length for the guest network.
    pub prefix_len: u8,
    /// IPv6 prefix length for the guest network.
    pub prefix_len_v6: u8,
    /// Virtual MTU.
    pub mtu: usize,
}

/// Messages from `NatProxy` to a running TCP connection task.
pub enum GuestPacket {
    /// Raw Ethernet TCP frame from the guest.
    TcpFrame(Vec<u8>),
    /// Shutdown request (eviction or `NatProxy` drop).
    Close,
}

/// Handle held by `NatProxy` to communicate with a running TCP task.
pub struct TcpConnectionHandle {
    pub guest_tx: mpsc::Sender<GuestPacket>,
    pub task: JoinHandle<()>,
    pub created_at: Instant,
}

/// Transport execution plan selected for a new guest TCP flow.
pub enum TcpConnectionMode {
    /// Connect directly to the requested host address.
    Direct {
        /// Authorizer used immediately before host socket connect/write.
        host_egress: HostEgressAuthorizer,
        /// Typed host egress request for the remote TCP socket.
        request: HostEgressRequest,
    },
    /// Serve the guest locally with no host socket.
    LocalService(Box<dyn crate::interceptor::LocalServiceHandler>),
    /// Give a trusted interceptor the owned guest stream and a lazy connector.
    TrustedInterceptor {
        /// Trusted code that owns the guest stream.
        interceptor: Box<dyn TrustedTcpInterceptor>,
        /// Whether this flow is allowed to open the deferred host connector.
        host_connect: HostConnectAccess,
    },
}

/// Capability state for the deferred host connector handed to interceptors.
pub enum HostConnectAccess {
    /// The connector may open the requested host socket if the authorizer allows it.
    Authorized {
        /// Authorizer used immediately before opening the host socket.
        host_egress: HostEgressAuthorizer,
        /// Typed host egress request for the remote TCP socket.
        request: HostEgressRequest,
    },
    /// The connector exists but fails closed if used.
    Denied {
        /// Remote address included in the permission error.
        remote_addr: SocketAddr,
    },
}

impl HostConnectAccess {
    fn authorize(self) -> io::Result<(crate::AuthorizedHostEgress, HostEgressAuthorizer)> {
        match self {
            Self::Authorized {
                host_egress,
                request,
            } => {
                let authorized = host_egress.authorize(request).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "host egress to {} is denied by network policy",
                            request.socket_addr
                        ),
                    )
                })?;
                Ok((authorized, host_egress))
            }
            Self::Denied { remote_addr } => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("host egress to {remote_addr} is denied by network policy"),
            )),
        }
    }
}

// =============================================================================
// Per-flow smoltcp Device
// =============================================================================

struct StackDevice {
    rx_queue: VecDeque<Vec<u8>>,
    tx_queue: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl StackDevice {
    const fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::new(),
            tx_queue: VecDeque::new(),
            mtu,
        }
    }

    fn queue_from_guest(&mut self, packet: Vec<u8>) -> bool {
        if self.rx_queue.len() < MAX_QUEUE_SIZE {
            self.rx_queue.push_back(packet);
            true
        } else {
            log::warn!("usernet tcp stack: refusing guest frame, per-flow rx queue full");
            false
        }
    }
}

struct StackRxToken {
    buffer: Vec<u8>,
}

impl RxToken for StackRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

struct StackTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
}

impl TxToken for StackTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        debug_assert!(self.queue.len() < MAX_QUEUE_SIZE);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for StackDevice {
    type RxToken<'a> = StackRxToken;
    type TxToken<'a> = StackTxToken<'a>;

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if self.tx_queue.len() >= MAX_QUEUE_SIZE {
            return None;
        }
        let buffer = self.rx_queue.pop_front()?;
        Some((
            StackRxToken { buffer },
            StackTxToken {
                queue: &mut self.tx_queue,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() >= MAX_QUEUE_SIZE {
            return None;
        }
        Some(StackTxToken {
            queue: &mut self.tx_queue,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps
    }
}

// =============================================================================
// Guest TCP Stack
// =============================================================================

struct GuestTcpStack {
    config: TcpStackConfig,
    iface: Interface,
    sockets: SocketSet<'static>,
    socket: SocketHandle,
    socket_ready: bool,
    device: StackDevice,
    collector_tx: mpsc::Sender<GuestOutput>,
    output_tag: ConnectionOutputTag,
    collector_closed: bool,
    rx_waker: Option<RxWaker>,
    host_read: HostReadState,
    guest_close: GuestCloseState,
    fin_wait2_since: Option<Instant>,
    time_wait_since: Option<Instant>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum HostReadState {
    Open,
    Eof,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum GuestCloseState {
    Open,
    FinPending,
    FinSeen,
    ResetPending,
    ResetSeen,
}

#[derive(Clone, Copy)]
pub struct InboundTarget {
    guest_mac: [u8; 6],
    guest_ip: IpAddr,
    guest_port: u16,
    gateway_ip: IpAddr,
    ephemeral_port: u16,
}

impl InboundTarget {
    /// Create an inbound TCP target for a host-initiated connection to the guest.
    pub(crate) const fn new(
        guest_mac: [u8; 6],
        guest_ip: IpAddr,
        guest_port: u16,
        gateway_ip: IpAddr,
        ephemeral_port: u16,
    ) -> Self {
        Self {
            guest_mac,
            guest_ip,
            guest_port,
            gateway_ip,
            ephemeral_port,
        }
    }
}

impl GuestTcpStack {
    fn new_server(
        config: TcpStackConfig,
        remote_addr: SocketAddr,
        collector_tx: mpsc::Sender<GuestOutput>,
        rx_waker: Option<RxWaker>,
        output_tag: ConnectionOutputTag,
    ) -> Result<Self, String> {
        let mut stack = Self::new_base(config, collector_tx, rx_waker, output_tag);
        let mut socket = tcp_socket();
        socket
            .listen(remote_addr.port())
            .map_err(|e| format!("listen {remote_addr}: {e}"))?;
        stack.socket = stack.sockets.add(socket);
        stack.socket_ready = true;
        Ok(stack)
    }

    fn new_client(
        config: TcpStackConfig,
        target: InboundTarget,
        collector_tx: mpsc::Sender<GuestOutput>,
        rx_waker: Option<RxWaker>,
        output_tag: ConnectionOutputTag,
    ) -> Result<Self, String> {
        let mut stack = Self::new_base(config, collector_tx, rx_waker, output_tag);
        if let (IpAddr::V4(guest_v4), IpAddr::V4(gateway_v4)) = (target.guest_ip, target.gateway_ip)
        {
            _ = stack.device.queue_from_guest(build_arp_reply(
                config.gateway_mac,
                target.guest_mac,
                guest_v4,
                gateway_v4,
            ));
            stack.poll();
        } else if let (IpAddr::V6(guest_v6), IpAddr::V6(gateway_v6)) =
            (target.guest_ip, target.gateway_ip)
        {
            _ = stack.device.queue_from_guest(build_ndp_neighbor_advert(
                config.gateway_mac,
                target.guest_mac,
                guest_v6,
                gateway_v6,
            ));
            stack.poll();
        }

        let mut socket = tcp_socket();
        let remote = SocketAddr::new(target.guest_ip, target.guest_port);
        let local = SocketAddr::new(target.gateway_ip, target.ephemeral_port);
        socket
            .connect(stack.iface.context(), remote, local)
            .map_err(|e| format!("connect guest {remote} from {local}: {e}"))?;
        stack.socket = stack.sockets.add(socket);
        stack.socket_ready = true;
        stack.poll();
        Ok(stack)
    }

    fn new_base(
        config: TcpStackConfig,
        collector_tx: mpsc::Sender<GuestOutput>,
        rx_waker: Option<RxWaker>,
        output_tag: ConnectionOutputTag,
    ) -> Self {
        let mut device = StackDevice::new(config.mtu);
        let iface_config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(
            config.gateway_mac,
        )));
        let mut iface = Interface::new(iface_config, &mut device, now());
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(config.gateway_ip),
                    config.prefix_len,
                ))
                .ok();
            addrs
                .push(IpCidr::Ipv6(Ipv6Cidr::new(
                    Ipv6Address::from_octets(config.gateway_ipv6.octets()),
                    config.prefix_len_v6,
                )))
                .ok();
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(config.gateway_ip)
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::from_octets(config.gateway_ipv6.octets()))
            .ok();
        iface.set_any_ip(true);

        let socket_storage: Vec<SocketStorage<'static>> =
            (0..1).map(|_| SocketStorage::EMPTY).collect();
        Self {
            config,
            iface,
            sockets: SocketSet::new(socket_storage),
            socket: SocketHandle::default(),
            socket_ready: false,
            device,
            collector_tx,
            output_tag,
            collector_closed: false,
            rx_waker,
            host_read: HostReadState::Open,
            guest_close: GuestCloseState::Open,
            fin_wait2_since: None,
            time_wait_since: None,
        }
    }

    fn ingest_guest_frame(&mut self, frame: Vec<u8>) {
        let before = self.state();
        self.seed_guest_neighbor(&frame);
        if !self.device.queue_from_guest(frame) {
            self.abort();
            return;
        }
        self.poll();
        self.observe_guest_close(before);
    }

    fn seed_guest_neighbor(&mut self, frame: &[u8]) {
        if !self.rx_queue_has_room(2) {
            return;
        }

        let Some(eth) = EthernetHeader::parse(frame) else {
            return;
        };
        match eth.ether_type {
            ETH_TYPE_IPV4 => {
                let Some(ip) = Ipv4Header::parse(frame.get(ETH_HEADER_LEN..).unwrap_or_default())
                else {
                    return;
                };
                _ = self.device.queue_from_guest(build_arp_reply(
                    self.config.gateway_mac,
                    eth.src_mac,
                    ip.src_ip,
                    self.config.gateway_ip,
                ));
                self.poll();
            }
            ETH_TYPE_IPV6 => {
                let Some(ip) = Ipv6Header::parse(frame.get(ETH_HEADER_LEN..).unwrap_or_default())
                else {
                    return;
                };
                _ = self.device.queue_from_guest(build_ndp_neighbor_advert(
                    self.config.gateway_mac,
                    eth.src_mac,
                    ip.src_ip,
                    self.config.gateway_ipv6,
                ));
                self.poll();
            }
            _ => {}
        }
    }

    fn state(&self) -> TcpSocketState {
        self.sockets.get::<Socket>(self.socket).state()
    }

    fn socket(&self) -> &Socket<'static> {
        self.sockets.get::<Socket>(self.socket)
    }

    fn socket_mut(&mut self) -> &mut Socket<'static> {
        self.sockets.get_mut::<Socket>(self.socket)
    }

    fn observe_guest_close(&mut self, before: TcpSocketState) {
        let after = self.state();
        if self.guest_close == GuestCloseState::Open && matches!(after, TcpSocketState::CloseWait) {
            self.guest_close = GuestCloseState::FinPending;
        }
        if !matches!(before, TcpSocketState::Closed | TcpSocketState::TimeWait)
            && after == TcpSocketState::Closed
            && self.guest_close == GuestCloseState::Open
        {
            self.guest_close = GuestCloseState::ResetPending;
        }
    }

    fn take_guest_fin(&mut self) -> bool {
        if self.guest_close == GuestCloseState::FinPending {
            self.guest_close = GuestCloseState::FinSeen;
            true
        } else {
            false
        }
    }

    fn take_guest_reset(&mut self) -> bool {
        if self.guest_close == GuestCloseState::ResetPending {
            self.guest_close = GuestCloseState::ResetSeen;
            true
        } else {
            false
        }
    }

    fn poll(&mut self) {
        self.close_if_host_eof();
        let timestamp = now();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        self.flush_output();
        self.close_if_host_eof();
        let timestamp = now();
        self.iface
            .poll(timestamp, &mut self.device, &mut self.sockets);
        self.flush_output();
        self.refresh_lifecycle_timers();
    }

    fn refresh_lifecycle_timers(&mut self) {
        if !self.socket_ready {
            return;
        }
        let state = self.state();
        let now = Instant::now();
        if state == TcpSocketState::FinWait2 {
            self.fin_wait2_since.get_or_insert(now);
        } else {
            self.fin_wait2_since = None;
        }
        if state == TcpSocketState::TimeWait {
            self.time_wait_since.get_or_insert(now);
        } else {
            self.time_wait_since = None;
        }
    }

    fn flush_output(&mut self) {
        while let Some(pkt) = self.device.tx_queue.pop_front() {
            match self
                .collector_tx
                .try_send(GuestOutput::tagged_reliable_tcp(self.output_tag, pkt))
            {
                Ok(()) => {
                    if let Some(waker) = self.rx_waker.as_ref() {
                        waker.wake();
                    }
                }
                Err(mpsc::error::TrySendError::Full(output)) => {
                    self.device.tx_queue.push_front(output.into_packet());
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    self.collector_closed = true;
                    return;
                }
            }
        }
    }

    fn has_pending_output(&self) -> bool {
        !self.collector_closed && !self.device.tx_queue.is_empty()
    }

    fn rx_queue_has_room(&self, slots: usize) -> bool {
        self.device.rx_queue.len().saturating_add(slots) <= MAX_QUEUE_SIZE
    }

    fn can_accept_guest_frame(&self) -> bool {
        // Neighbor seeding may enqueue one synthetic ARP/NDP frame before the
        // actual guest TCP frame. Keep room for both.
        self.rx_queue_has_room(2)
    }

    fn flush_one_output(&mut self, permit: mpsc::OwnedPermit<GuestOutput>) {
        let Some(pkt) = self.device.tx_queue.pop_front() else {
            return;
        };
        permit.send(GuestOutput::tagged_reliable_tcp(self.output_tag, pkt));
        if let Some(waker) = self.rx_waker.as_ref() {
            waker.wake();
        }
    }

    fn next_poll_delay(&mut self) -> Duration {
        let millis = self
            .iface
            .poll_delay(now(), &self.sockets)
            .map_or(1000, |delay| delay.total_millis().clamp(1, 1000));
        Duration::from_millis(millis)
    }

    fn guest_send_space(&self) -> usize {
        if !self.socket().may_send() {
            return 0;
        }
        self.socket()
            .send_capacity()
            .saturating_sub(self.socket().send_queue())
    }

    fn send_to_guest_socket(&mut self, data: &[u8]) -> Option<usize> {
        let len = data.len().min(self.guest_send_space());
        if len == 0 {
            return Some(0);
        }
        match self.socket_mut().send_slice(&data[..len]) {
            Ok(n) => {
                if n > 0 {
                    self.poll();
                }
                Some(n)
            }
            Err(e) => {
                log::warn!("usernet tcp stack: failed to queue guest-bound bytes: {e}");
                self.abort();
                None
            }
        }
    }

    #[cfg(test)]
    fn send_to_guest(&mut self, data: &[u8]) -> bool {
        matches!(self.send_to_guest_socket(data), Some(n) if n == data.len())
    }

    fn push_guest_bound_data(&mut self, pending: &mut VecDeque<u8>, data: &[u8]) -> bool {
        if pending.len().saturating_add(data.len()) > MAX_GUEST_BOUND_BUFFER {
            log::warn!(
                "usernet tcp stack: guest-bound buffer exceeded {MAX_GUEST_BOUND_BUFFER} bytes; aborting stream"
            );
            self.abort();
            return false;
        }
        pending.extend(data);
        self.flush_guest_bound_pending(pending)
    }

    fn flush_guest_bound_pending(&mut self, pending: &mut VecDeque<u8>) -> bool {
        while !pending.is_empty() {
            let len = pending.len().min(self.guest_send_space());
            if len == 0 {
                break;
            }
            let data: Vec<u8> = pending.iter().take(len).copied().collect();
            let Some(n) = self.send_to_guest_socket(&data) else {
                return false;
            };
            if n == 0 {
                break;
            }
            pending.drain(..n);
        }
        true
    }

    fn drain_guest_data(&mut self, limit: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 16 * 1024];
        while out.len() < limit && self.socket().can_recv() {
            let room = (limit - out.len()).min(buf.len());
            match self.socket_mut().recv_slice(&mut buf[..room]) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(RecvError::Finished) => {
                    if self.guest_close == GuestCloseState::Open {
                        self.guest_close = GuestCloseState::FinPending;
                    }
                    break;
                }
                Err(e) => {
                    log::trace!("usernet tcp stack: recv_slice blocked: {e}");
                    break;
                }
            }
        }
        out
    }

    fn mark_host_eof(&mut self) {
        self.host_read = HostReadState::Eof;
        self.close_if_host_eof();
        self.poll();
    }

    fn close_if_host_eof(&mut self) {
        if self.host_read == HostReadState::Eof && self.socket().may_send() {
            self.socket_mut().close();
        }
    }

    fn abort(&mut self) {
        self.socket_mut().abort();
        self.poll();
    }

    fn wants_backend_read(&self) -> bool {
        self.guest_send_space() > 0
            && self.host_read == HostReadState::Open
            && matches!(
                self.state(),
                TcpSocketState::Established
                    | TcpSocketState::FinWait1
                    | TcpSocketState::FinWait2
                    | TcpSocketState::CloseWait
                    | TcpSocketState::Closing
                    | TcpSocketState::LastAck
            )
    }

    fn should_cleanup(&self) -> bool {
        let pending_empty = self.device.tx_queue.is_empty();
        match self.state() {
            TcpSocketState::Closed => pending_empty,
            TcpSocketState::TimeWait => {
                pending_empty
                    && self.time_wait_since.is_some_and(|since| {
                        since.elapsed() >= Duration::from_secs(TIME_WAIT_CLEANUP_SECS)
                    })
            }
            TcpSocketState::FinWait2 => {
                pending_empty
                    && self.fin_wait2_since.is_some_and(|since| {
                        since.elapsed() >= Duration::from_secs(FIN_WAIT2_TIMEOUT_SECS)
                    })
            }
            _ => false,
        }
    }
}

fn tcp_socket() -> Socket<'static> {
    Socket::new(
        SocketBuffer::new(vec![0; TCP_SOCKET_BUFFER]),
        SocketBuffer::new(vec![0; TCP_SOCKET_BUFFER]),
    )
}

fn build_arp_reply(
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    guest_ip: Ipv4Addr,
    gateway_ip: Ipv4Addr,
) -> Vec<u8> {
    let mut frame = vec![0u8; 42];
    frame[0..6].copy_from_slice(&gateway_mac);
    frame[6..12].copy_from_slice(&guest_mac);
    frame[12..14].copy_from_slice(&0x0806u16.to_be_bytes());
    frame[14..16].copy_from_slice(&1u16.to_be_bytes());
    frame[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    frame[18] = 6;
    frame[19] = 4;
    frame[20..22].copy_from_slice(&2u16.to_be_bytes());
    frame[22..28].copy_from_slice(&guest_mac);
    frame[28..32].copy_from_slice(&guest_ip.octets());
    frame[32..38].copy_from_slice(&gateway_mac);
    frame[38..42].copy_from_slice(&gateway_ip.octets());
    frame
}

fn build_ndp_neighbor_advert(
    gateway_mac: [u8; 6],
    guest_mac: [u8; 6],
    guest_ip: Ipv6Addr,
    gateway_ip: Ipv6Addr,
) -> Vec<u8> {
    const ICMPV6_NA_LEN: usize = 32;
    let mut frame = vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + ICMPV6_NA_LEN];
    EthernetHeader {
        dst_mac: gateway_mac,
        src_mac: guest_mac,
        ether_type: ETH_TYPE_IPV6,
    }
    .write(&mut frame[..ETH_HEADER_LEN]);
    Ipv6Header {
        payload_len: u16::try_from(ICMPV6_NA_LEN).unwrap_or(u16::MAX),
        next_header: IP_PROTO_ICMPV6,
        hop_limit: 255,
        src_ip: guest_ip,
        dst_ip: gateway_ip,
    }
    .write(&mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

    let icmp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
    frame[icmp_offset] = 136; // Neighbor Advertisement
    frame[icmp_offset + 1] = 0;
    let flags: u32 = 0x6000_0000; // Solicited + Override
    frame[icmp_offset + 4..icmp_offset + 8].copy_from_slice(&flags.to_be_bytes());
    frame[icmp_offset + 8..icmp_offset + 24].copy_from_slice(&guest_ip.octets());
    frame[icmp_offset + 24] = 2; // Target Link-Layer Address option
    frame[icmp_offset + 25] = 1; // length (8 bytes)
    frame[icmp_offset + 26..icmp_offset + 32].copy_from_slice(&guest_mac);

    let checksum = checksum_icmpv6(
        guest_ip,
        gateway_ip,
        &frame[icmp_offset..icmp_offset + ICMPV6_NA_LEN],
    );
    frame[icmp_offset + 2..icmp_offset + 4].copy_from_slice(&checksum.to_be_bytes());
    frame
}

fn checksum_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in src.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    for chunk in dst.octets().chunks_exact(2) {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    let len = u32::try_from(icmp.len()).unwrap_or(u32::MAX);
    sum = sum.wrapping_add(len >> 16);
    sum = sum.wrapping_add(len & 0xFFFF);
    sum = sum.wrapping_add(u32::from(IP_PROTO_ICMPV6));
    let mut chunks = icmp.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let Some(&last) = chunks.remainder().first() {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    checksum_fold(sum)
}

// =============================================================================
// Async Task Functions
// =============================================================================

/// Run a complete outbound TCP connection lifecycle as an async task.
#[allow(clippy::too_many_arguments)]
pub async fn tcp_connection_task(
    flow: TcpFlow,
    initial_frame: Vec<u8>,
    stack_config: TcpStackConfig,
    mut guest_rx: mpsc::Receiver<GuestPacket>,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    mode: TcpConnectionMode,
    output_tag: ConnectionOutputTag,
) {
    match mode {
        TcpConnectionMode::LocalService(handler) => {
            match GuestTcpStack::new_server(
                stack_config,
                flow.remote_addr,
                collector_tx,
                rx_waker,
                output_tag,
            ) {
                Ok(mut stack) => {
                    stack.ingest_guest_frame(initial_frame);
                    run_local_socket(handler, &mut stack, &mut guest_rx).await;
                    stack.poll();
                }
                Err(e) => log::warn!("TCP: failed to create local-service stack: {e}"),
            }
        }
        TcpConnectionMode::TrustedInterceptor {
            interceptor,
            host_connect,
        } => {
            run_trusted_interceptor(
                interceptor,
                host_connect,
                flow,
                initial_frame,
                stack_config,
                guest_rx,
                collector_tx,
                rx_waker,
                output_tag,
            )
            .await;
        }
        TcpConnectionMode::Direct {
            host_egress,
            request,
        } => {
            run_direct(
                host_egress,
                request,
                initial_frame,
                stack_config,
                guest_rx,
                collector_tx,
                rx_waker,
                output_tag,
            )
            .await;
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_direct(
    host_egress: HostEgressAuthorizer,
    request: HostEgressRequest,
    initial_frame: Vec<u8>,
    stack_config: TcpStackConfig,
    guest_rx: mpsc::Receiver<GuestPacket>,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    output_tag: ConnectionOutputTag,
) {
    run_host_connected(
        host_egress,
        request,
        initial_frame,
        stack_config,
        guest_rx,
        collector_tx,
        rx_waker,
        output_tag,
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn run_trusted_interceptor(
    interceptor: Box<dyn TrustedTcpInterceptor>,
    host_connect: HostConnectAccess,
    flow: TcpFlow,
    initial_frame: Vec<u8>,
    stack_config: TcpStackConfig,
    mut guest_rx: mpsc::Receiver<GuestPacket>,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    output_tag: ConnectionOutputTag,
) {
    let mut stack = match GuestTcpStack::new_server(
        stack_config,
        flow.remote_addr,
        collector_tx,
        rx_waker,
        output_tag,
    ) {
        Ok(stack) => stack,
        Err(e) => {
            log::warn!("TCP: failed to create trusted-interceptor stack: {e}");
            return;
        }
    };
    stack.ingest_guest_frame(initial_frame);

    let connector = host_connector(host_connect);
    run_owned_guest_stream(&mut stack, &mut guest_rx, move |socket| {
        interceptor.run(socket, flow, connector)
    })
    .await;
    stack.poll();
}

struct AuthorizedTcpStream {
    stream: tokio::net::TcpStream,
    host_egress: HostEgressAuthorizer,
    request: HostEgressRequest,
}

impl AuthorizedTcpStream {
    const fn new(
        stream: tokio::net::TcpStream,
        host_egress: HostEgressAuthorizer,
        request: HostEgressRequest,
    ) -> Self {
        Self {
            stream,
            host_egress,
            request,
        }
    }

    fn authorize_write(&self) -> io::Result<()> {
        self.host_egress.authorize(self.request).map_or_else(
            || {
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!(
                        "host egress to {} is denied by network policy",
                        self.request.socket_addr
                    ),
                ))
            },
            |_| Ok(()),
        )
    }
}

impl AsyncRead for AuthorizedTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for AuthorizedTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Err(err) = self.authorize_write() {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(err) = self.authorize_write() {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Err(err) = self.authorize_write() {
            return Poll::Ready(Err(err));
        }
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

fn host_connector(access: HostConnectAccess) -> HostConnector {
    HostConnector::new(move || async move {
        let (authorized, host_egress) = access.authorize()?;
        let remote_addr = authorized.socket_addr();
        let request = authorized.request();
        match tokio::time::timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            tokio::net::TcpStream::connect(remote_addr),
        )
        .await
        {
            Ok(Ok(stream)) => Ok(
                Box::new(AuthorizedTcpStream::new(stream, host_egress, request)) as BoxHostStream,
            ),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("connect to {remote_addr} timed out"),
            )),
        }
    })
}

#[allow(clippy::too_many_arguments)]
async fn run_host_connected(
    host_egress: HostEgressAuthorizer,
    request: HostEgressRequest,
    initial_frame: Vec<u8>,
    stack_config: TcpStackConfig,
    guest_rx: mpsc::Receiver<GuestPacket>,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    output_tag: ConnectionOutputTag,
) {
    let Some(authorized) = host_egress.authorize(request) else {
        log::trace!(
            "TCP: host egress to {} denied by network policy",
            request.socket_addr
        );
        send_rst_for_initial_frame(
            &initial_frame,
            stack_config.gateway_mac,
            &collector_tx,
            rx_waker.as_ref(),
            output_tag,
        )
        .await;
        return;
    };
    let remote_addr = authorized.socket_addr();
    let connect_result = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        tokio::net::TcpStream::connect(remote_addr),
    )
    .await;

    match connect_result {
        Ok(Ok(stream)) => {
            let mut stack = match GuestTcpStack::new_server(
                stack_config,
                remote_addr,
                collector_tx,
                rx_waker,
                output_tag,
            ) {
                Ok(stack) => stack,
                Err(e) => {
                    log::warn!("TCP: failed to create guest stack: {e}");
                    return;
                }
            };
            stack.ingest_guest_frame(initial_frame);
            run_connected(stream, &mut stack, guest_rx, host_egress, request).await;
        }
        Ok(Err(e)) => {
            log::trace!("TCP: Connect to {remote_addr} failed: {e}");
            send_rst_for_initial_frame(
                &initial_frame,
                stack_config.gateway_mac,
                &collector_tx,
                rx_waker.as_ref(),
                output_tag,
            )
            .await;
        }
        Err(_) => {
            log::trace!("TCP: Connect to {remote_addr} timed out");
            send_rst_for_initial_frame(
                &initial_frame,
                stack_config.gateway_mac,
                &collector_tx,
                rx_waker.as_ref(),
                output_tag,
            )
            .await;
        }
    }
}

async fn send_rst_for_initial_frame(
    frame: &[u8],
    gateway_mac: [u8; 6],
    collector_tx: &mpsc::Sender<GuestOutput>,
    rx_waker: Option<&RxWaker>,
    output_tag: ConnectionOutputTag,
) {
    let Some(rst) = build_rst_for_frame(frame, gateway_mac) else {
        return;
    };
    match collector_tx.try_send(GuestOutput::tagged_control(output_tag, rst)) {
        Ok(()) => {
            if let Some(waker) = rx_waker {
                waker.wake();
            }
        }
        Err(mpsc::error::TrySendError::Full(_)) => {
            log::trace!("TCP: collector channel full, dropping RST");
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {}
    }
}

fn build_rst_for_frame(frame: &[u8], gateway_mac: [u8; 6]) -> Option<Vec<u8>> {
    let eth = EthernetHeader::parse(frame)?;
    let mut builder = PacketBuilder::new(gateway_mac);
    match eth.ether_type {
        ETH_TYPE_IPV4 => {
            let ip_start = ETH_HEADER_LEN;
            let ip = Ipv4Header::parse(frame.get(ip_start..)?)?;
            let transport_start = ip_start + ip.header_len();
            let transport_len = (ip.total_length as usize).saturating_sub(ip.header_len());
            let transport_end = (transport_start + transport_len).min(frame.len());
            let data = frame.get(transport_start..transport_end)?;
            let tcp = TcpHeader::parse(data)?;
            let payload_len = data.len().saturating_sub(tcp.header_len());
            let flow = FlowEndpoints::v4(
                eth.src_mac,
                ip.dst_ip,
                ip.src_ip,
                tcp.dst_port,
                tcp.src_port,
            );
            build_rst_for_segment(&mut builder, &flow, &tcp, payload_len)
        }
        ETH_TYPE_IPV6 => {
            let ip_start = ETH_HEADER_LEN;
            let ip = Ipv6Header::parse(frame.get(ip_start..)?)?;
            let transport_start = ip_start + IPV6_HEADER_LEN;
            let transport_len = ip.payload_len as usize;
            let transport_end = (transport_start + transport_len).min(frame.len());
            let data = frame.get(transport_start..transport_end)?;
            let tcp = TcpHeader::parse(data)?;
            let payload_len = data.len().saturating_sub(tcp.header_len());
            let flow = FlowEndpoints::v6(
                eth.src_mac,
                ip.dst_ip,
                ip.src_ip,
                tcp.dst_port,
                tcp.src_port,
            );
            build_rst_for_segment(&mut builder, &flow, &tcp, payload_len)
        }
        _ => None,
    }
}

fn build_rst_for_segment(
    builder: &mut PacketBuilder,
    flow: &FlowEndpoints,
    tcp: &TcpHeader,
    payload_len: usize,
) -> Option<Vec<u8>> {
    if tcp.is_rst() {
        return None;
    }
    if tcp.is_ack() {
        Some(builder.build_tcp_rst_only_ip(flow, tcp.ack_num))
    } else {
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

async fn reserve_permit<T>(sender: Option<mpsc::Sender<T>>) -> Option<mpsc::OwnedPermit<T>> {
    sender?.reserve_owned().await.ok()
}

/// Run the local-socket phase: service handler gets a `LocalSocket`, smoltcp
/// handles guest-facing TCP, channels bridge the two.
async fn run_local_socket(
    handler: Box<dyn crate::interceptor::LocalServiceHandler>,
    stack: &mut GuestTcpStack,
    guest_rx: &mut mpsc::Receiver<GuestPacket>,
) {
    run_owned_guest_stream(stack, guest_rx, move |socket| handler.handle(socket)).await;
}

#[allow(clippy::too_many_lines)]
async fn run_owned_guest_stream<F>(
    stack: &mut GuestTcpStack,
    guest_rx: &mut mpsc::Receiver<GuestPacket>,
    start: F,
) where
    F: FnOnce(LocalSocket) -> BoxFuture<'static, ()>,
{
    let (guest_to_service_tx, guest_to_service_rx) = mpsc::channel::<Vec<u8>>(64);
    let (service_to_guest_tx, mut service_to_guest_rx) = mpsc::channel::<Vec<u8>>(64);

    let socket = LocalSocket::new(guest_to_service_rx, service_to_guest_tx);
    let stream_fut = start(socket);
    tokio::pin!(stream_fut);

    let mut guest_to_service_tx = Some(guest_to_service_tx);
    let mut guest_to_service_pending = VecDeque::<Vec<u8>>::new();
    let mut guest_to_service_pending_bytes = 0usize;
    let mut service_to_guest_pending = VecDeque::<u8>::new();
    let mut service_to_guest_closed = false;
    let mut guest_fin_pending = false;
    let mut handler_done = false;

    loop {
        stack.poll();
        if stack.collector_closed {
            return;
        }
        if !stack.flush_guest_bound_pending(&mut service_to_guest_pending) {
            return;
        }
        if handler_done && service_to_guest_rx.is_closed() && service_to_guest_rx.is_empty() {
            service_to_guest_closed = true;
        }
        if service_to_guest_closed
            && service_to_guest_pending.is_empty()
            && stack.host_read == HostReadState::Open
        {
            stack.mark_host_eof();
        }

        let room = MAX_GUEST_BUFFER.saturating_sub(guest_to_service_pending_bytes);
        if room > 0 {
            let data = stack.drain_guest_data(room);
            if !data.is_empty() {
                guest_to_service_pending_bytes =
                    guest_to_service_pending_bytes.saturating_add(data.len());
                guest_to_service_pending.push_back(data);
            }
        }
        if stack.take_guest_fin() {
            guest_fin_pending = true;
        }
        if guest_fin_pending && guest_to_service_pending.is_empty() {
            guest_to_service_tx.take();
        }
        if stack.take_guest_reset() {
            guest_to_service_tx.take();
            return;
        }
        if service_to_guest_pending.is_empty()
            && guest_to_service_pending.is_empty()
            && stack.should_cleanup()
        {
            return;
        }

        let output_sender = stack
            .has_pending_output()
            .then(|| stack.collector_tx.clone());
        let guest_to_service_sender = (!guest_to_service_pending.is_empty())
            .then(|| guest_to_service_tx.clone())
            .flatten();
        let delay = if guest_to_service_pending.is_empty()
            && service_to_guest_pending.is_empty()
            && !stack.has_pending_output()
        {
            stack.next_poll_delay()
        } else {
            stack.next_poll_delay().min(Duration::from_millis(10))
        };
        tokio::select! {
            biased;

            permit = reserve_permit(output_sender), if stack.has_pending_output() => {
                match permit {
                    Some(permit) => stack.flush_one_output(permit),
                    None => return,
                }
            }

            permit = reserve_permit(guest_to_service_sender), if !guest_to_service_pending.is_empty() && guest_to_service_tx.is_some() => {
                if let Some(permit) = permit {
                    let Some(data) = guest_to_service_pending.pop_front() else {
                        return;
                    };
                    let len = data.len();
                    permit.send(data);
                    guest_to_service_pending_bytes =
                        guest_to_service_pending_bytes.saturating_sub(len);
                } else {
                    guest_to_service_tx.take();
                    guest_to_service_pending.clear();
                    guest_to_service_pending_bytes = 0;
                    service_to_guest_closed = true;
                }
            }

            msg = guest_rx.recv(), if stack.can_accept_guest_frame() => {
                match msg {
                    Some(GuestPacket::TcpFrame(frame)) => stack.ingest_guest_frame(frame),
                    Some(GuestPacket::Close) | None => {
                        guest_to_service_tx.take();
                        stack.abort();
                        return;
                    }
                }
            }

            data = service_to_guest_rx.recv(), if service_to_guest_pending.is_empty() && stack.wants_backend_read() && !service_to_guest_closed => {
                match data {
                    Some(data) => {
                        if !stack.push_guest_bound_data(&mut service_to_guest_pending, &data) {
                            return;
                        }
                    }
                    None => service_to_guest_closed = true,
                }
            }

            () = &mut stream_fut, if !handler_done => {
                handler_done = true;
            }

            () = tokio::time::sleep(delay) => {}
        }
    }
}

/// Run a direct TCP connection between the guest stack and a host socket.
#[allow(clippy::too_many_lines)]
async fn run_connected(
    stream: tokio::net::TcpStream,
    stack: &mut GuestTcpStack,
    mut guest_rx: mpsc::Receiver<GuestPacket>,
    host_egress: HostEgressAuthorizer,
    request: HostEgressRequest,
) {
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut guest_to_host_buf = VecDeque::<u8>::new();
    let mut host_to_guest_buf = VecDeque::<u8>::new();
    let mut host_read_closed = false;
    let mut host_write_closed = false;
    let mut host_eof_pending = false;
    let mut shutdown_pending = false;

    loop {
        stack.poll();
        if stack.collector_closed {
            return;
        }
        if !stack.flush_guest_bound_pending(&mut host_to_guest_buf) {
            return;
        }
        if host_eof_pending && host_to_guest_buf.is_empty() {
            stack.mark_host_eof();
            host_eof_pending = false;
        }

        let room = MAX_GUEST_BUFFER.saturating_sub(guest_to_host_buf.len());
        if room > 0 {
            let data = stack.drain_guest_data(room);
            guest_to_host_buf.extend(data);
        }

        if stack.take_guest_fin() {
            shutdown_pending = true;
        }
        if stack.take_guest_reset() {
            return;
        }

        if shutdown_pending && guest_to_host_buf.is_empty() && !host_write_closed {
            if host_egress.authorize(request).is_none() {
                log::warn!(
                    "TCP: host shutdown to {} denied by network policy",
                    request.socket_addr
                );
                stack.abort();
                return;
            }
            if let Err(e) = SockRef::from(&stream).shutdown(std::net::Shutdown::Write) {
                log::trace!("TCP: host shutdown(Write) failed: {e}");
            }
            host_write_closed = true;
            shutdown_pending = false;
        }

        if host_to_guest_buf.is_empty() && stack.should_cleanup() {
            return;
        }

        let wants_read = stack.wants_backend_read()
            && host_to_guest_buf.is_empty()
            && !host_read_closed
            && !host_eof_pending;
        let wants_write = !guest_to_host_buf.is_empty() && !host_write_closed;
        let output_sender = stack
            .has_pending_output()
            .then(|| stack.collector_tx.clone());
        let delay = if host_to_guest_buf.is_empty() && !stack.has_pending_output() {
            stack.next_poll_delay()
        } else {
            stack.next_poll_delay().min(Duration::from_millis(10))
        };

        tokio::select! {
            biased;

            permit = reserve_permit(output_sender), if stack.has_pending_output() => {
                match permit {
                    Some(permit) => stack.flush_one_output(permit),
                    None => return,
                }
            }

            msg = guest_rx.recv(), if stack.can_accept_guest_frame() => {
                match msg {
                    Some(GuestPacket::TcpFrame(frame)) => stack.ingest_guest_frame(frame),
                    Some(GuestPacket::Close) => {
                        stack.abort();
                        return;
                    }
                    None => return,
                }
            }

            result = stream.readable(), if wants_read => {
                match result {
                    Ok(()) => {
                        loop {
                            let space = stack.guest_send_space();
                            if space == 0 { break; }
                            let read_len = space.min(read_buf.len());
                            match stream.try_read(&mut read_buf[..read_len]) {
                                Ok(0) => {
                                    host_read_closed = true;
                                    host_eof_pending = true;
                                    break;
                                }
                                Ok(n) => {
                                    if !stack.push_guest_bound_data(&mut host_to_guest_buf, &read_buf[..n]) {
                                        return;
                                    }
                                    if !host_to_guest_buf.is_empty() {
                                        break;
                                    }
                                }
                                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => break,
                                Err(e) => {
                                    log::warn!("TCP: read error from host: {e}");
                                    host_read_closed = true;
                                    stack.abort();
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("TCP: readable() error: {e}");
                        host_read_closed = true;
                        stack.abort();
                    }
                }
            }

            result = stream.writable(), if wants_write => {
                match result {
                    Ok(()) => {
                        if host_egress.authorize(request).is_none() {
                            log::warn!(
                                "TCP: host write to {} denied by network policy",
                                request.socket_addr
                            );
                            guest_to_host_buf.clear();
                            stack.abort();
                            return;
                        }
                        let data = guest_to_host_buf.make_contiguous();
                        match stream.try_write(data) {
                            Ok(0) => {
                                log::warn!("TCP: write to host returned 0 bytes");
                                guest_to_host_buf.clear();
                                host_write_closed = true;
                                stack.abort();
                            }
                            Ok(n) => {
                                guest_to_host_buf.drain(..n);
                            }
                            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                            Err(e) => {
                                log::warn!("TCP: write error to host: {e}");
                                guest_to_host_buf.clear();
                                host_write_closed = true;
                                stack.abort();
                            }
                        }
                    }
                    Err(e) => {
                        log::warn!("TCP: writable() error: {e}");
                        guest_to_host_buf.clear();
                        host_write_closed = true;
                        stack.abort();
                    }
                }
            }

            () = tokio::time::sleep(delay) => {}
        }
    }
}

// =============================================================================
// Inbound Port Forwarding
// =============================================================================

/// A bidirectional byte stream for inbound port forwarding.
pub trait InboundStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin> InboundStream for T {}

/// Run an inbound TCP connection lifecycle (host client to guest service).
pub async fn inbound_tcp_task(
    stream: Box<dyn InboundStream + 'static>,
    target: InboundTarget,
    stack_config: TcpStackConfig,
    mut guest_rx: mpsc::Receiver<GuestPacket>,
    collector_tx: mpsc::Sender<GuestOutput>,
    rx_waker: Option<RxWaker>,
    output_tag: ConnectionOutputTag,
) {
    let mut stack =
        match GuestTcpStack::new_client(stack_config, target, collector_tx, rx_waker, output_tag) {
            Ok(stack) => stack,
            Err(e) => {
                log::warn!("TCP inbound: failed to create guest stack: {e}");
                return;
            }
        };
    let handshake = tokio::time::timeout(
        Duration::from_secs(CONNECT_TIMEOUT_SECS),
        wait_for_guest_handshake(&mut stack, &mut guest_rx),
    )
    .await;
    match handshake {
        Ok(true) => {}
        Ok(false) => {
            stack.abort();
            return;
        }
        Err(_) => {
            log::debug!("TCP inbound: guest handshake timed out");
            stack.abort();
            return;
        }
    }
    run_connected_inbound(stream, &mut stack, guest_rx).await;
}

async fn wait_for_guest_handshake(
    stack: &mut GuestTcpStack,
    guest_rx: &mut mpsc::Receiver<GuestPacket>,
) -> bool {
    loop {
        stack.poll();
        if stack.collector_closed {
            return false;
        }
        match stack.state() {
            TcpSocketState::Established | TcpSocketState::CloseWait => return true,
            TcpSocketState::Closed | TcpSocketState::TimeWait => return false,
            _ => {}
        }

        let output_sender = stack
            .has_pending_output()
            .then(|| stack.collector_tx.clone());
        let delay = if stack.has_pending_output() {
            stack.next_poll_delay().min(Duration::from_millis(10))
        } else {
            stack.next_poll_delay()
        };
        tokio::select! {
            biased;

            permit = reserve_permit(output_sender), if stack.has_pending_output() => {
                match permit {
                    Some(permit) => stack.flush_one_output(permit),
                    None => return false,
                }
            }

            msg = guest_rx.recv(), if stack.can_accept_guest_frame() => {
                match msg {
                    Some(GuestPacket::TcpFrame(frame)) => stack.ingest_guest_frame(frame),
                    Some(GuestPacket::Close) | None => return false,
                }
            }

            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn run_connected_inbound(
    stream: Box<dyn InboundStream + 'static>,
    stack: &mut GuestTcpStack,
    mut guest_rx: mpsc::Receiver<GuestPacket>,
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut read_buf = vec![0u8; 16 * 1024];
    let mut guest_to_host_buf = VecDeque::<u8>::new();
    let mut host_to_guest_buf = VecDeque::<u8>::new();
    let mut host_eof_pending = false;
    let mut shutdown_pending = false;
    let mut writer_closed = false;

    loop {
        stack.poll();
        if stack.collector_closed {
            return;
        }
        if !stack.flush_guest_bound_pending(&mut host_to_guest_buf) {
            return;
        }
        if host_eof_pending && host_to_guest_buf.is_empty() {
            stack.mark_host_eof();
            host_eof_pending = false;
        }

        let room = MAX_GUEST_BUFFER.saturating_sub(guest_to_host_buf.len());
        if room > 0 {
            let data = stack.drain_guest_data(room);
            guest_to_host_buf.extend(data);
        }
        if stack.take_guest_fin() {
            shutdown_pending = true;
        }
        if stack.take_guest_reset() {
            return;
        }
        if shutdown_pending && guest_to_host_buf.is_empty() && !writer_closed {
            if let Err(e) = writer.shutdown().await {
                log::debug!("TCP inbound: writer.shutdown() failed: {e}");
            }
            writer_closed = true;
            shutdown_pending = false;
        }
        if host_to_guest_buf.is_empty() && stack.should_cleanup() {
            return;
        }

        let wants_read =
            stack.wants_backend_read() && host_to_guest_buf.is_empty() && !host_eof_pending;
        let read_space = stack.guest_send_space().min(read_buf.len());
        let write_data: Vec<u8> = if guest_to_host_buf.is_empty() {
            Vec::new()
        } else {
            guest_to_host_buf.make_contiguous().to_vec()
        };
        let output_sender = stack
            .has_pending_output()
            .then(|| stack.collector_tx.clone());
        let delay = if host_to_guest_buf.is_empty() && !stack.has_pending_output() {
            stack.next_poll_delay()
        } else {
            stack.next_poll_delay().min(Duration::from_millis(10))
        };

        tokio::select! {
            biased;

            permit = reserve_permit(output_sender), if stack.has_pending_output() => {
                match permit {
                    Some(permit) => stack.flush_one_output(permit),
                    None => return,
                }
            }

            msg = guest_rx.recv(), if stack.can_accept_guest_frame() => {
                match msg {
                    Some(GuestPacket::TcpFrame(frame)) => stack.ingest_guest_frame(frame),
                    Some(GuestPacket::Close) | None => {
                        stack.abort();
                        return;
                    }
                }
            }

            result = reader.read(&mut read_buf[..read_space]), if wants_read && read_space > 0 => {
                match result {
                    Ok(0) => host_eof_pending = true,
                    Ok(n) => {
                        if !stack.push_guest_bound_data(&mut host_to_guest_buf, &read_buf[..n]) {
                            return;
                        }
                    }
                    Err(e) => {
                        log::warn!("TCP inbound: read error: {e}");
                        stack.abort();
                    }
                }
            }

            result = writer.write(&write_data), if !write_data.is_empty() && !writer_closed => {
                match result {
                    Ok(0) => {
                        log::warn!("TCP inbound: write returned 0 bytes");
                        stack.abort();
                    }
                    Ok(n) => {
                        guest_to_host_buf.drain(..n);
                    }
                    Err(e) => {
                        log::warn!("TCP inbound: write error: {e}");
                        stack.abort();
                    }
                }
            }

            () = tokio::time::sleep(delay) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet_builder::{
        ETH_TYPE_IPV4, ETH_TYPE_IPV6, IP_PROTO_TCP, IPV4_HEADER_LEN, TCP_ACK, TCP_HEADER_LEN,
        TCP_RST, calculate_ip_checksum, calculate_tcp_checksum, calculate_tcp_checksum_v6,
    };
    use proptest::prelude::*;

    const GUEST_MAC: [u8; 6] = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55];
    const GUEST_IPV4: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
    const GUEST_IPV6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15);

    fn config() -> TcpStackConfig {
        TcpStackConfig {
            gateway_mac: crate::DEFAULT_GATEWAY_MAC,
            gateway_ip: crate::DEFAULT_GATEWAY,
            gateway_ipv6: crate::DEFAULT_GATEWAY_V6,
            prefix_len: 24,
            prefix_len_v6: 64,
            mtu: 1500,
        }
    }

    fn tcp_output_tag() -> ConnectionOutputTag {
        ConnectionOutputTag::for_test(crate::Protocol::Tcp)
    }

    #[tokio::test]
    async fn denied_host_connector_fails_closed() {
        let connector = host_connector(HostConnectAccess::Denied {
            remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9),
        });
        let Err(err) = connector.connect().await else {
            panic!("denied connector unexpectedly opened a host stream");
        };
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    fn guest_syn(dst_port: u16) -> Vec<u8> {
        guest_tcp_frame(dst_port, TCP_SYN, 1000, 0, &[])
    }

    fn guest_tcp_frame(dst_port: u16, flags: u8, seq: u32, ack: u32, payload: &[u8]) -> Vec<u8> {
        guest_tcp_frame_v4(
            GUEST_IPV4,
            Ipv4Addr::LOCALHOST,
            49152,
            dst_port,
            flags,
            seq,
            ack,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn guest_tcp_frame_v4(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let total_len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len();
        let mut frame = vec![0u8; total_len];
        EthernetHeader {
            dst_mac: config().gateway_mac,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV4,
        }
        .write(&mut frame[..ETH_HEADER_LEN]);
        Ipv4Header {
            version_ihl: 0x45,
            dscp_ecn: 0,
            total_length: u16::try_from(IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len())
                .expect("test payload fits IPv4 length"),
            identification: 1,
            flags_fragment: 0x4000,
            ttl: 64,
            protocol: IP_PROTO_TCP,
            checksum: 0,
            src_ip,
            dst_ip,
        }
        .write(&mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        let ip_cksum =
            calculate_ip_checksum(&frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        frame[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&ip_cksum.to_be_bytes());

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
        .write(&mut frame[tcp_start..tcp_start + TCP_HEADER_LEN]);
        frame[tcp_start + TCP_HEADER_LEN..].copy_from_slice(payload);
        let tcp_cksum = calculate_tcp_checksum(
            src_ip,
            dst_ip,
            &frame[tcp_start..tcp_start + TCP_HEADER_LEN],
            payload,
        );
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        frame
    }

    fn guest_syn_v6(dst_port: u16) -> Vec<u8> {
        guest_tcp_frame_v6(
            GUEST_IPV6,
            Ipv6Addr::LOCALHOST,
            49152,
            dst_port,
            TCP_SYN,
            1000,
            0,
            &[],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn guest_tcp_frame_v6(
        src_ip: Ipv6Addr,
        dst_ip: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        flags: u8,
        seq: u32,
        ack: u32,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut frame =
            vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN + payload.len()];
        EthernetHeader {
            dst_mac: config().gateway_mac,
            src_mac: GUEST_MAC,
            ether_type: ETH_TYPE_IPV6,
        }
        .write(&mut frame[..ETH_HEADER_LEN]);
        Ipv6Header {
            payload_len: u16::try_from(TCP_HEADER_LEN + payload.len()).unwrap(),
            next_header: IP_PROTO_TCP,
            hop_limit: 64,
            src_ip,
            dst_ip,
        }
        .write(&mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN]);

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
        .write(&mut frame[tcp_start..tcp_start + TCP_HEADER_LEN]);
        frame[tcp_start + TCP_HEADER_LEN..].copy_from_slice(payload);
        let tcp_cksum = calculate_tcp_checksum_v6(
            src_ip,
            dst_ip,
            &frame[tcp_start..tcp_start + TCP_HEADER_LEN],
            payload,
        );
        frame[tcp_start + 16..tcp_start + 18].copy_from_slice(&tcp_cksum.to_be_bytes());
        frame
    }

    fn parse_ipv4_tcp(frame: &[u8]) -> Option<(EthernetHeader, Ipv4Header, TcpHeader, Vec<u8>)> {
        let eth = EthernetHeader::parse(frame)?;
        if eth.ether_type != ETH_TYPE_IPV4 {
            return None;
        }
        let ip = Ipv4Header::parse(frame.get(ETH_HEADER_LEN..)?)?;
        if ip.protocol != IP_PROTO_TCP {
            return None;
        }
        let tcp_start = ETH_HEADER_LEN + ip.header_len();
        let transport_len = (ip.total_length as usize).saturating_sub(ip.header_len());
        let transport_end = (tcp_start + transport_len).min(frame.len());
        let tcp = TcpHeader::parse(frame.get(tcp_start..transport_end)?)?;
        let payload_start = tcp_start + tcp.header_len();
        let payload = frame
            .get(payload_start..transport_end)
            .unwrap_or_default()
            .to_vec();
        Some((eth, ip, tcp, payload))
    }

    fn parse_ipv6_tcp(frame: &[u8]) -> Option<(EthernetHeader, Ipv6Header, TcpHeader, Vec<u8>)> {
        let eth = EthernetHeader::parse(frame)?;
        if eth.ether_type != ETH_TYPE_IPV6 {
            return None;
        }
        let ip = Ipv6Header::parse(frame.get(ETH_HEADER_LEN..)?)?;
        if ip.next_header != IP_PROTO_TCP {
            return None;
        }
        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let transport_end = (tcp_start + ip.payload_len as usize).min(frame.len());
        let tcp = TcpHeader::parse(frame.get(tcp_start..transport_end)?)?;
        let payload_start = tcp_start + tcp.header_len();
        let payload = frame
            .get(payload_start..transport_end)
            .unwrap_or_default()
            .to_vec();
        Some((eth, ip, tcp, payload))
    }

    fn recv_ipv4_tcp_matching(
        collector_rx: &mut mpsc::Receiver<GuestOutput>,
        predicate: impl Fn(&TcpHeader, &[u8]) -> bool,
    ) -> (EthernetHeader, Ipv4Header, TcpHeader, Vec<u8>) {
        while let Ok(output) = collector_rx.try_recv() {
            let frame = output.into_packet();
            if let Some(parsed) = parse_ipv4_tcp(&frame) {
                let matches = {
                    let tcp = &parsed.2;
                    let payload = &parsed.3;
                    predicate(tcp, payload)
                };
                if matches {
                    return parsed;
                }
            }
        }
        panic!("expected matching IPv4 TCP frame");
    }

    #[test]
    fn arp_reply_has_expected_shape() {
        let frame = build_arp_reply(
            config().gateway_mac,
            [0xaa; 6],
            Ipv4Addr::new(10, 0, 2, 15),
            crate::DEFAULT_GATEWAY,
        );
        assert_eq!(frame.len(), 42);
        assert_eq!(&frame[12..14], &0x0806u16.to_be_bytes());
        assert_eq!(&frame[20..22], &2u16.to_be_bytes());
        assert_eq!(&frame[22..28], &[0xaa; 6]);
    }

    #[test]
    fn ndp_advert_has_expected_shape_and_checksum() {
        let guest_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x15);
        let frame = build_ndp_neighbor_advert(
            config().gateway_mac,
            [0xaa; 6],
            guest_ip,
            config().gateway_ipv6,
        );
        assert_eq!(frame.len(), ETH_HEADER_LEN + IPV6_HEADER_LEN + 32);
        assert_eq!(&frame[12..14], &ETH_TYPE_IPV6.to_be_bytes());
        let ip = Ipv6Header::parse(&frame[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.next_header, IP_PROTO_ICMPV6);
        assert_eq!(ip.src_ip, guest_ip);
        let icmp_offset = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        assert_eq!(frame[icmp_offset], 136);
        assert_eq!(
            &frame[icmp_offset + 8..icmp_offset + 24],
            &guest_ip.octets()
        );
        assert_eq!(frame[icmp_offset + 24], 2);
        assert_eq!(&frame[icmp_offset + 26..icmp_offset + 32], &[0xaa; 6]);
        assert_eq!(
            checksum_icmpv6(
                guest_ip,
                config().gateway_ipv6,
                &frame[icmp_offset..icmp_offset + 32],
            ),
            0
        );
    }

    #[test]
    fn connect_failure_rst_builder_ignores_non_tcp() {
        assert!(build_rst_for_frame(&[], config().gateway_mac).is_none());
        assert!(build_rst_for_frame(&[0u8; ETH_HEADER_LEN], config().gateway_mac).is_none());
    }

    #[test]
    fn connect_failure_rst_builder_resets_initial_ipv4_syn() {
        let rst = build_rst_for_frame(&guest_syn(443), config().gateway_mac)
            .expect("initial SYN should produce RST");
        let (eth, ip, tcp, payload) = parse_ipv4_tcp(&rst).expect("RST should be IPv4/TCP");

        assert_eq!(eth.dst_mac, GUEST_MAC);
        assert_eq!(ip.src_ip, Ipv4Addr::LOCALHOST);
        assert_eq!(ip.dst_ip, GUEST_IPV4);
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.flags, TCP_RST | TCP_ACK);
        assert_eq!(tcp.seq_num, 0);
        assert_eq!(tcp.ack_num, 1001);
        assert!(payload.is_empty());
    }

    #[test]
    fn connect_failure_rst_builder_resets_initial_ipv6_syn() {
        let rst = build_rst_for_frame(&guest_syn_v6(443), config().gateway_mac)
            .expect("initial IPv6 SYN should produce RST");
        let (eth, ip, tcp, payload) = parse_ipv6_tcp(&rst).expect("RST should be IPv6/TCP");

        assert_eq!(eth.dst_mac, GUEST_MAC);
        assert_eq!(ip.src_ip, Ipv6Addr::LOCALHOST);
        assert_eq!(ip.dst_ip, GUEST_IPV6);
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.flags, TCP_RST | TCP_ACK);
        assert_eq!(tcp.seq_num, 0);
        assert_eq!(tcp.ack_num, 1001);
        assert!(payload.is_empty());
    }

    #[tokio::test]
    async fn connect_failure_rst_drops_when_collector_is_full() {
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        collector_tx
            .try_send(GuestOutput::Control(vec![0xFF]))
            .unwrap();

        let result = tokio::time::timeout(
            Duration::from_millis(50),
            send_rst_for_initial_frame(
                &guest_syn(443),
                config().gateway_mac,
                &collector_tx,
                None,
                tcp_output_tag(),
            ),
        )
        .await;

        assert!(
            result.is_ok(),
            "RST enqueue must not await collector backpressure"
        );
    }

    #[test]
    fn server_stack_generates_syn_ack() {
        let (collector_tx, mut collector_rx) = mpsc::channel(8);
        let mut stack = GuestTcpStack::new_server(
            config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            collector_tx,
            None,
            tcp_output_tag(),
        )
        .unwrap();

        stack.ingest_guest_frame(guest_syn(443));
        let frame = collector_rx
            .try_recv()
            .expect("expected SYN-ACK frame")
            .into_packet();
        let eth = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV4);
        let ip = Ipv4Header::parse(&frame[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.protocol, IP_PROTO_TCP);
        let tcp_start = ETH_HEADER_LEN + ip.header_len();
        let tcp = TcpHeader::parse(&frame[tcp_start..]).unwrap();
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
    }

    #[test]
    fn neighbor_seed_does_not_consume_last_guest_rx_slot() {
        let (collector_tx, _collector_rx) = mpsc::channel(1);
        collector_tx
            .try_send(GuestOutput::Control(vec![0xCC]))
            .unwrap();
        let mut stack = GuestTcpStack::new_server(
            config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            collector_tx,
            None,
            tcp_output_tag(),
        )
        .unwrap();

        for _ in 0..MAX_QUEUE_SIZE {
            stack.device.tx_queue.push_back(vec![0xAA]);
        }
        for _ in 0..(MAX_QUEUE_SIZE - 1) {
            stack.device.rx_queue.push_back(vec![0xBB]);
        }

        let frame = guest_tcp_frame(443, TCP_ACK, 1001, 1, &[]);
        stack.ingest_guest_frame(frame.clone());

        assert_eq!(stack.device.rx_queue.len(), MAX_QUEUE_SIZE);
        assert_eq!(
            stack.device.rx_queue.back().map(Vec::as_slice),
            Some(frame.as_slice())
        );
        assert_ne!(stack.state(), TcpSocketState::Closed);
    }

    #[test]
    fn oversized_guest_bound_chunk_aborts_without_buffering() {
        let (collector_tx, _collector_rx) = mpsc::channel(8);
        let mut stack = GuestTcpStack::new_server(
            config(),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
            collector_tx,
            None,
            tcp_output_tag(),
        )
        .unwrap();
        let mut pending = VecDeque::new();
        let data = vec![0xAB; MAX_GUEST_BOUND_BUFFER + 1];

        assert!(!stack.push_guest_bound_data(&mut pending, &data));
        assert!(pending.is_empty());
        assert_eq!(stack.state(), TcpSocketState::Closed);
    }

    #[test]
    fn inbound_client_stack_handshakes_sends_data_and_fin() {
        let (collector_tx, mut collector_rx) = mpsc::channel(16);
        let target = InboundTarget {
            guest_mac: GUEST_MAC,
            guest_ip: IpAddr::V4(GUEST_IPV4),
            guest_port: 8080,
            gateway_ip: IpAddr::V4(config().gateway_ip),
            ephemeral_port: 49152,
        };
        let mut stack =
            GuestTcpStack::new_client(config(), target, collector_tx, None, tcp_output_tag())
                .expect("inbound client stack should connect to guest");

        let (_, syn_ip, syn_tcp, syn_payload) =
            recv_ipv4_tcp_matching(&mut collector_rx, |tcp, _| {
                tcp.src_port == 49152 && tcp.dst_port == 8080 && tcp.flags & TCP_SYN != 0
            });
        assert_eq!(syn_ip.src_ip, config().gateway_ip);
        assert_eq!(syn_ip.dst_ip, GUEST_IPV4);
        assert_eq!(syn_tcp.flags & TCP_ACK, 0);
        assert!(syn_payload.is_empty());

        let guest_isn = 7000;
        stack.ingest_guest_frame(guest_tcp_frame_v4(
            GUEST_IPV4,
            config().gateway_ip,
            8080,
            49152,
            TCP_SYN | TCP_ACK,
            guest_isn,
            syn_tcp.seq_num.wrapping_add(1),
            &[],
        ));
        let (_, _, ack_tcp, ack_payload) =
            recv_ipv4_tcp_matching(&mut collector_rx, |tcp, payload| {
                tcp.src_port == 49152
                    && tcp.dst_port == 8080
                    && tcp.flags == TCP_ACK
                    && payload.is_empty()
            });
        assert_eq!(ack_tcp.seq_num, syn_tcp.seq_num.wrapping_add(1));
        assert_eq!(ack_tcp.ack_num, guest_isn + 1);
        assert_eq!(stack.state(), TcpSocketState::Established);
        assert!(ack_payload.is_empty());

        assert!(stack.send_to_guest(b"host-data"));
        let (_, _, data_tcp, data_payload) =
            recv_ipv4_tcp_matching(&mut collector_rx, |tcp, payload| {
                tcp.src_port == 49152
                    && tcp.dst_port == 8080
                    && tcp.flags & TCP_ACK != 0
                    && payload == b"host-data"
            });
        assert_eq!(data_tcp.seq_num, ack_tcp.seq_num);
        assert_eq!(data_payload, b"host-data");

        stack.ingest_guest_frame(guest_tcp_frame_v4(
            GUEST_IPV4,
            config().gateway_ip,
            8080,
            49152,
            TCP_ACK,
            ack_tcp.ack_num,
            data_tcp
                .seq_num
                .wrapping_add(u32::try_from(data_payload.len()).unwrap()),
            &[],
        ));
        stack.mark_host_eof();
        let (_, _, fin_tcp, fin_payload) =
            recv_ipv4_tcp_matching(&mut collector_rx, |tcp, payload| {
                tcp.src_port == 49152
                    && tcp.dst_port == 8080
                    && tcp.flags & TCP_FIN != 0
                    && payload.is_empty()
            });
        assert_eq!(
            fin_tcp.seq_num,
            data_tcp
                .seq_num
                .wrapping_add(u32::try_from(data_payload.len()).unwrap())
        );
        assert_eq!(fin_tcp.ack_num, ack_tcp.ack_num);
        assert!(fin_payload.is_empty());
    }

    #[test]
    fn guest_bound_data_waits_for_collector_capacity() {
        let (collector_tx, mut collector_rx) = mpsc::channel(4);
        let target = InboundTarget {
            guest_mac: GUEST_MAC,
            guest_ip: IpAddr::V4(GUEST_IPV4),
            guest_port: 8080,
            gateway_ip: IpAddr::V4(config().gateway_ip),
            ephemeral_port: 49152,
        };
        let mut stack = GuestTcpStack::new_client(
            config(),
            target,
            collector_tx.clone(),
            None,
            tcp_output_tag(),
        )
        .expect("inbound client stack should connect to guest");

        let (_, _, syn_tcp, _) = recv_ipv4_tcp_matching(&mut collector_rx, |tcp, _| {
            tcp.src_port == 49152 && tcp.dst_port == 8080 && tcp.flags & TCP_SYN != 0
        });
        stack.ingest_guest_frame(guest_tcp_frame_v4(
            GUEST_IPV4,
            config().gateway_ip,
            8080,
            49152,
            TCP_SYN | TCP_ACK,
            7000,
            syn_tcp.seq_num.wrapping_add(1),
            &[],
        ));
        let (_, _, ack_tcp, _) = recv_ipv4_tcp_matching(&mut collector_rx, |tcp, payload| {
            tcp.src_port == 49152
                && tcp.dst_port == 8080
                && tcp.flags == TCP_ACK
                && payload.is_empty()
        });
        while collector_rx.try_recv().is_ok() {}

        for _ in 0..4 {
            collector_tx
                .try_send(GuestOutput::Control(vec![0xFF]))
                .unwrap();
        }

        assert!(stack.send_to_guest(b"blocked-data"));
        assert!(
            stack.has_pending_output(),
            "guest-bound frame must remain queued while collector is full"
        );

        for _ in 0..4 {
            assert_eq!(collector_rx.try_recv().unwrap().into_packet(), vec![0xFF]);
        }
        stack.poll();

        let (_, _, data_tcp, data_payload) =
            recv_ipv4_tcp_matching(&mut collector_rx, |tcp, payload| {
                tcp.src_port == 49152
                    && tcp.dst_port == 8080
                    && tcp.flags & TCP_ACK != 0
                    && payload == b"blocked-data"
            });
        assert_eq!(data_tcp.seq_num, ack_tcp.seq_num);
        assert_eq!(data_payload, b"blocked-data");
    }

    proptest! {
        #[test]
        fn random_guest_frames_never_panic_or_escape_queue_bounds(
            segments in prop::collection::vec(
                (any::<u8>(), any::<u32>(), any::<u32>(), prop::collection::vec(any::<u8>(), 0..64)),
                0..32,
            ),
            raw_frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..1600), 0..32),
        ) {
            let (collector_tx, mut collector_rx) = mpsc::channel(1024);
            let mut stack = GuestTcpStack::new_server(
                config(),
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 443),
                collector_tx,
                None,
                tcp_output_tag(),
            )
            .expect("stack creation should succeed");

            for frame in raw_frames {
                stack.ingest_guest_frame(frame);
                while collector_rx.try_recv().is_ok() {}
                prop_assert!(stack.device.rx_queue.len() <= MAX_QUEUE_SIZE);
                prop_assert!(stack.device.tx_queue.len() <= MAX_QUEUE_SIZE);
            }

            for (flags, seq, ack, payload) in segments {
                stack.ingest_guest_frame(guest_tcp_frame(443, flags, seq, ack, &payload));
                while collector_rx.try_recv().is_ok() {}
                prop_assert!(stack.device.rx_queue.len() <= MAX_QUEUE_SIZE);
                prop_assert!(stack.device.tx_queue.len() <= MAX_QUEUE_SIZE);
            }
        }
    }

    #[test]
    fn server_stack_generates_syn_ack_v6() {
        let (collector_tx, mut collector_rx) = mpsc::channel(8);
        let mut stack = GuestTcpStack::new_server(
            config(),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
            collector_tx,
            None,
            tcp_output_tag(),
        )
        .unwrap();

        stack.ingest_guest_frame(guest_syn_v6(443));
        let frame = collector_rx
            .try_recv()
            .expect("expected IPv6 SYN-ACK frame")
            .into_packet();
        let eth = EthernetHeader::parse(&frame).unwrap();
        assert_eq!(eth.ether_type, ETH_TYPE_IPV6);
        let ip = Ipv6Header::parse(&frame[ETH_HEADER_LEN..]).unwrap();
        assert_eq!(ip.next_header, IP_PROTO_TCP);
        let tcp_start = ETH_HEADER_LEN + IPV6_HEADER_LEN;
        let tcp = TcpHeader::parse(&frame[tcp_start..]).unwrap();
        assert_eq!(tcp.src_port, 443);
        assert_eq!(tcp.dst_port, 49152);
        assert_eq!(tcp.flags & (TCP_SYN | TCP_ACK), TCP_SYN | TCP_ACK);
    }
}
