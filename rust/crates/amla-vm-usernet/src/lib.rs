// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! User-mode networking for amla-vm
//!
//! This crate provides a user-space network stack (similar to QEMU's slirp)
//! that allows guest VMs to access the network without special host privileges.
//!
//! # Architecture
//!
//! The stack uses smoltcp as the underlying TCP/IP implementation:
//! - Guest sends Ethernet frames through virtio-net
//! - `UserNetBackend` processes frames through smoltcp
//! - TCP/UDP connections are proxied to host sockets via `NatProxy`
//! - DHCP server provides automatic guest configuration
//!
//! # Features
//!
//! - NAT for outbound TCP/UDP connections (real internet connectivity)
//! - Built-in DHCP server for guest configuration
//! - DNS forwarding to host resolver when explicitly enabled by policy
//! - Port forwarding from host to guest (planned, not yet implemented)
//! - No root/`CAP_NET_ADMIN` required
//!
//! # Interceptor API
//!
//! DNS and TCP traffic can be intercepted via the [`interceptor`] module
//! (re-exported from `amla-interceptor`). Implement [`interceptor::DnsInterceptor`]
//! to inspect/modify/respond-to DNS queries before they reach the host resolver,
//! or [`interceptor::TcpConnectionPolicy`] to control outbound TCP stream lifecycles.
//! TCP and DNS policies are construction-time state via
//! [`UserNetBackend::try_new_with_policies`].
//!
//! # Thread Model
//!
//! `UserNetBackend` is single-threaded — call [`UserNetBackend::poll`] from the
//! virtio-net device thread. Proxied TCP/UDP connections run on a shared tokio
//! runtime; response packets are collected via an internal channel and delivered
//! to the guest on the next `poll()`.
//!
//! # Security
//!
//! - Guest is isolated in its own virtual network (10.0.2.0/24 by default)
//! - Only explicitly forwarded ports are accessible from host
//! - Outbound connections can be restricted via policy
//!
//! # Known Limitations
//!
//! - IPv6 NAT is functional but not fully exercised in integration tests
//! - ICMP echo (ping) is not proxied — guest pings will timeout
//! - MTU is fixed at 1500; jumbo frames are not supported

mod config;
mod device;
mod dhcp;
mod dns;
mod guest_output;
mod guest_packet;
mod icmp;
pub use amla_interceptor as interceptor;
mod nat;
pub mod packet_builder;
mod state;
mod tcp_proxy;
mod udp_proxy;

// Re-export public types from submodules
pub use config::{
    AuthorizedHostEgress, DnsForwardPolicy, EgressPolicy, HostEgressAuthorizer, HostEgressPurpose,
    HostEgressRequest, HostEgressRule, PortForward, Protocol, UserNetConfig,
};
pub use tcp_proxy::InboundStream;

use device::VirtualDevice;

use amla_core::backends::{NetBackend, NetRxPacketLease, RxWaker};
use nat::{NatConfig, NatProxy};
use parking_lot::{Mutex, MutexGuard};
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketSet, SocketStorage};
use smoltcp::time::Instant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, Ipv6Address};
use state::UserNetState;
use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::OnceLock;
use thiserror::Error;
use tokio::sync::mpsc;

#[cfg(test)]
mod tests;

// =============================================================================
// Constants — re-exported from amla-vm-constants (single source of truth)
// =============================================================================

pub use amla_constants::net::{
    DEFAULT_DNS, DEFAULT_DNS_V6, DEFAULT_GATEWAY, DEFAULT_GATEWAY_MAC, DEFAULT_GATEWAY_V6,
    DEFAULT_GUEST_IP, DEFAULT_GUEST_IP_V6, DEFAULT_GUEST_MAC, DEFAULT_NETMASK,
    DEFAULT_PREFIX_LEN_V6,
};

/// MTU for the virtual network
pub const VIRTUAL_MTU: usize = 1500;

/// Maximum packet queue size (each entry is one ethernet frame, ~1.5KB).
const MAX_QUEUE_SIZE: usize = 8192;

/// Maximum reliable collector backlog retained outside the device queue.
const MAX_RELIABLE_COLLECTOR_BACKLOG_BYTES: usize = MAX_QUEUE_SIZE * VIRTUAL_MTU;

/// Maximum concurrent DNS forward tasks.
///
/// Prevents a malicious guest from exhausting host sockets and memory
/// by flooding DNS queries. Each task holds a UDP socket + buffer for
/// up to 2 seconds. Without this limit, a guest could spawn thousands
/// of tasks consuming hundreds of MB of memory.
const MAX_CONCURRENT_DNS: usize = 128;

/// Maximum number of concurrent TCP/UDP sockets.
const MAX_SOCKETS: usize = 256;

// =============================================================================
// Time Utilities
// =============================================================================

/// Monotonic reference point for smoltcp timestamps.
fn monotonic_origin() -> &'static std::time::Instant {
    static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
    ORIGIN.get_or_init(std::time::Instant::now)
}

/// Get current time as smoltcp Instant using a monotonic clock.
///
/// Uses `std::time::Instant` (monotonic) to avoid backward jumps from
/// NTP corrections or VM restore that would stall smoltcp timers.
fn now() -> Instant {
    let millis = monotonic_origin().elapsed().as_millis();
    let millis = i64::try_from(millis).unwrap_or(i64::MAX);
    Instant::from_millis(millis)
}

fn checked_iov_len(bufs: &[IoSlice<'_>]) -> io::Result<usize> {
    bufs.iter().try_fold(0usize, |total, buf| {
        total.checked_add(buf.len()).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "guest packet descriptor length overflows usize",
            )
        })
    })
}

fn send_guest_frame<P, D>(state: &mut UserNetState<P, D>, bufs: &[IoSlice<'_>]) -> io::Result<()>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    let total = checked_iov_len(bufs)?;
    let max_frame_len = state
        .config
        .mtu
        .checked_add(packet_builder::ETH_HEADER_LEN)
        .ok_or_else(|| io::Error::other("configured MTU overflows ethernet frame length"))?;
    if total > max_frame_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("guest frame is {total} bytes, max {max_frame_len}"),
        ));
    }

    let mut packet = Vec::with_capacity(total);
    for buf in bufs {
        packet.extend_from_slice(buf);
    }
    log::trace!("usernet: send {total} bytes from guest");

    state
        .device
        .queue_from_guest(packet)
        .map_err(io::Error::other)?;

    state.poll_iface();

    if state.device.has_packets_for_guest()
        && let Some(ref waker) = state.rx_waker
    {
        log::trace!("usernet: send() -> has RX data, firing waker");
        waker.wake();
    } else {
        log::trace!("usernet: send() -> no RX data after poll");
    }

    Ok(())
}

fn lease_guest_packet<P, D>(
    mut state: MutexGuard<'_, UserNetState<P, D>>,
) -> Option<UserNetRxPacket<'_, P, D>>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    state.poll_iface();

    let Some(packet) = state.device.dequeue_to_guest() else {
        log::trace!("usernet: rx_packet() -> no packet");
        return None;
    };
    let len = packet.len();
    Some(UserNetRxPacket {
        state,
        packet,
        committed: false,
        len,
    })
}

/// Leased usernet packet retained in the backend until committed.
pub struct UserNetRxPacket<'a, P = interceptor::DirectTcpPolicy, D = interceptor::NoDnsInterceptor>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    state: MutexGuard<'a, UserNetState<P, D>>,
    packet: Vec<u8>,
    committed: bool,
    len: usize,
}

impl<'a, P, D> NetRxPacketLease<'a> for UserNetRxPacket<'a, P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    fn packet(&self) -> &[u8] {
        &self.packet
    }

    fn commit(mut self) -> io::Result<()> {
        self.committed = true;
        debug_assert_eq!(self.packet.len(), self.len);

        let more = self.state.device.has_packets_for_guest();
        log::trace!(
            "usernet: rx_packet commit -> {} bytes, more={more}",
            self.len
        );
        if more && let Some(ref waker) = self.state.rx_waker {
            waker.wake();
        }
        Ok(())
    }
}

impl<P, D> Drop for UserNetRxPacket<'_, P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    fn drop(&mut self) {
        if !self.committed {
            let packet = std::mem::take(&mut self.packet);
            self.state.device.requeue_to_guest_front(packet);
        }
    }
}

// =============================================================================
// Errors
// =============================================================================

/// Errors that can occur in user-mode networking
#[derive(Debug, Error)]
pub enum UserNetError {
    #[error("Network I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Packet queue full")]
    QueueFull,

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),

    /// Returned by `accept_inbound*` when every port in the ephemeral range
    /// (49152–65535) is already assigned to a live connection. The NAT table
    /// is effectively saturated for inbound forwards; the caller should drop
    /// the stream rather than proceed — reusing a live port would silently
    /// overwrite the existing `ConnectionHandle` in the NAT map and cross
    /// packet streams between flows.
    #[error("Ephemeral port range exhausted for inbound forward")]
    EphemeralPortExhausted,

    #[error("Connection limit reached for {protocol:?}")]
    ConnectionLimitReached { protocol: Protocol },
}

/// Result type for user-mode networking operations
pub type UserNetResult<T> = Result<T, UserNetError>;

// =============================================================================
// Subnet Mask Helpers
// =============================================================================

/// Compute IPv4 subnet mask from prefix length (0..=32).
pub(crate) const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        return 0;
    }
    !0u32 << (32 - prefix_len)
}

/// Compute IPv6 subnet mask from prefix length (0..=128).
pub(crate) const fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        return 0;
    }
    !0u128 << (128 - prefix_len)
}

// =============================================================================
// User-mode Network Backend
// =============================================================================

/// Maximum pending packets in the shared collector channel
const MAX_PENDING_PACKETS: usize = 10_000;

/// User-mode network backend for virtio-net
///
/// This implements the `NetBackend` trait and provides NAT networking
/// for the guest without requiring special host privileges.
pub struct UserNetBackend<P = interceptor::DirectTcpPolicy, D = interceptor::NoDnsInterceptor>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    /// Internal state protected by mutex
    state: Mutex<UserNetState<P, D>>,
}

impl UserNetBackend<interceptor::DirectTcpPolicy, interceptor::NoDnsInterceptor> {
    /// Create a new user-mode network backend, returning an error on invalid config.
    pub fn try_new(config: UserNetConfig) -> Result<Self, UserNetError> {
        Self::try_new_with_tcp_policy(config, interceptor::DirectTcpPolicy)
    }
}

impl<P> UserNetBackend<P>
where
    P: interceptor::TcpConnectionPolicy,
{
    /// Create a new user-mode network backend with a construction-time TCP policy.
    pub fn try_new_with_tcp_policy(
        config: UserNetConfig,
        tcp_policy: P,
    ) -> Result<Self, UserNetError> {
        Self::try_new_with_policies(config, tcp_policy, interceptor::NoDnsInterceptor)
    }
}

impl<P, D> UserNetBackend<P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    /// Create a new user-mode network backend with construction-time TCP and DNS policies.
    pub fn try_new_with_policies(
        config: UserNetConfig,
        tcp_policy: P,
        dns_interceptor: D,
    ) -> Result<Self, UserNetError> {
        config.validate()?;
        Ok(Self::new_unchecked(config, tcp_policy, dns_interceptor))
    }

    /// Internal: create backend without validation (caller must validate).
    fn new_unchecked(config: UserNetConfig, tcp_policy: P, dns_interceptor: D) -> Self {
        let mut device = VirtualDevice::new(config.mtu);

        // Create smoltcp interface configuration
        let iface_config = IfaceConfig::new(HardwareAddress::Ethernet(EthernetAddress(
            config.gateway_mac,
        )));

        // Create interface
        let mut iface = Interface::new(iface_config, &mut device, now());

        // Configure IP address
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv4(config.gateway_ip),
                    config.prefix_len,
                ))
                .ok();
            addrs
                .push(IpCidr::new(
                    IpAddress::Ipv6(config.gateway_ipv6),
                    config.prefix_len_v6,
                ))
                .ok();
        });

        // Set up routing
        iface
            .routes_mut()
            .add_default_ipv4_route(config.gateway_ip)
            .ok();
        iface
            .routes_mut()
            .add_default_ipv6_route(Ipv6Address::from_octets(config.gateway_ipv6.octets()))
            .ok();

        // Create socket storage with capacity for MAX_SOCKETS
        let socket_storage: Vec<SocketStorage<'static>> =
            (0..MAX_SOCKETS).map(|_| SocketStorage::EMPTY).collect();
        let sockets = SocketSet::new(socket_storage);

        // Create NAT proxy for external connections
        // Calculate network prefix from gateway IP and prefix length
        let mask = ipv4_mask(config.prefix_len);
        let network_prefix = Ipv4Addr::from(u32::from(config.gateway_ip) & mask);
        let network_mask = Ipv4Addr::from(mask);

        let mask_v6 = ipv6_mask(config.prefix_len_v6);
        let network_prefix_v6 = Ipv6Addr::from(u128::from(config.gateway_ipv6) & mask_v6);

        let (collector_tx, collector_rx) = mpsc::channel(MAX_PENDING_PACKETS);

        let nat_proxy = NatProxy::new_with_tcp_policy(
            NatConfig {
                gateway_mac: config.gateway_mac,
                #[cfg(test)]
                guest_mac: config.guest_mac,
                gateway_ip: config.gateway_ip,
                #[cfg(test)]
                guest_ip: config.guest_ip,
                gateway_ipv6: config.gateway_ipv6,
                #[cfg(test)]
                guest_ipv6: config.guest_ipv6,
                prefix_len: config.prefix_len,
                network_prefix,
                network_mask,
                network_prefix_v6,
                prefix_len_v6: config.prefix_len_v6,
                mtu: config.mtu,
                host_egress: config.host_egress_authorizer(),
                collector_tx: collector_tx.clone(),
            },
            tcp_policy,
        );
        log::info!("NAT proxy initialized for external connections");

        let state = UserNetState {
            iface,
            sockets,
            device,
            nat_proxy,
            config,
            rx_waker: None,
            dns_interceptor,
            collector_tx,
            collector_rx,
            collector_backlog: VecDeque::new(),
            collector_backlog_bytes: 0,
            reliable_backlogged_count: 0,
            best_effort_dropped_count: 0,
            control_dropped_count: 0,
            reliable_backlog_overflow_count: 0,
            dns_semaphore: Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_DNS)),
        };

        Self {
            state: Mutex::new(state),
        }
    }

    /// Attach a DNS interceptor for UDP port 53 traffic.
    ///
    /// When set, all IPv4 DNS queries (regardless of destination IP) are passed
    /// to the interceptor. This enables DNS MITM when TLS interception is active.
    ///
    /// Note: IPv6 DNS forwarding is not yet implemented. The `dns_server_v6`
    /// config field is reserved for future use.
    #[must_use]
    pub fn with_dns_interceptor<D2>(self, interceptor: D2) -> UserNetBackend<P, D2>
    where
        D2: interceptor::DnsInterceptor,
    {
        UserNetBackend {
            state: Mutex::new(self.state.into_inner().with_dns_interceptor(interceptor)),
        }
    }

    /// Accept an inbound connection and forward it to a guest TCP port.
    ///
    /// The caller owns the listener/transport. This method bridges the
    /// provided stream to the guest by initiating a TCP handshake with the
    /// guest kernel on `guest_port`.
    ///
    /// The stream must support half-close semantics via
    /// `AsyncWrite::poll_shutdown` for proper TCP FIN handling (`TcpStream`,
    /// `UnixStream`, and `DuplexStream` all do).
    ///
    /// # Panics
    ///
    /// Panics if called outside an active tokio runtime context.
    // Reason: state lock spans the entire body — register_inbound +
    // waker wake must observe the same state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn accept_inbound(
        &self,
        stream: Box<dyn InboundStream + 'static>,
        guest_port: u16,
    ) -> UserNetResult<()> {
        let mut state = self.state.lock();
        let guest_ip = std::net::IpAddr::V4(state.config.guest_ip);
        let guest_mac = state.config.guest_mac;
        let gateway_ip = std::net::IpAddr::V4(state.config.gateway_ip);
        state
            .nat_proxy
            .register_inbound(stream, guest_port, guest_mac, guest_ip, gateway_ip)?;
        if let Some(ref waker) = state.rx_waker {
            waker.wake();
        }
        Ok(())
    }

    /// Accept a bidirectional UDP port forward to a guest port.
    ///
    /// Datagrams sent to `from_host` are injected into the guest as UDP
    /// packets from `gateway_ip:ephemeral`. Guest responses to that
    /// address are forwarded to `to_host`. The association has a 30s
    /// inactivity timeout.
    ///
    /// # Panics
    ///
    /// Panics if called outside an active tokio runtime context.
    // Reason: state lock spans the entire body — register_inbound_udp
    // must execute against the same state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn accept_inbound_udp(
        &self,
        from_host: tokio::sync::mpsc::Receiver<Vec<u8>>,
        to_host: tokio::sync::mpsc::Sender<Vec<u8>>,
        guest_port: u16,
    ) -> UserNetResult<()> {
        let mut state = self.state.lock();
        let guest_ip = std::net::IpAddr::V4(state.config.guest_ip);
        let guest_mac = state.config.guest_mac;
        let gateway_ip = std::net::IpAddr::V4(state.config.gateway_ip);
        state.nat_proxy.register_inbound_udp(
            from_host, to_host, guest_port, guest_mac, guest_ip, gateway_ip,
        )?;
        Ok(())
    }

    /// Process pending network activity
    ///
    /// This should be called periodically to handle connections.
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn poll(&self) -> UserNetResult<()> {
        let mut state = self.state.lock();
        state.poll_iface();
        Ok(())
    }

    /// Get the gateway IP address
    pub fn gateway_ip(&self) -> Ipv4Addr {
        self.state.lock().config.gateway_ip
    }

    /// Get the guest IP address
    pub fn guest_ip(&self) -> Ipv4Addr {
        self.state.lock().config.guest_ip
    }

    /// Get statistics about the network stack
    pub fn stats(&self) -> UserNetStats {
        let state = self.state.lock();
        UserNetStats {
            rx_queue_len: state.device.rx_queue.len(),
            tx_queue_len: state.device.tx_queue.len(),
            socket_count: state.sockets.iter().count(),
            reliable_backlogged_count: state.reliable_backlogged_count,
            best_effort_dropped_count: state.best_effort_dropped_count,
            control_dropped_count: state.control_dropped_count,
            reliable_backlog_overflow_count: state.reliable_backlog_overflow_count,
        }
    }
}

/// # Runtime requirement
///
/// All methods (`send`, `rx_packet`, `poll`) must be called from within an active
/// tokio runtime context. Internally, `poll_iface` may call `tokio::spawn`
/// for new TCP, UDP, or DNS connections. Calling without a runtime will panic.
impl<P, D> NetBackend for UserNetBackend<P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    type RxPacket<'a>
        = UserNetRxPacket<'a, P, D>
    where
        Self: 'a;

    fn guest_mac(&self) -> Option<[u8; 6]> {
        Some(self.state.lock().config.guest_mac)
    }

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let mut state = self.state.lock();
        send_guest_frame(&mut state, bufs)
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Ok(lease_guest_packet(self.state.lock()))
    }

    fn set_rx_waker(&self, waker: Option<RxWaker>) {
        let mut state = self.state.lock();
        state.nat_proxy.set_rx_waker(waker.clone());
        if let Some(old) = std::mem::replace(&mut state.rx_waker, waker) {
            old.cancel();
        }
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        // Always non-blocking
        Ok(())
    }
}

/// Shared handle to a [`UserNetBackend`] that implements [`NetBackend`].
///
/// Wraps `Arc<UserNetBackend>` to satisfy the orphan rule (`NetBackend` is
/// defined in `amla-core`, `Arc` in `std`). Delegates all trait methods
/// through the inner `Mutex`.
///
/// Use this when the backend must be shared between the VMM device
/// infrastructure and external callers that need `accept_inbound` /
/// `accept_inbound_udp`.
pub struct SharedBackend<P = interceptor::DirectTcpPolicy, D = interceptor::NoDnsInterceptor>(
    pub Arc<UserNetBackend<P, D>>,
)
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor;

impl<P, D> NetBackend for SharedBackend<P, D>
where
    P: interceptor::TcpConnectionPolicy,
    D: interceptor::DnsInterceptor,
{
    type RxPacket<'a>
        = UserNetRxPacket<'a, P, D>
    where
        Self: 'a;

    fn guest_mac(&self) -> Option<[u8; 6]> {
        Some(self.0.state.lock().config.guest_mac)
    }

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        let mut state = self.0.state.lock();
        send_guest_frame(&mut state, bufs)
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        Ok(lease_guest_packet(self.0.state.lock()))
    }

    fn set_rx_waker(&self, waker: Option<RxWaker>) {
        let mut state = self.0.state.lock();
        state.nat_proxy.set_rx_waker(waker.clone());
        if let Some(old) = std::mem::replace(&mut state.rx_waker, waker) {
            old.cancel();
        }
    }

    fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
        Ok(())
    }
}

/// Statistics about the network stack.
///
/// Usernet applies a bounded pressure policy at the final guest TX queue:
/// reliable TCP output is retained in a bounded side backlog, while UDP/DNS
/// datagrams and control packets are best-effort and may be dropped when the
/// guest stops draining RX. These counters make that degraded-service policy
/// visible to callers.
#[derive(Clone, Debug, Default)]
pub struct UserNetStats {
    /// Packets in RX queue (from guest)
    pub rx_queue_len: usize,

    /// Packets in TX queue (to guest)
    pub tx_queue_len: usize,

    /// Active sockets
    pub socket_count: usize,

    /// Reliable TCP packets retained because the final guest TX queue was full.
    pub reliable_backlogged_count: u64,

    /// Best-effort datagrams dropped because the final guest TX queue was full.
    pub best_effort_dropped_count: u64,

    /// Control packets dropped because the final guest TX queue was full.
    pub control_dropped_count: u64,

    /// Reliable TCP packets dropped after the bounded side backlog filled.
    pub reliable_backlog_overflow_count: u64,
}
