// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

// =============================================================================
// Crate-level lint configuration for network policy code
// =============================================================================
// Doc comments use backticks around protocol terms for clippy::doc_markdown
#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
// return_self_not_must_use: replaced with #[must_use] on builder types
// cast_possible_truncation: narrowed to local scopes where truncation is intentional

//! Policy-based network filtering for amla-vm
//!
//! This crate provides a network backend wrapper that enforces security policies
//! on network traffic. It implements a **fail-closed** model where:
//!
//! - Unknown protocols → DENY
//! - Parse errors → DENY
//! - Fragmented packets → DENY
//!
//! # Architecture
//!
//! `PolicyNetBackend` wraps another `NetBackend` (e.g., `UserNetBackend`) and
//! admits raw packets with `PacketNetworkPolicy` before they reach the
//! underlying network:
//!
//! ```text
//! Guest → VirtioNet → PolicyNetBackend → UserNetBackend → Host
//!                          │
//!                    ┌─────┴─────┐
//!                    │  Packet   │
//!                    │  Policy   │
//!                    └───────────┘
//! ```
//!
//! `PolicyNetBackend` accepts only [`PacketNetworkPolicy`]. It never stores an
//! evidence-aware [`NetworkPolicy`], never projects domain rules implicitly, and
//! never performs DNS/TLS/HTTP authorization. Stream policy owns L7 evidence
//! before usernet opens a host connection.
//!
//! # Example
//!
//! ```
//! use amla_policy_net::{NetworkPolicy, PacketNetworkPolicy};
//!
//! let policy = NetworkPolicy::builder()
//!     .allow_host_port(std::net::Ipv4Addr::new(93, 184, 216, 34), 443)
//!     .allow_domain("api.example.com", &[443])
//!     .build();
//! let packet_policy = PacketNetworkPolicy::from_network_policy(&policy);
//! assert_eq!(policy.rules.len(), 2);
//! assert_eq!(packet_policy.rules.len(), 1);
//!
//! // Then wrap an inner NetBackend with PolicyNetBackend:
//! // let backend = PolicyNetBackend::new(inner_backend, packet_policy);
//! ```

use amla_core::backends::{NetBackend, NetRxPacketLease, RxWaker};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::io::{self, IoSlice};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub mod config;
pub mod connection_table;
pub mod evidence;
mod inspectors;
pub mod manager;
pub mod packet;
pub mod policy;

pub use config::{
    ConfigError, HostRuleConfig, PolicyConfig, PolicyConfigBuilder, example_ai_agent_policy,
};
pub use evidence::{
    AllowReason, AllowedDnsQuery, DenyReason, DnsEvidenceError, DnsEvidenceRecord,
    DnsEvidenceStore, Evidence, EvidencePolicyDecision, EvidencePolicyEngine, InterceptKind,
    InterceptPlan, MutationPlan, PolicyPhase, StreamInterest, TcpFlow, TransportProtocol,
    TrustedDnsAnswer,
};
pub use inspectors::ConnectionKey;
pub use manager::{NetworkManager, VmNetworkHandle};
pub use policy::{
    HostRule, HostSpec, IpSubnet, Ipv4PrefixLen, Ipv4Subnet, Ipv6PrefixLen, Ipv6Subnet,
    NetworkPolicy, NetworkPolicyBuilder, PacketNetworkPolicy, PrefixLen, PrefixLenError,
};

// =============================================================================
// Constants
// =============================================================================

/// Default NAT gateway IP address for the user-mode network.
///
/// DHCP traffic is allowed to this address when `allow_dhcp` is enabled.
/// `10.0.2.2` is the slirp convention (shared with QEMU user-mode
/// networking) and matches the default used by `amla-vm-usernet`.
const DEFAULT_NAT_GATEWAY_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

// =============================================================================
// Packet Policy Decision
// =============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
enum PacketPolicyDecision {
    Allow,
    Deny(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum OutboundDisposition {
    Allow,
    Deny(String),
}

// =============================================================================
// Metrics
// =============================================================================

/// Metrics for policy enforcement
#[derive(Debug, Default)]
pub struct PolicyMetrics {
    /// Packets allowed
    pub allowed: AtomicU64,
    /// Packets denied
    pub denied: AtomicU64,
    /// Parse errors (fail-closed)
    pub parse_errors: AtomicU64,
    /// Fragmented packets (denied)
    pub fragmented: AtomicU64,
    /// Unknown protocols (denied)
    pub unknown_protocol: AtomicU64,
    /// Bad checksums (denied)
    pub bad_checksum: AtomicU64,
    /// Bytes allowed through
    pub bytes_allowed: AtomicU64,
    /// Bytes denied
    pub bytes_denied: AtomicU64,
}

impl PolicyMetrics {
    /// Create new metrics
    pub fn new() -> Self {
        Self::default()
    }

    /// Record an allowed packet
    pub fn record_allowed(&self, bytes: usize) {
        self.allowed.fetch_add(1, Ordering::Relaxed);
        self.bytes_allowed
            .fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Record a denied packet
    pub fn record_denied(&self, bytes: usize) {
        self.denied.fetch_add(1, Ordering::Relaxed);
        self.bytes_denied.fetch_add(bytes as u64, Ordering::Relaxed);
    }

    /// Get a snapshot of current metrics
    ///
    /// Note: this snapshot is **not** atomic across fields. Each counter is
    /// loaded with `Ordering::Relaxed`, so concurrent updates may produce a
    /// snapshot where, e.g., `allowed` reflects a more recent state than
    /// `bytes_allowed`. This is acceptable for metrics/observability.
    pub fn snapshot(&self) -> PolicyMetricsSnapshot {
        PolicyMetricsSnapshot {
            allowed: self.allowed.load(Ordering::Relaxed),
            denied: self.denied.load(Ordering::Relaxed),
            parse_errors: self.parse_errors.load(Ordering::Relaxed),
            fragmented: self.fragmented.load(Ordering::Relaxed),
            unknown_protocol: self.unknown_protocol.load(Ordering::Relaxed),
            bad_checksum: self.bad_checksum.load(Ordering::Relaxed),
            bytes_allowed: self.bytes_allowed.load(Ordering::Relaxed),
            bytes_denied: self.bytes_denied.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of policy metrics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyMetricsSnapshot {
    pub allowed: u64,
    pub denied: u64,
    pub parse_errors: u64,
    pub fragmented: u64,
    pub unknown_protocol: u64,
    pub bad_checksum: u64,
    pub bytes_allowed: u64,
    pub bytes_denied: u64,
}

// =============================================================================
// Audit Log Entry
// =============================================================================

/// Audit log entry for policy decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Timestamp (Unix millis)
    pub timestamp_ms: u64,
    /// Source IP
    pub src_ip: Option<IpAddr>,
    /// Destination IP
    pub dst_ip: Option<IpAddr>,
    /// Source port
    pub src_port: Option<u16>,
    /// Destination port
    pub dst_port: Option<u16>,
    /// Protocol (TCP=6, UDP=17)
    pub protocol: Option<u8>,
    /// Decision
    pub decision: String,
    /// Reason for decision
    pub reason: String,
    /// Packet size
    pub packet_size: usize,
}

// =============================================================================
// Policy Net Backend
// =============================================================================

/// Network backend that enforces raw packet security policy.
///
/// This wrapper parses IP packets, applies [`PacketNetworkPolicy`], and records
/// outbound TCP/UDP flows for inbound conntrack. It intentionally has no DNS,
/// TLS, HTTP, or MITM policy hooks. L7/domain authorization belongs to the
/// stream lifecycle through [`EvidencePolicyEngine`] and trusted interceptors.
///
/// ## Other traits
///
/// - **Domain-based rules** (`HostSpec::Domain`) are not packet admission
///   rules. They are evaluated by `EvidencePolicyEngine` from DNS/SNI/HTTP
///   evidence, not by `PolicyNetBackend`'s raw packet allowlist.
///
/// - **Inbound traffic** is checked against a connection tracking table.
///   Only packets that match an allowed outbound connection (by reversed 5-tuple)
///   are permitted. DHCP replies (from gateway, UDP `src_port=67`→`dst_port=68`) are allowed as a special case.
///   Inbound fragments are denied (fail-closed).
pub struct PolicyNetBackend<I: NetBackend> {
    /// Inner network backend
    inner: I,
    /// Raw packet admission policy.
    packet_policy: Arc<PacketNetworkPolicy>,
    /// Metrics
    metrics: Arc<PolicyMetrics>,
    /// Audit log (ring buffer, most recent entries)
    audit_log: Mutex<VecDeque<AuditEntry>>,
    /// Maximum audit log size
    max_audit_entries: usize,
    /// Connection tracking table for stateful inbound filtering
    conn_table: Mutex<connection_table::ConnectionTable>,
}

impl<I: NetBackend> PolicyNetBackend<I> {
    /// Create a new policy-enforcing backend from a raw packet policy.
    pub fn new(inner: I, policy: PacketNetworkPolicy) -> Self {
        Self::with_shared_packet_policy(inner, Arc::new(policy))
    }

    /// Create with shared raw packet policy.
    pub fn with_shared_packet_policy(inner: I, packet_policy: Arc<PacketNetworkPolicy>) -> Self {
        Self {
            inner,
            packet_policy,
            metrics: Arc::new(PolicyMetrics::new()),
            audit_log: Mutex::new(VecDeque::new()),
            max_audit_entries: 1000,
            conn_table: Mutex::new(connection_table::ConnectionTable::new()),
        }
    }

    /// Get a reference to the raw packet policy.
    pub fn packet_policy(&self) -> &PacketNetworkPolicy {
        &self.packet_policy
    }

    /// Get metrics handle
    pub fn metrics(&self) -> Arc<PolicyMetrics> {
        Arc::clone(&self.metrics)
    }

    /// Get recent audit entries
    pub fn audit_entries(&self) -> Vec<AuditEntry> {
        self.audit_log.lock().iter().cloned().collect()
    }

    /// Set maximum audit log size
    pub const fn set_max_audit_entries(&mut self, max: usize) {
        self.max_audit_entries = max;
    }

    /// Add audit entry
    fn audit(&self, entry: AuditEntry) {
        if self.max_audit_entries == 0 {
            return; // Auditing disabled
        }
        let mut log = self.audit_log.lock();
        if log.len() >= self.max_audit_entries {
            log.pop_front();
        }
        log.push_back(entry);
    }

    /// Evaluate policy for an outbound packet.
    fn evaluate_outbound(
        &self,
        packet: &[u8],
    ) -> (OutboundDisposition, Option<packet::ParsedPacket>) {
        // Check for ARP packets - always allow, essential for local networking
        // ARP is EtherType 0x0806 (bytes 12-13)
        if packet.len() >= 14 {
            let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
            if ethertype == 0x0806 {
                // ARP packet - always allow for local networking
                return (OutboundDisposition::Allow, None);
            }
        }

        // Parse Ethernet frame (IPv4/IPv6)
        let parsed = match packet::parse_ethernet_frame(packet) {
            Ok(p) => p,
            Err(e) => {
                self.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
                log::debug!("Parse error (fail-closed): {e}");
                return (OutboundDisposition::Deny(format!("parse error: {e}")), None);
            }
        };

        // Check for fragmentation (fail-closed)
        if parsed.is_fragmented {
            self.metrics.fragmented.fetch_add(1, Ordering::Relaxed);
            return (
                OutboundDisposition::Deny("fragmented packets not allowed".to_string()),
                Some(parsed),
            );
        }

        // Verify IP checksum
        if !parsed.ip_checksum_valid {
            self.metrics.bad_checksum.fetch_add(1, Ordering::Relaxed);
            return (
                OutboundDisposition::Deny("invalid IP checksum".to_string()),
                Some(parsed),
            );
        }

        // Check protocol
        let decision = match parsed.protocol {
            packet::IpProtocol::Tcp => {
                // Check against allowlist
                if self
                    .packet_policy
                    .is_allowed_ip(parsed.dst_ip, parsed.dst_port)
                {
                    OutboundDisposition::Allow
                } else {
                    OutboundDisposition::Deny(format!(
                        "destination {}:{} not in allowlist",
                        parsed.dst_ip, parsed.dst_port
                    ))
                }
            }
            packet::IpProtocol::Udp => {
                // Check for DHCP - uses UDP ports 67/68 to broadcast (255.255.255.255)
                // or to the QEMU user-mode networking gateway (10.0.2.2).
                // NOTE: The gateway IP is hardcoded for QEMU slirp/user-mode networking.
                // If a different virtual network topology is used, this may need to
                // become configurable via NetworkPolicy.
                let is_dhcp = (parsed.dst_port == 67 || parsed.dst_port == 68)
                    && matches!(
                        parsed.dst_ip,
                        IpAddr::V4(ip)
                            if ip == Ipv4Addr::BROADCAST || ip == DEFAULT_NAT_GATEWAY_IP
                    );

                let allowed = (is_dhcp && self.packet_policy.allow_dhcp)
                    || self
                        .packet_policy
                        .is_allowed_ip(parsed.dst_ip, parsed.dst_port);

                if allowed {
                    OutboundDisposition::Allow
                } else {
                    OutboundDisposition::Deny(format!(
                        "destination {}:{} not in allowlist",
                        parsed.dst_ip, parsed.dst_port
                    ))
                }
            }
            packet::IpProtocol::Icmp | packet::IpProtocol::Icmpv6 => {
                // Allow ICMP if policy permits
                if self.packet_policy.allow_icmp {
                    OutboundDisposition::Allow
                } else {
                    OutboundDisposition::Deny("ICMP not allowed".to_string())
                }
            }
            packet::IpProtocol::Unknown(proto) => {
                self.metrics
                    .unknown_protocol
                    .fetch_add(1, Ordering::Relaxed);
                OutboundDisposition::Deny(format!("unknown protocol: {proto}"))
            }
        };

        (decision, Some(parsed))
    }

    /// Evaluate policy for an inbound packet
    ///
    /// Uses stateful connection tracking to verify that inbound packets are
    /// responses to allowed outbound connections. Only packets whose reversed
    /// 5-tuple matches a recorded outbound entry are permitted. Special cases:
    /// - DHCP replies (UDP `src_port=67`, `dst_port=68`, from gateway) are allowed when `allow_dhcp` is set
    /// - ICMP is allowed/denied based on `allow_icmp` (no connection state)
    /// - Fragments are denied (fail-closed — can't extract 5-tuple)
    ///
    /// Returns the parsed packet alongside the decision so the caller can
    /// build audit entries without re-parsing.
    fn evaluate_inbound(
        &self,
        packet: &[u8],
    ) -> (
        PacketPolicyDecision,
        Option<packet::ParsedPacket>,
        &'static str,
    ) {
        let parsed = match packet::parse_ethernet_frame(packet) {
            Ok(p) => p,
            Err(e) => {
                self.metrics.parse_errors.fetch_add(1, Ordering::Relaxed);
                return (
                    PacketPolicyDecision::Deny(format!("parse error: {e}")),
                    None,
                    "",
                );
            }
        };

        // Verify checksum
        if !parsed.ip_checksum_valid {
            self.metrics.bad_checksum.fetch_add(1, Ordering::Relaxed);
            return (
                PacketPolicyDecision::Deny("invalid IP checksum".to_string()),
                Some(parsed),
                "",
            );
        }

        // Reject fragments (fail-closed — can't extract 5-tuple from fragments)
        if parsed.is_fragmented {
            self.metrics.fragmented.fetch_add(1, Ordering::Relaxed);
            return (
                PacketPolicyDecision::Deny("inbound fragment denied".to_string()),
                Some(parsed),
                "",
            );
        }

        // Allow ICMP/ICMPv6 if policy permits (connectionless, no tracking)
        if parsed.protocol.is_icmp() {
            return if self.packet_policy.allow_icmp {
                (
                    PacketPolicyDecision::Allow,
                    Some(parsed),
                    "ICMP allowed by policy",
                )
            } else {
                (
                    PacketPolicyDecision::Deny("inbound ICMP not allowed".to_string()),
                    Some(parsed),
                    "",
                )
            };
        }

        // Allow DHCP replies: UDP from server port 67 to client port 68.
        // DHCP outbound goes to broadcast (255.255.255.255) but replies are
        // unicast from the gateway, so strict reverse 5-tuple lookup would
        // drop them. Restrict to gateway IP to prevent arbitrary UDP with
        // src_port=67 from bypassing the firewall.
        if matches!(parsed.protocol, packet::IpProtocol::Udp)
            && parsed.src_port == 67
            && parsed.dst_port == 68
            && self.packet_policy.allow_dhcp
            && matches!(parsed.src_ip, IpAddr::V4(ip) if ip == DEFAULT_NAT_GATEWAY_IP)
        {
            return (
                PacketPolicyDecision::Allow,
                Some(parsed),
                "DHCP reply from gateway",
            );
        }

        // For TCP/UDP: check connection tracking table (reversed 5-tuple)
        let inbound_key = ConnectionKey::new(
            parsed.src_ip,
            parsed.dst_ip,
            parsed.src_port,
            parsed.dst_port,
            parsed.protocol.to_number(),
        );
        if self.conn_table.lock().allows_inbound(&inbound_key) {
            (PacketPolicyDecision::Allow, Some(parsed), "conntrack match")
        } else {
            (
                PacketPolicyDecision::Deny("no matching outbound connection".to_string()),
                Some(parsed),
                "",
            )
        }
    }

    fn audit_inbound(
        &self,
        parsed: Option<&packet::ParsedPacket>,
        decision: &PacketPolicyDecision,
        allow_reason: &'static str,
        packet_size: usize,
    ) {
        self.audit(AuditEntry {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            src_ip: parsed.map(|p| p.src_ip),
            dst_ip: parsed.map(|p| p.dst_ip),
            src_port: parsed.map(|p| p.src_port),
            dst_port: parsed.map(|p| p.dst_port),
            protocol: parsed.map(|p| p.protocol.to_number()),
            decision: match decision {
                PacketPolicyDecision::Allow => "ALLOW_INBOUND".to_string(),
                PacketPolicyDecision::Deny(_) => "DENY_INBOUND".to_string(),
            },
            reason: match decision {
                PacketPolicyDecision::Allow => allow_reason.to_string(),
                PacketPolicyDecision::Deny(reason) => reason.clone(),
            },
            packet_size,
        });
    }

    fn connection_key(parsed: &packet::ParsedPacket) -> Option<ConnectionKey> {
        match parsed.protocol {
            packet::IpProtocol::Tcp | packet::IpProtocol::Udp => Some(ConnectionKey::new(
                parsed.src_ip,
                parsed.dst_ip,
                parsed.src_port,
                parsed.dst_port,
                parsed.protocol.to_number(),
            )),
            _ => None,
        }
    }

    fn audit_outbound(
        &self,
        parsed: Option<&packet::ParsedPacket>,
        decision: &str,
        reason: String,
        packet_size: usize,
    ) {
        self.audit(AuditEntry {
            timestamp_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            src_ip: parsed.map(|p| p.src_ip),
            dst_ip: parsed.map(|p| p.dst_ip),
            src_port: parsed.map(|p| p.src_port),
            dst_port: parsed.map(|p| p.dst_port),
            protocol: parsed.map(|p| p.protocol.to_number()),
            decision: decision.to_string(),
            reason,
            packet_size,
        });
    }

    fn record_forwarded_outbound(&self, packet: &[u8]) {
        self.metrics.record_allowed(packet.len());
        let Ok(parsed) = packet::parse_ethernet_frame(packet) else {
            if packet.len() >= 14 && u16::from_be_bytes([packet[12], packet[13]]) == 0x0806 {
                self.audit_outbound(None, "ALLOW", "ARP passthrough".to_string(), packet.len());
            }
            return;
        };
        if !parsed.protocol.is_icmp()
            && let Some(key) = Self::connection_key(&parsed)
        {
            self.conn_table
                .lock()
                .record_outbound(key, parsed.tcp_flags);
        }
        self.audit_outbound(
            Some(&parsed),
            "ALLOW",
            "policy allowed".to_string(),
            packet.len(),
        );
        log::trace!(
            "ALLOW: {:?}:{} -> {:?}:{}",
            parsed.src_ip,
            parsed.src_port,
            parsed.dst_ip,
            parsed.dst_port
        );
    }
}

enum InboundAllowAudit {
    Arp {
        len: usize,
    },
    Packet {
        parsed: Option<packet::ParsedPacket>,
        allow_reason: &'static str,
        len: usize,
    },
}

pub struct PolicyRxPacket<'a, I: NetBackend + 'a> {
    backend: &'a PolicyNetBackend<I>,
    inner: I::RxPacket<'a>,
    audit: InboundAllowAudit,
}

impl<'a, I: NetBackend + 'a> NetRxPacketLease<'a> for PolicyRxPacket<'a, I> {
    fn packet(&self) -> &[u8] {
        self.inner.packet()
    }

    fn commit(self) -> io::Result<()> {
        self.inner.commit()?;
        match self.audit {
            InboundAllowAudit::Arp { len } => {
                self.backend.metrics.record_allowed(len);
                self.backend.audit(AuditEntry {
                    timestamp_ms: std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
                    src_ip: None,
                    dst_ip: None,
                    src_port: None,
                    dst_port: None,
                    protocol: None,
                    decision: "ALLOW_INBOUND".to_string(),
                    reason: "ARP passthrough".to_string(),
                    packet_size: len,
                });
            }
            InboundAllowAudit::Packet {
                parsed,
                allow_reason,
                len,
            } => {
                self.backend.audit_inbound(
                    parsed.as_ref(),
                    &PacketPolicyDecision::Allow,
                    allow_reason,
                    len,
                );
                self.backend.metrics.record_allowed(len);
            }
        }
        Ok(())
    }
}

impl<I: NetBackend> NetBackend for PolicyNetBackend<I> {
    type RxPacket<'a>
        = PolicyRxPacket<'a, I>
    where
        Self: 'a;

    fn guest_mac(&self) -> Option<[u8; 6]> {
        self.inner.guest_mac()
    }

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        // TOCTOU: flatten iovecs into a local copy for evaluation AND forwarding.
        // The iovecs may point into guest memory that can be concurrently mutated.
        // We evaluate the copy and forward the same copy to inner.send().
        let packet: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
        let packet_len = packet.len();

        let (decision, parsed) = self.evaluate_outbound(&packet);
        match decision {
            OutboundDisposition::Allow => {
                // Send the same copy we evaluated — not the original iovecs.
                self.inner.send(&[IoSlice::new(&packet)])?;
                self.record_forwarded_outbound(&packet);
                Ok(())
            }
            OutboundDisposition::Deny(reason) => {
                self.metrics.record_denied(packet_len);
                self.audit_outbound(parsed.as_ref(), "DENY", reason, packet_len);
                Ok(())
            }
        }
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        loop {
            let Some(lease) = self.inner.rx_packet()? else {
                return Ok(None);
            };

            let packet = lease.packet();
            let len = packet.len();
            if len >= 14 {
                let ethertype = u16::from_be_bytes([packet[12], packet[13]]);
                if ethertype == 0x0806 {
                    return Ok(Some(PolicyRxPacket {
                        backend: self,
                        inner: lease,
                        audit: InboundAllowAudit::Arp { len },
                    }));
                }
            }

            let (decision, parsed, allow_reason) = self.evaluate_inbound(packet);
            match decision {
                PacketPolicyDecision::Allow => {
                    return Ok(Some(PolicyRxPacket {
                        backend: self,
                        inner: lease,
                        audit: InboundAllowAudit::Packet {
                            parsed,
                            allow_reason,
                            len,
                        },
                    }));
                }
                PacketPolicyDecision::Deny(reason) => {
                    self.audit_inbound(
                        parsed.as_ref(),
                        &PacketPolicyDecision::Deny(reason.clone()),
                        allow_reason,
                        len,
                    );
                    self.metrics.record_denied(len);
                    log::debug!("DENY inbound: {reason}");
                    lease.commit()?;
                }
            }
        }
    }

    fn set_rx_waker(&self, waker: Option<RxWaker>) {
        self.inner.set_rx_waker(waker);
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use amla_constants::net::DEFAULT_GUEST_MAC;

    use super::*;
    use std::sync::{Mutex, MutexGuard};

    // =========================================================================
    // Mock Backend for Testing
    // =========================================================================

    /// Mock backend that captures packets
    struct MockBackend {
        sent: Mutex<Vec<Vec<u8>>>,
        recv_queue: Mutex<Vec<Vec<u8>>>,
    }

    impl MockBackend {
        fn new() -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                recv_queue: Mutex::new(Vec::new()),
            }
        }

        fn with_recv_queue(recv_queue: Vec<Vec<u8>>) -> Self {
            Self {
                sent: Mutex::new(Vec::new()),
                recv_queue: Mutex::new(recv_queue),
            }
        }
    }

    impl NetBackend for MockBackend {
        type RxPacket<'a> = MockRxPacket<'a>;

        fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
            let packet: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
            self.sent.lock().unwrap().push(packet);
            Ok(())
        }

        fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
            let guard = self.recv_queue.lock().unwrap();
            if guard.is_empty() {
                Ok(None)
            } else {
                Ok(Some(MockRxPacket { guard }))
            }
        }

        fn set_nonblocking(&self, _: bool) -> io::Result<()> {
            Ok(())
        }
    }

    struct MockRxPacket<'a> {
        guard: MutexGuard<'a, Vec<Vec<u8>>>,
    }

    impl NetRxPacketLease<'_> for MockRxPacket<'_> {
        fn packet(&self) -> &[u8] {
            self.guard
                .last()
                .expect("lease exists only for nonempty queue")
        }

        fn commit(mut self) -> io::Result<()> {
            let _ = self.guard.pop();
            Ok(())
        }
    }

    fn recv_packet<B: NetBackend>(backend: &B, buf: &mut [u8]) -> io::Result<usize> {
        let Some(lease) = backend.rx_packet()? else {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no packets"));
        };
        let packet = lease.packet();
        if buf.len() < packet.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "receive buffer too small",
            ));
        }
        let len = packet.len();
        buf[..len].copy_from_slice(packet);
        lease.commit()?;
        Ok(len)
    }

    // =========================================================================
    // PolicyNetBackend Creation Tests
    // =========================================================================

    #[test]
    fn test_policy_net_backend_creation() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        assert_eq!(backend.metrics().snapshot().allowed, 0);
        assert_eq!(backend.metrics().snapshot().denied, 0);
    }

    #[test]
    fn test_policy_net_backend_with_shared_packet_policy() {
        let policy = Arc::new(
            NetworkPolicy::builder()
                .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
                .build()
                .to_packet_policy(),
        );

        let inner1 = MockBackend::new();
        let inner2 = MockBackend::new();

        let backend1 = PolicyNetBackend::with_shared_packet_policy(inner1, Arc::clone(&policy));
        let backend2 = PolicyNetBackend::with_shared_packet_policy(inner2, Arc::clone(&policy));

        assert_eq!(
            backend1.packet_policy().rules.len(),
            backend2.packet_policy().rules.len()
        );
        assert!(
            backend1
                .packet_policy()
                .is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53)
        );
        assert!(
            backend2
                .packet_policy()
                .is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53)
        );
    }

    #[test]
    fn test_policy_net_backend_packet_policy_accessor() {
        let policy = NetworkPolicy::builder()
            .name("test-policy")
            .allow_domain("api.example.com", &[443])
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .enable_icmp()
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = backend.packet_policy();
        assert_eq!(packet.name, Some("test-policy".to_string()));
        assert!(packet.allow_icmp);
        assert_eq!(packet.rules.len(), 1);
        assert!(packet.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(
            !packet
                .rules
                .iter()
                .any(|rule| matches!(rule.host, HostSpec::Domain(_)))
        );
    }

    // =========================================================================
    // Fail-Closed (Empty Policy Denies All) Tests
    // =========================================================================

    #[test]
    fn test_empty_policy_denies_all() {
        let policy = NetworkPolicy::builder().build(); // Empty = deny all
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create a minimal TCP packet to 1.2.3.4:443
        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        // Should "succeed" (packet dropped, not error)
        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        // But should be denied
        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.denied, 1);
        assert_eq!(metrics.allowed, 0);
    }

    #[test]
    fn test_empty_policy_denies_udp() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 12345, 53);

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.denied, 1);
        assert_eq!(metrics.allowed, 0);
    }

    #[test]
    fn test_empty_policy_denies_multiple_packets() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Send multiple packets to different destinations
        for i in 1..=5 {
            let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, i], 12345, 443);
            drop(backend.send(&[IoSlice::new(&packet)]));
        }

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.denied, 5);
        assert_eq!(metrics.allowed, 0);
    }

    // =========================================================================
    // Allowed Host Tests
    // =========================================================================

    #[test]
    fn test_allowed_host_passes() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1);
        assert_eq!(metrics.denied, 0);
    }

    #[test]
    fn test_multiple_allowed_hosts() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
            .allow_host_port(Ipv4Addr::new(9, 9, 9, 9), 53)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // All three should be allowed
        let pkt = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 12345, 53);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        let pkt = packet::tests::make_udp_packet([10, 0, 2, 15], [1, 1, 1, 1], 12345, 53);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        let pkt = packet::tests::make_udp_packet([10, 0, 2, 15], [9, 9, 9, 9], 12345, 53);
        drop(backend.send(&[IoSlice::new(&pkt)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 3);
        assert_eq!(metrics.denied, 0);
    }

    #[test]
    fn test_allowed_udp_passes() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 54321, 53);

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1);
    }

    #[test]
    fn test_allowed_subnet_passes() {
        let policy = NetworkPolicy::builder()
            .allow_subnet(
                Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 0), 8).unwrap(),
                &[22],
            )
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // All 10.x.x.x addresses should be allowed on port 22
        let pkt = packet::tests::make_tcp_packet([192, 168, 1, 100], [10, 1, 2, 3], 12345, 22);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        let pkt =
            packet::tests::make_tcp_packet([192, 168, 1, 100], [10, 255, 255, 255], 12345, 22);
        drop(backend.send(&[IoSlice::new(&pkt)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 2);
        assert_eq!(metrics.denied, 0);
    }

    // =========================================================================
    // Audit Log Tests
    // =========================================================================

    #[test]
    fn test_audit_log() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [8, 8, 8, 8], 12345, 443);

        drop(backend.send(&[IoSlice::new(&packet)]));

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].decision, "DENY");
        assert_eq!(
            entries[0].dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))
        );
        assert_eq!(entries[0].dst_port, Some(443));
    }

    #[test]
    fn test_audit_log_records_allowed() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&packet)]));

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].decision, "ALLOW");
        assert_eq!(
            entries[0].dst_ip,
            Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
    }

    #[test]
    fn test_audit_log_multiple_entries() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Allowed packet
        let pkt = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        // Denied packet
        let pkt = packet::tests::make_tcp_packet([10, 0, 2, 15], [5, 6, 7, 8], 12345, 80);
        drop(backend.send(&[IoSlice::new(&pkt)]));

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].decision, "ALLOW");
        assert_eq!(entries[1].decision, "DENY");
    }

    #[test]
    fn test_audit_log_max_entries() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let mut backend = PolicyNetBackend::new(inner, policy.to_packet_policy());
        backend.set_max_audit_entries(5);

        // Send more than max entries
        for i in 0u8..10 {
            let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, i], 12345, 443);
            drop(backend.send(&[IoSlice::new(&packet)]));
        }

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 5); // Should cap at max
    }

    #[test]
    fn test_audit_log_max_zero_no_panic() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let mut backend = PolicyNetBackend::new(inner, policy.to_packet_policy());
        backend.set_max_audit_entries(0);

        // Send a packet - should not panic
        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        // No audit entries since auditing is disabled
        assert!(backend.audit_entries().is_empty());
    }

    #[test]
    fn test_audit_log_records_timestamp() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&packet)]));

        let entries = backend.audit_entries();
        assert!(!entries.is_empty());
        assert!(entries[0].timestamp_ms > 0);
    }

    // =========================================================================
    // Protocol Filtering Tests
    // =========================================================================

    #[test]
    fn test_deny_unknown_protocol() {
        // SCTP (protocol 132) should be denied
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create a packet with SCTP protocol (132)
        let mut packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        // Change protocol from TCP (6) to SCTP (132)
        packet[14 + 9] = 132;
        // Recalculate IP checksum (zero it first, then calculate)
        packet[14 + 10] = 0;
        packet[14 + 11] = 0;
        let checksum = calc_ip_checksum(&packet[14..34]);
        packet[14 + 10] = (checksum >> 8) as u8;
        packet[14 + 11] = (checksum & 0xFF) as u8;

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok()); // Returns OK but packet is dropped

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.unknown_protocol, 1);
        assert_eq!(metrics.denied, 1);
        assert_eq!(metrics.allowed, 0);
    }

    #[test]
    fn test_deny_fragmented_packets() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create a fragmented packet (even to an allowed destination)
        let packet = packet::tests::make_fragmented_packet([10, 0, 2, 15], [1, 2, 3, 4]);

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.fragmented, 1);
        assert_eq!(metrics.denied, 1);
    }

    #[test]
    fn test_deny_bad_checksum() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create a packet with bad checksum
        let packet = packet::tests::make_bad_checksum_packet([10, 0, 2, 15], [1, 2, 3, 4]);

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.bad_checksum, 1);
        assert_eq!(metrics.denied, 1);
    }

    #[test]
    fn test_deny_malformed_packet() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Send a truncated packet
        let packet = vec![0u8; 10]; // Way too short

        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.parse_errors, 1);
        assert_eq!(metrics.denied, 1);
    }

    // =========================================================================
    // ICMP Tests
    // =========================================================================

    #[test]
    fn test_icmp_denied_by_default() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create an ICMP packet
        let mut packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [8, 8, 8, 8], 0, 0);
        // Change protocol to ICMP (1) and truncate to minimal ICMP
        packet[14 + 9] = 1;
        packet[14 + 10] = 0;
        packet[14 + 11] = 0;
        let checksum = calc_ip_checksum(&packet[14..34]);
        packet[14 + 10] = (checksum >> 8) as u8;
        packet[14 + 11] = (checksum & 0xFF) as u8;

        drop(backend.send(&[IoSlice::new(&packet)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.denied, 1);
    }

    #[test]
    fn test_icmp_allowed_when_enabled() {
        let policy = NetworkPolicy::builder().enable_icmp().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Create an ICMP packet
        let mut packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [8, 8, 8, 8], 0, 0);
        packet[14 + 9] = 1; // ICMP protocol
        packet[14 + 10] = 0;
        packet[14 + 11] = 0;
        let checksum = calc_ip_checksum(&packet[14..34]);
        packet[14 + 10] = (checksum >> 8) as u8;
        packet[14 + 11] = (checksum & 0xFF) as u8;

        drop(backend.send(&[IoSlice::new(&packet)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1);
    }

    // =========================================================================
    // Packet Forwarding Tests
    // =========================================================================

    #[test]
    fn test_packet_forwarded_to_inner_backend() {
        use std::sync::{Arc, Mutex as StdMutex};

        // Track what gets sent to inner backend
        struct TrackingBackend {
            sent_packets: Arc<StdMutex<Vec<Vec<u8>>>>,
        }

        impl NetBackend for TrackingBackend {
            type RxPacket<'a> = amla_core::backends::NoRxPacket;

            fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
                let packet: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
                self.sent_packets.lock().unwrap().push(packet);
                Ok(())
            }

            fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
                Ok(None)
            }

            fn set_nonblocking(&self, _: bool) -> io::Result<()> {
                Ok(())
            }
        }

        let sent_packets = Arc::new(StdMutex::new(Vec::new()));
        let tracking = TrackingBackend {
            sent_packets: Arc::clone(&sent_packets),
        };

        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let backend = PolicyNetBackend::new(tracking, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        drop(backend.send(&[IoSlice::new(&packet)]));

        // Verify packet was forwarded to inner backend
        let sent_snapshot: Vec<Vec<u8>> = sent_packets.lock().unwrap().clone();
        assert_eq!(sent_snapshot.len(), 1);
        assert_eq!(sent_snapshot[0], packet);
    }

    #[test]
    fn test_denied_packet_not_forwarded() {
        use std::sync::{Arc, Mutex as StdMutex};

        struct TrackingBackend {
            sent_packets: Arc<StdMutex<Vec<Vec<u8>>>>,
        }

        impl NetBackend for TrackingBackend {
            type RxPacket<'a> = amla_core::backends::NoRxPacket;

            fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
                let packet: Vec<u8> = bufs.iter().flat_map(|b| b.iter().copied()).collect();
                self.sent_packets.lock().unwrap().push(packet);
                Ok(())
            }

            fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
                Ok(None)
            }

            fn set_nonblocking(&self, _: bool) -> io::Result<()> {
                Ok(())
            }
        }

        let sent_packets = Arc::new(StdMutex::new(Vec::new()));
        let tracking = TrackingBackend {
            sent_packets: Arc::clone(&sent_packets),
        };

        let policy = NetworkPolicy::builder().build(); // Empty - denies all
        let backend = PolicyNetBackend::new(tracking, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);

        drop(backend.send(&[IoSlice::new(&packet)]));

        // Verify packet was NOT forwarded
        let sent_len = sent_packets.lock().unwrap().len();
        assert_eq!(sent_len, 0);
    }

    // =========================================================================
    // Metrics Tests
    // =========================================================================

    #[test]
    fn test_metrics_snapshot() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Send some allowed and denied packets
        let pkt = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        let pkt = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&pkt)]));
        let pkt = packet::tests::make_tcp_packet([10, 0, 2, 15], [5, 6, 7, 8], 12345, 80);
        drop(backend.send(&[IoSlice::new(&pkt)]));

        let snapshot = backend.metrics().snapshot();
        assert_eq!(snapshot.allowed, 2);
        assert_eq!(snapshot.denied, 1);
    }

    #[test]
    fn test_metrics_bytes_tracking() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let allowed_packet =
            packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let denied_packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [5, 6, 7, 8], 12345, 80);

        let allowed_size = allowed_packet.len() as u64;
        let denied_size = denied_packet.len() as u64;

        drop(backend.send(&[IoSlice::new(&allowed_packet)]));
        drop(backend.send(&[IoSlice::new(&denied_packet)]));

        let snapshot = backend.metrics().snapshot();
        assert_eq!(snapshot.bytes_allowed, allowed_size);
        assert_eq!(snapshot.bytes_denied, denied_size);
    }

    #[test]
    fn test_metrics_new() {
        let metrics = PolicyMetrics::new();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.allowed, 0);
        assert_eq!(snapshot.denied, 0);
        assert_eq!(snapshot.parse_errors, 0);
        assert_eq!(snapshot.fragmented, 0);
        assert_eq!(snapshot.unknown_protocol, 0);
        assert_eq!(snapshot.bad_checksum, 0);
        assert_eq!(snapshot.bytes_allowed, 0);
        assert_eq!(snapshot.bytes_denied, 0);
    }

    #[test]
    fn test_metrics_record_allowed() {
        let metrics = PolicyMetrics::new();
        metrics.record_allowed(100);
        metrics.record_allowed(200);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.allowed, 2);
        assert_eq!(snapshot.bytes_allowed, 300);
    }

    #[test]
    fn test_metrics_record_denied() {
        let metrics = PolicyMetrics::new();
        metrics.record_denied(50);
        metrics.record_denied(75);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.denied, 2);
        assert_eq!(snapshot.bytes_denied, 125);
    }

    // =========================================================================
    // PolicyMetricsSnapshot Serialization Tests
    // =========================================================================

    #[test]
    fn test_metrics_snapshot_serialization() {
        let snapshot = PolicyMetricsSnapshot {
            allowed: 10,
            denied: 5,
            bytes_allowed: 1000,
            bytes_denied: 500,
            ..Default::default()
        };

        let json = serde_json::to_string(&snapshot).unwrap();
        let parsed: PolicyMetricsSnapshot = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.allowed, 10);
        assert_eq!(parsed.denied, 5);
        assert_eq!(parsed.bytes_allowed, 1000);
        assert_eq!(parsed.bytes_denied, 500);
    }

    // =========================================================================
    // AuditEntry Tests
    // =========================================================================

    #[test]
    fn test_audit_entry_serialization() {
        let entry = AuditEntry {
            timestamp_ms: 1_234_567_890,
            src_ip: Some(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15))),
            dst_ip: Some(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
            src_port: Some(12345),
            dst_port: Some(53),
            protocol: Some(17),
            decision: "ALLOW".to_string(),
            reason: "policy allowed".to_string(),
            packet_size: 64,
        };

        let json = serde_json::to_string(&entry).unwrap();
        let parsed: AuditEntry = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.timestamp_ms, 1_234_567_890);
        assert_eq!(parsed.decision, "ALLOW");
        assert_eq!(parsed.packet_size, 64);
    }

    // =========================================================================
    // PacketPolicyDecision Tests
    // =========================================================================

    #[test]
    fn test_policy_decision_equality() {
        assert_eq!(PacketPolicyDecision::Allow, PacketPolicyDecision::Allow);
        assert_eq!(
            PacketPolicyDecision::Deny("test".to_string()),
            PacketPolicyDecision::Deny("test".to_string())
        );
        assert_ne!(
            PacketPolicyDecision::Allow,
            PacketPolicyDecision::Deny("test".to_string())
        );
        assert_ne!(
            PacketPolicyDecision::Deny("a".to_string()),
            PacketPolicyDecision::Deny("b".to_string())
        );
    }

    // =========================================================================
    // Receive Path Tests
    // =========================================================================

    #[test]
    fn test_recv_allows_response_after_outbound() {
        // Policy allows 8.8.8.8:53
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        let recv_queue = vec![packet::tests::make_tcp_packet(
            [8, 8, 8, 8],
            [10, 0, 2, 15],
            53,
            12345,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // First, send an outbound packet so the connection is tracked
        let outbound = packet::tests::make_tcp_packet([10, 0, 2, 15], [8, 8, 8, 8], 12345, 53);
        drop(backend.send(&[IoSlice::new(&outbound)]));

        // Now the inbound response should be allowed (matching conntrack entry)
        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_ok());
    }

    #[test]
    fn test_recv_denies_without_outbound() {
        // Empty policy — no outbound allowed, so no conntrack entries
        let policy = NetworkPolicy::builder().build();
        let recv_queue = vec![packet::tests::make_tcp_packet(
            [8, 8, 8, 8],
            [10, 0, 2, 15],
            53,
            12345,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // No matching outbound → denied
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_recv_denies_bad_checksum_inbound() {
        let policy = NetworkPolicy::builder().build();
        let recv_queue = vec![packet::tests::make_bad_checksum_packet(
            [8, 8, 8, 8],
            [10, 0, 2, 15],
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // Bad checksum should be denied
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn test_recv_denied_packet_not_written_to_iovecs() {
        // Verify that when an inbound packet is denied, the caller's iovecs
        // remain untouched — the staging buffer prevents data leakage.
        let policy = NetworkPolicy::builder().build(); // empty = deny all
        let recv_queue = vec![packet::tests::make_tcp_packet(
            [8, 8, 8, 8],
            [10, 0, 2, 15],
            53,
            12345,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Fill buffer with a sentinel pattern
        let mut buf = vec![0xAA_u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // Must be denied
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);

        // Buffer must still contain the sentinel — no packet data leaked
        assert!(
            buf.iter().all(|&b| b == 0xAA),
            "denied packet must not be written to caller's iovecs"
        );
    }

    // =========================================================================
    // RX lease tests
    // =========================================================================

    #[test]
    fn test_rx_packet_leases_allowed_packet() {
        let policy = NetworkPolicy::builder().build();
        let packet = make_arp_packet();
        let len = packet.len();
        let inner = MockBackend::with_recv_queue(vec![packet]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let leased_len = {
            let lease = backend
                .rx_packet()
                .unwrap()
                .expect("allowed packet should be leased");
            lease.packet().len()
        };
        assert_eq!(leased_len, len);
    }

    // =========================================================================
    // set_nonblocking Tests
    // =========================================================================

    #[test]
    fn test_set_nonblocking_delegates_to_inner() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct NonblockingBackend {
            nonblocking: Arc<AtomicBool>,
        }

        impl NetBackend for NonblockingBackend {
            type RxPacket<'a> = amla_core::backends::NoRxPacket;

            fn send(&self, _: &[IoSlice<'_>]) -> io::Result<()> {
                Ok(())
            }
            fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
                Ok(None)
            }
            fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
                self.nonblocking.store(nonblocking, Ordering::SeqCst);
                Ok(())
            }
        }

        let nonblocking = Arc::new(AtomicBool::new(false));
        let policy = NetworkPolicy::builder().build();
        let inner = NonblockingBackend {
            nonblocking: Arc::clone(&nonblocking),
        };
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        backend.set_nonblocking(true).unwrap();
        assert!(nonblocking.load(Ordering::SeqCst));

        backend.set_nonblocking(false).unwrap();
        assert!(!nonblocking.load(Ordering::SeqCst));
    }

    // =========================================================================
    // ARP Handling Tests
    // =========================================================================

    /// Helper to build a minimal ARP packet for testing.
    fn make_arp_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 42];
        // Destination MAC
        packet[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
        // Source MAC
        packet[6..12].copy_from_slice(&DEFAULT_GUEST_MAC);
        // EtherType: ARP
        packet[12] = 0x08;
        packet[13] = 0x06;
        packet
    }

    #[test]
    fn test_arp_packets_always_allowed_outbound() {
        let policy = NetworkPolicy::builder().build(); // Empty policy
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = make_arp_packet();
        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_ok());

        // ARP should be allowed
        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1);
        assert_eq!(metrics.denied, 0);
    }

    #[test]
    fn test_arp_outbound_audited() {
        let policy = NetworkPolicy::builder().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = make_arp_packet();
        drop(backend.send(&[IoSlice::new(&packet)]));

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 1, "ARP outbound must produce an audit entry");
        assert_eq!(entries[0].decision, "ALLOW");
        assert!(entries[0].src_ip.is_none(), "ARP has no IP-layer metadata");
    }

    #[test]
    fn test_arp_inbound_audited() {
        let policy = NetworkPolicy::builder().build();
        let arp_reply = make_arp_packet();
        let inner = MockBackend::with_recv_queue(vec![arp_reply]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_ok());

        let entries = backend.audit_entries();
        assert_eq!(entries.len(), 1, "ARP inbound must produce an audit entry");
        assert_eq!(entries[0].decision, "ALLOW_INBOUND");
        assert_eq!(entries[0].reason, "ARP passthrough");
    }

    // =========================================================================
    // Connection Tracking Integration Tests
    // =========================================================================

    #[test]
    fn test_inbound_fragment_rejected() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        // Send an outbound to create a conntrack entry
        let recv_queue = vec![packet::tests::make_fragmented_packet(
            [1, 2, 3, 4],
            [10, 0, 2, 15],
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Record an outbound connection first
        let outbound = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&outbound)]));

        // Even with a conntrack entry, inbound fragments are denied
        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_err());

        let metrics = backend.metrics().snapshot();
        assert!(metrics.fragmented > 0);
    }

    #[test]
    fn test_dhcp_reply_allowed() {
        let policy = NetworkPolicy::builder().enable_dhcp().build();
        // Inbound DHCP reply: server port 67 → client port 68
        let recv_queue = vec![packet::tests::make_udp_packet(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            67,
            68,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // DHCP reply should be allowed without conntrack entry
        assert!(result.is_ok());
    }

    #[test]
    fn test_dhcp_reply_denied_when_dhcp_disabled() {
        let policy = NetworkPolicy::builder().build(); // DHCP disabled by default
        let recv_queue = vec![packet::tests::make_udp_packet(
            [10, 0, 2, 2],
            [10, 0, 2, 15],
            67,
            68,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // No DHCP allowed + no conntrack entry → denied
        assert!(result.is_err());
    }

    #[test]
    fn test_dhcp_reply_denied_from_non_gateway_ip() {
        // Regression test: UDP src_port=67 from a non-gateway IP must NOT
        // bypass the firewall (CVE-like DHCP bypass).
        let policy = NetworkPolicy::builder().enable_dhcp().build();
        let recv_queue = vec![packet::tests::make_udp_packet(
            [192, 168, 1, 100], // attacker, NOT the gateway (10.0.2.2)
            [10, 0, 2, 15],
            67,
            68,
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // Must be denied: wrong source IP
        assert!(result.is_err());
    }

    #[test]
    fn test_dhcp_reply_denied_wrong_dst_port() {
        // UDP src_port=67 from gateway but dst_port is NOT 68 (DHCP client port)
        let policy = NetworkPolicy::builder().enable_dhcp().build();
        let recv_queue = vec![packet::tests::make_udp_packet(
            [10, 0, 2, 2], // gateway
            [10, 0, 2, 15],
            67,
            9999, // NOT port 68
        )];
        let inner = MockBackend::with_recv_queue(recv_queue);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);

        // Must be denied: wrong destination port
        assert!(result.is_err());
    }

    #[test]
    fn test_conntrack_udp_timeout_eviction() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Send outbound UDP to create entry
        let outbound = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 54321, 53);
        drop(backend.send(&[IoSlice::new(&outbound)]));

        // Expire entry: set timeout to 0 and backdate by 1 second
        {
            let mut table = backend.conn_table.lock();
            assert_eq!(table.len(), 1);
            table.udp_timeout_secs = 0;
            table.backdate_all(std::time::Duration::from_secs(1));
        }

        // Direct check: the expired entry should be rejected
        let inbound_key = ConnectionKey::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)),
            53,
            54321,
            17,
        );
        assert!(!backend.conn_table.lock().allows_inbound(&inbound_key));
        assert_eq!(backend.conn_table.lock().len(), 0);
    }

    #[test]
    fn test_conntrack_table_bounded() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // Limit table to 2 entries
        backend.conn_table.lock().max_entries = 2;

        // Send 3 outbound packets with different source ports
        for port in [1001u16, 1002, 1003] {
            let pkt = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], port, 53);
            drop(backend.send(&[IoSlice::new(&pkt)]));
        }

        // Only 2 entries should exist (third was dropped)
        assert_eq!(backend.conn_table.lock().len(), 2);
    }

    #[test]
    fn test_inbound_icmp_allowed_with_policy() {
        let policy = NetworkPolicy::builder().enable_icmp().build();
        // Create an ICMP packet (change protocol to 1)
        let mut recv_pkt = packet::tests::make_tcp_packet([8, 8, 8, 8], [10, 0, 2, 15], 0, 0);
        recv_pkt[14 + 9] = 1; // ICMP
        recv_pkt[14 + 10] = 0;
        recv_pkt[14 + 11] = 0;
        let checksum = calc_ip_checksum(&recv_pkt[14..34]);
        recv_pkt[14 + 10] = (checksum >> 8) as u8;
        recv_pkt[14 + 11] = (checksum & 0xFF) as u8;

        let inner = MockBackend::with_recv_queue(vec![recv_pkt]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_ok(), "ICMP should be allowed with enable_icmp()");
    }

    #[test]
    fn test_inbound_icmp_denied_by_default() {
        let policy = NetworkPolicy::builder().build(); // ICMP disabled
        let mut recv_pkt = packet::tests::make_tcp_packet([8, 8, 8, 8], [10, 0, 2, 15], 0, 0);
        recv_pkt[14 + 9] = 1; // ICMP
        recv_pkt[14 + 10] = 0;
        recv_pkt[14 + 11] = 0;
        let checksum = calc_ip_checksum(&recv_pkt[14..34]);
        recv_pkt[14 + 10] = (checksum >> 8) as u8;
        recv_pkt[14 + 11] = (checksum & 0xFF) as u8;

        let inner = MockBackend::with_recv_queue(vec![recv_pkt]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_err(), "ICMP should be denied by default");
    }

    // =========================================================================
    // Outbound DHCP Tests
    // =========================================================================

    #[test]
    fn test_outbound_dhcp_to_broadcast_allowed() {
        let policy = NetworkPolicy::builder().enable_dhcp().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // DHCP discover: client → broadcast:67
        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [255, 255, 255, 255], 68, 67);
        drop(backend.send(&[IoSlice::new(&packet)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1, "DHCP to broadcast should be allowed");
    }

    #[test]
    fn test_outbound_dhcp_to_gateway_allowed() {
        let policy = NetworkPolicy::builder().enable_dhcp().build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // DHCP to QEMU gateway (10.0.2.2)
        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [10, 0, 2, 2], 68, 67);
        drop(backend.send(&[IoSlice::new(&packet)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.allowed, 1, "DHCP to QEMU gateway should be allowed");
    }

    #[test]
    fn test_outbound_dhcp_denied_when_disabled() {
        let policy = NetworkPolicy::builder().build(); // DHCP disabled
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [255, 255, 255, 255], 68, 67);
        drop(backend.send(&[IoSlice::new(&packet)]));

        let metrics = backend.metrics().snapshot();
        assert_eq!(metrics.denied, 1, "DHCP should be denied when disabled");
    }

    // =========================================================================
    // Inbound ARP Passthrough Tests
    // =========================================================================

    #[test]
    fn test_recv_allows_arp_reply() {
        let policy = NetworkPolicy::builder().build(); // Empty policy
        let inner = MockBackend::with_recv_queue(vec![make_arp_packet()]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_ok(), "ARP replies should always pass through");
        assert_eq!(backend.metrics().snapshot().allowed, 1);
    }

    // =========================================================================
    // Inbound Parse Error Tests
    // =========================================================================

    #[test]
    fn test_recv_denies_malformed_inbound() {
        let policy = NetworkPolicy::builder().build();
        // Truncated IPv4 packet — will fail to parse
        let mut malformed = vec![0u8; 20];
        malformed[12] = 0x08;
        malformed[13] = 0x00; // IPv4 ethertype
        // Too short to be a valid IP packet

        let inner = MockBackend::with_recv_queue(vec![malformed]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(result.is_err());
        assert_eq!(backend.metrics().snapshot().parse_errors, 1);
    }

    // =========================================================================
    // set_rx_waker Tests
    // =========================================================================

    #[test]
    fn test_set_rx_waker_delegates() {
        use std::sync::atomic::{AtomicBool, Ordering};

        struct WakerBackend {
            waker_set: Arc<AtomicBool>,
        }

        impl NetBackend for WakerBackend {
            type RxPacket<'a> = amla_core::backends::NoRxPacket;

            fn send(&self, _: &[IoSlice<'_>]) -> io::Result<()> {
                Ok(())
            }
            fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
                Ok(None)
            }
            fn set_nonblocking(&self, _: bool) -> io::Result<()> {
                Ok(())
            }
            fn set_rx_waker(&self, _waker: Option<RxWaker>) {
                self.waker_set.store(true, Ordering::SeqCst);
            }
        }

        let waker_set = Arc::new(AtomicBool::new(false));
        let policy = NetworkPolicy::builder().build();
        let inner = WakerBackend {
            waker_set: Arc::clone(&waker_set),
        };
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        backend.set_rx_waker(Some(RxWaker::new(|| {})));
        assert!(waker_set.load(Ordering::SeqCst));
    }

    // =========================================================================
    // TCP Flags Connection Tracking Tests
    // =========================================================================

    #[test]
    fn test_tcp_syn_creates_conntrack_entry() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let inner = MockBackend::new();
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // TCP SYN packet (flags byte at offset 14+20+13 = 47)
        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend.send(&[IoSlice::new(&packet)]));

        // Should have created a conntrack entry
        assert_eq!(backend.conn_table.lock().len(), 1);
    }

    #[test]
    fn test_udp_conntrack_allows_response() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        // Prepare inbound response: 8.8.8.8:53 → 10.0.2.15:54321
        let inbound = packet::tests::make_udp_packet([8, 8, 8, 8], [10, 0, 2, 15], 53, 54321);
        let inner = MockBackend::with_recv_queue(vec![inbound]);
        let backend = PolicyNetBackend::new(inner, policy.to_packet_policy());

        // First send outbound: 10.0.2.15:54321 → 8.8.8.8:53
        let outbound = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 54321, 53);
        drop(backend.send(&[IoSlice::new(&outbound)]));

        // Now the inbound response should be allowed
        let mut buf = vec![0u8; 1500];
        let result = recv_packet(&backend, &mut buf);
        assert!(
            result.is_ok(),
            "UDP response should be allowed via conntrack"
        );
    }

    // FIX-M5: Regression test for B1 — send failure must not leak conntrack state
    #[test]
    fn test_send_failure_no_conntrack_leak() {
        /// Backend that always fails on send
        struct FailingSendBackend;

        impl NetBackend for FailingSendBackend {
            type RxPacket<'a> = amla_core::backends::NoRxPacket;

            fn send(&self, _: &[IoSlice<'_>]) -> io::Result<()> {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "send failed"))
            }
            fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
                Ok(None)
            }
            fn set_nonblocking(&self, _: bool) -> io::Result<()> {
                Ok(())
            }
        }

        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let backend = PolicyNetBackend::new(FailingSendBackend, policy.to_packet_policy());

        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        let result = backend.send(&[IoSlice::new(&packet)]);
        assert!(result.is_err(), "send should propagate the backend error");

        // Conntrack must NOT have an entry (the send failed)
        assert_eq!(
            backend.conn_table.lock().len(),
            0,
            "conntrack must be empty after failed send"
        );

        // Metrics must NOT count it as allowed
        let metrics = backend.metrics().snapshot();
        assert_eq!(
            metrics.allowed, 0,
            "failed send must not be counted as allowed"
        );

        // Audit log should be empty (no successful send = no audit)
        assert!(
            backend.audit_entries().is_empty(),
            "no audit entry for failed send"
        );
    }

    /// Helper to calculate IP checksum for test packets
    fn calc_ip_checksum(header: &[u8]) -> u16 {
        let mut sum: u32 = 0;
        for chunk in header.chunks(2) {
            if chunk.len() == 2 {
                let word = u16::from_be_bytes([chunk[0], chunk[1]]);
                sum = sum.wrapping_add(u32::from(word));
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        // After folding, sum fits in 16 bits
        #[allow(clippy::cast_possible_truncation)]
        let result = !(sum as u16);
        result
    }
}
