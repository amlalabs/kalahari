// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Evidence-driven stream policy model.
//!
//! This module is the replacement policy surface for L7 authorization. Packet
//! policy remains responsible for raw IP admission and conntrack while stream
//! policy evaluates DNS, TLS, and HTTP evidence before usernet opens a host
//! connection.

use crate::policy::{HostSpec, NetworkPolicy};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use thiserror::Error;

/// Phase that produced a policy decision or requested more evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyPhase {
    /// Raw network-layer and transport-layer destination evidence.
    L3L4,
    /// DNS query evidence.
    DnsQuery,
    /// DNS answer evidence.
    DnsResolved,
    /// TLS `ClientHello` evidence.
    TlsClientHello,
    /// HTTP request headers evidence.
    HttpRequest,
    /// HTTP request body evidence.
    HttpBody,
    /// HTTP response body evidence.
    HttpResponse,
}

/// IP transport protocol observed by policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// `ICMPv4`.
    Icmp,
    /// `ICMPv6`.
    Icmpv6,
    /// Any protocol not modeled explicitly.
    Other(u8),
}

impl TransportProtocol {
    /// Numeric IP protocol value.
    #[must_use]
    pub const fn number(self) -> u8 {
        match self {
            Self::Tcp => 6,
            Self::Udp => 17,
            Self::Icmp => 1,
            Self::Icmpv6 => 58,
            Self::Other(value) => value,
        }
    }
}

/// Guest TCP flow metadata used for stream authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TcpFlow {
    /// Guest-side socket address.
    pub guest_addr: SocketAddr,
    /// Remote socket address requested by the guest.
    pub remote_addr: SocketAddr,
}

impl TcpFlow {
    /// Create a new TCP flow.
    #[must_use]
    pub const fn new(guest_addr: SocketAddr, remote_addr: SocketAddr) -> Self {
        Self {
            guest_addr,
            remote_addr,
        }
    }
}

/// Evidence emitted by parsers and transport lifecycle hooks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Evidence {
    /// Raw destination evidence from the packet admission layer.
    L3L4 {
        /// Destination IP.
        dst_ip: IpAddr,
        /// Destination port.
        dst_port: u16,
        /// IP protocol.
        proto: TransportProtocol,
    },
    /// DNS query evidence.
    DnsQuery {
        /// Queried name.
        qname: String,
        /// DNS QTYPE.
        qtype: u16,
    },
    /// TLS `ClientHello` evidence.
    TlsClientHello {
        /// Server Name Indication, if present.
        sni: Option<String>,
        /// Whether Encrypted Client Hello was present.
        ech_present: bool,
    },
    /// HTTP request headers evidence.
    HttpRequest {
        /// HTTP `Host` authority, if present.
        host: Option<String>,
        /// Request method.
        method: String,
        /// Request path or absolute URI.
        path: String,
    },
    /// HTTP request body chunk evidence.
    HttpBodyChunk {
        /// Body bytes.
        bytes: Vec<u8>,
        /// Whether this is the end of the body.
        end: bool,
    },
    /// HTTP response body chunk evidence.
    HttpResponseChunk {
        /// Body bytes.
        bytes: Vec<u8>,
        /// Whether this is the end of the body.
        end: bool,
    },
}

impl Evidence {
    /// Phase associated with this evidence item.
    #[must_use]
    pub const fn phase(&self) -> PolicyPhase {
        match self {
            Self::L3L4 { .. } => PolicyPhase::L3L4,
            Self::DnsQuery { .. } => PolicyPhase::DnsQuery,
            Self::TlsClientHello { .. } => PolicyPhase::TlsClientHello,
            Self::HttpRequest { .. } => PolicyPhase::HttpRequest,
            Self::HttpBodyChunk { .. } => PolicyPhase::HttpBody,
            Self::HttpResponseChunk { .. } => PolicyPhase::HttpResponse,
        }
    }
}

/// Why policy allowed a stream or evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowReason {
    /// Matched an explicit IP rule.
    ExplicitIp { ip: IpAddr, port: u16 },
    /// Matched an explicit subnet rule.
    ExplicitSubnet { ip: IpAddr, port: u16 },
    /// Matched a domain rule using stream evidence.
    ExplicitDomain { name: String, port: u16 },
    /// Matched a domain rule using DNS answer evidence for the destination IP.
    DnsEvidence {
        /// Resolved name that authorized the destination.
        name: String,
        /// Destination IP.
        ip: IpAddr,
        /// Destination port.
        port: u16,
    },
    /// DNS query matched an allowed domain rule.
    DnsQueryAllowed { qname: String },
    /// DNS answer was accepted into the evidence store.
    DnsResolved { name: String },
    /// Body evidence was accepted by policy.
    BodyAllowed { phase: PolicyPhase },
}

/// Why policy denied a stream or evidence item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    /// No rule or evidence authorized the stream.
    DefaultDeny,
    /// Raw IP destination is denied.
    RawIpDenied { dst_ip: IpAddr, dst_port: u16 },
    /// Domain evidence did not match an allow rule.
    DomainDenied { name: String, port: u16 },
    /// More evidence was required but unavailable.
    MissingEvidence { phase: PolicyPhase },
    /// TLS SNI was absent.
    MissingSni,
    /// TLS ECH prevents required hostname inspection.
    EchPresent,
    /// HTTP request had no `Host` authority.
    MissingHttpHost,
    /// Parser failed before producing usable evidence.
    ParseError(String),
    /// Policy lookup failed.
    PolicyLookupFailed(String),
    /// Buffered evidence exceeded a configured limit.
    BufferOverflow { limit: usize },
    /// Pending evidence timed out.
    Timeout { phase: PolicyPhase },
    /// The stream ended before required evidence arrived.
    StreamClosed { phase: PolicyPhase },
}

/// Additional stream bytes or parser state needed before a final decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamInterest {
    /// Read a TLS `ClientHello`.
    TlsClientHello { max_bytes: usize },
    /// Read HTTP request headers.
    HttpRequestHeaders { max_bytes: usize },
    /// Wait for DNS answer evidence.
    DnsEvidence,
    /// Apply policy to request body chunks.
    HttpBody,
    /// Observe response body chunks.
    HttpResponse,
}

/// Plan for handing a stream to trusted interception code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InterceptPlan {
    /// Interceptor kind selected by policy.
    pub kind: InterceptKind,
    /// Evidence phase that selected the interceptor.
    pub phase: PolicyPhase,
}

/// Built-in interceptor classes understood by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterceptKind {
    /// TLS MITM over an owned guest stream.
    TlsMitm,
    /// HTTP-aware interceptor over a plaintext stream.
    Http,
    /// Named local implementation supplied by the embedding process.
    Named(String),
}

/// Mutation policy to apply before bytes leave the trusted boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationPlan {
    /// Set a header to a literal value.
    SetHeader { name: String, value: String },
    /// Set a header from a secret resolved by the trusted interceptor.
    SetSecret {
        /// Header name.
        name: String,
        /// Secret reference resolved immediately before serialization.
        secret_ref: String,
        /// Optional value prefix such as `Bearer`.
        prefix: Option<String>,
    },
    /// Remove a header.
    RemoveHeader { name: String },
}

/// Evidence-driven verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidencePolicyDecision {
    /// Allow with a reason.
    Allow(AllowReason),
    /// Deny with a reason.
    Deny(DenyReason),
    /// More stream evidence is required before deciding.
    NeedMoreData(StreamInterest),
    /// Hand the stream to a trusted interceptor.
    Intercept(InterceptPlan),
    /// Apply a mutation plan.
    Mutate(MutationPlan),
}

/// Error returned when building trusted DNS answer evidence.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DnsEvidenceError {
    /// The DNS answer name does not match the previously authorized query.
    #[error("DNS answer name {answer_name} does not match authorized query {query_name}")]
    NameMismatch {
        /// Normalized authorized query name.
        query_name: String,
        /// Normalized answer name.
        answer_name: String,
    },
    /// No address answers were supplied.
    #[error("DNS answer contains no IP addresses")]
    EmptyAnswer,
}

/// Token proving that a DNS query name was accepted by policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AllowedDnsQuery {
    name: String,
    qtype: u16,
}

impl AllowedDnsQuery {
    const fn new(name: String, qtype: u16) -> Self {
        Self { name, qtype }
    }

    /// Normalized query name accepted by policy.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// DNS query type accepted by policy.
    #[must_use]
    pub const fn qtype(&self) -> u16 {
        self.qtype
    }
}

/// Host-trusted DNS answer evidence.
///
/// This type is intentionally constructed from an [`AllowedDnsQuery`] token and
/// is not deserializable. Raw guest bytes must be parsed and authenticated by
/// trusted DNS handling code before answer evidence reaches policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TrustedDnsAnswer {
    name: String,
    ips: Vec<IpAddr>,
    ttl: NonZeroU32,
}

impl TrustedDnsAnswer {
    /// Build answer evidence for an accepted DNS query.
    ///
    /// The answer name must match the authorized query and the TTL must already
    /// be non-zero. Zero-TTL answers are deliberately not representable as
    /// durable authorization evidence.
    pub fn new(
        query: &AllowedDnsQuery,
        answer_name: impl AsRef<str>,
        ips: Vec<IpAddr>,
        ttl: NonZeroU32,
    ) -> Result<Self, DnsEvidenceError> {
        let answer_name = normalize_domain(answer_name);
        if answer_name != query.name {
            return Err(DnsEvidenceError::NameMismatch {
                query_name: query.name.clone(),
                answer_name,
            });
        }
        if ips.is_empty() {
            return Err(DnsEvidenceError::EmptyAnswer);
        }
        Ok(Self {
            name: query.name.clone(),
            ips,
            ttl,
        })
    }

    /// Normalized answer name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Address answers bound to the name.
    #[must_use]
    pub fn ips(&self) -> &[IpAddr] {
        &self.ips
    }

    /// Non-zero DNS TTL in seconds.
    #[must_use]
    pub const fn ttl(&self) -> NonZeroU32 {
        self.ttl
    }
}

/// DNS answer evidence for one IP/name mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsEvidenceRecord {
    /// Resolved name.
    pub name: String,
    /// Resolved IP.
    pub ip: IpAddr,
    /// Expiration timestamp as Unix seconds.
    pub expires_at_epoch_secs: u64,
}

/// Per-VM DNS evidence store.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsEvidenceStore {
    by_ip: HashMap<IpAddr, Vec<DnsEvidenceRecord>>,
}

impl DnsEvidenceStore {
    /// Record DNS answer evidence.
    pub fn insert(&mut self, answer: TrustedDnsAnswer, now_epoch_secs: u64) {
        let expires_at_epoch_secs = now_epoch_secs.saturating_add(u64::from(answer.ttl.get()));
        for ip in answer.ips {
            let records = self.by_ip.entry(ip).or_default();
            records.retain(|record| record.name != answer.name);
            records.push(DnsEvidenceRecord {
                name: answer.name.clone(),
                ip,
                expires_at_epoch_secs,
            });
        }
    }

    /// Remove expired DNS evidence.
    pub fn prune_expired(&mut self, now_epoch_secs: u64) {
        self.by_ip.retain(|_, records| {
            records.retain(|record| record.expires_at_epoch_secs > now_epoch_secs);
            !records.is_empty()
        });
    }

    /// Return unexpired names recorded for an IP.
    pub fn names_for_ip(&mut self, ip: IpAddr, now_epoch_secs: u64) -> Vec<String> {
        self.prune_expired(now_epoch_secs);
        self.by_ip
            .get(&ip)
            .map(|records| records.iter().map(|record| record.name.clone()).collect())
            .unwrap_or_default()
    }

    /// Return the number of IP keys with unexpired evidence.
    pub fn len(&self) -> usize {
        self.by_ip.len()
    }

    /// Whether no IP has DNS evidence.
    pub fn is_empty(&self) -> bool {
        self.by_ip.is_empty()
    }
}

/// Evidence-driven policy engine.
#[derive(Debug)]
pub struct EvidencePolicyEngine {
    policy: Arc<NetworkPolicy>,
    dns: Mutex<DnsEvidenceStore>,
}

impl EvidencePolicyEngine {
    /// Create an engine from an owned policy.
    #[must_use]
    pub fn new(policy: NetworkPolicy) -> Self {
        Self {
            policy: Arc::new(policy),
            dns: Mutex::new(DnsEvidenceStore::default()),
        }
    }

    /// Create an engine from a shared policy.
    #[must_use]
    pub fn with_shared_policy(policy: Arc<NetworkPolicy>) -> Self {
        Self {
            policy,
            dns: Mutex::new(DnsEvidenceStore::default()),
        }
    }

    /// Access the underlying policy.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Evaluate initial TCP open evidence.
    pub fn open_tcp(&self, flow: TcpFlow, now_epoch_secs: u64) -> EvidencePolicyDecision {
        self.evaluate(
            Some(flow),
            Evidence::L3L4 {
                dst_ip: flow.remote_addr.ip(),
                dst_port: flow.remote_addr.port(),
                proto: TransportProtocol::Tcp,
            },
            now_epoch_secs,
        )
    }

    /// Evaluate one evidence item.
    pub fn evaluate(
        &self,
        flow: Option<TcpFlow>,
        evidence: Evidence,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        match evidence {
            Evidence::L3L4 {
                dst_ip,
                dst_port,
                proto,
            } => self.evaluate_l3_l4(dst_ip, dst_port, proto, now_epoch_secs),
            Evidence::DnsQuery { qname, qtype } => self.evaluate_dns_query(&qname, qtype),
            Evidence::TlsClientHello { sni, ech_present } => {
                self.evaluate_tls_client_hello(flow, sni, ech_present, now_epoch_secs)
            }
            Evidence::HttpRequest { host, .. } => {
                self.evaluate_http_request(flow, host, now_epoch_secs)
            }
            Evidence::HttpBodyChunk { .. } => {
                EvidencePolicyDecision::Allow(AllowReason::BodyAllowed {
                    phase: PolicyPhase::HttpBody,
                })
            }
            Evidence::HttpResponseChunk { .. } => {
                EvidencePolicyDecision::Allow(AllowReason::BodyAllowed {
                    phase: PolicyPhase::HttpResponse,
                })
            }
        }
    }

    /// Authorize a DNS query and return a token required to record its answer.
    pub fn authorize_dns_query(
        &self,
        qname: impl AsRef<str>,
        qtype: u16,
    ) -> Result<AllowedDnsQuery, DenyReason> {
        let qname = normalize_domain(qname);
        if self.domain_rule_matches_any_port(&qname) {
            return Ok(AllowedDnsQuery::new(qname, qtype));
        }
        Err(DenyReason::DomainDenied {
            name: qname,
            port: 53,
        })
    }

    /// Record trusted DNS answer evidence.
    pub fn record_dns_answer(
        &self,
        answer: TrustedDnsAnswer,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        let name = answer.name.clone();
        self.dns.lock().insert(answer, now_epoch_secs);
        EvidencePolicyDecision::Allow(AllowReason::DnsResolved { name })
    }

    fn evaluate_l3_l4(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        proto: TransportProtocol,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        if let Some(reason) = raw_ip_allow(&self.policy, dst_ip, dst_port) {
            return EvidencePolicyDecision::Allow(reason);
        }

        if let Some(name) = self.dns_name_authorizing(dst_ip, dst_port, now_epoch_secs) {
            return EvidencePolicyDecision::Allow(AllowReason::DnsEvidence {
                name,
                ip: dst_ip,
                port: dst_port,
            });
        }

        if proto == TransportProtocol::Tcp && self.has_domain_rule_for_port(dst_port) {
            return match dst_port {
                443 => EvidencePolicyDecision::NeedMoreData(StreamInterest::TlsClientHello {
                    max_bytes: 32 * 1024,
                }),
                80 => EvidencePolicyDecision::NeedMoreData(StreamInterest::HttpRequestHeaders {
                    max_bytes: 32 * 1024,
                }),
                _ => EvidencePolicyDecision::NeedMoreData(StreamInterest::DnsEvidence),
            };
        }

        EvidencePolicyDecision::Deny(DenyReason::RawIpDenied { dst_ip, dst_port })
    }

    fn evaluate_dns_query(&self, qname: &str, qtype: u16) -> EvidencePolicyDecision {
        match self.authorize_dns_query(qname, qtype) {
            Ok(query) => {
                EvidencePolicyDecision::Allow(AllowReason::DnsQueryAllowed { qname: query.name })
            }
            Err(reason) => EvidencePolicyDecision::Deny(reason),
        }
    }

    fn evaluate_tls_client_hello(
        &self,
        flow: Option<TcpFlow>,
        sni: Option<String>,
        ech_present: bool,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        if ech_present {
            return EvidencePolicyDecision::Deny(DenyReason::EchPresent);
        }
        let Some(sni) = sni.filter(|value| !value.trim().is_empty()) else {
            return EvidencePolicyDecision::Deny(DenyReason::MissingSni);
        };
        let Some(flow) = flow else {
            return EvidencePolicyDecision::Deny(DenyReason::PolicyLookupFailed(
                "TLS evidence requires TCP flow context".to_string(),
            ));
        };
        self.evaluate_domain_for_flow(&sni, flow, now_epoch_secs)
    }

    fn evaluate_http_request(
        &self,
        flow: Option<TcpFlow>,
        host: Option<String>,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        let Some(host) = host.filter(|value| !value.trim().is_empty()) else {
            return EvidencePolicyDecision::Deny(DenyReason::MissingHttpHost);
        };
        let Some(flow) = flow else {
            return EvidencePolicyDecision::Deny(DenyReason::PolicyLookupFailed(
                "HTTP evidence requires TCP flow context".to_string(),
            ));
        };
        self.evaluate_domain_for_flow(&normalize_authority_host(&host), flow, now_epoch_secs)
    }

    fn evaluate_domain_for_flow(
        &self,
        name: &str,
        flow: TcpFlow,
        now_epoch_secs: u64,
    ) -> EvidencePolicyDecision {
        let name = normalize_domain(name);
        let port = flow.remote_addr.port();
        if self.domain_rule_matches_port(&name, port) {
            if self.dns_name_authorizing_exact(flow.remote_addr.ip(), port, now_epoch_secs, &name) {
                return EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain { name, port });
            }
            return EvidencePolicyDecision::NeedMoreData(StreamInterest::DnsEvidence);
        }
        EvidencePolicyDecision::Deny(DenyReason::DomainDenied { name, port })
    }

    fn dns_name_authorizing(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        now_epoch_secs: u64,
    ) -> Option<String> {
        self.dns
            .lock()
            .names_for_ip(dst_ip, now_epoch_secs)
            .into_iter()
            .find(|name| self.domain_rule_matches_port(name, dst_port))
    }

    fn dns_name_authorizing_exact(
        &self,
        dst_ip: IpAddr,
        dst_port: u16,
        now_epoch_secs: u64,
        expected_name: &str,
    ) -> bool {
        self.dns
            .lock()
            .names_for_ip(dst_ip, now_epoch_secs)
            .into_iter()
            .any(|name| name == expected_name && self.domain_rule_matches_port(&name, dst_port))
    }

    fn has_domain_rule_for_port(&self, port: u16) -> bool {
        self.policy.rules.iter().any(|rule| {
            matches!(rule.host, HostSpec::Domain(_))
                && (rule.ports.contains(&0) || rule.ports.contains(&port))
        })
    }

    fn domain_rule_matches_port(&self, name: &str, port: u16) -> bool {
        self.policy
            .rules
            .iter()
            .any(|rule| rule.matches_domain(name, port))
    }

    fn domain_rule_matches_any_port(&self, name: &str) -> bool {
        self.policy
            .rules
            .iter()
            .any(|rule| matches!(rule.host, HostSpec::Domain(_)) && rule.host.matches_domain(name))
    }
}

fn raw_ip_allow(policy: &NetworkPolicy, dst_ip: IpAddr, dst_port: u16) -> Option<AllowReason> {
    for rule in &policy.rules {
        if !rule.ports.contains(&0) && !rule.ports.contains(&dst_port) {
            continue;
        }
        match &rule.host {
            HostSpec::Ip(ip) if *ip == dst_ip => {
                return Some(AllowReason::ExplicitIp {
                    ip: dst_ip,
                    port: dst_port,
                });
            }
            HostSpec::Subnet(_) if rule.matches_ip(dst_ip, dst_port) => {
                return Some(AllowReason::ExplicitSubnet {
                    ip: dst_ip,
                    port: dst_port,
                });
            }
            HostSpec::Ip(_) | HostSpec::Subnet(_) | HostSpec::Domain(_) => {}
        }
    }
    None
}

fn normalize_domain(name: impl AsRef<str>) -> String {
    name.as_ref().trim_end_matches('.').to_ascii_lowercase()
}

fn normalize_authority_host(authority: &str) -> String {
    let authority = authority.trim().trim_end_matches('.');
    if let Some(without_opening_bracket) = authority.strip_prefix('[') {
        if let Some(closing_bracket) = without_opening_bracket.find(']') {
            return without_opening_bracket[..closing_bracket].to_ascii_lowercase();
        }
        return normalize_domain(authority);
    }

    if let Some((host, port)) = authority.rsplit_once(':')
        && !host.is_empty()
        && !host.contains(':')
        && !port.is_empty()
        && port.chars().all(|ch| ch.is_ascii_digit())
    {
        return normalize_domain(host);
    }

    normalize_domain(authority)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::num::NonZeroU32;

    fn flow_to(ip: Ipv4Addr, port: u16) -> TcpFlow {
        TcpFlow::new(
            SocketAddr::from(([10, 0, 2, 15], 49152)),
            SocketAddr::from((ip, port)),
        )
    }

    fn record_dns(engine: &EvidencePolicyEngine, name: &str, ip: IpAddr, now_epoch_secs: u64) {
        let query = engine
            .authorize_dns_query(name, 1)
            .expect("query should be allowed");
        let answer = TrustedDnsAnswer::new(
            &query,
            name,
            vec![ip],
            NonZeroU32::new(10).expect("test TTL is nonzero"),
        )
        .expect("trusted answer should validate");
        assert_eq!(
            engine.record_dns_answer(answer, now_epoch_secs),
            EvidencePolicyDecision::Allow(AllowReason::DnsResolved {
                name: normalize_domain(name),
            })
        );
    }

    #[test]
    fn raw_ip_requires_explicit_ip_or_subnet_rule() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        let decision = engine.open_tcp(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443), 100);
        assert_eq!(
            decision,
            EvidencePolicyDecision::NeedMoreData(StreamInterest::TlsClientHello {
                max_bytes: 32 * 1024
            })
        );

        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(203, 0, 113, 10), 443)
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        assert_eq!(
            engine.open_tcp(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443), 100),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitIp {
                ip: IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
                port: 443,
            })
        );
    }

    #[test]
    fn domain_evidence_without_trusted_dns_does_not_authorize_open_tcp() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .allow_domain("example.com", &[80])
            .build();
        let engine = EvidencePolicyEngine::new(policy);

        assert_eq!(
            engine.open_tcp(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443), 105),
            EvidencePolicyDecision::NeedMoreData(StreamInterest::TlsClientHello {
                max_bytes: 32 * 1024
            })
        );
        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443)),
                Evidence::TlsClientHello {
                    sni: Some("api.openai.com".to_string()),
                    ech_present: false,
                },
                105,
            ),
            EvidencePolicyDecision::NeedMoreData(StreamInterest::DnsEvidence)
        );
        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 20), 80)),
                Evidence::HttpRequest {
                    host: Some("example.com".to_string()),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                105,
            ),
            EvidencePolicyDecision::NeedMoreData(StreamInterest::DnsEvidence)
        );
    }

    #[test]
    fn trusted_dns_answer_requires_authorized_query_token() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        let query = engine
            .authorize_dns_query("api.openai.com.", 1)
            .expect("query should be allowed");
        let ttl = NonZeroU32::new(10).expect("test TTL is nonzero");
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        assert_eq!(
            TrustedDnsAnswer::new(&query, "evil.example", vec![ip], ttl),
            Err(DnsEvidenceError::NameMismatch {
                query_name: "api.openai.com".to_string(),
                answer_name: "evil.example".to_string(),
            })
        );
        assert_eq!(
            TrustedDnsAnswer::new(&query, "api.openai.com", Vec::new(), ttl),
            Err(DnsEvidenceError::EmptyAnswer)
        );
    }

    #[test]
    fn dns_evidence_authorizes_matching_domain_rule_until_ttl_expires_after_allowed_query() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));

        assert_eq!(
            engine.evaluate(
                None,
                Evidence::DnsQuery {
                    qname: "API.OPENAI.COM.".to_string(),
                    qtype: 1,
                },
                99,
            ),
            EvidencePolicyDecision::Allow(AllowReason::DnsQueryAllowed {
                qname: "api.openai.com".to_string(),
            })
        );

        record_dns(&engine, "api.openai.com", ip, 100);

        assert_eq!(
            engine.open_tcp(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443), 105),
            EvidencePolicyDecision::Allow(AllowReason::DnsEvidence {
                name: "api.openai.com".to_string(),
                ip,
                port: 443,
            })
        );
        assert_eq!(
            engine.open_tcp(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443), 111),
            EvidencePolicyDecision::NeedMoreData(StreamInterest::TlsClientHello {
                max_bytes: 32 * 1024
            })
        );
    }

    #[test]
    fn sni_and_http_host_authorize_domain_rules() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .allow_domain("example.com", &[80])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        record_dns(
            &engine,
            "api.openai.com",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)),
            100,
        );
        record_dns(
            &engine,
            "example.com",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
            100,
        );

        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 10), 443)),
                Evidence::TlsClientHello {
                    sni: Some("API.OPENAI.COM".to_string()),
                    ech_present: false,
                },
                100,
            ),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain {
                name: "api.openai.com".to_string(),
                port: 443,
            })
        );

        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 20), 80)),
                Evidence::HttpRequest {
                    host: Some("example.com".to_string()),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                100,
            ),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain {
                name: "example.com".to_string(),
                port: 80,
            })
        );
    }

    #[test]
    fn http_host_authority_with_explicit_port_matches_domain_rules() {
        let policy = NetworkPolicy::builder()
            .allow_domain("example.com", &[80, 8080])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        record_dns(
            &engine,
            "example.com",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
            100,
        );

        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 20), 80)),
                Evidence::HttpRequest {
                    host: Some("example.com:80".to_string()),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                100,
            ),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain {
                name: "example.com".to_string(),
                port: 80,
            })
        );

        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 20), 8080)),
                Evidence::HttpRequest {
                    host: Some("example.com:8080".to_string()),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                100,
            ),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain {
                name: "example.com".to_string(),
                port: 8080,
            })
        );
    }

    #[test]
    fn bracketed_ipv6_authority_is_not_split_like_a_domain_port() {
        let policy = NetworkPolicy::builder()
            .allow_domain("2001:db8::1", &[80])
            .build();
        let engine = EvidencePolicyEngine::new(policy);
        record_dns(
            &engine,
            "2001:db8::1",
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 20)),
            100,
        );

        assert_eq!(
            engine.evaluate(
                Some(flow_to(Ipv4Addr::new(203, 0, 113, 20), 80)),
                Evidence::HttpRequest {
                    host: Some("[2001:db8::1]:80".to_string()),
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                100,
            ),
            EvidencePolicyDecision::Allow(AllowReason::ExplicitDomain {
                name: "2001:db8::1".to_string(),
                port: 80,
            })
        );
    }

    #[test]
    fn missing_sni_ech_and_missing_http_host_fail_closed() {
        let engine = EvidencePolicyEngine::new(NetworkPolicy::deny_all());
        let flow = flow_to(Ipv4Addr::new(203, 0, 113, 10), 443);

        assert_eq!(
            engine.evaluate(
                Some(flow),
                Evidence::TlsClientHello {
                    sni: None,
                    ech_present: false,
                },
                100,
            ),
            EvidencePolicyDecision::Deny(DenyReason::MissingSni)
        );
        assert_eq!(
            engine.evaluate(
                Some(flow),
                Evidence::TlsClientHello {
                    sni: Some("api.openai.com".to_string()),
                    ech_present: true,
                },
                100,
            ),
            EvidencePolicyDecision::Deny(DenyReason::EchPresent)
        );
        assert_eq!(
            engine.evaluate(
                Some(flow),
                Evidence::HttpRequest {
                    host: None,
                    method: "GET".to_string(),
                    path: "/".to_string(),
                },
                100,
            ),
            EvidencePolicyDecision::Deny(DenyReason::MissingHttpHost)
        );
    }
}
