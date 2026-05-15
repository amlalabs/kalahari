// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! MITM policy — which connections to intercept.
//!
//! The policy is checked at two points:
//! - **SYN time**: `should_intercept_addr()` (port-only, fast)
//! - **After SNI extraction**: `should_intercept_host()` (hostname match)
//! - **After missing-SNI detection**: `should_intercept_no_sni_ip()`
//!   (explicit destination IP match)
//!
//! If `should_intercept_addr()` returns true but `should_intercept_host()`
//! returns false, the connection is denied. Mismatched SNI is not a passthrough
//! signal; direct host access must be authorized before this interceptor is
//! selected.
//!
//! Missing SNI is not treated as a hostname. It is denied unless the caller
//! explicitly adds a no-SNI destination IP/subnet rule.

use std::fmt;
use std::net::{IpAddr, SocketAddr};

const DEFAULT_HTTPS_PORT: u16 = 443;

/// Policy controlling which TLS connections are MITM'd.
#[derive(Clone, Debug)]
pub struct MitmPolicy {
    mode: Option<PolicyMode>,
    no_sni_ip_rules: Vec<NoSniIpRule>,
}

/// Error returned by [`MitmPolicyBuilder::build`] when the builder has no
/// intercept rules configured.
///
/// MITM'ing all HTTPS traffic is a security-sensitive default — a forgotten
/// `intercept_host()` / `intercept_port()` call would silently enable a
/// wildcard intercept. This crate rejects empty builders rather than
/// defaulting silently; callers who really do want every port-443 connection
/// intercepted must say so explicitly via
/// [`MitmPolicyBuilder::intercept_all_https`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmptyPolicyError;

impl fmt::Display for EmptyPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(
            "MitmPolicy has no rules — call intercept_all_https(), \
             intercept_port(...), intercept_host(...), intercept_suffix(...), \
             intercept_no_sni_ip(...), or intercept_no_sni_subnet(...) \
             at least once before build()",
        )
    }
}

impl std::error::Error for EmptyPolicyError {}

#[derive(Clone, Debug)]
enum PolicyMode {
    /// Intercept all HTTPS (port 443) traffic.
    AllHttps,
    /// Intercept specific ports.
    Ports(Vec<u16>),
    /// Intercept specific hostnames (checked after SNI extraction).
    Hosts(Vec<HostPattern>),
    /// Intercept specific ports AND hostnames.
    PortsAndHosts {
        ports: Vec<u16>,
        hosts: Vec<HostPattern>,
    },
}

/// A hostname pattern for matching SNI values.
#[derive(Clone, Debug)]
enum HostPattern {
    /// Exact match: "api.openai.com"
    Exact(String),
    /// Suffix match: "*.openai.com" matches "api.openai.com"
    Suffix(String),
}

/// A destination IP pattern for missing-SNI TLS.
#[derive(Clone, Debug)]
struct NoSniIpRule {
    matcher: IpMatcher,
    port: u16,
}

impl NoSniIpRule {
    const fn exact(ip: IpAddr, port: u16) -> Self {
        Self {
            matcher: IpMatcher::Exact(ip),
            port,
        }
    }

    fn subnet(addr: IpAddr, prefix_len: u8, port: u16) -> Self {
        assert_valid_prefix_len(addr, prefix_len);
        Self {
            matcher: IpMatcher::Subnet { addr, prefix_len },
            port,
        }
    }

    fn matches_addr(&self, addr: SocketAddr) -> bool {
        addr.port() == self.port && self.matcher.matches_ip(addr.ip())
    }
}

#[derive(Clone, Debug)]
enum IpMatcher {
    Exact(IpAddr),
    Subnet { addr: IpAddr, prefix_len: u8 },
}

impl IpMatcher {
    fn matches_ip(&self, ip: IpAddr) -> bool {
        match self {
            Self::Exact(addr) => *addr == ip,
            Self::Subnet {
                addr: IpAddr::V4(network),
                prefix_len,
            } => {
                let IpAddr::V4(ip) = ip else {
                    return false;
                };
                let mask = ipv4_mask(*prefix_len);
                u32::from(ip) & mask == u32::from(*network) & mask
            }
            Self::Subnet {
                addr: IpAddr::V6(network),
                prefix_len,
            } => {
                let IpAddr::V6(ip) = ip else {
                    return false;
                };
                let mask = ipv6_mask(*prefix_len);
                u128::from(ip) & mask == u128::from(*network) & mask
            }
        }
    }
}

fn assert_valid_prefix_len(addr: IpAddr, prefix_len: u8) {
    let max = match addr {
        IpAddr::V4(_) => 32,
        IpAddr::V6(_) => 128,
    };
    assert!(prefix_len <= max, "prefix_len must be <= {max} for {addr}");
}

const fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len)
    }
}

const fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        u128::MAX << (128 - prefix_len)
    }
}

impl HostPattern {
    fn matches(&self, hostname: &str) -> bool {
        match self {
            Self::Exact(h) => hostname.eq_ignore_ascii_case(h),
            Self::Suffix(suffix) => {
                let lower = hostname.to_ascii_lowercase();
                lower.ends_with(suffix)
                    && lower.len() > suffix.len()
                    && lower.as_bytes()[lower.len() - suffix.len() - 1] == b'.'
            }
        }
    }
}

impl MitmPolicy {
    pub fn builder() -> MitmPolicyBuilder {
        MitmPolicyBuilder::default()
    }

    /// Check at SYN time — does this address match the port policy?
    pub fn should_intercept_addr(&self, addr: SocketAddr) -> bool {
        let sni_rule_matches = match &self.mode {
            None => false,
            Some(PolicyMode::AllHttps | PolicyMode::Hosts(_)) => addr.port() == DEFAULT_HTTPS_PORT,
            Some(PolicyMode::Ports(ports) | PolicyMode::PortsAndHosts { ports, .. }) => {
                ports.contains(&addr.port())
            }
        };
        sni_rule_matches || self.no_sni_ip_rules.iter().any(|r| r.matches_addr(addr))
    }

    /// Check after SNI extraction — does this hostname match the host policy?
    ///
    /// Returns `true` if the connection should be MITM'd, `false` if the
    /// hostname does not satisfy the MITM host policy.
    pub fn should_intercept_host(&self, hostname: &str) -> bool {
        match &self.mode {
            None => false,
            Some(PolicyMode::AllHttps | PolicyMode::Ports(_)) => true,
            Some(PolicyMode::Hosts(hosts) | PolicyMode::PortsAndHosts { hosts, .. }) => {
                hosts.iter().any(|h| h.matches(hostname))
            }
        }
    }

    /// Check after a valid `ClientHello` omitted SNI — does the destination IP
    /// match an explicit no-SNI rule?
    ///
    /// This deliberately does not fall back to host/port/all-HTTPS policy. No
    /// SNI is ambiguous evidence, and only an explicit destination IP/subnet
    /// rule can authorize MITM.
    pub fn should_intercept_no_sni_ip(&self, addr: SocketAddr) -> bool {
        self.no_sni_ip_rules.iter().any(|r| r.matches_addr(addr))
    }
}

/// Builder for [`MitmPolicy`].
#[derive(Default)]
pub struct MitmPolicyBuilder {
    ports: Vec<u16>,
    hosts: Vec<HostPattern>,
    no_sni_ip_rules: Vec<NoSniIpRule>,
    all_https: bool,
}

impl MitmPolicyBuilder {
    /// Intercept all HTTPS (port 443) traffic regardless of hostname.
    #[must_use]
    pub const fn intercept_all_https(mut self) -> Self {
        self.all_https = true;
        self
    }

    /// Intercept traffic on a specific port.
    #[must_use]
    pub fn intercept_port(mut self, port: u16) -> Self {
        self.ports.push(port);
        self
    }

    /// Intercept traffic to a specific hostname (exact match).
    #[must_use]
    pub fn intercept_host(mut self, hostname: &str) -> Self {
        self.hosts
            .push(HostPattern::Exact(hostname.to_ascii_lowercase()));
        self
    }

    /// Intercept traffic to hostnames matching a suffix pattern.
    ///
    /// Example: `intercept_suffix("openai.com")` matches `api.openai.com`
    /// but not `openai.com` itself.
    #[must_use]
    pub fn intercept_suffix(mut self, suffix: &str) -> Self {
        self.hosts
            .push(HostPattern::Suffix(suffix.to_ascii_lowercase()));
        self
    }

    /// Intercept missing-SNI TLS to an exact destination IP on port 443.
    ///
    /// Missing SNI does not prove the client used an IP-literal URL; it only
    /// gives the proxy a destination socket address. Scope these rules tightly.
    #[must_use]
    pub fn intercept_no_sni_ip(mut self, ip: IpAddr) -> Self {
        self.no_sni_ip_rules
            .push(NoSniIpRule::exact(ip, DEFAULT_HTTPS_PORT));
        self
    }

    /// Intercept missing-SNI TLS to an exact destination IP on a specific port.
    #[must_use]
    pub fn intercept_no_sni_ip_port(mut self, ip: IpAddr, port: u16) -> Self {
        self.no_sni_ip_rules.push(NoSniIpRule::exact(ip, port));
        self
    }

    /// Intercept missing-SNI TLS to a destination IP subnet on port 443.
    ///
    /// `prefix_len` must be <= 32 for IPv4 and <= 128 for IPv6.
    #[must_use]
    pub fn intercept_no_sni_subnet(mut self, addr: IpAddr, prefix_len: u8) -> Self {
        self.no_sni_ip_rules
            .push(NoSniIpRule::subnet(addr, prefix_len, DEFAULT_HTTPS_PORT));
        self
    }

    /// Intercept missing-SNI TLS to a destination IP subnet on a specific port.
    ///
    /// `prefix_len` must be <= 32 for IPv4 and <= 128 for IPv6.
    #[must_use]
    pub fn intercept_no_sni_subnet_port(mut self, addr: IpAddr, prefix_len: u8, port: u16) -> Self {
        self.no_sni_ip_rules
            .push(NoSniIpRule::subnet(addr, prefix_len, port));
        self
    }

    /// Build the policy.
    ///
    /// Returns [`EmptyPolicyError`] when no intercept rules were added. An
    /// empty builder would previously default to intercepting *all* HTTPS
    /// traffic — a footgun, since a forgotten `intercept_host()` call would
    /// silently escalate to a wildcard MITM. Callers who want the wildcard
    /// must call [`intercept_all_https`] explicitly. Missing-SNI IP-literal
    /// interception still requires an explicit no-SNI IP/subnet rule.
    ///
    /// [`intercept_all_https`]: Self::intercept_all_https
    pub fn build(self) -> Result<MitmPolicy, EmptyPolicyError> {
        let mode = if self.all_https {
            Some(PolicyMode::AllHttps)
        } else {
            match (self.ports.is_empty(), self.hosts.is_empty()) {
                (true, true) => None,
                (false, true) => Some(PolicyMode::Ports(self.ports)),
                (true, false) => Some(PolicyMode::Hosts(self.hosts)),
                (false, false) => Some(PolicyMode::PortsAndHosts {
                    ports: self.ports,
                    hosts: self.hosts,
                }),
            }
        };
        if mode.is_none() && self.no_sni_ip_rules.is_empty() {
            return Err(EmptyPolicyError);
        }
        Ok(MitmPolicy {
            mode,
            no_sni_ip_rules: self.no_sni_ip_rules,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), port))
    }

    fn ip_addr(ip: [u8; 4], port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
    }

    #[test]
    fn all_https_matches_443() {
        let policy = MitmPolicy::builder().intercept_all_https().build().unwrap();
        assert!(policy.should_intercept_addr(addr(443)));
        assert!(!policy.should_intercept_addr(addr(80)));
        assert!(policy.should_intercept_host("anything.com"));
        assert!(!policy.should_intercept_no_sni_ip(addr(443)));
    }

    #[test]
    fn port_matching() {
        let policy = MitmPolicy::builder()
            .intercept_port(443)
            .intercept_port(8443)
            .build()
            .unwrap();
        assert!(policy.should_intercept_addr(addr(443)));
        assert!(policy.should_intercept_addr(addr(8443)));
        assert!(!policy.should_intercept_addr(addr(80)));
    }

    #[test]
    fn host_exact_matching() {
        let policy = MitmPolicy::builder()
            .intercept_host("api.openai.com")
            .build()
            .unwrap();
        // Port check defaults to 443 for host-only policy
        assert!(policy.should_intercept_addr(addr(443)));
        assert!(!policy.should_intercept_addr(addr(80)));
        // Hostname check
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("API.OPENAI.COM"));
        assert!(!policy.should_intercept_host("other.openai.com"));
    }

    #[test]
    fn host_suffix_matching() {
        let policy = MitmPolicy::builder()
            .intercept_suffix("openai.com")
            .build()
            .unwrap();
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("beta.api.openai.com"));
        // Suffix must match at dot boundary
        assert!(!policy.should_intercept_host("openai.com"));
        assert!(!policy.should_intercept_host("notopenai.com"));
    }

    #[test]
    fn ports_and_hosts_combined() {
        let policy = MitmPolicy::builder()
            .intercept_port(8443)
            .intercept_host("api.example.com")
            .build()
            .unwrap();
        assert!(policy.should_intercept_addr(addr(8443)));
        assert!(!policy.should_intercept_addr(addr(443)));
        assert!(policy.should_intercept_host("api.example.com"));
        assert!(!policy.should_intercept_host("other.com"));
    }

    #[test]
    fn empty_builder_is_rejected() {
        // An empty builder used to silently default to AllHttps — a footgun.
        // Now requires an explicit intercept rule or `intercept_all_https()`.
        assert!(matches!(
            MitmPolicy::builder().build(),
            Err(EmptyPolicyError)
        ));
    }

    #[test]
    fn no_sni_exact_ip_is_explicit_and_defaults_to_443() {
        let policy = MitmPolicy::builder()
            .intercept_no_sni_ip(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .build()
            .unwrap();

        assert!(policy.should_intercept_addr(ip_addr([127, 0, 0, 1], 443)));
        assert!(policy.should_intercept_no_sni_ip(ip_addr([127, 0, 0, 1], 443)));
        assert!(!policy.should_intercept_no_sni_ip(ip_addr([127, 0, 0, 2], 443)));
        assert!(!policy.should_intercept_no_sni_ip(ip_addr([127, 0, 0, 1], 8443)));
        assert!(!policy.should_intercept_host("127.0.0.1"));
    }

    #[test]
    fn no_sni_exact_ip_can_use_custom_port() {
        let policy = MitmPolicy::builder()
            .intercept_no_sni_ip_port(IpAddr::V4(Ipv4Addr::LOCALHOST), 8443)
            .build()
            .unwrap();

        assert!(policy.should_intercept_addr(ip_addr([127, 0, 0, 1], 8443)));
        assert!(policy.should_intercept_no_sni_ip(ip_addr([127, 0, 0, 1], 8443)));
        assert!(!policy.should_intercept_addr(ip_addr([127, 0, 0, 1], 443)));
    }

    #[test]
    fn no_sni_subnet_matches_at_family_boundary() {
        let policy = MitmPolicy::builder()
            .intercept_no_sni_subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 8)
            .intercept_no_sni_subnet_port(IpAddr::V6(Ipv6Addr::LOCALHOST), 128, 8443)
            .build()
            .unwrap();

        assert!(policy.should_intercept_no_sni_ip(ip_addr([10, 2, 3, 4], 443)));
        assert!(!policy.should_intercept_no_sni_ip(ip_addr([11, 2, 3, 4], 443)));
        let v6_loopback = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 8443, 0, 0));
        assert!(policy.should_intercept_no_sni_ip(v6_loopback));
        let v6_other = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        assert!(!policy.should_intercept_no_sni_ip(v6_other));
    }

    #[test]
    fn ports_only_accepts_all_hostnames() {
        let policy = MitmPolicy::builder().intercept_port(8443).build().unwrap();
        // Ports-only mode → should_intercept_host always returns true
        assert!(policy.should_intercept_host("anything.com"));
        assert!(policy.should_intercept_host("evil.example.com"));
    }

    #[test]
    fn all_https_overrides_ports_and_hosts() {
        // If all_https is set, ports/hosts are ignored
        let policy = MitmPolicy::builder()
            .intercept_port(8443)
            .intercept_host("specific.com")
            .intercept_all_https()
            .build()
            .unwrap();
        // Should match port 443 (all_https), not just 8443
        assert!(policy.should_intercept_addr(addr(443)));
        // Should match any hostname
        assert!(policy.should_intercept_host("anything.com"));
    }

    #[test]
    fn ipv6_address() {
        use std::net::{Ipv6Addr, SocketAddrV6};
        let policy = MitmPolicy::builder().intercept_all_https().build().unwrap();
        let v6 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        assert!(policy.should_intercept_addr(v6));
        let v6_80 = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 80, 0, 0));
        assert!(!policy.should_intercept_addr(v6_80));
    }

    #[test]
    fn multiple_hosts() {
        let policy = MitmPolicy::builder()
            .intercept_host("api.openai.com")
            .intercept_host("api.example.com")
            .build()
            .unwrap();
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("api.example.com"));
        assert!(!policy.should_intercept_host("api.google.com"));
    }

    #[test]
    fn multiple_suffixes() {
        let policy = MitmPolicy::builder()
            .intercept_suffix("openai.com")
            .intercept_suffix("example.com")
            .build()
            .unwrap();
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("api.example.com"));
        assert!(!policy.should_intercept_host("api.google.com"));
    }

    #[test]
    fn suffix_case_insensitive() {
        let policy = MitmPolicy::builder()
            .intercept_suffix("OpenAI.COM")
            .build()
            .unwrap();
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("API.OPENAI.COM"));
    }

    #[test]
    fn exact_host_stored_lowercase() {
        let policy = MitmPolicy::builder()
            .intercept_host("API.OpenAI.COM")
            .build()
            .unwrap();
        assert!(policy.should_intercept_host("api.openai.com"));
        assert!(policy.should_intercept_host("API.OPENAI.COM"));
    }

    #[test]
    fn ports_and_hosts_rejects_non_matching_host() {
        let policy = MitmPolicy::builder()
            .intercept_port(443)
            .intercept_host("api.openai.com")
            .build()
            .unwrap();
        // Port matches but host doesn't → should_intercept_host returns false
        assert!(policy.should_intercept_addr(addr(443)));
        assert!(!policy.should_intercept_host("api.google.com"));
    }

    #[test]
    fn suffix_requires_dot_boundary() {
        let policy = MitmPolicy::builder()
            .intercept_suffix("ai.com")
            .build()
            .unwrap();
        // "openai.com" ends with "ai.com" but the char before is 'n', not '.'
        assert!(!policy.should_intercept_host("openai.com"));
        // "sub.ai.com" has a dot before "ai.com" → matches
        assert!(policy.should_intercept_host("sub.ai.com"));
    }

    #[test]
    fn empty_hostname_does_not_match() {
        let policy = MitmPolicy::builder()
            .intercept_host("api.openai.com")
            .build()
            .unwrap();
        assert!(!policy.should_intercept_host(""));

        let suffix_policy = MitmPolicy::builder()
            .intercept_suffix("openai.com")
            .build()
            .unwrap();
        assert!(!suffix_policy.should_intercept_host(""));
    }
}
