// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Network policy configuration
//!
//! Defines allowlist-based policies for controlling network access.
//! Follows a **fail-closed** model - anything not explicitly allowed is denied.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// =============================================================================
// Host Rule
// =============================================================================

/// A rule specifying allowed host:port combinations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[must_use]
pub struct HostRule {
    /// Host specification - either IP address or domain pattern
    pub host: HostSpec,
    /// Allowed ports (empty means no ports allowed)
    pub ports: HashSet<u16>,
    /// Optional comment for documentation
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl HostRule {
    /// Create a new rule for an IP address
    pub fn ip(addr: Ipv4Addr, ports: &[u16]) -> Self {
        Self {
            host: HostSpec::Ip(IpAddr::V4(addr)),
            ports: ports.iter().copied().collect(),
            comment: None,
        }
    }

    /// Create a new rule for an IPv6 address
    pub fn ip_v6(addr: Ipv6Addr, ports: &[u16]) -> Self {
        Self {
            host: HostSpec::Ip(IpAddr::V6(addr)),
            ports: ports.iter().copied().collect(),
            comment: None,
        }
    }

    /// Create a new rule for a domain pattern
    pub fn domain(pattern: &str, ports: &[u16]) -> Self {
        Self {
            host: HostSpec::Domain(pattern.to_string()),
            ports: ports.iter().copied().collect(),
            comment: None,
        }
    }

    /// Add a comment to this rule
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }

    /// Check if this rule matches an IP and port
    ///
    /// Port 0 in the rule's port set is treated as a wildcard meaning "all ports".
    ///
    /// **Important:** `HostSpec::Domain` rules always return `false` here because
    /// domain matching requires DNS resolution, which is not available at the
    /// packet-level enforcement layer. Domain rules are intended for use with
    /// stream evidence such as DNS answers, TLS SNI, or HTTP `Host`.
    /// If you need IP-level enforcement, use `HostSpec::Ip` or
    /// `HostSpec::Subnet` rules instead.
    pub fn matches_ip(&self, ip: IpAddr, port: u16) -> bool {
        // Port 0 in the rule means "all ports" (wildcard)
        if !self.ports.contains(&0) && !self.ports.contains(&port) {
            return false;
        }

        match &self.host {
            HostSpec::Ip(addr) => *addr == ip,
            // Domain matching requires DNS resolution - see doc comment above.
            HostSpec::Domain(_) => false,
            HostSpec::Subnet(subnet) => subnet.contains(ip),
        }
    }

    pub fn matches(&self, ip: Ipv4Addr, port: u16) -> bool {
        self.matches_ip(IpAddr::V4(ip), port)
    }

    /// Check if this rule matches a domain name and port.
    ///
    /// Port 0 in the rule's port set is treated as a wildcard meaning "all
    /// ports". Only [`HostSpec::Domain`] rules match here; IP and subnet rules
    /// are intentionally excluded because domain evidence must not authorize
    /// unrelated raw-IP rules.
    pub fn matches_domain(&self, name: &str, port: u16) -> bool {
        if !self.ports.contains(&0) && !self.ports.contains(&port) {
            return false;
        }
        self.host.matches_domain(name)
    }
}

// =============================================================================
// Host Specification
// =============================================================================

/// Prefix length that is statically bounded by the address family maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PrefixLen<const MAX: u8>(u8);

impl<const MAX: u8> PrefixLen<MAX> {
    /// Create a prefix length, rejecting values above the family maximum.
    pub const fn new(value: u8) -> Result<Self, PrefixLenError> {
        if value > MAX {
            return Err(PrefixLenError { value, max: MAX });
        }
        Ok(Self(value))
    }

    /// Return the validated prefix length as a plain integer.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<const MAX: u8> TryFrom<u8> for PrefixLen<MAX> {
    type Error = PrefixLenError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<const MAX: u8> Serialize for PrefixLen<MAX> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(self.0)
    }
}

impl<'de, const MAX: u8> Deserialize<'de> for PrefixLen<MAX> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = u8::deserialize(deserializer)?;
        Self::new(value).map_err(serde::de::Error::custom)
    }
}

/// Validated IPv4 CIDR prefix length.
pub type Ipv4PrefixLen = PrefixLen<32>;

/// Validated IPv6 CIDR prefix length.
pub type Ipv6PrefixLen = PrefixLen<128>;

/// Error returned for an out-of-range CIDR prefix length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixLenError {
    value: u8,
    max: u8,
}

impl PrefixLenError {
    /// The rejected prefix length.
    pub const fn value(self) -> u8 {
        self.value
    }

    /// The maximum valid prefix length for the address family.
    pub const fn max(self) -> u8 {
        self.max
    }
}

impl fmt::Display for PrefixLenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "prefix_len {} exceeds maximum {}", self.value, self.max)
    }
}

impl std::error::Error for PrefixLenError {}

/// IPv4 subnet with a prefix length that cannot exceed 32.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv4Subnet {
    /// Network address used for matching after masking.
    pub addr: Ipv4Addr,
    /// Validated IPv4 prefix length.
    pub prefix_len: Ipv4PrefixLen,
}

impl Ipv4Subnet {
    /// Create an IPv4 subnet.
    pub fn new(addr: Ipv4Addr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        Ok(Self {
            addr,
            prefix_len: Ipv4PrefixLen::new(prefix_len)?,
        })
    }

    /// Return `true` if the IP is in this subnet.
    pub const fn contains(self, ip: Ipv4Addr) -> bool {
        let prefix_len = self.prefix_len.get();
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let addr_bits = u32::from_be_bytes(self.addr.octets());
        let ip_bits = u32::from_be_bytes(ip.octets());
        (addr_bits & mask) == (ip_bits & mask)
    }
}

/// IPv6 subnet with a prefix length that cannot exceed 128.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ipv6Subnet {
    /// Network address used for matching after masking.
    pub addr: Ipv6Addr,
    /// Validated IPv6 prefix length.
    pub prefix_len: Ipv6PrefixLen,
}

impl Ipv6Subnet {
    /// Create an IPv6 subnet.
    pub fn new(addr: Ipv6Addr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        Ok(Self {
            addr,
            prefix_len: Ipv6PrefixLen::new(prefix_len)?,
        })
    }

    /// Return `true` if the IP is in this subnet.
    pub const fn contains(self, ip: Ipv6Addr) -> bool {
        let prefix_len = self.prefix_len.get();
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u128 << (128 - prefix_len)
        };
        let addr_bits = u128::from_be_bytes(self.addr.octets());
        let ip_bits = u128::from_be_bytes(ip.octets());
        (addr_bits & mask) == (ip_bits & mask)
    }
}

/// IP subnet whose address family is encoded in the variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpSubnet {
    /// IPv4 subnet.
    V4(Ipv4Subnet),
    /// IPv6 subnet.
    V6(Ipv6Subnet),
}

impl IpSubnet {
    /// Create an IP subnet matching the address family of `addr`.
    pub fn new(addr: IpAddr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        match addr {
            IpAddr::V4(addr) => Ok(Self::V4(Ipv4Subnet::new(addr, prefix_len)?)),
            IpAddr::V6(addr) => Ok(Self::V6(Ipv6Subnet::new(addr, prefix_len)?)),
        }
    }

    /// Return `true` if the IP is in this subnet.
    pub const fn contains(self, ip: IpAddr) -> bool {
        match (self, ip) {
            (Self::V4(subnet), IpAddr::V4(ip)) => subnet.contains(ip),
            (Self::V6(subnet), IpAddr::V6(ip)) => subnet.contains(ip),
            _ => false,
        }
    }

    /// Return the subnet address as an [`IpAddr`].
    pub const fn addr(self) -> IpAddr {
        match self {
            Self::V4(subnet) => IpAddr::V4(subnet.addr),
            Self::V6(subnet) => IpAddr::V6(subnet.addr),
        }
    }

    /// Return the validated prefix length.
    pub const fn prefix_len(self) -> u8 {
        match self {
            Self::V4(subnet) => subnet.prefix_len.get(),
            Self::V6(subnet) => subnet.prefix_len.get(),
        }
    }
}

impl From<Ipv4Subnet> for IpSubnet {
    fn from(value: Ipv4Subnet) -> Self {
        Self::V4(value)
    }
}

impl From<Ipv6Subnet> for IpSubnet {
    fn from(value: Ipv6Subnet) -> Self {
        Self::V6(value)
    }
}

impl fmt::Display for IpSubnet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr(), self.prefix_len())
    }
}

/// Specification of a host (IP, domain, or subnet)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSpec {
    /// Exact IP address
    Ip(IpAddr),
    /// Domain pattern (supports wildcards like *.github.com)
    ///
    /// **Note:** Domain rules do not match at the IP packet level in
    /// `PolicyNetBackend`. They require stream evidence from DNS answers, TLS
    /// SNI, HTTP `Host`, or another trusted parser.
    Domain(String),
    /// Subnet (CIDR notation).
    Subnet(IpSubnet),
}

impl HostSpec {
    /// Create a subnet specification.
    pub fn subnet(subnet: impl Into<IpSubnet>) -> Self {
        Self::Subnet(subnet.into())
    }

    /// Fallible version of [`subnet`](Self::subnet).
    ///
    /// Returns `Err` if `prefix_len` exceeds 32 for IPv4 or 128 for IPv6.
    pub fn try_subnet(addr: IpAddr, prefix_len: u8) -> Result<Self, PrefixLenError> {
        Ok(Self::Subnet(IpSubnet::new(addr, prefix_len)?))
    }

    /// Render the host spec in config-friendly string form.
    pub fn to_host_string(&self) -> String {
        match self {
            Self::Ip(addr) => addr.to_string(),
            Self::Domain(domain) => domain.clone(),
            Self::Subnet(subnet) => subnet.to_string(),
        }
    }

    /// Check whether this host spec matches a DNS-style domain name.
    ///
    /// Exact domain rules compare case-insensitively. Wildcard rules support
    /// `*` for all names and `*.example.com` for the bare apex plus any
    /// subdomain. Malformed wildcard forms such as `*example.com` do not
    /// match.
    pub fn matches_domain(&self, name: &str) -> bool {
        let Self::Domain(pattern) = self else {
            return false;
        };
        domain_pattern_matches(name, pattern)
    }
}

fn domain_pattern_matches(name: &str, pattern: &str) -> bool {
    let name = name.trim_end_matches('.').to_ascii_lowercase();
    let pattern = pattern.trim_end_matches('.').to_ascii_lowercase();
    if pattern == "*" || name == pattern {
        return true;
    }
    let Some(suffix) = pattern.strip_prefix("*.") else {
        return false;
    };
    name == suffix || name.ends_with(&format!(".{suffix}"))
}

// =============================================================================
// Network Policy
// =============================================================================

/// Network access policy for evidence-aware stream/domain authorization.
///
/// `NetworkPolicy` can contain domain rules. Domain rules require L7 evidence
/// from DNS, TLS SNI, HTTP Host, or another trusted parser; they are not raw
/// packet admission rules. Use [`PacketNetworkPolicy`] for packet-layer
/// enforcement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[must_use]
pub struct NetworkPolicy {
    /// Host rules (IP/domain/subnet allowlist)
    #[serde(default)]
    pub rules: Vec<HostRule>,

    /// Allow ICMP (ping, etc.)
    #[serde(default)]
    pub allow_icmp: bool,

    /// Allow DHCP (UDP ports 67/68 to broadcast addresses)
    #[serde(default)]
    pub allow_dhcp: bool,

    /// Policy name/description
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Policy version (for config management)
    #[serde(default)]
    pub version: u32,
}

/// Raw packet admission policy.
///
/// This type contains only policy inputs available in the packet path:
/// destination IP/subnet, port, default action, and coarse ICMP/DHCP flags.
/// Domain rules are omitted when converting from [`NetworkPolicy`] because
/// they require stream evidence.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[must_use]
pub struct PacketNetworkPolicy {
    /// IP/subnet rules used by raw packet admission.
    #[serde(default)]
    pub rules: Vec<HostRule>,

    /// Allow ICMP (ping, etc.).
    #[serde(default)]
    pub allow_icmp: bool,

    /// Allow DHCP (UDP ports 67/68 to broadcast addresses).
    #[serde(default)]
    pub allow_dhcp: bool,

    /// Policy name/description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Policy version.
    #[serde(default)]
    pub version: u32,
}

impl PacketNetworkPolicy {
    /// Create a deny-all packet policy.
    pub const fn deny_all() -> Self {
        Self {
            rules: Vec::new(),
            allow_icmp: false,
            allow_dhcp: false,
            name: None,
            version: 1,
        }
    }

    /// Project the raw packet portion of an evidence-aware network policy.
    pub fn from_network_policy(policy: &NetworkPolicy) -> Self {
        Self {
            rules: policy
                .rules
                .iter()
                .filter(|rule| !matches!(rule.host, HostSpec::Domain(_)))
                .cloned()
                .collect(),
            allow_icmp: policy.allow_icmp,
            allow_dhcp: policy.allow_dhcp,
            name: policy.name.clone(),
            version: policy.version,
        }
    }

    /// Check if a destination IPv4 address and port are allowed.
    pub fn is_allowed(&self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        self.is_allowed_ip(IpAddr::V4(dst_ip), dst_port)
    }

    /// Check if a destination IP address and port are allowed.
    pub fn is_allowed_ip(&self, dst_ip: IpAddr, dst_port: u16) -> bool {
        for rule in &self.rules {
            if rule.matches_ip(dst_ip, dst_port) {
                return true;
            }
        }

        false
    }
}

impl NetworkPolicy {
    /// Create a new empty policy (deny-all by default).
    ///
    /// This is the safest starting point - nothing is allowed until
    /// explicitly permitted.
    pub const fn new() -> Self {
        Self::deny_all()
    }

    /// Create a deny-all policy.
    ///
    /// Alias for `new()`. Explicit name for clarity.
    pub const fn deny_all() -> Self {
        Self {
            rules: Vec::new(),
            allow_icmp: false,
            allow_dhcp: false,
            name: None,
            version: 1,
        }
    }

    /// Create a fluent policy builder.
    pub const fn builder() -> NetworkPolicyBuilder {
        NetworkPolicyBuilder::new()
    }

    /// Project this policy into the raw packet policy enforced by
    /// `PolicyNetBackend`.
    pub fn to_packet_policy(&self) -> PacketNetworkPolicy {
        PacketNetworkPolicy::from_network_policy(self)
    }

    /// Set policy name
    ///
    pub fn with_name(mut self, name: &str) -> Self {
        self.name = Some(name.to_string());
        self
    }

    /// Allow ICMP traffic
    pub const fn allow_icmp(mut self) -> Self {
        self.allow_icmp = true;
        self
    }

    /// Allow DHCP traffic (UDP ports 67/68 to broadcast addresses)
    ///
    /// DHCP uses broadcast addresses which aren't normally in the policy.
    /// This flag allows DHCP discover/offer/request/ack packets.
    pub const fn allow_dhcp(mut self) -> Self {
        self.allow_dhcp = true;
        self
    }

    /// Add a rule allowing a specific IP and port
    pub fn allow_host_port(mut self, ip: Ipv4Addr, port: u16) -> Self {
        // Check if we already have a rule for this IP
        for rule in &mut self.rules {
            if let HostSpec::Ip(addr) = &rule.host
                && *addr == IpAddr::V4(ip)
            {
                rule.ports.insert(port);
                return self;
            }
        }
        // Add new rule
        self.rules.push(HostRule::ip(ip, &[port]));
        self
    }

    /// Add a rule allowing a specific IPv6 and port
    pub fn allow_host_port_v6(mut self, ip: Ipv6Addr, port: u16) -> Self {
        for rule in &mut self.rules {
            if let HostSpec::Ip(addr) = &rule.host
                && *addr == IpAddr::V6(ip)
            {
                rule.ports.insert(port);
                return self;
            }
        }
        self.rules.push(HostRule::ip_v6(ip, &[port]));
        self
    }

    /// Add a rule allowing a specific IP with multiple ports
    pub fn allow_host_ports(mut self, ip: Ipv4Addr, ports: &[u16]) -> Self {
        // Check if we already have a rule for this IP
        for rule in &mut self.rules {
            if let HostSpec::Ip(addr) = &rule.host
                && *addr == IpAddr::V4(ip)
            {
                rule.ports.extend(ports.iter());
                return self;
            }
        }
        // Add new rule
        self.rules.push(HostRule::ip(ip, ports));
        self
    }

    /// Add a rule allowing a specific IPv6 with multiple ports
    pub fn allow_host_ports_v6(mut self, ip: Ipv6Addr, ports: &[u16]) -> Self {
        for rule in &mut self.rules {
            if let HostSpec::Ip(addr) = &rule.host
                && *addr == IpAddr::V6(ip)
            {
                rule.ports.extend(ports.iter());
                return self;
            }
        }
        self.rules.push(HostRule::ip_v6(ip, ports));
        self
    }

    /// Add a rule allowing a domain pattern with ports
    pub fn allow_domain(mut self, pattern: &str, ports: &[u16]) -> Self {
        self.rules.push(HostRule::domain(pattern, ports));
        self
    }

    /// Add a rule allowing a subnet with ports
    pub fn allow_subnet(mut self, subnet: Ipv4Subnet, ports: &[u16]) -> Self {
        self.rules.push(HostRule {
            host: HostSpec::subnet(subnet),
            ports: ports.iter().copied().collect(),
            comment: None,
        });
        self
    }

    /// Add a rule allowing an IPv6 subnet with ports
    pub fn allow_subnet_v6(mut self, subnet: Ipv6Subnet, ports: &[u16]) -> Self {
        self.rules.push(HostRule {
            host: HostSpec::subnet(subnet),
            ports: ports.iter().copied().collect(),
            comment: None,
        });
        self
    }

    /// Add a pre-built rule
    pub fn add_rule(mut self, rule: HostRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Check if a destination IP:port is allowed
    pub fn is_allowed(&self, dst_ip: Ipv4Addr, dst_port: u16) -> bool {
        self.is_allowed_ip(IpAddr::V4(dst_ip), dst_port)
    }

    /// Check if a destination IP:port is allowed (IPv4/IPv6)
    pub fn is_allowed_ip(&self, dst_ip: IpAddr, dst_port: u16) -> bool {
        // Check all rules
        for rule in &self.rules {
            if rule.matches_ip(dst_ip, dst_port) {
                return true;
            }
        }

        false
    }

    /// Combine this policy with another using AND semantics (intersection).
    ///
    /// This implements **capability attenuation**: the resulting policy only
    /// allows traffic that BOTH policies allow. This is used when spawning
    /// VMs from a zygote - the spawned VM can only have equal or fewer
    /// permissions than the parent.
    ///
    /// # Semantics
    /// - For IP rules: keeps rules that exist in BOTH policies (port intersection)
    /// - For flags (ICMP, DHCP): both must allow for result to allow
    /// - For domain rules: keeps domains that appear in both
    /// - For subnet rules: keeps only exact matches (conservative)
    ///
    /// # Example
    /// ```
    /// use amla_policy_net::NetworkPolicy;
    /// use std::net::Ipv4Addr;
    ///
    /// let base = NetworkPolicy::builder()
    ///     .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
    ///     .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
    ///     .enable_icmp()
    ///     .build();
    ///
    /// let additional = NetworkPolicy::builder()
    ///     .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
    ///     .build();
    ///
    /// // Result only allows 8.8.8.8:53 (intersection)
    /// let combined = base.and(&additional);
    /// ```
    pub fn and(&self, other: &Self) -> Self {
        // Combine rules by computing intersection
        let mut combined_rules = Vec::new();

        for self_rule in &self.rules {
            for other_rule in &other.rules {
                // Only combine rules with matching host specs
                if self_rule.host == other_rule.host {
                    // Intersect the port sets
                    // Special case: port 0 means "all ports" - handle it
                    let ports: HashSet<u16> = if self_rule.ports.contains(&0) {
                        // self allows all ports, use other's ports
                        other_rule.ports.clone()
                    } else if other_rule.ports.contains(&0) {
                        // other allows all ports, use self's ports
                        self_rule.ports.clone()
                    } else {
                        // Intersect the port sets
                        self_rule
                            .ports
                            .intersection(&other_rule.ports)
                            .copied()
                            .collect()
                    };

                    // Only add rule if there are allowed ports
                    if !ports.is_empty() {
                        combined_rules.push(HostRule {
                            host: self_rule.host.clone(),
                            ports,
                            comment: match (&self_rule.comment, &other_rule.comment) {
                                (Some(a), Some(b)) => Some(format!("{a} & {b}")),
                                (Some(a), None) | (None, Some(a)) => Some(a.clone()),
                                (None, None) => None,
                            },
                        });
                    }
                }
            }
        }

        Self {
            rules: combined_rules,
            // Both must allow ICMP for combined to allow
            allow_icmp: self.allow_icmp && other.allow_icmp,
            // Both must allow DHCP for combined to allow
            allow_dhcp: self.allow_dhcp && other.allow_dhcp,
            name: Some(format!(
                "{} & {}",
                self.name.as_deref().unwrap_or("policy1"),
                other.name.as_deref().unwrap_or("policy2")
            )),
            version: std::cmp::max(self.version, other.version),
        }
    }

    /// Validate policy configuration
    ///
    /// Returns a list of validation errors/warnings.
    pub fn validate(&self) -> Vec<PolicyValidationError> {
        let mut errors = Vec::new();

        // Check for empty port sets
        for (i, rule) in self.rules.iter().enumerate() {
            if rule.ports.is_empty() {
                errors.push(PolicyValidationError::EmptyPortSet { rule_index: i });
            }
        }

        // Check for duplicate rules
        let mut seen_ips: HashSet<IpAddr> = HashSet::new();
        for rule in &self.rules {
            if let HostSpec::Ip(addr) = &rule.host {
                if seen_ips.contains(addr) {
                    // Not an error per se, just a note (we merge ports)
                }
                seen_ips.insert(*addr);
            }
        }

        errors
    }
}

/// Fluent builder for `NetworkPolicy`.
#[derive(Debug, Clone)]
#[must_use]
pub struct NetworkPolicyBuilder {
    policy: NetworkPolicy,
}

impl Default for NetworkPolicyBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkPolicyBuilder {
    /// Start a builder with a deny-all policy.
    pub const fn new() -> Self {
        Self {
            policy: NetworkPolicy::deny_all(),
        }
    }

    /// Set policy name.
    pub fn name(mut self, name: impl Into<String>) -> Self {
        self.policy.name = Some(name.into());
        self
    }

    /// Set policy version.
    pub const fn version(mut self, version: u32) -> Self {
        self.policy.version = version;
        self
    }

    /// Allow ICMP traffic.
    pub const fn allow_icmp(mut self, allow: bool) -> Self {
        self.policy.allow_icmp = allow;
        self
    }

    /// Allow ICMP traffic (convenience).
    pub const fn enable_icmp(self) -> Self {
        self.allow_icmp(true)
    }

    /// Allow DHCP traffic.
    pub const fn allow_dhcp(mut self, allow: bool) -> Self {
        self.policy.allow_dhcp = allow;
        self
    }

    /// Allow DHCP traffic (convenience).
    pub const fn enable_dhcp(self) -> Self {
        self.allow_dhcp(true)
    }

    /// Add a domain rule.
    pub fn allow_domain(mut self, domain: impl Into<String>, ports: &[u16]) -> Self {
        self.policy.rules.push(HostRule {
            host: HostSpec::Domain(domain.into()),
            ports: ports.iter().copied().collect(),
            comment: None,
        });
        self
    }

    /// Add a domain rule with a comment.
    pub fn allow_domain_with_comment(
        mut self,
        domain: impl Into<String>,
        ports: &[u16],
        comment: impl Into<String>,
    ) -> Self {
        self.policy.rules.push(HostRule {
            host: HostSpec::Domain(domain.into()),
            ports: ports.iter().copied().collect(),
            comment: Some(comment.into()),
        });
        self
    }

    /// Add a host rule for a single port.
    pub fn allow_host_port(mut self, host: Ipv4Addr, port: u16) -> Self {
        self.policy = self.policy.allow_host_port(host, port);
        self
    }

    /// Add a host rule for multiple ports.
    pub fn allow_host_ports(mut self, host: Ipv4Addr, ports: &[u16]) -> Self {
        self.policy = self.policy.allow_host_ports(host, ports);
        self
    }

    /// Add a subnet rule.
    pub fn allow_subnet(mut self, subnet: Ipv4Subnet, ports: &[u16]) -> Self {
        self.policy = self.policy.allow_subnet(subnet, ports);
        self
    }

    /// Add a host rule from `HostSpec`.
    pub fn allow_host_spec(mut self, host: HostSpec, ports: &[u16]) -> Self {
        self.policy.rules.push(HostRule {
            host,
            ports: ports.iter().copied().collect(),
            comment: None,
        });
        self
    }

    /// Add a host rule with a comment.
    pub fn allow_host_rule(mut self, rule: HostRule) -> Self {
        self.policy.rules.push(rule);
        self
    }

    /// Build the `NetworkPolicy`.
    pub fn build(self) -> NetworkPolicy {
        self.policy
    }
}

/// Policy validation error
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValidationError {
    /// Rule has no ports configured
    EmptyPortSet { rule_index: usize },
    /// Invalid port number
    InvalidPort { rule_index: usize, port: u16 },
    /// Invalid wildcard pattern
    InvalidWildcard { rule_index: usize, pattern: String },
}

impl std::fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyPortSet { rule_index } => {
                write!(f, "rule {rule_index} has no ports configured")
            }
            Self::InvalidPort { rule_index, port } => {
                write!(f, "rule {rule_index} has invalid port {port}")
            }
            Self::InvalidWildcard {
                rule_index,
                pattern,
            } => {
                write!(
                    f,
                    "rule {rule_index} has invalid wildcard pattern: {pattern}"
                )
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn subnet(addr: Ipv4Addr, prefix_len: u8) -> Ipv4Subnet {
        Ipv4Subnet::new(addr, prefix_len).unwrap()
    }

    fn subnet_v6(addr: Ipv6Addr, prefix_len: u8) -> Ipv6Subnet {
        Ipv6Subnet::new(addr, prefix_len).unwrap()
    }

    // =========================================================================
    // NetworkPolicy Builder Tests
    // =========================================================================

    #[test]
    fn test_empty_policy_denies_all() {
        let policy = NetworkPolicy::builder().build();

        assert!(!policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        assert!(!policy.allow_icmp);
    }

    #[test]
    fn test_deny_all_is_fail_closed() {
        // Verify that an empty policy with default settings denies everything
        let policy = NetworkPolicy::deny_all();

        // Test various IPs and ports
        assert!(!policy.is_allowed(Ipv4Addr::UNSPECIFIED, 0));
        assert!(!policy.is_allowed(Ipv4Addr::LOCALHOST, 80));
        assert!(!policy.is_allowed(Ipv4Addr::BROADCAST, 65535));
        assert!(!policy.is_allowed(Ipv4Addr::new(10, 0, 0, 1), 22));
        assert!(!policy.allow_icmp);
        assert!(!policy.allow_dhcp);
    }

    #[test]
    fn test_new_creates_deny_all_policy() {
        // NetworkPolicy::new() should be equivalent to deny_all()
        let policy = NetworkPolicy::new();

        assert!(policy.rules.is_empty());
        assert!(!policy.allow_icmp);
        assert!(!policy.allow_dhcp);
    }

    #[test]
    fn test_allow_host_port() {
        let policy = NetworkPolicy::builder()
            .allow_host_spec(HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))), &[443])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80)); // Wrong port
        assert!(!policy.is_allowed(Ipv4Addr::new(5, 6, 7, 8), 443)); // Wrong IP
    }

    #[test]
    fn test_builder_allow_host_port_convenience() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        assert!(!policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 80));
    }

    #[test]
    fn test_allow_multiple_ports() {
        let policy = NetworkPolicy::builder()
            .allow_host_ports(Ipv4Addr::new(192, 168, 1, 1), &[80, 443, 8080])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 80));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 8080));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 22));
    }

    #[test]
    fn test_enable_dhcp() {
        let policy = NetworkPolicy::builder().enable_dhcp().build();

        assert!(policy.allow_dhcp);
        assert!(!policy.allow_icmp); // Shouldn't affect ICMP
    }

    #[test]
    fn test_enable_icmp() {
        let policy = NetworkPolicy::builder().enable_icmp().build();

        assert!(policy.allow_icmp);
        assert!(!policy.allow_dhcp); // Shouldn't affect DHCP
    }

    #[test]
    fn test_enable_both_dhcp_and_icmp() {
        let policy = NetworkPolicy::builder().enable_dhcp().enable_icmp().build();

        assert!(policy.allow_dhcp);
        assert!(policy.allow_icmp);
    }

    #[test]
    fn test_builder_name() {
        let policy = NetworkPolicy::builder().name("my-custom-policy").build();

        assert_eq!(policy.name, Some("my-custom-policy".to_string()));
    }

    #[test]
    fn test_allow_domain() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .build();

        assert_eq!(policy.rules.len(), 1);
        match &policy.rules[0].host {
            HostSpec::Domain(d) => assert_eq!(d, "api.openai.com"),
            _ => panic!("Expected Domain HostSpec"),
        }
        assert!(policy.rules[0].ports.contains(&443));
    }

    #[test]
    fn test_allow_domain_with_comment() {
        let policy = NetworkPolicy::builder()
            .allow_domain_with_comment("api.example.com", &[443], "Example API")
            .build();

        assert_eq!(policy.rules[0].comment, Some("Example API".to_string()));
    }

    // =========================================================================
    // Subnet Matching Tests
    // =========================================================================

    #[test]
    fn test_allow_subnet() {
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8), &[443])
            .build();

        // All 10.x.x.x should match
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 0, 1), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(10, 1, 2, 3), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(10, 255, 255, 255), 443));

        // Different subnet should not match
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 443));
        assert!(!policy.is_allowed(Ipv4Addr::new(11, 0, 0, 1), 443));
    }

    #[test]
    fn test_subnet_24() {
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(192, 168, 1, 0), 24), &[22, 80])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 22));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 254), 80));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 2, 1), 22));
    }

    #[test]
    fn test_subnet_16() {
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(172, 16, 0, 0), 16), &[443])
            .build();

        // Should match 172.16.x.x
        assert!(policy.is_allowed(Ipv4Addr::new(172, 16, 0, 1), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(172, 16, 255, 255), 443));

        // Should not match 172.17.x.x
        assert!(!policy.is_allowed(Ipv4Addr::new(172, 17, 0, 1), 443));
    }

    #[test]
    fn test_subnet_32_single_host() {
        // /32 should match only the exact IP
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(192, 168, 1, 100), 32), &[22])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 100), 22));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 101), 22));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 99), 22));
    }

    #[test]
    fn test_subnet_0_all_ips() {
        // /0 should match all IPv4 addresses
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::UNSPECIFIED, 0), &[80])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 80));
        assert!(policy.is_allowed(Ipv4Addr::BROADCAST, 80));

        // Wrong port should still be denied
        assert!(!policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
    }

    #[test]
    fn test_subnet_boundary_cases() {
        // Test /25 (128 hosts)
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(192, 168, 1, 0), 25), &[443])
            .build();

        // First half of /24 (0-127)
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 0), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 127), 443));

        // Second half (128-255) should NOT match
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 128), 443));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 255), 443));
    }

    #[test]
    fn test_subnet_ipv6() {
        let policy = NetworkPolicy::new().allow_subnet_v6(
            subnet_v6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0), 32),
            &[443],
        );

        // Should match any 2001:db8::/32 address
        assert!(policy.is_allowed_ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0x1, 0, 0, 0, 0, 1)),
            443
        ));
        assert!(policy.is_allowed_ip(
            IpAddr::V6(Ipv6Addr::new(
                0x2001, 0xdb8, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
            )),
            443
        ));

        // Different prefix should not match
        assert!(!policy.is_allowed_ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1)),
            443
        ));
    }

    // =========================================================================
    // Policy Evaluation Tests
    // =========================================================================

    #[test]
    fn test_is_allowed_checks_all_rules() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .allow_subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8), &[22])
            .build();

        // All should be allowed
        assert!(policy.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 53));
        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        assert!(policy.is_allowed(Ipv4Addr::new(10, 5, 5, 5), 22));

        // Not in any rule
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 80));
    }

    #[test]
    fn test_is_allowed_ip_ipv4() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();

        assert!(policy.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443));
        assert!(!policy.is_allowed_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 5)), 443));
    }

    #[test]
    fn test_is_allowed_ip_ipv6() {
        let policy = NetworkPolicy::new().allow_host_ports_v6(Ipv6Addr::LOCALHOST, &[8080]);

        assert!(policy.is_allowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080));
        assert!(!policy.is_allowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80));
    }

    // =========================================================================
    // Rule Accumulation and Port Merging Tests
    // =========================================================================

    #[test]
    fn test_rule_accumulation() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 443)
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 80)
            .build();

        // Both ports should be allowed (ports merged)
        assert!(policy.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 80));

        // Should only have one rule (merged)
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_ports_merged_for_same_ip() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 853)
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 443)
            .build();

        // Only one rule should exist
        assert_eq!(policy.rules.len(), 1);

        // All three ports should be in the merged set
        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 853));
        assert!(policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 443));
    }

    #[test]
    fn test_different_ips_not_merged() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();

        // Should have two separate rules
        assert_eq!(policy.rules.len(), 2);
    }

    // =========================================================================
    // Port Zero Wildcard Tests
    // =========================================================================

    #[test]
    fn test_port_zero_wildcard() {
        // Port 0 means "all ports" - useful for allowing all traffic to a host
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(10, 0, 2, 2), 0)
            .build(); // Gateway, all ports

        // Should allow any port to 10.0.2.2
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 67)); // DHCP
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 53)); // DNS
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 443)); // HTTPS
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 80)); // HTTP
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 1)); // Low port
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 65535)); // High port

        // But other IPs should still be denied
        assert!(!policy.is_allowed(Ipv4Addr::new(10, 0, 2, 3), 53));
        assert!(!policy.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
    }

    #[test]
    fn test_port_zero_with_other_ports() {
        // If port 0 is in the set, it should act as wildcard even with other ports
        let mut policy = NetworkPolicy::builder().build();
        policy.rules.push(HostRule {
            host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            ports: [0, 443].into_iter().collect(), // 0 = wildcard, 443 specific
            comment: None,
        });

        // All ports should be allowed due to port 0
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 22));
    }

    // =========================================================================
    // Policy AND (Intersection) Tests
    // =========================================================================

    #[test]
    fn test_policy_and_intersection() {
        // Base policy allows 8.8.8.8:53, 1.1.1.1:53, and ICMP
        let base = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
            .enable_icmp()
            .build();

        // Additional policy only allows 8.8.8.8:53
        let additional = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();

        // Combined (AND) policy should only allow 8.8.8.8:53
        let combined = base.and(&additional);

        // 8.8.8.8:53 is allowed by both
        assert!(combined.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));

        // 1.1.1.1:53 is NOT in combined (only in base)
        assert!(!combined.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 53));

        // ICMP: base allows, additional doesn't have it -> NOT allowed
        assert!(!combined.allow_icmp);
    }

    #[test]
    fn test_policy_and_port_intersection() {
        // Base allows 8.8.8.8:53 and 8.8.8.8:443
        let base = NetworkPolicy::builder()
            .allow_host_ports(Ipv4Addr::new(8, 8, 8, 8), &[53, 443])
            .build();

        // Additional allows 8.8.8.8:443 and 8.8.8.8:80
        let additional = NetworkPolicy::builder()
            .allow_host_ports(Ipv4Addr::new(8, 8, 8, 8), &[443, 80])
            .build();

        // Combined should only allow 8.8.8.8:443 (intersection)
        let combined = base.and(&additional);

        assert!(combined.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 443));
        assert!(!combined.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53)); // Only in base
        assert!(!combined.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 80)); // Only in additional
    }

    #[test]
    fn test_policy_and_port_zero_wildcard() {
        // Base allows any port to 10.0.2.2 (port 0 = wildcard)
        let base = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(10, 0, 2, 2), 0)
            .build();

        // Additional only allows port 53
        let additional = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(10, 0, 2, 2), 53)
            .build();

        // Combined should allow 10.0.2.2:53 (specific from additional, wildcard matches)
        let combined = base.and(&additional);

        assert!(combined.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 53));
        // Port 80 not in combined (not in additional's specific ports)
        assert!(!combined.is_allowed(Ipv4Addr::new(10, 0, 2, 2), 80));
    }

    #[test]
    fn test_policy_and_disjoint_hosts() {
        // Base allows host A
        let base = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 53)
            .build();

        // Additional allows host B (different host)
        let additional = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();

        // Combined should allow nothing (disjoint)
        let combined = base.and(&additional);

        assert!(!combined.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 53));
        assert!(!combined.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
    }

    #[test]
    fn test_policy_and_dhcp_intersection() {
        let with_dhcp = NetworkPolicy::builder().enable_dhcp().build();
        let without_dhcp = NetworkPolicy::builder().build();

        // DHCP allowed AND not allowed = not allowed
        assert!(!with_dhcp.and(&without_dhcp).allow_dhcp);
        assert!(!without_dhcp.and(&with_dhcp).allow_dhcp);

        // DHCP allowed AND allowed = allowed
        let both_dhcp = with_dhcp.and(&NetworkPolicy::builder().enable_dhcp().build());
        assert!(both_dhcp.allow_dhcp);
    }

    // =========================================================================
    // Validation Tests
    // =========================================================================

    #[test]
    fn test_validation_empty_ports() {
        let mut policy = NetworkPolicy::builder().build();
        policy.rules.push(HostRule {
            host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            ports: HashSet::new(), // Empty!
            comment: None,
        });

        let errors = policy.validate();
        assert!(errors.contains(&PolicyValidationError::EmptyPortSet { rule_index: 0 }));
    }

    #[test]
    fn test_validation_multiple_empty_ports() {
        let mut policy = NetworkPolicy::builder().build();
        policy.rules.push(HostRule {
            host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
            ports: HashSet::new(),
            comment: None,
        });
        policy.rules.push(HostRule {
            host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))),
            ports: HashSet::new(),
            comment: None,
        });

        let errors = policy.validate();
        assert!(errors.contains(&PolicyValidationError::EmptyPortSet { rule_index: 0 }));
        assert!(errors.contains(&PolicyValidationError::EmptyPortSet { rule_index: 1 }));
    }

    #[test]
    fn test_validation_valid_policy_no_errors() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(8, 8, 8, 8), 53)
            .enable_icmp()
            .build();

        let errors = policy.validate();
        assert!(errors.is_empty());
    }

    // =========================================================================
    // Serialization Tests
    // =========================================================================

    #[test]
    fn test_serialization_roundtrip() {
        let policy = NetworkPolicy::builder()
            .name("test-policy")
            .allow_host_ports(Ipv4Addr::new(8, 8, 8, 8), &[53, 853])
            .allow_host_port(Ipv4Addr::new(1, 1, 1, 1), 443)
            .enable_icmp()
            .build();

        let json = serde_json::to_string_pretty(&policy).unwrap();
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.name, Some("test-policy".to_string()));
        assert!(parsed.allow_icmp);
        assert!(parsed.is_allowed(Ipv4Addr::new(8, 8, 8, 8), 53));
        assert!(parsed.is_allowed(Ipv4Addr::new(1, 1, 1, 1), 443));
    }

    #[test]
    fn test_serialization_subnet_roundtrip() {
        let policy = NetworkPolicy::builder()
            .allow_subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8), &[22, 80, 443])
            .build();

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();

        assert!(parsed.is_allowed(Ipv4Addr::new(10, 1, 2, 3), 22));
        assert!(parsed.is_allowed(Ipv4Addr::new(10, 255, 255, 255), 443));
    }

    #[test]
    fn test_serialization_empty_policy() {
        let policy = NetworkPolicy::deny_all();

        let json = serde_json::to_string(&policy).unwrap();
        let parsed: NetworkPolicy = serde_json::from_str(&json).unwrap();

        assert!(parsed.rules.is_empty());
        assert!(!parsed.allow_icmp);
        assert!(!parsed.allow_dhcp);
    }

    // =========================================================================
    // HostRule Tests
    // =========================================================================

    #[test]
    fn test_host_rule_with_comment() {
        let rule = HostRule::ip(Ipv4Addr::new(8, 8, 8, 8), &[53]).with_comment("Google DNS");

        assert_eq!(rule.comment, Some("Google DNS".to_string()));
        assert!(rule.matches(Ipv4Addr::new(8, 8, 8, 8), 53));
    }

    #[test]
    fn test_host_rule_ip_v6() {
        let rule = HostRule::ip_v6(Ipv6Addr::LOCALHOST, &[8080, 9090]);

        assert!(rule.matches_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080));
        assert!(rule.matches_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 9090));
        assert!(!rule.matches_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80));
    }

    #[test]
    fn test_domain_rule_does_not_match_ip_directly() {
        // Domain rules require DNS resolution, so they don't match raw IPs
        let rule = HostRule::domain("api.openai.com", &[443]);

        // Should not match any IP directly
        assert!(!rule.matches(Ipv4Addr::new(1, 2, 3, 4), 443));
    }

    #[test]
    fn test_packet_policy_projection_omits_domain_rules() {
        let policy = NetworkPolicy::builder()
            .allow_domain("api.openai.com", &[443])
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .enable_icmp()
            .build();

        let packet_policy = policy.to_packet_policy();

        assert_eq!(packet_policy.rules.len(), 1);
        assert!(packet_policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!packet_policy.is_allowed(Ipv4Addr::new(93, 184, 216, 34), 443));
        assert!(packet_policy.allow_icmp);
    }

    #[test]
    fn test_host_rule_matches_port_only_when_in_set() {
        let rule = HostRule::ip(Ipv4Addr::new(1, 2, 3, 4), &[80, 443]);

        assert!(rule.matches(Ipv4Addr::new(1, 2, 3, 4), 80));
        assert!(rule.matches(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!rule.matches(Ipv4Addr::new(1, 2, 3, 4), 22));
        assert!(!rule.matches(Ipv4Addr::new(1, 2, 3, 4), 8080));
    }

    // =========================================================================
    // HostSpec Tests
    // =========================================================================

    #[test]
    fn test_host_spec_subnet_creation() {
        let spec = HostSpec::subnet(subnet(Ipv4Addr::new(192, 168, 0, 0), 16));
        match spec {
            HostSpec::Subnet(IpSubnet::V4(subnet)) => {
                assert_eq!(subnet.addr, Ipv4Addr::new(192, 168, 0, 0));
                assert_eq!(subnet.prefix_len.get(), 16);
            }
            _ => panic!("Expected Subnet"),
        }
    }

    #[test]
    fn test_host_spec_to_host_string() {
        assert_eq!(
            HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))).to_host_string(),
            "1.2.3.4"
        );
        assert_eq!(
            HostSpec::Domain("example.com".to_string()).to_host_string(),
            "example.com"
        );
        assert_eq!(
            HostSpec::subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8)).to_host_string(),
            "10.0.0.0/8"
        );
    }

    #[test]
    fn test_host_spec_subnet_invalid_ipv4_prefix() {
        assert!(HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33).is_err());
    }

    #[test]
    fn test_host_spec_subnet_invalid_ipv6_prefix() {
        assert!(HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::LOCALHOST), 129).is_err());
    }

    #[test]
    fn test_subnet_prefix_len_overflow_ipv4_rejected_by_type() {
        let err = Ipv4PrefixLen::new(33).unwrap_err();
        assert_eq!(err.value(), 33);
        assert_eq!(err.max(), 32);
        assert!(Ipv4Subnet::new(Ipv4Addr::new(10, 0, 0, 1), 33).is_err());
    }

    #[test]
    fn test_subnet_prefix_len_overflow_ipv6_rejected_by_type() {
        let err = Ipv6PrefixLen::new(129).unwrap_err();
        assert_eq!(err.value(), 129);
        assert_eq!(err.max(), 128);
        assert!(Ipv6Subnet::new(Ipv6Addr::LOCALHOST, 129).is_err());
    }

    #[test]
    fn test_subnet_prefix_len_overflow_rejected_by_deserialize() {
        let json = serde_json::json!({
            "subnet": {
                "v4": {
                    "addr": "10.0.0.1",
                    "prefix_len": 33
                }
            }
        });
        assert!(serde_json::from_value::<HostSpec>(json).is_err());
    }

    // =========================================================================
    // Edge Case Tests
    // =========================================================================

    #[test]
    fn test_loopback_addresses() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::LOCALHOST, 8080)
            .build();

        assert!(policy.is_allowed(Ipv4Addr::LOCALHOST, 8080));
        assert!(!policy.is_allowed(Ipv4Addr::new(127, 0, 0, 2), 8080));
    }

    #[test]
    fn test_broadcast_address() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::BROADCAST, 67)
            .build();

        assert!(policy.is_allowed(Ipv4Addr::BROADCAST, 67));
    }

    #[test]
    fn test_unspecified_address() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::UNSPECIFIED, 80)
            .build();

        assert!(policy.is_allowed(Ipv4Addr::UNSPECIFIED, 80));
    }

    #[test]
    fn test_high_port_numbers() {
        let policy = NetworkPolicy::builder()
            .allow_host_ports(Ipv4Addr::new(1, 2, 3, 4), &[65535, 65534])
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 65535));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 65534));
    }

    #[test]
    fn test_port_one() {
        // Port 1 is a valid port (though rarely used)
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 1)
            .build();

        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 1));
    }

    // =========================================================================
    // Builder allow_icmp/allow_dhcp(false) Tests
    // =========================================================================

    #[test]
    fn test_builder_allow_icmp_false_disables() {
        let policy = NetworkPolicy::builder()
            .enable_icmp()
            .allow_icmp(false)
            .build();
        assert!(!policy.allow_icmp);
    }

    #[test]
    fn test_builder_allow_dhcp_false_disables() {
        let policy = NetworkPolicy::builder()
            .enable_dhcp()
            .allow_dhcp(false)
            .build();
        assert!(!policy.allow_dhcp);
    }

    // =========================================================================
    // Default Builder Tests
    // =========================================================================

    #[test]
    fn test_builder_default_impl() {
        let builder1 = NetworkPolicyBuilder::new();
        let builder2 = NetworkPolicyBuilder::default();

        // Both should create equivalent policies
        let policy1 = builder1.build();
        let policy2 = builder2.build();

        assert_eq!(policy1.rules.len(), policy2.rules.len());
        assert_eq!(policy1.allow_icmp, policy2.allow_icmp);
        assert_eq!(policy1.allow_dhcp, policy2.allow_dhcp);
    }

    // =========================================================================
    // PolicyValidationError Display Tests
    // =========================================================================

    #[test]
    fn test_validation_error_display() {
        let err = PolicyValidationError::EmptyPortSet { rule_index: 5 };
        assert!(err.to_string().contains('5'));
        assert!(err.to_string().contains("no ports"));

        let err = PolicyValidationError::InvalidPort {
            rule_index: 3,
            port: 0,
        };
        assert!(err.to_string().contains('3'));
        assert!(err.to_string().contains('0'));

        let err = PolicyValidationError::InvalidWildcard {
            rule_index: 2,
            pattern: "**.bad".to_string(),
        };
        assert!(err.to_string().contains("**.bad"));
    }

    // =========================================================================
    // Self-consuming NetworkPolicy convenience methods
    // =========================================================================

    #[test]
    fn test_with_name_self_consuming() {
        let policy = NetworkPolicy::deny_all().with_name("my-policy");
        assert_eq!(policy.name, Some("my-policy".to_string()));
    }

    #[test]
    fn test_allow_icmp_self_consuming() {
        let policy = NetworkPolicy::deny_all().allow_icmp();
        assert!(policy.allow_icmp);
    }

    #[test]
    fn test_allow_dhcp_self_consuming() {
        let policy = NetworkPolicy::deny_all().allow_dhcp();
        assert!(policy.allow_dhcp);
    }

    // =========================================================================
    // IPv6 builder and NetworkPolicy methods
    // =========================================================================

    #[test]
    fn test_allow_host_port_v6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let policy = NetworkPolicy::deny_all().allow_host_port_v6(ip, 443);
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 443));
        assert!(!policy.is_allowed_ip(IpAddr::V6(ip), 80));
    }

    #[test]
    fn test_allow_host_port_v6_merges_ports() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let policy = NetworkPolicy::deny_all()
            .allow_host_port_v6(ip, 443)
            .allow_host_port_v6(ip, 80);
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 443));
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 80));
        assert_eq!(policy.rules.len(), 1, "should merge into one rule");
    }

    #[test]
    fn test_allow_host_ports_v6() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let policy = NetworkPolicy::deny_all().allow_host_ports_v6(ip, &[80, 443, 8080]);
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 80));
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 443));
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 8080));
        assert!(!policy.is_allowed_ip(IpAddr::V6(ip), 22));
    }

    #[test]
    fn test_allow_host_ports_v6_merges() {
        let ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let policy = NetworkPolicy::deny_all()
            .allow_host_ports_v6(ip, &[80])
            .allow_host_ports_v6(ip, &[443]);
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 80));
        assert!(policy.is_allowed_ip(IpAddr::V6(ip), 443));
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_allow_host_ports_merges_into_existing() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 80)
            .allow_host_ports(Ipv4Addr::new(1, 2, 3, 4), &[443, 8080])
            .build();
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 8080));
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_allow_domain_builder() {
        let policy = NetworkPolicy::builder()
            .allow_domain("*.example.com", &[443])
            .build();
        assert_eq!(policy.rules.len(), 1);
        assert!(matches!(
            &policy.rules[0].host,
            HostSpec::Domain(d) if d == "*.example.com"
        ));
    }

    #[test]
    fn test_allow_domain_self_consuming() {
        let policy = NetworkPolicy::deny_all().allow_domain("api.example.com", &[443]);
        assert_eq!(policy.rules.len(), 1);
    }

    #[test]
    fn test_add_rule_self_consuming() {
        let rule = HostRule::ip(Ipv4Addr::new(10, 0, 0, 1), &[22, 80]);
        let policy = NetworkPolicy::deny_all().add_rule(rule);
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 0, 1), 22));
        assert!(policy.is_allowed(Ipv4Addr::new(10, 0, 0, 1), 80));
    }

    #[test]
    fn test_allow_subnet_self_consuming() {
        let policy =
            NetworkPolicy::deny_all().allow_subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8), &[22]);
        assert!(policy.is_allowed(Ipv4Addr::new(10, 1, 2, 3), 22));
        assert!(!policy.is_allowed(Ipv4Addr::new(192, 168, 1, 1), 22));
    }

    #[test]
    fn test_ipv6_subnet_with_zero_prefix() {
        // prefix_len=0 means match any IPv6 address
        let policy =
            NetworkPolicy::deny_all().allow_subnet_v6(subnet_v6(Ipv6Addr::UNSPECIFIED, 0), &[443]);
        assert!(policy.is_allowed_ip(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            443
        ));
        assert!(policy.is_allowed_ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 443));
    }

    #[test]
    fn test_subnet_mixed_ip_versions_no_match() {
        // IPv4 subnet should not match IPv6 address
        let policy =
            NetworkPolicy::deny_all().allow_subnet(subnet(Ipv4Addr::new(10, 0, 0, 0), 8), &[443]);
        assert!(!policy.is_allowed_ip(IpAddr::V6(Ipv6Addr::new(0x0a00, 0, 0, 0, 0, 0, 0, 1)), 443));
    }

    #[test]
    fn test_and_one_sided_comment() {
        // Test (Some, None) and (None, Some) paths in and() comment merging
        let a = NetworkPolicy {
            rules: vec![HostRule {
                host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                ports: std::iter::once(53).collect(),
                comment: Some("has comment".to_string()),
            }],
            allow_icmp: false,
            allow_dhcp: false,
            name: None,
            version: 1,
        };
        let b = NetworkPolicy {
            rules: vec![HostRule {
                host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
                ports: std::iter::once(53).collect(),
                comment: None, // no comment
            }],
            allow_icmp: false,
            allow_dhcp: false,
            name: None,
            version: 1,
        };

        let combined = a.and(&b);
        assert_eq!(
            combined.rules[0].comment.as_deref(),
            Some("has comment"),
            "(Some, None) should keep the existing comment"
        );

        // Reverse to hit (None, Some) path
        let combined2 = b.and(&a);
        assert_eq!(
            combined2.rules[0].comment.as_deref(),
            Some("has comment"),
            "(None, Some) should keep the existing comment"
        );
    }

    #[test]
    fn test_and_with_wildcard_ports() {
        // Test the "port 0 means all ports" paths in the and() method
        let base = NetworkPolicy {
            rules: vec![HostRule {
                host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))),
                ports: std::iter::once(0).collect(), // wildcard: all ports
                comment: None,
            }],
            allow_icmp: true,
            allow_dhcp: false,
            name: Some("base".to_string()),
            version: 1,
        };

        let restricted = NetworkPolicy::builder()
            .allow_host_port(Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();

        let combined = base.and(&restricted);
        // base allows all ports, restricted allows only 443 → result is 443
        assert!(combined.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!combined.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80));

        // Reverse: restricted.and(&base) — "other allows all ports"
        let combined2 = restricted.and(&base);
        assert!(combined2.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 443));
        assert!(!combined2.is_allowed(Ipv4Addr::new(1, 2, 3, 4), 80));
    }

    #[test]
    fn test_and_comment_merging() {
        let a = NetworkPolicy {
            rules: vec![HostRule {
                host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                ports: std::iter::once(53).collect(),
                comment: Some("DNS primary".to_string()),
            }],
            allow_icmp: false,
            allow_dhcp: false,
            name: Some("a".to_string()),
            version: 1,
        };
        let b = NetworkPolicy {
            rules: vec![HostRule {
                host: HostSpec::Ip(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))),
                ports: std::iter::once(53).collect(),
                comment: Some("DNS backup".to_string()),
            }],
            allow_icmp: false,
            allow_dhcp: false,
            name: Some("b".to_string()),
            version: 2,
        };

        let combined = a.and(&b);
        assert_eq!(
            combined.rules[0].comment.as_deref(),
            Some("DNS primary & DNS backup")
        );
        assert_eq!(combined.name, Some("a & b".to_string()));
        assert_eq!(combined.version, 2);
    }

    // =========================================================================
    // try_subnet Tests
    // =========================================================================

    #[test]
    fn test_try_subnet_valid_ipv4() {
        let spec = HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 24);
        assert!(spec.is_ok());
    }

    #[test]
    fn test_try_subnet_valid_ipv6() {
        let spec = HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::LOCALHOST), 64);
        assert!(spec.is_ok());
    }

    #[test]
    fn test_try_subnet_invalid_ipv4() {
        let spec = HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)), 33);
        assert!(spec.is_err());
        assert_eq!(spec.unwrap_err().value(), 33);
    }

    #[test]
    fn test_try_subnet_invalid_ipv6() {
        let spec = HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::LOCALHOST), 129);
        assert!(spec.is_err());
        assert_eq!(spec.unwrap_err().value(), 129);
    }

    #[test]
    fn test_try_subnet_boundary_ipv4() {
        assert!(HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0).is_ok());
        assert!(HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 32).is_ok());
        assert!(HostSpec::try_subnet(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 33).is_err());
    }

    #[test]
    fn test_try_subnet_boundary_ipv6() {
        assert!(HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0).is_ok());
        assert!(HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 128).is_ok());
        assert!(HostSpec::try_subnet(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 129).is_err());
    }
}
