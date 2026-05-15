// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::{
    DEFAULT_DNS, DEFAULT_DNS_V6, DEFAULT_GATEWAY, DEFAULT_GATEWAY_MAC, DEFAULT_GATEWAY_V6,
    DEFAULT_GUEST_IP, DEFAULT_GUEST_IP_V6, DEFAULT_GUEST_MAC, DEFAULT_PREFIX_LEN_V6, UserNetError,
    VIRTUAL_MTU, ipv6_mask,
};

const MIN_MTU: usize = 1280;
const MAX_MTU: usize = VIRTUAL_MTU;

const fn default_guest_mac() -> [u8; 6] {
    DEFAULT_GUEST_MAC
}

fn default_egress_policy() -> EgressPolicy {
    EgressPolicy::default()
}

fn default_dns_forward_policy() -> DnsForwardPolicy {
    DnsForwardPolicy::default()
}

/// Parse the first IPv4 nameserver from resolv.conf-formatted content.
/// Errors if the input contains no IPv4 nameservers — callers must
/// surface the failure rather than silently resolving via a hard-coded
/// public resolver.
pub fn parse_host_dns_from_str(content: &str) -> Result<Ipv4Addr, UserNetError> {
    content
        .lines()
        .find_map(|line| {
            let line = line.trim();
            if !line.starts_with("nameserver") {
                return None;
            }
            let addr_str = line.split_whitespace().nth(1)?;
            addr_str.parse::<Ipv4Addr>().ok()
        })
        .ok_or_else(|| {
            UserNetError::InvalidConfig("resolv.conf contains no IPv4 nameservers".into())
        })
}

/// Parse the first host nameserver from /etc/resolv.conf.
pub fn parse_host_dns() -> Result<Ipv4Addr, UserNetError> {
    let contents = std::fs::read_to_string("/etc/resolv.conf").map_err(UserNetError::Io)?;
    parse_host_dns_from_str(&contents)
}

/// Configuration for user-mode networking
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserNetConfig {
    /// Gateway MAC address (what guest sees as router)
    pub gateway_mac: [u8; 6],

    /// Guest MAC address (virtio-net device)
    #[serde(default = "default_guest_mac")]
    pub guest_mac: [u8; 6],

    /// Gateway IP address
    pub gateway_ip: Ipv4Addr,

    /// Guest IP address (assigned by DHCP)
    pub guest_ip: Ipv4Addr,

    /// Network prefix length (e.g., 24 for /24)
    pub prefix_len: u8,

    /// DNS server address
    pub dns_server: Ipv4Addr,

    /// IPv6 gateway address
    pub gateway_ipv6: Ipv6Addr,

    /// IPv6 guest address
    pub guest_ipv6: Ipv6Addr,

    /// IPv6 prefix length
    pub prefix_len_v6: u8,

    /// IPv6 DNS server address. Reserved for future use; DNS forwarding is
    /// currently IPv4-only.
    pub dns_server_v6: Ipv6Addr,

    /// Host-to-guest port forwards.
    ///
    /// Reserved for future declarative listener setup. Non-empty values are
    /// rejected by [`validate`](Self::validate); use
    /// [`UserNetBackend::accept_inbound`](crate::UserNetBackend::accept_inbound)
    /// or [`accept_inbound_udp`](crate::UserNetBackend::accept_inbound_udp)
    /// today.
    pub port_forwards: Vec<PortForward>,

    /// MTU for the virtual network
    pub mtu: usize,

    /// Host DNS server used by the DNS forwarder to proxy gateway:53
    /// queries to a real resolver. Populated by [`UserNetConfig::try_default`]
    /// from `/etc/resolv.conf`. [`Default::default`] sets the unspecified
    /// address (`0.0.0.0`) as a sentinel that [`validate`] rejects, so a
    /// config built via plain `Default` must have DNS set explicitly
    /// before use.
    ///
    /// [`validate`]: UserNetConfig::validate
    pub host_dns_server: Ipv4Addr,

    /// Host socket egress policy for outbound guest NAT.
    ///
    /// Defaults to [`EgressPolicy::DenyAll`]. Call
    /// [`with_public_internet_egress`](Self::with_public_internet_egress) to
    /// enable outbound NAT to globally routable addresses while still blocking
    /// host-local, private, link-local, ULA, multicast, documentation, and
    /// other special-purpose networks.
    #[serde(default = "default_egress_policy")]
    pub egress_policy: EgressPolicy,

    /// Host socket egress policy for DNS forwarder sockets.
    ///
    /// Defaults to [`DnsForwardPolicy::DenyAll`]. DNS forwarding to
    /// [`host_dns_server`](Self::host_dns_server) or interceptor-selected
    /// [`DnsAction::Forward`](crate::interceptor::DnsAction::Forward)
    /// destinations is disabled unless callers explicitly opt in.
    #[serde(default = "default_dns_forward_policy")]
    pub dns_forward_policy: DnsForwardPolicy,
}

impl Default for UserNetConfig {
    fn default() -> Self {
        Self {
            gateway_mac: DEFAULT_GATEWAY_MAC,
            guest_mac: DEFAULT_GUEST_MAC,
            gateway_ip: DEFAULT_GATEWAY,
            guest_ip: DEFAULT_GUEST_IP,
            prefix_len: 24,
            dns_server: DEFAULT_DNS,
            gateway_ipv6: DEFAULT_GATEWAY_V6,
            guest_ipv6: DEFAULT_GUEST_IP_V6,
            prefix_len_v6: DEFAULT_PREFIX_LEN_V6,
            dns_server_v6: DEFAULT_DNS_V6,
            port_forwards: Vec::new(),
            mtu: VIRTUAL_MTU,
            host_dns_server: Ipv4Addr::UNSPECIFIED,
            egress_policy: EgressPolicy::default(),
            dns_forward_policy: DnsForwardPolicy::default(),
        }
    }
}

impl UserNetConfig {
    /// Create a new configuration with default settings.
    ///
    /// The `host_dns_server` field is the unspecified address (`0.0.0.0`)
    /// and must be set before the config is passed to
    /// [`UserNetBackend::try_new`](crate::UserNetBackend::try_new). Use
    /// [`try_default`](Self::try_default) for a config pre-populated from
    /// the host's `/etc/resolv.conf`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build a configuration using defaults, with `host_dns_server`
    /// populated from the host's `/etc/resolv.conf`. Returns an error if
    /// resolv.conf cannot be read or contains no IPv4 nameservers.
    pub fn try_default() -> Result<Self, UserNetError> {
        Ok(Self {
            host_dns_server: parse_host_dns()?,
            ..Self::default()
        })
    }

    /// Set the host DNS server explicitly. Required when building a config
    /// via [`new`](Self::new) / [`default`](Self::default) rather than
    /// [`try_default`](Self::try_default).
    #[must_use]
    pub const fn with_host_dns_server(mut self, ip: Ipv4Addr) -> Self {
        self.host_dns_server = ip;
        self
    }

    /// Allow outbound NAT only to globally routable Internet addresses.
    #[must_use]
    pub fn with_public_internet_egress(mut self) -> Self {
        self.egress_policy = EgressPolicy::PublicInternetOnly;
        self
    }

    /// Allow outbound NAT to any destination address.
    ///
    /// This includes host-local and private networks, so it should only be
    /// used when the caller deliberately wants the guest to reach those
    /// networks.
    #[must_use]
    pub fn with_unrestricted_egress(mut self) -> Self {
        self.egress_policy = EgressPolicy::AllowAll;
        self
    }

    /// Set the outbound NAT egress policy explicitly.
    #[must_use]
    pub fn with_egress_policy(mut self, policy: EgressPolicy) -> Self {
        self.egress_policy = policy;
        self
    }

    /// Configure DNS forwarding to use the same destination policy as NAT.
    #[must_use]
    pub fn with_dns_forwarding_via_egress_policy(mut self) -> Self {
        self.dns_forward_policy = DnsForwardPolicy::UseEgressPolicy;
        self
    }

    /// Allow DNS forwarding only to globally routable Internet resolvers.
    ///
    /// This is independent of [`egress_policy`](Self::egress_policy), so callers
    /// can permit DNS forwarding without permitting general outbound NAT.
    #[must_use]
    pub fn with_public_internet_dns_forwarding(mut self) -> Self {
        self.dns_forward_policy = DnsForwardPolicy::PublicInternetOnly;
        self
    }

    /// Allow DNS forwarding to any resolver address.
    ///
    /// This includes host-local and private resolvers. Use only when the guest
    /// should be able to send DNS queries to those networks through the host.
    #[must_use]
    pub fn with_unrestricted_dns_forwarding(mut self) -> Self {
        self.dns_forward_policy = DnsForwardPolicy::AllowAll;
        self
    }

    /// Set the DNS forwarding egress policy explicitly.
    #[must_use]
    pub fn with_dns_forward_policy(mut self, policy: DnsForwardPolicy) -> Self {
        self.dns_forward_policy = policy;
        self
    }

    /// Build the typed host egress authorizer for this configuration.
    pub(crate) fn host_egress_authorizer(&self) -> HostEgressAuthorizer {
        HostEgressAuthorizer::new(self.egress_policy.clone(), self.dns_forward_policy.clone())
    }

    /// Add a port forward from host to guest
    #[must_use]
    pub fn with_port_forward(mut self, forward: PortForward) -> Self {
        self.port_forwards.push(forward);
        self
    }

    /// Set custom guest MAC
    #[must_use]
    pub const fn with_guest_mac(mut self, mac: [u8; 6]) -> Self {
        self.guest_mac = mac;
        self
    }

    /// Set custom gateway IP
    #[must_use]
    pub const fn with_gateway_ip(mut self, ip: Ipv4Addr) -> Self {
        self.gateway_ip = ip;
        self
    }

    /// Set custom guest IP
    #[must_use]
    pub const fn with_guest_ip(mut self, ip: Ipv4Addr) -> Self {
        self.guest_ip = ip;
        self
    }

    /// Set custom DNS server
    #[must_use]
    pub const fn with_dns(mut self, dns: Ipv4Addr) -> Self {
        self.dns_server = dns;
        self
    }

    /// Set custom IPv6 gateway
    #[must_use]
    pub const fn with_gateway_ipv6(mut self, ip: Ipv6Addr) -> Self {
        self.gateway_ipv6 = ip;
        self
    }

    /// Set custom IPv6 guest address
    #[must_use]
    pub const fn with_guest_ipv6(mut self, ip: Ipv6Addr) -> Self {
        self.guest_ipv6 = ip;
        self
    }

    /// Set custom IPv6 prefix length
    #[must_use]
    pub const fn with_prefix_len_v6(mut self, prefix_len: u8) -> Self {
        self.prefix_len_v6 = prefix_len;
        self
    }

    /// Set custom IPv6 DNS server
    #[must_use]
    pub const fn with_dns_ipv6(mut self, dns: Ipv6Addr) -> Self {
        self.dns_server_v6 = dns;
        self
    }

    /// Validate configuration, returning an error if invalid.
    pub fn validate(&self) -> Result<(), UserNetError> {
        if self.prefix_len > 32 {
            return Err(UserNetError::InvalidConfig(format!(
                "IPv4 prefix_len must be <= 32, got {}",
                self.prefix_len
            )));
        }
        if self.prefix_len_v6 > 128 {
            return Err(UserNetError::InvalidConfig(format!(
                "IPv6 prefix_len must be <= 128, got {}",
                self.prefix_len_v6
            )));
        }
        if self.gateway_ip == self.guest_ip {
            return Err(UserNetError::InvalidConfig(
                "gateway_ip and guest_ip must differ".into(),
            ));
        }
        if self.gateway_ipv6 == self.guest_ipv6 {
            return Err(UserNetError::InvalidConfig(
                "gateway_ipv6 and guest_ipv6 must differ".into(),
            ));
        }
        if self.host_dns_server.is_unspecified() {
            return Err(UserNetError::InvalidConfig(
                "host_dns_server is unspecified — call try_default or with_host_dns_server".into(),
            ));
        }
        if !(MIN_MTU..=MAX_MTU).contains(&self.mtu) {
            return Err(UserNetError::InvalidConfig(format!(
                "mtu must be between {MIN_MTU} and {MAX_MTU}, got {}",
                self.mtu
            )));
        }
        // Verify gateway and guest are on the same IPv4 subnet.
        // Skip for /0 (any-to-any) and /32 (point-to-point, only one host).
        if self.prefix_len > 0 && self.prefix_len < 32 {
            let mask = u32::MAX << (32 - u32::from(self.prefix_len));
            let gw = u32::from(self.gateway_ip) & mask;
            let guest = u32::from(self.guest_ip) & mask;
            if gw != guest {
                return Err(UserNetError::InvalidConfig(format!(
                    "gateway {} and guest {} are not on the same /{} subnet",
                    self.gateway_ip, self.guest_ip, self.prefix_len
                )));
            }
        }
        // Verify gateway and guest are on the same IPv6 subnet.
        // Skip for /0 (any-to-any) and /128 (point-to-point, only one host).
        if self.prefix_len_v6 > 0 && self.prefix_len_v6 < 128 {
            let mask = ipv6_mask(self.prefix_len_v6);
            let gw = u128::from(self.gateway_ipv6) & mask;
            let guest = u128::from(self.guest_ipv6) & mask;
            if gw != guest {
                return Err(UserNetError::InvalidConfig(format!(
                    "gateway {} and guest {} are not on the same /{} IPv6 subnet",
                    self.gateway_ipv6, self.guest_ipv6, self.prefix_len_v6
                )));
            }
        }
        for pf in &self.port_forwards {
            if pf.guest_port == 0 {
                return Err(UserNetError::InvalidConfig(
                    "guest_port must be non-zero".into(),
                ));
            }
        }
        if !self.port_forwards.is_empty() {
            return Err(UserNetError::InvalidConfig(
                "port_forwards is not wired to listener setup; use accept_inbound or accept_inbound_udp".into(),
            ));
        }
        Ok(())
    }
}

/// Port forwarding configuration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PortForward {
    /// Protocol (TCP or UDP)
    pub protocol: Protocol,

    /// Host port to listen on
    pub host_port: u16,

    /// Guest port to forward to
    pub guest_port: u16,

    /// Host address to bind to (None = all interfaces)
    pub host_addr: Option<IpAddr>,
}

impl PortForward {
    /// Create a TCP port forward
    pub const fn tcp(host_port: u16, guest_port: u16) -> Self {
        Self {
            protocol: Protocol::Tcp,
            host_port,
            guest_port,
            host_addr: None,
        }
    }

    /// Create a UDP port forward
    pub const fn udp(host_port: u16, guest_port: u16) -> Self {
        Self {
            protocol: Protocol::Udp,
            host_port,
            guest_port,
            host_addr: None,
        }
    }

    /// Bind to specific host address
    #[must_use]
    pub const fn bind_to(mut self, addr: IpAddr) -> Self {
        self.host_addr = Some(addr);
        self
    }
}

/// A specific reason usernet wants to contact a host socket.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum HostEgressPurpose {
    /// Guest TCP traffic is being proxied through outbound NAT.
    GuestTcpNat,
    /// Guest UDP traffic is being proxied through outbound NAT.
    GuestUdpNat,
    /// A guest DNS query is being forwarded to a host resolver.
    DnsForward,
}

/// A typed host socket egress request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HostEgressRequest {
    /// Transport protocol used for the host socket.
    pub protocol: Protocol,
    /// Full host socket destination, including port.
    pub socket_addr: SocketAddr,
    /// Why usernet is opening or using the host socket.
    pub purpose: HostEgressPurpose,
}

impl HostEgressRequest {
    /// Create a host egress request.
    #[must_use]
    pub const fn new(
        protocol: Protocol,
        socket_addr: SocketAddr,
        purpose: HostEgressPurpose,
    ) -> Self {
        Self {
            protocol,
            socket_addr,
            purpose,
        }
    }

    const fn protocol_matches_purpose(self) -> bool {
        matches!(
            (self.protocol, self.purpose),
            (Protocol::Tcp, HostEgressPurpose::GuestTcpNat)
                | (
                    Protocol::Udp,
                    HostEgressPurpose::GuestUdpNat | HostEgressPurpose::DnsForward,
                )
        )
    }
}

/// An allow-list entry for host egress.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostEgressRule {
    /// Transport protocol allowed by this rule.
    pub protocol: Protocol,
    /// Exact host socket destination allowed by this rule.
    pub socket_addr: SocketAddr,
    /// Exact egress purpose allowed by this rule.
    pub purpose: HostEgressPurpose,
}

impl HostEgressRule {
    /// Create an exact host egress allow-list rule.
    #[must_use]
    pub const fn new(
        protocol: Protocol,
        socket_addr: SocketAddr,
        purpose: HostEgressPurpose,
    ) -> Self {
        Self {
            protocol,
            socket_addr,
            purpose,
        }
    }

    /// Allow a guest TCP NAT connection to `socket_addr`.
    #[must_use]
    pub const fn tcp_nat(socket_addr: SocketAddr) -> Self {
        Self::new(Protocol::Tcp, socket_addr, HostEgressPurpose::GuestTcpNat)
    }

    /// Allow a guest UDP NAT association to `socket_addr`.
    #[must_use]
    pub const fn udp_nat(socket_addr: SocketAddr) -> Self {
        Self::new(Protocol::Udp, socket_addr, HostEgressPurpose::GuestUdpNat)
    }

    /// Allow DNS forwarding to `socket_addr`.
    #[must_use]
    pub const fn dns_forward(socket_addr: SocketAddr) -> Self {
        Self::new(Protocol::Udp, socket_addr, HostEgressPurpose::DnsForward)
    }

    fn matches(&self, request: HostEgressRequest) -> bool {
        self.protocol == request.protocol
            && self.socket_addr == request.socket_addr
            && self.purpose == request.purpose
    }
}

/// Proof that a host egress request passed policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AuthorizedHostEgress {
    request: HostEgressRequest,
}

impl AuthorizedHostEgress {
    /// Return the authorized request.
    #[must_use]
    pub const fn request(self) -> HostEgressRequest {
        self.request
    }

    /// Return the authorized host socket destination.
    #[must_use]
    pub const fn socket_addr(self) -> SocketAddr {
        self.request.socket_addr
    }
}

/// Mandatory typed authorizer for host socket egress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostEgressAuthorizer {
    egress_policy: EgressPolicy,
    dns_forward_policy: DnsForwardPolicy,
}

impl HostEgressAuthorizer {
    /// Create an authorizer from NAT and DNS forwarding policies.
    #[must_use]
    pub const fn new(egress_policy: EgressPolicy, dns_forward_policy: DnsForwardPolicy) -> Self {
        Self {
            egress_policy,
            dns_forward_policy,
        }
    }

    /// Authorize a typed host egress request.
    #[must_use]
    pub fn authorize(&self, request: HostEgressRequest) -> Option<AuthorizedHostEgress> {
        self.allows(request)
            .then_some(AuthorizedHostEgress { request })
    }

    /// Returns true when the configured policy allows the typed request.
    #[must_use]
    pub fn allows(&self, request: HostEgressRequest) -> bool {
        if !request.protocol_matches_purpose() {
            return false;
        }

        match request.purpose {
            HostEgressPurpose::GuestTcpNat | HostEgressPurpose::GuestUdpNat => {
                self.egress_policy.allows_request(request)
            }
            HostEgressPurpose::DnsForward => self
                .dns_forward_policy
                .allows_request(request, &self.egress_policy),
        }
    }
}

/// Policy for outbound NAT sockets opened by usernet.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum EgressPolicy {
    /// Do not open host sockets for outbound guest NAT.
    #[default]
    DenyAll,

    /// Allow outbound NAT only to globally routable Internet addresses.
    PublicInternetOnly,

    /// Allow outbound NAT to all addresses, including host-local/private.
    AllowAll,

    /// Allow only exact protocol/address/purpose rules.
    AllowList(Vec<HostEgressRule>),
}

impl EgressPolicy {
    fn allows_request(&self, request: HostEgressRequest) -> bool {
        match self {
            Self::DenyAll => false,
            Self::PublicInternetOnly => PublicInternetAddr::new(request.socket_addr.ip()).is_some(),
            Self::AllowAll => true,
            Self::AllowList(rules) => rules.iter().any(|rule| rule.matches(request)),
        }
    }
}

/// Policy for host UDP sockets opened by DNS forwarding.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum DnsForwardPolicy {
    /// Do not open host sockets for DNS forwarding.
    #[default]
    DenyAll,

    /// Apply [`UserNetConfig::egress_policy`] to DNS forwarding destinations.
    UseEgressPolicy,

    /// Allow DNS forwarding only to globally routable Internet resolvers.
    PublicInternetOnly,

    /// Allow DNS forwarding to all resolver addresses, including host-local/private.
    AllowAll,

    /// Allow only exact protocol/address/purpose rules.
    AllowList(Vec<HostEgressRule>),
}

impl DnsForwardPolicy {
    fn allows_request(&self, request: HostEgressRequest, egress_policy: &EgressPolicy) -> bool {
        match self {
            Self::DenyAll => false,
            Self::UseEgressPolicy => egress_policy.allows_request(request),
            Self::PublicInternetOnly => EgressPolicy::PublicInternetOnly.allows_request(request),
            Self::AllowAll => true,
            Self::AllowList(rules) => rules.iter().any(|rule| rule.matches(request)),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct PublicInternetAddr(IpAddr);

impl PublicInternetAddr {
    fn new(addr: IpAddr) -> Option<Self> {
        let addr = normalize_public_internet_candidate(addr);
        if match addr {
            IpAddr::V4(addr) => is_global_unicast_v4(addr),
            IpAddr::V6(addr) => is_global_unicast_v6(addr),
        } {
            Some(Self(addr))
        } else {
            None
        }
    }
}

fn normalize_public_internet_candidate(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(addr) => IpAddr::V4(addr),
        IpAddr::V6(addr) => embedded_ipv4(addr).map_or(IpAddr::V6(addr), IpAddr::V4),
    }
}

fn embedded_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    ipv4_mapped(addr).or_else(|| nat64_well_known_ipv4(addr))
}

fn ipv4_mapped(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    let octets = addr.octets();
    if octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

fn nat64_well_known_ipv4(addr: Ipv6Addr) -> Option<Ipv4Addr> {
    if in_ipv6_prefix(addr, Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96) {
        let octets = addr.octets();
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

const fn is_global_unicast_v4(addr: Ipv4Addr) -> bool {
    let [a, b, c, d] = addr.octets();
    if a == 0 || a >= 240 {
        return false;
    }
    if addr.is_private()
        || addr.is_loopback()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
    {
        return false;
    }

    // IANA special-purpose ranges that must not be treated as Internet egress.
    !matches!(
        (a, b, c, d),
        (100, 64..=127, _, _)
            | (192, 0, 0 | 2, _)
            | (192, 88, 99, _)
            | (198, 18 | 19, _, _)
            | (198, 51, 100, _)
            | (203, 0, 113, _)
    )
}

fn is_global_unicast_v6(addr: Ipv6Addr) -> bool {
    if addr.is_unspecified() || addr.is_loopback() || addr.is_multicast() {
        return false;
    }

    !(in_ipv6_prefix(addr, Ipv6Addr::UNSPECIFIED, 96)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0, 0), 96)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x0064, 0, 0, 0, 0, 0, 0, 0), 64)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64)
        || in_ipv6_prefix(
            addr,
            Ipv6Addr::new(0x0064, 0xff9b, 0x0001, 0, 0, 0, 0, 0),
            48,
        )
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x2001, 0x0002, 0, 0, 0, 0, 0, 0), 48)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x2001, 0x0010, 0, 0, 0, 0, 0, 0), 28)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0x5f00, 0, 0, 0, 0, 0, 0, 0), 16)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7)
        || in_ipv6_prefix(addr, Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10))
}

fn in_ipv6_prefix(addr: Ipv6Addr, prefix: Ipv6Addr, len: u8) -> bool {
    let mask = ipv6_mask(len);
    (u128::from(addr) & mask) == (u128::from(prefix) & mask)
}

/// Network protocol
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Protocol {
    Tcp,
    Udp,
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parse_dns_single_nameserver() {
        let conf = "nameserver 1.1.1.1\n";
        assert_eq!(
            parse_host_dns_from_str(conf).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1)
        );
    }

    #[test]
    fn parse_dns_takes_first_of_multiple() {
        let conf = "nameserver 1.1.1.1\nnameserver 8.8.4.4\n";
        assert_eq!(
            parse_host_dns_from_str(conf).unwrap(),
            Ipv4Addr::new(1, 1, 1, 1)
        );
    }

    #[test]
    fn parse_dns_skips_ipv6_and_comments() {
        let conf = "\
# DNS configuration
nameserver 2001:4860:4860::8888
nameserver 10.0.0.1
search example.com
nameserver 10.0.0.2
";
        assert_eq!(
            parse_host_dns_from_str(conf).unwrap(),
            Ipv4Addr::new(10, 0, 0, 1)
        );
    }

    #[test]
    fn parse_dns_empty_is_error() {
        assert!(matches!(
            parse_host_dns_from_str(""),
            Err(UserNetError::InvalidConfig(_))
        ));
    }

    #[test]
    fn parse_dns_only_ipv6_is_error() {
        let conf = "nameserver ::1\nnameserver 2001:db8::1\n";
        assert!(matches!(
            parse_host_dns_from_str(conf),
            Err(UserNetError::InvalidConfig(_))
        ));
    }

    #[test]
    fn egress_policy_defaults_to_deny_all() {
        let policy = UserNetConfig::default().egress_policy;
        assert!(!policy.allows_request(tcp_nat_request(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))));
    }

    #[test]
    fn public_internet_egress_blocks_special_purpose_networks() {
        let policy = EgressPolicy::PublicInternetOnly;
        for addr in [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0xffff, 0x7f00, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)),
            IpAddr::V6(nat64_well_known(Ipv4Addr::LOCALHOST)),
            IpAddr::V6(nat64_well_known(Ipv4Addr::new(10, 0, 0, 1))),
            IpAddr::V6(nat64_well_known(Ipv4Addr::new(192, 0, 2, 1))),
            IpAddr::V6(ipv4_mapped_for_test(Ipv4Addr::new(10, 0, 0, 1))),
        ] {
            assert!(
                !policy.allows_request(tcp_nat_request(addr)),
                "{addr} should be denied"
            );
        }
    }

    #[test]
    fn public_internet_egress_allows_global_unicast() {
        let policy = EgressPolicy::PublicInternetOnly;
        assert!(policy.allows_request(tcp_nat_request(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))));
        assert!(
            policy.allows_request(tcp_nat_request(IpAddr::V6(Ipv6Addr::new(
                0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
            ))))
        );
        assert!(
            policy.allows_request(tcp_nat_request(IpAddr::V6(nat64_well_known(
                Ipv4Addr::new(8, 8, 8, 8)
            ))))
        );
        assert!(
            policy.allows_request(tcp_nat_request(IpAddr::V6(ipv4_mapped_for_test(
                Ipv4Addr::new(8, 8, 8, 8)
            ))))
        );
    }

    fn tcp_nat_request(addr: IpAddr) -> HostEgressRequest {
        HostEgressRequest::new(
            Protocol::Tcp,
            SocketAddr::new(addr, 443),
            HostEgressPurpose::GuestTcpNat,
        )
    }

    fn nat64_well_known(addr: Ipv4Addr) -> Ipv6Addr {
        let [a, b, c, d] = addr.octets();
        Ipv6Addr::new(
            0x0064,
            0xff9b,
            0,
            0,
            0,
            0,
            u16::from_be_bytes([a, b]),
            u16::from_be_bytes([c, d]),
        )
    }

    fn ipv4_mapped_for_test(addr: Ipv4Addr) -> Ipv6Addr {
        let [a, b, c, d] = addr.octets();
        Ipv6Addr::new(
            0,
            0,
            0,
            0,
            0,
            0xffff,
            u16::from_be_bytes([a, b]),
            u16::from_be_bytes([c, d]),
        )
    }
}
