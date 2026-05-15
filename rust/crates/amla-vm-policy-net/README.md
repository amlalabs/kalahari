# amla-vm-policy-net

Evidence-driven network policy types and packet admission.

Crate: `amla-vm-policy-net` (lib name `amla_policy_net`).

## What It Does

Owns network rules, stream evidence, policy decisions, DNS evidence, metrics, audit entries, and the packet admission backend. `EvidencePolicyEngine` is the stream lifecycle policy model used by usernet/interceptors. `PolicyNetBackend` remains as the L3/L4 packet admission and conntrack wrapper around another `NetBackend`.

## Key Types

- `NetworkPolicy` — evidence-aware allowlist. Fields: `rules: Vec<HostRule>`, plus `allow_icmp`/`allow_dhcp` flags. Built with `NetworkPolicy::builder()` or the inline `allow_host_port`, `allow_domain`, `allow_subnet`, etc. methods.
- `PacketNetworkPolicy` — raw packet admission policy. It can be explicitly projected from `NetworkPolicy`; domain rules are omitted because packets carry destination IPs, not DNS/SNI/HTTP evidence.
- `NetworkPolicyBuilder` — chainable builder (`allow_host_spec`, `allow_host_rule`, …).
- `HostRule`, `HostSpec` — host matching. `HostSpec::Ip`, `HostSpec::Domain`, `HostSpec::Subnet(IpSubnet)`.
- `Evidence`, `PolicyPhase`, `EvidencePolicyDecision`, `TcpFlow` — stream policy vocabulary.
- `EvidencePolicyEngine` — evidence-driven decision engine.
- `DnsEvidenceStore` — per-VM DNS name/IP/TTL evidence store.
- `PolicyNetBackend<I>` — generic `NetBackend` wrapper. Constructed with `new(inner, PacketNetworkPolicy)` or `with_shared_packet_policy(inner, Arc<PacketNetworkPolicy>)`. It exposes only `packet_policy()`; evidence-aware policy stays in the stream layer.
- `PolicyMetrics` — allow/deny counters for packet admission.
- `AuditEntry` — ring-buffered decision log; inspect via `PolicyNetBackend::audit_entries()`.
- `PolicyConfig`, `PolicyConfigBuilder`, `example_ai_agent_policy` — serde config layer.

## Fail-Closed Semantics

The policy layer is **default-deny on ambiguity**. Every case below drops the
packet rather than guessing:

- Unknown IP protocols, malformed IP/TCP/UDP headers, fragmented inbound packets.
  TCP data offsets must describe a complete header, and UDP lengths must be
  valid and match the available IP payload rather than being treated as hints.
- Raw IP destinations without an explicit IP/subnet allow rule.
- ECH, missing SNI, missing HTTP Host, buffer overflow, timeout, FIN/RST,
  or policy lookup failure in a stream parser.
- Configuration has no `default_action = allow` escape hatch. Unknown serde
  fields, including stale `http`/`dns`/`tls` sections, are rejected instead of
  being accepted as inert policy.

### Intentional exceptions

A few flows are allowed without per-rule matching. They are **not
fail-closed** — they bypass the policy layer entirely:

- **ARP** from the guest is always allowed. The usernet stack is
  single-tenant and the NAT layer does not relay ARP outside the virtual
  segment, so the practical impact is confined to the guest's view of
  its own link. Not rate-limited; a misbehaving guest can churn ARP
  traffic locally.
- **DHCP** to the NAT gateway (`10.0.2.2`) is allowed when `allow_dhcp`
  is set.

### Stream Authorization

`PolicyNetBackend` does not inspect DNS, TLS, HTTP, or body bytes. Domain and
MITM policy runs in the TCP stream lifecycle through `EvidencePolicyEngine`,
`TcpConnectionPolicy`, and trusted interceptors, where host connection can be
deferred until SNI/HTTP evidence authorizes it.

See `src/lib.rs` for the full list of deny cases.

## Where It Fits

Wraps any `amla_core::backends::NetBackend` (typically `amla-vm-usernet`'s `UserNetBackend`). Sits between the virtio-net device and the inner backend.

## Usage

```rust
use amla_policy_net::{NetworkPolicy, PacketNetworkPolicy};
use std::net::Ipv4Addr;

let policy = NetworkPolicy::builder()
    .allow_host_port(Ipv4Addr::new(93, 184, 216, 34), 443)
    .allow_domain("api.openai.com", &[443])
    .build();

let packet_policy = PacketNetworkPolicy::from_network_policy(&policy);
assert_eq!(policy.rules.len(), 2);
assert_eq!(packet_policy.rules.len(), 1);

// Wrap an inner NetBackend with PolicyNetBackend:
// let backend = PolicyNetBackend::new(inner_backend, packet_policy);
// assert_eq!(backend.packet_policy().rules.len(), 1);
```

## License

AGPL-3.0-or-later OR BUSL-1.1
