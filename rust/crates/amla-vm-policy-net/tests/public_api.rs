// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#[test]
fn policy_net_backend_accepts_packet_policy_only() {
    use amla_core::backends::NullNetBackend;
    use amla_policy_net::{HostSpec, NetworkPolicy, PacketNetworkPolicy, PolicyNetBackend};
    use std::net::Ipv4Addr;

    let policy = NetworkPolicy::builder()
        .allow_host_port(Ipv4Addr::new(93, 184, 216, 34), 443)
        .allow_domain("api.example.com", &[443])
        .build();
    let packet_policy = PacketNetworkPolicy::from_network_policy(&policy);

    let backend = PolicyNetBackend::new(NullNetBackend::new(), packet_policy);

    let packet_policy: &PacketNetworkPolicy = backend.packet_policy();

    assert_eq!(packet_policy.rules.len(), 1);
    assert!(
        !packet_policy
            .rules
            .iter()
            .any(|rule| matches!(rule.host, HostSpec::Domain(_)))
    );
}
