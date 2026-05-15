// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use std::net::IpAddr;

use crate::UserNetConfig;
use crate::packet_builder::{
    ETH_HEADER_LEN, ETH_TYPE_IPV4, ETH_TYPE_IPV6, EthernetHeader, ParsedIpPacket, parse_ip_packet,
};

pub enum GuestIpPacketValidation<'a> {
    Valid(ValidatedGuestIpPacket<'a>),
    InvalidIdentity { src_mac: [u8; 6], src_ip: IpAddr },
    MalformedIp { ether_type: u16 },
    NotIp,
}

pub struct ValidatedGuestIpPacket<'a> {
    frame: &'a [u8],
    eth: EthernetHeader,
    ip: ParsedIpPacket<'a>,
}

impl<'a> ValidatedGuestIpPacket<'a> {
    pub(crate) fn validate(
        packet: &'a [u8],
        config: &UserNetConfig,
    ) -> GuestIpPacketValidation<'a> {
        let Some(eth) = EthernetHeader::parse(packet) else {
            return GuestIpPacketValidation::NotIp;
        };
        if !matches!(eth.ether_type, ETH_TYPE_IPV4 | ETH_TYPE_IPV6) {
            return GuestIpPacketValidation::NotIp;
        }
        let Some(ip) = parse_ip_packet(eth.ether_type, &packet[ETH_HEADER_LEN..]) else {
            return GuestIpPacketValidation::MalformedIp {
                ether_type: eth.ether_type,
            };
        };

        if eth.src_mac != config.guest_mac || !guest_ip_matches(ip.src_ip(), config) {
            return GuestIpPacketValidation::InvalidIdentity {
                src_mac: eth.src_mac,
                src_ip: ip.src_ip(),
            };
        }

        GuestIpPacketValidation::Valid(Self {
            frame: packet,
            eth,
            ip,
        })
    }

    pub(crate) const fn frame(&self) -> &'a [u8] {
        self.frame
    }

    pub(crate) const fn ethernet(&self) -> &EthernetHeader {
        &self.eth
    }

    pub(crate) const fn ip(&self) -> &ParsedIpPacket<'a> {
        &self.ip
    }
}

fn guest_ip_matches(src_ip: IpAddr, config: &UserNetConfig) -> bool {
    match src_ip {
        IpAddr::V4(src) => src == config.guest_ip,
        IpAddr::V6(src) => src == config.guest_ipv6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_ethertype_with_invalid_ip_header_is_malformed() {
        let config = UserNetConfig::default();
        let mut packet = vec![0u8; ETH_HEADER_LEN + 1];
        packet[6..12].copy_from_slice(&config.guest_mac);
        packet[12..14].copy_from_slice(&ETH_TYPE_IPV4.to_be_bytes());

        assert!(matches!(
            ValidatedGuestIpPacket::validate(&packet, &config),
            GuestIpPacketValidation::MalformedIp {
                ether_type: ETH_TYPE_IPV4
            }
        ));
    }

    #[test]
    fn non_ip_ethertype_is_not_ip() {
        let config = UserNetConfig::default();
        let mut packet = vec![0u8; ETH_HEADER_LEN];
        packet[12..14].copy_from_slice(&0x0806u16.to_be_bytes());

        assert!(matches!(
            ValidatedGuestIpPacket::validate(&packet, &config),
            GuestIpPacketValidation::NotIp
        ));
    }
}
