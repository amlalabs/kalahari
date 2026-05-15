// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use crate::Protocol;
use std::net::SocketAddr;

/// Unique identifier for a proxied TCP or UDP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    /// Protocol (TCP or UDP).
    pub protocol: Protocol,
    /// Guest address.
    pub guest_addr: SocketAddr,
    /// Remote address.
    pub remote_addr: SocketAddr,
}

/// Monotonic NAT generation assigned when a connection key becomes current.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionGeneration(pub(crate) u64);

/// Provenance attached to async NAT output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionOutputTag {
    /// Connection key that produced the packet.
    pub key: ConnectionKey,
    /// Generation active when the producer was spawned.
    pub generation: ConnectionGeneration,
}

impl ConnectionOutputTag {
    #[cfg(test)]
    pub(crate) const fn for_test(protocol: Protocol) -> Self {
        use std::net::{IpAddr, Ipv4Addr};

        Self {
            key: ConnectionKey {
                protocol,
                guest_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)), 49152),
                remote_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 80),
            },
            generation: ConnectionGeneration(1),
        }
    }
}

/// Packet emitted by an async producer for delivery to the guest.
#[derive(Debug)]
#[allow(dead_code)]
pub enum GuestOutput {
    /// TCP frames whose loss would corrupt a reliable byte stream.
    ReliableTcp(Vec<u8>),
    /// TCP frame tagged with the NAT connection generation that produced it.
    TaggedReliableTcp {
        tag: ConnectionOutputTag,
        packet: Vec<u8>,
    },
    /// UDP/DNS datagrams that may be dropped under queue pressure.
    BestEffortDatagram(Vec<u8>),
    /// Best-effort datagram tagged with the producing NAT connection generation.
    TaggedBestEffortDatagram {
        tag: ConnectionOutputTag,
        packet: Vec<u8>,
    },
    /// Control frames such as connection-failure TCP resets.
    Control(Vec<u8>),
    /// Control frame tagged with the producing NAT connection generation.
    TaggedControl {
        tag: ConnectionOutputTag,
        packet: Vec<u8>,
    },
}

/// Delivery behavior for guest-bound async output under queue pressure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestOutputClass {
    /// Must be retained until the guest can accept it.
    Reliable,
    /// May be dropped under queue pressure.
    BestEffort,
    /// Control frame; may be dropped, but counted separately.
    Control,
}

impl GuestOutput {
    pub(crate) const fn tagged_reliable_tcp(tag: ConnectionOutputTag, packet: Vec<u8>) -> Self {
        Self::TaggedReliableTcp { tag, packet }
    }

    pub(crate) const fn tagged_best_effort_datagram(
        tag: ConnectionOutputTag,
        packet: Vec<u8>,
    ) -> Self {
        Self::TaggedBestEffortDatagram { tag, packet }
    }

    pub(crate) const fn tagged_control(tag: ConnectionOutputTag, packet: Vec<u8>) -> Self {
        Self::TaggedControl { tag, packet }
    }

    pub(crate) const fn connection_tag(&self) -> Option<ConnectionOutputTag> {
        match self {
            Self::TaggedReliableTcp { tag, .. }
            | Self::TaggedBestEffortDatagram { tag, .. }
            | Self::TaggedControl { tag, .. } => Some(*tag),
            Self::ReliableTcp(_) | Self::BestEffortDatagram(_) | Self::Control(_) => None,
        }
    }

    pub(crate) const fn packet_len(&self) -> usize {
        match self {
            Self::ReliableTcp(packet)
            | Self::BestEffortDatagram(packet)
            | Self::Control(packet)
            | Self::TaggedReliableTcp { packet, .. }
            | Self::TaggedBestEffortDatagram { packet, .. }
            | Self::TaggedControl { packet, .. } => packet.len(),
        }
    }

    pub(crate) fn is_reliable(&self) -> bool {
        self.class() == GuestOutputClass::Reliable
    }

    pub(crate) const fn class(&self) -> GuestOutputClass {
        match self {
            Self::ReliableTcp(_) | Self::TaggedReliableTcp { .. } => GuestOutputClass::Reliable,
            Self::BestEffortDatagram(_) | Self::TaggedBestEffortDatagram { .. } => {
                GuestOutputClass::BestEffort
            }
            Self::Control(_) | Self::TaggedControl { .. } => GuestOutputClass::Control,
        }
    }

    pub(crate) fn into_packet(self) -> Vec<u8> {
        match self {
            Self::ReliableTcp(packet)
            | Self::BestEffortDatagram(packet)
            | Self::Control(packet)
            | Self::TaggedReliableTcp { packet, .. }
            | Self::TaggedBestEffortDatagram { packet, .. }
            | Self::TaggedControl { packet, .. } => packet,
        }
    }
}
