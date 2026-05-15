// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Well-known network addresses for the guest virtual network.
//!
//! These constants define the default 10.0.2.0/24 subnet used by the
//! user-mode networking stack. They are the single source of truth —
//! host crates (`amla-usernet`, `amla-guest-rootfs`) and guest crates
//! (`amla-guest-net`) should reference these rather than hardcoding IPs.

use core::net::{Ipv4Addr, Ipv6Addr};

/// Default gateway IP (also serves as DNS forwarder).
pub const DEFAULT_GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);

/// Default guest IP (assigned via DHCP).
pub const DEFAULT_GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);

/// Default subnet mask.
pub const DEFAULT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 0);

/// Default subnet prefix length.
pub const DEFAULT_PREFIX_LEN: u8 = 24;

/// Default DNS server — same as the gateway (DNS forwarder runs there).
pub const DEFAULT_DNS: Ipv4Addr = DEFAULT_GATEWAY;

/// Default gateway MAC address.
pub const DEFAULT_GATEWAY_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Default guest MAC address.
pub const DEFAULT_GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];

/// Default IPv6 gateway (ULA).
pub const DEFAULT_GATEWAY_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0002);

/// Default IPv6 guest address (ULA).
pub const DEFAULT_GUEST_IP_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 0x0015);

/// Default IPv6 prefix length.
pub const DEFAULT_PREFIX_LEN_V6: u8 = 64;

/// Default IPv6 DNS server (Google Public DNS).
pub const DEFAULT_DNS_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888);
