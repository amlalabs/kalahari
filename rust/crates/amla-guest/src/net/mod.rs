//! Pure-Rust guest VM networking via netlink.
//!
//! Replaces `ip` and `udhcpc` commands with direct netlink syscalls.
//! Static config only — no DHCP (usernet always provides 10.0.2.15/24).
//!
//! This crate only functions on Linux; on other platforms the public API
//! compiles but returns `io::ErrorKind::Unsupported`.

// Low-level netlink code requires many casts between integer types and raw
// pointers. These are intentional and correct for the repr(C) structs used.
#![allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_ptr_alignment,
    clippy::ptr_as_ptr,
    clippy::borrow_as_ptr,
    clippy::unnecessary_cast,
    clippy::struct_field_names,
    clippy::cast_possible_wrap,
    clippy::ref_as_ptr
)]

// On non-Linux platforms, provide stub functions that return Unsupported.
#[cfg(not(target_os = "linux"))]
mod platform {
    use std::io;
    fn unsupported() -> io::Error {
        io::Error::new(io::ErrorKind::Unsupported, "netlink requires Linux")
    }
    pub fn set_link_up(_iface: &str) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn add_ipv4_addr(_iface: &str, _addr: [u8; 4], _prefix_len: u8) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn add_default_route(_gateway: [u8; 4]) -> io::Result<()> {
        Err(unsupported())
    }
    pub fn setup_network() -> io::Result<bool> {
        Err(unsupported())
    }
}
#[cfg(not(target_os = "linux"))]
pub use platform::*;

// Everything below is Linux-only (netlink, ioctls, etc.).
#[cfg(target_os = "linux")]
mod linux_impl {

    use std::io;
    use std::mem;

    // ─── Netlink constants not in libc ──────────────────────────────────────

    const NETLINK_ROUTE: i32 = 0;

    // RTM message types
    const RTM_NEWLINK: u16 = 16;
    const RTM_NEWADDR: u16 = 20;
    const RTM_NEWROUTE: u16 = 24;
    pub const RTM_NEWNEIGH: u16 = 28;

    // Netlink flags
    const NLM_F_REQUEST: u16 = 1;
    const NLM_F_ACK: u16 = 4;
    const NLM_F_CREATE: u16 = 0x400;
    const NLM_F_REPLACE: u16 = 0x100;

    // Interface flags
    const IFF_UP: u32 = libc::IFF_UP as u32;

    // Attribute types
    #[cfg(test)]
    pub const IFLA_IFNAME: u16 = 3;
    pub const IFA_LOCAL: u16 = 2;
    const IFA_ADDRESS: u16 = 1;
    const RTA_GATEWAY: u16 = 5;
    const RTA_OIF: u16 = 4;
    pub const NDA_DST: u16 = 1;
    pub const NDA_LLADDR: u16 = 2;
    pub const NUD_PERMANENT: u16 = 0x80;

    // ─── Netlink message structures ─────────────────────────────────────────

    #[repr(C)]
    pub struct NlMsgHdr {
        nlmsg_len: u32,
        nlmsg_type: u16,
        nlmsg_flags: u16,
        nlmsg_seq: u32,
        nlmsg_pid: u32,
    }

    #[repr(C)]
    struct IfInfoMsg {
        ifi_family: u8,
        _pad: u8,
        ifi_type: u16,
        ifi_index: i32,
        ifi_flags: u32,
        ifi_change: u32,
    }

    #[repr(C)]
    struct IfAddrMsg {
        ifa_family: u8,
        ifa_prefixlen: u8,
        ifa_flags: u8,
        ifa_scope: u8,
        ifa_index: u32,
    }

    #[repr(C)]
    struct RtMsg {
        rtm_family: u8,
        rtm_dst_len: u8,
        rtm_src_len: u8,
        rtm_tos: u8,
        rtm_table: u8,
        rtm_protocol: u8,
        rtm_scope: u8,
        rtm_type: u8,
        rtm_flags: u32,
    }

    #[repr(C)]
    pub struct NdMsg {
        ndm_family: u8,
        ndm_pad1: u8,
        ndm_pad2: u16,
        ndm_ifindex: i32,
        ndm_state: u16,
        ndm_flags: u8,
        ndm_type: u8,
    }

    #[repr(C)]
    struct RtAttr {
        rta_len: u16,
        rta_type: u16,
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    pub const fn nlmsg_align(len: usize) -> usize {
        (len + 3) & !3
    }

    const fn rta_size(payload_len: usize) -> usize {
        nlmsg_align(mem::size_of::<RtAttr>() + payload_len)
    }

    pub fn push_attr(buf: &mut Vec<u8>, rta_type: u16, data: &[u8]) {
        let rta = RtAttr {
            rta_len: (mem::size_of::<RtAttr>() + data.len()) as u16,
            rta_type,
        };
        let rta_bytes =
        // SAFETY: RtAttr is repr(C) with no padding concerns at 4 bytes
        unsafe { std::slice::from_raw_parts(&rta as *const RtAttr as *const u8, mem::size_of::<RtAttr>()) };
        buf.extend_from_slice(rta_bytes);
        buf.extend_from_slice(data);
        // Pad to 4-byte alignment
        while !buf.len().is_multiple_of(4) {
            buf.push(0);
        }
    }

    fn if_nametoindex(name: &str) -> io::Result<u32> {
        let mut buf = [0u8; libc::IFNAMSIZ];
        if name.len() >= libc::IFNAMSIZ {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        buf[..name.len()].copy_from_slice(name.as_bytes());
        // SAFETY: buf is a valid C string (null-terminated since initialized to zeros)
        let idx = unsafe { libc::if_nametoindex(buf.as_ptr().cast()) };
        if idx == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(idx)
    }

    /// Open a netlink route socket.
    fn nl_socket() -> io::Result<i32> {
        // SAFETY: standard socket creation
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                NETLINK_ROUTE,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }

        // SAFETY: `sockaddr_nl` is an all-zero-valid POD.
        let mut addr: libc::sockaddr_nl = unsafe { mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;

        // SAFETY: addr is a valid sockaddr_nl
        let ret = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
            unsafe {
                libc::close(fd);
            }
            return Err(err);
        }
        Ok(fd)
    }

    /// Send a netlink message and wait for ACK.
    fn nl_send_and_ack(fd: i32, msg: &[u8]) -> io::Result<()> {
        // SAFETY: fd is a valid socket, msg is a valid buffer
        let sent = unsafe { libc::send(fd, msg.as_ptr().cast(), msg.len(), 0) };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }

        // Read ACK
        let mut ack_buf = [0u8; 1024];
        // SAFETY: fd is valid, ack_buf is a valid buffer
        let n = unsafe { libc::recv(fd, ack_buf.as_mut_ptr().cast(), ack_buf.len(), 0) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if (n as usize) < mem::size_of::<NlMsgHdr>() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "short netlink reply",
            ));
        }

        // Check for NLMSG_ERROR
        // SAFETY: we checked n >= sizeof(NlMsgHdr)
        let hdr = unsafe { &*(ack_buf.as_ptr() as *const NlMsgHdr) };
        if hdr.nlmsg_type == libc::NLMSG_ERROR as u16 {
            if (n as usize) < mem::size_of::<NlMsgHdr>() + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated NLMSG_ERROR",
                ));
            }
            let errno_bytes: [u8; 4] = ack_buf[mem::size_of::<NlMsgHdr>()..][..4]
                .try_into()
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "errno slice conversion")
                })?;
            let errno = i32::from_ne_bytes(errno_bytes);
            if errno < 0 {
                return Err(io::Error::from_raw_os_error(-errno));
            }
        }
        Ok(())
    }

    // ─── Public API ─────────────────────────────────────────────────────────

    /// Bring a network interface up.
    pub fn set_link_up(iface: &str) -> io::Result<()> {
        let idx = if_nametoindex(iface)?;
        let fd = nl_socket()?;

        let hdr_size = mem::size_of::<NlMsgHdr>();
        let ifi_size = mem::size_of::<IfInfoMsg>();
        let total = hdr_size + ifi_size;

        let mut buf = vec![0u8; total];

        // SAFETY: buf is large enough for both structs
        unsafe {
            let hdr = &mut *(buf.as_mut_ptr() as *mut NlMsgHdr);
            hdr.nlmsg_len = total as u32;
            hdr.nlmsg_type = RTM_NEWLINK;
            hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
            hdr.nlmsg_seq = 1;

            let ifi = &mut *(buf.as_mut_ptr().add(hdr_size) as *mut IfInfoMsg);
            ifi.ifi_family = libc::AF_UNSPEC as u8;
            ifi.ifi_index = idx as i32;
            ifi.ifi_flags = IFF_UP;
            ifi.ifi_change = IFF_UP;
        }

        let result = nl_send_and_ack(fd, &buf);
        // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
        unsafe {
            libc::close(fd);
        }
        result
    }

    /// Add an IPv4 address to an interface.
    pub fn add_ipv4_addr(iface: &str, addr: [u8; 4], prefix_len: u8) -> io::Result<()> {
        let idx = if_nametoindex(iface)?;
        let fd = nl_socket()?;

        let hdr_size = mem::size_of::<NlMsgHdr>();
        let ifa_size = mem::size_of::<IfAddrMsg>();
        let base = hdr_size + ifa_size;
        let total = base + rta_size(4) + rta_size(4);

        let mut buf = Vec::with_capacity(total);
        buf.resize(base, 0);

        // SAFETY: buf is large enough
        unsafe {
            let hdr = &mut *(buf.as_mut_ptr() as *mut NlMsgHdr);
            hdr.nlmsg_type = RTM_NEWADDR;
            hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            hdr.nlmsg_seq = 2;

            let ifa = &mut *(buf.as_mut_ptr().add(hdr_size) as *mut IfAddrMsg);
            ifa.ifa_family = libc::AF_INET as u8;
            ifa.ifa_prefixlen = prefix_len;
            ifa.ifa_index = idx;
        }

        push_attr(&mut buf, IFA_LOCAL, &addr);
        push_attr(&mut buf, IFA_ADDRESS, &addr);

        // Patch nlmsg_len
        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());

        let result = nl_send_and_ack(fd, &buf);
        // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
        unsafe {
            libc::close(fd);
        }
        result
    }

    /// Add a default route via the given gateway.
    pub fn add_default_route(gateway: [u8; 4]) -> io::Result<()> {
        let fd = nl_socket()?;

        let hdr_size = mem::size_of::<NlMsgHdr>();
        let rt_size = mem::size_of::<RtMsg>();
        let base = hdr_size + rt_size;

        let mut buf = Vec::with_capacity(base + rta_size(4) * 2);
        buf.resize(base, 0);

        // SAFETY: buf is large enough
        unsafe {
            let hdr = &mut *(buf.as_mut_ptr() as *mut NlMsgHdr);
            hdr.nlmsg_type = RTM_NEWROUTE;
            hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            hdr.nlmsg_seq = 3;

            let rt = &mut *(buf.as_mut_ptr().add(hdr_size) as *mut RtMsg);
            rt.rtm_family = libc::AF_INET as u8;
            rt.rtm_dst_len = 0; // default route
            rt.rtm_table = libc::RT_TABLE_MAIN as u8;
            rt.rtm_protocol = libc::RTPROT_BOOT as u8;
            rt.rtm_scope = libc::RT_SCOPE_UNIVERSE as u8;
            rt.rtm_type = libc::RTN_UNICAST as u8;
        }

        push_attr(&mut buf, RTA_GATEWAY, &gateway);

        // OIF: route via the first non-lo interface (eth0 = index 2 typically,
        // but we look it up). If eth0 doesn't exist, try index 2.
        let oif = if_nametoindex("eth0").unwrap_or(2);
        push_attr(&mut buf, RTA_OIF, &oif.to_ne_bytes());

        // Patch nlmsg_len
        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());

        let result = nl_send_and_ack(fd, &buf);
        // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
        unsafe {
            libc::close(fd);
        }
        result
    }

    pub fn build_static_ipv4_neighbor_msg(
        idx: u32,
        ip: [u8; 4],
        mac: [u8; 6],
        seq: u32,
    ) -> Vec<u8> {
        let hdr_size = mem::size_of::<NlMsgHdr>();
        let nd_size = mem::size_of::<NdMsg>();
        let base = hdr_size + nd_size;

        let mut buf = Vec::with_capacity(base + rta_size(4) + rta_size(6));
        buf.resize(base, 0);

        // SAFETY: buf is large enough for both headers.
        unsafe {
            let hdr = &mut *(buf.as_mut_ptr() as *mut NlMsgHdr);
            hdr.nlmsg_type = RTM_NEWNEIGH;
            hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
            hdr.nlmsg_seq = seq;

            let nd = &mut *(buf.as_mut_ptr().add(hdr_size) as *mut NdMsg);
            nd.ndm_family = libc::AF_INET as u8;
            nd.ndm_ifindex = idx as i32;
            nd.ndm_state = NUD_PERMANENT;
            nd.ndm_type = libc::RTN_UNICAST as u8;
        }

        push_attr(&mut buf, NDA_DST, &ip);
        push_attr(&mut buf, NDA_LLADDR, &mac);

        let len = buf.len() as u32;
        buf[..4].copy_from_slice(&len.to_ne_bytes());
        buf
    }

    fn add_static_ipv4_neighbor(iface: &str, ip: [u8; 4], mac: [u8; 6]) -> io::Result<()> {
        let idx = if_nametoindex(iface)?;
        let fd = nl_socket()?;

        let buf = build_static_ipv4_neighbor_msg(idx, ip, mac, 4);
        let result = nl_send_and_ack(fd, &buf);
        // SAFETY: `fd` is a valid OS fd owned by this scope; close takes a valid fd.
        unsafe {
            libc::close(fd);
        }
        result
    }

    /// Configure guest networking with static usernet defaults.
    ///
    /// Brings up `lo` and `eth0`, assigns the default guest IP with the
    /// default route via the gateway, installs the known usernet gateway
    /// neighbor, and writes `/etc/resolv.conf` pointing at the gateway (where
    /// the DNS forwarder runs).
    ///
    /// Returns `Ok(true)` if networking was configured, `Ok(false)` if eth0
    /// doesn't exist (no network device), or `Err` on failure.
    pub fn setup_network() -> io::Result<bool> {
        use amla_constants::net;

        // Loopback — must be up for 127.0.0.1
        if let Err(e) = set_link_up("lo") {
            eprintln!("network: lo up failed: {e}");
        }

        if !std::path::Path::new("/sys/class/net/eth0").exists() {
            return Ok(false);
        }

        let guest_ip = net::DEFAULT_GUEST_IP.octets();
        let gateway_ip = net::DEFAULT_GATEWAY.octets();
        let prefix_len = net::DEFAULT_PREFIX_LEN;

        set_link_up("eth0")?;
        add_ipv4_addr("eth0", guest_ip, prefix_len)?;
        add_default_route(gateway_ip)?;
        add_static_ipv4_neighbor("eth0", gateway_ip, net::DEFAULT_GATEWAY_MAC)?;
        if let Err(e) = std::fs::write(
            "/etc/resolv.conf",
            format!("nameserver {}\n", net::DEFAULT_DNS),
        ) {
            eprintln!("network: write /etc/resolv.conf: {e}");
        }
        if let Err(e) = std::fs::write(
            "/dev/kmsg",
            format!(
                "<6>network: static config applied ({}/{} gw {})\n",
                net::DEFAULT_GUEST_IP,
                prefix_len,
                net::DEFAULT_GATEWAY,
            ),
        ) {
            eprintln!("network: kmsg banner write: {e}");
        }
        Ok(true)
    }
} // mod linux_impl
#[cfg(target_os = "linux")]
pub use linux_impl::setup_network;

#[cfg(all(test, target_os = "linux"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::linux_impl::*;

    #[test]
    fn nlmsg_align_rounds_up() {
        assert_eq!(nlmsg_align(1), 4);
        assert_eq!(nlmsg_align(4), 4);
        assert_eq!(nlmsg_align(5), 8);
        assert_eq!(nlmsg_align(0), 0);
    }

    #[test]
    fn push_attr_pads_to_alignment() {
        let mut buf = Vec::new();
        push_attr(&mut buf, IFA_LOCAL, &[10, 0, 2, 15]);
        // RtAttr (4 bytes) + data (4 bytes) = 8 bytes, already aligned
        assert_eq!(buf.len(), 8);

        let mut buf = Vec::new();
        push_attr(&mut buf, IFLA_IFNAME, &[b'l', b'o', 0]);
        // RtAttr (4) + data (3) = 7, padded to 8
        assert_eq!(buf.len(), 8);
    }

    #[test]
    fn static_neighbor_message_uses_permanent_gateway_mapping() {
        let msg = build_static_ipv4_neighbor_msg(
            2,
            amla_constants::net::DEFAULT_GATEWAY.octets(),
            amla_constants::net::DEFAULT_GATEWAY_MAC,
            99,
        );
        let hdr_size = std::mem::size_of::<NlMsgHdr>();
        let nd_size = std::mem::size_of::<NdMsg>();

        let len = u32::from_ne_bytes(msg[0..4].try_into().unwrap());
        assert_eq!(usize::try_from(len).unwrap(), msg.len());
        let msg_type = u16::from_ne_bytes(msg[4..6].try_into().unwrap());
        assert_eq!(msg_type, RTM_NEWNEIGH);
        let seq = u32::from_ne_bytes(msg[8..12].try_into().unwrap());
        assert_eq!(seq, 99);

        let nd = &msg[hdr_size..hdr_size + nd_size];
        assert_eq!(nd[0], libc::AF_INET as u8);
        assert_eq!(i32::from_ne_bytes(nd[4..8].try_into().unwrap()), 2);
        assert_eq!(
            u16::from_ne_bytes(nd[8..10].try_into().unwrap()),
            NUD_PERMANENT
        );

        let attrs = &msg[hdr_size + nd_size..];
        let first_len = u16::from_ne_bytes(attrs[0..2].try_into().unwrap()) as usize;
        let first_type = u16::from_ne_bytes(attrs[2..4].try_into().unwrap());
        assert_eq!(first_type, NDA_DST);
        assert_eq!(
            &attrs[4..first_len],
            &amla_constants::net::DEFAULT_GATEWAY.octets()
        );

        let second = nlmsg_align(first_len);
        let second_len = u16::from_ne_bytes(attrs[second..second + 2].try_into().unwrap()) as usize;
        let second_type = u16::from_ne_bytes(attrs[second + 2..second + 4].try_into().unwrap());
        assert_eq!(second_type, NDA_LLADDR);
        assert_eq!(
            &attrs[second + 4..second + second_len],
            &amla_constants::net::DEFAULT_GATEWAY_MAC
        );
    }
}
