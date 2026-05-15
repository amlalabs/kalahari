// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! macOS IPC implementation.
//!
//! - **Ring buffer**: anonymous Mach VM (`mach_vm_allocate` + `mach_make_memory_entry_64`)
//! - **Doorbell**: AF_LOCAL socketpair carrying 4-byte sequence numbers
//! - **Aux transport**: Mach messages with port descriptors for memory entry transfer
//! - **Bootstrap**: `mach_ports_register` in `pre_exec` → child `mach_ports_lookup`
//!
//! No `SCM_RIGHTS` or `fileport` is used. Memory entries transfer as native
//! Mach port descriptors in complex messages.

use std::ffi::OsStr;
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;

use amla_vm_ringbuf::{HostGuestRingBuffer, HostGuestRingBufferHandle};
use rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair};
use tokio::io::unix::AsyncFd;

use super::RawFdWrap;
use crate::AuxSlot;
use crate::channel::{AuxRecv, AuxSend, DoorbellRecv, DoorbellSend};

// ============================================================================
// Mach FFI — stable kernel ABI
// ============================================================================

#[allow(non_camel_case_types, dead_code)]
mod ffi {
    pub type mach_port_t = u32;
    pub type mach_msg_return_t = i32;
    pub type kern_return_t = i32;
    pub type mach_msg_bits_t = u32;
    pub type mach_msg_size_t = u32;
    pub type mach_msg_id_t = i32;
    pub type mach_msg_type_name_t = u32;
    pub type mach_msg_option_t = i32;
    pub type mach_msg_timeout_t = u32;

    pub const MACH_PORT_NULL: mach_port_t = 0;
    pub const MACH_PORT_RIGHT_RECEIVE: i32 = 1;
    pub const MACH_MSG_TYPE_MOVE_SEND: mach_msg_type_name_t = 17;
    pub const MACH_MSG_TYPE_MAKE_SEND: mach_msg_type_name_t = 20;
    pub const MACH_MSG_TYPE_COPY_SEND: mach_msg_type_name_t = 19;
    pub const MACH_MSG_PORT_DESCRIPTOR: u32 = 0;
    pub const MACH_MSGH_BITS_COMPLEX: mach_msg_bits_t = 0x8000_0000;
    pub const MACH_SEND_MSG: mach_msg_option_t = 0x0000_0001;
    pub const MACH_RCV_MSG: mach_msg_option_t = 0x0000_0002;
    pub const MACH_RCV_LARGE: mach_msg_option_t = 0x0000_0004;
    pub const MACH_MSG_TIMEOUT_NONE: mach_msg_timeout_t = 0;
    pub const KERN_SUCCESS: kern_return_t = 0;
    pub const MACH_MSG_SUCCESS: mach_msg_return_t = 0;
    pub const MACH_RCV_TOO_LARGE: mach_msg_return_t = 0x1000_4004_u32 as i32;

    pub const fn mach_msgh_bits(
        remote: mach_msg_type_name_t,
        local: mach_msg_type_name_t,
    ) -> mach_msg_bits_t {
        (remote & 0x1f) | ((local & 0x1f) << 8)
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct mach_msg_header_t {
        pub msgh_bits: mach_msg_bits_t,
        pub msgh_size: mach_msg_size_t,
        pub msgh_remote_port: mach_port_t,
        pub msgh_local_port: mach_port_t,
        pub msgh_voucher_port: mach_port_t,
        pub msgh_id: mach_msg_id_t,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct mach_msg_body_t {
        pub msgh_descriptor_count: u32,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct mach_msg_port_descriptor_t {
        pub name: mach_port_t,
        pub pad1: mach_msg_size_t,
        /// Packed: bits 16-23 = disposition, bits 24-31 = type.
        pub type_disposition: u32,
    }

    pub const fn port_desc_bits(disposition: mach_msg_type_name_t, desc_type: u32) -> u32 {
        ((disposition & 0xFF) << 16) | ((desc_type & 0xFF) << 24)
    }

    unsafe extern "C" {
        pub fn mach_task_self() -> mach_port_t;
        pub fn mach_port_allocate(
            task: mach_port_t,
            right: i32,
            name: *mut mach_port_t,
        ) -> kern_return_t;
        pub fn mach_port_insert_right(
            task: mach_port_t,
            name: mach_port_t,
            poly: mach_port_t,
            poly_poly: mach_msg_type_name_t,
        ) -> kern_return_t;
        pub fn mach_port_deallocate(task: mach_port_t, name: mach_port_t) -> kern_return_t;
        pub fn mach_msg(
            msg: *mut mach_msg_header_t,
            option: mach_msg_option_t,
            send_size: mach_msg_size_t,
            rcv_size: mach_msg_size_t,
            rcv_name: mach_port_t,
            timeout: mach_msg_timeout_t,
            notify: mach_port_t,
        ) -> mach_msg_return_t;
    }
}

use ffi::mach_port_t;

fn check_kern(ret: ffi::kern_return_t) -> crate::Result<()> {
    if ret == ffi::KERN_SUCCESS {
        Ok(())
    } else {
        Err(crate::Error::Io(io::Error::other(format!(
            "mach kernel error: {ret}"
        ))))
    }
}

// ============================================================================
// Mach message send/recv
// ============================================================================

const MSG_ID: ffi::mach_msg_id_t = 0x414D_4C41; // "AMLA"

fn send_mach_msg(remote: mach_port_t, data: &[u8], ports: &[mach_port_t]) -> io::Result<()> {
    let n_desc = ports.len();
    let h_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
    let b_sz = if n_desc > 0 {
        std::mem::size_of::<ffi::mach_msg_body_t>()
    } else {
        0
    };
    let d_sz = n_desc * std::mem::size_of::<ffi::mach_msg_port_descriptor_t>();
    let total = h_sz + b_sz + d_sz + 4 + data.len();

    let mut buf = vec![0u8; total];
    let mut off = 0;

    let bits = if n_desc > 0 {
        ffi::mach_msgh_bits(ffi::MACH_MSG_TYPE_COPY_SEND, 0) | ffi::MACH_MSGH_BITS_COMPLEX
    } else {
        ffi::mach_msgh_bits(ffi::MACH_MSG_TYPE_COPY_SEND, 0)
    };
    let header = ffi::mach_msg_header_t {
        msgh_bits: bits,
        msgh_size: total as u32,
        msgh_remote_port: remote,
        msgh_local_port: ffi::MACH_PORT_NULL,
        msgh_voucher_port: ffi::MACH_PORT_NULL,
        msgh_id: MSG_ID,
    };
    write_struct(&mut buf, &mut off, &header);

    if n_desc > 0 {
        let body = ffi::mach_msg_body_t {
            msgh_descriptor_count: n_desc as u32,
        };
        write_struct(&mut buf, &mut off, &body);
        for &port in ports {
            let desc = ffi::mach_msg_port_descriptor_t {
                name: port,
                pad1: 0,
                type_disposition: ffi::port_desc_bits(
                    ffi::MACH_MSG_TYPE_COPY_SEND,
                    ffi::MACH_MSG_PORT_DESCRIPTOR,
                ),
            };
            write_struct(&mut buf, &mut off, &desc);
        }
    }

    buf[off..off + 4].copy_from_slice(&(data.len() as u32).to_le_bytes());
    off += 4;
    buf[off..off + data.len()].copy_from_slice(data);

    // SAFETY: `buf` is `total` bytes long, 4-byte aligned (Vec<u8> has at
    // least that alignment, and Mach requires natural-size alignment),
    // with the leading bytes laid out as a valid `mach_msg_header_t` +
    // body + descriptors + payload per the Mach ABI.
    let ret = unsafe {
        ffi::mach_msg(
            buf.as_mut_ptr().cast(),
            ffi::MACH_SEND_MSG,
            total as u32,
            0,
            ffi::MACH_PORT_NULL,
            ffi::MACH_MSG_TIMEOUT_NONE,
            ffi::MACH_PORT_NULL,
        )
    };
    if ret != ffi::MACH_MSG_SUCCESS {
        return Err(io::Error::other(format!("mach_msg send: {ret}")));
    }
    Ok(())
}

/// Upper bound on a single Mach message receive buffer. A peer sending
/// `msgh_size = u32::MAX` would otherwise drive `buf_size` to ~4 GiB on
/// the very first `MACH_RCV_TOO_LARGE` retry.
const MAX_MACH_MSG_SIZE: usize = 64 * 1024 * 1024;

fn recv_mach_msg(recv_port: mach_port_t) -> io::Result<(Vec<u8>, Vec<mach_port_t>)> {
    let mut buf_size: usize = 4096;
    loop {
        let mut buf = vec![0u8; buf_size];
        // SAFETY: `buf` is `buf_size` bytes long and Vec-aligned; the Mach
        // kernel writes a valid `mach_msg_header_t` + body + descriptors
        // + payload into the leading bytes per the Mach ABI.
        let ret = unsafe {
            ffi::mach_msg(
                buf.as_mut_ptr().cast(),
                ffi::MACH_RCV_MSG | ffi::MACH_RCV_LARGE,
                0,
                buf_size as u32,
                recv_port,
                ffi::MACH_MSG_TIMEOUT_NONE,
                ffi::MACH_PORT_NULL,
            )
        };

        if ret == ffi::MACH_RCV_TOO_LARGE {
            // Even on MACH_RCV_TOO_LARGE the kernel writes a valid
            // `mach_msg_header_t` into the leading bytes of `buf`.
            let header: ffi::mach_msg_header_t = read_unaligned_struct(&buf, 0);
            let requested = (header.msgh_size as usize).saturating_add(64);
            if requested > MAX_MACH_MSG_SIZE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("mach message size {requested} exceeds cap {MAX_MACH_MSG_SIZE}"),
                ));
            }
            buf_size = requested;
            continue;
        }
        if ret != ffi::MACH_MSG_SUCCESS {
            return Err(io::Error::other(format!("mach_msg recv: {ret}")));
        }

        return parse_mach_msg(&buf);
    }
}

fn parse_mach_msg(buf: &[u8]) -> io::Result<(Vec<u8>, Vec<mach_port_t>)> {
    let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
    if buf.len() < header_sz {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message too short for header",
        ));
    }

    let header: ffi::mach_msg_header_t = read_unaligned_struct(buf, 0);
    if header.msgh_id != MSG_ID {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message id mismatch",
        ));
    }

    let msg_size = header.msgh_size as usize;
    if msg_size < header_sz {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message size shorter than header",
        ));
    }
    if msg_size > buf.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message size exceeds receive buffer",
        ));
    }

    let msg = &buf[..msg_size];
    let mut off = header_sz;
    let mut ports = Vec::new();

    if header.msgh_bits & ffi::MACH_MSGH_BITS_COMPLEX != 0 {
        let body_sz = std::mem::size_of::<ffi::mach_msg_body_t>();
        if off + body_sz > msg.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mach message too short for body",
            ));
        }
        let body: ffi::mach_msg_body_t = read_unaligned_struct(msg, off);
        off += body_sz;
        if body.msgh_descriptor_count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "complex mach message has no descriptors",
            ));
        }

        let d_sz = std::mem::size_of::<ffi::mach_msg_port_descriptor_t>();
        for _ in 0..body.msgh_descriptor_count {
            if off + d_sz > msg.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mach message descriptor count exceeds buffer",
                ));
            }
            let desc: ffi::mach_msg_port_descriptor_t = read_unaligned_struct(msg, off);
            let disposition = (desc.type_disposition >> 16) & 0xFF;
            let desc_type = (desc.type_disposition >> 24) & 0xFF;
            if desc_type != ffi::MACH_MSG_PORT_DESCRIPTOR {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mach message descriptor is not a port descriptor",
                ));
            }
            if !matches!(
                disposition,
                ffi::MACH_MSG_TYPE_COPY_SEND | ffi::MACH_MSG_TYPE_MOVE_SEND
            ) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "mach message port descriptor has unexpected disposition {disposition}"
                    ),
                ));
            }
            if desc.name == ffi::MACH_PORT_NULL {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "mach message port descriptor is null",
                ));
            }
            ports.push(desc.name);
            off += d_sz;
        }
    }

    if off + 4 > msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message too short for data header",
        ));
    }
    let data_len =
        u32::from_le_bytes([msg[off], msg[off + 1], msg[off + 2], msg[off + 3]]) as usize;
    off += 4;
    if off + data_len > msg.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mach message too short for payload",
        ));
    }
    Ok((msg[off..off + data_len].to_vec(), ports))
}

fn read_unaligned_struct<T: Copy>(buf: &[u8], off: usize) -> T {
    let sz = std::mem::size_of::<T>();
    let end = off.checked_add(sz).expect("struct read offset overflow");
    assert!(end <= buf.len(), "struct read exceeds buffer");
    // SAFETY: the checked range above guarantees the full struct lies within
    // `buf`. The Mach message buffer is byte-addressed, so use an unaligned
    // read rather than forming a typed reference into it.
    unsafe { std::ptr::read_unaligned(buf.as_ptr().add(off).cast()) }
}

fn write_struct<T>(buf: &mut [u8], off: &mut usize, val: &T) {
    let sz = std::mem::size_of::<T>();
    // SAFETY: callers size `buf` large enough that `*off + sz <= buf.len()`;
    // `val` is a valid `&T` of `sz` bytes and cannot alias `buf` (distinct
    // borrows). Writing arbitrary bytes into a `&mut [u8]` is always sound.
    unsafe {
        std::ptr::copy_nonoverlapping(val as *const T as *const u8, buf.as_mut_ptr().add(*off), sz);
    }
    *off += sz;
}

// ============================================================================
// Mach port transport — bidirectional channel between parent and child
// ============================================================================

struct Transport {
    send_port: mach_port_t,
    recv_port: mach_port_t,
}

impl Transport {
    /// Create an asymmetric pair for subprocess spawning.
    ///
    /// Returns `(parent_transport, child_send_right)`. The child send right
    /// is stashed via `mach_ports_register` in `pre_exec`. The child calls
    /// `from_registered_ports()` to complete the bidirectional handshake.
    fn pair_for_spawn() -> crate::Result<(Self, mach_port_t)> {
        // SAFETY: mach_task_self has no preconditions.
        let task = unsafe { ffi::mach_task_self() };

        let mut parent_recv: mach_port_t = 0;
        // SAFETY: `task` is mach_task_self; `&mut parent_recv` is a valid
        // writable pointer. On success the kernel writes a new receive-right
        // name into `parent_recv`.
        check_kern(unsafe {
            ffi::mach_port_allocate(task, ffi::MACH_PORT_RIGHT_RECEIVE, &mut parent_recv)
        })?;
        // SAFETY: `task` is mach_task_self; `parent_recv` is the receive
        // right just allocated above; MAKE_SEND derives a send right from
        // a receive right owned by this task.
        check_kern(unsafe {
            ffi::mach_port_insert_right(
                task,
                parent_recv,
                parent_recv,
                ffi::MACH_MSG_TYPE_MAKE_SEND,
            )
        })?;

        // The send right for the child is the same name as the receive right
        // in the parent's namespace — after fork, the child inherits this
        // send right. The parent keeps the receive right.
        let child_send_right = parent_recv;

        Ok((
            Transport {
                send_port: ffi::MACH_PORT_NULL, // filled by complete_handshake
                recv_port: parent_recv,
            },
            child_send_right,
        ))
    }

    /// Child side: recover the Mach channel from registered ports.
    ///
    /// Retrieves the parent's send right from slot 0, creates a local
    /// receive port, and sends its send right back for bidirectional IPC.
    /// Build transport from a parent send right (already extracted from
    /// registered ports by the caller). Creates a local receive port and
    /// sends its send right back to complete the bidirectional handshake.
    fn from_parent_send_right(parent_send: u32) -> crate::Result<Self> {
        // SAFETY: mach_task_self has no preconditions.
        let task = unsafe { ffi::mach_task_self() };

        let mut child_recv: mach_port_t = 0;
        // SAFETY: `task` is mach_task_self; `&mut child_recv` is a valid
        // writable pointer. On success the kernel writes a new receive-right
        // name into `child_recv`.
        check_kern(unsafe {
            ffi::mach_port_allocate(task, ffi::MACH_PORT_RIGHT_RECEIVE, &mut child_recv)
        })?;
        // SAFETY: `task` is mach_task_self; `child_recv` is the receive
        // right just allocated above; MAKE_SEND derives a send right from
        // a receive right owned by this task.
        check_kern(unsafe {
            ffi::mach_port_insert_right(task, child_recv, child_recv, ffi::MACH_MSG_TYPE_MAKE_SEND)
        })?;

        // Send our send right to parent to complete the handshake.
        send_mach_msg(parent_send, &[], &[child_recv]).map_err(crate::Error::Io)?;

        Ok(Transport {
            send_port: parent_send,
            recv_port: child_recv,
        })
    }

    /// Parent side: receive the child's send right to complete the handshake.
    fn complete_handshake(&mut self) -> crate::Result<()> {
        let (_, ports) = recv_mach_msg(self.recv_port).map_err(crate::Error::Io)?;
        if ports.is_empty() {
            return Err(crate::Error::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "handshake: no port in first message from child",
            )));
        }
        self.send_port = ports[0];
        Ok(())
    }
}

impl Drop for Transport {
    fn drop(&mut self) {
        // SAFETY: mach_task_self has no preconditions.
        let task = unsafe { ffi::mach_task_self() };
        if self.send_port != ffi::MACH_PORT_NULL {
            // SAFETY: `task` is mach_task_self; `self.send_port` is a send
            // right owned by this process and Drop is the unique release site.
            unsafe { ffi::mach_port_deallocate(task, self.send_port) };
        }
        if self.recv_port != ffi::MACH_PORT_NULL {
            // SAFETY: `task` is mach_task_self; `self.recv_port` is a receive
            // right owned by this process and Drop is the unique release site.
            unsafe { ffi::mach_port_deallocate(task, self.recv_port) };
        }
    }
}

// ============================================================================
// mach_ports_register / mach_ports_lookup
// ============================================================================

fn lookup_registered_ports() -> crate::Result<Vec<u32>> {
    unsafe extern "C" {
        fn mach_ports_lookup(task: u32, ports: *mut *mut u32, count: *mut u32) -> i32;
        fn mach_task_self() -> u32;
        fn vm_deallocate(task: u32, addr: usize, size: usize) -> i32;
    }

    // SAFETY: mach_task_self has no preconditions. On success
    // mach_ports_lookup writes a vm_allocate'd `*mut u32` array of `count`
    // port names into `ports`; we copy it into an owned Vec and release
    // the kernel allocation with `vm_deallocate` exactly once.
    unsafe {
        let task = mach_task_self();
        let mut ports: *mut u32 = std::ptr::null_mut();
        let mut count: u32 = 0;

        let kr = mach_ports_lookup(task, &mut ports, &mut count);
        if kr != 0 {
            return Err(crate::Error::Io(io::Error::other(format!(
                "mach_ports_lookup failed: {kr}"
            ))));
        }

        let result: Vec<u32> = std::slice::from_raw_parts(ports, count as usize).to_vec();
        vm_deallocate(
            task,
            ports as usize,
            count as usize * std::mem::size_of::<u32>(),
        );

        Ok(result)
    }
}

// ============================================================================
// Doorbell — AF_LOCAL socket (identical to Linux)
// ============================================================================

pub struct MacosDoorbellSend {
    fd: Arc<OwnedFd>,
}

impl DoorbellSend for MacosDoorbellSend {
    async fn kick(&self, seq: u32) -> io::Result<()> {
        let buf = seq.to_le_bytes();
        // The doorbell is a pure notification — if WOULDBLOCK, the socket
        // already has unread data so the receiver will wake regardless.
        // We must NOT await writable here: both sides share the same
        // UNIX socket pair buffer, so awaiting writable while the peer
        // also awaits writable is a deadlock.
        match rustix::io::write(self.fd.as_fd(), &buf) {
            Ok(_) => Ok(()),
            Err(rustix::io::Errno::WOULDBLOCK) => Ok(()), // peer will drain
            Err(rustix::io::Errno::INTR) => Ok(()),       // harmless
            Err(e) => Err(e.into()),
        }
    }
}

pub struct MacosDoorbellRecv {
    afd: AsyncFd<RawFdWrap>,
}

impl DoorbellRecv for MacosDoorbellRecv {
    async fn wait_kick(&self) -> io::Result<()> {
        let raw = self.afd.get_ref().0;
        // SAFETY: `raw` is owned by `self.afd` (an AsyncFd<RawFdWrap>) and is valid for the duration of this borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        loop {
            // Use a bounded wait to recover from lost kqueue edge events.
            // macOS kqueue with EV_CLEAR is edge-triggered: if a new event
            // arrives while readiness is still cached in tokio, the kernel
            // clears the event but tokio's IO driver no-ops. After the stale
            // readiness is consumed (WOULDBLOCK + clear_ready), no new event
            // fires and readable() blocks forever. The 1ms timeout ensures
            // the recv loop's drain+try_peek re-checks the ring buffer.
            let ready_result =
                tokio::time::timeout(std::time::Duration::from_millis(1), self.afd.readable())
                    .await;
            let mut ready = match ready_result {
                Ok(Ok(ready)) => ready,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()), // timeout — let recv() re-check ring
            };
            let mut buf = [0u8; 256];
            match rustix::io::read(fd, &mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "doorbell: peer closed",
                    ));
                }
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::WOULDBLOCK) => {
                    ready.clear_ready();
                    continue;
                }
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn drain(&self) -> io::Result<()> {
        let raw = self.afd.get_ref().0;
        // SAFETY: `raw` is owned by `self.afd` (an AsyncFd<RawFdWrap>) and is valid for the duration of this borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(raw) };
        let mut buf = [0u8; 256];
        loop {
            match rustix::io::read(fd, &mut buf) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "doorbell: peer closed",
                    ));
                }
                Ok(_) => continue,
                Err(rustix::io::Errno::WOULDBLOCK) => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
}

// ============================================================================
// Aux transport — Mach messages with port descriptors
// ============================================================================

pub struct MacosAuxSend<'a> {
    send_port: mach_port_t,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl AuxSend for MacosAuxSend<'_> {
    // Mach ports don't support kqueue/poll for write-readiness, so this
    // remains a blocking mach_msg send. In practice it returns immediately
    // because the port queue has sufficient capacity for IPC messages.
    async fn send_slots(&self, seq: u32, slots: Vec<AuxSlot>) -> io::Result<()> {
        let payload = crate::aux_frame::encode(seq, slots.iter().map(|slot| slot.meta))?;

        let mut ports: Vec<mach_port_t> = Vec::with_capacity(slots.len());
        for slot in &slots {
            ports.push(slot.port);
        }

        send_mach_msg(self.send_port, &payload, &ports)?;

        // Ports were sent with COPY_SEND — our local copies are still valid.
        // AuxSlot::drop will deallocate them when `slots` is dropped.
        Ok(())
    }
}

pub struct MacosAuxRecv {
    recv_port: mach_port_t,
}

impl AuxRecv for MacosAuxRecv {
    async fn recv_slots(
        &mut self,
        expected_seq: u32,
        expected_count: usize,
    ) -> io::Result<Vec<AuxSlot>> {
        // By the time recv_slots is called, the sender has already sent
        // the mach_msg (send happens before doorbell kick). The blocking
        // mach_msg recv returns immediately.
        let (data, ports) = recv_mach_msg(self.recv_port)?;
        let metas = crate::aux_frame::decode(expected_seq, expected_count, &data)?;
        if ports.len() != metas.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "aux: metadata/port count mismatch (metas={}, ports={})",
                    metas.len(),
                    ports.len()
                ),
            ));
        }

        let mut slots = Vec::with_capacity(metas.len());
        for (port, meta) in ports.into_iter().zip(metas) {
            slots.push(AuxSlot { port, meta });
        }
        Ok(slots)
    }
}

// ============================================================================
// RingBuffer
// ============================================================================

pub struct RingBuffer {
    /// Owned mapping of the shared ring region. Declared first so its
    /// `Drop` (munmap) runs before `_ring_handle` drops the Mach port
    /// and before the child is reaped, matching the original order.
    mmap: amla_mem::MmapSlice,
    _ring_handle: amla_mem::MemHandle,
    /// Shared with the send-side `MacosDoorbellSend` via `Arc` so that the
    /// sender can write to the same kernel fd without a `dup(2)` call.
    doorbell_fd: Arc<OwnedFd>,
    transport: Transport,
    _child: Option<ChildHandle>,
}

impl RingBuffer {
    #[inline]
    fn mmap_ptr(&self) -> NonNull<u8> {
        // SAFETY: `RingBuffer` owns this writable shared-memory mapping for
        // the lifetime of the attached transport. The raw pointer is only
        // passed to the ring buffer abstraction, which enforces its own
        // atomic synchronization protocol for cross-process access.
        NonNull::new(unsafe { self.mmap.as_mut_ptr() }).expect("mmap is non-null by construction")
    }
}

// SAFETY: Ring buffer uses atomics for cross-process sync.
unsafe impl Send for RingBuffer {}

impl RingBuffer {
    /// Parent side: create ring buffer and bootstrap IPC with the subprocess.
    pub fn establish(subprocess: Subprocess) -> crate::Result<Self> {
        let ring_handle = subprocess.ring_handle;

        let mmap =
            amla_mem::map_handle(&ring_handle).map_err(|e| io::Error::other(e.to_string()))?;
        // SAFETY: This newly mapped shared-memory region is being attached to
        // the ring buffer abstraction before any endpoint is published. The
        // ring abstraction owns all mutable access through atomics afterward.
        let mmap_ptr = NonNull::new(unsafe { mmap.as_mut_ptr() }).expect("mmap returned null");

        // SAFETY: `mmap_ptr` is non-null and points to a Mach memory-entry-
        // backed mapping of at least `HostGuestRingBuffer::TOTAL_SIZE` bytes
        // (ring_handle was allocated for exactly that). mach_vm_map returns
        // page-aligned (16 KiB on ARM64 macOS) pointers, comfortably more
        // than the 64-byte alignment RingBuffer needs. SPSC: `init()` is
        // the only write before the Mach port is cloned and sent to the
        // child, so no concurrent access exists yet.
        let ready = unsafe {
            HostGuestRingBufferHandle::attach(mmap_ptr, HostGuestRingBuffer::TOTAL_SIZE)
        }?
        .init();

        // Complete the Mach port handshake — child sends its send right back.
        let mut transport = subprocess.transport;
        transport.complete_handshake()?;

        // Bootstrap: send the ring MemHandle to the child via normal IPC.
        // Write a frame into the ring the same way Sender::send does
        // (slot_count + postcard data), send the port via aux, kick doorbell.
        // The child synthesizes a temp ring with the same frame and does a
        // standard IPC receive to extract the MemHandle.
        {
            let slot_count = 1u32;
            let data = postcard::to_allocvec(&0u32).map_err(crate::Error::Codec)?;
            let endpoints = ready.split_host();
            endpoints
                .to_guest
                .try_write_parts(&[&slot_count.to_le_bytes(), data.as_slice()])
                .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?;
        }

        let slot = <amla_mem::MemHandle as crate::IpcResource>::into_slot(
            ring_handle
                .try_clone()
                .map_err(|e| io::Error::other(e.to_string()))?,
        )
        .map_err(crate::Error::Io)?;
        send_mach_msg(transport.send_port, &slot.meta.to_le_bytes(), &[slot.port])
            .map_err(crate::Error::Io)?;

        write_all(subprocess.doorbell.as_fd(), &1u32.to_le_bytes())?;

        Ok(Self {
            mmap,
            _ring_handle: ring_handle,
            doorbell_fd: Arc::new(subprocess.doorbell),
            transport,
            _child: Some(subprocess.child),
        })
    }

    /// Child side: bootstrap from stdin (doorbell) + registered ports.
    ///
    /// The child can't read the real ring buffer yet (it doesn't have the
    /// MemHandle). To solve this, it stack-allocates a small temporary ring
    /// buffer, pushes the same bootstrap frame the parent wrote (acting as
    /// the "host" writer), then reads it back through the standard reader
    /// path. The MemHandle port arrives via the real aux transport and is
    /// reconstructed through `IpcResource::from_slot`.
    pub fn from_child_stdin() -> crate::Result<Self> {
        // SAFETY: fd 0 (stdin) was dup2'd from the doorbell socket via
        // posix_spawn file actions before exec; this is the unique owner
        // in the child process. Ownership transfers to OwnedFd.
        let doorbell_fd = unsafe { OwnedFd::from_raw_fd(0) };
        log::trace!("Doorbell fd {doorbell_fd:?} acquired");

        // Recover Mach transport from registered port slot 0.
        let ports = lookup_registered_ports()?;
        if ports.is_empty() || ports[0] == ffi::MACH_PORT_NULL {
            log::error!("Could not find any registered ports");
            return Err(crate::Error::Protocol(
                "no transport port in registered port slot 0",
            ));
        }
        let transport = Transport::from_parent_send_right(ports[0])?;

        // Synthesize a temporary ring buffer and push the bootstrap frame
        // the same way the parent did — slot_count + postcard-serialized
        // slot index. This lets us read it back through the standard ring
        // reader, matching the Receiver::recv path.
        type TempRing = amla_vm_ringbuf::RingBuffer<256>;
        #[repr(C, align(64))]
        struct TempStorage([u8; std::mem::size_of::<TempRing>()]);
        let mut storage = TempStorage([0u8; std::mem::size_of::<TempRing>()]);
        let temp_ptr = NonNull::new(storage.0.as_mut_ptr()).unwrap();

        // Push the bootstrap frame as if we were the parent's Sender. We
        // use the HG direction both ways (same-process, sequential): first
        // a host-role handle writes, then a guest-role handle reads. Since
        // each RingBufferHandle enforces linear split, we use two disjoint
        // handle lifetimes — SPSC is trivially preserved within a single
        // function with no concurrency.
        let slot_count = 1u32;
        let data = postcard::to_allocvec(&0u32).map_err(crate::Error::Codec)?;
        {
            // SAFETY: `temp_ptr` points to `TempStorage` (exactly
            // `size_of::<TempRing>()` bytes, 64-aligned via `#[repr(C,
            // align(64))]`); no other thread touches it.
            let write_ep = unsafe {
                amla_vm_ringbuf::RingBufferHandle::<256>::attach(temp_ptr, TempRing::TOTAL_SIZE)
            }?
            .init()
            .split_host();
            write_ep
                .to_guest
                .try_write_parts(&[&slot_count.to_le_bytes(), data.as_slice()])
                .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?;
        }

        // Read the frame back through the standard reader path.
        // SAFETY: same `temp_ptr` contract as above; the previous handle was
        // dropped, so we're the sole reader.
        let mut reader = unsafe {
            amla_vm_ringbuf::RingBufferHandle::<256>::attach(temp_ptr, TempRing::TOTAL_SIZE)
        }
        .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?
        .validate()
        .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?
        .split_guest()
        .from_host;
        let frame = reader
            .try_peek()
            .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?
            .ok_or(crate::Error::Protocol("bootstrap: empty temp ring"))?;
        if frame.len() < 4 {
            return Err(crate::Error::Protocol("bootstrap: frame too short"));
        }
        let slot_count = u32::from_le_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| crate::Error::Protocol("bootstrap: ring header truncated"))?,
        ) as usize;
        reader
            .advance()
            .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?;

        if slot_count != 1 {
            return Err(crate::Error::Protocol("bootstrap: invalid slot count"));
        }

        // Receive the MemHandle port from the real aux transport.
        let (aux_data, mut msg_ports) =
            recv_mach_msg(transport.recv_port).map_err(crate::Error::Io)?;
        if msg_ports.len() != 1 {
            for port in msg_ports {
                amla_mem::platform::macos::deallocate_port(port);
            }
            return Err(crate::Error::Protocol("bootstrap: invalid port count"));
        }
        if aux_data.len() != 8 {
            for port in msg_ports {
                amla_mem::platform::macos::deallocate_port(port);
            }
            return Err(crate::Error::Protocol("bootstrap: invalid aux_data size"));
        }
        let meta = u64::from_le_bytes(
            aux_data
                .try_into()
                .map_err(|_| crate::Error::Protocol("bootstrap: invalid aux_data"))?,
        );

        // Reconstruct MemHandle via the standard IPC resource path.
        let slot = crate::AuxSlot {
            port: msg_ports
                .pop()
                .ok_or(crate::Error::Protocol("bootstrap: invalid port count"))?,
            meta,
        };
        let ring_handle = <amla_mem::MemHandle as crate::IpcResource>::from_slot(slot)
            .map_err(crate::Error::Io)?;
        let expected_ring_size =
            *amla_mem::PageAlignedLen::round_up(std::mem::size_of::<HostGuestRingBuffer>())
                .map_err(|_| crate::Error::Protocol("bootstrap: invalid ring size"))?;
        if *ring_handle.size() != expected_ring_size {
            return Err(crate::Error::Protocol("bootstrap: unexpected ring size"));
        }

        // Map the real ring buffer and validate.
        let mmap =
            amla_mem::map_handle(&ring_handle).map_err(|e| io::Error::other(e.to_string()))?;
        // SAFETY: This process maps the shared ring after receiving the Mach
        // memory entry. The pointer is immediately attached to the ring
        // abstraction, which validates the initialized header before use and
        // owns subsequent synchronized mutable access.
        let mmap_ptr = NonNull::new(unsafe { mmap.as_mut_ptr() }).expect("mmap returned null");

        // SAFETY: Same argument as `establish()`. `mmap_ptr` is non-null,
        // page-aligned, and points to a Mach-entry-backed mapping large
        // enough for `HostGuestRingBuffer`. The parent already called
        // `init()` before sending us the Mach port; `validate()` verifies
        // the magic/version before we start using the ring.
        let ready = unsafe {
            HostGuestRingBufferHandle::attach(mmap_ptr, HostGuestRingBuffer::TOTAL_SIZE)
        }?
        .validate()?;

        // Advance past the bootstrap frame in the real ring buffer. The
        // endpoints go out of scope at end of this block; a fresh pair is
        // taken from a new handle inside `split()` — cursors live in shared
        // memory, so consumption here is observed by the later reader.
        {
            let mut bootstrap = ready.split_guest();
            if bootstrap
                .from_host
                .try_peek()
                .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?
                .is_none()
            {
                return Err(crate::Error::Protocol("bootstrap: missing ring frame"));
            }
            bootstrap
                .from_host
                .advance()
                .map_err(|e| crate::Error::Io(io::Error::other(e.to_string())))?;
        }

        log::trace!("Set up ring buffer");

        Ok(Self {
            mmap,
            _ring_handle: ring_handle,
            doorbell_fd: Arc::new(doorbell_fd),
            transport,
            _child: None,
        })
    }

    pub fn split(
        &mut self,
        is_host: bool,
    ) -> crate::Result<(super::Sender<'_>, super::Receiver<'_>)> {
        // SAFETY: `self.mmap` was created by `establish()` or
        // `from_child_stdin()`, which verified non-null and size, and
        // the mapping is owned by `self`. `&mut self` ensures only one
        // `split()` is live at a time per side, producing a single writer
        // and single reader per ring direction; the peer process owns
        // the opposite pair.
        let ready = unsafe {
            HostGuestRingBufferHandle::attach(self.mmap_ptr(), HostGuestRingBuffer::TOTAL_SIZE)
        }?
        .validate()?;
        let (writer, reader) = if is_host {
            let ep = ready.split_host();
            (ep.to_guest, ep.from_guest)
        } else {
            let ep = ready.split_guest();
            (ep.to_host, ep.from_host)
        };

        set_nonblock(self.doorbell_fd.as_fd())?;

        let sender = crate::channel::Sender::new(
            writer,
            MacosDoorbellSend {
                fd: Arc::clone(&self.doorbell_fd),
            },
            MacosAuxSend {
                send_port: self.transport.send_port,
                _marker: std::marker::PhantomData,
            },
        );

        let receiver = crate::channel::Receiver::new(
            reader,
            MacosDoorbellRecv {
                afd: AsyncFd::new(RawFdWrap(self.doorbell_fd.as_raw_fd()))?,
            },
            MacosAuxRecv {
                recv_port: self.transport.recv_port,
            },
        );

        Ok((sender, receiver))
    }
}

// ============================================================================
// posix_spawnattr_t registered port injection
// ============================================================================

/// Port action type (`pspa_t` enum in XNU).
#[allow(dead_code)]
mod pspa {
    pub const SPECIAL: i32 = 0;
    pub const REGISTERED_PORTS: i32 = 4;
}

/// Single port action — `sizeof(_ps_port_action_t) == 24`.
#[repr(C)]
#[derive(Clone, Copy)]
struct PortAction {
    port_type: i32,
    mask: u32,
    new_port: u32,
    behavior: u32,
    flavor: u32,
    which: i32,
}

#[repr(C)]
struct PortActions {
    pspa_alloc: i32,
    pspa_count: i32,
}

fn port_actions_size(n: usize) -> usize {
    std::mem::size_of::<PortActions>() + std::mem::size_of::<PortAction>() * n
}

/// Discover the byte offset of `psa_ports` inside `_posix_spawnattr`.
///
/// # macOS SPI warning
///
/// This function depends on the **private internal layout** of
/// `_posix_spawnattr` (the heap-allocated struct behind
/// `posix_spawnattr_t`). Apple does not export a public API to attach
/// registered Mach ports to a child at `posix_spawn` time, so we probe
/// the layout at runtime:
///
/// 1. Allocate a fresh `posix_spawnattr_t`.
/// 2. Call `posix_spawnattr_setspecialport_np` (also private) to install
///    a known sentinel port action.
/// 3. Scan up to 64 pointer-sized words of the internal struct looking
///    for the heap block that matches the sentinel, using `malloc_size`
///    to avoid dereferencing anything that isn't a live allocation.
///
/// The internal layout has been stable across macOS 13–15 (aarch64) at
/// the time of writing but may change in any future macOS update. If
/// the scan fails, registered-port injection returns `ENOTSUP`, which
/// surfaces as a subprocess-spawn failure — we do not silently continue.
///
/// Before relying on this on a new major macOS release, re-verify by
/// running the bootstrap integration tests.
fn find_psa_ports_offset() -> Option<usize> {
    unsafe extern "C" {
        fn posix_spawnattr_setspecialport_np(
            attr: *mut libc::posix_spawnattr_t,
            new_port: u32,
            which: libc::c_int,
        ) -> libc::c_int;
        fn malloc_size(ptr: *const libc::c_void) -> usize;
    }

    const TASK_BOOTSTRAP_PORT: libc::c_int = 4;

    // SAFETY: Probes the private layout of a freshly-initialized
    // `posix_spawnattr_t`: `posix_spawnattr_init` produces a valid attr,
    // `setspecialport_np` allocates the internal port_actions buffer, and
    // we scan its raw word slots guarded by `malloc_size` to verify each
    // pointer is a live heap block of at least `port_actions_size(1)`
    // bytes before dereferencing. `posix_spawnattr_destroy` always runs.
    unsafe {
        let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
        if libc::posix_spawnattr_init(&mut attr) != 0 {
            return None;
        }
        if posix_spawnattr_setspecialport_np(&mut attr, 0, TASK_BOOTSTRAP_PORT) != 0 {
            libc::posix_spawnattr_destroy(&mut attr);
            return None;
        }

        let psattr: *const u8 = *((&attr) as *const _ as *const *const u8);
        let slots = psattr as *const usize;
        let mut found: Option<usize> = None;

        for i in 0..64 {
            let val = *slots.add(i);
            if val == 0 {
                continue;
            }
            let msz = malloc_size(val as *const libc::c_void);
            if msz < port_actions_size(1) {
                continue;
            }
            let pa = val as *const PortActions;
            if (*pa).pspa_alloc >= 1 && (*pa).pspa_alloc <= 16 && (*pa).pspa_count == 1 {
                let action =
                    (pa as *const u8).add(std::mem::size_of::<PortActions>()) as *const PortAction;
                if (*action).port_type == pspa::SPECIAL
                    && (*action).which == TASK_BOOTSTRAP_PORT
                    && (*action).new_port == 0
                {
                    found = Some(i * std::mem::size_of::<usize>());
                    break;
                }
            }
        }

        libc::posix_spawnattr_destroy(&mut attr);
        found
    }
}

fn psa_ports_offset() -> Option<usize> {
    use std::sync::OnceLock;
    static OFFSET: OnceLock<Option<usize>> = OnceLock::new();
    *OFFSET.get_or_init(find_psa_ports_offset)
}

/// Set registered ports on a `posix_spawnattr_t`.
///
/// The kernel transfers these ports to the child during `posix_spawn`.
/// The child retrieves them via `mach_ports_lookup()`.
///
/// # Safety
///
/// Manipulates internal `posix_spawnattr_t` layout discovered at runtime.
unsafe fn set_registered_ports(
    attr: *mut libc::posix_spawnattr_t,
    ports: &[u32],
) -> Result<(), i32> {
    if attr.is_null() || ports.len() > 3 {
        return Err(libc::EINVAL);
    }
    if ports.is_empty() {
        return Ok(());
    }

    let offset = psa_ports_offset().ok_or(libc::ENOTSUP)?;
    // SAFETY: caller guarantees attr is valid; layout probed at runtime.
    unsafe {
        let psattr: *mut u8 = *(attr as *const *mut u8);
        let pa_ptr = (psattr.add(offset)) as *mut *mut PortActions;
        let mut pa = *pa_ptr;

        if pa.is_null() {
            // Use libc::calloc — posix_spawnattr_destroy frees with C free().
            pa = libc::calloc(1, port_actions_size(ports.len())) as *mut PortActions;
            if pa.is_null() {
                return Err(libc::ENOMEM);
            }
            (*pa).pspa_alloc = ports.len() as i32;
            (*pa).pspa_count = 0;
            *pa_ptr = pa;
        } else {
            let needed = (*pa).pspa_count as usize + ports.len();
            if needed > (*pa).pspa_alloc as usize {
                let new_alloc = needed.max((*pa).pspa_alloc as usize * 2);
                pa = libc::realloc(pa.cast(), port_actions_size(new_alloc)) as *mut PortActions;
                if pa.is_null() {
                    return Err(libc::ENOMEM);
                }
                (*pa).pspa_alloc = new_alloc as i32;
                *pa_ptr = pa;
            }
        }

        let actions_base =
            (pa as *mut u8).add(std::mem::size_of::<PortActions>()) as *mut PortAction;
        for &port in ports {
            let idx = (*pa).pspa_count as usize;
            let action = &mut *actions_base.add(idx);
            *action = PortAction {
                port_type: pspa::REGISTERED_PORTS,
                mask: 0,
                new_port: port,
                behavior: 0,
                flavor: 0,
                which: 0,
            };
            (*pa).pspa_count += 1;
        }
    }

    Ok(())
}

// ============================================================================
// Subprocess — raw posix_spawn with Mach registered ports
// ============================================================================

struct ChildHandle {
    pid: libc::pid_t,
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        // SAFETY: `self.pid` was written by a successful `posix_spawn` in
        // `Subprocess::spawn` and is owned by this handle; Drop is the
        // unique reap site, so a kill+waitpid pair is race-free here.
        unsafe {
            libc::kill(self.pid, libc::SIGKILL);
            libc::waitpid(self.pid, std::ptr::null_mut(), 0);
        }
    }
}

pub struct Subprocess {
    child: ChildHandle,
    doorbell: OwnedFd,
    transport: Transport,
    ring_handle: amla_mem::MemHandle,
}

impl std::fmt::Debug for Subprocess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subprocess")
            .field("pid", &self.child.pid)
            .finish_non_exhaustive()
    }
}

impl Subprocess {
    pub fn spawn(exe: &Path, args: &[&OsStr], env: &[(&OsStr, &OsStr)]) -> crate::Result<Self> {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let ring_size = std::mem::size_of::<HostGuestRingBuffer>();

        // Allocate ring buffer via MemHandle (anonymous Mach VM).
        let ring_handle = amla_mem::MemHandle::allocate(c"ring", ring_size)
            .map_err(|e| io::Error::other(e.to_string()))?;

        // AF_LOCAL socketpair for doorbell.
        let (doorbell_parent, doorbell_child) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::empty(),
            None,
        )
        .map_err(io::Error::from)?;
        set_cloexec(doorbell_parent.as_fd())?;
        // Don't set CLOEXEC on doorbell_child — posix_spawn file actions handle it.

        // Mach port pair for aux transport.
        let (transport, child_send_right) = Transport::pair_for_spawn()?;

        // Build argv as CStrings.
        let prog_cstr = CString::new(exe.as_os_str().as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let mut argv_cstrs: Vec<CString> = vec![prog_cstr.clone()];
        for arg in args {
            argv_cstrs.push(
                CString::new(arg.as_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?,
            );
        }
        let argv_ptrs: Vec<*const libc::c_char> = argv_cstrs
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // Build envp: inherit current env + caller extras + ring info.
        let mut env_cstrs: Vec<CString> = std::env::vars_os()
            .map(|(k, v)| {
                let mut s = k.into_encoded_bytes();
                s.push(b'=');
                s.extend_from_slice(&v.into_encoded_bytes());
                CString::new(s).unwrap_or_default()
            })
            .collect();
        for (k, v) in env {
            let mut s = k.as_bytes().to_vec();
            s.push(b'=');
            s.extend_from_slice(v.as_bytes());
            if let Ok(c) = CString::new(s) {
                env_cstrs.push(c);
            }
        }
        // Ring size is compile-time known — no env var needed.
        let envp_ptrs: Vec<*const libc::c_char> = env_cstrs
            .iter()
            .map(|s| s.as_ptr())
            .chain(std::iter::once(std::ptr::null()))
            .collect();

        // SAFETY: `attr` and `file_actions` live for the duration of this
        // block, are always `*_destroy`'d before return, and are passed by
        // `&mut` to well-typed libc wrappers. `argv_ptrs`/`envp_ptrs` are
        // null-terminated arrays of C-string pointers rooted in
        // `argv_cstrs`/`env_cstrs` which outlive `posix_spawn`.
        // `set_registered_ports` requires a valid attr, satisfied above.
        let pid = unsafe {
            let mut attr: libc::posix_spawnattr_t = std::mem::zeroed();
            let ret = libc::posix_spawnattr_init(&mut attr);
            if ret != 0 {
                return Err(io::Error::from_raw_os_error(ret).into());
            }

            // Inject Mach send right via posix_spawnattr registered ports.
            let reg_ports = [child_send_right, 0, 0];
            if let Err(errno) = set_registered_ports(&mut attr, &reg_ports) {
                libc::posix_spawnattr_destroy(&mut attr);
                return Err(io::Error::from_raw_os_error(errno).into());
            }

            // File actions: dup doorbell to stdin, close parent's end in child.
            let mut file_actions: libc::posix_spawn_file_actions_t = std::mem::zeroed();
            libc::posix_spawn_file_actions_init(&mut file_actions);
            libc::posix_spawn_file_actions_adddup2(
                &mut file_actions,
                doorbell_child.as_raw_fd(),
                0,
            );
            libc::posix_spawn_file_actions_addclose(&mut file_actions, doorbell_parent.as_raw_fd());

            let mut pid: libc::pid_t = 0;
            let ret = libc::posix_spawn(
                &mut pid,
                prog_cstr.as_ptr(),
                &file_actions,
                &attr,
                argv_ptrs.as_ptr() as *const *mut libc::c_char,
                envp_ptrs.as_ptr() as *const *mut libc::c_char,
            );
            libc::posix_spawn_file_actions_destroy(&mut file_actions);
            libc::posix_spawnattr_destroy(&mut attr);

            if ret != 0 {
                return Err(crate::Error::Io(io::Error::other(format!(
                    "posix_spawn {}: {}",
                    exe.display(),
                    io::Error::from_raw_os_error(ret)
                ))));
            }
            pid
        };
        drop(doorbell_child);

        Ok(Self {
            child: ChildHandle { pid },
            doorbell: doorbell_parent,
            transport,
            ring_handle,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.pid as u32
    }
}

// ============================================================================
// Socket helpers
// ============================================================================

/// Blocking write used only during bootstrap (before socket is set non-blocking).
fn write_all(fd: BorrowedFd<'_>, mut buf: &[u8]) -> io::Result<()> {
    while !buf.is_empty() {
        match rustix::io::write(fd, buf) {
            Ok(n) => buf = &buf[n..],
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Ok(())
}

fn set_nonblock(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)?;
    Ok(())
}

fn set_cloexec(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = rustix::io::fcntl_getfd(fd).map_err(io::Error::from)?;
    rustix::io::fcntl_setfd(fd, flags | rustix::io::FdFlags::CLOEXEC).map_err(io::Error::from)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header(msg_size: usize) -> ffi::mach_msg_header_t {
        ffi::mach_msg_header_t {
            msgh_bits: ffi::mach_msgh_bits(ffi::MACH_MSG_TYPE_COPY_SEND, 0),
            msgh_size: msg_size as u32,
            msgh_remote_port: 0,
            msgh_local_port: 0,
            msgh_voucher_port: 0,
            msgh_id: MSG_ID,
        }
    }

    #[test]
    fn parse_mach_msg_accepts_payload_within_msgh_size() {
        let payload = b"hello";
        let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
        let msg_size = header_sz + 4 + payload.len();
        let mut buf = vec![0xAA; msg_size + 64];

        let mut off = 0;
        write_struct(&mut buf, &mut off, &test_header(msg_size));
        buf[off..off + 4].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        off += 4;
        buf[off..off + payload.len()].copy_from_slice(payload);

        let (data, ports) = parse_mach_msg(&buf).expect("parse mach message");
        assert_eq!(data, payload);
        assert!(ports.is_empty());
    }

    #[test]
    fn parse_mach_msg_rejects_payload_beyond_msgh_size() {
        let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
        let msg_size = header_sz + 4;
        let mut buf = vec![0xAA; msg_size + 8];

        let mut off = 0;
        write_struct(&mut buf, &mut off, &test_header(msg_size));
        buf[off..off + 4].copy_from_slice(&8u32.to_le_bytes());

        let err = parse_mach_msg(&buf).expect_err("truncated payload must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("payload"));
    }

    #[test]
    fn parse_mach_msg_rejects_wrong_message_id() {
        let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
        let msg_size = header_sz + 4;
        let mut header = test_header(msg_size);
        header.msgh_id = MSG_ID + 1;
        let mut buf = vec![0u8; msg_size];

        let mut off = 0;
        write_struct(&mut buf, &mut off, &header);
        buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

        let err = parse_mach_msg(&buf).expect_err("wrong id must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("id"));
    }

    #[test]
    fn parse_mach_msg_rejects_invalid_port_descriptor() {
        let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
        let body_sz = std::mem::size_of::<ffi::mach_msg_body_t>();
        let desc_sz = std::mem::size_of::<ffi::mach_msg_port_descriptor_t>();
        let msg_size = header_sz + body_sz + desc_sz + 4;
        let mut header = test_header(msg_size);
        header.msgh_bits |= ffi::MACH_MSGH_BITS_COMPLEX;
        let mut buf = vec![0u8; msg_size];

        let mut off = 0;
        write_struct(&mut buf, &mut off, &header);
        write_struct(
            &mut buf,
            &mut off,
            &ffi::mach_msg_body_t {
                msgh_descriptor_count: 1,
            },
        );
        write_struct(
            &mut buf,
            &mut off,
            &ffi::mach_msg_port_descriptor_t {
                name: 42,
                pad1: 0,
                type_disposition: ffi::port_desc_bits(
                    ffi::MACH_MSG_TYPE_COPY_SEND,
                    ffi::MACH_MSG_PORT_DESCRIPTOR + 1,
                ),
            },
        );
        buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

        let err = parse_mach_msg(&buf).expect_err("invalid descriptor must fail");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("descriptor"));
    }

    #[test]
    fn parse_mach_msg_accepts_moved_send_right_descriptor() {
        let header_sz = std::mem::size_of::<ffi::mach_msg_header_t>();
        let body_sz = std::mem::size_of::<ffi::mach_msg_body_t>();
        let desc_sz = std::mem::size_of::<ffi::mach_msg_port_descriptor_t>();
        let msg_size = header_sz + body_sz + desc_sz + 4;
        let mut header = test_header(msg_size);
        header.msgh_bits |= ffi::MACH_MSGH_BITS_COMPLEX;
        let mut buf = vec![0u8; msg_size];

        let mut off = 0;
        write_struct(&mut buf, &mut off, &header);
        write_struct(
            &mut buf,
            &mut off,
            &ffi::mach_msg_body_t {
                msgh_descriptor_count: 1,
            },
        );
        write_struct(
            &mut buf,
            &mut off,
            &ffi::mach_msg_port_descriptor_t {
                name: 42,
                pad1: 0,
                type_disposition: ffi::port_desc_bits(
                    ffi::MACH_MSG_TYPE_MOVE_SEND,
                    ffi::MACH_MSG_PORT_DESCRIPTOR,
                ),
            },
        );
        buf[off..off + 4].copy_from_slice(&0u32.to_le_bytes());

        let (data, ports) = parse_mach_msg(&buf).expect("parse mach message");
        assert!(data.is_empty());
        assert_eq!(ports, [42]);
    }
}
