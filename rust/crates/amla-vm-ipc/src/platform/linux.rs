// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Linux IPC implementation.
//!
//! - Doorbell: STREAM socketpair carrying 4-byte sequence numbers
//! - Aux transport: SEQPACKET socketpair carrying SCM_RIGHTS fds + sizes
//! - Bootstrap: memfd ring buffer + aux socket sent via doorbell

use std::ffi::OsStr;
use std::io::{self, IoSlice, IoSliceMut};
use std::mem::MaybeUninit;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;
use std::ptr::NonNull;
use std::sync::Arc;

use amla_vm_ringbuf::{HostGuestRingBuffer, HostGuestRingBufferHandle};
use rustix::net::{
    AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
    SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketFlags, SocketType, recvmsg,
    sendmsg, socketpair,
};
use tokio::io::unix::AsyncFd;

use super::RawFdWrap;
use crate::AuxSlot;
use crate::channel::{AuxRecv, AuxSend, DoorbellRecv, DoorbellSend};

// ============================================================================
// Doorbell — STREAM socket, carries [seq: u32 LE] per kick
// ============================================================================

pub struct LinuxDoorbellSend {
    fd: Arc<OwnedFd>,
}

impl DoorbellSend for LinuxDoorbellSend {
    async fn kick(&self, seq: u32) -> io::Result<()> {
        let buf = seq.to_le_bytes();
        // The doorbell is a pure notification — if WOULDBLOCK, the socket
        // already has unread data so the receiver will wake regardless.
        // We must NOT await writable here: both sides share the same
        // UNIX socket pair buffer, so awaiting writable while the peer
        // also awaits writable is a deadlock.
        //
        // `NOSIGNAL` suppresses SIGPIPE if the peer has closed (e.g. a
        // worker process crashed mid-session) — without it the host VMM
        // inherits SIGPIPE's default action (terminate) unless another
        // component happens to have already installed `SIG_IGN`. Rely on
        // the syscall flag rather than that ambient assumption.
        loop {
            match rustix::net::send(self.fd.as_fd(), &buf, SendFlags::NOSIGNAL) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "doorbell: zero-byte kick",
                    ));
                }
                Ok(_) => return Ok(()),
                Err(rustix::io::Errno::WOULDBLOCK) => return Ok(()), // peer will drain
                Err(rustix::io::Errno::INTR) => continue,
                Err(e) => return Err(e.into()),
            }
        }
    }
}

pub struct LinuxDoorbellRecv {
    afd: AsyncFd<RawFdWrap>,
}

impl DoorbellRecv for LinuxDoorbellRecv {
    async fn wait_kick(&self) -> io::Result<()> {
        // SAFETY: the raw fd is owned by `self.afd` (an AsyncFd<RawFdWrap>) and is valid for the duration of this borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(self.afd.get_ref().0) };
        loop {
            let mut ready = self.afd.readable().await?;
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
        // SAFETY: the raw fd is owned by `self.afd` (an AsyncFd<RawFdWrap>) and is valid for the duration of this borrow.
        let fd = unsafe { BorrowedFd::borrow_raw(self.afd.get_ref().0) };
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
// Aux transport — SEQPACKET socket, carries SCM_RIGHTS fds + sizes
// ============================================================================

pub struct LinuxAuxSend {
    // Field order matters: `afd` must drop before `fd`. AsyncFd's drop
    // deregisters the fd from the tokio reactor's epoll set via the raw fd
    // number; if `fd` (the OwnedFd) closed first, the fd number could be
    // reused by the kernel, and we'd deregister the wrong fd.
    afd: AsyncFd<RawFdWrap>,
    fd: Arc<OwnedFd>,
}

impl AuxSend for LinuxAuxSend {
    async fn send_slots(&self, seq: u32, slots: Vec<AuxSlot>) -> io::Result<()> {
        let payload = crate::aux_frame::encode(seq, slots.iter().map(|slot| slot.meta))?;

        let mut fds: Vec<Arc<OwnedFd>> = Vec::with_capacity(slots.len());
        for slot in slots {
            fds.push(slot.fd);
        }

        let borrowed: Vec<BorrowedFd<'_>> = fds.iter().map(|fd| fd.as_fd()).collect();

        // Await write-readiness before sendmsg to avoid blocking the executor.
        loop {
            let mut ready = self.afd.writable().await?;
            match send_fds(self.fd.as_fd(), &payload, &borrowed) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

pub struct LinuxAuxRecv {
    afd: AsyncFd<RawFdWrap>,
}

impl AuxRecv for LinuxAuxRecv {
    async fn recv_slots(&mut self, seq: u32, count: usize) -> io::Result<Vec<AuxSlot>> {
        loop {
            let mut ready = self.afd.readable().await?;
            // SAFETY: the raw fd is owned by `self.afd` (an AsyncFd<RawFdWrap>) and is valid for the duration of this borrow.
            let fd = unsafe { BorrowedFd::borrow_raw(self.afd.get_ref().0) };
            match recv_fds(fd) {
                Ok((data, fds)) => return parse_slots(seq, count, &data, fds),
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    ready.clear_ready();
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }
}

fn parse_slots(
    expected_seq: u32,
    expected_count: usize,
    data: &[u8],
    fds: Vec<OwnedFd>,
) -> io::Result<Vec<AuxSlot>> {
    let metas = crate::aux_frame::decode(expected_seq, expected_count, data)?;
    if fds.len() != metas.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "aux: metadata/fd count mismatch",
        ));
    }

    let mut slots = Vec::with_capacity(metas.len());
    for (fd, meta) in fds.into_iter().zip(metas) {
        slots.push(AuxSlot {
            fd: Arc::new(fd),
            meta,
        });
    }
    Ok(slots)
}

// ============================================================================
// RingBuffer
// ============================================================================

pub struct RingBuffer {
    mmap_ptr: NonNull<u8>,
    mmap_len: usize,
    _memfd: OwnedFd,
    /// Shared with the send-side `LinuxDoorbellSend` via `Arc` so both
    /// sides can write the doorbell socket without `dup(2)`.
    doorbell_fd: Arc<OwnedFd>,
    /// Shared with the send-side `LinuxAuxSend` via `Arc` so the ancillary
    /// SEQPACKET socket has a single kernel fd-table entry.
    handle_fd: Arc<OwnedFd>,
    _child: Option<ChildHandle>,
}

// SAFETY: Ring buffer uses atomics for cross-process sync.
unsafe impl Send for RingBuffer {}

impl RingBuffer {
    /// Parent side: create ring buffer and bootstrap IPC with the subprocess.
    pub fn establish(subprocess: Subprocess) -> crate::Result<Self> {
        log::trace!("establishing connection to {subprocess:?}");
        let ring_size = std::mem::size_of::<HostGuestRingBuffer>();

        // Create memfd
        let memfd = rustix::fs::memfd_create(
            c"ipc-ring",
            rustix::fs::MemfdFlags::CLOEXEC | rustix::fs::MemfdFlags::ALLOW_SEALING,
        )
        .map_err(io::Error::from)?;
        rustix::fs::ftruncate(&memfd, ring_size as u64).map_err(io::Error::from)?;

        // mmap + init ring BEFORE sending to child (avoid race)
        // SAFETY: addr=NULL lets the kernel choose the mapping; `memfd` is a
        // valid fd owned for the duration of the call; ftruncate above sized
        // it to `ring_size`; MAP_SHARED RW is compatible with the memfd's
        // access mode.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                ring_size,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::SHARED,
                memfd.as_fd(),
                0,
            )
        }
        .map_err(io::Error::from)?;
        let mmap_ptr = NonNull::new(ptr.cast::<u8>()).expect("mmap returned null");
        // SAFETY: `mmap_ptr` points to a `HOST_GUEST_TOTAL_SIZE`-byte,
        // 64-aligned mmap region live for this handle's lifetime; SPSC
        // discipline enforced (one reader + one writer per direction).
        // `init()` is the only write before the memfd is shared with the
        // child via SCM_RIGHTS, so no concurrent access exists yet.
        let _ready = unsafe { HostGuestRingBufferHandle::attach(mmap_ptr, ring_size) }?.init();
        seal_ring_memfd(memfd.as_fd())?;
        validate_ring_memfd(memfd.as_fd(), ring_size)?;

        // Bootstrap: send [ring_size: u64] + SCM_RIGHTS [memfd, handle_child]
        let data = (ring_size as u64).to_le_bytes();
        send_fds(
            subprocess.doorbell.as_fd(),
            &data,
            &[memfd.as_fd(), subprocess.handle_child.as_fd()],
        )?;
        drop(subprocess.handle_child);

        Ok(Self {
            mmap_ptr,
            mmap_len: ring_size,
            _memfd: memfd,
            doorbell_fd: Arc::new(subprocess.doorbell),
            handle_fd: Arc::new(subprocess.handle_parent),
            _child: Some(subprocess.child),
        })
    }

    /// Child side: bootstrap from stdin (the doorbell socket).
    pub fn from_child_stdin() -> crate::Result<Self> {
        // SAFETY: fd 0 (stdin) was dup2'd from the doorbell socket by the
        // parent's `pre_exec` before exec; this is the unique owner in the
        // child process. Ownership transfers to OwnedFd.
        let doorbell_fd = unsafe { OwnedFd::from_raw_fd(0) };

        // Receive bootstrap: [ring_size: u64] + SCM_RIGHTS [memfd, handle_fd].
        let (data, fds) = recv_fds(doorbell_fd.as_fd())?;
        if data.len() != 8 || fds.len() != 2 {
            return Err(crate::Error::Protocol("invalid bootstrap message"));
        }
        let raw_ring_size = u64::from_le_bytes(
            data.try_into()
                .map_err(|_| crate::Error::Protocol("invalid bootstrap ring size"))?,
        );
        let ring_size = usize::try_from(raw_ring_size)
            .map_err(|_| crate::Error::Protocol("invalid bootstrap ring size"))?;
        let expected_ring_size = std::mem::size_of::<HostGuestRingBuffer>();
        if ring_size != expected_ring_size {
            return Err(crate::Error::Protocol("unexpected bootstrap ring size"));
        }
        // fds arrive in order: [memfd, handle_fd]
        let mut fds = fds.into_iter();
        let Some(memfd) = fds.next() else {
            return Err(crate::Error::Protocol("invalid bootstrap message"));
        };
        let Some(handle_fd) = fds.next() else {
            return Err(crate::Error::Protocol("invalid bootstrap message"));
        };

        validate_ring_memfd(memfd.as_fd(), expected_ring_size)?;

        // mmap (MAP_SHARED read-write)
        // SAFETY: addr=NULL lets the kernel choose the mapping; `memfd` is
        // the parent-sent memory fd, valid for the duration of the call and
        // sized to `ring_size` by the parent; MAP_SHARED RW matches the
        // parent's access mode.
        let ptr = unsafe {
            rustix::mm::mmap(
                std::ptr::null_mut(),
                ring_size,
                rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
                rustix::mm::MapFlags::SHARED,
                memfd.as_fd(),
                0,
            )
        }
        .map_err(io::Error::from)?;
        let mmap_ptr = NonNull::new(ptr.cast::<u8>()).expect("mmap returned null");

        // Validate ring header
        // SAFETY: Same argument as `establish()`. `mmap_ptr` is non-null,
        // points to `ring_size` bytes of page-aligned MAP_SHARED memory
        // backed by the memfd sent by the parent. The parent already
        // called `init()` before sending us the fd; `validate()` verifies
        // the magic/version before we start using the ring.
        let _ready =
            unsafe { HostGuestRingBufferHandle::attach(mmap_ptr, ring_size) }?.validate()?;

        Ok(Self {
            mmap_ptr,
            mmap_len: ring_size,
            _memfd: memfd,
            doorbell_fd: Arc::new(doorbell_fd),
            handle_fd: Arc::new(handle_fd),
            _child: None,
        })
    }

    /// Split into a Sender/Receiver pair.
    ///
    /// `is_host`: true for parent (host→guest writer), false for child.
    pub fn split(
        &mut self,
        is_host: bool,
    ) -> crate::Result<(super::Sender<'_>, super::Receiver<'_>)> {
        // SAFETY: `self.mmap_ptr` was created by `establish()` or
        // `from_child_stdin()`, both of which verified non-null and size,
        // and stored the mapping in `self` — the mapping lives until
        // `self` is dropped. `&mut self` ensures only one `split()` is
        // live at a time per side, producing a single writer and single
        // reader per ring direction (the SPSC discipline); the peer
        // process owns the opposite pair.
        let ready = unsafe { HostGuestRingBufferHandle::attach(self.mmap_ptr, self.mmap_len) }?
            .validate()?;
        let (writer, reader) = if is_host {
            let ep = ready.split_host();
            (ep.to_guest, ep.from_guest)
        } else {
            let ep = ready.split_guest();
            (ep.to_host, ep.from_host)
        };

        set_nonblock(self.doorbell_fd.as_fd())?;
        set_nonblock(self.handle_fd.as_fd())?;

        // Share the doorbell with the send side via Arc — kick() uses
        // non-blocking write() directly, so no AsyncFd registration is
        // needed on the send doorbell.
        let sender = crate::channel::Sender::new(
            writer,
            LinuxDoorbellSend {
                fd: Arc::clone(&self.doorbell_fd),
            },
            {
                // Reason: the aux socket is registered with `AsyncFd` on
                // both the send side (writable readiness) and the receive
                // side (readable readiness). epoll rejects registering the
                // same kernel fd twice, so the send side genuinely needs
                // an independent fd-table entry.
                let handle_send_fd = rustix::io::fcntl_dupfd_cloexec(self.handle_fd.as_fd(), 0)
                    .map_err(io::Error::from)?;
                let handle_send_raw = handle_send_fd.as_raw_fd();
                LinuxAuxSend {
                    fd: Arc::new(handle_send_fd),
                    afd: AsyncFd::new(RawFdWrap(handle_send_raw))?,
                }
            },
        );

        let receiver = crate::channel::Receiver::new(
            reader,
            LinuxDoorbellRecv {
                afd: AsyncFd::new(RawFdWrap(self.doorbell_fd.as_raw_fd()))?,
            },
            LinuxAuxRecv {
                afd: AsyncFd::new(RawFdWrap(self.handle_fd.as_raw_fd()))?,
            },
        );

        Ok((sender, receiver))
    }
}

impl Drop for RingBuffer {
    fn drop(&mut self) {
        // SAFETY: `self.mmap_ptr`/`self.mmap_len` describe the mapping
        // installed in `establish()` / `from_child_stdin()` and never
        // handed out elsewhere; Drop is the unique unmap site.
        unsafe {
            let _ = rustix::mm::munmap(self.mmap_ptr.as_ptr().cast(), self.mmap_len);
        }
    }
}

fn ring_memfd_seals() -> rustix::fs::SealFlags {
    rustix::fs::SealFlags::SEAL | rustix::fs::SealFlags::SHRINK | rustix::fs::SealFlags::GROW
}

fn seal_ring_memfd(fd: BorrowedFd<'_>) -> io::Result<()> {
    rustix::fs::fcntl_add_seals(fd, ring_memfd_seals()).map_err(io::Error::from)
}

fn validate_ring_memfd(fd: BorrowedFd<'_>, expected_size: usize) -> crate::Result<()> {
    let stat = rustix::fs::fstat(fd).map_err(io::Error::from)?;
    let expected_st_size =
        i64::try_from(expected_size).map_err(|_| crate::Error::Protocol("invalid ring size"))?;
    if stat.st_size != expected_st_size {
        return Err(crate::Error::Protocol("ring memfd size mismatch"));
    }

    let seals = rustix::fs::fcntl_get_seals(fd).map_err(io::Error::from)?;
    let required = ring_memfd_seals();
    if !seals.contains(required) {
        return Err(crate::Error::Protocol("ring memfd is not sealed"));
    }

    Ok(())
}

// ============================================================================
// Subprocess
// ============================================================================

struct ChildHandle {
    child: std::process::Child,
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub struct Subprocess {
    child: ChildHandle,
    doorbell: OwnedFd,
    handle_parent: OwnedFd,
    handle_child: OwnedFd,
}

impl std::fmt::Debug for Subprocess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Subprocess")
            .field("pid", &self.child.child.id())
            .finish()
    }
}

impl Subprocess {
    pub fn spawn(exe: &Path, args: &[&OsStr], env: &[(&OsStr, &OsStr)]) -> crate::Result<Self> {
        let (doorbell_parent, doorbell_child) = socketpair(
            AddressFamily::UNIX,
            SocketType::STREAM,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from)?;

        let (handle_parent, handle_child) = socketpair(
            AddressFamily::UNIX,
            SocketType::SEQPACKET,
            SocketFlags::CLOEXEC,
            None,
        )
        .map_err(io::Error::from)?;

        let child_raw = doorbell_child.as_raw_fd();

        let mut cmd = Command::new(exe);
        for arg in args {
            cmd.arg(arg);
        }
        for (k, v) in env {
            cmd.env(k, v);
        }

        // SAFETY: pre_exec runs after fork. Retarget fd 0 to the doorbell.
        unsafe {
            cmd.pre_exec(move || {
                if child_raw != 0 {
                    let src = BorrowedFd::borrow_raw(child_raw);
                    rustix::stdio::dup2_stdin(src).map_err(io::Error::from)?;
                    rustix::io::close(child_raw);
                }
                Ok(())
            });
        }

        crate::dbg_log!("Subprocess::spawn pre-spawn exe={}", exe.display());
        let child = cmd.spawn().map_err(|e| {
            crate::Error::Io(io::Error::new(
                e.kind(),
                format!("spawn {}: {e}", exe.display()),
            ))
        })?;
        crate::dbg_log!("Subprocess::spawn post-spawn pid={}", child.id());

        Ok(Self {
            child: ChildHandle { child },
            doorbell: doorbell_parent,
            handle_parent,
            handle_child,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.child.id()
    }
}

// ============================================================================
// Socket helpers
// ============================================================================

fn send_fds(fd: BorrowedFd<'_>, data: &[u8], fds: &[BorrowedFd<'_>]) -> io::Result<()> {
    let iov = [IoSlice::new(data)];
    // Allocate cmsg space for the fds (at least 1 to avoid zero-length)
    let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len().max(1)))];
    let mut cmsg = SendAncillaryBuffer::new(&mut space);
    if !fds.is_empty() {
        cmsg.push(SendAncillaryMessage::ScmRights(fds));
    }
    let sent = loop {
        match sendmsg(fd, &iov, &mut cmsg, SendFlags::NOSIGNAL) {
            Ok(sent) => break sent,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    if sent != data.len() {
        return Err(io::Error::new(
            io::ErrorKind::WriteZero,
            "send_fds: partial seqpacket send",
        ));
    }
    Ok(())
}

/// Hard upper bound on fds received per IPC message.
///
/// SCM_RIGHTS has a kernel-side ceiling of SCM_MAX_FD (253 on Linux).
/// 64 is well above the protocol's typical needs (an IPC message rarely
/// carries more than a handful of fds) while staying comfortably under
/// the kernel cap. If the peer ever sends more, the kernel sets
/// `MSG_CTRUNC` and we error rather than silently dropping fds.
const MAX_FDS_PER_MSG: usize = 64;

fn recv_fds(fd: BorrowedFd<'_>) -> io::Result<(Vec<u8>, Vec<OwnedFd>)> {
    let mut data_buf = vec![0u8; 4096];
    let mut iov = [IoSliceMut::new(&mut data_buf)];
    let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(MAX_FDS_PER_MSG))];
    let mut cmsg = RecvAncillaryBuffer::new(&mut space);

    let msg = loop {
        match recvmsg(fd, &mut iov, &mut cmsg, RecvFlags::CMSG_CLOEXEC) {
            Ok(msg) => break msg,
            Err(rustix::io::Errno::INTR) => continue,
            Err(e) => return Err(e.into()),
        }
    };
    if msg.bytes == 0 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "recv_fds: peer closed",
        ));
    }
    // MSG_CTRUNC means the kernel dropped one or more fds because our cmsg
    // buffer was too small. Silent truncation would leak fds on the sender
    // and desynchronize the receiver's AuxSlot parsing, so surface it.
    if msg.flags.contains(ReturnFlags::CTRUNC) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "recv_fds: ancillary data truncated (peer sent >MAX_FDS_PER_MSG fds)",
        ));
    }
    data_buf.truncate(msg.bytes);

    let mut fds = Vec::new();
    for m in cmsg.drain() {
        if let RecvAncillaryMessage::ScmRights(iter) = m {
            fds.extend(iter);
        }
    }
    Ok((data_buf, fds))
}

fn set_nonblock(fd: BorrowedFd<'_>) -> io::Result<()> {
    let flags = rustix::fs::fcntl_getfl(fd).map_err(io::Error::from)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK).map_err(io::Error::from)?;
    Ok(())
}
