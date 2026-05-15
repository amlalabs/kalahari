//! Shared library for amla guest binaries.
//!
//! Provides ring buffer transport, length-prefixed message I/O, and common
//! system helpers used by the guest agent.

use std::ffi::CString;
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::time::{Duration, Instant};

use amla_constants::protocol::{GuestMessage, HostMessage};

// =============================================================================
// Length-prefixed message I/O
// =============================================================================

/// Read a length-prefixed postcard message.
///
/// Wire format: `[u32 le len][postcard payload]`.
/// Returns an error if the message exceeds `max_size`.
pub fn read_msg<T: serde::de::DeserializeOwned>(
    reader: &mut impl Read,
    max_size: usize,
) -> io::Result<T> {
    let mut len_buf = [0u8; 4];
    reader.read_exact(&mut len_buf)?;
    let len = u32::from_le_bytes(len_buf);
    let len_usize =
        usize::try_from(len).map_err(|_| io::Error::other("message length overflow"))?;

    if len_usize > max_size {
        return Err(io::Error::other("message too large"));
    }

    let mut payload = vec![0u8; len_usize];
    reader.read_exact(&mut payload)?;

    postcard::from_bytes(&payload).map_err(|e| io::Error::other(format!("deserialize: {e}")))
}

/// Write a length-prefixed postcard message.
///
/// Wire format: `[u32 le len][postcard payload]`.
pub fn write_msg<T: serde::Serialize>(writer: &mut impl Write, msg: &T) -> io::Result<()> {
    let payload =
        postcard::to_allocvec(msg).map_err(|e| io::Error::other(format!("serialize: {e}")))?;
    let len = u32::try_from(payload.len()).map_err(|_| io::Error::other("message too large"))?;

    writer.write_all(&len.to_le_bytes())?;
    writer.write_all(&payload)?;
    writer.flush()
}

// =============================================================================
// System helpers
// =============================================================================

/// Mount a filesystem using `libc::mount`.
pub fn mount_fs(
    source: &str,
    target: &str,
    fstype: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source_c = CString::new(source).map_err(|e| io::Error::other(format!("source: {e}")))?;
    let target_c = CString::new(target).map_err(|e| io::Error::other(format!("target: {e}")))?;
    let fstype_c = CString::new(fstype).map_err(|e| io::Error::other(format!("fstype: {e}")))?;
    let data_c = data
        .map(|d| CString::new(d).map_err(|e| io::Error::other(format!("data: {e}"))))
        .transpose()?;

    let data_ptr = data_c
        .as_ref()
        .map_or(std::ptr::null(), |c| c.as_ptr().cast());

    // SAFETY: all four string pointers come from live CStrings (or the NULL
    // from a None `data`); mount returns 0 on success / -1 on error.
    let ret = unsafe {
        libc::mount(
            source_c.as_ptr(),
            target_c.as_ptr(),
            fstype_c.as_ptr(),
            flags,
            data_ptr,
        )
    };

    if ret != 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Loop forever (fallback when something irrecoverable happens).
pub fn halt() -> ! {
    loop {
        // SAFETY: pause has no preconditions.
        unsafe { libc::pause() };
    }
}

/// Trigger a clean VM shutdown.
///
/// On `x86_64`, writes the keyboard controller reset command (0xFE to port 0x64)
/// which the VMM intercepts as an immediate VM exit. This avoids the kernel's
/// `device_shutdown()` path which hangs on virtio driver teardown.
///
/// On ARM64, falls back to `reboot(POWER_OFF)` which triggers PSCI `SYSTEM_OFF`.
///
/// The exit `_code` is not communicated via this mechanism — use
/// `GuestMessage::RunExited` over the ring buffer instead.
pub fn vm_exit(_code: u8) -> ! {
    // SAFETY: sync has no preconditions; iopl(3) requires CAP_SYS_RAWIO (we
    // run as PID 1 with full privileges); the inline asm writes to the legacy
    // PS/2 controller port which the VMM intercepts; reboot() with
    // LINUX_REBOOT_CMD_POWER_OFF requires CAP_SYS_BOOT.
    unsafe {
        libc::sync();

        #[cfg(target_arch = "x86_64")]
        {
            // Enable I/O port access, then trigger keyboard controller reset.
            // The VMM intercepts outb(0xFE, 0x64) as a VM exit signal.
            libc::iopl(3);
            core::arch::asm!("out dx, al", in("dx") 0x64u16, in("al") 0xFEu8, options(nostack, nomem));
        }

        #[cfg(not(target_arch = "x86_64"))]
        {
            libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
        }
    }
    halt()
}

// =============================================================================
// Ring Buffer Transport (Linux-only)
// =============================================================================

/// Ring buffer transport for host↔guest IPC via shared memory + vport.
///
/// Discovery reads `amla_ring=<gpa>` from `/proc/cmdline` and mmaps the
/// shared memory from `/dev/mem`. The vport (`/dev/vport0p1`) carries
/// bidirectional kick signals: 1-byte writes notify the peer.
pub struct RingTransport {
    hg_reader: amla_vm_ringbuf::RingReader<'static>,
    gh_writer: amla_vm_ringbuf::RingWriter<'static>,
    vport: std::fs::File,
    shm_ptr: *mut u8,
    shm_size: usize,
}

// SAFETY: The raw pointers target mmap'd memory that is valid for the
// process lifetime. RingReader/RingWriter are Send by construction.
unsafe impl Send for RingTransport {}

impl RingTransport {
    /// Discover and initialize the ring buffer transport.
    ///
    /// Opens `/dev/vport0p1`, reads the framed ring GPA from the host,
    /// mmaps the shared memory region from `/dev/mem`, and validates the
    /// ring buffer headers.
    pub fn discover() -> io::Result<Self> {
        // Read ring GPA from kernel cmdline.
        let ring_gpa = parse_cmdline_ring_gpa()?;

        // Open the agent vport (port 1 of the virtio-console MULTIPORT device).
        // The port may not exist immediately at boot — retry until it appears.
        // ARM64 under QEMU TCG needs much longer (nested KVM is ~10x slower).
        let timeout = if cfg!(target_arch = "aarch64") {
            Duration::from_mins(2)
        } else {
            Duration::from_secs(10)
        };
        let vport = retry_open("/dev/vport0p1", timeout)?;

        // Open /dev/mem for physical memory access, mmap the shared region,
        // then let the File drop (auto-closes the fd).
        let mem_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/mem")?;

        let shm_size = amla_vm_ringbuf::HOST_GUEST_TOTAL_SIZE;
        // SAFETY: null addr lets the kernel pick; `mem_file` is a live OwnedFd
        // for /dev/mem; `shm_size` is the requested mapping length; flags and
        // offset are valid mmap arguments.
        let shm_ptr = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                shm_size,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                mem_file.as_raw_fd(),
                ring_gpa.cast_signed(),
            )
        };
        drop(mem_file);

        if shm_ptr == libc::MAP_FAILED {
            return Err(io::Error::other(format!(
                "mmap SHM at {ring_gpa:#x}: {}",
                io::Error::last_os_error()
            )));
        }

        // Validate the ring buffer
        let base = std::ptr::NonNull::new(shm_ptr.cast::<u8>())
            .ok_or_else(|| io::Error::other("mmap returned null"))?;
        // SAFETY: shm_ptr points to shm_size bytes of valid shared memory.
        let ready = unsafe { amla_vm_ringbuf::HostGuestRingBufferHandle::attach(base, shm_size) }
            .and_then(amla_vm_ringbuf::HostGuestRingBufferHandle::validate)
            .map_err(|e| io::Error::other(format!("ring validate: {e}")))?;
        let endpoints = ready.split_guest();

        Ok(Self {
            hg_reader: endpoints.from_host,
            gh_writer: endpoints.to_host,
            vport,
            shm_ptr: shm_ptr.cast(),
            shm_size,
        })
    }

    /// Send a guest→host message over the ring buffer.
    ///
    /// Convenience wrapper: tries to write, spins if full. The writer
    /// auto-wakes the host after each successful write.
    pub fn send(&self, msg: &GuestMessage) -> io::Result<()> {
        loop {
            if self.try_send(msg)? {
                return Ok(());
            }
            // Ring full — wait for host to drain (blocking).
            self.wait_kick()?;
        }
    }

    /// Try to write a guest→host message to the ring buffer.
    ///
    /// Returns `Ok(true)` if written, `Ok(false)` if the GH ring is full.
    /// The writer auto-wakes the host on success.
    pub fn try_send(&self, msg: &GuestMessage) -> io::Result<bool> {
        // Fast path: raw encoding for bulk data messages (no postcard overhead).
        match msg {
            GuestMessage::ExecStdout { id, data } => {
                return self.try_send_raw(
                    amla_constants::protocol::GuestRawTag::ExecStdout,
                    *id,
                    data,
                );
            }
            GuestMessage::ExecStderr { id, data } => {
                return self.try_send_raw(
                    amla_constants::protocol::GuestRawTag::ExecStderr,
                    *id,
                    data,
                );
            }
            _ => {}
        }
        let payload =
            postcard::to_allocvec(msg).map_err(|e| io::Error::other(format!("serialize: {e}")))?;
        match self.gh_writer.try_write(&payload) {
            Ok(written) => Ok(written),
            Err(e) => Err(io::Error::other(format!("ring write: {e}"))),
        }
    }

    /// Write a raw binary message to the GH ring (no postcard serialization).
    ///
    /// Wire format: `[tag][u32 LE id][data...]`. Uses scatter-gather write
    /// to avoid allocating an intermediate buffer.
    pub fn try_send_raw(
        &self,
        tag: amla_constants::protocol::GuestRawTag,
        id: amla_constants::protocol::ExecId,
        data: &[u8],
    ) -> io::Result<bool> {
        let header = amla_constants::protocol::guest_raw_header(tag, id);
        match self.gh_writer.try_write_parts(&[&header, data]) {
            Ok(written) => Ok(written),
            Err(e) => Err(io::Error::other(format!("ring write raw: {e}"))),
        }
    }

    /// Kick the host to signal new GH ring data.
    pub fn kick(&self) {
        if let Err(e) = (&self.vport).write_all(&[1u8]) {
            eprintln!("vport kick failed: {e}");
        }
    }

    /// Try to receive a host→guest message from the ring buffer.
    ///
    /// Returns `None` if the ring is empty. Transparently decodes both
    /// postcard messages and raw binary messages (tag >= 0x80).
    pub fn try_recv(&mut self) -> io::Result<Option<HostMessage>> {
        match self.hg_reader.try_peek() {
            Ok(Some(data)) => {
                let decoded = match amla_constants::protocol::try_decode_host_raw(data) {
                    Ok(Some(frame)) => Ok(match frame.tag {
                        amla_constants::protocol::HostRawTag::ExecStdin => HostMessage::ExecStdin {
                            id: frame.id,
                            data: frame.data.to_vec(),
                        },
                    }),
                    Ok(None) => postcard::from_bytes(data)
                        .map_err(|e| io::Error::other(format!("deserialize: {e}"))),
                    Err(e) => Err(io::Error::other(format!("decode raw: {e:?}"))),
                };
                self.hg_reader
                    .advance()
                    .map_err(|e| io::Error::other(format!("ring advance: {e}")))?;
                match decoded {
                    Ok(msg) => Ok(Some(msg)),
                    Err(e) => Err(e),
                }
            }
            Ok(None) => Ok(None),
            Err(e) => Err(io::Error::other(format!("ring peek: {e}"))),
        }
    }

    /// Drain all available host→guest messages.
    pub fn drain_recv(&mut self) -> io::Result<Vec<HostMessage>> {
        let mut msgs = Vec::new();
        while let Some(msg) = self.try_recv()? {
            msgs.push(msg);
        }
        Ok(msgs)
    }

    /// Wait for a host→guest kick on the vport.
    ///
    /// Blocks until the host writes data to the vport. The actual bytes
    /// are consumed and discarded — they are just doorbell signals.
    pub fn wait_kick(&self) -> io::Result<()> {
        let mut buf = [0u8; 64];
        let mut vport_ref = &self.vport;
        let _ = vport_ref.read(&mut buf)?;
        Ok(())
    }

    /// Returns `(used_bytes, capacity)` for the guest→host ring.
    pub fn gh_usage(&self) -> io::Result<(u32, u32)> {
        self.gh_writer
            .usage()
            .map(|usage| (usage.used_bytes(), usage.capacity()))
            .map_err(|e| io::Error::other(format!("GH ring usage: {e}")))
    }

    /// Returns `(used_bytes, capacity)` for the host→guest ring.
    pub fn hg_usage(&self) -> io::Result<(u32, u32)> {
        self.hg_reader
            .usage()
            .map(|usage| (usage.used_bytes(), usage.capacity()))
            .map_err(|e| io::Error::other(format!("HG ring usage: {e}")))
    }

    /// Get the raw vport fd for use with `AsyncFd`.
    pub fn vport_raw_fd(&self) -> i32 {
        self.vport.as_raw_fd()
    }
}

impl Drop for RingTransport {
    fn drop(&mut self) {
        // vport is a File — closed automatically by Drop.
        // shm_ptr was mmap'd from /dev/mem — must be munmap'd manually.
        // SAFETY: `self.shm_ptr`/`self.shm_size` are the mapping returned by
        // the mmap in `discover`; RingTransport uniquely owns it.
        unsafe {
            libc::munmap(self.shm_ptr.cast(), self.shm_size);
        }
    }
}

/// Open a device path with retries, sleeping 100ms between attempts.
fn retry_open(path: &str, timeout: Duration) -> io::Result<std::fs::File> {
    let started = Instant::now();
    loop {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_CLOEXEC)
            .open(path)
        {
            Ok(f) => return Ok(f),
            Err(_) if started.elapsed() < timeout => {
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(io::Error::other(format!(
                    "open {path} timed out after {timeout:?}: {e}"
                )));
            }
        }
    }
}

/// Parse `amla_ring=<hex>` from `/proc/cmdline`.
fn parse_cmdline_ring_gpa() -> io::Result<u64> {
    let cmdline = std::fs::read_to_string("/proc/cmdline")?;
    for param in cmdline.split_whitespace() {
        if let Some(val) = param.strip_prefix("amla_ring=") {
            let val = val.strip_prefix("0x").unwrap_or(val);
            return u64::from_str_radix(val, 16)
                .map_err(|e| io::Error::other(format!("bad amla_ring value: {e}")));
        }
    }
    Err(io::Error::other("amla_ring= not found in /proc/cmdline"))
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    // =========================================================================
    // Message I/O tests
    // =========================================================================

    #[test]
    fn test_write_read_msg_roundtrip() {
        let original = GuestMessage::Status {
            message: String::from("hello"),
        };
        let mut buf = Vec::new();
        write_msg(&mut buf, &original).unwrap();

        let decoded: GuestMessage = read_msg(
            &mut buf.as_slice(),
            amla_constants::protocol::MAX_MESSAGE_SIZE,
        )
        .unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_write_read_msg_all_variants() {
        let variants: Vec<HostMessage> = vec![
            HostMessage::Setup(amla_constants::protocol::AgentSetup { mounts: Vec::new() }),
            HostMessage::Ok,
            HostMessage::Pong,
            HostMessage::Shutdown,
            HostMessage::Error {
                message: String::from("oops"),
            },
        ];
        for original in &variants {
            let mut buf = Vec::new();
            write_msg(&mut buf, original).unwrap();
            let decoded: HostMessage = read_msg(
                &mut buf.as_slice(),
                amla_constants::protocol::MAX_MESSAGE_SIZE,
            )
            .unwrap();
            assert_eq!(original, &decoded);
        }
    }

    #[test]
    fn test_read_msg_oversized() {
        // Write a length header claiming 1MB, which exceeds MAX_MESSAGE_SIZE (64KB)
        let len: u32 = 1_000_000;
        let mut buf = Vec::new();
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 100]); // some payload (doesn't matter)

        let result: io::Result<GuestMessage> = read_msg(&mut buf.as_slice(), 64 * 1024);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_read_msg_truncated() {
        // Write a valid length header but not enough payload bytes
        let mut buf = Vec::new();
        let len: u32 = 100;
        buf.extend_from_slice(&len.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]); // only 10 bytes, header says 100

        let result: io::Result<GuestMessage> = read_msg(
            &mut buf.as_slice(),
            amla_constants::protocol::MAX_MESSAGE_SIZE,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_read_msg_empty_reader() {
        let buf: &[u8] = &[];
        let result: io::Result<GuestMessage> =
            read_msg(&mut &buf[..], amla_constants::protocol::MAX_MESSAGE_SIZE);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_read_msg_zero_length() {
        // A unit variant serializes to a single byte (discriminant).
        let original = HostMessage::Ok;
        let mut buf = Vec::new();
        write_msg(&mut buf, &original).unwrap();

        // Verify wire format: 4-byte length header + 1-byte payload
        assert_eq!(buf.len(), 5);
        assert_eq!(&buf[..4], &1u32.to_le_bytes());

        let decoded: HostMessage = read_msg(
            &mut buf.as_slice(),
            amla_constants::protocol::MAX_MESSAGE_SIZE,
        )
        .unwrap();
        assert_eq!(original, decoded);
    }
}
