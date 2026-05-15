// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Guest agent protocol definitions.
//!
//! This crate defines the wire protocol between the guest agent (running inside
//! the VM as PID 1) and the host VMM over a shared ring buffer.
//!
//! # Protocol
//!
//! Messages are length-prefixed: `[u32 len][payload]` where len is little-endian.
//! Payload is postcard-serialized `GuestMessage` or `HostMessage`.
//!
//! # Compatibility
//!
//! This is a same-version host/guest contract. Postcard encodes Serde enum
//! variants by declaration order, so the host VMM and guest agent must be built
//! from the same source version. The golden-byte tests pin the current encoding
//! against accidental changes, but there is no promise that different Amla
//! versions can exchange these messages.
//!
//! # Handshake
//!
//! 1. Guest boots, discovers ring buffer transport via `/proc/cmdline`.
//! 2. Guest sends `Ready`, host responds with `Setup { mounts }`.
//! 3. Guest configures itself, then sends periodic `Ping` heartbeats.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::num::NonZeroU32;
use serde::{Deserialize, Serialize};

/// Maximum message size (64KB).
pub const MAX_MESSAGE_SIZE: usize = 64 * 1024;

// =============================================================================
// Raw binary message tags (0x80+ range, no postcard overhead)
// =============================================================================

/// Size of the raw message header (1 tag + 4 id).
pub const RAW_HEADER_SIZE: usize = 5;

/// Host-assigned nonzero exec session identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecId(NonZeroU32);

impl ExecId {
    /// First valid exec session ID.
    pub const FIRST: Self = Self(NonZeroU32::MIN);

    /// Create an exec ID from a raw wire value.
    #[must_use]
    pub const fn new(raw: u32) -> Option<Self> {
        match NonZeroU32::new(raw) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    /// Return the raw wire value.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

impl fmt::Display for ExecId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.get().fmt(f)
    }
}

const RAW_EXEC_STDIN: u8 = 0x80;
const RAW_EXEC_STDOUT: u8 = 0x81;
const RAW_EXEC_STDERR: u8 = 0x82;

/// Host-to-guest raw binary message tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRawTag {
    /// `ExecStdin` data.
    ///
    /// Wire format: `[0x80][u32 LE id][data...]`
    ExecStdin,
}

impl HostRawTag {
    const fn from_wire(tag: u8) -> Option<Self> {
        match tag {
            RAW_EXEC_STDIN => Some(Self::ExecStdin),
            _ => None,
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::ExecStdin => RAW_EXEC_STDIN,
        }
    }
}

/// Guest-to-host raw binary message tags.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestRawTag {
    /// `ExecStdout` data.
    ///
    /// Wire format: `[0x81][u32 LE id][data...]`
    ExecStdout,
    /// `ExecStderr` data.
    ///
    /// Wire format: `[0x82][u32 LE id][data...]`
    ExecStderr,
}

impl GuestRawTag {
    const fn from_wire(tag: u8) -> Option<Self> {
        match tag {
            RAW_EXEC_STDOUT => Some(Self::ExecStdout),
            RAW_EXEC_STDERR => Some(Self::ExecStderr),
            _ => None,
        }
    }

    const fn wire(self) -> u8 {
        match self {
            Self::ExecStdout => RAW_EXEC_STDOUT,
            Self::ExecStderr => RAW_EXEC_STDERR,
        }
    }
}

/// A decoded directional raw binary frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RawFrame<'a, T> {
    /// Direction-specific raw tag.
    pub tag: T,
    /// Exec session ID.
    pub id: ExecId,
    /// Raw payload bytes following the 5-byte header.
    pub data: &'a [u8],
}

/// Raw-frame decode failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawDecodeError {
    /// First byte is a raw tag prefix but the 5-byte raw header is incomplete.
    ShortHeader { len: usize },
    /// The raw tag is not valid for the expected transport direction.
    UnknownTag { tag: u8 },
    /// Raw exec frames must carry a nonzero host-assigned session ID.
    ZeroExecId,
}

/// Encode a host-to-guest raw message header on the stack.
pub const fn host_raw_header(tag: HostRawTag, id: ExecId) -> [u8; RAW_HEADER_SIZE] {
    raw_header(tag.wire(), id.get())
}

/// Encode a guest-to-host raw message header on the stack.
pub const fn guest_raw_header(tag: GuestRawTag, id: ExecId) -> [u8; RAW_HEADER_SIZE] {
    raw_header(tag.wire(), id.get())
}

const fn raw_header(tag: u8, id: u32) -> [u8; RAW_HEADER_SIZE] {
    let b = id.to_le_bytes();
    [tag, b[0], b[1], b[2], b[3]]
}

/// Try to decode a host-to-guest raw message from a ring buffer payload.
pub fn try_decode_host_raw(
    payload: &[u8],
) -> Result<Option<RawFrame<'_, HostRawTag>>, RawDecodeError> {
    try_decode_raw(payload, HostRawTag::from_wire)
}

/// Try to decode a guest-to-host raw message from a ring buffer payload.
pub fn try_decode_guest_raw(
    payload: &[u8],
) -> Result<Option<RawFrame<'_, GuestRawTag>>, RawDecodeError> {
    try_decode_raw(payload, GuestRawTag::from_wire)
}

fn try_decode_raw<T>(
    payload: &[u8],
    from_wire: impl FnOnce(u8) -> Option<T>,
) -> Result<Option<RawFrame<'_, T>>, RawDecodeError> {
    let Some(&tag) = payload.first() else {
        return Ok(None);
    };
    if tag < 0x80 {
        return Ok(None);
    }
    if payload.len() < RAW_HEADER_SIZE {
        return Err(RawDecodeError::ShortHeader { len: payload.len() });
    }
    let tag = from_wire(tag).ok_or(RawDecodeError::UnknownTag { tag })?;
    let raw_id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
    let id = ExecId::new(raw_id).ok_or(RawDecodeError::ZeroExecId)?;
    Ok(Some(RawFrame {
        tag,
        id,
        data: &payload[RAW_HEADER_SIZE..],
    }))
}

/// A recursive mount operation for the guest agent.
///
/// The DAG of mount operations is expressed as a tree: each node embeds
/// its children directly. The guest evaluates recursively (depth-first).
///
/// Inner nodes (`Pmem`, `DmLinear`, `Mount` without `mount_path`,
/// `VirtioFs` without `mount_path`) are intermediate — the guest agent
/// auto-assigns temp directories. Only outer nodes with an explicit
/// `mount_path` (or `Overlay.mount_path`) produce user-visible mounts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MountOp {
    /// Reference to `/dev/pmemN` (direct, no dm-linear).
    Pmem { device_index: u32 },
    /// Carve a region from `/dev/pmemN` via dm-linear.
    DmLinear {
        device_index: u32,
        offset: u64,
        size: u64,
    },
    /// Mount a block device source as a filesystem.
    ///
    /// When `mount_path` is `None`, the agent picks a temp directory
    /// and returns it for the parent op to consume.
    Mount {
        source: Box<Self>,
        mount_path: Option<String>,
        fs_type: String,
        options: String,
    },
    /// Compose layers via overlayfs.
    ///
    /// If `upper` is `Some`, execute it and use the result as upperdir
    /// (with a `work` subdir alongside). If `None`, use tmpfs.
    ///
    /// If `lower` is empty, the agent uses whatever already exists at
    /// `mount_path` as the sole lower layer (overlay-in-place).
    Overlay {
        lower: Vec<Self>,
        upper: Option<Box<Self>>,
        mount_path: String,
    },
    /// Mount a virtiofs tag.
    ///
    /// When `mount_path` is `None`, the agent picks a temp directory
    /// and returns it for the parent op to consume.
    VirtioFs {
        tag: String,
        mount_path: Option<String>,
    },
}

/// Host-to-guest setup payload, sent in response to `Ready`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSetup {
    pub mounts: Vec<MountOp>,
}

/// Messages sent from guest agent to host over the persistent control channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GuestMessage {
    /// Agent has completed initialization and is ready.
    Ready,

    /// Heartbeat ping.
    Ping,

    /// Report agent status.
    Status { message: String },

    /// Opaque application payload (e.g. benchmark results).
    ///
    /// The agent backend logs but does not interpret the contents.
    /// Callers define their own postcard types inside `payload`.
    Custom { payload: Vec<u8> },

    /// Stdout chunk from an exec session.
    ExecStdout { id: ExecId, data: Vec<u8> },

    /// Stderr chunk from an exec session.
    ExecStderr { id: ExecId, data: Vec<u8> },

    /// Exec process exited.
    ExecExit { id: ExecId, code: i32 },

    /// Result of a CPU online/offline operation.
    CpuOnlineResult { count: u32, error: Option<String> },

    /// Memory pressure notification from PSI monitor.
    ///
    /// Sent when the guest detects memory stalls via `/proc/pressure/memory`.
    /// The host can respond by hot-adding memory via virtio-mem.
    MemoryPressure {
        /// PSI level: 0 = some (partial stall), 1 = full (all tasks stalled).
        level: u8,
        /// Available memory in KB (from `/proc/meminfo` `MemAvailable`).
        available_kb: u64,
        /// Total memory in KB.
        total_kb: u64,
    },
}

/// Messages sent from host to guest agent over the persistent control channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HostMessage {
    /// Setup payload — the one message the host sends to configure the guest.
    Setup(AgentSetup),

    /// Generic acknowledgment.
    Ok,

    /// Heartbeat response.
    Pong,

    /// Request agent to shut down.
    Shutdown,

    /// Error response.
    Error { message: String },

    /// Start an exec session. Guest spawns `argv[0]` with the given args.
    /// `env` entries are `KEY=VALUE` strings. Empty vec = inherit parent env.
    /// `cwd` sets the child's working directory. Empty string = inherit.
    Exec {
        /// Host-assigned session ID.
        id: ExecId,
        /// Argument vector.
        argv: Vec<String>,
        /// Environment entries encoded as `KEY=VALUE`.
        env: Vec<String>,
        /// Guest working directory, or empty to inherit.
        cwd: String,
    },

    /// Write to an exec session's stdin.
    ExecStdin { id: ExecId, data: Vec<u8> },

    /// Close an exec session's stdin.
    ExecStdinEof { id: ExecId },

    /// Set the number of online vCPUs. Guest agent writes to sysfs.
    SetOnlineCpus { count: u32 },

    /// Acknowledge memory pressure — host has added memory.
    ///
    /// Sent after virtio-mem plug completes. The guest agent can use
    /// this to log or adjust PSI thresholds.
    MemoryAdded {
        /// New total memory in MB after hot-add.
        total_mb: u32,
    },

    /// Start an exec session with a PTY (instead of pipes).
    ///
    /// Like [`Exec`](Self::Exec) but the guest allocates a pseudo-terminal
    /// for the child process. The PTY gives the child a real terminal
    /// (TERM, line discipline, job control) — needed for interactive agents
    /// like Claude Code. Output is sent as `ExecStdout`, input received
    /// as `ExecStdin`, same as a regular exec session.
    ExecPty {
        /// Host-assigned session ID.
        id: ExecId,
        /// Argument vector.
        argv: Vec<String>,
        /// Environment entries encoded as `KEY=VALUE`.
        env: Vec<String>,
        /// Guest working directory, or empty to inherit.
        cwd: String,
    },

    /// Resize the PTY window for an active session.
    ///
    /// The guest calls `ioctl(TIOCSWINSZ)` on the PTY master fd.
    /// Only valid for sessions started with [`ExecPty`](Self::ExecPty).
    SessionResize {
        /// Exec session ID.
        id: ExecId,
        /// PTY row count.
        rows: u16,
        /// PTY column count.
        cols: u16,
    },

    /// Tell guest to stop reading stdout/stderr for this exec session.
    ///
    /// Sent when the host-side channel buffer exceeds the pause threshold.
    /// The guest disables POLLIN on the session's output fds, causing the
    /// child process to block on `write()` when pipe buffers fill.
    PauseExecOutput {
        /// Exec session ID.
        id: ExecId,
    },

    /// Tell guest to resume reading stdout/stderr for this exec session.
    ///
    /// Sent when the host-side channel buffer drains below the resume threshold.
    ResumeExecOutput {
        /// Exec session ID.
        id: ExecId,
    },
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn id(raw: u32) -> ExecId {
        ExecId::new(raw).unwrap()
    }

    // =========================================================================
    // AgentSetup
    // =========================================================================

    #[test]
    fn test_agent_setup_empty() {
        let setup = AgentSetup { mounts: Vec::new() };
        let bytes = postcard::to_allocvec(&setup).unwrap();
        let decoded: AgentSetup = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(setup, decoded);
    }

    #[test]
    fn test_agent_setup_with_mounts() {
        let setup = AgentSetup {
            mounts: vec![
                // Top-level mount with explicit path.
                MountOp::Mount {
                    source: Box::new(MountOp::DmLinear {
                        device_index: 0,
                        offset: 0,
                        size: 50_000_000,
                    }),
                    mount_path: Some(String::from("/data")),
                    fs_type: String::from("erofs"),
                    options: String::from("dax=always"),
                },
                // Overlay with inner mounts (no mount_path — agent picks temp dirs).
                MountOp::Overlay {
                    lower: vec![
                        MountOp::Mount {
                            source: Box::new(MountOp::DmLinear {
                                device_index: 0,
                                offset: 0,
                                size: 50_000_000,
                            }),
                            mount_path: None,
                            fs_type: String::from("erofs"),
                            options: String::from("dax=always"),
                        },
                        MountOp::Mount {
                            source: Box::new(MountOp::DmLinear {
                                device_index: 0,
                                offset: 50_003_968,
                                size: 30_000_000,
                            }),
                            mount_path: None,
                            fs_type: String::from("erofs"),
                            options: String::from("dax=always"),
                        },
                    ],
                    upper: None,
                    mount_path: String::from("/rootfs"),
                },
                // Overlay-in-place: empty lower = use existing dir at mount_path.
                MountOp::Overlay {
                    lower: vec![],
                    upper: Some(Box::new(MountOp::VirtioFs {
                        tag: String::from("repo"),
                        mount_path: None,
                    })),
                    mount_path: String::from("/rootfs/workspaces/repo"),
                },
                // Bare virtiofs with explicit path.
                MountOp::VirtioFs {
                    tag: String::from("shared"),
                    mount_path: Some(String::from("/shared")),
                },
            ],
        };
        let bytes = postcard::to_allocvec(&setup).unwrap();
        let decoded: AgentSetup = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(setup, decoded);
    }

    // =========================================================================
    // Serialization roundtrips (all variants)
    // =========================================================================

    #[test]
    fn test_guest_message_serialization_roundtrip() {
        let msg = GuestMessage::Status {
            message: String::from("hello"),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let decoded: GuestMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_host_message_serialization_roundtrip() {
        let setup = AgentSetup { mounts: Vec::new() };
        let resp = HostMessage::Setup(setup);
        let bytes = postcard::to_allocvec(&resp).unwrap();
        let decoded: HostMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(resp, decoded);
    }

    #[test]
    fn test_all_guest_message_variants_roundtrip() {
        let variants: Vec<GuestMessage> = vec![
            GuestMessage::Ready,
            GuestMessage::Ping,
            GuestMessage::Status {
                message: String::from("booting"),
            },
            GuestMessage::Custom {
                payload: vec![1, 2, 3],
            },
            GuestMessage::ExecStdout {
                id: id(1),
                data: vec![72, 73],
            },
            GuestMessage::ExecStderr {
                id: id(1),
                data: vec![69, 82, 82],
            },
            GuestMessage::ExecExit { id: id(1), code: 0 },
            GuestMessage::CpuOnlineResult {
                count: 4,
                error: None,
            },
            GuestMessage::MemoryPressure {
                level: 0,
                available_kb: 102_400,
                total_kb: 262_144,
            },
        ];
        for msg in &variants {
            let bytes = postcard::to_allocvec(msg).unwrap();
            let decoded: GuestMessage = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, &decoded);
        }
    }

    #[test]
    fn test_all_host_message_variants_roundtrip() {
        let variants: Vec<HostMessage> = vec![
            HostMessage::Setup(AgentSetup { mounts: Vec::new() }),
            HostMessage::Ok,
            HostMessage::Pong,
            HostMessage::Shutdown,
            HostMessage::Error {
                message: String::from("oops"),
            },
            HostMessage::Exec {
                id: id(42),
                argv: vec![String::from("echo"), String::from("hello")],
                env: vec![String::from("FOO=bar")],
                cwd: String::new(),
            },
            HostMessage::ExecStdin {
                id: id(42),
                data: vec![1, 2],
            },
            HostMessage::ExecStdinEof { id: id(42) },
            HostMessage::SetOnlineCpus { count: 4 },
            HostMessage::MemoryAdded { total_mb: 512 },
            HostMessage::ExecPty {
                id: id(43),
                argv: vec![String::from("/bin/sh")],
                env: vec![String::from("TERM=xterm")],
                cwd: String::from("/tmp"),
            },
            HostMessage::SessionResize {
                id: id(1),
                rows: 24,
                cols: 80,
            },
            HostMessage::PauseExecOutput { id: id(1) },
            HostMessage::ResumeExecOutput { id: id(1) },
        ];
        for msg in &variants {
            let bytes = postcard::to_allocvec(msg).unwrap();
            let decoded: HostMessage = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(msg, &decoded);
        }
    }

    // =========================================================================
    // Wire format stability
    // =========================================================================

    #[test]
    fn test_unit_variants_are_compact() {
        let ready = postcard::to_allocvec(&GuestMessage::Ready).unwrap();
        assert_eq!(ready.len(), 1);

        let ok = postcard::to_allocvec(&HostMessage::Ok).unwrap();
        assert_eq!(ok.len(), 1);

        let pong = postcard::to_allocvec(&HostMessage::Pong).unwrap();
        assert_eq!(pong.len(), 1);
    }

    #[test]
    fn test_empty_string_roundtrip() {
        let msg = GuestMessage::Status {
            message: String::new(),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        let decoded: GuestMessage = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(msg, decoded);
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_MESSAGE_SIZE, 64 * 1024);
    }

    // =========================================================================
    // Raw tag collision guard
    // =========================================================================

    /// Ensure postcard discriminants stay below 0x80 so they never collide
    /// with raw binary tags.
    ///
    /// Postcard encodes enum variant index as a varint. Variant indices < 128
    /// produce a single byte with the high bit clear (<0x80). If either enum
    /// ever grows to 128+ variants, the first byte would be >= 0x80, breaking
    /// the `try_decode_raw` heuristic.
    #[test]
    fn raw_tag_no_collision() {
        let msg = GuestMessage::MemoryPressure {
            level: 0,
            available_kb: 0,
            total_kb: 0,
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        assert!(
            bytes[0] < 0x80,
            "GuestMessage discriminant >= 0x80 collides with raw tags"
        );
        let msg = HostMessage::ResumeExecOutput { id: id(1) };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        assert!(
            bytes[0] < 0x80,
            "HostMessage discriminant >= 0x80 collides with raw tags"
        );
    }

    // =========================================================================
    // Raw header / decode tests
    // =========================================================================

    #[test]
    fn raw_header_encodes_tag_and_id() {
        let hdr = guest_raw_header(GuestRawTag::ExecStdout, id(42));
        assert_eq!(hdr[0], RAW_EXEC_STDOUT);
        assert_eq!(u32::from_le_bytes([hdr[1], hdr[2], hdr[3], hdr[4]]), 42);
    }

    #[test]
    fn raw_header_roundtrips_through_decode() {
        let host_cases = [(HostRawTag::ExecStdin, RAW_EXEC_STDIN)];
        for (tag, wire_tag) in host_cases {
            let hdr = host_raw_header(tag, id(0xDEAD_BEEF));
            let payload = &hdr[..];
            let frame = try_decode_host_raw(payload).unwrap().unwrap();
            assert_eq!(frame.tag, tag);
            assert_eq!(hdr[0], wire_tag);
            assert_eq!(frame.id, id(0xDEAD_BEEF));
            assert!(frame.data.is_empty());
        }

        let guest_cases = [
            (GuestRawTag::ExecStdout, RAW_EXEC_STDOUT),
            (GuestRawTag::ExecStderr, RAW_EXEC_STDERR),
        ];
        for (tag, wire_tag) in guest_cases {
            let hdr = guest_raw_header(tag, id(0xDEAD_BEEF));
            let payload = &hdr[..];
            let frame = try_decode_guest_raw(payload).unwrap().unwrap();
            assert_eq!(frame.tag, tag);
            assert_eq!(hdr[0], wire_tag);
            assert_eq!(frame.id, id(0xDEAD_BEEF));
            assert!(frame.data.is_empty());
        }
    }

    #[test]
    fn try_decode_raw_returns_trailing_data() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&guest_raw_header(GuestRawTag::ExecStdout, id(7)));
        buf.extend_from_slice(b"hello");

        let frame = try_decode_guest_raw(&buf).unwrap().unwrap();
        assert_eq!(frame.tag, GuestRawTag::ExecStdout);
        assert_eq!(frame.id, id(7));
        assert_eq!(frame.data, b"hello");
    }

    #[test]
    fn try_decode_raw_rejects_postcard_discriminant() {
        // Postcard discriminants are < 0x80, should NOT decode as raw
        let postcard_bytes = postcard::to_allocvec(&GuestMessage::Ready).unwrap();
        assert!(try_decode_guest_raw(&postcard_bytes).unwrap().is_none());
    }

    #[test]
    fn try_decode_raw_rejects_short_payload() {
        assert!(try_decode_guest_raw(&[]).unwrap().is_none());
        assert_eq!(
            try_decode_guest_raw(&[0x80]),
            Err(RawDecodeError::ShortHeader { len: 1 }),
        );
        assert_eq!(
            try_decode_guest_raw(&[0x80, 0, 0, 0]),
            Err(RawDecodeError::ShortHeader { len: 4 }),
        );
    }

    #[test]
    fn try_decode_raw_rejects_zero_exec_id() {
        let mut frame = guest_raw_header(GuestRawTag::ExecStdout, id(7));
        frame[1..RAW_HEADER_SIZE].copy_from_slice(&0_u32.to_le_bytes());

        assert_eq!(
            try_decode_guest_raw(&frame),
            Err(RawDecodeError::ZeroExecId),
        );
    }

    #[test]
    fn raw_decode_rejects_wrong_direction() {
        let host_frame = host_raw_header(HostRawTag::ExecStdin, id(7));
        assert_eq!(
            try_decode_guest_raw(&host_frame),
            Err(RawDecodeError::UnknownTag {
                tag: RAW_EXEC_STDIN,
            }),
        );

        let guest_frame = guest_raw_header(GuestRawTag::ExecStdout, id(7));
        assert_eq!(
            try_decode_host_raw(&guest_frame),
            Err(RawDecodeError::UnknownTag {
                tag: RAW_EXEC_STDOUT,
            }),
        );
    }
}
