// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Guest agent host-side backend.
//!
//! Provides host-side handling for the guest agent protocol over a shared
//! ring buffer. Uses length-prefixed postcard serialization:
//! `[u32 len][payload]`.
//!
//! # Architecture
//!
//! - [`AgentLink`] holds session-level state (channels, exec sessions) behind
//!   a mutex. Shared between `run()` infrastructure and `AgentRingState` via `Arc`.
//! - [`AgentRingState`] (`ring` submodule) processes the ring buffer
//!   synchronously inside the device loop's poll cycle.
//! - [`VmHandle`] / [`CommandExecution`] (`vm_handle` / `command` submodules)
//!   are the host-facing public APIs.

mod command;
pub mod ring;
mod vm_handle;

// Re-export public API types.
pub use command::{
    CollectedOutput, CommandExecution, CommandExecutionHandle, DEFAULT_COLLECT_OUTPUT_LIMIT,
    IntoHandleError, OutputEvent, StdinWriter,
};
pub use vm_handle::{
    CommandSpec, ExecArg, ExecBuilder, GuestCwd, GuestEnvVar, Paused, Running, VmHandle,
};

// Re-export internal types used by other crate modules.
pub use ring::{AgentRingState, AgentRingWake};

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::task::{Context, Poll};

use amla_constants::protocol::ExecId;
use tokio::sync::{Notify, mpsc, oneshot};

use crate::shared_state::VmStatus;

/// Maximum queued exec start requests waiting for the device loop.
pub const EXEC_REQUEST_QUEUE_CAPACITY: usize = 128;

/// Maximum queued stdin data frames waiting for the device loop.
pub const EXEC_STDIN_DATA_QUEUE_CAPACITY: usize = 256;

/// Maximum queued output chunks per stdout/stderr stream.
pub const EXEC_OUTPUT_QUEUE_CAPACITY: usize = 256;

/// Pause output when a stream reaches the bounded channel capacity.
pub const OUTPUT_PAUSE_ITEM_THRESHOLD: usize = EXEC_OUTPUT_QUEUE_CAPACITY;

/// Resume output when a paused stream drains below the old low-water mark.
pub const OUTPUT_RESUME_ITEM_THRESHOLD: usize = EXEC_OUTPUT_QUEUE_CAPACITY / 4;

/// Maximum queued memory-pressure events for the host observer.
const MEMORY_PRESSURE_QUEUE_CAPACITY: usize = 32;

/// Maximum accepted stdin chunk size.
pub const EXEC_STDIN_CHUNK_MAX: usize = 64 * 1024;

/// Maximum host-queued stdin bytes per exec session.
pub const EXEC_STDIN_PENDING_BYTES: usize = 1024 * 1024;

/// When a session's queued output reaches this, tell the guest to pause output.
const PAUSE_THRESHOLD: usize = 512 * 1024;

/// When a paused session's queued output drops to this, tell the guest to resume.
const RESUME_THRESHOLD: usize = 128 * 1024;

/// Hard cap on queued output bytes per stdout/stderr stream.
const EXEC_OUTPUT_STREAM_BUDGET: usize = 4 * 1024 * 1024;

/// Sticky wake handle for host-side agent work.
#[derive(Clone)]
pub struct HostNotify {
    wake: Arc<Notify>,
    pending: Arc<AtomicBool>,
}

impl HostNotify {
    fn new() -> Self {
        Self {
            wake: Arc::new(Notify::new()),
            pending: Arc::new(AtomicBool::new(false)),
        }
    }

    pub(crate) fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    pub(crate) fn pending(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.pending)
    }

    pub(crate) fn notify(&self) {
        self.pending.store(true, Ordering::Release);
        self.wake.notify_one();
    }
}

/// Reference-counted byte budget for data accepted into bounded queues.
#[derive(Clone)]
pub struct ByteBudget {
    used: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    limit: usize,
}

impl ByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
            limit,
        }
    }

    fn try_acquire(&self, bytes: usize) -> Result<ByteCredit, ByteBudgetTryAcquireError> {
        if bytes > self.limit {
            return Err(ByteBudgetTryAcquireError::TooLarge {
                len: bytes,
                max: self.limit,
            });
        }

        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(bytes) else {
                return Err(ByteBudgetTryAcquireError::Full);
            };
            if next > self.limit {
                return Err(ByteBudgetTryAcquireError::Full);
            }
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Ok(ByteCredit {
                        used: Arc::clone(&self.used),
                        notify: Arc::clone(&self.notify),
                        bytes,
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    async fn acquire(&self, bytes: usize) -> Result<ByteCredit, ExecError> {
        loop {
            let notified = self.notify.notified();
            match self.try_acquire(bytes) {
                Ok(credit) => return Ok(credit),
                Err(ByteBudgetTryAcquireError::Full) => notified.await,
                Err(ByteBudgetTryAcquireError::TooLarge { len, max }) => {
                    return Err(ExecError::MessageTooLarge { len, max });
                }
            }
        }
    }
}

#[derive(Debug)]
enum ByteBudgetTryAcquireError {
    Full,
    TooLarge { len: usize, max: usize },
}

/// Releases byte credit when a queued item is delivered or dropped.
pub struct ByteCredit {
    used: Arc<AtomicUsize>,
    notify: Arc<Notify>,
    bytes: usize,
}

impl Drop for ByteCredit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
}

/// Bounded sender that tracks queued output items and bytes.
pub struct CountedSender<T> {
    inner: mpsc::Sender<T>,
    items: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
    byte_budget: usize,
}

#[derive(Debug)]
pub enum CountedSendError {
    Closed,
    Full,
    TooLarge { len: usize, max: usize },
}

impl CountedSender<Vec<u8>> {
    fn send(&self, value: Vec<u8>) -> Result<(), CountedSendError> {
        let byte_len = value.len();
        self.reserve_bytes(byte_len)?;
        self.items.fetch_add(1, Ordering::Relaxed);
        match self.inner.try_send(value) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(_)) => {
                self.release(byte_len);
                Err(CountedSendError::Closed)
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.release(byte_len);
                Err(CountedSendError::Full)
            }
        }
    }

    fn pending_bytes(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }

    fn pending_items(&self) -> usize {
        self.items.load(Ordering::Relaxed)
    }

    fn reserve_bytes(&self, byte_len: usize) -> Result<(), CountedSendError> {
        if byte_len > self.byte_budget {
            return Err(CountedSendError::TooLarge {
                len: byte_len,
                max: self.byte_budget,
            });
        }
        let mut cur = self.bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(byte_len) else {
                return Err(CountedSendError::Full);
            };
            if next > self.byte_budget {
                return Err(CountedSendError::Full);
            }
            match self
                .bytes
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => return Ok(()),
                Err(actual) => cur = actual,
            }
        }
    }

    fn release(&self, byte_len: usize) {
        self.items.fetch_sub(1, Ordering::Relaxed);
        self.bytes.fetch_sub(byte_len, Ordering::AcqRel);
    }
}

/// Bounded receiver that decrements shared item/byte counters on each recv.
///
/// Returned by [`CommandExecution::take_stdout()`] / [`CommandExecution::take_stderr()`].
pub struct CountedReceiver {
    inner: mpsc::Receiver<Vec<u8>>,
    items: Arc<AtomicUsize>,
    bytes: Arc<AtomicUsize>,
    host_notify: HostNotify,
}

impl CountedReceiver {
    /// Poll the next item, decrementing the shared counters when an item is
    /// received.
    ///
    /// This is equivalent to [`recv()`](Self::recv), but is useful for
    /// schedulers that need to poll several command streams from one owner
    /// future without spawning per-stream tasks.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        match Pin::new(&mut self.inner).poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                self.items.fetch_sub(1, Ordering::Relaxed);
                self.bytes.fetch_sub(bytes.len(), Ordering::AcqRel);
                self.host_notify.notify();
                Poll::Ready(Some(bytes))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Return whether this receiver has queued output that has not been received.
    #[must_use]
    pub fn has_pending(&self) -> bool {
        self.items.load(Ordering::Acquire) != 0 || self.bytes.load(Ordering::Acquire) != 0
    }

    /// Receive the next item, decrementing the shared counters.
    ///
    /// After each successful recv, notifies the device loop so it can
    /// check whether paused sessions should be resumed.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        std::future::poll_fn(|cx| self.poll_recv(cx)).await
    }
}

impl Drop for CountedReceiver {
    fn drop(&mut self) {
        self.inner.close();
        let mut items = 0usize;
        let mut bytes = 0usize;
        while let Ok(item) = self.inner.try_recv() {
            items += 1;
            bytes += item.len();
        }
        if items != 0 {
            self.items.fetch_sub(items, Ordering::Relaxed);
            self.bytes.fetch_sub(bytes, Ordering::AcqRel);
            self.host_notify.notify();
        }
    }
}

fn counted_channel(host_notify: HostNotify) -> (CountedSender<Vec<u8>>, CountedReceiver) {
    let (tx, rx) = mpsc::channel(EXEC_OUTPUT_QUEUE_CAPACITY);
    let items = Arc::new(AtomicUsize::new(0));
    let bytes = Arc::new(AtomicUsize::new(0));
    (
        CountedSender {
            inner: tx,
            items: Arc::clone(&items),
            bytes: Arc::clone(&bytes),
            byte_budget: EXEC_OUTPUT_STREAM_BUDGET,
        },
        CountedReceiver {
            inner: rx,
            items,
            bytes,
            host_notify,
        },
    )
}

/// A memory pressure event received from the guest's PSI monitor.
#[derive(Debug, Clone)]
pub struct MemoryPressureEvent {
    /// PSI level: 0 = some (partial stall), 1 = full (all tasks stalled).
    pub level: u8,
    /// Available memory in KB (from `/proc/meminfo` `MemAvailable`).
    pub available_kb: u64,
    /// Total memory in KB.
    pub total_kb: u64,
}

/// Error type for command execution operations.
#[derive(Debug, thiserror::Error)]
pub enum ExecError {
    /// Guest agent disconnected.
    #[error("guest agent disconnected")]
    Disconnected,
    /// The command has transient host-side state and cannot be made durable.
    #[error("command cannot be made reattachable: {reason}")]
    NotReattachable {
        /// Why the command cannot be safely converted into a reattach handle.
        reason: &'static str,
    },
    /// Message exceeds the configured per-message or per-session byte limit.
    #[error("guest agent message too large: {len} bytes exceeds {max} byte limit")]
    MessageTooLarge {
        /// Attempted message length in bytes.
        len: usize,
        /// Configured maximum length in bytes.
        max: usize,
    },
    /// Command request failed validation before it was queued for the guest.
    #[error("invalid command request: {reason}")]
    InvalidCommand {
        /// Why the command request was rejected.
        reason: &'static str,
    },
    /// Captured command output exceeded the caller-provided collection limit.
    #[error(
        "command output limit exceeded: attempted to collect {attempted} bytes, limit is {limit} bytes"
    )]
    OutputLimitExceeded {
        /// Number of bytes that would have been collected.
        attempted: usize,
        /// Maximum number of bytes allowed by the collector.
        limit: usize,
    },
    /// Host-side exec session ID space is exhausted.
    #[error("exec session ID space exhausted")]
    ExecIdExhausted,
}

/// Internal: start-session request from `VmHandle` to `AgentBackend`.
pub struct ExecRequest {
    pub id: ExecId,
    pub payload: Vec<u8>,
    pub stdout_tx: CountedSender<Vec<u8>>,
    pub stderr_tx: CountedSender<Vec<u8>>,
    pub exit_tx: oneshot::Sender<i32>,
    pub control: Arc<SessionControl>,
    /// Sent once the ring processor has accepted ownership of the request.
    pub accepted_tx: oneshot::Sender<()>,
}

/// Coalesced per-session control state.
pub struct SessionControl {
    eof_requested: AtomicBool,
    pending_resize: parking_lot::Mutex<Option<(u16, u16)>>,
}

impl SessionControl {
    pub(super) const fn new() -> Self {
        Self {
            eof_requested: AtomicBool::new(false),
            pending_resize: parking_lot::Mutex::new(None),
        }
    }

    pub(super) fn request_eof(&self) {
        self.eof_requested.store(true, Ordering::Release);
    }

    pub(super) fn eof_requested(&self) -> bool {
        self.eof_requested.load(Ordering::Acquire)
    }

    pub(super) fn clear_eof_requested(&self) {
        self.eof_requested.store(false, Ordering::Release);
    }

    pub(super) fn request_resize(&self, rows: u16, cols: u16) {
        *self.pending_resize.lock() = Some((rows, cols));
    }

    pub(super) fn pending_resize(&self) -> Option<(u16, u16)> {
        *self.pending_resize.lock()
    }

    pub(super) fn clear_resize_if_current(&self, rows: u16, cols: u16) {
        let mut pending = self.pending_resize.lock();
        if *pending == Some((rows, cols)) {
            *pending = None;
        }
    }

    pub(super) fn has_pending_control(&self) -> bool {
        self.eof_requested() || self.pending_resize().is_some()
    }
}

/// Stdin data destined for a specific exec session.
pub struct ExecStdinData {
    id: ExecId,
    data: Vec<u8>,
    credit: ByteCredit,
}

impl ExecStdinData {
    /// Build a stdin data frame while holding the byte-budget credit.
    pub(super) const fn new(id: ExecId, data: Vec<u8>, credit: ByteCredit) -> Self {
        Self { id, data, credit }
    }

    /// Return the stdin data payload length.
    pub(super) const fn len(&self) -> usize {
        self.data.len()
    }

    /// Consume the frame into fields needed by the ring writer.
    pub(super) fn into_parts(self) -> (ExecId, Vec<u8>, ByteCredit) {
        (self.id, self.data, self.credit)
    }
}

/// A pending host-to-guest frame, either postcard-serialized or raw binary.
pub enum PendingFrame {
    /// Postcard-serialized message (control messages, etc.).
    Serialized(Vec<u8>),
    /// Raw binary data: 5-byte header + owned data (stdin).
    Raw {
        header: [u8; amla_constants::protocol::RAW_HEADER_SIZE],
        data: Vec<u8>,
        _credit: Option<ByteCredit>,
    },
}

impl PendingFrame {
    pub(super) const fn wire_len(&self) -> usize {
        match self {
            Self::Serialized(payload) => payload.len(),
            Self::Raw { header, data, .. } => header.len() + data.len(),
        }
    }
}

/// Per-session state held by the backend for routing responses.
pub struct ExecSession {
    stdout: CountedSender<Vec<u8>>,
    stderr: CountedSender<Vec<u8>>,
    exit: Option<oneshot::Sender<i32>>,
    /// Set by `CommandExecution::into_handle()`. While true, output and exit
    /// frames must stay in the durable guest-to-host mmap ring for a future
    /// `attach()` instead of being consumed into per-run channels.
    reattachable: bool,
    /// Coalesced controls that must survive bounded stdin-channel pressure.
    control: Arc<SessionControl>,
    /// True when the host has sent `PauseExecOutput` and is waiting for
    /// the channel to drain before sending `ResumeExecOutput`.
    paused: bool,
}

/// Raw channel endpoints for building a `VmHandle`.
pub struct ExecChannels {
    pub exec_req_tx: mpsc::Sender<ExecRequest>,
    pub exec_stdin_data_tx: mpsc::Sender<ExecStdinData>,
    pub memory_pressure_rx: mpsc::Receiver<MemoryPressureEvent>,
    pub host_notify: HostNotify,
    pub shutdown_tx: oneshot::Sender<()>,
}

/// Shared link between `run()` infrastructure and `AgentBackend`.
///
/// Holds session-level state (channels + sessions) behind a mutex.
/// `AgentLink::connect()` creates fresh channels each `run()` cycle,
/// resetting session state.
///
/// Also holds per-run coordination state (`vm_status`) that connects
/// `VmHandle` to `AgentBackend`.
pub struct AgentLink {
    pub(super) inner: parking_lot::Mutex<AgentLinkInner>,
    /// VM status for run-exit signaling (set per `run()` cycle).
    vm_status: parking_lot::Mutex<Option<Arc<VmStatus>>>,
    /// Wakes the device loop when host channels have data.
    /// Shared with `VmHandle`.
    host_notify: HostNotify,
    next_exec_id: AtomicU32,
}

#[allow(clippy::struct_field_names)]
pub struct AgentLinkInner {
    // Channels (replaced each run() via connect())
    pub exec_req_rx: mpsc::Receiver<ExecRequest>,
    pub exec_stdin_data_rx: mpsc::Receiver<ExecStdinData>,
    // Active sessions keyed by host-assigned ID.
    pub exec_sessions: HashMap<ExecId, ExecSession>,
    // Memory pressure events from the guest PSI monitor.
    pub memory_pressure_tx: mpsc::Sender<MemoryPressureEvent>,
    // Graceful shutdown signal from the host.
    pub shutdown_rx: oneshot::Receiver<()>,
    // True once the per-run host API channels have been closed for final drain.
    pub run_channels_closed: bool,
}

impl AgentLink {
    /// Create a new agent link with dead (disconnected) channels.
    pub fn new() -> Self {
        // Create dead channels: counterparts are immediately dropped, so
        // try_recv() returns Disconnected and send() returns Err — same
        // behavior as the old Option::None paths.
        let (_, exec_req_rx) = mpsc::channel(EXEC_REQUEST_QUEUE_CAPACITY);
        let (_, exec_stdin_data_rx) = mpsc::channel(EXEC_STDIN_DATA_QUEUE_CAPACITY);
        let (memory_pressure_tx, _) = mpsc::channel(MEMORY_PRESSURE_QUEUE_CAPACITY);
        let (_, shutdown_rx) = oneshot::channel();

        Self {
            inner: parking_lot::Mutex::new(AgentLinkInner {
                exec_req_rx,
                exec_stdin_data_rx,
                exec_sessions: HashMap::new(),
                memory_pressure_tx,
                shutdown_rx,
                run_channels_closed: true,
            }),
            vm_status: parking_lot::Mutex::new(None),
            host_notify: HostNotify::new(),
            next_exec_id: AtomicU32::new(ExecId::FIRST.get()),
        }
    }

    pub(super) fn alloc_exec_id(&self) -> Result<ExecId, ExecError> {
        loop {
            let raw = self.next_exec_id.load(Ordering::Acquire);
            let id = ExecId::new(raw).ok_or(ExecError::ExecIdExhausted)?;
            let next = raw.checked_add(1).ok_or(ExecError::ExecIdExhausted)?;
            if self
                .next_exec_id
                .compare_exchange(raw, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(id);
            }
        }
    }

    fn reserve_after_known_id(&self, id: ExecId) {
        let Some(min_next) = id.get().checked_add(1) else {
            self.next_exec_id.store(0, Ordering::Release);
            return;
        };
        let mut cur = self.next_exec_id.load(Ordering::Acquire);
        while cur != 0 && cur < min_next {
            match self.next_exec_id.compare_exchange(
                cur,
                min_next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(next_cur) => cur = next_cur,
            }
        }
    }

    /// Get the host notify handle (shared with the device loop).
    pub fn host_notify(&self) -> Arc<Notify> {
        self.host_notify.wake()
    }

    /// Get the paired sticky notifier for host-side producers.
    pub(crate) fn host_notifier(&self) -> HostNotify {
        self.host_notify.clone()
    }

    /// Get the sticky pending flag paired with [`Self::host_notify`].
    pub fn host_pending(&self) -> Arc<AtomicBool> {
        self.host_notify.pending()
    }

    /// Notify the device loop that host-side agent work is pending.
    pub fn notify_host(&self) {
        self.host_notify.notify();
    }

    /// Set the VM status for run-exit signaling.
    ///
    /// Called at the start of each `run()` cycle to give the backend
    /// access to the current `VmStatus`.
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn set_vm_status(&self, status: Arc<VmStatus>) {
        *self.vm_status.lock() = Some(status);
    }

    /// Register a pre-existing session (from a forked parent) by ID.
    ///
    /// Inserts an `ExecSession` so that ring messages for this ID are
    /// routed to the returned channels. Called by `VmHandle::start()`
    /// during the Paused → Running transition.
    // Reason: the inner-lock guard intentionally spans the insert and
    // any concurrent observer must see the updated session table.
    #[allow(clippy::significant_drop_tightening)]
    pub fn register_session(
        &self,
        id: ExecId,
    ) -> (
        CountedReceiver,
        CountedReceiver,
        oneshot::Receiver<i32>,
        Arc<SessionControl>,
    ) {
        let (stdout_tx, stdout_rx) = counted_channel(self.host_notify.clone());
        let (stderr_tx, stderr_rx) = counted_channel(self.host_notify.clone());
        let (exit_tx, exit_rx) = oneshot::channel();
        let control = Arc::new(SessionControl::new());
        self.reserve_after_known_id(id);

        let mut inner = self.inner.lock();
        let old = inner.exec_sessions.insert(
            id,
            ExecSession {
                stdout: stdout_tx,
                stderr: stderr_tx,
                exit: Some(exit_tx),
                reattachable: false,
                control: Arc::clone(&control),
                paused: false,
            },
        );
        debug_assert!(old.is_none(), "duplicate exec session id {id}");
        log::trace!(
            "agent register_session id={id} replaced_existing={} sessions={}",
            old.is_some(),
            inner.exec_sessions.len()
        );

        (stdout_rx, stderr_rx, exit_rx, control)
    }

    /// Convert a live session into a reattachable session.
    ///
    /// This is deliberately checked under the same lock used by ring output
    /// forwarding. It can only succeed when no stdout/stderr/exit state has
    /// escaped from durable mmap into transient host channels.
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn mark_session_reattachable(&self, id: ExecId) -> Result<(), ExecError> {
        log::trace!("agent mark_session_reattachable id={id}: requested");
        let mut inner = self.inner.lock();
        let Some(session) = inner.exec_sessions.get_mut(&id) else {
            log::trace!("agent mark_session_reattachable id={id}: no active session");
            return Err(ExecError::NotReattachable {
                reason: "session has already exited or is not active",
            });
        };
        if session.stdout.pending_items() != 0
            || session.stderr.pending_items() != 0
            || session.stdout.pending_bytes() != 0
            || session.stderr.pending_bytes() != 0
        {
            log::trace!(
                "agent mark_session_reattachable id={id}: host-buffered output stdout_items={} stderr_items={} stdout_bytes={} stderr_bytes={}",
                session.stdout.pending_items(),
                session.stderr.pending_items(),
                session.stdout.pending_bytes(),
                session.stderr.pending_bytes()
            );
            return Err(ExecError::NotReattachable {
                reason: "stdout/stderr has already been delivered to host channels",
            });
        }
        if session.paused {
            log::trace!("agent mark_session_reattachable id={id}: paused");
            return Err(ExecError::NotReattachable {
                reason: "session is paused for host output backpressure",
            });
        }
        if session.control.has_pending_control() {
            log::trace!("agent mark_session_reattachable id={id}: pending control");
            return Err(ExecError::NotReattachable {
                reason: "session control has pending host-side state",
            });
        }
        session.reattachable = true;
        log::trace!("agent mark_session_reattachable id={id}: succeeded");
        Ok(())
    }

    pub(super) fn has_session(&self, id: ExecId) -> bool {
        self.inner.lock().exec_sessions.contains_key(&id)
    }

    /// Create fresh channels and reset session state.
    ///
    /// Returns `ExecChannels` for building a `VmHandle`.
    /// The backend reads from the link's inner channels via `drain_host_channels()`.
    pub fn connect(&self) -> ExecChannels {
        let (exec_req_tx, exec_req_rx) = mpsc::channel(EXEC_REQUEST_QUEUE_CAPACITY);
        let (exec_stdin_data_tx, exec_stdin_data_rx) =
            mpsc::channel(EXEC_STDIN_DATA_QUEUE_CAPACITY);
        let (memory_pressure_tx, memory_pressure_rx) =
            mpsc::channel(MEMORY_PRESSURE_QUEUE_CAPACITY);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let mut inner = self.inner.lock();
        log::trace!(
            "agent connect: resetting per-run channels old_sessions={} run_channels_closed={}",
            inner.exec_sessions.len(),
            inner.run_channels_closed
        );
        inner.exec_req_rx = exec_req_rx;
        inner.exec_stdin_data_rx = exec_stdin_data_rx;
        inner.exec_sessions.clear();
        inner.memory_pressure_tx = memory_pressure_tx;
        inner.shutdown_rx = shutdown_rx;
        inner.run_channels_closed = false;
        drop(inner);

        ExecChannels {
            exec_req_tx,
            exec_stdin_data_tx,
            memory_pressure_rx,
            host_notify: self.host_notify.clone(),
            shutdown_tx,
        }
    }

    /// Close per-run host API channels before final ring drain.
    ///
    /// Already queued requests remain drainable by `AgentRingState`, but
    /// surviving `VmHandle::into_exec_only()` / `StdinWriter` clones can no
    /// longer enqueue new work after `run()` is on its way back to `Ready`.
    pub fn close_run_channels(&self) {
        let mut inner = self.inner.lock();
        log::trace!(
            "agent close_run_channels: sessions={} exec_req_queued={} stdin_queued={}",
            inner.exec_sessions.len(),
            inner.exec_req_rx.len(),
            inner.exec_stdin_data_rx.len()
        );
        inner.exec_req_rx.close();
        inner.exec_stdin_data_rx.close();
        inner.shutdown_rx.close();
        inner.run_channels_closed = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: u32) -> ExecId {
        ExecId::new(raw).unwrap()
    }

    fn exec_payload(argv: &[&str]) -> Vec<u8> {
        postcard::to_allocvec(&amla_constants::protocol::HostMessage::Exec {
            id: id(1),
            argv: argv.iter().map(|arg| (*arg).to_string()).collect(),
            env: Vec::new(),
            cwd: String::new(),
        })
        .unwrap()
    }

    #[test]
    fn counted_receiver_drop_releases_pending_accounting() {
        let notify = HostNotify::new();
        let (tx, rx) = counted_channel(notify.clone());
        tx.send(vec![1, 2, 3]).unwrap();
        tx.send(vec![4, 5]).unwrap();

        assert_eq!(tx.pending_items(), 2);
        assert_eq!(tx.pending_bytes(), 5);

        drop(rx);

        assert_eq!(tx.pending_items(), 0);
        assert_eq!(tx.pending_bytes(), 0);
        assert!(notify.pending.load(Ordering::Acquire));
    }

    #[test]
    fn mark_session_reattachable_rejects_host_buffered_output() {
        let link = AgentLink::new();
        let (stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));

        {
            let inner = link.inner.lock();
            inner
                .exec_sessions
                .get(&id(7))
                .unwrap()
                .stdout
                .send(b"buffered".to_vec())
                .unwrap();
        }

        let err = link.mark_session_reattachable(id(7)).unwrap_err();
        assert!(matches!(err, ExecError::NotReattachable { .. }));
        assert!(err.to_string().contains("delivered"), "{err}");

        drop(stdout_rx);
        assert!(link.mark_session_reattachable(id(7)).is_ok());
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn test_agent_link_connect_creates_channels() {
        let link = AgentLink::new();
        let ch = link.connect();

        // Channel should be functional.
        let notify = HostNotify::new();
        ch.exec_req_tx
            .try_send(ExecRequest {
                id: id(1),
                payload: exec_payload(&["echo", "hello"]),
                stdout_tx: counted_channel(notify.clone()).0,
                stderr_tx: counted_channel(notify).0,
                exit_tx: oneshot::channel().0,
                control: Arc::new(SessionControl::new()),
                accepted_tx: oneshot::channel().0,
            })
            .unwrap();
        let inner = link.inner.lock();
        assert_eq!(inner.exec_req_rx.len(), 1);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn close_run_channels_rejects_late_senders_but_keeps_queued_work() {
        let link = AgentLink::new();
        let ch = link.connect();
        let notify = HostNotify::new();

        ch.exec_req_tx
            .try_send(ExecRequest {
                id: id(1),
                payload: exec_payload(&["echo", "hello"]),
                stdout_tx: counted_channel(notify.clone()).0,
                stderr_tx: counted_channel(notify).0,
                exit_tx: oneshot::channel().0,
                control: Arc::new(SessionControl::new()),
                accepted_tx: oneshot::channel().0,
            })
            .unwrap();
        ch.exec_stdin_data_tx
            .try_send(ExecStdinData::new(
                id(7),
                vec![1],
                ByteBudget::new(16).try_acquire(1).unwrap(),
            ))
            .unwrap();

        link.close_run_channels();

        let notify = HostNotify::new();
        assert!(
            ch.exec_req_tx
                .try_send(ExecRequest {
                    id: id(2),
                    payload: exec_payload(&["echo", "late"]),
                    stdout_tx: counted_channel(notify.clone()).0,
                    stderr_tx: counted_channel(notify).0,
                    exit_tx: oneshot::channel().0,
                    control: Arc::new(SessionControl::new()),
                    accepted_tx: oneshot::channel().0,
                })
                .is_err()
        );
        assert!(
            ch.exec_stdin_data_tx
                .try_send(ExecStdinData::new(
                    id(7),
                    vec![2],
                    ByteBudget::new(16).try_acquire(1).unwrap(),
                ))
                .is_err()
        );
        assert!(ch.shutdown_tx.send(()).is_err());

        let inner = link.inner.lock();
        assert!(inner.run_channels_closed);
        assert_eq!(inner.exec_req_rx.len(), 1);
        assert_eq!(inner.exec_stdin_data_rx.len(), 1);
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn test_agent_link_reconnect_resets_state() {
        let link = AgentLink::new();

        // First connection cycle — add session.
        let _ch1 = link.connect();
        {
            let notify = HostNotify::new();
            let mut inner = link.inner.lock();
            inner.exec_sessions.insert(
                id(42),
                ExecSession {
                    stdout: counted_channel(notify.clone()).0,
                    stderr: counted_channel(notify).0,
                    exit: Some(oneshot::channel().0),
                    reattachable: false,
                    control: Arc::new(SessionControl::new()),
                    paused: false,
                },
            );
        }

        // Reconnect — creates fresh channels, resets session state.
        let _ch2 = link.connect();
        {
            let inner = link.inner.lock();
            assert!(
                inner.exec_sessions.is_empty(),
                "reconnect should clear exec_sessions"
            );
        }
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn test_agent_link_connect_creates_fresh_channels() {
        let link = AgentLink::new();
        let _ch = link.connect();
        // Channels are fresh after connect.
        let inner = link.inner.lock();
        assert!(inner.exec_sessions.is_empty());
    }
}
