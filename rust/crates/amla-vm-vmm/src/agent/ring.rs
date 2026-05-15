// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Ring buffer agent transport — processes the host↔guest shared ring.
//!
//! [`AgentRingState`] communicates with the guest agent via SPSC ring buffers.
//! Runs synchronously inside the device loop poll cycle.

use std::collections::VecDeque;
use std::sync::Arc;

use amla_constants::protocol::{ExecId, GuestMessage, HostMessage};

use super::{
    AgentLink, CountedSendError, EXEC_STDIN_CHUNK_MAX, ExecSession, MemoryPressureEvent,
    OUTPUT_PAUSE_ITEM_THRESHOLD, OUTPUT_RESUME_ITEM_THRESHOLD, PAUSE_THRESHOLD, PendingFrame,
    RESUME_THRESHOLD, SessionControl,
};

/// Maximum host-to-guest frames buffered outside the ring.
const PENDING_TX_FRAME_CAPACITY: usize = 1024;

/// Maximum host-to-guest bytes buffered outside the ring.
const PENDING_TX_BYTE_CAPACITY: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputForwardResult {
    Forwarded,
    Backpressured,
    Reattachable,
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RingHealth {
    Clean,
    Corrupt,
}

enum RawFrameProgress {
    Consumed,
    Blocked,
}

/// Host-side wake hook used after writing host-to-guest ring data.
pub trait AgentRingWake: Send + Sync {
    fn wake_peer(&self);
}

impl<F> AgentRingWake for F
where
    F: Fn() + Send + Sync,
{
    fn wake_peer(&self) {
        self();
    }
}

fn decode_guest_raw_frame(
    bytes: &[u8],
) -> Result<
    Option<(
        amla_constants::protocol::GuestRawTag,
        amla_constants::protocol::ExecId,
        Vec<u8>,
    )>,
    amla_constants::protocol::RawDecodeError,
> {
    Ok(amla_constants::protocol::try_decode_guest_raw(bytes)?
        .map(|frame| (frame.tag, frame.id, frame.data.to_vec())))
}

const fn raw_header_id(header: [u8; amla_constants::protocol::RAW_HEADER_SIZE]) -> Option<ExecId> {
    ExecId::new(u32::from_le_bytes([
        header[1], header[2], header[3], header[4],
    ]))
}

fn pending_frame_summary(frame: &PendingFrame) -> String {
    match frame {
        PendingFrame::Serialized(payload) => match postcard::from_bytes::<HostMessage>(payload) {
            Ok(HostMessage::Exec { id, argv, .. }) => {
                format!("HostMessage::Exec id={id} argv0={:?}", argv.first())
            }
            Ok(HostMessage::ExecPty { id, argv, .. }) => {
                format!("HostMessage::ExecPty id={id} argv0={:?}", argv.first())
            }
            Ok(HostMessage::ExecStdinEof { id }) => {
                format!("HostMessage::ExecStdinEof id={id}")
            }
            Ok(HostMessage::SessionResize { id, rows, cols }) => {
                format!("HostMessage::SessionResize id={id} rows={rows} cols={cols}")
            }
            Ok(HostMessage::PauseExecOutput { id }) => {
                format!("HostMessage::PauseExecOutput id={id}")
            }
            Ok(HostMessage::ResumeExecOutput { id }) => {
                format!("HostMessage::ResumeExecOutput id={id}")
            }
            Ok(other) => format!("{other:?}"),
            Err(error) => format!("serialized host frame decode_error={error}"),
        },
        PendingFrame::Raw { header, data, .. } => raw_header_id(*header).map_or_else(
            || format!("raw unknown tag={} bytes={}", header[0], data.len()),
            |id| format!("raw ExecStdin id={id} bytes={}", data.len()),
        ),
    }
}

/// Ring buffer-based agent transport state.
///
/// Communicates with the guest agent via SPSC ring buffers in shared memory.
/// Runs synchronously inside the device loop poll cycle — no
/// separate tokio task needed.
///
/// # Notification
///
/// The `wake` closure signals the peer after writing to the HG ring. The
/// concrete implementation depends on the transport:
/// - VM: pushes a kick byte through the virtio console port (IRQ)
/// - Subprocess: writes to a pipe doorbell
///
/// The "wait" side (how this state machine gets woken) is external —
/// driven by the device loop or a dedicated async loop.
pub struct AgentRingState<'ring, W: AgentRingWake> {
    hg_writer: amla_vm_ringbuf::RingWriter<'ring>,
    gh_reader: amla_vm_ringbuf::RingReader<'ring>,
    link: Arc<AgentLink>,
    pending_tx: VecDeque<PendingFrame>,
    pending_tx_bytes: usize,
    /// True when the GH ring was recently near-full. Used to decide
    /// whether a backpressure kick is needed after draining.
    gh_high_water: bool,
    /// True after this run has notified the guest about currently pending
    /// HG ring bytes. Doorbells are edges, while the ring bytes themselves
    /// are durable mmap state, so this is only a per-run duplicate-kick guard.
    hg_pending_kicked: bool,
    /// Coalesced graceful-shutdown request that has not reached mmap yet.
    shutdown_pending: bool,
    /// Ring protocol health observed in this run. Corrupt rings are not valid
    /// durable snapshot boundaries.
    ring_health: RingHealth,
    last_hg_used: Option<u32>,
    last_gh_used: Option<u32>,
    /// Notify the peer after writing to the HG ring.
    wake: W,
}

impl<'ring, W: AgentRingWake> AgentRingState<'ring, W> {
    /// Create a new agent ring state.
    pub const fn new(
        hg_writer: amla_vm_ringbuf::RingWriter<'ring>,
        gh_reader: amla_vm_ringbuf::RingReader<'ring>,
        link: Arc<AgentLink>,
        wake: W,
    ) -> Self {
        Self {
            hg_writer,
            gh_reader,
            link,
            pending_tx: VecDeque::new(),
            pending_tx_bytes: 0,
            gh_high_water: false,
            hg_pending_kicked: false,
            shutdown_pending: false,
            ring_health: RingHealth::Clean,
            last_hg_used: None,
            last_gh_used: None,
            wake,
        }
    }

    /// Notify the guest to re-check mmap-backed host-to-guest state.
    ///
    /// The doorbell itself is volatile, so callers may use this after a run
    /// transition to reconstruct a lost edge. It does not mutate durable ring
    /// state.
    pub fn kick_peer(&self) {
        self.wake.wake_peer();
    }

    /// Process ring buffer: drain guest messages, drain host channels, flush TX.
    ///
    /// Called from the device loop's poll cycle. Returns `true` if
    /// any work was done (messages processed or flushed).
    ///
    pub fn process(&mut self) -> bool {
        let had_guest = self.drain_guest_messages();
        let had_host = self.drain_host_channels();
        // A CountedReceiver drain wakes the device loop but does not appear as
        // guest or host-channel work here, so resume checks must run on every
        // process wake.
        let resumed = self.check_resume();
        let flushed = self.flush_pending_tx();
        // Backpressure kick: only needed when the GH ring was nearly full.
        // If the guest's writes were failing due to a full ring, draining
        // frees space and the kick tells it to retry. Skip when the ring
        // has plenty of room — avoids a spurious VM exit per poll cycle.
        let woke_peer = if had_guest && !flushed && self.gh_high_water {
            self.gh_high_water = false;
            self.wake.wake_peer();
            true
        } else {
            false
        };
        let hg_used = match self.hg_writer.usage() {
            Ok(usage) => usage.used_bytes(),
            Err(e) => {
                log::error!("agent host-to-guest ring cursor error: {e}");
                self.ring_health = RingHealth::Corrupt;
                return had_guest || had_host || resumed || flushed;
            }
        };
        let gh_used = match self.gh_reader.usage() {
            Ok(usage) => usage.used_bytes(),
            Err(e) => {
                log::error!("agent guest-to-host ring cursor error: {e}");
                self.ring_health = RingHealth::Corrupt;
                return had_guest || had_host || resumed || flushed;
            }
        };
        if log::log_enabled!(log::Level::Trace)
            && (self.last_hg_used != Some(hg_used) || self.last_gh_used != Some(gh_used))
        {
            log::trace!(
                "agent ring usage hg_used={hg_used} gh_used={gh_used} pending_tx={} pending_tx_bytes={} had_guest={had_guest} had_host={had_host} flushed={flushed}",
                self.pending_tx.len(),
                self.pending_tx_bytes,
            );
            self.last_hg_used = Some(hg_used);
            self.last_gh_used = Some(gh_used);
        }
        if hg_used == 0 {
            self.hg_pending_kicked = false;
        } else if woke_peer {
            self.hg_pending_kicked = true;
        }
        let kicked_persisted_hg = !flushed && hg_used != 0 && !self.hg_pending_kicked;
        if kicked_persisted_hg {
            self.wake.wake_peer();
            self.hg_pending_kicked = true;
        }
        had_guest || had_host || resumed || flushed || kicked_persisted_hg
    }

    /// Return why this state is not safe to snapshot, if any.
    ///
    /// The host-to-guest ring itself is mmap-backed and can contain pending
    /// frames across a pause/spawn. `pending_tx` is host heap state, so `run()`
    /// must not return while it carries command progress that has not reached
    /// durable mmap state.
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn snapshot_quiescence_error(&self) -> Option<String> {
        if self.ring_health == RingHealth::Corrupt {
            return Some("agent ring protocol corruption observed".to_string());
        }
        if !self.pending_tx.is_empty() {
            return Some(format!(
                "{} host-to-guest frame(s), {} byte(s), still staged outside mmap",
                self.pending_tx.len(),
                self.pending_tx_bytes
            ));
        }

        let link = self.link.inner.lock();
        if !link.run_channels_closed {
            return Some("host run channels are still open".to_string());
        }
        if !link.exec_req_rx.is_empty() {
            return Some(format!(
                "{} exec request(s) still queued outside mmap",
                link.exec_req_rx.len()
            ));
        }
        if !link.exec_stdin_data_rx.is_empty() {
            return Some(format!(
                "{} exec stdin data frame(s) still queued outside mmap",
                link.exec_stdin_data_rx.len()
            ));
        }
        let active_sessions = link
            .exec_sessions
            .values()
            .filter(|session| !session.reattachable)
            .count();
        if active_sessions != 0 {
            return Some(format!(
                "{active_sessions} active exec session(s) still attached to host handles"
            ));
        }
        let paused_sessions = link
            .exec_sessions
            .values()
            .filter(|session| session.paused)
            .count();
        if paused_sessions != 0 {
            return Some(format!(
                "{paused_sessions} exec session(s) still paused for host output backpressure"
            ));
        }
        let host_buffered_sessions = link
            .exec_sessions
            .values()
            .filter(|session| {
                session.reattachable
                    && (session.stdout.pending_items() != 0
                        || session.stderr.pending_items() != 0
                        || session.stdout.pending_bytes() != 0
                        || session.stderr.pending_bytes() != 0)
            })
            .count();
        if host_buffered_sessions != 0 {
            return Some(format!(
                "{host_buffered_sessions} reattachable exec session(s) still have host-buffered output outside mmap"
            ));
        }
        let host_control_sessions = link
            .exec_sessions
            .values()
            .filter(|session| session.reattachable && session.control.has_pending_control())
            .count();
        if host_control_sessions != 0 {
            return Some(format!(
                "{host_control_sessions} reattachable exec session(s) still have host-side session control outside mmap"
            ));
        }

        None
    }

    /// Check paused sessions and resume any whose channels have drained.
    ///
    /// Called during each `process()` cycle. When a `CountedReceiver`
    /// consumes items, it marks the host notify pending and wakes the
    /// device loop and brings us here.
    fn check_resume(&mut self) -> bool {
        let link = self.link.inner.lock();
        let mut to_resume = Vec::new();
        for (&id, session) in &link.exec_sessions {
            if session.paused && Self::session_below_resume_threshold(session) {
                to_resume.push(id);
            }
        }
        drop(link);

        let mut resumed = false;
        for id in to_resume {
            if !self.queue_message(&HostMessage::ResumeExecOutput { id }) {
                break;
            }
            if let Some(session) = self.link.inner.lock().exec_sessions.get_mut(&id) {
                session.paused = false;
            }
            resumed = true;
        }
        resumed
    }

    fn update_guest_high_water(&mut self) -> bool {
        match self.gh_reader.usage() {
            Ok(usage) => {
                if usage.used_bytes() > usage.capacity() / 4 * 3 {
                    self.gh_high_water = true;
                }
                true
            }
            Err(e) => {
                log::error!("agent guest-to-host ring cursor error: {e}");
                self.ring_health = RingHealth::Corrupt;
                false
            }
        }
    }

    /// Read and dispatch all available messages from the guest→host ring.
    /// Returns true if any messages were processed.
    fn drain_guest_messages(&mut self) -> bool {
        // Check GH ring utilization before draining — if it was >75% full,
        // the guest may have been unable to write. Set high-water flag so
        // process() knows a backpressure kick is needed after we free space.
        if !self.update_guest_high_water() {
            return false;
        }
        let mut had_work = false;
        loop {
            let bytes = match self.gh_reader.try_peek() {
                Ok(Some(b)) => b,
                Ok(None) => break,
                Err(e) => {
                    log::warn!("agent ring read error: {e}");
                    self.ring_health = RingHealth::Corrupt;
                    break;
                }
            };

            // Fast path: guest-to-host raw binary messages.
            // Extract header + copy payload before advance (peek borrows reader).
            let raw_frame = match decode_guest_raw_frame(bytes) {
                Ok(frame) => frame,
                Err(e) => {
                    log::warn!("agent guest-to-host raw frame decode error: {e:?}");
                    self.ring_health = RingHealth::Corrupt;
                    if let Err(e) = self.gh_reader.advance() {
                        log::error!("advance after raw decode error: {e}");
                        break;
                    }
                    had_work = true;
                    continue;
                }
            };
            if let Some((tag, id, data)) = raw_frame {
                match self.handle_guest_raw_frame(tag, id, data) {
                    RawFrameProgress::Consumed => {
                        had_work = true;
                        continue;
                    }
                    RawFrameProgress::Blocked => break,
                }
            }

            // Guard against oversized structured messages. The ring allows
            // payloads up to 16 MiB (MAX_PAYLOAD_SIZE), but structured
            // protocol messages should never exceed MAX_MESSAGE_SIZE (64 KB).
            // A larger payload would cause postcard to allocate unbounded
            // Vecs/Strings on the host heap.
            if bytes.len() > amla_constants::protocol::MAX_MESSAGE_SIZE {
                log::warn!(
                    "agent ring: structured message too large ({} bytes, max {})",
                    bytes.len(),
                    amla_constants::protocol::MAX_MESSAGE_SIZE,
                );
                self.ring_health = RingHealth::Corrupt;
                if let Err(e) = self.gh_reader.advance() {
                    log::error!("advance after size reject: {e}");
                }
                had_work = true;
                continue;
            }

            let msg: GuestMessage = match postcard::from_bytes(bytes) {
                Ok(m) => m,
                Err(e) => {
                    log::warn!("agent ring decode error: {e}");
                    self.ring_health = RingHealth::Corrupt;
                    if let Err(e) = self.gh_reader.advance() {
                        log::error!("advance after decode error: {e}");
                    }
                    had_work = true;
                    continue;
                }
            };
            match msg {
                GuestMessage::ExecStdout { id, data } => {
                    let result = self.try_forward_exec_output(id, data, true);
                    if !Self::output_frame_consumed(result) {
                        break;
                    }
                    had_work = true;
                }
                GuestMessage::ExecStderr { id, data } => {
                    let result = self.try_forward_exec_output(id, data, false);
                    if !Self::output_frame_consumed(result) {
                        break;
                    }
                    had_work = true;
                }
                GuestMessage::ExecExit { id, .. } if self.session_is_reattachable(id) => {
                    log::trace!(
                        "agent ring leaving ExecExit id={id} in guest-to-host ring for reattach"
                    );
                    break;
                }
                other => {
                    if let Err(e) = self.gh_reader.advance() {
                        log::error!("ring advance error: {e}");
                        break;
                    }
                    had_work = true;
                    self.dispatch(other);
                    continue;
                }
            }
            if let Err(e) = self.gh_reader.advance() {
                log::error!("ring advance error: {e}");
                break;
            }
        }
        had_work
    }

    fn session_needs_pause(session: &ExecSession) -> bool {
        session.stdout.pending_bytes() >= PAUSE_THRESHOLD
            || session.stderr.pending_bytes() >= PAUSE_THRESHOLD
            || session.stdout.pending_items() >= OUTPUT_PAUSE_ITEM_THRESHOLD
            || session.stderr.pending_items() >= OUTPUT_PAUSE_ITEM_THRESHOLD
    }

    const fn output_frame_consumed(result: OutputForwardResult) -> bool {
        matches!(
            result,
            OutputForwardResult::Forwarded | OutputForwardResult::Dropped
        )
    }

    fn handle_guest_raw_frame(
        &mut self,
        tag: amla_constants::protocol::GuestRawTag,
        id: amla_constants::protocol::ExecId,
        data: Vec<u8>,
    ) -> RawFrameProgress {
        if matches!(
            tag,
            amla_constants::protocol::GuestRawTag::ExecStdout
                | amla_constants::protocol::GuestRawTag::ExecStderr
        ) {
            let is_stdout = tag == amla_constants::protocol::GuestRawTag::ExecStdout;
            let result = self.try_forward_exec_output(id, data, is_stdout);
            if !Self::output_frame_consumed(result) {
                return RawFrameProgress::Blocked;
            }
        } else {
            self.dispatch_raw(tag, id, data);
        }

        if let Err(e) = self.gh_reader.advance() {
            log::error!("ring advance error: {e}");
            return RawFrameProgress::Blocked;
        }
        RawFrameProgress::Consumed
    }

    fn session_below_resume_threshold(session: &ExecSession) -> bool {
        session.stdout.pending_bytes() <= RESUME_THRESHOLD
            && session.stderr.pending_bytes() <= RESUME_THRESHOLD
            && session.stdout.pending_items() <= OUTPUT_RESUME_ITEM_THRESHOLD
            && session.stderr.pending_items() <= OUTPUT_RESUME_ITEM_THRESHOLD
    }

    fn session_is_reattachable(&self, id: amla_constants::protocol::ExecId) -> bool {
        self.link
            .inner
            .lock()
            .exec_sessions
            .get(&id)
            .is_some_and(|session| session.reattachable)
    }

    /// Forward exec stdout or stderr data to the session's channel.
    ///
    /// Output queue saturation is retryable backpressure: the caller must not
    /// advance the guest-to-host ring frame when this returns
    /// [`OutputForwardResult::Backpressured`].
    fn try_forward_exec_output(
        &mut self,
        id: amla_constants::protocol::ExecId,
        data: Vec<u8>,
        is_stdout: bool,
    ) -> OutputForwardResult {
        let mut link = self.link.inner.lock();
        let Some(session) = link.exec_sessions.get_mut(&id) else {
            // Session removed by an earlier ExecExit — output arriving after
            // the exit event is dropped. This is a real loss of data; log so
            // it shows up in test failures and production debugging.
            let stream = if is_stdout { "stdout" } else { "stderr" };
            log::warn!(
                "forward_exec_output: no session for id={id} {stream} ({} bytes DROPPED)",
                data.len()
            );
            return OutputForwardResult::Dropped;
        };
        if session.reattachable {
            let stream = if is_stdout { "stdout" } else { "stderr" };
            log::trace!(
                "agent ring leaving {stream} id={id} bytes={} in guest-to-host ring for reattach",
                data.len()
            );
            return OutputForwardResult::Reattachable;
        }

        let result = if is_stdout {
            session.stdout.send(data)
        } else {
            session.stderr.send(data)
        };
        let mut pause = false;
        let mut backpressured = false;
        let mut forwarded = false;
        let mut dropped = false;
        match &result {
            Ok(()) => {
                forwarded = true;
                if !session.paused && Self::session_needs_pause(session) {
                    session.paused = true;
                    pause = true;
                }
            }
            Err(CountedSendError::Closed) => {
                dropped = true;
                let stream = if is_stdout { "stdout" } else { "stderr" };
                log::debug!("exec {id}: {stream} receiver dropped");
            }
            Err(CountedSendError::Full) => {
                backpressured = true;
                let stream = if is_stdout { "stdout" } else { "stderr" };
                log::debug!("exec {id}: {stream} output queue full; pausing guest output");
                if !session.paused {
                    session.paused = true;
                    pause = true;
                }
            }
            Err(CountedSendError::TooLarge { len, max }) => {
                dropped = true;
                let stream = if is_stdout { "stdout" } else { "stderr" };
                log::warn!(
                    "exec {id}: {stream} output frame too large ({len} bytes, max {max}); dropping frame"
                );
            }
        }

        drop(link);
        let pause_queued = if pause {
            self.queue_message(&HostMessage::PauseExecOutput { id })
        } else {
            false
        };

        if pause
            && !pause_queued
            && let Some(session) = self.link.inner.lock().exec_sessions.get_mut(&id)
        {
            session.paused = false;
        }

        if backpressured {
            OutputForwardResult::Backpressured
        } else if forwarded {
            OutputForwardResult::Forwarded
        } else {
            debug_assert!(dropped);
            OutputForwardResult::Dropped
        }
    }

    /// Dispatch a raw binary guest message (fast path, no postcard).
    fn dispatch_raw(
        &mut self,
        tag: amla_constants::protocol::GuestRawTag,
        id: amla_constants::protocol::ExecId,
        data: Vec<u8>,
    ) {
        match tag {
            amla_constants::protocol::GuestRawTag::ExecStdout => {
                self.try_forward_exec_output(id, data, true);
            }
            amla_constants::protocol::GuestRawTag::ExecStderr => {
                self.try_forward_exec_output(id, data, false);
            }
        }
    }

    /// Dispatch a guest message.
    fn dispatch(&mut self, msg: GuestMessage) {
        match msg {
            GuestMessage::Ready => {
                // Acknowledged implicitly — host sends Setup proactively.
            }
            GuestMessage::Ping => {
                self.queue_message(&HostMessage::Pong);
            }
            GuestMessage::Status { message } => {
                log::debug!("guest agent status: {message}");
                self.queue_message(&HostMessage::Ok);
            }
            GuestMessage::Custom { payload } => {
                log::debug!("custom message: {} bytes", payload.len());
                self.queue_message(&HostMessage::Ok);
            }
            GuestMessage::ExecStdout { id, data } => {
                self.try_forward_exec_output(id, data, true);
            }
            GuestMessage::ExecStderr { id, data } => {
                self.try_forward_exec_output(id, data, false);
            }
            GuestMessage::ExecExit { id, code } => {
                log::info!("dispatch: ExecExit id={id} code={code}");
                let mut link = self.link.inner.lock();
                if let Some(mut session) = link.exec_sessions.remove(&id) {
                    if let Some(tx) = session.exit.take()
                        && tx.send(code).is_err()
                    {
                        log::debug!("exec {id}: exit receiver dropped");
                    }
                } else {
                    log::warn!("ExecExit {id} with no active session");
                }
            }
            GuestMessage::CpuOnlineResult { count, error } => {
                // CPU hotplug is no longer supported. Log and discard.
                log::debug!("ignoring stale CpuOnlineResult: count={count}, error={error:?}");
            }
            GuestMessage::MemoryPressure {
                level,
                available_kb,
                total_kb,
            } => {
                log::info!(
                    "memory pressure: level={level}, available={available_kb}KB, total={total_kb}KB"
                );
                // Forward to VmHandle for observability. Best-effort: if no
                // observer is subscribed, the event is dropped.
                let link = self.link.inner.lock();
                if link
                    .memory_pressure_tx
                    .try_send(MemoryPressureEvent {
                        level,
                        available_kb,
                        total_kb,
                    })
                    .is_err()
                {
                    log::debug!("memory_pressure_tx: no subscriber");
                }
            }
        }
    }

    /// Drain host-side channels (exec requests, stdin, control).
    /// Returns true if any work was done.
    #[allow(clippy::too_many_lines)]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn drain_host_channels(&mut self) -> bool {
        let mut had_work = false;

        let shutdown = {
            let mut link = self.link.inner.lock();
            link.shutdown_rx.try_recv().is_ok()
        };
        if shutdown {
            self.shutdown_pending = true;
            had_work = true;
        }
        if self.shutdown_pending && self.queue_message(&HostMessage::Shutdown) {
            self.shutdown_pending = false;
        }

        loop {
            if !self.has_pending_capacity_for(amla_constants::protocol::MAX_MESSAGE_SIZE) {
                break;
            }
            let req = {
                let mut link = self.link.inner.lock();
                link.exec_req_rx.try_recv().ok()
            };
            let Some(req) = req else {
                break;
            };
            had_work = true;

            let id = req.id;
            if self.try_queue_frame(PendingFrame::Serialized(req.payload)) {
                log::trace!("agent ring staged Exec request id={id}");
                let mut link = self.link.inner.lock();
                let old = link.exec_sessions.insert(
                    id,
                    ExecSession {
                        stdout: req.stdout_tx,
                        stderr: req.stderr_tx,
                        exit: Some(req.exit_tx),
                        reattachable: false,
                        control: req.control,
                        paused: false,
                    },
                );
                debug_assert!(old.is_none(), "duplicate exec session id {id}");
                if req.accepted_tx.send(()).is_err() {
                    log::debug!("exec request accepted after caller dropped id={id}");
                }
            } else {
                log::warn!("dropping exec request because host-to-guest pending queue is full");
            }
        }

        had_work |= self.drain_coalesced_session_resizes();

        let max_stdin_frame = amla_constants::protocol::RAW_HEADER_SIZE + EXEC_STDIN_CHUNK_MAX;
        loop {
            if !self.has_pending_capacity_for(max_stdin_frame) {
                break;
            }
            let frame = {
                let mut link = self.link.inner.lock();
                link.exec_stdin_data_rx.try_recv().ok()
            };
            let Some(frame) = frame else {
                break;
            };
            had_work = true;

            let (id, data, credit) = frame.into_parts();
            if !self.link.inner.lock().exec_sessions.contains_key(&id) {
                log::debug!("dropping stdin for inactive exec {id}");
                drop(credit);
                continue;
            }
            let byte_len = data.len();
            let header = amla_constants::protocol::host_raw_header(
                amla_constants::protocol::HostRawTag::ExecStdin,
                id,
            );
            if self.try_queue_frame(PendingFrame::Raw {
                header,
                data,
                _credit: Some(credit),
            }) {
                log::trace!("agent ring staged ExecStdin id={id} bytes={byte_len}");
            } else {
                log::warn!("dropping stdin for exec {id}: host-to-guest pending queue full");
            }
        }

        if self.link.inner.lock().exec_stdin_data_rx.is_empty() {
            had_work |= self.drain_coalesced_session_eofs();
        }

        had_work
    }

    fn session_controls(&self) -> Vec<(amla_constants::protocol::ExecId, Arc<SessionControl>)> {
        let link = self.link.inner.lock();
        link.exec_sessions
            .iter()
            .map(|(&id, session)| (id, Arc::clone(&session.control)))
            .collect::<Vec<(amla_constants::protocol::ExecId, Arc<SessionControl>)>>()
    }

    fn drain_coalesced_session_resizes(&mut self) -> bool {
        let mut had_work = false;
        for (id, control) in self.session_controls() {
            if let Some((rows, cols)) = control.pending_resize() {
                if !self.queue_message(&HostMessage::SessionResize { id, rows, cols }) {
                    return had_work;
                }
                log::trace!("agent ring staged SessionResize id={id} rows={rows} cols={cols}");
                control.clear_resize_if_current(rows, cols);
                had_work = true;
            }
        }

        had_work
    }

    fn drain_coalesced_session_eofs(&mut self) -> bool {
        let mut had_work = false;
        for (id, control) in self.session_controls() {
            if control.eof_requested() {
                if !self.queue_message(&HostMessage::ExecStdinEof { id }) {
                    return had_work;
                }
                log::trace!("agent ring staged ExecStdinEof id={id}");
                control.clear_eof_requested();
                had_work = true;
            }
        }

        had_work
    }

    fn has_pending_capacity_for(&self, bytes: usize) -> bool {
        self.pending_tx.len() < PENDING_TX_FRAME_CAPACITY
            && self
                .pending_tx_bytes
                .checked_add(bytes)
                .is_some_and(|next| next <= PENDING_TX_BYTE_CAPACITY)
    }

    fn try_queue_frame(&mut self, frame: PendingFrame) -> bool {
        let len = frame.wire_len();
        if !self.has_pending_capacity_for(len) {
            return false;
        }
        self.pending_tx_bytes += len;
        self.pending_tx.push_back(frame);
        true
    }

    fn pop_pending_frame(&mut self) {
        if let Some(frame) = self.pending_tx.pop_front() {
            self.pending_tx_bytes = self.pending_tx_bytes.saturating_sub(frame.wire_len());
        }
    }

    /// Serialize a host message and add to the pending TX queue.
    fn queue_message(&mut self, msg: &HostMessage) -> bool {
        match postcard::to_allocvec(msg) {
            Ok(payload) => {
                if self.try_queue_frame(PendingFrame::Serialized(payload)) {
                    true
                } else {
                    log::warn!("dropping host message because host-to-guest pending queue is full");
                    false
                }
            }
            Err(e) => {
                log::error!("failed to serialize host message: {e}");
                false
            }
        }
    }

    /// Flush pending TX messages to the host→guest ring.
    ///
    /// Writes as many messages as will fit, then wakes the peer once if
    /// any data was written. Returns true if any messages were flushed.
    fn flush_pending_tx(&mut self) -> bool {
        let mut flushed = false;
        while let Some(frame) = self.pending_tx.front() {
            let summary =
                log::log_enabled!(log::Level::Trace).then(|| pending_frame_summary(frame));
            let result = match frame {
                PendingFrame::Serialized(payload) => self.hg_writer.try_write(payload),
                PendingFrame::Raw { header, data, .. } => {
                    self.hg_writer.try_write_parts(&[header, data])
                }
            };
            match result {
                Ok(true) => {
                    if let Some(summary) = summary {
                        log::trace!("agent ring flushed {summary}");
                    }
                    self.pop_pending_frame();
                    flushed = true;
                }
                Ok(false) => {
                    if let Some(summary) = summary {
                        log::trace!(
                            "agent ring could not flush {summary}: host-to-guest ring full"
                        );
                    }
                    break;
                }
                Err(e) => {
                    log::error!("ring write error: {e}");
                    self.ring_health = RingHealth::Corrupt;
                    break;
                }
            }
        }
        if flushed {
            self.hg_pending_kicked = true;
            self.wake.wake_peer();
        }
        flushed
    }
}

#[cfg(test)]
mod tests {
    use std::alloc::{Layout, alloc_zeroed, dealloc};
    use std::ptr::NonNull;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::agent::{ByteBudget, ExecStdinData};

    use super::*;

    const TEST_RING_SIZE: usize = 4096;
    const LARGE_TEST_RING_SIZE: usize = 128 * 1024;

    fn id(raw: u32) -> amla_constants::protocol::ExecId {
        amla_constants::protocol::ExecId::new(raw).unwrap()
    }

    struct TestRing {
        ptr: NonNull<u8>,
        layout: Layout,
    }

    struct LargeTestRing {
        ptr: NonNull<u8>,
        layout: Layout,
    }

    fn allocate_ring<const SIZE: usize>() -> (NonNull<u8>, Layout) {
        let layout =
            Layout::from_size_align(amla_vm_ringbuf::RingBuffer::<SIZE>::TOTAL_SIZE, 64).unwrap();
        // SAFETY: layout has non-zero size and 64-byte alignment.
        let ptr = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        (ptr, layout)
    }

    impl TestRing {
        fn new() -> Self {
            let (ptr, layout) = allocate_ring::<TEST_RING_SIZE>();
            Self { ptr, layout }
        }
    }

    impl LargeTestRing {
        fn new() -> Self {
            let (ptr, layout) = allocate_ring::<LARGE_TEST_RING_SIZE>();
            Self { ptr, layout }
        }
    }

    impl Drop for TestRing {
        fn drop(&mut self) {
            // SAFETY: ptr/layout were returned by alloc_zeroed in TestRing::new.
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
        }
    }

    impl Drop for LargeTestRing {
        fn drop(&mut self) {
            // SAFETY: ptr/layout were returned by alloc_zeroed in LargeTestRing::new.
            unsafe { dealloc(self.ptr.as_ptr(), self.layout) };
        }
    }

    fn attach_test_ring(
        ring_mem: &TestRing,
    ) -> amla_vm_ringbuf::RingBufferHandle<'_, TEST_RING_SIZE> {
        // SAFETY: TestRing provides aligned storage for exactly this
        // RingBuffer layout.
        unsafe {
            amla_vm_ringbuf::RingBufferHandle::<TEST_RING_SIZE>::attach(
                ring_mem.ptr,
                ring_mem.layout.size(),
            )
        }
        .unwrap()
    }

    fn attach_large_test_ring(
        ring_mem: &LargeTestRing,
    ) -> amla_vm_ringbuf::RingBufferHandle<'_, LARGE_TEST_RING_SIZE> {
        // SAFETY: LargeTestRing provides aligned storage for exactly this
        // RingBuffer layout.
        unsafe {
            amla_vm_ringbuf::RingBufferHandle::<LARGE_TEST_RING_SIZE>::attach(
                ring_mem.ptr,
                ring_mem.layout.size(),
            )
        }
        .unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn process_resumes_paused_exec_after_counted_receiver_drain_without_other_work() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let (mut stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));

        {
            let mut inner = link.inner.lock();
            let session = inner.exec_sessions.get_mut(&id(7)).unwrap();
            session.paused = true;
            session
                .stdout
                .send(vec![b'x'; RESUME_THRESHOLD + 1])
                .unwrap();
        }

        assert_eq!(
            stdout_rx.recv().await,
            Some(vec![b'x'; RESUME_THRESHOLD + 1])
        );

        let wake_count = Arc::new(AtomicUsize::new(0));
        let wake_count_clone = Arc::clone(&wake_count);
        let mut ring = AgentRingState::new(
            host.to_guest,
            host.from_guest,
            Arc::clone(&link),
            move || {
                wake_count_clone.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert!(ring.process(), "resume should count as ring process work");
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        assert!(
            !link.inner.lock().exec_sessions.get(&id(7)).unwrap().paused,
            "session should be marked resumed"
        );

        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("resume message should be written to host-to-guest ring");
        let msg: HostMessage = postcard::from_bytes(payload).unwrap();
        assert!(matches!(msg, HostMessage::ResumeExecOutput { id: actual } if actual == id(7)));
        guest.from_host.advance().unwrap();

        assert!(
            !ring.process(),
            "subsequent idle process should not queue a duplicate resume"
        );
        assert!(guest.from_host.try_peek().unwrap().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn output_backpressure_stalls_ring_frame_instead_of_terminating() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let (mut stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));
        {
            let mut inner = link.inner.lock();
            let session = inner.exec_sessions.get_mut(&id(7)).unwrap();
            for _ in 0..OUTPUT_PAUSE_ITEM_THRESHOLD {
                session.stdout.send(vec![b'x']).unwrap();
            }
            assert_eq!(session.stdout.pending_items(), OUTPUT_PAUSE_ITEM_THRESHOLD);
        }

        let header = amla_constants::protocol::guest_raw_header(
            amla_constants::protocol::GuestRawTag::ExecStdout,
            id(7),
        );
        assert!(guest.to_host.try_write_parts(&[&header, b"held"]).unwrap());

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        assert!(
            ring.gh_reader.has_peeked(),
            "output frame must remain in the GH ring while host output is full"
        );
        assert!(link.inner.lock().exec_sessions.get(&id(7)).unwrap().paused);

        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("pause message should be sent");
        let msg: HostMessage = postcard::from_bytes(payload).unwrap();
        assert!(matches!(msg, HostMessage::PauseExecOutput { id: actual } if actual == id(7)));
        guest.from_host.advance().unwrap();
        assert!(
            guest.from_host.try_peek().unwrap().is_none(),
            "output backpressure must not enqueue terminate/detach"
        );

        for _ in 0..=(OUTPUT_PAUSE_ITEM_THRESHOLD - OUTPUT_RESUME_ITEM_THRESHOLD) {
            assert_eq!(stdout_rx.recv().await, Some(vec![b'x']));
        }

        assert!(ring.process());
        assert!(
            !ring.gh_reader.has_peeked(),
            "held output frame should advance once receiver credit returns"
        );

        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("resume message should be sent");
        let msg: HostMessage = postcard::from_bytes(payload).unwrap();
        assert!(matches!(msg, HostMessage::ResumeExecOutput { id: actual } if actual == id(7)));

        for _ in 0..(OUTPUT_RESUME_ITEM_THRESHOLD - 1) {
            assert_eq!(stdout_rx.recv().await, Some(vec![b'x']));
        }
        assert_eq!(stdout_rx.recv().await, Some(b"held".to_vec()));
    }

    #[test]
    fn malformed_guest_raw_frame_is_consumed_and_marks_ring_corrupt() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let guest = guest_ready.split_guest();
        let link = Arc::new(AgentLink::new());

        let wrong_direction_raw_header = [0x80, 0, 0, 0, 0];
        assert!(
            guest
                .to_host
                .try_write_parts(&[&wrong_direction_raw_header])
                .unwrap()
        );

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        assert!(
            ring.gh_reader.try_peek().unwrap().is_none(),
            "malformed raw frame must be dropped instead of poisoning the ring head",
        );
        assert!(
            ring.snapshot_quiescence_error()
                .unwrap()
                .contains("protocol corruption"),
        );
    }

    #[test]
    fn malformed_structured_guest_frame_is_consumed_and_marks_ring_corrupt() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let guest = guest_ready.split_guest();
        let link = Arc::new(AgentLink::new());

        assert!(guest.to_host.try_write(&[0x7f]).unwrap());

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        assert!(
            ring.gh_reader.try_peek().unwrap().is_none(),
            "malformed structured frame must not poison the ring head",
        );
        assert!(
            ring.snapshot_quiescence_error()
                .unwrap()
                .contains("protocol corruption"),
        );
    }

    #[test]
    fn oversized_structured_guest_frame_is_consumed_and_marks_ring_corrupt() {
        let ring_mem = LargeTestRing::new();
        let host_ready = attach_large_test_ring(&ring_mem).init();
        let guest_ready = attach_large_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let guest = guest_ready.split_guest();
        let link = Arc::new(AgentLink::new());

        let oversized = vec![0x7f; amla_constants::protocol::MAX_MESSAGE_SIZE + 1];
        assert!(guest.to_host.try_write(&oversized).unwrap());

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        assert!(
            ring.gh_reader.try_peek().unwrap().is_none(),
            "oversized structured frame must not poison the ring head",
        );
        assert!(
            ring.snapshot_quiescence_error()
                .unwrap()
                .contains("protocol corruption"),
        );
    }

    #[test]
    fn process_kicks_existing_host_to_guest_ring_bytes() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        assert!(host.to_guest.try_write(b"persisted").unwrap());

        let wake_count = Arc::new(AtomicUsize::new(0));
        let wake_count_clone = Arc::clone(&wake_count);
        let mut ring = AgentRingState::new(
            host.to_guest,
            host.from_guest,
            Arc::new(AgentLink::new()),
            move || {
                wake_count_clone.fetch_add(1, Ordering::Relaxed);
            },
        );

        assert!(
            ring.process(),
            "existing host-to-guest mmap bytes should generate a peer kick"
        );
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        assert!(
            !ring.process(),
            "unchanged host-to-guest bytes should not self-wake repeatedly"
        );
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        assert_eq!(guest.from_host.try_peek().unwrap().unwrap(), b"persisted");
        guest.from_host.advance().unwrap();

        assert!(
            !ring.process(),
            "empty host-to-guest ring should reset the duplicate-kick guard"
        );
        assert!(ring.queue_message(&HostMessage::Pong));
        assert!(ring.process());
        assert_eq!(wake_count.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn explicit_peer_kick_reconstructs_volatile_doorbell() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let host = host_ready.split_host();

        let wake_count = Arc::new(AtomicUsize::new(0));
        let wake_count_clone = Arc::clone(&wake_count);
        let ring = AgentRingState::new(
            host.to_guest,
            host.from_guest,
            Arc::new(AgentLink::new()),
            move || {
                wake_count_clone.fetch_add(1, Ordering::Relaxed);
            },
        );

        ring.kick_peer();
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn coalesced_eof_is_drained_without_stdin_channel_credit() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        control.request_eof();

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("EOF message should be sent");
        let msg: HostMessage = postcard::from_bytes(payload).unwrap();
        assert!(matches!(msg, HostMessage::ExecStdinEof { id: actual } if actual == id(7)));
        assert!(!control.eof_requested());
    }

    #[test]
    fn coalesced_resize_is_drained_without_stdin_channel_capacity() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        control.request_resize(24, 80);
        control.request_resize(40, 120);

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        let payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("resize message should be sent");
        let msg: HostMessage = postcard::from_bytes(payload).unwrap();
        assert!(matches!(
            msg,
            HostMessage::SessionResize {
                id: actual,
                rows: 40,
                cols: 120
            } if actual == id(7)
        ));
        assert_eq!(control.pending_resize(), None);
    }

    #[test]
    fn coalesced_resize_bypasses_queued_stdin_data() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        ch.exec_stdin_data_tx
            .try_send(ExecStdinData::new(
                id(7),
                b"input".to_vec(),
                ByteBudget::new(16).try_acquire(5).unwrap(),
            ))
            .unwrap();
        control.request_resize(40, 120);

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        let resize_payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("resize message should be sent before stdin data");
        let msg: HostMessage = postcard::from_bytes(resize_payload).unwrap();
        assert!(matches!(
            msg,
            HostMessage::SessionResize {
                id: actual,
                rows: 40,
                cols: 120
            } if actual == id(7)
        ));
        guest.from_host.advance().unwrap();

        let stdin_payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("stdin data should still be delivered");
        let frame = amla_constants::protocol::try_decode_host_raw(stdin_payload)
            .unwrap()
            .unwrap();
        assert_eq!(frame.tag, amla_constants::protocol::HostRawTag::ExecStdin);
        assert_eq!(frame.id, id(7));
        assert_eq!(frame.data, b"input");
        assert_eq!(control.pending_resize(), None);
    }

    #[test]
    fn queued_stdin_for_inactive_session_is_not_sent_to_guest() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        ch.exec_stdin_data_tx
            .try_send(ExecStdinData::new(
                id(7),
                b"late".to_vec(),
                ByteBudget::new(16).try_acquire(4).unwrap(),
            ))
            .unwrap();

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        assert!(
            guest.from_host.try_peek().unwrap().is_none(),
            "stdin for inactive sessions must not reach the guest",
        );
    }

    #[test]
    fn coalesced_eof_stays_after_queued_stdin_data() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();

        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        ch.exec_stdin_data_tx
            .try_send(ExecStdinData::new(
                id(7),
                b"input".to_vec(),
                ByteBudget::new(16).try_acquire(5).unwrap(),
            ))
            .unwrap();
        control.request_eof();

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(ring.process());
        let stdin_payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("stdin data should be sent before EOF");
        let frame = amla_constants::protocol::try_decode_host_raw(stdin_payload)
            .unwrap()
            .unwrap();
        assert_eq!(frame.tag, amla_constants::protocol::HostRawTag::ExecStdin);
        assert_eq!(frame.id, id(7));
        assert_eq!(frame.data, b"input");
        guest.from_host.advance().unwrap();

        let eof_payload = guest
            .from_host
            .try_peek()
            .unwrap()
            .expect("EOF should be sent after stdin data");
        let msg: HostMessage = postcard::from_bytes(eof_payload).unwrap();
        assert!(matches!(msg, HostMessage::ExecStdinEof { id: actual } if actual == id(7)));
        assert!(!control.eof_requested());
    }

    #[test]
    fn snapshot_quiescence_rejects_pending_host_frames_outside_mmap() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let host = host_ready.split_host();

        let mut ring = AgentRingState::new(
            host.to_guest,
            host.from_guest,
            Arc::new(AgentLink::new()),
            || {},
        );
        assert!(ring.queue_message(&HostMessage::Pong));

        let detail = ring.snapshot_quiescence_error().unwrap();
        assert!(detail.contains("outside mmap"), "{detail}");

        assert!(ring.process());
        assert!(ring.snapshot_quiescence_error().is_none());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reattachable_output_stays_in_guest_to_host_ring_until_attached() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let mut guest = guest_ready.split_guest();
        let link = Arc::new(AgentLink::new());

        let (stdout_rx, stderr_rx, exit_rx, _control) = link.register_session(id(7));
        link.mark_session_reattachable(id(7)).unwrap();
        drop(stdout_rx);
        drop(stderr_rx);
        drop(exit_rx);

        let header = amla_constants::protocol::guest_raw_header(
            amla_constants::protocol::GuestRawTag::ExecStdout,
            id(7),
        );
        assert!(guest.to_host.try_write_parts(&[&header, b"held"]).unwrap());

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(
            !ring.process(),
            "reattachable output has no transient recipient and should remain durable mmap state"
        );
        assert!(ring.gh_reader.has_peeked());
        assert!(guest.from_host.try_peek().unwrap().is_none());
        assert!(ring.snapshot_quiescence_error().is_none());

        let _ch = link.connect();
        let (mut stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));
        assert!(ring.process());
        assert!(!ring.gh_reader.has_peeked());
        assert_eq!(stdout_rx.recv().await, Some(b"held".to_vec()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn reattachable_exit_stays_in_guest_to_host_ring_until_attached() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let guest_ready = attach_test_ring(&ring_mem).validate().unwrap();
        let host = host_ready.split_host();
        let guest = guest_ready.split_guest();
        let link = Arc::new(AgentLink::new());

        let (stdout_rx, stderr_rx, exit_rx, _control) = link.register_session(id(7));
        link.mark_session_reattachable(id(7)).unwrap();
        drop(stdout_rx);
        drop(stderr_rx);
        drop(exit_rx);

        let payload = postcard::to_allocvec(&GuestMessage::ExecExit {
            id: id(7),
            code: 42,
        })
        .unwrap();
        assert!(guest.to_host.try_write(&payload).unwrap());

        let mut ring =
            AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        assert!(
            !ring.process(),
            "reattachable exit has no transient recipient and should remain durable mmap state"
        );
        assert!(ring.gh_reader.has_peeked());
        assert!(ring.snapshot_quiescence_error().is_none());

        let _ch = link.connect();
        let (_stdout_rx, _stderr_rx, exit_rx, _control) = link.register_session(id(7));
        assert!(ring.process());
        assert!(!ring.gh_reader.has_peeked());
        assert_eq!(exit_rx.await.unwrap(), 42);
        assert!(!link.inner.lock().exec_sessions.contains_key(&id(7)));
    }

    #[test]
    fn snapshot_quiescence_rejects_active_sessions_but_allows_reattachable() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let host = host_ready.split_host();
        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));

        let ring = AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        let detail = ring.snapshot_quiescence_error().unwrap();
        assert!(detail.contains("active exec session"), "{detail}");

        link.mark_session_reattachable(id(7)).unwrap();
        assert!(ring.snapshot_quiescence_error().is_none());
    }

    #[test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn snapshot_quiescence_rejects_reattachable_host_buffered_output() {
        let ring_mem = TestRing::new();
        let host_ready = attach_test_ring(&ring_mem).init();
        let host = host_ready.split_host();
        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, _control) = link.register_session(id(7));
        {
            let mut inner = link.inner.lock();
            let session = inner.exec_sessions.get_mut(&id(7)).unwrap();
            session.reattachable = true;
            session.stdout.send(b"buffered".to_vec()).unwrap();
        }

        let ring = AgentRingState::new(host.to_guest, host.from_guest, Arc::clone(&link), || {});

        let detail = ring.snapshot_quiescence_error().unwrap();
        assert!(
            detail.contains("host-buffered output outside mmap"),
            "{detail}"
        );
    }
}
