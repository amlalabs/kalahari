// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Command execution types — public API for running commands in the guest.
//!
//! [`CommandExecution`] provides streaming I/O with a running guest process.
//! [`StdinWriter`] is a clonable handle for concurrent stdin writes.
//! [`OutputEvent`] and [`CollectedOutput`] provide output consumption.

use std::fmt;
use std::sync::Arc;

use amla_constants::protocol::ExecId;
use tokio::sync::{mpsc, oneshot};

use super::{
    AgentLink, ByteBudget, CountedReceiver, EXEC_STDIN_CHUNK_MAX, EXEC_STDIN_PENDING_BYTES,
    ExecError, ExecStdinData, HostNotify, SessionControl,
};

/// Default total stdout+stderr bytes captured by [`CommandExecution::collect_output()`].
pub const DEFAULT_COLLECT_OUTPUT_LIMIT: usize = 1024 * 1024;

/// A running command in the guest with streaming I/O.
///
/// Stdin operations ([`write_stdin`](Self::write_stdin),
/// [`close_stdin`](Self::close_stdin), [`resize`](Self::resize)) are
/// delegated to an internal [`StdinWriter`]. Use
/// [`stdin_writer()`](Self::stdin_writer) to get a clonable handle for
/// concurrent use.
pub struct CommandExecution {
    stdin: StdinWriter,
    agent_link: Arc<AgentLink>,
    stdout_rx: Option<CountedReceiver>,
    stderr_rx: Option<CountedReceiver>,
    exit_rx: Option<oneshot::Receiver<i32>>,
    detached: bool,
    /// Exit code received from the guest, held until stdout/stderr are
    /// drained. The guest can send `ExecExit` before the host has drained
    /// the last `ExecStdout`/`ExecStderr` chunks; if `recv_output` returned
    /// `Exit` the moment it observed the exit oneshot, those buffered
    /// stdout/stderr bytes would be dropped on the floor.
    pending_exit: Option<i32>,
}

pub(super) struct CommandExecutionParts {
    pub(super) stdin_data_tx: mpsc::Sender<ExecStdinData>,
    pub(super) host_notify: HostNotify,
    pub(super) agent_link: Arc<AgentLink>,
    pub(super) control: Arc<SessionControl>,
    pub(super) stdout_rx: CountedReceiver,
    pub(super) stderr_rx: CountedReceiver,
    pub(super) exit_rx: oneshot::Receiver<i32>,
}

impl CommandExecution {
    /// Create a new `CommandExecution` (crate-internal).
    pub(super) fn new(id: ExecId, parts: CommandExecutionParts) -> Self {
        let agent_link = Arc::clone(&parts.agent_link);
        Self {
            stdin: StdinWriter {
                id,
                stdin_data_tx: parts.stdin_data_tx,
                stdin_budget: ByteBudget::new(EXEC_STDIN_PENDING_BYTES),
                control: parts.control,
                host_notify: parts.host_notify,
                agent_link,
            },
            agent_link: parts.agent_link,
            stdout_rx: Some(parts.stdout_rx),
            stderr_rx: Some(parts.stderr_rx),
            exit_rx: Some(parts.exit_rx),
            detached: false,
            pending_exit: None,
        }
    }

    /// Get a clonable stdin writer for this command.
    ///
    /// The returned writer can be sent to another thread/task, allowing
    /// concurrent stdin writes and stdout reads (required for streaming).
    /// The writer also supports [`resize()`](StdinWriter::resize) for PTY
    /// sessions.
    pub fn stdin_writer(&self) -> StdinWriter {
        self.stdin.clone()
    }

    /// Write data to the process's stdin, waiting for bounded queue credit if
    /// needed.
    ///
    /// Accepts `&[u8]`, `&str`, `Vec<u8>`, byte literals (`b"..."`), or
    /// any type that implements `AsRef<[u8]>`.
    pub async fn write_stdin(&self, data: impl AsRef<[u8]>) -> Result<(), ExecError> {
        self.stdin.write(data).await
    }

    /// Close the process's stdin (signals EOF to the guest).
    pub async fn close_stdin(&self) -> Result<(), ExecError> {
        self.stdin.close().await
    }

    /// Resize the PTY window (only valid for PTY sessions).
    ///
    /// Sends `SessionResize` to the guest which calls `ioctl(TIOCSWINSZ)`.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<(), ExecError> {
        self.stdin.resize(rows, cols).await
    }

    /// Take the stdout receiver for concurrent use in `select!`.
    ///
    /// After calling this, [`recv_stdout()`](Self::recv_stdout) will return `None`.
    /// Use this when you need to read stdout and stderr concurrently.
    ///
    /// Returns `None` if already taken.
    pub const fn take_stdout(&mut self) -> Option<CountedReceiver> {
        self.stdout_rx.take()
    }

    /// Take the stderr receiver for concurrent use in `select!`.
    ///
    /// After calling this, [`recv_stderr()`](Self::recv_stderr) will return `None`.
    /// Use this when you need to read stdout and stderr concurrently.
    ///
    /// Returns `None` if already taken.
    pub const fn take_stderr(&mut self) -> Option<CountedReceiver> {
        self.stderr_rx.take()
    }

    /// Receive the next stdout chunk.
    ///
    /// Returns `None` when the channel closes (process exited) or if the
    /// receiver was taken via [`take_stdout()`](Self::take_stdout).
    pub async fn recv_stdout(&mut self) -> Option<Vec<u8>> {
        self.stdout_rx.as_mut()?.recv().await
    }

    /// Receive the next stderr chunk.
    ///
    /// Returns `None` when the channel closes (process exited) or if the
    /// receiver was taken via [`take_stderr()`](Self::take_stderr).
    pub async fn recv_stderr(&mut self) -> Option<Vec<u8>> {
        self.stderr_rx.as_mut()?.recv().await
    }

    /// Take the exit receiver for concurrent use.
    ///
    /// After calling this, [`wait()`](Self::wait) and
    /// [`recv_output()`](Self::recv_output) will return
    /// `Err(Disconnected)` / `None` for the exit event.
    ///
    /// Use this when you need to call [`resize()`](Self::resize)
    /// concurrently with awaiting process exit — `resize` takes
    /// `&self` while `wait` takes `&mut self`, so they conflict.
    /// Splitting off the exit receiver resolves this:
    ///
    /// ```ignore
    /// let exit_rx = cmd.take_exit().unwrap();
    /// // Now cmd can be used for resize(&self) while exit_rx is awaited elsewhere
    /// ```
    ///
    /// Returns `None` if already taken.
    pub const fn take_exit(&mut self) -> Option<oneshot::Receiver<i32>> {
        self.exit_rx.take()
    }

    /// Wait for the process to exit. Returns exit code.
    ///
    /// Returns `Err(Disconnected)` if the exit receiver was already taken
    /// via [`take_exit()`](Self::take_exit).
    pub async fn wait(&mut self) -> Result<i32, ExecError> {
        let rx = self.exit_rx.as_mut().ok_or(ExecError::Disconnected)?;
        rx.await.map_err(|_| ExecError::Disconnected)
    }

    /// Receive the next output event (stdout, stderr, or exit).
    ///
    /// Returns events in arrival order, draining stdout and stderr concurrently.
    /// The final event is always [`OutputEvent::Exit`] with the exit code.
    /// Returns `None` after the exit event has been delivered, or if the guest
    /// agent disconnects.
    ///
    /// This is the preferred way to consume command output — callers get a
    /// single stream instead of manually orchestrating `tokio::select!` over
    /// separate channels.
    pub async fn recv_output(&mut self) -> Option<OutputEvent> {
        loop {
            let stdout_live = self.stdout_rx.is_some();
            let stderr_live = self.stderr_rx.is_some();
            let exit_live = self.exit_rx.is_some();

            if !stdout_live && !stderr_live {
                // Both streams drained — emit exit code (held from earlier
                // observation, or read now if exit_rx is still live).
                if let Some(code) = self.pending_exit.take() {
                    return Some(OutputEvent::Exit(code));
                }
                return match self.exit_rx.take() {
                    Some(rx) => rx.await.ok().map(OutputEvent::Exit),
                    None => None,
                };
            }

            tokio::select! {
                data = async { self.stdout_rx.as_mut()?.recv().await }, if stdout_live => {
                    match data {
                        Some(bytes) => return Some(OutputEvent::Stdout(bytes)),
                        None => { self.stdout_rx = None; }
                    }
                }
                data = async { self.stderr_rx.as_mut()?.recv().await }, if stderr_live => {
                    match data {
                        Some(bytes) => return Some(OutputEvent::Stderr(bytes)),
                        None => { self.stderr_rx = None; }
                    }
                }
                // Also poll exit — prevents deadlock when stderr is unused
                // (PTY sessions merge stderr into stdout, so stderr_rx
                // blocks forever until the ExecExit drops the sender).
                //
                // When exit fires we MUST keep stdout/stderr alive and
                // continue the loop. The guest can send `ExecExit` before
                // the host has dispatched the final `ExecStdout`/`ExecStderr`
                // chunks, so dropping those receivers here would silently
                // discard buffered output. Instead we stash the code in
                // `pending_exit` and let stdout/stderr drain naturally —
                // their senders close when the dispatcher removes the
                // session, signaling None on the receivers, after which we
                // hit the "both streams drained" branch above and emit Exit.
                result = async {
                    match self.exit_rx.as_mut() {
                        Some(rx) => rx.await,
                        None => std::future::pending().await,
                    }
                }, if exit_live => {
                    self.exit_rx = None;
                    match result {
                        Ok(c) => { self.pending_exit = Some(c); }
                        Err(_) => return None,
                    }
                }
            }
        }
    }

    /// Close stdin, drain stdout and stderr concurrently with a bounded
    /// default capture limit, then wait for exit.
    ///
    /// Returns captured output and the exit code. This is the safe way to run
    /// a command to completion when bounded output is expected — draining both
    /// streams concurrently avoids deadlocks when the OS pipe buffer fills up
    /// on one stream while the other is being read.
    ///
    /// Returns `Err` if the guest agent disconnects before the process exits.
    /// Returns [`ExecError::OutputLimitExceeded`] if stdout and stderr together
    /// exceed `DEFAULT_COLLECT_OUTPUT_LIMIT`. Use
    /// [`collect_output_with_limit`](Self::collect_output_with_limit) for an
    /// explicit limit, or the streaming APIs for long-running output.
    pub async fn collect_output(&mut self) -> Result<CollectedOutput, ExecError> {
        self.collect_output_with_limit(DEFAULT_COLLECT_OUTPUT_LIMIT)
            .await
    }

    /// Close stdin, drain stdout and stderr concurrently up to `limit` bytes,
    /// then wait for exit.
    ///
    /// The limit applies to the total captured stdout plus stderr bytes. If a
    /// chunk would exceed the limit, collection stops and returns
    /// [`ExecError::OutputLimitExceeded`].
    pub async fn collect_output_with_limit(
        &mut self,
        limit: usize,
    ) -> Result<CollectedOutput, ExecError> {
        // Best-effort close: EOF is a coalesced per-session control so it is
        // not lost behind a full stdin data channel.
        if let Err(e) = self.stdin.close().await {
            log::debug!("collect_output: close_stdin failed (guest gone?): {e}");
        }

        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut captured = 0usize;

        while let Some(event) = self.recv_output().await {
            match event {
                OutputEvent::Stdout(bytes) => {
                    captured = add_captured_output(captured, bytes.len(), limit)?;
                    stdout.extend_from_slice(&bytes);
                }
                OutputEvent::Stderr(bytes) => {
                    captured = add_captured_output(captured, bytes.len(), limit)?;
                    stderr.extend_from_slice(&bytes);
                }
                OutputEvent::Exit(code) => {
                    return Ok(CollectedOutput {
                        stdout,
                        stderr,
                        exit_code: code,
                    });
                }
            }
        }

        Err(ExecError::Disconnected)
    }
}

const fn add_captured_output(
    captured: usize,
    chunk_len: usize,
    limit: usize,
) -> Result<usize, ExecError> {
    let Some(attempted) = captured.checked_add(chunk_len) else {
        return Err(ExecError::OutputLimitExceeded {
            attempted: usize::MAX,
            limit,
        });
    };
    if attempted > limit {
        return Err(ExecError::OutputLimitExceeded { attempted, limit });
    }
    Ok(attempted)
}

impl CommandExecution {
    /// Convert into a lightweight handle that survives freeze/spawn.
    ///
    /// Consumes `self` without sending `StdinEof`, so the guest process
    /// stays alive across a zygote fork. Pass the handle to
    /// [`VmHandle::attach()`](super::VmHandle::attach) on the cloned VM.
    ///
    /// This only succeeds while the session has no stdout, stderr, or exit
    /// state buffered in transient host channels. On failure, the returned
    /// [`IntoHandleError`] contains the original command so the caller can
    /// keep draining it.
    pub fn into_handle(mut self) -> Result<CommandExecutionHandle, IntoHandleError> {
        let id = self.stdin.id();
        log::trace!("primitive command id={id}: into_handle requested");
        if let Err(source) = self.agent_link.mark_session_reattachable(id) {
            log::trace!("primitive command id={id}: into_handle rejected: {source}");
            return Err(IntoHandleError {
                command: Box::new(self),
                source,
            });
        }
        drop(self.stdout_rx.take());
        drop(self.stderr_rx.take());
        drop(self.exit_rx.take());
        self.detached = true;
        log::trace!("primitive command id={id}: into_handle succeeded");
        Ok(CommandExecutionHandle { id })
    }
}

impl Drop for CommandExecution {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        // Send StdinEof so the guest process sees EOF and doesn't hang.
        // Harmless if already closed — guest ignores duplicate StdinEof.
        self.stdin.send_eof();
    }
}

/// Error returned when a command cannot be converted into a reattach handle.
///
/// The original command is returned so callers can keep draining output or
/// wait for exit instead of losing transient host-side state.
pub struct IntoHandleError {
    command: Box<CommandExecution>,
    source: ExecError,
}

impl IntoHandleError {
    /// Recover the command whose conversion failed.
    pub fn into_command(self) -> CommandExecution {
        *self.command
    }

    /// Return the reason conversion failed.
    pub const fn source(&self) -> &ExecError {
        &self.source
    }
}

impl fmt::Debug for IntoHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntoHandleError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl fmt::Display for IntoHandleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for IntoHandleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Lightweight handle representing a running guest command.
///
/// Created by [`CommandExecution::into_handle()`] to transfer a session
/// across a freeze/spawn boundary without triggering `StdinEof`.
/// Pass to [`VmHandle::attach()`](super::VmHandle::attach) on the cloned
/// VM to reconnect I/O channels.
#[derive(Clone, Debug)]
pub struct CommandExecutionHandle {
    pub(super) id: ExecId,
}

impl CommandExecutionHandle {
    /// Get the host-assigned session ID.
    pub const fn id(&self) -> ExecId {
        self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(raw: u32) -> ExecId {
        ExecId::new(raw).unwrap()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn into_handle_failure_returns_command_for_drain() {
        let link = Arc::new(AgentLink::new());
        let (stdout_rx, stderr_rx, exit_rx, control) = link.register_session(id(7));
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
        let (stdin_tx, _stdin_rx) = mpsc::channel(1);
        let cmd = CommandExecution::new(
            id(7),
            CommandExecutionParts {
                stdin_data_tx: stdin_tx,
                host_notify: link.host_notifier(),
                agent_link: Arc::clone(&link),
                control,
                stdout_rx,
                stderr_rx,
                exit_rx,
            },
        );

        let mut cmd = match cmd.into_handle() {
            Ok(_) => panic!("command with host-buffered output must not become reattachable"),
            Err(err) => {
                assert!(matches!(err.source(), ExecError::NotReattachable { .. }));
                err.into_command()
            }
        };

        assert_eq!(cmd.recv_stdout().await, Some(b"buffered".to_vec()));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resize_does_not_need_stdin_channel_capacity() {
        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        let (stdin_tx, mut stdin_rx) = mpsc::channel(1);
        stdin_tx
            .try_send(ExecStdinData::new(
                id(7),
                vec![1],
                ByteBudget::new(16).try_acquire(1).unwrap(),
            ))
            .unwrap();
        let writer = StdinWriter {
            id: id(7),
            stdin_data_tx: stdin_tx,
            stdin_budget: ByteBudget::new(EXEC_STDIN_PENDING_BYTES),
            control: Arc::clone(&control),
            host_notify: HostNotify::new(),
            agent_link: Arc::clone(&link),
        };

        writer.resize(24, 80).await.unwrap();
        writer.resize(40, 120).await.unwrap();

        assert_eq!(control.pending_resize(), Some((40, 120)));
        assert!(stdin_rx.try_recv().is_ok());
        assert!(stdin_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn resize_rejects_zero_dimensions_without_queuing_control() {
        let link = Arc::new(AgentLink::new());
        let (_stdout_rx, _stderr_rx, _exit_rx, control) = link.register_session(id(7));
        let (stdin_tx, _stdin_rx) = mpsc::channel(1);
        let writer = StdinWriter {
            id: id(7),
            stdin_data_tx: stdin_tx,
            stdin_budget: ByteBudget::new(EXEC_STDIN_PENDING_BYTES),
            control: Arc::clone(&control),
            host_notify: HostNotify::new(),
            agent_link: Arc::clone(&link),
        };

        let err = writer.resize(0, 80).await.unwrap_err().to_string();
        assert!(err.contains("greater than zero"), "{err}");
        let err = writer.resize(24, 0).await.unwrap_err().to_string();
        assert!(err.contains("greater than zero"), "{err}");
        assert_eq!(control.pending_resize(), None);
    }

    #[tokio::test(flavor = "current_thread")]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn stdin_and_resize_reject_after_session_exit() {
        let link = Arc::new(AgentLink::new());
        let (stdout_rx, stderr_rx, exit_rx, control) = link.register_session(id(7));
        let (stdin_tx, mut stdin_rx) = mpsc::channel(1);
        let mut cmd = CommandExecution::new(
            id(7),
            CommandExecutionParts {
                stdin_data_tx: stdin_tx,
                host_notify: link.host_notifier(),
                agent_link: Arc::clone(&link),
                control,
                stdout_rx,
                stderr_rx,
                exit_rx,
            },
        );
        {
            let mut inner = link.inner.lock();
            let mut session = inner.exec_sessions.remove(&id(7)).unwrap();
            session.exit.take().unwrap().send(0).unwrap();
        }

        assert_eq!(cmd.wait().await.unwrap(), 0);
        assert!(matches!(
            cmd.write_stdin("late").await,
            Err(ExecError::Disconnected)
        ));
        assert!(matches!(
            cmd.resize(24, 80).await,
            Err(ExecError::Disconnected)
        ));
        assert!(matches!(
            cmd.close_stdin().await,
            Err(ExecError::Disconnected)
        ));
        assert!(stdin_rx.try_recv().is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn collect_output_with_limit_rejects_excess_output() {
        let link = Arc::new(AgentLink::new());
        let (stdout_rx, stderr_rx, exit_rx, control) = link.register_session(id(7));
        {
            let inner = link.inner.lock();
            let session = inner.exec_sessions.get(&id(7)).unwrap();
            session.stdout.send(b"12345".to_vec()).unwrap();
            session.stderr.send(b"67890".to_vec()).unwrap();
        }
        {
            let mut inner = link.inner.lock();
            let mut session = inner.exec_sessions.remove(&id(7)).unwrap();
            session.exit.take().unwrap().send(0).unwrap();
        }
        let (stdin_tx, _stdin_rx) = mpsc::channel(1);
        let mut cmd = CommandExecution::new(
            id(7),
            CommandExecutionParts {
                stdin_data_tx: stdin_tx,
                host_notify: link.host_notifier(),
                agent_link: Arc::clone(&link),
                control,
                stdout_rx,
                stderr_rx,
                exit_rx,
            },
        );

        let err = cmd.collect_output_with_limit(9).await.unwrap_err();
        assert!(matches!(
            err,
            ExecError::OutputLimitExceeded {
                attempted: 10,
                limit: 9
            }
        ));
    }
}

/// A single output event from a running command.
///
/// Yielded by [`CommandExecution::recv_output()`]. This provides a unified
/// stream of stdout, stderr, and exit events — callers don't need to manually
/// orchestrate `tokio::select!` over separate channels.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OutputEvent {
    /// Stdout data chunk.
    Stdout(Vec<u8>),
    /// Stderr data chunk.
    Stderr(Vec<u8>),
    /// Process exited with the given code. This is always the last event.
    Exit(i32),
}

/// Output collected from a completed command.
///
/// Returned by [`CommandExecution::collect_output()`].
#[derive(Debug, Clone)]
pub struct CollectedOutput {
    /// Captured stdout bytes.
    pub stdout: Vec<u8>,
    /// Captured stderr bytes.
    pub stderr: Vec<u8>,
    /// Process exit code.
    pub exit_code: i32,
}

impl CollectedOutput {
    /// Stdout as a UTF-8 string, replacing invalid bytes with U+FFFD.
    #[must_use]
    pub fn stdout_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stdout)
    }

    /// Stderr as a UTF-8 string, replacing invalid bytes with U+FFFD.
    #[must_use]
    pub fn stderr_str(&self) -> std::borrow::Cow<'_, str> {
        String::from_utf8_lossy(&self.stderr)
    }
}

/// A clonable, `Send` handle for writing to a command's stdin.
///
/// Obtained via [`CommandExecution::stdin_writer()`]. Can be moved to another
/// thread or task to write stdin concurrently with stdout reads.
///
/// Supports all stdin operations: [`write()`](Self::write),
/// [`close()`](Self::close), and [`resize()`](Self::resize) (PTY only).
#[derive(Clone)]
pub struct StdinWriter {
    id: ExecId,
    stdin_data_tx: mpsc::Sender<ExecStdinData>,
    stdin_budget: ByteBudget,
    control: Arc<SessionControl>,
    host_notify: HostNotify,
    agent_link: Arc<AgentLink>,
}

impl StdinWriter {
    fn ensure_session_active(&self) -> Result<(), ExecError> {
        if self.stdin_data_tx.is_closed() || !self.agent_link.has_session(self.id) {
            return Err(ExecError::Disconnected);
        }
        Ok(())
    }

    /// Send a stdin message asynchronously, waiting for bounded channel credit.
    async fn send_stdin_data(&self, msg: ExecStdinData) -> Result<(), ExecError> {
        self.ensure_session_active()?;
        log::trace!(
            "primitive command id={}: queueing stdin data bytes={}",
            self.id,
            msg.len()
        );
        self.stdin_data_tx
            .send(msg)
            .await
            .map_err(|_| ExecError::Disconnected)?;
        self.host_notify.notify();
        log::trace!(
            "primitive command id={}: queued stdin data and notified agent ring",
            self.id
        );
        Ok(())
    }

    async fn data_message(&self, data: Vec<u8>) -> Result<ExecStdinData, ExecError> {
        if data.len() > EXEC_STDIN_CHUNK_MAX {
            return Err(ExecError::MessageTooLarge {
                len: data.len(),
                max: EXEC_STDIN_CHUNK_MAX,
            });
        }
        let credit = self.stdin_budget.acquire(data.len()).await?;
        Ok(ExecStdinData::new(self.id, data, credit))
    }

    /// Get the host-assigned session ID.
    pub const fn id(&self) -> ExecId {
        self.id
    }

    /// Write data to the process's stdin, waiting for bounded queue credit if
    /// needed.
    ///
    /// Accepts `&[u8]`, `&str`, `Vec<u8>`, byte literals (`b"..."`), or
    /// any type that implements `AsRef<[u8]>`.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> Result<(), ExecError> {
        self.write_owned(data.as_ref().to_vec()).await
    }

    /// Write pre-owned data to stdin without copying, waiting for bounded
    /// queue credit if needed.
    pub async fn write_owned(&self, data: Vec<u8>) -> Result<(), ExecError> {
        self.ensure_session_active()?;
        let msg = self.data_message(data).await?;
        self.send_stdin_data(msg).await
    }

    /// Close the process's stdin (signals EOF).
    pub async fn close(&self) -> Result<(), ExecError> {
        self.ensure_session_active()?;
        self.send_eof();
        Ok(())
    }

    /// Resize the PTY window (only valid for PTY sessions).
    ///
    /// Sends `SessionResize` to the guest which calls `ioctl(TIOCSWINSZ)`.
    pub async fn resize(&self, rows: u16, cols: u16) -> Result<(), ExecError> {
        if rows == 0 || cols == 0 {
            return Err(ExecError::InvalidCommand {
                reason: "PTY resize dimensions must be greater than zero",
            });
        }
        self.ensure_session_active()?;
        self.control.request_resize(rows, cols);
        self.host_notify.notify();
        Ok(())
    }

    /// Send EOF without consuming self (used by `CommandExecution::close_stdin`
    /// and `Drop`).
    fn send_eof(&self) {
        log::trace!("primitive command id={}: queueing stdin EOF", self.id);
        self.control.request_eof();
        self.host_notify.notify();
    }
}
