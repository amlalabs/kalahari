// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! [`VmHandle`] — user-facing VM control during `run()`.
//!
//! Uses typestate to enforce ordering: the `run()` closure receives
//! `VmHandle<Paused>`. Call [`attach()`](VmHandle::attach) to queue
//! sessions from a forked parent, then [`start()`](VmHandle::start) to
//! register them atomically and transition to `VmHandle<Running>`.

use std::collections::HashMap;
use std::marker::PhantomData;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use amla_constants::protocol::{ExecId, HostMessage};
use tokio::sync::{mpsc, oneshot};

use crate::shared_state::{StartGate, VmStatus};

use super::command::{CommandExecution, CommandExecutionHandle, CommandExecutionParts};
use super::{
    AgentLink, ExecChannels, ExecError, ExecRequest, ExecStdinData, HostNotify,
    MemoryPressureEvent, counted_channel,
};

/// A validated argument for guest exec requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecArg(String);

impl ExecArg {
    /// Validate and create a guest exec argument.
    ///
    /// Arguments must be nonempty and must not contain NUL or other control
    /// characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ExecError> {
        let value = value.into();
        if value.is_empty() {
            return Err(ExecError::InvalidCommand {
                reason: "argv entries must be nonempty",
            });
        }
        validate_text("argv entries", &value)?;
        Ok(Self(value))
    }

    /// Borrow the argument as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated guest working directory.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestCwd(String);

impl GuestCwd {
    /// Use the guest agent's current working directory.
    #[must_use]
    pub const fn inherit() -> Self {
        Self(String::new())
    }

    /// Validate and create an absolute guest working directory.
    ///
    /// Empty strings mean inherit. Nonempty paths must be canonical absolute
    /// guest paths and must not contain NUL or other control characters.
    pub fn new(value: impl Into<String>) -> Result<Self, ExecError> {
        let value = value.into();
        if value.is_empty() {
            return Ok(Self::inherit());
        }
        crate::config::validate_guest_absolute_path(&value).map_err(|_| {
            ExecError::InvalidCommand {
                reason: "cwd must be empty or a canonical absolute path",
            }
        })?;
        Ok(Self(value))
    }

    /// Borrow the working directory as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Default for GuestCwd {
    fn default() -> Self {
        Self::inherit()
    }
}

/// A validated guest environment variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestEnvVar {
    key: String,
    value: String,
}

impl GuestEnvVar {
    /// Validate and create an environment variable from a key and value.
    ///
    /// Keys must be shell-style identifiers. Values may be empty but must not
    /// contain NUL or other control characters.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Result<Self, ExecError> {
        let key = key.into();
        let value = value.into();
        validate_env_key(&key)?;
        validate_text("env values", &value)?;
        Ok(Self { key, value })
    }

    /// Validate and create an environment variable from a `KEY=VALUE` entry.
    pub fn from_entry(entry: impl AsRef<str>) -> Result<Self, ExecError> {
        let entry = entry.as_ref();
        let Some((key, value)) = entry.split_once('=') else {
            return Err(ExecError::InvalidCommand {
                reason: "env entries must be KEY=VALUE",
            });
        };
        Self::new(key, value)
    }

    /// Environment variable key.
    #[must_use]
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Environment variable value.
    #[must_use]
    pub fn value(&self) -> &str {
        &self.value
    }

    fn protocol_entry(&self) -> String {
        format!("{}={}", self.key, self.value)
    }
}

/// A validated guest command request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandSpec {
    argv: Vec<ExecArg>,
    env: Vec<GuestEnvVar>,
    cwd: GuestCwd,
}

impl CommandSpec {
    /// Validate and create a command spec with no explicit environment or cwd.
    pub fn new(argv: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, ExecError> {
        let argv = validate_argv(argv)?;
        Ok(Self {
            argv,
            env: Vec::new(),
            cwd: GuestCwd::inherit(),
        })
    }

    /// Add validated environment entries to the command spec.
    pub fn with_env(
        mut self,
        env: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> Result<Self, ExecError> {
        for entry in env {
            self.env.push(GuestEnvVar::from_entry(entry)?);
        }
        Ok(self)
    }

    /// Set the guest working directory.
    pub fn with_cwd(mut self, cwd: impl Into<String>) -> Result<Self, ExecError> {
        self.cwd = GuestCwd::new(cwd)?;
        Ok(self)
    }

    /// Validated command arguments.
    #[must_use]
    pub fn argv(&self) -> &[ExecArg] {
        &self.argv
    }

    /// Validated environment variables.
    #[must_use]
    pub fn env(&self) -> &[GuestEnvVar] {
        &self.env
    }

    /// Validated working directory.
    #[must_use]
    pub const fn cwd(&self) -> &GuestCwd {
        &self.cwd
    }

    fn from_parts(argv: Vec<String>, env: Vec<String>, cwd: String) -> Result<Self, ExecError> {
        let argv = validate_argv(argv)?;
        let env = env
            .into_iter()
            .map(GuestEnvVar::from_entry)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            argv,
            env,
            cwd: GuestCwd::new(cwd)?,
        })
    }

    fn argv_protocol(&self) -> Vec<String> {
        self.argv.iter().map(|arg| arg.0.clone()).collect()
    }

    fn env_protocol(&self) -> Vec<String> {
        self.env.iter().map(GuestEnvVar::protocol_entry).collect()
    }

    fn payload(&self, id: ExecId, pty: bool) -> Result<Vec<u8>, ExecError> {
        let argv = self.argv_protocol();
        let env = self.env_protocol();
        let cwd = self.cwd.0.clone();
        let msg = if pty {
            HostMessage::ExecPty { id, argv, env, cwd }
        } else {
            HostMessage::Exec { id, argv, env, cwd }
        };
        let payload = postcard::to_allocvec(&msg).map_err(|_| ExecError::InvalidCommand {
            reason: "failed to serialize command request",
        })?;
        if payload.len() > amla_constants::protocol::MAX_MESSAGE_SIZE {
            return Err(ExecError::MessageTooLarge {
                len: payload.len(),
                max: amla_constants::protocol::MAX_MESSAGE_SIZE,
            });
        }
        Ok(payload)
    }
}

fn validate_argv(
    argv: impl IntoIterator<Item = impl AsRef<str>>,
) -> Result<Vec<ExecArg>, ExecError> {
    let argv = argv
        .into_iter()
        .map(|arg| ExecArg::new(arg.as_ref().to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if argv.is_empty() {
        return Err(ExecError::InvalidCommand {
            reason: "argv must contain at least one argument",
        });
    }
    Ok(argv)
}

fn validate_text(field: &'static str, value: &str) -> Result<(), ExecError> {
    if value.chars().any(char::is_control) {
        return Err(ExecError::InvalidCommand {
            reason: match field {
                "argv entries" => "argv entries must not contain control characters",
                "cwd" => "cwd must not contain control characters",
                "env values" => "env values must not contain control characters",
                _ => "command strings must not contain control characters",
            },
        });
    }
    Ok(())
}

fn validate_env_key(key: &str) -> Result<(), ExecError> {
    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return Err(ExecError::InvalidCommand {
            reason: "env keys must be nonempty",
        });
    };
    if !(first == '_' || first.is_ascii_alphabetic()) {
        return Err(ExecError::InvalidCommand {
            reason: "env keys must start with '_' or an ASCII letter",
        });
    }
    if !chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric()) {
        return Err(ExecError::InvalidCommand {
            reason: "env keys must contain only ASCII letters, digits, or '_'",
        });
    }
    Ok(())
}

/// `VmHandle` state before ring processing begins.
///
/// Accumulates [`attach()`](VmHandle::attach) calls. All pending sessions
/// are registered atomically when [`start()`](VmHandle::start) is called.
pub struct Paused {
    start_gate: Arc<StartGate>,
    pending_attaches: Vec<CommandExecutionHandle>,
}

/// `VmHandle` state after [`start()`](VmHandle::start).
///
/// Holds any sessions attached during the `Paused` phase and provides
/// command execution and VM control methods.
pub struct Running {
    attached: HashMap<ExecId, CommandExecution>,
}

/// Builder for [`VmHandle::exec()`] and [`VmHandle::exec_pty()`].
///
/// Call `.await` to send the command, or chain `.env(...)` / `.cwd(...)` first.
pub struct ExecBuilder<'a, 'dev> {
    handle: &'a VmHandle<'dev, Running>,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    pty: bool,
}

impl ExecBuilder<'_, '_> {
    /// Add environment variables for the command (`KEY=VALUE` strings).
    ///
    /// Multiple calls extend the list (they do not replace prior values).
    #[must_use]
    pub fn env(mut self, env: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.env
            .extend(env.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Set the working directory for the child process.
    ///
    /// The guest agent calls `chdir(cwd)` before spawning. If empty (default),
    /// the child inherits the agent's working directory (`/`).
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }
}

impl<'a> std::future::IntoFuture for ExecBuilder<'a, '_> {
    type Output = Result<CommandExecution, ExecError>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(
            self.handle
                .exec_inner(self.argv, self.env, self.cwd, self.pty),
        )
    }
}

/// Handle for interacting with a VM during `run()`.
///
/// The type parameter `S` tracks the handle's phase:
/// - [`Paused`]: pre-start — can [`attach()`](Self::attach) forked sessions
/// - [`Running`]: post-start — can [`exec()`](Self::exec) commands and
///   retrieve attached sessions via [`take_attached()`](Self::take_attached)
///
/// The `'dev` lifetime prevents escape via `tokio::spawn` (which requires `'static`).
pub struct VmHandle<'dev, S = Running> {
    exec_req_tx: mpsc::Sender<ExecRequest>,
    exec_stdin_data_tx: mpsc::Sender<ExecStdinData>,
    memory_pressure_rx: mpsc::Receiver<MemoryPressureEvent>,
    host_notify: HostNotify,
    agent_link: Arc<AgentLink>,
    status: Arc<VmStatus>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    _not_static: PhantomData<&'dev ()>,
    state: S,
}

impl<'dev> VmHandle<'dev, Paused> {
    /// Create a new paused `VmHandle` (crate-internal).
    pub(crate) fn new(
        ch: ExecChannels,
        status: Arc<VmStatus>,
        agent_link: Arc<AgentLink>,
        start_gate: Arc<StartGate>,
    ) -> Self {
        Self {
            exec_req_tx: ch.exec_req_tx,
            exec_stdin_data_tx: ch.exec_stdin_data_tx,
            memory_pressure_rx: ch.memory_pressure_rx,
            host_notify: ch.host_notify,
            agent_link,
            status,
            shutdown_tx: Some(ch.shutdown_tx),
            _not_static: PhantomData,
            state: Paused {
                start_gate,
                pending_attaches: Vec::new(),
            },
        }
    }

    /// Queue a session from a forked parent for attachment.
    ///
    /// The session is registered in the agent backend when
    /// [`start()`](Self::start) is called. Retrieve the resulting
    /// `CommandExecution` via [`take_attached()`](VmHandle::take_attached).
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidCommand`] if the same command handle was
    /// already queued.
    pub fn attach(&mut self, handle: CommandExecutionHandle) -> Result<(), ExecError> {
        if self
            .state
            .pending_attaches
            .iter()
            .any(|pending| pending.id() == handle.id())
        {
            return Err(ExecError::InvalidCommand {
                reason: "command handle already attached",
            });
        }
        self.state.pending_attaches.push(handle);
        Ok(())
    }

    /// Register all pending attaches and transition to [`Running`].
    ///
    /// Each queued [`CommandExecutionHandle`] gets a fresh set of I/O
    /// channels registered in the agent backend. The resulting
    /// `CommandExecution` objects are stored on `Running` and can be
    /// retrieved by ID via [`take_attached()`](VmHandle::take_attached).
    pub fn start(self) -> VmHandle<'dev, Running> {
        let mut attached = HashMap::new();
        for h in &self.state.pending_attaches {
            let (stdout_rx, stderr_rx, exit_rx, control) = self.agent_link.register_session(h.id());
            attached.insert(
                h.id(),
                CommandExecution::new(
                    h.id(),
                    CommandExecutionParts {
                        stdin_data_tx: self.exec_stdin_data_tx.clone(),
                        host_notify: self.host_notify.clone(),
                        agent_link: Arc::clone(&self.agent_link),
                        control,
                        stdout_rx,
                        stderr_rx,
                        exit_rx,
                    },
                ),
            );
        }
        self.state.start_gate.start();

        VmHandle {
            exec_req_tx: self.exec_req_tx,
            exec_stdin_data_tx: self.exec_stdin_data_tx,
            memory_pressure_rx: self.memory_pressure_rx,
            host_notify: self.host_notify,
            agent_link: self.agent_link,
            status: self.status,
            shutdown_tx: self.shutdown_tx,
            _not_static: PhantomData,
            state: Running { attached },
        }
    }
}

impl<'dev> VmHandle<'dev, Running> {
    /// Take an attached session by ID.
    ///
    /// Returns the `CommandExecution` that was registered during
    /// [`start()`](VmHandle::start) for the given session ID, or `None`
    /// if no session with that ID was attached (or already taken).
    pub fn take_attached(&mut self, id: ExecId) -> Option<CommandExecution> {
        self.state.attached.remove(&id)
    }

    /// Start a command in the guest with piped stdin/stdout/stderr.
    ///
    /// Returns an [`ExecBuilder`] — call `.await` to send, or chain
    /// `.env(...)` first to set environment variables.
    ///
    /// ```ignore
    /// vm.exec(["echo", "hello"]).await
    /// vm.exec(["sh", "-c", "cmd"]).env(["FOO=bar"]).await
    /// ```
    pub fn exec(&self, argv: impl IntoIterator<Item = impl AsRef<str>>) -> ExecBuilder<'_, 'dev> {
        ExecBuilder {
            handle: self,
            argv: argv.into_iter().map(|s| s.as_ref().to_string()).collect(),
            env: Vec::new(),
            cwd: String::new(),
            pty: false,
        }
    }

    /// Start a validated command spec in the guest with piped stdin/stdout/stderr.
    ///
    /// The spec is still serialized and size-checked before it is enqueued.
    pub fn exec_spec(&self, spec: CommandSpec) -> ExecBuilder<'_, 'dev> {
        let argv = spec.argv_protocol();
        let env = spec.env_protocol();
        let cwd = spec.cwd.0;
        ExecBuilder {
            handle: self,
            argv,
            env,
            cwd,
            pty: false,
        }
    }

    /// Start a command in the guest with a PTY (pseudo-terminal).
    ///
    /// Like [`exec()`](Self::exec) but the guest allocates a PTY
    /// instead of pipes. The child process sees `isatty() == true`.
    /// Use [`CommandExecution::resize()`] to change the terminal size.
    pub fn exec_pty(
        &self,
        argv: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> ExecBuilder<'_, 'dev> {
        ExecBuilder {
            handle: self,
            argv: argv.into_iter().map(|s| s.as_ref().to_string()).collect(),
            env: Vec::new(),
            cwd: String::new(),
            pty: true,
        }
    }

    /// Start a validated command spec in the guest with a PTY.
    ///
    /// Like [`exec_spec()`](Self::exec_spec) but the guest allocates a PTY
    /// instead of pipes.
    pub fn exec_pty_spec(&self, spec: CommandSpec) -> ExecBuilder<'_, 'dev> {
        let argv = spec.argv_protocol();
        let env = spec.env_protocol();
        let cwd = spec.cwd.0;
        ExecBuilder {
            handle: self,
            argv,
            env,
            cwd,
            pty: true,
        }
    }

    async fn exec_inner(
        &self,
        argv: Vec<String>,
        env: Vec<String>,
        cwd: String,
        pty: bool,
    ) -> Result<CommandExecution, ExecError> {
        if self.status.has_exited() {
            return Err(ExecError::Disconnected);
        }
        let spec = CommandSpec::from_parts(argv, env, cwd)?;
        let id = self.agent_link.alloc_exec_id()?;
        let payload = spec.payload(id, pty)?;

        let (stdout_tx, stdout_rx) = counted_channel(self.host_notify.clone());
        let (stderr_tx, stderr_rx) = counted_channel(self.host_notify.clone());
        let (exit_tx, exit_rx) = oneshot::channel();
        let (accepted_tx, accepted_rx) = oneshot::channel();
        let control = Arc::new(super::SessionControl::new());

        log::debug!(
            "exec: sending id={id} {:?} pty={pty} cwd={:?}",
            spec.argv,
            spec.cwd
        );
        let req = ExecRequest {
            id,
            payload,
            stdout_tx,
            stderr_tx,
            exit_tx,
            control: Arc::clone(&control),
            accepted_tx,
        };
        tokio::select! {
            biased;

            () = self.status.wait_for_exit() => return Err(ExecError::Disconnected),
            result = self.exec_req_tx.send(req) => {
                result.map_err(|_| ExecError::Disconnected)?;
            }
        }
        self.host_notify.notify();

        tokio::select! {
            accepted = accepted_rx => accepted.map_err(|_| ExecError::Disconnected)?,
            () = self.status.wait_for_exit() => return Err(ExecError::Disconnected),
        };
        log::info!("exec: host assigned id={id} pty={pty}");

        Ok(CommandExecution::new(
            id,
            CommandExecutionParts {
                stdin_data_tx: self.exec_stdin_data_tx.clone(),
                host_notify: self.host_notify.clone(),
                agent_link: Arc::clone(&self.agent_link),
                control,
                stdout_rx,
                stderr_rx,
                exit_rx,
            },
        ))
    }

    /// Request a graceful guest shutdown and wait for the VM to exit.
    ///
    /// Sends `HostMessage::Shutdown` to the guest agent, which calls
    /// `sync()` and triggers a VM exit. Waits until all vCPUs have exited.
    ///
    /// Can only be called once — subsequent calls return immediately
    /// (the shutdown signal has already been sent).
    pub async fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            if tx.send(()).is_err() {
                log::debug!("shutdown: receiver already dropped (vm exited)");
            }
            self.host_notify.notify();
        }
        self.status.wait_for_exit().await;
    }

    /// Check if the guest has exited.
    pub fn has_exited(&self) -> bool {
        self.status.has_exited()
    }

    /// Wait until the guest exits.
    pub async fn wait_for_exit(&self) {
        self.status.wait_for_exit().await;
    }

    /// Receive the next memory pressure event from the guest PSI monitor.
    ///
    /// Returns `None` when the guest agent disconnects (VM exited or
    /// channel closed). Use this in a `tokio::select!` loop alongside
    /// other VM events.
    pub async fn recv_memory_pressure(&mut self) -> Option<MemoryPressureEvent> {
        self.memory_pressure_rx.recv().await
    }

    /// Poll the next memory pressure event from the guest PSI monitor.
    ///
    /// This is equivalent to [`recv_memory_pressure()`](Self::recv_memory_pressure), but
    /// lets schedulers multiplex memory pressure with other VM events without
    /// spawning a helper task.
    pub fn poll_recv_memory_pressure(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<MemoryPressureEvent>> {
        Pin::new(&mut self.memory_pressure_rx).poll_recv(cx)
    }

    /// Return a `'static` exec-only handle.
    ///
    /// The returned handle can call `exec()` but not device-specific ops.
    /// Use this when you need to send the handle across task boundaries
    /// (e.g. via a channel or `tokio::spawn`).
    pub fn into_exec_only(self) -> VmHandle<'static, Running> {
        VmHandle {
            exec_req_tx: self.exec_req_tx,
            exec_stdin_data_tx: self.exec_stdin_data_tx,
            memory_pressure_rx: self.memory_pressure_rx,
            host_notify: self.host_notify,
            agent_link: self.agent_link,
            status: self.status,
            shutdown_tx: self.shutdown_tx,
            _not_static: PhantomData,
            state: Running {
                attached: self.state.attached,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::AgentLink;

    fn started_handle(
        ch: ExecChannels,
        status: Arc<VmStatus>,
        link: Arc<AgentLink>,
    ) -> VmHandle<'static, Running> {
        VmHandle::new(ch, status, link, Arc::new(StartGate::new())).start()
    }

    /// `exec()` on a VM whose exit flag is already set returns
    /// `Disconnected` immediately without enqueueing host-side exec state.
    #[tokio::test]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn test_exec_on_exited_vm_returns_disconnected() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());

        // Set the exit flag BEFORE calling exec.
        status.set_exited();

        let handle = started_handle(ch, status, Arc::clone(&link));

        // Must return Disconnected quickly, not hang.
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            handle.exec(["echo", "dead"]),
        )
        .await
        .expect("exec() hung on exited VM — deadlock");

        assert!(matches!(result, Err(ExecError::Disconnected)));
        let inner = link.inner.lock();
        assert_eq!(inner.exec_req_rx.len(), 0);
        assert!(inner.exec_sessions.is_empty());
    }

    /// Chaining `.env()` calls extends rather than replaces.
    #[test]
    fn test_exec_builder_env_extends() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, link);

        let builder = handle.exec(["cmd"]).env(["A=1", "B=2"]).env(["C=3"]);

        // All three env vars should be present (extend, not replace).
        assert_eq!(builder.env, vec!["A=1", "B=2", "C=3"]);
    }

    /// `.cwd()` sets the working directory for exec.
    #[test]
    fn test_exec_builder_cwd() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, link);

        let builder = handle.exec(["cmd"]).cwd("/tmp");
        assert_eq!(builder.cwd, "/tmp");
    }

    /// Default cwd is empty (inherit).
    #[test]
    fn test_exec_builder_default_cwd_empty() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, link);

        let builder = handle.exec(["cmd"]);
        assert!(builder.cwd.is_empty());
    }

    #[tokio::test]
    async fn exec_rejects_empty_argv_before_enqueue() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, Arc::clone(&link));

        let result = handle.exec(std::iter::empty::<&str>()).await;

        assert!(matches!(result, Err(ExecError::InvalidCommand { .. })));
        assert_eq!(link.inner.lock().exec_req_rx.len(), 0);
    }

    #[tokio::test]
    async fn exec_rejects_control_bytes_before_enqueue() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, Arc::clone(&link));

        let result = handle.exec(["echo", "bad\narg"]).await;

        assert!(matches!(result, Err(ExecError::InvalidCommand { .. })));
        assert_eq!(link.inner.lock().exec_req_rx.len(), 0);
    }

    #[tokio::test]
    async fn exec_rejects_malformed_env_before_enqueue() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, Arc::clone(&link));

        let result = handle.exec(["cmd"]).env(["BAD-KEY=value"]).await;

        assert!(matches!(result, Err(ExecError::InvalidCommand { .. })));
        assert_eq!(link.inner.lock().exec_req_rx.len(), 0);
    }

    #[tokio::test]
    async fn exec_rejects_noncanonical_cwd_before_enqueue() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, Arc::clone(&link));

        let result = handle.exec(["cmd"]).cwd("/tmp/../root").await;

        assert!(matches!(result, Err(ExecError::InvalidCommand { .. })));
        assert_eq!(link.inner.lock().exec_req_rx.len(), 0);
    }

    #[tokio::test]
    async fn exec_rejects_oversized_request_before_enqueue() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let handle = started_handle(ch, status, Arc::clone(&link));
        let huge = "x".repeat(amla_constants::protocol::MAX_MESSAGE_SIZE);

        let result = handle.exec(["cmd", huge.as_str()]).await;

        assert!(matches!(result, Err(ExecError::MessageTooLarge { .. })));
        assert_eq!(link.inner.lock().exec_req_rx.len(), 0);
    }

    /// `exec()` unblocks when exit flag is set mid-flight.
    #[tokio::test]
    async fn test_exec_unblocks_on_exit_during_wait() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());

        let handle = started_handle(ch, Arc::clone(&status), link);

        // Spawn exec — it will block waiting for host-side ring acceptance.
        let exec_task = tokio::spawn({
            let handle = handle.into_exec_only();
            async move { handle.exec(["echo", "crash"]).await }
        });

        // Small delay to let exec() queue and start awaiting acceptance.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Simulate guest crash — set exit flag.
        status.set_exited();

        // exec() should unblock and return Disconnected.
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), exec_task)
            .await
            .expect("exec() hung after exit — deadlock")
            .expect("task panicked");

        assert!(
            result.is_err(),
            "exec during crash should return Disconnected"
        );
    }

    #[tokio::test]
    async fn poll_recv_memory_pressure_yields_forwarded_event() {
        let link = Arc::new(AgentLink::new());
        let ch = link.connect();
        let status = Arc::new(VmStatus::new());
        let mut handle = started_handle(ch, status, Arc::clone(&link));
        let event = MemoryPressureEvent {
            level: 1,
            available_kb: 2048,
            total_kb: 8192,
        };
        link.inner
            .lock()
            .memory_pressure_tx
            .try_send(event.clone())
            .expect("memory pressure receiver should be connected");

        let received = std::future::poll_fn(|cx| handle.poll_recv_memory_pressure(cx))
            .await
            .expect("memory pressure channel should be open");

        assert_eq!(received.level, event.level);
        assert_eq!(received.available_kb, event.available_kb);
        assert_eq!(received.total_kb, event.total_kb);
    }
}
