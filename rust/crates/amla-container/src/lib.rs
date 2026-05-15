//! Helpers for running OCI containers inside amla VMs.
//!
//! This crate provides the thin layer between a guest exec surface and
//! application code that wants to run commands inside a container namespace.
//!
//! # What this crate does
//!
//! - [`ContainerHandle`]: wraps a VM-like guest exec surface so every exec call
//!   is routed through `amla-exec`, running inside the container namespace that
//!   `amla-init` set up. Callers choose the concrete VM surface explicitly:
//!   direct VMM, scheduler, or a test double.
//!
//! - [`init_container`]: runs `amla-init` in the VM, waits for the `READY`
//!   signal on stderr, and returns the init process handle (which must be
//!   kept alive) together with a `ContainerHandle`.
//!
//! # What this crate does NOT do
//!
//! No runtime, no orchestration, no image management.  Those belong in
//! higher layers.

#![deny(missing_docs)]

// Re-export types that appear in our public API.
pub use amla_erofs::BuiltImage;
pub use amla_vmm::{
    CollectedOutput, CommandExecution, CountedReceiver, ExecError, OutputEvent, StdinWriter,
    VmHandle,
};

use std::future::{Future, IntoFuture};
use std::marker::PhantomData;
use std::pin::Pin;

// ─── Rootfs ─────────────────────────────────────────────────────────────

/// Build a VM rootfs image with the unified guest binary.
///
/// Assembles the base VM rootfs containing `/bin/amla-guest` — a single
/// multi-call binary that provides agent, init, exec, and coreutils.
///
/// Returns a [`BuiltImage`] suitable for `MemHandle::allocate_and_write`.
pub fn build_rootfs() -> Result<BuiltImage, RootfsError> {
    let image = amla_guest_rootfs::RootfsBuilder::base().build()?;
    Ok(image)
}

/// Linux kernel image bytes (`vmlinux` ELF on `x86_64`, `Image` on `aarch64`).
pub const KERNEL: &[u8] = amla_guest_rootfs::KERNEL;

/// Errors from rootfs building.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct RootfsError(#[from] amla_erofs::ErofsError);

// ─── Error ──────────────────────────────────────────────────────────────

/// Errors from container initialization.
#[derive(Debug, thiserror::Error)]
pub enum InitError {
    /// Failed to execute amla-init in the VM.
    #[error("exec: {0}")]
    Exec(#[from] ExecError),

    /// amla-init process exited before sending the READY signal.
    #[error("amla-init exited before ready")]
    InitExitedBeforeReady,
}

/// Errors from [`ContainerHandle::read_user_file`] and [`ContainerHandle::write_user_file`].
#[derive(Debug, thiserror::Error)]
pub enum FileError {
    /// Failed to execute the amla-exec file command.
    #[error("exec: {0}")]
    Exec(#[from] ExecError),

    /// The file command exited with a non-zero status.
    #[error("{op} {path}: exit code {code}")]
    Failed {
        /// `"read-user-file"` or `"write-user-file"`.
        op: &'static str,
        /// Guest path.
        path: String,
        /// Exit code from amla-exec.
        code: i32,
    },

    /// Failed to write stdin or collect output.
    #[error("{0}")]
    Io(String),
}

// ─── Guest exec abstraction ─────────────────────────────────────────────

/// Output stream produced by a guest command.
pub trait GuestOutputStream {
    /// Future returned by [`recv()`](Self::recv).
    type RecvFuture<'a>: Future<Output = Option<Vec<u8>>> + Send + 'a
    where
        Self: 'a;

    /// Receive the next output chunk, or `None` once the stream closes.
    fn recv(&mut self) -> Self::RecvFuture<'_>;
}

/// Running guest command used by the container layer.
pub trait GuestCommand {
    /// Stream type returned for stdout and stderr.
    type OutputStream: GuestOutputStream + Send;

    /// Future returned by [`close_stdin()`](Self::close_stdin).
    type CloseStdinFuture<'a>: Future<Output = Result<(), ExecError>> + Send + 'a
    where
        Self: 'a;

    /// Future returned by [`wait()`](Self::wait).
    type WaitFuture<'a>: Future<Output = Result<i32, ExecError>> + Send + 'a
    where
        Self: 'a;

    /// Take the stdout stream for independent consumption.
    fn take_stdout(&mut self) -> Option<Self::OutputStream>;

    /// Take the stderr stream for independent consumption.
    fn take_stderr(&mut self) -> Option<Self::OutputStream>;

    /// Close stdin for the guest command.
    fn close_stdin(&self) -> Self::CloseStdinFuture<'_>;

    /// Wait for the guest command to exit.
    fn wait(&mut self) -> Self::WaitFuture<'_>;
}

/// Minimal VM-like surface needed to run commands in a guest.
pub trait GuestExec {
    /// Command type returned by this execution surface.
    type Command: GuestCommand + Send;

    /// Future produced after submitting an exec request.
    type ExecFuture<'a>: Future<Output = Result<Self::Command, ExecError>> + Send + 'a
    where
        Self: 'a;

    /// Builder or future returned by [`exec()`](Self::exec).
    type Exec<'a>: IntoFuture<Output = Result<Self::Command, ExecError>, IntoFuture = Self::ExecFuture<'a>>
        + Send
        + 'a
    where
        Self: 'a;

    /// Start a command in the guest.
    ///
    /// When `pty` is true, the guest allocates a pseudo-terminal instead of
    /// using piped stdout/stderr.
    fn exec(&self, argv: Vec<String>, pty: bool) -> Self::Exec<'_>;
}

impl GuestOutputStream for CountedReceiver {
    type RecvFuture<'a>
        = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>
    where
        Self: 'a;

    fn recv(&mut self) -> Self::RecvFuture<'_> {
        Box::pin(async move { Self::recv(self).await })
    }
}

impl GuestCommand for CommandExecution {
    type OutputStream = CountedReceiver;
    type CloseStdinFuture<'a>
        = Pin<Box<dyn Future<Output = Result<(), ExecError>> + Send + 'a>>
    where
        Self: 'a;
    type WaitFuture<'a>
        = Pin<Box<dyn Future<Output = Result<i32, ExecError>> + Send + 'a>>
    where
        Self: 'a;

    fn take_stdout(&mut self) -> Option<Self::OutputStream> {
        Self::take_stdout(self)
    }

    fn take_stderr(&mut self) -> Option<Self::OutputStream> {
        Self::take_stderr(self)
    }

    fn close_stdin(&self) -> Self::CloseStdinFuture<'_> {
        Box::pin(async move { Self::close_stdin(self).await })
    }

    fn wait(&mut self) -> Self::WaitFuture<'_> {
        Box::pin(async move { Self::wait(self).await })
    }
}

impl<'dev> GuestExec for VmHandle<'dev> {
    type Command = CommandExecution;
    type ExecFuture<'a>
        = <amla_vmm::ExecBuilder<'a, 'dev> as IntoFuture>::IntoFuture
    where
        Self: 'a;
    type Exec<'a>
        = amla_vmm::ExecBuilder<'a, 'dev>
    where
        Self: 'a;

    fn exec(&self, argv: Vec<String>, pty: bool) -> Self::Exec<'_> {
        if pty {
            VmHandle::exec_pty(self, argv)
        } else {
            VmHandle::exec(self, argv)
        }
    }
}

#[cfg(feature = "scheduler")]
impl GuestOutputStream for amla_vm_scheduler::CountedReceiver {
    type RecvFuture<'a>
        = Pin<Box<dyn Future<Output = Option<Vec<u8>>> + Send + 'a>>
    where
        Self: 'a;

    fn recv(&mut self) -> Self::RecvFuture<'_> {
        Box::pin(async move { Self::recv(self).await })
    }
}

#[cfg(feature = "scheduler")]
impl GuestCommand for amla_vm_scheduler::CommandExecution {
    type OutputStream = amla_vm_scheduler::CountedReceiver;
    type CloseStdinFuture<'a>
        = Pin<Box<dyn Future<Output = Result<(), ExecError>> + Send + 'a>>
    where
        Self: 'a;
    type WaitFuture<'a>
        = Pin<Box<dyn Future<Output = Result<i32, ExecError>> + Send + 'a>>
    where
        Self: 'a;

    fn take_stdout(&mut self) -> Option<Self::OutputStream> {
        Self::take_stdout(self)
    }

    fn take_stderr(&mut self) -> Option<Self::OutputStream> {
        Self::take_stderr(self)
    }

    fn close_stdin(&self) -> Self::CloseStdinFuture<'_> {
        Box::pin(async move { Self::close_stdin(self).await })
    }

    fn wait(&mut self) -> Self::WaitFuture<'_> {
        Box::pin(async move { Self::wait(self).await })
    }
}

#[cfg(feature = "scheduler")]
impl<'dev> GuestExec for amla_vm_scheduler::VmHandle<'dev> {
    type Command = amla_vm_scheduler::CommandExecution;
    type ExecFuture<'a>
        = <amla_vm_scheduler::ExecBuilder<'a, 'dev> as IntoFuture>::IntoFuture
    where
        Self: 'a;
    type Exec<'a>
        = amla_vm_scheduler::ExecBuilder<'a, 'dev>
    where
        Self: 'a;

    fn exec(&self, argv: Vec<String>, pty: bool) -> Self::Exec<'_> {
        if pty {
            amla_vm_scheduler::VmHandle::exec_pty(self, argv)
        } else {
            amla_vm_scheduler::VmHandle::exec(self, argv)
        }
    }
}

// ─── ContainerHandle ────────────────────────────────────────────────────

/// Wrapper around a guest exec surface that routes exec calls through `amla-exec`,
/// running commands inside the container namespace.
///
/// Created after `amla-init` has set up the container.  All `exec`/`exec_pty`
/// calls prepend `/bin/amla-exec run <bundle> --` so the command enters the
/// namespace that `amla-init` created.
pub struct ContainerHandle<'a, 'dev, H>
where
    H: GuestExec,
{
    vm: &'a H,
    bundle: String,
    _not_static: PhantomData<&'dev ()>,
}

/// Container handle backed by the direct `amla-vmm` VM handle.
pub type DirectContainerHandle<'a, 'dev> = ContainerHandle<'a, 'dev, VmHandle<'dev>>;

impl<'a, 'dev, H> ContainerHandle<'a, 'dev, H>
where
    H: GuestExec,
{
    /// Wrap a VM handle whose container has already been initialized.
    ///
    /// `bundle` is the bundle name passed to `amla-init` (e.g. `"ax"`).
    /// It is forwarded to `amla-exec run <bundle> --`.
    pub fn new(vm: &'a H, bundle: &str) -> Self {
        Self {
            vm,
            bundle: bundle.to_string(),
            _not_static: PhantomData,
        }
    }

    /// Run a command inside the container namespace (piped stdin/stdout/stderr).
    ///
    /// Returns a [`ContainerRunBuilder`] — call `.await` to send, or chain
    /// `.env(["KEY=val"])` first. Env vars are forwarded to `amla-exec`
    /// via `--env` flags so they reach the containerized process.
    pub fn run(
        &self,
        argv: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> ContainerRunBuilder<'_, 'dev, H> {
        ContainerRunBuilder {
            handle: self,
            argv: argv.into_iter().map(|s| s.as_ref().to_string()).collect(),
            env: Vec::new(),
            cwd: String::new(),
            pty: false,
        }
    }

    /// Run a command inside the container namespace with a PTY.
    ///
    /// Like [`run()`](Self::run) but allocates a pseudo-terminal.
    pub fn run_pty(
        &self,
        argv: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> ContainerRunBuilder<'_, 'dev, H> {
        ContainerRunBuilder {
            handle: self,
            argv: argv.into_iter().map(|s| s.as_ref().to_string()).collect(),
            env: Vec::new(),
            cwd: String::new(),
            pty: true,
        }
    }

    /// Access the underlying guest exec surface.
    pub const fn vm(&self) -> &H {
        self.vm
    }

    fn build_amla_exec_argv(&self, env: &[String], cwd: &str, argv: &[String]) -> Vec<String> {
        let mut full = vec![
            "/bin/amla-guest".to_string(),
            "exec".to_string(),
            "run".to_string(),
            self.bundle.clone(),
        ];
        for var in env {
            full.push("--env".to_string());
            full.push(var.clone());
        }
        if !cwd.is_empty() {
            full.push("--cwd".to_string());
            full.push(cwd.to_string());
        }
        full.push("--".to_string());
        full.extend(argv.iter().cloned());
        full
    }
}

impl<'dev> ContainerHandle<'_, 'dev, VmHandle<'dev>> {
    /// Read a file from the container as the container user.
    ///
    /// `path` is relative to the container user's home directory (resolved
    /// from `/etc/passwd` inside the container). Returns the raw file contents.
    pub async fn read_user_file(&self, path: &str) -> Result<Vec<u8>, FileError> {
        let argv = [
            "/bin/amla-guest",
            "exec",
            "read-user-file",
            self.bundle.as_str(),
            path,
        ];
        let mut cmd = self.vm.exec(argv).await?;
        let output = cmd
            .collect_output()
            .await
            .map_err(|e| FileError::Io(e.to_string()))?;
        if output.exit_code != 0 {
            return Err(FileError::Failed {
                op: "read-user-file",
                path: path.to_string(),
                code: output.exit_code,
            });
        }
        Ok(output.stdout)
    }

    /// Write a file into the container as the container user.
    ///
    /// `path` is relative to the container user's home directory (resolved
    /// from `/etc/passwd` inside the container). Creates parent directories
    /// as needed. The file is owned by the container user, not root.
    pub async fn write_user_file(&self, path: &str, data: &[u8]) -> Result<(), FileError> {
        let argv = [
            "/bin/amla-guest",
            "exec",
            "write-user-file",
            self.bundle.as_str(),
            path,
        ];
        let mut cmd = self.vm.exec(argv).await?;
        cmd.write_stdin(data)
            .await
            .map_err(|e| FileError::Io(e.to_string()))?;
        cmd.close_stdin()
            .await
            .map_err(|e| FileError::Io(e.to_string()))?;
        let output = cmd
            .collect_output()
            .await
            .map_err(|e| FileError::Io(e.to_string()))?;
        if output.exit_code != 0 {
            return Err(FileError::Failed {
                op: "write-user-file",
                path: path.to_string(),
                code: output.exit_code,
            });
        }
        Ok(())
    }
}

/// Builder for container commands. Call `.env(...)` then `.await`.
///
/// Env vars are passed as `--env K=V` flags to `amla-exec` so they
/// reach the process inside the container namespace (not the wrapper).
pub struct ContainerRunBuilder<'a, 'dev, H>
where
    H: GuestExec,
{
    handle: &'a ContainerHandle<'a, 'dev, H>,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    pty: bool,
}

impl<H> ContainerRunBuilder<'_, '_, H>
where
    H: GuestExec,
{
    /// Set environment variables for the containerized process.
    ///
    /// Values are `KEY=VALUE` strings forwarded via `amla-exec --env`.
    /// Multiple calls extend the list.
    #[must_use]
    pub fn env(mut self, env: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.env
            .extend(env.into_iter().map(|s| s.as_ref().to_string()));
        self
    }

    /// Set the working directory for the containerized process.
    ///
    /// Overrides the OCI config's `process.cwd`. Empty string (default)
    /// uses the image's configured working directory.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }
}

impl<'a, H> std::future::IntoFuture for ContainerRunBuilder<'a, '_, H>
where
    H: GuestExec + 'a,
{
    type Output = Result<H::Command, ExecError>;
    type IntoFuture = H::ExecFuture<'a>;

    fn into_future(self) -> Self::IntoFuture {
        let full_argv = self
            .handle
            .build_amla_exec_argv(&self.env, &self.cwd, &self.argv);
        self.handle.vm.exec(full_argv, self.pty).into_future()
    }
}

// ─── init_container ─────────────────────────────────────────────────────

/// Result of [`init_container`]: the running init process and a handle for
/// running commands inside the container.
pub struct Container<'a, 'dev, H>
where
    H: GuestExec,
{
    /// The running `amla-init` process.
    ///
    /// **Keep this alive** — dropping it closes stdin, which signals
    /// `amla-init` to tear down the container namespace.
    ///
    /// Stdout carries display frames (length-prefixed LZ4); the caller
    /// is free to `take_stdout()` and wire it up as needed.
    pub init: H::Command,

    /// Handle for running commands inside the container namespace.
    pub handle: ContainerHandle<'a, 'dev, H>,
}

/// Initialized container backed by the direct `amla-vmm` VM handle.
pub type DirectContainer<'a, 'dev> = Container<'a, 'dev, VmHandle<'dev>>;

/// Run `amla-init` in the VM and wait for the container to become ready.
///
/// This is the standard container boot ceremony:
/// 1. Run `amla-init <bundle> --config <json>`
/// 2. Wait for `READY` on stderr
/// 3. Drop the stderr receiver after READY so later diagnostics do not keep
///    host-side state alive
/// 4. Return the init process + a [`ContainerHandle`]
///
/// The caller owns the returned [`Container`] and is responsible for:
/// - Keeping `container.init` alive for the container's lifetime
/// - Optionally wiring up `container.init.take_stdout()` for display frames
pub async fn init_container<'a, 'dev, H>(
    handle: &'a H,
    bundle: &str,
    config_json: &str,
) -> Result<Container<'a, 'dev, H>, InitError>
where
    H: GuestExec + Sync,
{
    let args = vec![
        "/bin/amla-guest".to_string(),
        "init".to_string(),
        bundle.to_string(),
        "--config".to_string(),
        config_json.to_string(),
    ];

    let mut init = handle.exec(args, false).await?;

    // Wait for "READY <pid>" on stderr. The stream is shared with diagnostics
    // from multiple guest-side processes, so the marker can be glued to a
    // partial log line even though the marker itself is a complete record.
    let mut stderr = init.take_stderr().ok_or(InitError::InitExitedBeforeReady)?;
    let mut buf = Vec::new();
    loop {
        match stderr.recv().await {
            Some(data) => {
                buf.extend_from_slice(&data);
                if contains_ready_marker(&buf) {
                    break;
                }
                let text = String::from_utf8_lossy(&buf);
                // Log non-READY lines at debug (pre-ready init output).
                for line in text.lines() {
                    if !line.is_empty() {
                        log::debug!("amla-init (pre-ready): {line}");
                    }
                }
            }
            None => return Err(InitError::InitExitedBeforeReady),
        }
    }

    // `amla-init` is a long-lived process. Do not hide a background drain here:
    // callers that need zygote/snapshot support must be able to make the init
    // session reattachable immediately after READY. Dropping the receiver closes
    // the host-side stderr stream; future init diagnostics are discarded by the
    // exec layer instead of creating backpressure or transient host state.
    drop(stderr);

    let container_handle = ContainerHandle::new(handle, bundle);
    Ok(Container {
        init,
        handle: container_handle,
    })
}

fn contains_ready_marker(buf: &[u8]) -> bool {
    let marker = b"READY ";
    let mut offset = 0;
    while let Some(pos) = find_subslice(&buf[offset..], marker) {
        let start = offset + pos;
        let after_marker = start + marker.len();
        let before_is_boundary =
            start == 0 || (!buf[start - 1].is_ascii_alphanumeric() && buf[start - 1] != b'_');

        if before_is_boundary {
            let mut end = after_marker;
            while end < buf.len() && buf[end].is_ascii_digit() {
                end += 1;
            }
            let has_pid = end > after_marker;
            let after_is_boundary =
                end == buf.len() || matches!(buf[end], b'\n' | b'\r' | b' ' | b'\t');
            if has_pid && after_is_boundary {
                return true;
            }
        }

        offset = start + 1;
    }
    false
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::contains_ready_marker;

    #[test]
    fn ready_marker_at_line_start_is_detected() {
        assert!(contains_ready_marker(b"compositor: listening\nREADY 42\n"));
    }

    #[test]
    fn ready_marker_glued_to_partial_log_line_is_detected() {
        assert!(contains_ready_marker(
            b"amla-init: CMD exited with code READY 38\n0\n"
        ));
    }

    #[test]
    fn ready_marker_requires_token_boundary_and_pid() {
        assert!(!contains_ready_marker(b"ALREADY 38\n"));
        assert!(!contains_ready_marker(b"READY soon\n"));
        assert!(!contains_ready_marker(b"READY 38abc\n"));
    }
}
