// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
#![deny(missing_docs)]

//! Scheduler-owned VM API with backend pool management and VM multiplexing.
//!
//! The scheduler mirrors the shape of `amla-vm-vmm` while owning the pieces
//! callers should not have to thread through each run: backend pools, shell
//! permits, and long-lived VM backends. A scheduler VM is a logical VM. Its
//! `Parked` typestate is intentionally distinct from `amla_vmm::Parked`: the
//! scheduler may temporarily resume the primitive VMM internally, but the VM is
//! inert again once the public scheduler operation returns.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::fmt::Write as _;
use std::future::Future;
use std::io::{self, IoSlice};
use std::marker::PhantomData;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use amla_core::backends::{NetBackend, NullNetBackend, RxWaker};
use amla_fuse::fuse::FsBackend;
use amla_vmm::backend;
use amla_vmm::{
    CommandExecution as PrimitiveCommandExecution,
    CommandExecutionHandle as PrimitiveCommandExecutionHandle,
    CountedReceiver as PrimitiveCountedReceiver, New as PrimitiveNew, Parked as PrimitiveParked,
    Paused as PrimitivePaused, Ready as PrimitiveReady, Running as PrimitiveRunning,
    VirtualMachine as PrimitiveVirtualMachine, VmHandle as PrimitiveVmHandle,
    Zygote as PrimitiveZygote,
};
use tokio::sync::{Mutex, Notify, mpsc, oneshot};

pub use amla_constants::protocol::ExecId;
pub use amla_vmm::{
    CollectedOutput, CommandSpec, ConfigError, ConsoleBufferLimits, ConsoleStream,
    DEFAULT_COLLECT_OUTPUT_LIMIT, DeviceError, DeviceKind, Error, ExecArg, ExecError, FsConfig,
    FsRequestQueueCount, GuestCwd, GuestEnvVar, GuestPath, KernelCmdlineAtom, MemHandle,
    MemoryPressureEvent, NetConfig, OutputEvent, PmemDiskConfig, PmemImageConfig, Result,
    VirtioFsTag, VmConfig, VmTopology, VmTopologyEntry, WorkerBinary, WorkerProcessConfig,
    available, worker_main,
};

type PrimitiveVm<S> = PrimitiveVirtualMachine<S>;

/// Scheduler-owned network session wrapper.
///
/// This keeps the host-side network backend state alive for one logical VM
/// while allowing each VMM `run()` to install a short-lived device-loop waker.
/// The wrapped backend receives one stable wake token for its whole lifetime;
/// detached TCP/DNS/NAT tasks can therefore wake the scheduler even after the
/// live hypervisor shell has been parked.
pub struct NetworkSession<N: NetBackend> {
    inner: N,
    wake_hub: Arc<NetworkWakeHub>,
}

impl<N: NetBackend> NetworkSession<N> {
    /// Create a network session around a backend.
    #[must_use]
    pub fn new(inner: N) -> Self {
        let wake_hub = Arc::new(NetworkWakeHub::new());
        inner.set_rx_waker(Some(wake_hub.backend_waker()));
        Self { inner, wake_hub }
    }

    /// Wait until backend RX activity is observed.
    pub async fn wait_for_rx(&self) {
        self.wake_hub.wait().await;
    }

    /// Consume and return the sticky scheduler RX wake bit.
    #[must_use]
    pub fn take_rx_wake(&self) -> bool {
        self.wake_hub.take_pending()
    }

    fn scheduler_wake_hub(&self) -> Arc<NetworkWakeHub> {
        Arc::clone(&self.wake_hub)
    }
}

impl<N: NetBackend> Drop for NetworkSession<N> {
    fn drop(&mut self) {
        self.inner.set_rx_waker(None);
    }
}

impl<N: NetBackend> NetBackend for NetworkSession<N> {
    type RxPacket<'a>
        = N::RxPacket<'a>
    where
        Self: 'a;

    fn guest_mac(&self) -> Option<[u8; 6]> {
        self.inner.guest_mac()
    }

    fn send(&self, bufs: &[IoSlice<'_>]) -> io::Result<()> {
        self.inner.send(bufs)
    }

    fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
        self.inner.rx_packet()
    }

    fn set_nonblocking(&self, nonblocking: bool) -> io::Result<()> {
        self.inner.set_nonblocking(nonblocking)
    }

    fn set_rx_waker(&self, waker: Option<RxWaker>) {
        self.wake_hub.set_device_waker(waker);
    }
}

struct NetworkWakeHub {
    device_waker: std::sync::Mutex<Option<RxWaker>>,
    scheduler_pending: AtomicBool,
    scheduler_notify: tokio::sync::Notify,
}

impl NetworkWakeHub {
    fn new() -> Self {
        Self {
            device_waker: std::sync::Mutex::new(None),
            scheduler_pending: AtomicBool::new(false),
            scheduler_notify: tokio::sync::Notify::new(),
        }
    }

    fn backend_waker(self: &Arc<Self>) -> RxWaker {
        let hub = Arc::clone(self);
        RxWaker::new(move || hub.wake())
    }

    fn set_device_waker(&self, waker: Option<RxWaker>) {
        let should_wake = self.has_pending();
        let active = waker.clone();
        let old = {
            let mut guard = self
                .device_waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            std::mem::replace(&mut *guard, waker)
        };
        if let Some(old) = old {
            old.cancel();
        }
        if should_wake && let Some(waker) = active {
            waker.wake();
        }
    }

    fn wake(&self) {
        self.scheduler_pending.store(true, Ordering::Release);
        self.scheduler_notify.notify_waiters();
        let device_waker = self
            .device_waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(waker) = device_waker {
            waker.wake();
        }
    }

    async fn wait(&self) {
        loop {
            let notified = self.scheduler_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.take_pending() {
                return;
            }
            notified.await;
        }
    }

    fn has_pending(&self) -> bool {
        self.scheduler_pending.load(Ordering::Acquire)
    }

    fn take_pending(&self) -> bool {
        self.scheduler_pending.swap(false, Ordering::AcqRel)
    }
}

/// Runtime host backends owned by one scheduler VM.
///
/// These resources stay with the logical VM across park/resume cycles. The
/// scheduler borrows them only while it has attached the VM to a live backend
/// shell.
pub struct RuntimeBackends<F: FsBackend = amla_fuse::NullFsBackend, N: NetBackend = NullNetBackend>
{
    console: ConsoleStream,
    net: Option<N>,
    fs: Option<F>,
    rx_wake: Option<Arc<NetworkWakeHub>>,
}

impl RuntimeBackends<amla_fuse::NullFsBackend, NullNetBackend> {
    /// Create runtime backends with only a console device.
    #[must_use]
    pub const fn new(console: ConsoleStream) -> Self {
        Self {
            console,
            net: None,
            fs: None,
            rx_wake: None,
        }
    }
}

impl<F: FsBackend, N: NetBackend> RuntimeBackends<F, N> {
    /// Borrow the console stream.
    #[must_use]
    pub const fn console(&self) -> &ConsoleStream {
        &self.console
    }

    /// Borrow the network backend, if configured.
    #[must_use]
    pub const fn net(&self) -> Option<&N> {
        self.net.as_ref()
    }

    /// Borrow the virtio-fs backend, if configured.
    #[must_use]
    pub const fn fs(&self) -> Option<&F> {
        self.fs.as_ref()
    }

    /// Add a network backend.
    ///
    /// The scheduler wraps the backend in a `NetworkSession` so RX activity can
    /// participate in scheduler admission decisions across park/resume cycles.
    #[must_use]
    pub fn with_net<N2: NetBackend>(self, net: N2) -> RuntimeBackends<F, NetworkSession<N2>> {
        self.with_network_session(NetworkSession::new(net))
    }

    /// Add an already-created scheduler network session.
    #[must_use]
    pub fn with_network_session<N2: NetBackend>(
        self,
        net: NetworkSession<N2>,
    ) -> RuntimeBackends<F, NetworkSession<N2>> {
        let rx_wake = Some(net.scheduler_wake_hub());
        RuntimeBackends {
            console: self.console,
            net: Some(net),
            fs: self.fs,
            rx_wake,
        }
    }

    /// Add a virtio-fs backend.
    #[must_use]
    pub fn with_fs<F2: FsBackend>(self, fs: F2) -> RuntimeBackends<F2, N> {
        RuntimeBackends {
            console: self.console,
            net: self.net,
            fs: Some(fs),
            rx_wake: self.rx_wake,
        }
    }

    fn as_spawn_backends(&self) -> amla_vmm::SpawnBackends<'_, F, N> {
        amla_vmm::SpawnBackends {
            console: &self.console,
            net: self.net.as_ref(),
            fs: self.fs.as_ref(),
        }
    }

    const fn has_scheduler_rx_wake(&self) -> bool {
        self.rx_wake.is_some()
    }

    fn take_scheduler_rx_wake(&self) -> bool {
        self.rx_wake
            .as_ref()
            .is_some_and(|wake_hub| wake_hub.take_pending())
    }

    async fn wait_for_scheduler_rx(&self) {
        match &self.rx_wake {
            Some(wake_hub) => wake_hub.wait().await,
            None => std::future::pending().await,
        }
    }
}

/// Backends required to create and boot one scheduler-owned VM.
///
/// `pmem` source images are consumed by `load_kernel`; the scheduler clones
/// them for each live shell load attempt so platform resource-limit retries do
/// not consume the caller's durable VM backend bundle. Console, net, and fs
/// backends remain owned by the logical VM for subsequent scheduler runs.
pub struct VmBackends<F: FsBackend = amla_fuse::NullFsBackend, N: NetBackend = NullNetBackend> {
    runtime: RuntimeBackends<F, N>,
    pmem: Vec<MemHandle>,
}

impl VmBackends<amla_fuse::NullFsBackend, NullNetBackend> {
    /// Create VM backends with only a console device.
    #[must_use]
    pub const fn new(console: ConsoleStream) -> Self {
        Self {
            runtime: RuntimeBackends::new(console),
            pmem: Vec::new(),
        }
    }
}

impl<F: FsBackend, N: NetBackend> VmBackends<F, N> {
    /// Create VM backends from explicit parts.
    #[must_use]
    pub const fn from_parts(runtime: RuntimeBackends<F, N>, pmem: Vec<MemHandle>) -> Self {
        Self { runtime, pmem }
    }

    /// Add pmem images.
    #[must_use]
    pub fn with_pmem(mut self, pmem: Vec<MemHandle>) -> Self {
        self.pmem = pmem;
        self
    }

    /// Add a network backend.
    ///
    /// The scheduler wraps the backend in a `NetworkSession` so RX activity can
    /// participate in scheduler admission decisions across park/resume cycles.
    #[must_use]
    pub fn with_net<N2: NetBackend>(self, net: N2) -> VmBackends<F, NetworkSession<N2>> {
        self.with_network_session(NetworkSession::new(net))
    }

    /// Add an already-created scheduler network session.
    #[must_use]
    pub fn with_network_session<N2: NetBackend>(
        self,
        net: NetworkSession<N2>,
    ) -> VmBackends<F, NetworkSession<N2>> {
        VmBackends {
            runtime: self.runtime.with_network_session(net),
            pmem: self.pmem,
        }
    }

    /// Add a virtio-fs backend.
    #[must_use]
    pub fn with_fs<F2: FsBackend>(self, fs: F2) -> VmBackends<F2, N> {
        VmBackends {
            runtime: self.runtime.with_fs(fs),
            pmem: self.pmem,
        }
    }

    fn into_parts(self) -> (RuntimeBackends<F, N>, Vec<MemHandle>) {
        (self.runtime, self.pmem)
    }
}

/// Scheduler-owned VM with typestate encoded by `S`.
pub struct VirtualMachine<S> {
    state: S,
}

/// Scheduler VM state before the kernel is loaded.
pub struct New<F: FsBackend = amla_fuse::NullFsBackend, N: NetBackend = NullNetBackend> {
    inner: PrimitiveVm<PrimitiveNew>,
    backends: VmBackends<F, N>,
    scheduler: VmScheduler,
}

/// Scheduler VM state with durable guest state and no live backend shell.
pub struct Parked<F: FsBackend = amla_fuse::NullFsBackend, N: NetBackend = NullNetBackend> {
    inner: PrimitiveVm<PrimitiveParked>,
    backends: RuntimeBackends<F, N>,
    commands: VmCommandRegistry,
    scheduler: VmScheduler,
}

/// Scheduler VM state for a frozen template.
pub struct Zygote {
    inner: PrimitiveVm<PrimitiveZygote>,
    scheduler: VmScheduler,
}

impl<F: FsBackend, N: NetBackend> VirtualMachine<New<F, N>> {
    /// Borrow the VM config.
    #[must_use]
    pub const fn config(&self) -> &VmConfig {
        self.state.inner.config()
    }

    /// Load the configured kernel and return a parked scheduler VM.
    pub async fn load_kernel(
        self,
        kernel: &[u8],
    ) -> std::result::Result<VirtualMachine<Parked<F, N>>, SchedulerOperationError> {
        let scheduler = self.state.scheduler.clone();
        scheduler.load_kernel_owned(self, kernel).await
    }
}

impl<F: FsBackend, N: NetBackend> VirtualMachine<Parked<F, N>> {
    /// Borrow the VM config.
    #[must_use]
    pub const fn config(&self) -> &VmConfig {
        self.state.inner.config()
    }

    /// Borrow this VM's runtime backend bundle.
    #[must_use]
    pub const fn backends(&self) -> &RuntimeBackends<F, N> {
        &self.state.backends
    }

    /// Run this VM until the supplied closure completes, then park it again.
    ///
    /// The closure receives a scheduler-specific handle with the same shape as
    /// the VMM handle. Backend pools and runtime backends remain scheduler
    /// owned and are never passed through this API.
    pub async fn run<Fn, R>(self, f: Fn) -> std::result::Result<(Self, R), SchedulerRunError<F, N>>
    where
        Fn: AsyncFnOnce(VmHandle<'_, Paused>) -> R,
    {
        let Parked {
            inner,
            backends,
            commands,
            scheduler,
        } = self.state;
        scheduler
            .run_primitive_parked(inner, backends, commands, f)
            .await
    }

    /// Freeze this VM into a zygote template.
    pub async fn freeze(
        self,
    ) -> std::result::Result<VirtualMachine<Zygote>, SchedulerFreezeError<F, N>> {
        let Parked {
            inner,
            backends,
            commands,
            scheduler,
        } = self.state;
        scheduler
            .freeze_primitive_parked(inner, backends, commands)
            .await
    }
}

impl VirtualMachine<Zygote> {
    /// Borrow the VM config.
    #[must_use]
    pub const fn config(&self) -> &VmConfig {
        self.state.inner.config()
    }

    /// Spawn a child VM from this zygote and park it immediately.
    pub async fn spawn<F: FsBackend, N: NetBackend>(
        &self,
        backends: RuntimeBackends<F, N>,
    ) -> std::result::Result<VirtualMachine<Parked<F, N>>, SchedulerOperationError> {
        self.state.scheduler.spawn_owned(self, backends).await
    }
}

/// Scheduler `VmHandle` state before guest execution starts.
pub struct Paused {
    pending_attaches: Vec<CommandExecutionHandle>,
}

/// Scheduler `VmHandle` state after guest execution starts.
pub struct Running {
    attached: HashMap<ExecId, CommandExecution>,
}

/// Handle for interacting with a scheduler VM during `run()`.
pub struct VmHandle<'dev, S = Running> {
    run: Arc<RunShared>,
    _not_static: PhantomData<&'dev ()>,
    state: S,
}

impl<'dev> VmHandle<'dev, Paused> {
    const fn new(run: Arc<RunShared>) -> Self {
        Self {
            run,
            _not_static: PhantomData,
            state: Paused {
                pending_attaches: Vec::new(),
            },
        }
    }

    /// Queue a detached command session for attachment when the VM starts.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::InvalidCommand`] if the same command handle was
    /// already queued.
    pub fn attach(&mut self, handle: CommandExecutionHandle) -> std::result::Result<(), ExecError> {
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

    /// Start guest execution and transition to a running handle.
    #[must_use]
    pub fn start(self) -> VmHandle<'dev, Running> {
        let mut attached = HashMap::new();
        for handle in self.state.pending_attaches {
            let command = self.run.attach_command(handle);
            attached.insert(command.id(), command);
        }
        self.run.start();
        VmHandle {
            run: self.run,
            _not_static: PhantomData,
            state: Running { attached },
        }
    }
}

impl<'dev> VmHandle<'dev, Running> {
    /// Take an attached session by ID.
    pub fn take_attached(&mut self, id: ExecId) -> Option<CommandExecution> {
        self.state.attached.remove(&id)
    }

    /// Start a command in the guest with piped stdin/stdout/stderr.
    #[must_use]
    pub fn exec(&self, argv: impl IntoIterator<Item = impl AsRef<str>>) -> ExecBuilder<'_, 'dev> {
        ExecBuilder::new(self, argv, false)
    }

    /// Start a validated command spec in the guest with piped stdin/stdout/stderr.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn exec_spec(&self, spec: CommandSpec) -> ExecBuilder<'_, 'dev> {
        ExecBuilder::from_spec(self, &spec, false)
    }

    /// Start a command in the guest with a PTY.
    #[must_use]
    pub fn exec_pty(
        &self,
        argv: impl IntoIterator<Item = impl AsRef<str>>,
    ) -> ExecBuilder<'_, 'dev> {
        ExecBuilder::new(self, argv, true)
    }

    /// Start a validated command spec in the guest with a PTY.
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn exec_pty_spec(&self, spec: CommandSpec) -> ExecBuilder<'_, 'dev> {
        ExecBuilder::from_spec(self, &spec, true)
    }

    async fn exec_inner(
        &self,
        spec: CommandSpec,
        pty: bool,
    ) -> std::result::Result<CommandExecution, ExecError> {
        self.run.exec(spec, pty).await
    }

    /// Request a graceful guest shutdown and wait for VM exit.
    pub async fn shutdown(&mut self) {
        self.run.shutdown().await;
    }

    /// Check if the guest has exited.
    #[must_use]
    pub fn has_exited(&self) -> bool {
        self.run.has_exited()
    }

    /// Wait until the guest exits.
    pub async fn wait_for_exit(&self) {
        self.run.wait_for_exit().await;
    }

    /// Receive the next memory pressure event from the guest.
    pub async fn recv_memory_pressure(&mut self) -> Option<MemoryPressureEvent> {
        self.run.recv_memory_pressure().await
    }

    /// Poll the next memory pressure event from the guest PSI monitor.
    pub fn poll_recv_memory_pressure(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Option<MemoryPressureEvent>> {
        self.run.poll_recv_memory_pressure(cx)
    }

    /// Return a `'static` exec-only handle.
    #[must_use]
    pub fn into_exec_only(self) -> VmHandle<'static, Running> {
        VmHandle {
            run: self.run,
            _not_static: PhantomData,
            state: self.state,
        }
    }
}

/// Builder for [`VmHandle::exec`] and [`VmHandle::exec_pty`].
pub struct ExecBuilder<'a, 'dev> {
    handle: &'a VmHandle<'dev, Running>,
    argv: Vec<String>,
    env: Vec<String>,
    cwd: String,
    pty: bool,
}

impl<'a, 'dev> ExecBuilder<'a, 'dev> {
    fn new(
        handle: &'a VmHandle<'dev, Running>,
        argv: impl IntoIterator<Item = impl AsRef<str>>,
        pty: bool,
    ) -> Self {
        Self {
            handle,
            argv: argv
                .into_iter()
                .map(|arg| arg.as_ref().to_string())
                .collect(),
            env: Vec::new(),
            cwd: String::new(),
            pty,
        }
    }

    fn from_spec(handle: &'a VmHandle<'dev, Running>, spec: &CommandSpec, pty: bool) -> Self {
        Self {
            handle,
            argv: spec
                .argv()
                .iter()
                .map(|arg| arg.as_str().to_string())
                .collect(),
            env: spec
                .env()
                .iter()
                .map(|entry| format!("{}={}", entry.key(), entry.value()))
                .collect(),
            cwd: spec.cwd().as_str().to_string(),
            pty,
        }
    }

    /// Add environment variables for the command (`KEY=VALUE` strings).
    #[must_use]
    pub fn env(mut self, env: impl IntoIterator<Item = impl AsRef<str>>) -> Self {
        self.env
            .extend(env.into_iter().map(|entry| entry.as_ref().to_string()));
        self
    }

    /// Set the working directory for the child process.
    #[must_use]
    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = cwd.into();
        self
    }
}

impl<'a> std::future::IntoFuture for ExecBuilder<'a, '_> {
    type Output = std::result::Result<CommandExecution, ExecError>;
    type IntoFuture =
        std::pin::Pin<Box<dyn std::future::Future<Output = Self::Output> + Send + 'a>>;

    fn into_future(self) -> Self::IntoFuture {
        Box::pin(async move {
            let mut spec = CommandSpec::new(self.argv)?;
            if !self.env.is_empty() {
                spec = spec.with_env(self.env)?;
            }
            if !self.cwd.is_empty() {
                spec = spec.with_cwd(self.cwd)?;
            }
            self.handle.exec_inner(spec, self.pty).await
        })
    }
}

/// Scheduler-owned counted output receiver.
///
/// This mirrors the VMM counted receiver shape while keeping accounting in the
/// scheduler's durable command registry instead of a single VMM run epoch.
pub struct CountedReceiver {
    inner: mpsc::Receiver<Vec<u8>>,
    items: Arc<std::sync::atomic::AtomicUsize>,
    bytes: Arc<std::sync::atomic::AtomicUsize>,
    wake: Arc<Notify>,
}

impl CountedReceiver {
    /// Poll the next item, decrementing the shared counters.
    pub fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Vec<u8>>> {
        match Pin::new(&mut self.inner).poll_recv(cx) {
            Poll::Ready(Some(bytes)) => {
                self.items.fetch_sub(1, Ordering::Relaxed);
                self.bytes.fetch_sub(bytes.len(), Ordering::AcqRel);
                self.wake.notify_waiters();
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
            self.wake.notify_waiters();
        }
    }
}

#[derive(Clone)]
struct CountedSender {
    inner: mpsc::Sender<Vec<u8>>,
    items: Arc<std::sync::atomic::AtomicUsize>,
    bytes: Arc<std::sync::atomic::AtomicUsize>,
}

impl CountedSender {
    fn try_send(&self, bytes: Vec<u8>) -> std::result::Result<(), CountedSendError> {
        let byte_len = bytes.len();
        if let Err(error) = self.reserve_bytes(byte_len) {
            return Err(match error {
                CountedSendReserveError::Full => CountedSendError::Full(bytes),
                CountedSendReserveError::TooLarge { len, max } => {
                    CountedSendError::TooLarge { len, max }
                }
            });
        }
        self.items.fetch_add(1, Ordering::Relaxed);
        match self.inner.try_send(bytes) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Closed(bytes)) => {
                drop(bytes);
                self.release(byte_len);
                Err(CountedSendError::Closed)
            }
            Err(mpsc::error::TrySendError::Full(bytes)) => {
                self.release(byte_len);
                Err(CountedSendError::Full(bytes))
            }
        }
    }

    fn pending_items(&self) -> usize {
        self.items.load(Ordering::Acquire)
    }

    fn pending_bytes(&self) -> usize {
        self.bytes.load(Ordering::Acquire)
    }

    fn reserve_bytes(&self, byte_len: usize) -> std::result::Result<(), CountedSendReserveError> {
        if byte_len > SCHEDULER_OUTPUT_STREAM_BUDGET {
            return Err(CountedSendReserveError::TooLarge {
                len: byte_len,
                max: SCHEDULER_OUTPUT_STREAM_BUDGET,
            });
        }
        let mut cur = self.bytes.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(byte_len) else {
                return Err(CountedSendReserveError::Full);
            };
            if next > SCHEDULER_OUTPUT_STREAM_BUDGET {
                return Err(CountedSendReserveError::Full);
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

#[derive(Debug)]
enum CountedSendError {
    Closed,
    Full(Vec<u8>),
    TooLarge { len: usize, max: usize },
}

#[derive(Debug)]
enum CountedSendReserveError {
    Full,
    TooLarge { len: usize, max: usize },
}

fn counted_channel(wake: Arc<Notify>) -> (CountedSender, CountedReceiver) {
    let (tx, rx) = mpsc::channel(SCHEDULER_OUTPUT_QUEUE_CAPACITY);
    let items = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    (
        CountedSender {
            inner: tx,
            items: Arc::clone(&items),
            bytes: Arc::clone(&bytes),
        },
        CountedReceiver {
            inner: rx,
            items,
            bytes,
            wake,
        },
    )
}

#[derive(Clone)]
struct SchedulerByteBudget {
    used: Arc<std::sync::atomic::AtomicUsize>,
    notify: Arc<Notify>,
    limit: usize,
}

impl SchedulerByteBudget {
    fn new(limit: usize) -> Self {
        Self {
            used: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            notify: Arc::new(Notify::new()),
            limit,
        }
    }

    fn try_acquire(
        &self,
        bytes: usize,
    ) -> std::result::Result<SchedulerByteCredit, SchedulerByteBudgetError> {
        if bytes > self.limit {
            return Err(SchedulerByteBudgetError::TooLarge {
                len: bytes,
                max: self.limit,
            });
        }
        let mut cur = self.used.load(Ordering::Relaxed);
        loop {
            let Some(next) = cur.checked_add(bytes) else {
                return Err(SchedulerByteBudgetError::Full);
            };
            if next > self.limit {
                return Err(SchedulerByteBudgetError::Full);
            }
            match self
                .used
                .compare_exchange_weak(cur, next, Ordering::AcqRel, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Ok(SchedulerByteCredit {
                        used: Arc::clone(&self.used),
                        notify: Arc::clone(&self.notify),
                        bytes,
                    });
                }
                Err(actual) => cur = actual,
            }
        }
    }

    async fn acquire(&self, bytes: usize) -> std::result::Result<SchedulerByteCredit, ExecError> {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            match self.try_acquire(bytes) {
                Ok(credit) => return Ok(credit),
                Err(SchedulerByteBudgetError::Full) => notified.await,
                Err(SchedulerByteBudgetError::TooLarge { len, max }) => {
                    return Err(ExecError::MessageTooLarge { len, max });
                }
            }
        }
    }
}

struct SchedulerByteCredit {
    used: Arc<std::sync::atomic::AtomicUsize>,
    notify: Arc<Notify>,
    bytes: usize,
}

impl Drop for SchedulerByteCredit {
    fn drop(&mut self) {
        self.used.fetch_sub(self.bytes, Ordering::AcqRel);
        self.notify.notify_waiters();
    }
}

enum SchedulerByteBudgetError {
    Full,
    TooLarge { len: usize, max: usize },
}

struct CommandIo {
    stdout: CountedSender,
    stderr: CountedSender,
    exit: std::sync::Mutex<Option<oneshot::Sender<i32>>>,
}

impl CommandIo {
    fn try_send_stdout(&self, bytes: Vec<u8>) -> std::result::Result<(), CountedSendError> {
        self.stdout.try_send(bytes)
    }

    fn try_send_stderr(&self, bytes: Vec<u8>) -> std::result::Result<(), CountedSendError> {
        self.stderr.try_send(bytes)
    }

    fn send_exit(&self, code: i32) {
        let tx = self
            .exit
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(tx) = tx {
            let _sent = tx.send(code);
        }
    }

    fn has_pending_output(&self) -> bool {
        self.stdout.pending_items() != 0
            || self.stderr.pending_items() != 0
            || self.stdout.pending_bytes() != 0
            || self.stderr.pending_bytes() != 0
    }
}

#[derive(Default)]
struct CommandControl {
    pending_writes: VecDeque<PendingWrite>,
    eof_requested: bool,
    pending_resize: Option<(u16, u16)>,
}

struct PendingWrite {
    data: Vec<u8>,
    done: oneshot::Sender<std::result::Result<(), ExecError>>,
    _credit: SchedulerByteCredit,
}

struct CommandShared {
    run_id: u64,
    id: ExecId,
    state: std::sync::Mutex<CommandSharedState>,
    stdin_budget: SchedulerByteBudget,
}

struct CommandSharedState {
    active_primitive: Option<PrimitiveCommandExecution>,
    primitive_handle: Option<PrimitiveCommandExecutionHandle>,
    io: Option<Arc<CommandIo>>,
    visible_detached: bool,
    completed: bool,
    dropped: bool,
    pending_scheduler_output_items: usize,
    pending_scheduler_output_bytes: usize,
    control: CommandControl,
}

fn validate_visible_detach_state(state: &CommandSharedState) -> std::result::Result<(), ExecError> {
    if state.completed {
        return Err(ExecError::NotReattachable {
            reason: "session has already exited or is not active",
        });
    }
    if let Some(io) = state.io.as_ref()
        && io.has_pending_output()
    {
        return Err(ExecError::NotReattachable {
            reason: "stdout/stderr has already been delivered to host channels",
        });
    }
    if state.pending_scheduler_output_items != 0 || state.pending_scheduler_output_bytes != 0 {
        return Err(ExecError::NotReattachable {
            reason: "stdout/stderr has already been delivered to host channels",
        });
    }
    if !state.control.pending_writes.is_empty()
        || state.control.eof_requested
        || state.control.pending_resize.is_some()
    {
        return Err(ExecError::NotReattachable {
            reason: "session control has pending host-side state",
        });
    }
    Ok(())
}

const fn exec_error_from_ref(error: &ExecError) -> ExecError {
    match error {
        ExecError::Disconnected => ExecError::Disconnected,
        ExecError::NotReattachable { reason } => ExecError::NotReattachable { reason },
        ExecError::MessageTooLarge { len, max } => ExecError::MessageTooLarge {
            len: *len,
            max: *max,
        },
        ExecError::InvalidCommand { reason } => ExecError::InvalidCommand { reason },
        ExecError::OutputLimitExceeded { attempted, limit } => ExecError::OutputLimitExceeded {
            attempted: *attempted,
            limit: *limit,
        },
        ExecError::ExecIdExhausted => ExecError::ExecIdExhausted,
    }
}

impl CommandShared {
    fn new(run_id: u64, id: ExecId) -> Arc<Self> {
        Arc::new(Self {
            run_id,
            id,
            stdin_budget: SchedulerByteBudget::new(SCHEDULER_STDIN_PENDING_BYTES),
            state: std::sync::Mutex::new(CommandSharedState {
                active_primitive: None,
                primitive_handle: None,
                io: None,
                visible_detached: false,
                completed: false,
                dropped: false,
                pending_scheduler_output_items: 0,
                pending_scheduler_output_bytes: 0,
                control: CommandControl::default(),
            }),
        })
    }

    fn from_handle(run_id: u64, handle: PrimitiveCommandExecutionHandle) -> Arc<Self> {
        let command = Self::new(run_id, handle.id());
        command.store_primitive_handle(handle);
        command
    }

    const fn run_id(&self) -> u64 {
        self.run_id
    }

    const fn id(&self) -> ExecId {
        self.id
    }

    fn trace_state_locked(&self, context: &str, state: &CommandSharedState) {
        if !log::log_enabled!(log::Level::Trace) {
            return;
        }
        log::trace!(
            "scheduler run#{} command id={} {context}: active_primitive={} primitive_handle={} io={} visible_detached={} completed={} dropped={} pending_scheduler_output_items={} pending_scheduler_output_bytes={} pending_writes={} eof_requested={} pending_resize={}",
            self.run_id,
            self.id,
            state.active_primitive.is_some(),
            state.primitive_handle.is_some(),
            state.io.is_some(),
            state.visible_detached,
            state.completed,
            state.dropped,
            state.pending_scheduler_output_items,
            state.pending_scheduler_output_bytes,
            state.control.pending_writes.len(),
            state.control.eof_requested,
            state.control.pending_resize.is_some(),
        );
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn attach_io(self: &Arc<Self>, run: Arc<RunShared>) -> CommandExecution {
        let (stdout_tx, stdout_rx) = counted_channel(Arc::clone(&run.notify));
        let (stderr_tx, stderr_rx) = counted_channel(Arc::clone(&run.notify));
        let (exit_tx, exit_rx) = oneshot::channel();
        let io = Arc::new(CommandIo {
            stdout: stdout_tx,
            stderr: stderr_tx,
            exit: std::sync::Mutex::new(Some(exit_tx)),
        });
        {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.io = Some(io);
            state.visible_detached = false;
            state.dropped = false;
            state.pending_scheduler_output_items = 0;
            state.pending_scheduler_output_bytes = 0;
            self.trace_state_locked("attached scheduler-visible io", &state);
        }
        run.notify.notify_waiters();
        CommandExecution {
            inner: Arc::clone(self),
            run,
            stdout_rx: Some(stdout_rx),
            stderr_rx: Some(stderr_rx),
            exit_rx: Some(exit_rx),
            detached: false,
            pending_exit: None,
        }
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn take_epoch_handle(&self) -> Option<PrimitiveCommandExecutionHandle> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.completed || state.visible_detached || state.io.is_none() {
            self.trace_state_locked("skipped epoch attachment", &state);
            return None;
        }
        let handle = state.primitive_handle.take();
        if handle.is_some() {
            self.trace_state_locked("took primitive handle for epoch attachment", &state);
        }
        handle
    }

    fn store_active_primitive(&self, command: PrimitiveCommandExecution) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_primitive = Some(command);
    }

    fn take_active_primitive(&self) -> Option<PrimitiveCommandExecution> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.active_primitive.take()
    }

    fn has_active_primitive(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active_primitive
            .is_some()
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn store_primitive_handle(&self, handle: PrimitiveCommandExecutionHandle) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.primitive_handle = Some(handle);
        self.trace_state_locked("stored detached primitive handle", &state);
    }

    fn io(&self) -> Option<Arc<CommandIo>> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .io
            .clone()
    }

    fn is_visible_detached(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .visible_detached
    }

    fn is_dropped(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .dropped
    }

    fn mark_completed(&self, code: i32) {
        let (io, pending_writes) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.completed = true;
            state.active_primitive = None;
            state.primitive_handle = None;
            self.trace_state_locked("marked command completed", &state);
            (
                state.io.take(),
                std::mem::take(&mut state.control.pending_writes),
            )
        };
        if let Some(io) = io {
            io.send_exit(code);
        }
        for write in pending_writes {
            let _sent = write.done.send(Err(ExecError::Disconnected));
        }
    }

    fn mark_abandoned(&self) {
        let pending_writes = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state.completed = true;
            state.visible_detached = false;
            state.active_primitive = None;
            state.primitive_handle = None;
            state.io = None;
            self.trace_state_locked("marked command abandoned", &state);
            std::mem::take(&mut state.control.pending_writes)
        };
        for write in pending_writes {
            let _sent = write.done.send(Err(ExecError::Disconnected));
        }
    }

    #[cfg(test)]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn add_pending_scheduler_output(&self, byte_len: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending_scheduler_output_items =
            state.pending_scheduler_output_items.saturating_add(1);
        state.pending_scheduler_output_bytes = state
            .pending_scheduler_output_bytes
            .saturating_add(byte_len);
    }

    // Reason: state guard spans validation, snapshot, and bookkeeping
    // so the result observes a consistent state.
    #[allow(clippy::significant_drop_tightening)]
    fn begin_output_forward(
        &self,
        byte_len: usize,
    ) -> std::result::Result<Option<Arc<CommandIo>>, ExecError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.visible_detached {
            self.trace_state_locked("rejecting output forward during visible detach", &state);
            return Err(ExecError::NotReattachable {
                reason: "stdout/stderr reached host while session was being detached",
            });
        }
        let Some(io) = state.io.clone() else {
            self.trace_state_locked("dropping output forward because io is detached", &state);
            return Ok(None);
        };
        state.pending_scheduler_output_items =
            state.pending_scheduler_output_items.saturating_add(1);
        state.pending_scheduler_output_bytes = state
            .pending_scheduler_output_bytes
            .saturating_add(byte_len);
        self.trace_state_locked("begin output forward", &state);
        Ok(Some(io))
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn remove_pending_scheduler_output(&self, byte_len: usize) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.pending_scheduler_output_items =
            state.pending_scheduler_output_items.saturating_sub(1);
        state.pending_scheduler_output_bytes = state
            .pending_scheduler_output_bytes
            .saturating_sub(byte_len);
        self.trace_state_locked("removed pending scheduler output", &state);
    }

    #[cfg(test)]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn mark_visible_detached(&self) -> std::result::Result<(), ExecError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        validate_visible_detach_state(&state)?;
        state.visible_detached = true;
        state.io = None;
        self.trace_state_locked("marked visible detached for test", &state);
        Ok(())
    }

    // Reason: each `state.lock()` scope is the minimal critical section
    // around its own state mutation; the locks intentionally cover the
    // entire block they appear in.
    #[allow(clippy::significant_drop_tightening)]
    fn detach_into_handle(
        &self,
    ) -> std::result::Result<PrimitiveCommandExecutionHandle, ExecError> {
        let primitive = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            validate_visible_detach_state(&state)?;
            if let Some(handle) = state.primitive_handle.take() {
                state.visible_detached = true;
                state.io = None;
                self.trace_state_locked("detached existing primitive handle", &state);
                return Ok(handle);
            }
            let Some(primitive) = state.active_primitive.take() else {
                self.trace_state_locked("failed visible detach without active primitive", &state);
                return Err(ExecError::NotReattachable {
                    reason: "session has already exited or is not active",
                });
            };
            state.visible_detached = true;
            self.trace_state_locked("taking active primitive for visible detach", &state);
            primitive
        };

        match primitive.into_handle() {
            Ok(handle) => {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.io = None;
                self.trace_state_locked("visible detach converted primitive into handle", &state);
                Ok(handle)
            }
            Err(error) => {
                let source = exec_error_from_ref(error.source());
                let primitive = error.into_command();
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.active_primitive = Some(primitive);
                state.visible_detached = false;
                self.trace_state_locked("visible detach failed; restored active primitive", &state);
                Err(source)
            }
        }
    }

    // Reason: state guard spans the credit-charge, queue-push, and
    // trace-record sequence so the queued frame and bookkeeping match.
    #[allow(clippy::significant_drop_tightening)]
    async fn enqueue_write(
        &self,
        data: Vec<u8>,
    ) -> std::result::Result<oneshot::Receiver<std::result::Result<(), ExecError>>, ExecError> {
        if data.len() > SCHEDULER_STDIN_CHUNK_MAX {
            return Err(ExecError::MessageTooLarge {
                len: data.len(),
                max: SCHEDULER_STDIN_CHUNK_MAX,
            });
        }
        let credit = self.stdin_budget.acquire(data.len()).await?;
        let (done, rx) = oneshot::channel();
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.completed || state.visible_detached {
            self.trace_state_locked("rejecting stdin write enqueue", &state);
            return Err(ExecError::Disconnected);
        }
        state.control.pending_writes.push_back(PendingWrite {
            data,
            done,
            _credit: credit,
        });
        self.trace_state_locked("enqueued stdin write", &state);
        Ok(rx)
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn request_close(&self) -> std::result::Result<(), ExecError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.completed || state.visible_detached {
            self.trace_state_locked("rejecting explicit stdin close", &state);
            return Err(ExecError::Disconnected);
        }
        state.control.eof_requested = true;
        self.trace_state_locked("queued explicit stdin close", &state);
        Ok(())
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn request_drop_eof(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.dropped = true;
        state.control.eof_requested = true;
        self.trace_state_locked("queued drop-triggered stdin close", &state);
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn request_resize(&self, rows: u16, cols: u16) -> std::result::Result<(), ExecError> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.completed || state.visible_detached {
            self.trace_state_locked("rejecting resize request", &state);
            return Err(ExecError::Disconnected);
        }
        state.control.pending_resize = Some((rows, cols));
        self.trace_state_locked("queued resize request", &state);
        Ok(())
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn pop_write(&self) -> Option<PendingWrite> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let write = state.control.pending_writes.pop_front();
        if write.is_some() {
            self.trace_state_locked("popped stdin write for primitive", &state);
        }
        write
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn take_close_request(&self) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.control.eof_requested {
            return false;
        }
        state.control.eof_requested = false;
        self.trace_state_locked("took stdin close request for primitive", &state);
        true
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn take_resize(&self) -> Option<(u16, u16)> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let resize = state.control.pending_resize.take();
        if resize.is_some() {
            self.trace_state_locked("took resize request for primitive", &state);
        }
        resize
    }
}

/// A running scheduler command in the guest with streaming I/O.
pub struct CommandExecution {
    inner: Arc<CommandShared>,
    run: Arc<RunShared>,
    stdout_rx: Option<CountedReceiver>,
    stderr_rx: Option<CountedReceiver>,
    exit_rx: Option<oneshot::Receiver<i32>>,
    detached: bool,
    pending_exit: Option<i32>,
}

impl CommandExecution {
    fn id(&self) -> ExecId {
        self.inner.id()
    }

    /// Get a clonable stdin writer for this command.
    #[must_use]
    pub fn stdin_writer(&self) -> StdinWriter {
        StdinWriter {
            inner: Arc::clone(&self.inner),
            run: Arc::clone(&self.run),
        }
    }

    /// Write data to the process's stdin.
    pub async fn write_stdin(&self, data: impl AsRef<[u8]>) -> std::result::Result<(), ExecError> {
        self.stdin_writer().write(data).await
    }

    /// Close the process's stdin.
    pub async fn close_stdin(&self) -> std::result::Result<(), ExecError> {
        self.stdin_writer().close().await
    }

    /// Resize the PTY window.
    pub async fn resize(&self, rows: u16, cols: u16) -> std::result::Result<(), ExecError> {
        self.stdin_writer().resize(rows, cols).await
    }

    /// Take the stdout receiver for concurrent use.
    #[must_use]
    pub const fn take_stdout(&mut self) -> Option<CountedReceiver> {
        self.stdout_rx.take()
    }

    /// Take the stderr receiver for concurrent use.
    #[must_use]
    pub const fn take_stderr(&mut self) -> Option<CountedReceiver> {
        self.stderr_rx.take()
    }

    /// Receive the next stdout chunk.
    pub async fn recv_stdout(&mut self) -> Option<Vec<u8>> {
        self.stdout_rx.as_mut()?.recv().await
    }

    /// Receive the next stderr chunk.
    pub async fn recv_stderr(&mut self) -> Option<Vec<u8>> {
        self.stderr_rx.as_mut()?.recv().await
    }

    /// Take the exit receiver for concurrent use.
    #[must_use]
    pub const fn take_exit(&mut self) -> Option<oneshot::Receiver<i32>> {
        self.exit_rx.take()
    }

    /// Wait for the process to exit.
    pub async fn wait(&mut self) -> std::result::Result<i32, ExecError> {
        let rx = self.exit_rx.as_mut().ok_or(ExecError::Disconnected)?;
        rx.await.map_err(|_| ExecError::Disconnected)
    }

    /// Receive the next output event.
    pub async fn recv_output(&mut self) -> Option<OutputEvent> {
        loop {
            let stdout_live = self.stdout_rx.is_some();
            let stderr_live = self.stderr_rx.is_some();
            let exit_live = self.exit_rx.is_some();

            if !stdout_live && !stderr_live {
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
                        None => self.stdout_rx = None,
                    }
                }
                data = async { self.stderr_rx.as_mut()?.recv().await }, if stderr_live => {
                    match data {
                        Some(bytes) => return Some(OutputEvent::Stderr(bytes)),
                        None => self.stderr_rx = None,
                    }
                }
                result = async {
                    match self.exit_rx.as_mut() {
                        Some(rx) => rx.await,
                        None => std::future::pending().await,
                    }
                }, if exit_live => {
                    self.exit_rx = None;
                    match result {
                        Ok(code) => self.pending_exit = Some(code),
                        Err(_) => return None,
                    }
                }
            }
        }
    }

    /// Close stdin, drain output with the default limit, and wait for exit.
    pub async fn collect_output(&mut self) -> std::result::Result<CollectedOutput, ExecError> {
        self.collect_output_with_limit(DEFAULT_COLLECT_OUTPUT_LIMIT)
            .await
    }

    /// Close stdin, drain output up to `limit`, and wait for exit.
    pub async fn collect_output_with_limit(
        &mut self,
        limit: usize,
    ) -> std::result::Result<CollectedOutput, ExecError> {
        match self.close_stdin().await {
            Ok(()) | Err(_) => {}
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

    /// Convert into a lightweight handle that can be attached in another run.
    pub fn into_handle(mut self) -> std::result::Result<CommandExecutionHandle, IntoHandleError> {
        let id = self.id();
        log::trace!(
            "scheduler run#{} command id={id} visible detach requested",
            self.inner.run_id()
        );
        let primitive = match self.inner.detach_into_handle() {
            Ok(handle) => handle,
            Err(source) => {
                log::trace!(
                    "scheduler run#{} command id={id} visible detach rejected: {source}",
                    self.inner.run_id()
                );
                return Err(IntoHandleError {
                    command: Box::new(self),
                    source,
                });
            }
        };
        drop(self.stdout_rx.take());
        drop(self.stderr_rx.take());
        drop(self.exit_rx.take());
        self.detached = true;
        self.run.registry.remove(self.inner.id());
        self.run.notify.notify_waiters();
        log::trace!(
            "scheduler run#{} command id={id} visible detach completed",
            self.inner.run_id()
        );
        Ok(CommandExecutionHandle { primitive })
    }
}

impl Drop for CommandExecution {
    fn drop(&mut self) {
        if self.detached {
            return;
        }
        log::trace!(
            "scheduler run#{} command id={} dropped while attached; queuing EOF",
            self.inner.run_id(),
            self.id()
        );
        self.inner.request_drop_eof();
        self.run.notify.notify_waiters();
    }
}

/// Lightweight handle representing a running guest command.
#[derive(Clone)]
pub struct CommandExecutionHandle {
    primitive: PrimitiveCommandExecutionHandle,
}

impl CommandExecutionHandle {
    /// Get the scheduler-visible session ID.
    #[must_use]
    pub const fn id(&self) -> ExecId {
        self.primitive.id()
    }
}

impl std::fmt::Debug for CommandExecutionHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CommandExecutionHandle")
            .field("id", &self.id())
            .finish()
    }
}

/// Error returned when a command cannot be converted into a reattach handle.
pub struct IntoHandleError {
    command: Box<CommandExecution>,
    source: ExecError,
}

impl IntoHandleError {
    /// Recover the command whose conversion failed.
    #[must_use]
    pub fn into_command(self) -> CommandExecution {
        *self.command
    }

    /// Return the reason conversion failed.
    #[must_use]
    pub const fn source(&self) -> &ExecError {
        &self.source
    }
}

impl std::fmt::Debug for IntoHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IntoHandleError")
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for IntoHandleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for IntoHandleError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Clonable handle for writing to a command's stdin.
#[derive(Clone)]
pub struct StdinWriter {
    inner: Arc<CommandShared>,
    run: Arc<RunShared>,
}

impl StdinWriter {
    /// Get the host-assigned session ID.
    #[must_use]
    pub fn id(&self) -> ExecId {
        self.inner.id()
    }

    /// Write data to stdin.
    pub async fn write(&self, data: impl AsRef<[u8]>) -> std::result::Result<(), ExecError> {
        self.write_owned(data.as_ref().to_vec()).await
    }

    /// Write owned data to stdin.
    pub async fn write_owned(&self, data: Vec<u8>) -> std::result::Result<(), ExecError> {
        let len = data.len();
        log::trace!(
            "scheduler run#{} command id={} stdin write requested bytes={len}",
            self.inner.run_id(),
            self.id()
        );
        let rx = self.inner.enqueue_write(data).await?;
        self.run.notify.notify_waiters();
        let result = rx.await.map_err(|_| ExecError::Disconnected)?;
        log::trace!(
            "scheduler run#{} command id={} stdin write completed result={result:?}",
            self.inner.run_id(),
            self.id()
        );
        result
    }

    /// Close stdin.
    pub async fn close(&self) -> std::result::Result<(), ExecError> {
        log::trace!(
            "scheduler run#{} command id={} stdin close requested",
            self.inner.run_id(),
            self.id()
        );
        self.inner.request_close()?;
        self.run.notify.notify_waiters();
        Ok(())
    }

    /// Resize the PTY window.
    pub async fn resize(&self, rows: u16, cols: u16) -> std::result::Result<(), ExecError> {
        log::trace!(
            "scheduler run#{} command id={} resize requested rows={rows} cols={cols}",
            self.inner.run_id(),
            self.id()
        );
        self.inner.request_resize(rows, cols)?;
        self.run.notify.notify_waiters();
        Ok(())
    }
}

const fn add_captured_output(
    captured: usize,
    chunk_len: usize,
    limit: usize,
) -> std::result::Result<usize, ExecError> {
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

const DEFAULT_QUANTUM: Duration = Duration::from_millis(100);
const RUN_REQUEST_QUEUE_CAPACITY: usize = 128;
const VM_STATUS_POLL_INTERVAL: Duration = Duration::from_millis(1);
const SCHEDULER_OUTPUT_QUEUE_CAPACITY: usize = 256;
const SCHEDULER_OUTPUT_STREAM_BUDGET: usize = 4 * 1024 * 1024;
const SCHEDULER_STDIN_CHUNK_MAX: usize = amla_constants::protocol::MAX_MESSAGE_SIZE;
const SCHEDULER_STDIN_PENDING_BYTES: usize = 1024 * 1024;
const SCHEDULER_MEMORY_PRESSURE_QUEUE_CAPACITY: usize = 32;

static NEXT_RUN_ID: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Default)]
struct VmCommandRegistry {
    commands: Arc<std::sync::Mutex<HashMap<ExecId, Arc<CommandShared>>>>,
}

impl VmCommandRegistry {
    fn insert(&self, command: Arc<CommandShared>) {
        let id = command.id();
        let run_id = command.run_id();
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(id, command);
        log::trace!("scheduler run#{run_id} registry inserted command id={id}");
    }

    fn remove(&self, id: ExecId) {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&id);
        log::trace!("scheduler registry removed command id={id}");
    }

    fn epoch_attachments(&self) -> Vec<(ExecId, PrimitiveCommandExecutionHandle)> {
        let attachments = self
            .commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter_map(|command| {
                command
                    .take_epoch_handle()
                    .map(|handle| (command.id(), handle))
            })
            .collect::<Vec<_>>();
        if !attachments.is_empty() {
            log::trace!(
                "scheduler registry yielded epoch attachments ids={:?}",
                attachments.iter().map(|(id, _)| *id).collect::<Vec<_>>()
            );
        }
        attachments
    }

    fn command(&self, id: ExecId) -> Option<Arc<CommandShared>> {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&id)
            .cloned()
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.commands
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }
}

fn complete_command(registry: &VmCommandRegistry, command: &CommandShared, code: i32) {
    log::trace!(
        "scheduler run#{} command id={} completing with exit_code={code}",
        command.run_id(),
        command.id()
    );
    command.mark_completed(code);
    registry.remove(command.id());
}

fn abandon_command(registry: &VmCommandRegistry, command: &CommandShared) {
    log::trace!(
        "scheduler run#{} command id={} abandoning",
        command.run_id(),
        command.id()
    );
    command.mark_abandoned();
    registry.remove(command.id());
}

enum RunRequest {
    Exec {
        spec: CommandSpec,
        pty: bool,
        done: oneshot::Sender<std::result::Result<CommandExecution, ExecError>>,
    },
    Shutdown {
        done: oneshot::Sender<()>,
    },
}

#[derive(Default)]
struct RunSharedState {
    started: bool,
    exited: bool,
}

struct RunShared {
    id: u64,
    requests: mpsc::Sender<RunRequest>,
    notify: Arc<Notify>,
    registry: VmCommandRegistry,
    state: std::sync::Mutex<RunSharedState>,
    exit_notify: Notify,
    memory_pressure_tx: mpsc::Sender<MemoryPressureEvent>,
    memory_pressure: std::sync::Mutex<mpsc::Receiver<MemoryPressureEvent>>,
    memory_pressure_exit_waker: std::sync::Mutex<Option<Waker>>,
}

impl RunShared {
    fn new(registry: VmCommandRegistry) -> (Arc<Self>, mpsc::Receiver<RunRequest>) {
        let (requests, request_rx) = mpsc::channel(RUN_REQUEST_QUEUE_CAPACITY);
        let (memory_pressure_tx, memory_pressure_rx) =
            mpsc::channel(SCHEDULER_MEMORY_PRESSURE_QUEUE_CAPACITY);
        let id = NEXT_RUN_ID.fetch_add(1, Ordering::Relaxed);
        (
            Arc::new(Self {
                id,
                requests,
                notify: Arc::new(Notify::new()),
                registry,
                state: std::sync::Mutex::new(RunSharedState::default()),
                exit_notify: Notify::new(),
                memory_pressure_tx,
                memory_pressure: std::sync::Mutex::new(memory_pressure_rx),
                memory_pressure_exit_waker: std::sync::Mutex::new(None),
            }),
            request_rx,
        )
    }

    const fn id(&self) -> u64 {
        self.id
    }

    fn start(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .started = true;
        log::trace!("scheduler run#{} marked started", self.id);
        self.notify.notify_one();
    }

    fn is_started(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .started
    }

    fn set_exited(&self) {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .exited = true;
        log::trace!("scheduler run#{} marked exited", self.id);
        self.exit_notify.notify_waiters();
        let waker = self
            .memory_pressure_exit_waker
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(waker) = waker {
            waker.wake();
        }
    }

    fn has_exited(&self) -> bool {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .exited
    }

    async fn wait_for_exit(&self) {
        log::trace!("scheduler run#{} waiting for exit", self.id);
        loop {
            let notified = self.exit_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.has_exited() {
                log::trace!("scheduler run#{} observed exit", self.id);
                return;
            }
            notified.await;
        }
    }

    async fn exec(
        &self,
        spec: CommandSpec,
        pty: bool,
    ) -> std::result::Result<CommandExecution, ExecError> {
        let (done, rx) = oneshot::channel();
        log::trace!(
            "scheduler run#{} queueing exec request pty={pty} spec={spec:?}",
            self.id
        );
        self.requests
            .send(RunRequest::Exec { spec, pty, done })
            .await
            .map_err(|_| ExecError::Disconnected)?;
        self.notify.notify_waiters();
        let result = rx.await.map_err(|_| ExecError::Disconnected)?;
        match &result {
            Ok(command) => {
                log::trace!(
                    "scheduler run#{} exec request completed id={}",
                    self.id,
                    command.id()
                );
            }
            Err(error) => {
                log::trace!("scheduler run#{} exec request failed: {error}", self.id);
            }
        }
        result
    }

    fn attach_command(self: &Arc<Self>, handle: CommandExecutionHandle) -> CommandExecution {
        log::trace!(
            "scheduler run#{} attaching command handle id={}",
            self.id,
            handle.id()
        );
        let command = CommandShared::from_handle(self.id, handle.primitive);
        self.registry.insert(Arc::clone(&command));
        command.attach_io(Arc::clone(self))
    }

    async fn shutdown(&self) {
        let (done, rx) = oneshot::channel();
        log::trace!("scheduler run#{} queueing shutdown request", self.id);
        if self
            .requests
            .send(RunRequest::Shutdown { done })
            .await
            .is_ok()
        {
            self.notify.notify_waiters();
            match rx.await {
                Ok(()) => log::trace!("scheduler run#{} shutdown request acknowledged", self.id),
                Err(_) => log::trace!("scheduler run#{} shutdown request ack dropped", self.id),
            }
        } else {
            log::trace!(
                "scheduler run#{} shutdown request channel already closed",
                self.id
            );
        }
        self.wait_for_exit().await;
    }

    async fn recv_memory_pressure(&self) -> Option<MemoryPressureEvent> {
        std::future::poll_fn(|cx| self.poll_recv_memory_pressure(cx)).await
    }

    fn poll_recv_memory_pressure(&self, cx: &mut Context<'_>) -> Poll<Option<MemoryPressureEvent>> {
        let mut memory_pressure = self
            .memory_pressure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.has_exited() {
            return Poll::Ready(memory_pressure.try_recv().ok());
        }
        match Pin::new(&mut *memory_pressure).poll_recv(cx) {
            Poll::Ready(event) => Poll::Ready(event),
            Poll::Pending => {
                if self.has_exited() {
                    return Poll::Ready(memory_pressure.try_recv().ok());
                }
                *self
                    .memory_pressure_exit_waker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cx.waker().clone());
                if self.has_exited() {
                    drop(
                        self.memory_pressure_exit_waker
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .take(),
                    );
                    return Poll::Ready(memory_pressure.try_recv().ok());
                }
                Poll::Pending
            }
        }
    }

    fn forward_memory_pressure(&self, event: MemoryPressureEvent) {
        log::trace!(
            "scheduler run#{} forwarding memory pressure event={event:?}",
            self.id
        );
        match self.memory_pressure_tx.try_send(event) {
            Ok(()) | Err(_) => {}
        }
    }
}

enum EpochVm<'dev> {
    Paused(PrimitiveVmHandle<'dev, PrimitivePaused>),
    Running(PrimitiveVmHandle<'dev, PrimitiveRunning>),
}

#[derive(Clone, Copy)]
enum CommandOutputStream {
    Stdout,
    Stderr,
}

impl CommandOutputStream {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }

    fn send(self, io: &CommandIo, bytes: Vec<u8>) -> std::result::Result<(), CountedSendError> {
        match self {
            Self::Stdout => io.try_send_stdout(bytes),
            Self::Stderr => io.try_send_stderr(bytes),
        }
    }
}

struct PendingSchedulerOutput {
    stream: CommandOutputStream,
    bytes: Vec<u8>,
}

struct ActiveCommand {
    inner: Arc<CommandShared>,
    stdout: Option<PrimitiveCountedReceiver>,
    stderr: Option<PrimitiveCountedReceiver>,
    exit: Option<oneshot::Receiver<i32>>,
    pending_exit: Option<i32>,
    pending_scheduler_output: Option<PendingSchedulerOutput>,
}

impl ActiveCommand {
    fn new(inner: &Arc<CommandShared>, mut command: PrimitiveCommandExecution) -> Self {
        log::trace!(
            "scheduler run#{} command id={} activated in epoch",
            inner.run_id(),
            inner.id()
        );
        let active = Self {
            stdout: command.take_stdout(),
            stderr: command.take_stderr(),
            exit: command.take_exit(),
            inner: Arc::clone(inner),
            pending_exit: None,
            pending_scheduler_output: None,
        };
        inner.store_active_primitive(command);
        active
    }

    const fn has_pending_scheduler_output(&self) -> bool {
        self.pending_scheduler_output.is_some()
    }

    fn has_pending_primitive_output(&self) -> bool {
        self.stdout
            .as_ref()
            .is_some_and(PrimitiveCountedReceiver::has_pending)
            || self
                .stderr
                .as_ref()
                .is_some_and(PrimitiveCountedReceiver::has_pending)
    }

    fn blocks_preemption(&self) -> bool {
        self.has_pending_scheduler_output() || self.has_pending_primitive_output()
    }

    fn retain_pending_scheduler_output(&mut self, stream: CommandOutputStream, bytes: Vec<u8>) {
        log::trace!(
            "scheduler run#{} command id={} retaining pending scheduler output stream={} bytes={}",
            self.inner.run_id(),
            self.inner.id(),
            stream.as_str(),
            bytes.len()
        );
        self.pending_scheduler_output = Some(PendingSchedulerOutput { stream, bytes });
    }

    fn try_flush_scheduler_output(&mut self) -> std::result::Result<(), ExecError> {
        let Some(pending) = self.pending_scheduler_output.take() else {
            return Ok(());
        };
        let Some(io) = self.inner.io() else {
            log::trace!(
                "scheduler run#{} command id={} dropping pending scheduler output because io is gone",
                self.inner.run_id(),
                self.inner.id()
            );
            self.inner
                .remove_pending_scheduler_output(pending.bytes.len());
            return Ok(());
        };
        let byte_len = pending.bytes.len();
        let stream = pending.stream;
        log::trace!(
            "scheduler run#{} command id={} flushing pending scheduler output stream={} bytes={byte_len}",
            self.inner.run_id(),
            self.inner.id(),
            stream.as_str(),
        );
        let result = stream.send(&io, pending.bytes);
        match result {
            Ok(()) | Err(CountedSendError::Closed) => {
                log::trace!(
                    "scheduler run#{} command id={} flushed pending scheduler output stream={}",
                    self.inner.run_id(),
                    self.inner.id(),
                    stream.as_str(),
                );
                self.inner.remove_pending_scheduler_output(byte_len);
                Ok(())
            }
            Err(CountedSendError::Full(bytes)) => {
                log::trace!(
                    "scheduler run#{} command id={} pending scheduler output still blocked stream={} bytes={}",
                    self.inner.run_id(),
                    self.inner.id(),
                    stream.as_str(),
                    bytes.len()
                );
                self.pending_scheduler_output = Some(PendingSchedulerOutput { stream, bytes });
                Ok(())
            }
            Err(CountedSendError::TooLarge { len, max }) => {
                Err(ExecError::MessageTooLarge { len, max })
            }
        }
    }
}

impl Drop for ActiveCommand {
    fn drop(&mut self) {
        if let Some(pending) = self.pending_scheduler_output.take() {
            self.inner
                .remove_pending_scheduler_output(pending.bytes.len());
        }
    }
}

fn trace_active_commands(context: &str, active: &HashMap<ExecId, ActiveCommand>) {
    if !log::log_enabled!(log::Level::Trace) {
        return;
    }
    let mut summary = String::new();
    for (index, (id, command)) in active.iter().enumerate() {
        if index != 0 {
            summary.push_str(", ");
        }
        if write!(
            &mut summary,
            "run#{}:{id}:stdout={} stderr={} exit={} pending_exit={:?} sched_pending={} primitive_pending={} dropped={} visible_detached={} has_active={}",
            command.inner.run_id(),
            command.stdout.is_some(),
            command.stderr.is_some(),
            command.exit.is_some(),
            command.pending_exit,
            command.has_pending_scheduler_output(),
            command.has_pending_primitive_output(),
            command.inner.is_dropped(),
            command.inner.is_visible_detached(),
            command.inner.has_active_primitive(),
        )
        .is_err()
        {
            return;
        }
    }
    log::trace!(
        "scheduler active commands {context}: count={} [{}]",
        active.len(),
        summary
    );
}

enum PrimitiveCommandEvent {
    Stdout(ExecId, Vec<u8>),
    Stderr(ExecId, Vec<u8>),
    ExitReady(ExecId, i32),
    StdoutClosed(ExecId),
    StderrClosed(ExecId),
    ExitClosed(ExecId),
}

enum PrimitiveVmEvent {
    MemoryPressure(MemoryPressureEvent),
    MemoryPressureClosed,
}

enum EpochOutcome<R> {
    Complete(R),
    Preempt,
}

enum PrimitiveResumeEpoch<'a, F: FsBackend, N: NetBackend> {
    Ready(ScheduledReady<'a, F, N>),
    Retry(PrimitiveVm<PrimitiveParked>),
    Failed(RawSchedulerResumeError),
}

/// Error returned by scheduler-owned run coordination inside one VM epoch.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerEpochError {
    /// Command/session coordination failed.
    #[error("{0}")]
    Exec(#[from] ExecError),
}

/// Maximum number of live backend shells the scheduler may hold at once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LiveShellLimit(NonZeroUsize);

impl LiveShellLimit {
    /// Create a live-shell limit from a non-zero value.
    #[must_use]
    pub const fn new(value: NonZeroUsize) -> Self {
        Self(value)
    }

    /// Return the underlying shell count.
    #[must_use]
    pub const fn get(self) -> usize {
        self.0.get()
    }
}

impl TryFrom<usize> for LiveShellLimit {
    type Error = SchedulerError;

    fn try_from(value: usize) -> std::result::Result<Self, Self::Error> {
        NonZeroUsize::new(value)
            .map(Self)
            .ok_or(SchedulerError::ZeroLiveShellLimit)
    }
}

#[derive(Clone, Debug)]
struct ShellBudget {
    inner: Arc<ShellBudgetInner>,
}

#[derive(Debug)]
struct ShellBudgetInner {
    state: std::sync::Mutex<ShellBudgetState>,
    notify: Notify,
}

#[derive(Debug)]
struct ShellBudgetState {
    limit: usize,
    live: usize,
    next_ticket: u64,
    waiters: VecDeque<AdmissionWaiter>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AdmissionWaiter {
    ticket: u64,
    priority: AdmissionPriority,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionPriority {
    Normal,
    Network,
}

impl ShellBudget {
    fn new(limit: LiveShellLimit) -> Self {
        Self {
            inner: Arc::new(ShellBudgetInner {
                state: std::sync::Mutex::new(ShellBudgetState {
                    limit: limit.get(),
                    live: 0,
                    next_ticket: 0,
                    waiters: VecDeque::new(),
                }),
                notify: Notify::new(),
            }),
        }
    }

    async fn acquire(
        &self,
        priority: AdmissionPriority,
    ) -> std::result::Result<ShellLease, SchedulerError> {
        let ticket = self.inner.enqueue(priority);
        log::trace!("scheduler shell budget waiting ticket={ticket} priority={priority:?}");
        let mut guard = AdmissionWaiterGuard::new(Arc::clone(&self.inner), ticket);
        loop {
            let notified = self.inner.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.inner.try_admit(ticket) {
                guard.disarm();
                log::trace!("scheduler shell budget admitted ticket={ticket}");
                return Ok(ShellLease::new(Arc::clone(&self.inner)));
            }
            notified.await;
        }
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        self.inner.available_slots()
    }

    fn has_preemption_pressure(&self) -> bool {
        self.inner.has_preemption_pressure()
    }

    fn live_count(&self) -> usize {
        self.inner.live_count()
    }
}

impl ShellBudgetInner {
    fn enqueue(&self, priority: AdmissionPriority) -> u64 {
        let (ticket, live, limit, waiters) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state
                .waiters
                .push_back(AdmissionWaiter { ticket, priority });
            (ticket, state.live, state.limit, state.waiters.len())
        };
        log::trace!(
            "scheduler shell budget enqueued ticket={ticket} priority={priority:?} live={live} limit={limit} waiters={waiters}"
        );
        self.notify.notify_waiters();
        ticket
    }

    fn try_admit(&self, ticket: u64) -> bool {
        let admit = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.live >= state.limit {
                log::trace!(
                    "scheduler shell budget cannot admit ticket={ticket}: live={} limit={} waiters={}",
                    state.live,
                    state.limit,
                    state.waiters.len()
                );
                return false;
            }
            let Some(index) = Self::selected_waiter_index(&state) else {
                log::trace!("scheduler shell budget cannot admit ticket={ticket}: no waiters");
                return false;
            };
            if state.waiters[index].ticket != ticket {
                log::trace!(
                    "scheduler shell budget ticket={ticket} waiting behind selected_ticket={}",
                    state.waiters[index].ticket
                );
                return false;
            }
            state.waiters.remove(index);
            state.live += 1;
            (
                state.live < state.limit && !state.waiters.is_empty(),
                state.live,
                state.limit,
                state.waiters.len(),
            )
        };
        let (should_notify, live, limit, waiters) = admit;
        log::trace!(
            "scheduler shell budget admitted ticket={ticket} live={live} limit={limit} waiters={waiters}"
        );
        if should_notify {
            self.notify.notify_waiters();
        }
        true
    }

    fn selected_waiter_index(state: &ShellBudgetState) -> Option<usize> {
        state
            .waiters
            .iter()
            .position(|waiter| waiter.priority == AdmissionPriority::Network)
            .or_else(|| (!state.waiters.is_empty()).then_some(0))
    }

    fn remove_waiter(&self, ticket: u64) {
        let removed = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            state
                .waiters
                .iter()
                .position(|waiter| waiter.ticket == ticket)
                .is_some_and(|index| {
                    state.waiters.remove(index);
                    true
                })
        };
        if removed {
            log::trace!("scheduler shell budget removed waiter ticket={ticket}");
            self.notify.notify_waiters();
        }
    }

    fn release(&self) {
        let (live, limit, waiters) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(state.live > 0, "released shell budget with no live shell");
            state.live = state.live.saturating_sub(1);
            (state.live, state.limit, state.waiters.len())
        };
        log::trace!("scheduler shell budget released live={live} limit={limit} waiters={waiters}");
        self.notify.notify_waiters();
    }

    fn release_after_resource_exhaustion(&self, _proof: NoLiveShellProof) {
        let (live, limit, waiters) = {
            let mut state = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            debug_assert!(
                state.live > 0,
                "released resource-exhausted shell budget with no live shell"
            );
            let observed_limit = state.live.saturating_sub(1).max(1);
            state.limit = state.limit.min(observed_limit);
            state.live = state.live.saturating_sub(1);
            (state.live, state.limit, state.waiters.len())
        };
        log::trace!(
            "scheduler shell budget released after resource exhaustion live={live} limit={limit} waiters={waiters}"
        );
        self.notify.notify_waiters();
    }

    fn has_preemption_pressure(&self) -> bool {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live >= state.limit && !state.waiters.is_empty()
    }

    fn live_count(&self) -> usize {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.live
    }

    #[cfg(test)]
    fn available_slots(&self) -> usize {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.limit.saturating_sub(state.live)
    }
}

#[derive(Debug)]
struct AdmissionWaiterGuard {
    inner: Arc<ShellBudgetInner>,
    ticket: u64,
    active: bool,
}

impl AdmissionWaiterGuard {
    const fn new(inner: Arc<ShellBudgetInner>, ticket: u64) -> Self {
        Self {
            inner,
            ticket,
            active: true,
        }
    }

    const fn disarm(&mut self) {
        self.active = false;
    }
}

impl Drop for AdmissionWaiterGuard {
    fn drop(&mut self) {
        if self.active {
            self.inner.remove_waiter(self.ticket);
        }
    }
}

#[derive(Debug)]
struct NoLiveShellProof(());

struct FailedVmmOperation {
    proof: NoLiveShellProof,
    error: amla_vmm::Error,
}

impl FailedVmmOperation {
    const fn new(error: amla_vmm::Error) -> std::result::Result<Self, amla_vmm::Error> {
        if matches!(
            &error,
            amla_vmm::Error::VmOperationFailedAndBackendCloseFailed { .. }
        ) {
            Err(error)
        } else {
            Ok(Self {
                proof: NoLiveShellProof(()),
                error,
            })
        }
    }
}

trait NoLiveShell: Sized {
    fn into_no_live_shell_proof(self) -> (NoLiveShellProof, Self);
}

impl NoLiveShell for PrimitiveVm<PrimitiveParked> {
    fn into_no_live_shell_proof(self) -> (NoLiveShellProof, Self) {
        (NoLiveShellProof(()), self)
    }
}

impl NoLiveShell for PrimitiveVm<PrimitiveZygote> {
    fn into_no_live_shell_proof(self) -> (NoLiveShellProof, Self) {
        (NoLiveShellProof(()), self)
    }
}

#[derive(Debug)]
struct ShellLease {
    budget: Option<Arc<ShellBudgetInner>>,
}

impl ShellLease {
    const fn new(budget: Arc<ShellBudgetInner>) -> Self {
        Self {
            budget: Some(budget),
        }
    }

    fn release_after_proof(mut self, _proof: NoLiveShellProof) {
        if let Some(budget) = self.budget.take() {
            budget.release();
        }
    }

    fn release_after<T: NoLiveShell>(self, value: T) -> T {
        let (proof, value) = value.into_no_live_shell_proof();
        self.release_after_proof(proof);
        value
    }

    fn release_after_failed_vmm_operation(mut self, error: amla_vmm::Error) -> amla_vmm::Error {
        let resource_exhausted = error.is_backend_resource_exhausted();
        match FailedVmmOperation::new(error) {
            Ok(failure) => {
                let FailedVmmOperation { proof, error } = failure;
                if resource_exhausted {
                    if let Some(budget) = self.budget.take() {
                        budget.release_after_resource_exhaustion(proof);
                    }
                } else {
                    self.release_after_proof(proof);
                }
                error
            }
            Err(error) => {
                let _unreleased_live_shell = self.budget.take();
                error
            }
        }
    }

    #[cfg(test)]
    fn release_after_resource_exhaustion_for_test(mut self) {
        if let Some(budget) = self.budget.take() {
            budget.release_after_resource_exhaustion(NoLiveShellProof(()));
        }
    }
}

impl Drop for ShellLease {
    fn drop(&mut self) {
        if let Some(budget) = self.budget.take() {
            budget.release();
        }
    }
}

/// Scheduler-owned backend pool manager.
#[derive(Clone)]
pub struct VmScheduler {
    inner: Arc<VmSchedulerInner>,
}

struct VmSchedulerInner {
    worker: WorkerProcessConfig,
    shell_budget: ShellBudget,
    pools: Mutex<HashMap<PoolShape, Arc<backend::BackendPools>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct PoolShape {
    vcpu_count: u32,
    topology: VmTopology,
}

impl PoolShape {
    fn from_config(config: &VmConfig) -> Result<Self> {
        Ok(Self {
            vcpu_count: config.vcpu_count,
            topology: config.topology()?,
        })
    }
}

struct ScheduledReady<'a, F: FsBackend, N: NetBackend = NullNetBackend> {
    inner: PrimitiveVm<PrimitiveReady<'a, F, N>>,
    lease: ShellLease,
}

impl<'a, F: FsBackend, N: NetBackend> ScheduledReady<'a, F, N> {
    const fn new(inner: PrimitiveVm<PrimitiveReady<'a, F, N>>, lease: ShellLease) -> Self {
        Self { inner, lease }
    }

    async fn run<Fn, R>(self, f: Fn) -> Result<(Self, R)>
    where
        Fn: AsyncFnOnce(PrimitiveVmHandle<'_, PrimitivePaused>) -> R,
    {
        let Self { inner, lease } = self;
        match inner.run(f).await {
            Ok((inner, result)) => Ok((Self { inner, lease }, result)),
            Err(error) => {
                let error = lease.release_after_failed_vmm_operation(error);
                Err(error)
            }
        }
    }

    async fn freeze(self) -> Result<PrimitiveVm<PrimitiveZygote>> {
        let Self { inner, lease } = self;
        match inner.freeze().await {
            Ok(zygote) => Ok(lease.release_after(zygote)),
            Err(error) => Err(lease.release_after_failed_vmm_operation(error)),
        }
    }

    async fn park(self) -> Result<PrimitiveVm<PrimitiveParked>> {
        let Self { inner, lease } = self;
        match inner.park().await {
            Ok(parked) => Ok(lease.release_after(parked)),
            Err(error) => Err(lease.release_after_failed_vmm_operation(error)),
        }
    }
}

fn poll_primitive_command_event(
    active: &mut HashMap<ExecId, ActiveCommand>,
    cx: &mut Context<'_>,
) -> Poll<PrimitiveCommandEvent> {
    for (&id, command) in active.iter_mut() {
        if command.has_pending_scheduler_output() {
            continue;
        }
        if let Some(code) = command.pending_exit
            && command.stdout.is_none()
            && command.stderr.is_none()
        {
            return Poll::Ready(PrimitiveCommandEvent::ExitReady(id, code));
        }

        if let Some(stdout) = command.stdout.as_mut() {
            match stdout.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    return Poll::Ready(PrimitiveCommandEvent::Stdout(id, bytes));
                }
                Poll::Ready(None) => return Poll::Ready(PrimitiveCommandEvent::StdoutClosed(id)),
                Poll::Pending => {}
            }
        }

        if let Some(stderr) = command.stderr.as_mut() {
            match stderr.poll_recv(cx) {
                Poll::Ready(Some(bytes)) => {
                    return Poll::Ready(PrimitiveCommandEvent::Stderr(id, bytes));
                }
                Poll::Ready(None) => return Poll::Ready(PrimitiveCommandEvent::StderrClosed(id)),
                Poll::Pending => {}
            }
        }

        if let Some(exit) = command.exit.as_mut() {
            match Pin::new(exit).poll(cx) {
                Poll::Ready(Ok(code)) => {
                    return Poll::Ready(PrimitiveCommandEvent::ExitReady(id, code));
                }
                Poll::Ready(Err(_)) => return Poll::Ready(PrimitiveCommandEvent::ExitClosed(id)),
                Poll::Pending => {}
            }
        }
    }
    Poll::Pending
}

fn primitive_has_exited(primitive: Option<&EpochVm<'_>>) -> bool {
    matches!(
        primitive,
        Some(EpochVm::Running(running)) if running.has_exited()
    )
}

fn forward_primitive_exit_if_needed(shared: &RunShared, primitive: Option<&EpochVm<'_>>) {
    if !shared.has_exited() && primitive_has_exited(primitive) {
        shared.set_exited();
    }
}

fn poll_primitive_vm_event(
    primitive: &mut Option<EpochVm<'_>>,
    memory_pressure_open: &mut bool,
    cx: &mut Context<'_>,
) -> Poll<PrimitiveVmEvent> {
    let Some(EpochVm::Running(running)) = primitive.as_mut() else {
        return Poll::Pending;
    };
    if *memory_pressure_open {
        match running.poll_recv_memory_pressure(cx) {
            Poll::Ready(Some(event)) => {
                return Poll::Ready(PrimitiveVmEvent::MemoryPressure(event));
            }
            Poll::Ready(None) => {
                *memory_pressure_open = false;
                return Poll::Ready(PrimitiveVmEvent::MemoryPressureClosed);
            }
            Poll::Pending => {}
        }
    }
    Poll::Pending
}

fn handle_primitive_output_event(
    active: &mut HashMap<ExecId, ActiveCommand>,
    id: ExecId,
    stream: CommandOutputStream,
    bytes: Vec<u8>,
) -> std::result::Result<(), ExecError> {
    let Some(command) = active.get_mut(&id) else {
        log::trace!(
            "scheduler command id={id} {} ignored; command inactive",
            stream.as_str()
        );
        return Ok(());
    };
    log::trace!(
        "scheduler run#{} command id={id} primitive {} event bytes={}",
        command.inner.run_id(),
        stream.as_str(),
        bytes.len()
    );
    let byte_len = bytes.len();
    if let Some(io) = command.inner.begin_output_forward(byte_len)? {
        match stream.send(&io, bytes) {
            Ok(()) | Err(CountedSendError::Closed) => {
                log::trace!(
                    "scheduler run#{} command id={id} forwarded {} bytes={byte_len}",
                    command.inner.run_id(),
                    stream.as_str()
                );
                command.inner.remove_pending_scheduler_output(byte_len);
            }
            Err(CountedSendError::Full(bytes)) => {
                command.retain_pending_scheduler_output(stream, bytes);
            }
            Err(CountedSendError::TooLarge { len, max }) => {
                command.inner.remove_pending_scheduler_output(byte_len);
                return Err(ExecError::MessageTooLarge { len, max });
            }
        }
    }
    Ok(())
}

fn handle_primitive_exit_ready(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
    id: ExecId,
    code: i32,
) {
    if let Some(mut command) = active.remove(&id) {
        log::trace!(
            "scheduler run#{} command id={id} primitive exit ready code={code}",
            command.inner.run_id()
        );
        command.exit = None;
        command.pending_exit = Some(code);
        if command.stdout.is_some() || command.stderr.is_some() {
            log::trace!(
                "scheduler run#{} command id={id} delaying completion until output streams close",
                command.inner.run_id()
            );
            active.insert(id, command);
        } else {
            complete_command(registry, &command.inner, code);
        }
    }
}

fn handle_primitive_stream_closed(
    active: &mut HashMap<ExecId, ActiveCommand>,
    id: ExecId,
    stream: CommandOutputStream,
) {
    if let Some(command) = active.get_mut(&id) {
        log::trace!(
            "scheduler run#{} command id={id} primitive {} closed",
            command.inner.run_id(),
            stream.as_str()
        );
        match stream {
            CommandOutputStream::Stdout => command.stdout = None,
            CommandOutputStream::Stderr => command.stderr = None,
        }
    }
}

fn handle_primitive_command_event(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
    event: PrimitiveCommandEvent,
) -> std::result::Result<(), ExecError> {
    match event {
        PrimitiveCommandEvent::Stdout(id, bytes) => {
            handle_primitive_output_event(active, id, CommandOutputStream::Stdout, bytes)?;
        }
        PrimitiveCommandEvent::Stderr(id, bytes) => {
            handle_primitive_output_event(active, id, CommandOutputStream::Stderr, bytes)?;
        }
        PrimitiveCommandEvent::ExitReady(id, code) => {
            handle_primitive_exit_ready(registry, active, id, code);
        }
        PrimitiveCommandEvent::StdoutClosed(id) => {
            handle_primitive_stream_closed(active, id, CommandOutputStream::Stdout);
        }
        PrimitiveCommandEvent::StderrClosed(id) => {
            handle_primitive_stream_closed(active, id, CommandOutputStream::Stderr);
        }
        PrimitiveCommandEvent::ExitClosed(id) => {
            if let Some(command) = active.get(&id) {
                log::trace!(
                    "scheduler run#{} command id={id} primitive exit channel closed",
                    command.inner.run_id()
                );
            } else {
                log::trace!("scheduler command id={id} primitive exit channel closed");
            }
            active.remove(&id);
            registry.remove(id);
            return Err(ExecError::Disconnected);
        }
    }
    Ok(())
}

async fn process_active_command_host_work(
    command: &mut ActiveCommand,
) -> std::result::Result<(), ExecError> {
    command.try_flush_scheduler_output()?;

    let Some(primitive) = command.inner.take_active_primitive() else {
        return Ok(());
    };

    while let Some(write) = command.inner.pop_write() {
        let byte_len = write.data.len();
        log::trace!(
            "scheduler run#{} command id={} forwarding stdin write to primitive bytes={byte_len}",
            command.inner.run_id(),
            command.inner.id()
        );
        let result = primitive.write_stdin(write.data).await;
        log::trace!(
            "scheduler run#{} command id={} primitive stdin write result={result:?}",
            command.inner.run_id(),
            command.inner.id()
        );
        let _sent = write.done.send(result);
    }

    if command.inner.take_close_request() {
        log::trace!(
            "scheduler run#{} command id={} forwarding stdin close to primitive",
            command.inner.run_id(),
            command.inner.id()
        );
        match primitive.close_stdin().await {
            Ok(()) => {
                log::trace!(
                    "scheduler run#{} command id={} primitive stdin close completed",
                    command.inner.run_id(),
                    command.inner.id()
                );
            }
            Err(error) => {
                log::trace!(
                    "scheduler run#{} command id={} primitive stdin close failed/ignored: {error}",
                    command.inner.run_id(),
                    command.inner.id()
                );
            }
        }
    }

    if let Some((rows, cols)) = command.inner.take_resize() {
        log::trace!(
            "scheduler run#{} command id={} forwarding resize to primitive rows={rows} cols={cols}",
            command.inner.run_id(),
            command.inner.id()
        );
        match primitive.resize(rows, cols).await {
            Ok(()) => {}
            Err(error) => {
                log::trace!(
                    "scheduler run#{} command id={} primitive resize failed/ignored: {error}",
                    command.inner.run_id(),
                    command.inner.id()
                );
            }
        }
    }
    command.inner.store_active_primitive(primitive);
    Ok(())
}

async fn process_command_host_work(
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<(), ExecError> {
    for command in active.values_mut() {
        process_active_command_host_work(command).await?;
    }
    Ok(())
}

fn start_epoch_if_needed(
    shared: &RunShared,
    primitive: &mut Option<EpochVm<'_>>,
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<(), ExecError> {
    if !shared.is_started() {
        return Ok(());
    }
    if !matches!(primitive.as_ref(), Some(EpochVm::Paused(_))) {
        return Ok(());
    }
    let Some(EpochVm::Paused(mut paused)) = primitive.take() else {
        unreachable!("primitive state was checked as paused above");
    };

    let attachments = shared.registry.epoch_attachments();
    let attached_ids = attachments
        .iter()
        .map(|(id, _handle)| *id)
        .collect::<Vec<_>>();
    log::trace!(
        "scheduler run#{} epoch starting primitive VM with attached command ids={attached_ids:?}",
        shared.id()
    );
    for (_id, handle) in attachments {
        paused.attach(handle)?;
    }

    let mut running = paused.start();
    for id in attached_ids {
        let Some(primitive_command) = running.take_attached(id) else {
            return Err(ExecError::Disconnected);
        };
        let Some(command) = shared.registry.command(id) else {
            return Err(ExecError::Disconnected);
        };
        active.insert(id, ActiveCommand::new(&command, primitive_command));
    }
    trace_active_commands("after epoch start attachments", active);
    *primitive = Some(EpochVm::Running(running));
    Ok(())
}

async fn process_run_request(
    shared: &Arc<RunShared>,
    primitive: &mut Option<EpochVm<'_>>,
    active: &mut HashMap<ExecId, ActiveCommand>,
    request: RunRequest,
) -> std::result::Result<(), ExecError> {
    let Some(EpochVm::Running(running)) = primitive.as_mut() else {
        return Ok(());
    };

    match request {
        RunRequest::Exec { spec, pty, done } => {
            log::trace!(
                "scheduler run#{} epoch handling exec request pty={pty} spec={spec:?}",
                shared.id()
            );
            let result = if pty {
                running.exec_pty_spec(spec).await
            } else {
                running.exec_spec(spec).await
            };
            let result = result.map(|primitive_command| {
                let id = primitive_command.stdin_writer().id();
                let command = CommandShared::new(shared.id(), id);
                shared.registry.insert(Arc::clone(&command));
                let scheduled = command.attach_io(Arc::clone(shared));
                active.insert(id, ActiveCommand::new(&command, primitive_command));
                scheduled
            });
            match &result {
                Ok(command) => log::trace!(
                    "scheduler run#{} epoch exec request produced command id={}",
                    shared.id(),
                    command.id()
                ),
                Err(error) => log::trace!(
                    "scheduler run#{} epoch exec request failed: {error}",
                    shared.id()
                ),
            }
            let _sent = done.send(result);
        }
        RunRequest::Shutdown { done } => {
            log::trace!(
                "scheduler run#{} epoch handling shutdown request",
                shared.id()
            );
            running.shutdown().await;
            log::trace!(
                "scheduler run#{} epoch primitive shutdown returned",
                shared.id()
            );
            shared.set_exited();
            let _sent = done.send(());
        }
    }
    Ok(())
}

async fn try_detach_active_command(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
    id: ExecId,
) -> std::result::Result<bool, ExecError> {
    log::trace!("scheduler command id={id} trying to detach active command");
    {
        let Some(command) = active.get_mut(&id) else {
            log::trace!("scheduler command id={id} already inactive before detach");
            return Ok(true);
        };
        process_active_command_host_work(command).await?;
    }

    let Some(command) = active.get_mut(&id) else {
        log::trace!("scheduler command id={id} inactive after host work during detach");
        return Ok(true);
    };
    if command.inner.is_visible_detached() && !command.inner.has_active_primitive() {
        active.remove(&id);
        log::trace!("scheduler command id={id} visible detach already completed");
        return Ok(true);
    }
    if let Some(code) = command.pending_exit
        && command.stdout.is_none()
        && command.stderr.is_none()
        && !command.has_pending_scheduler_output()
    {
        let Some(command) = active.remove(&id) else {
            return Err(ExecError::Disconnected);
        };
        complete_command(registry, &command.inner, code);
        log::trace!("scheduler command id={id} detach completed by command exit");
        return Ok(true);
    }
    if command.has_pending_scheduler_output() {
        log::trace!("scheduler command id={id} detach blocked by pending scheduler output");
        return Ok(false);
    }
    let dropped = command.inner.is_dropped();
    log::trace!("scheduler command id={id} converting primitive into handle dropped={dropped}");
    let primitive = command
        .inner
        .take_active_primitive()
        .ok_or(ExecError::Disconnected)?;
    match primitive.into_handle() {
        Ok(handle) => {
            let Some(command) = active.remove(&id) else {
                return Err(ExecError::Disconnected);
            };
            if dropped {
                abandon_command(registry, &command.inner);
                log::trace!("scheduler command id={id} detached dropped command and abandoned it");
            } else {
                command.inner.store_primitive_handle(handle);
                log::trace!("scheduler command id={id} detached active command into handle");
            }
            Ok(true)
        }
        Err(error) => {
            log::trace!(
                "scheduler command id={id} primitive into_handle failed during detach: {}",
                error.source()
            );
            let source_is_terminal = matches!(
                error.source(),
                ExecError::NotReattachable { reason }
                    if reason.contains("already exited") || reason.contains("not active")
            );
            command.inner.store_active_primitive(error.into_command());
            if source_is_terminal {
                if dropped {
                    let Some(command) = active.remove(&id) else {
                        return Err(ExecError::Disconnected);
                    };
                    abandon_command(registry, &command.inner);
                    log::trace!(
                        "scheduler command id={id} abandoned dropped terminal command after detach failure"
                    );
                    return Ok(true);
                }
                return Err(ExecError::Disconnected);
            }
            log::trace!("scheduler command id={id} detach made no progress");
            Ok(false)
        }
    }
}

async fn wait_for_detach_progress(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<(), ExecError> {
    trace_active_commands("waiting for detach progress", active);
    for command in active.values_mut() {
        command.try_flush_scheduler_output()?;
    }
    tokio::select! {
        event = std::future::poll_fn(|cx| poll_primitive_command_event(active, cx)), if !active.is_empty() => {
            log::trace!("scheduler detach wait observed primitive command event");
            handle_primitive_command_event(registry, active, event)?;
        }
        () = tokio::time::sleep(Duration::from_millis(1)) => {
            trace_active_commands("detach wait tick", active);
        }
    }
    Ok(())
}

async fn detach_all_for_preemption(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<bool, ExecError> {
    trace_active_commands("detach all for preemption start", active);
    while !active.is_empty() {
        if active.values().any(ActiveCommand::blocks_preemption) {
            trace_active_commands("preemption blocked by pending command output", active);
            return Ok(false);
        }
        let ids = active.keys().copied().collect::<Vec<_>>();
        let mut detached_any = false;
        for id in ids {
            detached_any |= try_detach_active_command(registry, active, id).await?;
        }
        if active.values().any(ActiveCommand::blocks_preemption) {
            trace_active_commands("preemption blocked after detach attempt", active);
            return Ok(false);
        }
        if !detached_any && !active.is_empty() {
            wait_for_detach_progress(registry, active).await?;
        }
    }
    log::trace!("scheduler preemption detached all active commands");
    Ok(true)
}

async fn process_visible_detaches(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<(), ExecError> {
    loop {
        let ids = active
            .iter()
            .filter_map(|(&id, command)| command.inner.is_visible_detached().then_some(id))
            .collect::<Vec<_>>();
        if ids.is_empty() {
            return Ok(());
        }

        log::trace!("scheduler processing visible detaches ids={ids:?}");
        let mut detached_all = true;
        for id in ids {
            detached_all &= try_detach_active_command(registry, active, id).await?;
        }
        if detached_all {
            return Ok(());
        }
        wait_for_detach_progress(registry, active).await?;
    }
}

async fn finish_visible_run(
    registry: &VmCommandRegistry,
    active: &mut HashMap<ExecId, ActiveCommand>,
) -> std::result::Result<(), ExecError> {
    loop {
        trace_active_commands("finish visible run loop", active);
        process_command_host_work(active).await?;
        process_visible_detaches(registry, active).await?;

        if active.is_empty() {
            log::trace!("scheduler finish visible run completed with no active commands");
            return Ok(());
        }

        let all_remaining_dropped = active.values().all(|command| command.inner.is_dropped());
        if !all_remaining_dropped {
            trace_active_commands(
                "finish visible run found still-attached active command",
                active,
            );
            return Err(ExecError::NotReattachable {
                reason: "active command was still attached when scheduler run returned",
            });
        }

        let ids = active.keys().copied().collect::<Vec<_>>();
        let mut detached_any = false;
        for id in ids {
            detached_any |= try_detach_active_command(registry, active, id).await?;
        }
        if !detached_any && !active.is_empty() {
            trace_active_commands(
                "finish visible run waiting for dropped command detach progress",
                active,
            );
            wait_for_detach_progress(registry, active).await?;
        }
    }
}

async fn run_epoch<R, U>(
    shared: Arc<RunShared>,
    shell_budget: ShellBudget,
    requests: &mut mpsc::Receiver<RunRequest>,
    primitive_paused: PrimitiveVmHandle<'_, PrimitivePaused>,
    mut user_fut: Pin<&mut U>,
) -> std::result::Result<EpochOutcome<R>, SchedulerEpochError>
where
    U: Future<Output = R>,
{
    let mut primitive = Some(EpochVm::Paused(primitive_paused));
    let mut active = HashMap::new();
    let mut memory_pressure_open = true;
    let quantum = tokio::time::sleep(DEFAULT_QUANTUM);
    tokio::pin!(quantum);
    let mut diagnostic_tick = tokio::time::interval(Duration::from_secs(1));
    diagnostic_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    log::trace!("scheduler run#{} epoch begin", shared.id());

    loop {
        start_epoch_if_needed(&shared, &mut primitive, &mut active)?;
        forward_primitive_exit_if_needed(&shared, primitive.as_ref());
        process_command_host_work(&mut active).await?;
        process_visible_detaches(&shared.registry, &mut active).await?;
        let running = matches!(primitive, Some(EpochVm::Running(_)));

        tokio::select! {
            biased;

            request = requests.recv(), if running => {
                match request {
                    Some(request) => process_run_request(&shared, &mut primitive, &mut active, request).await?,
                    None => return Err(ExecError::Disconnected.into()),
                }
            }
            result = user_fut.as_mut() => {
                log::trace!(
                    "scheduler run#{} epoch user future completed; finishing visible run",
                    shared.id()
                );
                start_epoch_if_needed(&shared, &mut primitive, &mut active)?;
                finish_visible_run(&shared.registry, &mut active).await?;
                log::trace!("scheduler run#{} epoch complete", shared.id());
                return Ok(EpochOutcome::Complete(result));
            }
            () = &mut quantum => {
                if !shell_budget.has_preemption_pressure() {
                    quantum
                        .as_mut()
                        .reset(tokio::time::Instant::now() + DEFAULT_QUANTUM);
                    continue;
                }
                log::trace!(
                    "scheduler run#{} epoch quantum expired under preemption pressure",
                    shared.id()
                );
                if detach_all_for_preemption(&shared.registry, &mut active).await? {
                    log::trace!(
                        "scheduler run#{} epoch preempting after detaching active commands",
                        shared.id()
                    );
                    return Ok(EpochOutcome::Preempt);
                }
                quantum
                    .as_mut()
                    .reset(tokio::time::Instant::now() + DEFAULT_QUANTUM);
            }
            event = std::future::poll_fn(|cx| poll_primitive_vm_event(&mut primitive, &mut memory_pressure_open, cx)), if running => {
                match event {
                    PrimitiveVmEvent::MemoryPressure(event) => shared.forward_memory_pressure(event),
                    PrimitiveVmEvent::MemoryPressureClosed => {
                        log::trace!(
                            "scheduler run#{} epoch primitive memory-pressure stream closed",
                            shared.id()
                        );
                    }
                }
            }
            () = shared.notify.notified() => {
                trace_active_commands("scheduler epoch notified", &active);
            }
            () = tokio::time::sleep(VM_STATUS_POLL_INTERVAL), if running && !shared.has_exited() => {
                forward_primitive_exit_if_needed(&shared, primitive.as_ref());
            }
            event = std::future::poll_fn(|cx| poll_primitive_command_event(&mut active, cx)), if !active.is_empty() => {
                log::trace!(
                    "scheduler run#{} epoch observed primitive command event",
                    shared.id()
                );
                handle_primitive_command_event(&shared.registry, &mut active, event)?;
            }
            _ = diagnostic_tick.tick(), if log::log_enabled!(log::Level::Trace) => {
                let primitive_state = match primitive.as_ref() {
                    Some(EpochVm::Paused(_)) => "paused",
                    Some(EpochVm::Running(_)) => "running",
                    None => "none",
                };
                log::trace!(
                    "scheduler run#{} epoch heartbeat primitive_state={primitive_state} running={running} started={} exited={} memory_pressure_open={memory_pressure_open}",
                    shared.id(),
                    shared.is_started(),
                    shared.has_exited(),
                );
                trace_active_commands("scheduler epoch heartbeat", &active);
            }
        }
    }
}

fn clone_pmem(pmem: &[MemHandle]) -> std::result::Result<Vec<MemHandle>, SchedulerOperationError> {
    pmem.iter()
        .map(MemHandle::try_clone)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(amla_vmm::Error::from)
        .map_err(SchedulerOperationError::Vmm)
}

const fn parked_vm_from_parts<F: FsBackend, N: NetBackend>(
    inner: PrimitiveVm<PrimitiveParked>,
    backends: RuntimeBackends<F, N>,
    commands: VmCommandRegistry,
    scheduler: VmScheduler,
) -> VirtualMachine<Parked<F, N>> {
    VirtualMachine {
        state: Parked {
            inner,
            backends,
            commands,
            scheduler,
        },
    }
}

fn scheduler_resume_run_error<F: FsBackend, N: NetBackend>(
    error: RawSchedulerResumeError,
    backends: RuntimeBackends<F, N>,
    commands: VmCommandRegistry,
    scheduler: VmScheduler,
) -> SchedulerRunError<F, N> {
    SchedulerRunError::Resume(Box::new(SchedulerResumeError::from_raw(
        error, backends, commands, scheduler,
    )))
}

async fn park_primitive_after_epoch<F: FsBackend, N: NetBackend>(
    ready: ScheduledReady<'_, F, N>,
    run: &RunShared,
    epoch_index: u64,
) -> std::result::Result<PrimitiveVm<PrimitiveParked>, SchedulerRunError<F, N>> {
    log::trace!(
        "scheduler run#{} epoch#{epoch_index}: parking primitive VM",
        run.id()
    );
    match ready.park().await {
        Ok(parked) => {
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: primitive VM parked",
                run.id()
            );
            Ok(parked)
        }
        Err(error) => {
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: park failed: {error}",
                run.id()
            );
            run.set_exited();
            Err(SchedulerRunError::Park(error))
        }
    }
}

// Reason: forwards to `is_backend_resource_exhausted` which we cannot
// make `const fn` on the cross-build targets (see error.rs).
#[allow(clippy::missing_const_for_fn)]
fn operation_error_is_resource_exhausted(error: &SchedulerOperationError) -> bool {
    match error {
        SchedulerOperationError::Vmm(error) => error.is_backend_resource_exhausted(),
        SchedulerOperationError::Scheduler(_) => false,
    }
}

impl VmScheduler {
    /// Create a scheduler using the given live-shell limit and worker settings.
    #[must_use]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub fn new(live_shell_limit: LiveShellLimit, worker: WorkerProcessConfig) -> Self {
        Self {
            inner: Arc::new(VmSchedulerInner {
                shell_budget: ShellBudget::new(live_shell_limit),
                worker,
                pools: Mutex::new(HashMap::new()),
            }),
        }
    }

    /// Create a scheduler-owned VM in the `New` state.
    pub async fn create_vm<F: FsBackend, N: NetBackend>(
        &self,
        config: VmConfig,
        backends: VmBackends<F, N>,
    ) -> Result<VirtualMachine<New<F, N>>> {
        Ok(VirtualMachine {
            state: New {
                inner: PrimitiveVm::create(config).await?,
                backends,
                scheduler: self.clone(),
            },
        })
    }

    async fn load_kernel_owned<F: FsBackend, N: NetBackend>(
        &self,
        vm: VirtualMachine<New<F, N>>,
        kernel: &[u8],
    ) -> std::result::Result<VirtualMachine<Parked<F, N>>, SchedulerOperationError> {
        let New {
            mut inner,
            backends,
            scheduler,
        } = vm.state;
        let (runtime, pmem) = backends.into_parts();
        let config = inner.config().clone();
        loop {
            let load_backends = amla_vmm::Backends {
                console: &runtime.console,
                net: runtime.net.as_ref(),
                fs: runtime.fs.as_ref(),
                pmem: clone_pmem(&pmem)?,
            };
            match self
                .load_kernel_primitive(inner, kernel, load_backends)
                .await
            {
                Ok(ready) => {
                    let parked = ready.park().await?;
                    return Ok(VirtualMachine {
                        state: Parked {
                            inner: parked,
                            backends: runtime,
                            commands: VmCommandRegistry::default(),
                            scheduler,
                        },
                    });
                }
                Err(error)
                    if operation_error_is_resource_exhausted(&error)
                        && self.inner.shell_budget.live_count() != 0 =>
                {
                    inner = PrimitiveVm::create(config.clone()).await?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    async fn spawn_owned<F: FsBackend, N: NetBackend>(
        &self,
        zygote: &VirtualMachine<Zygote>,
        backends: RuntimeBackends<F, N>,
    ) -> std::result::Result<VirtualMachine<Parked<F, N>>, SchedulerOperationError> {
        let ready = self
            .spawn_primitive(&zygote.state.inner, backends.as_spawn_backends())
            .await?;
        let parked = ready.park().await?;
        Ok(VirtualMachine {
            state: Parked {
                inner: parked,
                backends,
                commands: VmCommandRegistry::default(),
                scheduler: self.clone(),
            },
        })
    }

    async fn load_kernel_primitive<'a, F: FsBackend, N: NetBackend>(
        &self,
        vm: PrimitiveVm<PrimitiveNew>,
        kernel: &[u8],
        backends: amla_vmm::Backends<'a, F, N>,
    ) -> std::result::Result<ScheduledReady<'a, F, N>, SchedulerOperationError> {
        let pool = self.pool_for_config(vm.config()).await?;
        let lease = self
            .acquire_shell_permit_with_priority(AdmissionPriority::Normal)
            .await?;
        match vm.load_kernel(&pool, kernel, backends).await {
            Ok(ready) => Ok(ScheduledReady::new(ready, lease)),
            Err(error) => {
                let error = lease.release_after_failed_vmm_operation(error);
                Err(error.into())
            }
        }
    }

    async fn spawn_primitive<'a, F: FsBackend, N: NetBackend>(
        &self,
        zygote: &PrimitiveVm<PrimitiveZygote>,
        backends: amla_vmm::SpawnBackends<'a, F, N>,
    ) -> std::result::Result<ScheduledReady<'a, F, N>, SchedulerOperationError> {
        let pool = self.pool_for_config(zygote.config()).await?;
        let lease = self
            .acquire_shell_permit_with_priority(AdmissionPriority::Normal)
            .await?;
        match zygote.spawn(&pool, backends).await {
            Ok(ready) => Ok(ScheduledReady::new(ready, lease)),
            Err(error) => {
                let error = lease.release_after_failed_vmm_operation(error);
                Err(error.into())
            }
        }
    }

    async fn resume_primitive<'a, F: FsBackend, N: NetBackend>(
        &self,
        vm: PrimitiveVm<PrimitiveParked>,
        backends: amla_vmm::SpawnBackends<'a, F, N>,
    ) -> std::result::Result<ScheduledReady<'a, F, N>, RawSchedulerResumeError> {
        let pool = match self.pool_for_config(vm.config()).await {
            Ok(pool) => pool,
            Err(SchedulerOperationError::Vmm(error)) => {
                return Err(RawSchedulerResumeError::vmm(vm, error));
            }
            Err(SchedulerOperationError::Scheduler(error)) => {
                return Err(RawSchedulerResumeError::scheduler(vm, error));
            }
        };
        let lease = match self
            .acquire_shell_permit_with_priority(AdmissionPriority::Normal)
            .await
        {
            Ok(lease) => lease,
            Err(error) => return Err(RawSchedulerResumeError::scheduler(vm, error)),
        };
        match vm.resume(&pool, backends).await {
            Ok(ready) => Ok(ScheduledReady::new(ready, lease)),
            Err(error) => {
                let (vm, error) = error.into_parts();
                let error = lease.release_after_failed_vmm_operation(error);
                Err(RawSchedulerResumeError::vmm_parts(vm, error))
            }
        }
    }

    async fn resume_primitive_for_run<'a, F: FsBackend, N: NetBackend>(
        &self,
        vm: PrimitiveVm<PrimitiveParked>,
        backends: amla_vmm::SpawnBackends<'a, F, N>,
        runtime: &RuntimeBackends<F, N>,
    ) -> std::result::Result<ScheduledReady<'a, F, N>, RawSchedulerResumeError> {
        let pool = match self.pool_for_config(vm.config()).await {
            Ok(pool) => pool,
            Err(SchedulerOperationError::Vmm(error)) => {
                return Err(RawSchedulerResumeError::vmm(vm, error));
            }
            Err(SchedulerOperationError::Scheduler(error)) => {
                return Err(RawSchedulerResumeError::scheduler(vm, error));
            }
        };
        let lease = match self.acquire_run_shell_permit(runtime).await {
            Ok(lease) => lease,
            Err(error) => return Err(RawSchedulerResumeError::scheduler(vm, error)),
        };
        match vm.resume(&pool, backends).await {
            Ok(ready) => Ok(ScheduledReady::new(ready, lease)),
            Err(error) => {
                let (vm, error) = error.into_parts();
                let error = lease.release_after_failed_vmm_operation(error);
                Err(RawSchedulerResumeError::vmm_parts(vm, error))
            }
        }
    }

    async fn resume_primitive_epoch<'a, F: FsBackend, N: NetBackend>(
        &self,
        inner: PrimitiveVm<PrimitiveParked>,
        backends: &'a RuntimeBackends<F, N>,
        run_id: u64,
        epoch_index: u64,
    ) -> PrimitiveResumeEpoch<'a, F, N> {
        match self
            .resume_primitive_for_run(inner, backends.as_spawn_backends(), backends)
            .await
        {
            Ok(ready) => PrimitiveResumeEpoch::Ready(ready),
            Err(mut error)
                if operation_error_is_resource_exhausted(&error.error)
                    && self.inner.shell_budget.live_count() != 0 =>
            {
                log::trace!(
                    "scheduler run#{run_id} epoch#{epoch_index}: resume hit resource exhaustion; retrying with parked VM"
                );
                // Reason: clippy suggests `map_or_else`, but the else
                // branch needs to move `error` while the take() borrowed
                // it; a match is the cleanest expression of that flow.
                #[allow(clippy::option_if_let_else)]
                match error.vm.take() {
                    Some(vm) => PrimitiveResumeEpoch::Retry(vm),
                    None => PrimitiveResumeEpoch::Failed(error),
                }
            }
            Err(error) => {
                log::trace!(
                    "scheduler run#{run_id} epoch#{epoch_index}: resume failed: {}",
                    error.error
                );
                PrimitiveResumeEpoch::Failed(error)
            }
        }
    }

    async fn run_primitive_parked<F: FsBackend, N: NetBackend, Fn, R>(
        &self,
        mut inner: PrimitiveVm<PrimitiveParked>,
        backends: RuntimeBackends<F, N>,
        commands: VmCommandRegistry,
        f: Fn,
    ) -> std::result::Result<(VirtualMachine<Parked<F, N>>, R), SchedulerRunError<F, N>>
    where
        Fn: AsyncFnOnce(VmHandle<'_, Paused>) -> R,
    {
        let scheduler = self.clone();
        let (run, mut requests) = RunShared::new(commands.clone());
        let user_handle = VmHandle::new(Arc::clone(&run));
        let mut user_fut = Box::pin(f(user_handle));
        let mut epoch_index = 0u64;

        loop {
            epoch_index = epoch_index.wrapping_add(1);
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: resuming primitive VM",
                run.id()
            );
            let ready = match self
                .resume_primitive_epoch(inner, &backends, run.id(), epoch_index)
                .await
            {
                PrimitiveResumeEpoch::Ready(ready) => ready,
                PrimitiveResumeEpoch::Retry(vm) => {
                    inner = vm;
                    continue;
                }
                PrimitiveResumeEpoch::Failed(error) => {
                    run.set_exited();
                    return Err(scheduler_resume_run_error(
                        error, backends, commands, scheduler,
                    ));
                }
            };
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: primitive VM resumed",
                run.id()
            );

            let epoch_run = ready
                .run(async |handle| {
                    run_epoch(
                        Arc::clone(&run),
                        self.inner.shell_budget.clone(),
                        &mut requests,
                        handle,
                        user_fut.as_mut(),
                    )
                    .await
                })
                .await;
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: primitive run returned",
                run.id()
            );
            let (ready, epoch) = match epoch_run {
                Ok(result) => result,
                Err(error) => {
                    log::trace!(
                        "scheduler run#{} epoch#{epoch_index}: primitive run failed: {error}",
                        run.id()
                    );
                    run.set_exited();
                    return Err(SchedulerRunError::Run(error));
                }
            };
            let parked = park_primitive_after_epoch(ready, &run, epoch_index).await?;
            let epoch = match epoch {
                Ok(epoch) => epoch,
                Err(error) => {
                    log::trace!(
                        "scheduler run#{} epoch#{epoch_index}: scheduler epoch failed: {error}",
                        run.id()
                    );
                    run.set_exited();
                    return Err(SchedulerRunError::Scheduler(error));
                }
            };
            log::trace!(
                "scheduler run#{} epoch#{epoch_index}: scheduler epoch returned",
                run.id()
            );
            match epoch {
                EpochOutcome::Complete(result) => {
                    log::trace!("scheduler run#{} epoch#{epoch_index}: complete", run.id());
                    run.set_exited();
                    return Ok((
                        parked_vm_from_parts(parked, backends, commands, scheduler),
                        result,
                    ));
                }
                EpochOutcome::Preempt => {
                    log::trace!("scheduler run#{} epoch#{epoch_index}: preempted", run.id());
                    inner = parked;
                }
            }
        }
    }

    async fn freeze_primitive_parked<F: FsBackend, N: NetBackend>(
        &self,
        inner: PrimitiveVm<PrimitiveParked>,
        backends: RuntimeBackends<F, N>,
        commands: VmCommandRegistry,
    ) -> std::result::Result<VirtualMachine<Zygote>, SchedulerFreezeError<F, N>> {
        let scheduler = self.clone();
        let ready = match self
            .resume_primitive(inner, backends.as_spawn_backends())
            .await
        {
            Ok(ready) => ready,
            Err(error) => {
                return Err(SchedulerFreezeError::Resume(Box::new(
                    SchedulerResumeError::from_raw(error, backends, commands, scheduler),
                )));
            }
        };
        let zygote = ready.freeze().await.map_err(SchedulerFreezeError::Freeze)?;
        Ok(VirtualMachine {
            state: Zygote {
                inner: zygote,
                scheduler,
            },
        })
    }

    // Reason: pools lock covers the get-then-insert check; releasing
    // earlier would race two callers into double pool creation.
    #[allow(clippy::significant_drop_tightening)]
    async fn pool_for_config(
        &self,
        config: &VmConfig,
    ) -> std::result::Result<Arc<backend::BackendPools>, SchedulerOperationError> {
        let shape = PoolShape::from_config(config)?;
        let mut pools = self.inner.pools.lock().await;
        if let Some(pool) = pools.get(&shape) {
            return Ok(Arc::clone(pool));
        }
        let pool = Arc::new(backend::BackendPools::new(
            0,
            config,
            self.inner.worker.clone(),
        )?);
        pools.insert(shape, Arc::clone(&pool));
        Ok(pool)
    }

    async fn acquire_shell_permit_with_priority(
        &self,
        priority: AdmissionPriority,
    ) -> std::result::Result<ShellLease, SchedulerError> {
        self.inner.shell_budget.acquire(priority).await
    }

    async fn acquire_run_shell_permit<F: FsBackend, N: NetBackend>(
        &self,
        backends: &RuntimeBackends<F, N>,
    ) -> std::result::Result<ShellLease, SchedulerError> {
        let mut priority = if backends.take_scheduler_rx_wake() {
            AdmissionPriority::Network
        } else {
            AdmissionPriority::Normal
        };
        loop {
            if priority == AdmissionPriority::Network || !backends.has_scheduler_rx_wake() {
                return self.acquire_shell_permit_with_priority(priority).await;
            }
            tokio::select! {
                result = self.acquire_shell_permit_with_priority(priority) => return result,
                () = backends.wait_for_scheduler_rx() => {
                    priority = AdmissionPriority::Network;
                }
            }
        }
    }

    #[cfg(test)]
    async fn acquire_shell_permit(&self) -> std::result::Result<ShellLease, SchedulerError> {
        self.acquire_shell_permit_with_priority(AdmissionPriority::Normal)
            .await
    }
}

/// Scheduler configuration or runtime errors.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    /// A scheduler must be able to run at least one backend shell.
    #[error("live shell limit must be greater than zero")]
    ZeroLiveShellLimit,
}

/// Error returned by scheduler operations that create or spawn live VMs.
#[derive(Debug, thiserror::Error)]
pub enum SchedulerOperationError {
    /// Scheduler-owned shell budget or scheduling state failed.
    #[error("{0}")]
    Scheduler(#[from] SchedulerError),

    /// Primitive VMM operation failed.
    #[error("{0}")]
    Vmm(#[from] amla_vmm::Error),
}

struct RawSchedulerResumeError {
    vm: Option<PrimitiveVm<PrimitiveParked>>,
    error: SchedulerOperationError,
}

impl RawSchedulerResumeError {
    const fn scheduler(vm: PrimitiveVm<PrimitiveParked>, error: SchedulerError) -> Self {
        Self {
            vm: Some(vm),
            error: SchedulerOperationError::Scheduler(error),
        }
    }

    const fn vmm(vm: PrimitiveVm<PrimitiveParked>, error: amla_vmm::Error) -> Self {
        Self {
            vm: Some(vm),
            error: SchedulerOperationError::Vmm(error),
        }
    }

    const fn vmm_parts(vm: Option<PrimitiveVm<PrimitiveParked>>, error: amla_vmm::Error) -> Self {
        Self {
            vm,
            error: SchedulerOperationError::Vmm(error),
        }
    }
}

/// Error returned when the scheduler cannot resume a parked VM.
pub struct SchedulerResumeError<F: FsBackend, N: NetBackend = NullNetBackend> {
    vm: Option<VirtualMachine<Parked<F, N>>>,
    error: SchedulerOperationError,
}

impl<F: FsBackend, N: NetBackend> SchedulerResumeError<F, N> {
    fn from_raw(
        raw: RawSchedulerResumeError,
        backends: RuntimeBackends<F, N>,
        commands: VmCommandRegistry,
        scheduler: VmScheduler,
    ) -> Self {
        let RawSchedulerResumeError { vm, error } = raw;
        Self {
            vm: vm.map(|inner| VirtualMachine {
                state: Parked {
                    inner,
                    backends,
                    commands,
                    scheduler,
                },
            }),
            error,
        }
    }

    /// Borrow the underlying resume error.
    #[must_use]
    pub const fn error(&self) -> &SchedulerOperationError {
        &self.error
    }

    /// Split into the still-parked VM, when recovery is safe, and the error.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Option<VirtualMachine<Parked<F, N>>>,
        SchedulerOperationError,
    ) {
        (self.vm, self.error)
    }

    /// Discard the parked VM and return only the resume error.
    #[must_use]
    pub fn into_error(self) -> SchedulerOperationError {
        self.error
    }
}

impl<F: FsBackend, N: NetBackend> std::fmt::Debug for SchedulerResumeError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SchedulerResumeError")
            .field("has_vm", &self.vm.is_some())
            .field("error", &self.error)
            .finish()
    }
}

impl<F: FsBackend, N: NetBackend> std::fmt::Display for SchedulerResumeError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "failed to resume parked VM: {}", self.error)
    }
}

impl<F: FsBackend, N: NetBackend> std::error::Error for SchedulerResumeError<F, N> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

/// Error returned when freezing a parked scheduler VM fails.
pub enum SchedulerFreezeError<F: FsBackend, N: NetBackend = NullNetBackend> {
    /// The VM could not be resumed for freezing.
    Resume(Box<SchedulerResumeError<F, N>>),
    /// The primitive VMM freeze operation failed.
    Freeze(amla_vmm::Error),
}

impl<F: FsBackend, N: NetBackend> std::fmt::Debug for SchedulerFreezeError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume(error) => f.debug_tuple("Resume").field(error).finish(),
            Self::Freeze(error) => f.debug_tuple("Freeze").field(error).finish(),
        }
    }
}

impl<F: FsBackend, N: NetBackend> std::fmt::Display for SchedulerFreezeError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume(error) => write!(f, "{error}"),
            Self::Freeze(error) => write!(f, "scheduled VM freeze failed: {error}"),
        }
    }
}

impl<F: FsBackend + 'static, N: NetBackend + 'static> std::error::Error
    for SchedulerFreezeError<F, N>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error.as_ref()),
            Self::Freeze(error) => Some(error),
        }
    }
}

/// Error returned by one parked VM execution.
pub enum SchedulerRunError<F: FsBackend, N: NetBackend = NullNetBackend> {
    /// The VM could not be resumed.
    Resume(Box<SchedulerResumeError<F, N>>),
    /// Scheduler-owned VM run coordination failed.
    Scheduler(SchedulerEpochError),
    /// The VM failed while running.
    Run(amla_vmm::Error),
    /// The VM ran successfully but could not be parked afterward.
    Park(amla_vmm::Error),
}

impl<F: FsBackend, N: NetBackend> std::fmt::Debug for SchedulerRunError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume(error) => f.debug_tuple("Resume").field(error).finish(),
            Self::Scheduler(error) => f.debug_tuple("Scheduler").field(error).finish(),
            Self::Run(error) => f.debug_tuple("Run").field(error).finish(),
            Self::Park(error) => f.debug_tuple("Park").field(error).finish(),
        }
    }
}

impl<F: FsBackend, N: NetBackend> std::fmt::Display for SchedulerRunError<F, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resume(error) => write!(f, "{error}"),
            Self::Scheduler(error) => write!(f, "scheduled VM coordination failed: {error}"),
            Self::Run(error) => write!(f, "scheduled VM run failed: {error}"),
            Self::Park(error) => write!(f, "scheduled VM park failed: {error}"),
        }
    }
}

impl<F: FsBackend + 'static, N: NetBackend + 'static> std::error::Error
    for SchedulerRunError<F, N>
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Resume(error) => Some(error.as_ref()),
            Self::Scheduler(error) => Some(error),
            Self::Run(error) | Self::Park(error) => Some(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use amla_core::backends::NoRxPacket;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    #[test]
    fn live_shell_limit_rejects_zero() {
        let err = LiveShellLimit::try_from(0).unwrap_err();
        assert!(matches!(err, SchedulerError::ZeroLiveShellLimit));
    }

    #[tokio::test]
    async fn scheduler_reuses_pool_for_matching_topology() {
        if !amla_vmm::available() {
            return;
        }
        let limit = LiveShellLimit::try_from(2).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));
        let config = VmConfig::default();

        let first = scheduler.pool_for_config(&config).await.unwrap();
        let second = scheduler.pool_for_config(&config).await.unwrap();

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(scheduler.inner.pools.lock().await.len(), 1);
    }

    #[tokio::test]
    async fn scheduler_separates_different_queue_topologies() {
        if !amla_vmm::available() {
            return;
        }
        let limit = LiveShellLimit::try_from(2).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));
        let one_pair = VmConfig::default().net(NetConfig::default().queue_pairs(1).unwrap());
        let three_pairs = VmConfig::default().net(NetConfig::default().queue_pairs(3).unwrap());

        let first = scheduler.pool_for_config(&one_pair).await.unwrap();
        let second = scheduler.pool_for_config(&three_pairs).await.unwrap();

        assert!(!Arc::ptr_eq(&first, &second));
        assert_eq!(scheduler.inner.pools.lock().await.len(), 2);
    }

    #[tokio::test]
    async fn scheduler_shell_budget_waits_until_permit_is_released() {
        let limit = LiveShellLimit::try_from(1).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));

        let first = scheduler.acquire_shell_permit().await.unwrap();
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);

        let blocked =
            tokio::time::timeout(Duration::from_millis(10), scheduler.acquire_shell_permit()).await;
        assert!(blocked.is_err());

        first.release_after_proof(NoLiveShellProof(()));
        let second = scheduler.acquire_shell_permit().await.unwrap();
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);
        second.release_after_proof(NoLiveShellProof(()));
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 1);
    }

    #[tokio::test]
    async fn scheduler_shell_budget_learns_observed_resource_limit() {
        let limit = LiveShellLimit::try_from(4).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));

        let first = scheduler.acquire_shell_permit().await.unwrap();
        let second = scheduler.acquire_shell_permit().await.unwrap();
        let failed_attempt = scheduler.acquire_shell_permit().await.unwrap();
        failed_attempt.release_after_resource_exhaustion_for_test();

        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);
        let waiting = scheduler.acquire_shell_permit();
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err(),
            "learned limit should block admission while observed live shells remain"
        );

        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), &mut waiting)
            .await
            .unwrap()
            .unwrap();
        drop(second);
        drop(third);
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 2);
    }

    #[tokio::test]
    async fn dropped_admitted_shell_lease_releases_shell_budget() {
        let limit = LiveShellLimit::try_from(1).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));

        let first = scheduler.acquire_shell_permit().await.unwrap();
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);
        drop(first);

        assert_eq!(scheduler.inner.shell_budget.available_slots(), 1);
        let second = tokio::time::timeout(Duration::from_secs(1), scheduler.acquire_shell_permit())
            .await
            .expect("dropped lease should release shell budget")
            .expect("second permit should be admitted");
        second.release_after_proof(NoLiveShellProof(()));
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 1);
    }

    #[tokio::test]
    async fn failed_backend_close_keeps_shell_budget_consumed() {
        let limit = LiveShellLimit::try_from(1).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));

        let lease = scheduler.acquire_shell_permit().await.unwrap();
        let error = amla_vmm::Error::VmOperationFailedAndBackendCloseFailed {
            operation: "test",
            source: Box::new(amla_vmm::Error::VcpuExitedEarly),
            close: Box::new(amla_vmm::Error::VcpuExitedEarly),
        };
        let _error = lease.release_after_failed_vmm_operation(error);

        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);
        let blocked =
            tokio::time::timeout(Duration::from_millis(10), scheduler.acquire_shell_permit()).await;
        assert!(
            blocked.is_err(),
            "fatal backend-close failures must preserve live-shell accounting"
        );
    }

    #[tokio::test]
    async fn scheduler_preemption_pressure_requires_waiting_vm() {
        let limit = LiveShellLimit::try_from(3).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));

        let first = scheduler.acquire_shell_permit().await.unwrap();
        let second = scheduler.acquire_shell_permit().await.unwrap();
        assert!(!scheduler.inner.shell_budget.has_preemption_pressure());

        let third = scheduler.acquire_shell_permit().await.unwrap();
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 0);
        assert!(!scheduler.inner.shell_budget.has_preemption_pressure());

        {
            let fourth = scheduler.acquire_shell_permit();
            tokio::pin!(fourth);
            assert!(
                tokio::time::timeout(Duration::from_millis(10), fourth.as_mut())
                    .await
                    .is_err()
            );
            assert!(scheduler.inner.shell_budget.has_preemption_pressure());
        }
        assert!(!scheduler.inner.shell_budget.has_preemption_pressure());

        first.release_after_proof(NoLiveShellProof(()));
        second.release_after_proof(NoLiveShellProof(()));
        third.release_after_proof(NoLiveShellProof(()));
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 3);
    }

    #[tokio::test]
    async fn scheduler_shell_budget_prioritizes_network_waiters() {
        let limit = LiveShellLimit::try_from(1).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));
        let first = scheduler.acquire_shell_permit().await.unwrap();
        let normal = scheduler.acquire_shell_permit_with_priority(AdmissionPriority::Normal);
        let network = scheduler.acquire_shell_permit_with_priority(AdmissionPriority::Network);
        tokio::pin!(normal);
        tokio::pin!(network);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), normal.as_mut())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), network.as_mut())
                .await
                .is_err()
        );

        first.release_after_proof(NoLiveShellProof(()));
        let network_lease = tokio::time::timeout(Duration::from_secs(1), network.as_mut())
            .await
            .expect("network waiter should be admitted first")
            .expect("network waiter should acquire shell lease");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), normal.as_mut())
                .await
                .is_err()
        );

        network_lease.release_after_proof(NoLiveShellProof(()));
        let normal_lease = tokio::time::timeout(Duration::from_secs(1), normal.as_mut())
            .await
            .expect("normal waiter should be admitted after network")
            .expect("normal waiter should acquire shell lease");
        normal_lease.release_after_proof(NoLiveShellProof(()));
        assert_eq!(scheduler.inner.shell_budget.available_slots(), 1);
    }

    #[tokio::test]
    async fn scheduler_counted_output_channel_is_bounded() {
        let wake = Arc::new(Notify::new());
        let (tx, mut rx) = counted_channel(wake);
        let chunk = vec![b'x'];

        for _ in 0..SCHEDULER_OUTPUT_QUEUE_CAPACITY {
            tx.try_send(chunk.clone()).expect("channel should accept");
        }

        assert!(matches!(
            tx.try_send(chunk.clone()),
            Err(CountedSendError::Full(bytes)) if bytes == chunk
        ));
        assert_eq!(tx.pending_items(), SCHEDULER_OUTPUT_QUEUE_CAPACITY);

        assert_eq!(rx.recv().await, Some(chunk.clone()));
        tx.try_send(chunk).expect("drain should free one slot");
    }

    #[tokio::test]
    async fn scheduler_stdin_rejects_oversized_write_before_queueing() {
        let command = CommandShared::new(0, ExecId::FIRST);
        let Err(err) = command
            .enqueue_write(vec![b'x'; SCHEDULER_STDIN_CHUNK_MAX + 1])
            .await
        else {
            panic!("oversized stdin write should be rejected");
        };

        assert!(matches!(err, ExecError::MessageTooLarge { .. }));
        assert!(command.pop_write().is_none());
    }

    #[tokio::test]
    async fn scheduler_stdin_pending_queue_is_byte_bounded() {
        let command = CommandShared::new(0, ExecId::FIRST);
        let chunks = SCHEDULER_STDIN_PENDING_BYTES / SCHEDULER_STDIN_CHUNK_MAX;
        let mut receivers = Vec::with_capacity(chunks);
        for _ in 0..chunks {
            receivers.push(
                command
                    .enqueue_write(vec![b'x'; SCHEDULER_STDIN_CHUNK_MAX])
                    .await
                    .expect("write should consume stdin budget"),
            );
        }

        let second = command.enqueue_write(vec![b'y']);
        tokio::pin!(second);
        assert!(
            tokio::time::timeout(Duration::from_millis(10), second.as_mut())
                .await
                .is_err(),
            "second write should wait for scheduler stdin budget"
        );

        drop(command.pop_write());
        let rx = tokio::time::timeout(Duration::from_secs(1), second.as_mut())
            .await
            .expect("stdin budget should be released")
            .expect("second write should queue after budget release");
        receivers.push(rx);
        drop(receivers);
    }

    #[test]
    fn pending_scheduler_output_blocks_visible_detach() {
        let (run, _requests) = RunShared::new(VmCommandRegistry::default());
        let command = CommandShared::new(0, ExecId::FIRST);
        let _visible = command.attach_io(run);

        command.add_pending_scheduler_output(4);
        assert!(matches!(
            command.mark_visible_detached(),
            Err(ExecError::NotReattachable { .. })
        ));

        command.remove_pending_scheduler_output(4);
        command
            .mark_visible_detached()
            .expect("reattach should be allowed once transient output is gone");
    }

    #[test]
    fn in_flight_output_forward_blocks_visible_detach() {
        let (run, _requests) = RunShared::new(VmCommandRegistry::default());
        let command = CommandShared::new(0, ExecId::FIRST);
        let _visible = command.attach_io(run);

        let _io = command
            .begin_output_forward(4)
            .expect("output forwarding should start")
            .expect("visible command should have output channels");
        assert!(matches!(
            command.mark_visible_detached(),
            Err(ExecError::NotReattachable { .. })
        ));

        command.remove_pending_scheduler_output(4);
        command
            .mark_visible_detached()
            .expect("reattach should be allowed after forwarding completes");
    }

    #[test]
    fn command_completion_and_abandonment_prune_registry() {
        let registry = VmCommandRegistry::default();
        let completed = CommandShared::new(0, ExecId::FIRST);
        registry.insert(Arc::clone(&completed));
        assert_eq!(registry.len(), 1);

        complete_command(&registry, &completed, 0);
        assert_eq!(registry.len(), 0);

        let abandoned = CommandShared::new(0, ExecId::new(2).unwrap());
        registry.insert(Arc::clone(&abandoned));
        assert_eq!(registry.len(), 1);

        abandon_command(&registry, &abandoned);
        assert_eq!(registry.len(), 0);
    }

    #[tokio::test]
    async fn run_shared_forwards_memory_pressure_events() {
        let (run, _requests) = RunShared::new(VmCommandRegistry::default());
        let event = MemoryPressureEvent {
            level: 1,
            available_kb: 1024,
            total_kb: 4096,
        };

        run.forward_memory_pressure(event.clone());

        let received = run
            .recv_memory_pressure()
            .await
            .expect("memory pressure event should be forwarded");
        assert_eq!(received.level, event.level);
        assert_eq!(received.available_kb, event.available_kb);
        assert_eq!(received.total_kb, event.total_kb);
    }

    #[tokio::test]
    async fn run_shared_memory_pressure_returns_none_after_exit() {
        let (run, _requests) = RunShared::new(VmCommandRegistry::default());
        run.set_exited();

        let event = tokio::time::timeout(Duration::from_secs(1), run.recv_memory_pressure())
            .await
            .expect("memory pressure receive should not hang after exit");
        assert!(event.is_none());
    }

    #[tokio::test]
    async fn scheduler_run_admission_promotes_network_wake() {
        let limit = LiveShellLimit::try_from(1).unwrap();
        let scheduler = VmScheduler::new(limit, WorkerProcessConfig::path("unused-test-worker"));
        let first = scheduler.acquire_shell_permit().await.unwrap();
        let backend = RecordingNetBackend::default();
        let backend_probe = backend.clone();
        let normal_runtime = RuntimeBackends::new(ConsoleStream::new());
        let network_runtime = RuntimeBackends::new(ConsoleStream::new()).with_net(backend);
        let stable_backend_waker = backend_probe.stable_waker();
        let normal = scheduler.acquire_run_shell_permit(&normal_runtime);
        let network = scheduler.acquire_run_shell_permit(&network_runtime);
        tokio::pin!(normal);
        tokio::pin!(network);

        assert!(
            tokio::time::timeout(Duration::from_millis(10), normal.as_mut())
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), network.as_mut())
                .await
                .is_err()
        );

        stable_backend_waker.wake();
        assert!(
            tokio::time::timeout(Duration::from_millis(10), network.as_mut())
                .await
                .is_err()
        );
        first.release_after_proof(NoLiveShellProof(()));

        let network_lease = tokio::time::timeout(Duration::from_secs(1), network.as_mut())
            .await
            .expect("network wake should promote run admission")
            .expect("network wake should acquire shell lease");
        assert!(
            tokio::time::timeout(Duration::from_millis(10), normal.as_mut())
                .await
                .is_err()
        );

        network_lease.release_after_proof(NoLiveShellProof(()));
        let normal_lease = tokio::time::timeout(Duration::from_secs(1), normal.as_mut())
            .await
            .expect("normal admission should run after network wake")
            .expect("normal admission should acquire shell lease");
        normal_lease.release_after_proof(NoLiveShellProof(()));
    }

    #[derive(Clone, Default)]
    struct RecordingNetBackend {
        state: Arc<RecordingNetBackendState>,
    }

    #[derive(Default)]
    struct RecordingNetBackendState {
        waker: std::sync::Mutex<Option<RxWaker>>,
    }

    impl RecordingNetBackend {
        fn stable_waker(&self) -> RxWaker {
            self.state
                .waker
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .expect("network session installs backend waker")
                .clone()
        }
    }

    impl NetBackend for RecordingNetBackend {
        type RxPacket<'a> = NoRxPacket;

        fn send(&self, _bufs: &[IoSlice<'_>]) -> io::Result<()> {
            Ok(())
        }

        fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
            Ok(None)
        }

        fn set_nonblocking(&self, _nonblocking: bool) -> io::Result<()> {
            Ok(())
        }

        fn set_rx_waker(&self, waker: Option<RxWaker>) {
            let old = {
                let mut guard = self
                    .state
                    .waker
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                std::mem::replace(&mut *guard, waker)
            };
            if let Some(old) = old {
                old.cancel();
            }
        }
    }

    #[tokio::test]
    async fn network_session_keeps_scheduler_wake_after_device_waker_cancel() {
        let backend = RecordingNetBackend::default();
        let backend_probe = backend.clone();
        let session = NetworkSession::new(backend);
        let stable_backend_waker = backend_probe.stable_waker();
        let wake_count = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&wake_count);
        let device_waker = RxWaker::new(move || {
            counter.fetch_add(1, Ordering::Relaxed);
        });
        session.set_rx_waker(Some(device_waker.clone()));

        stable_backend_waker.wake();
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        assert!(session.take_rx_wake());

        device_waker.cancel();
        stable_backend_waker.wake();
        assert_eq!(wake_count.load(Ordering::Relaxed), 1);
        tokio::time::timeout(Duration::from_millis(1), session.wait_for_rx())
            .await
            .expect("stable backend wake should still wake scheduler");
    }

    #[tokio::test]
    async fn with_net_records_scheduler_rx_wake() {
        let backend = RecordingNetBackend::default();
        let backend_probe = backend.clone();
        let runtime = RuntimeBackends::new(ConsoleStream::new()).with_net(backend);
        let stable_backend_waker = backend_probe.stable_waker();

        stable_backend_waker.wake();

        assert!(runtime.take_scheduler_rx_wake());
        assert!(!runtime.take_scheduler_rx_wake());
    }
}
