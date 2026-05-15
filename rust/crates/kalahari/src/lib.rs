// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Native Node-API bindings for the Kalahari agent sandbox API.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::future::Future;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use amla_container as container;
use amla_container_engine as engine;
use amla_container_store::{ContainerStore, StoredImage};
use amla_oci::progress::NoProgress;
use amla_oci::reference::ImageSource;
use amla_policy_net::{Ipv4Subnet, Ipv6Subnet, NetworkPolicy, PolicyNetBackend};
use amla_usernet as usernet;
use amla_vm_scheduler as scheduler;
use base64::Engine;
use napi::bindgen_prelude::*;
use napi_derive::napi;
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;

const DEFAULT_NODE_IMAGE: &str = "node:22-alpine";
const DEFAULT_OUTPUT_LIMIT: u32 = 16 * 1024 * 1024;
const DEFAULT_REQUEST_QUEUE_SIZE: u32 = 64;
const DEFAULT_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(10);
const INIT_REATTACH_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const INIT_REATTACH_RETRY_DELAY: Duration = Duration::from_millis(1);
const COMMAND_STDIN_CHUNK_SIZE: usize = 32 * 1024;
// Private optimistic ceiling. The scheduler lowers this when typed backend
// resource exhaustion reveals the actual platform limit.
const SCHEDULER_LIVE_SHELL_DISCOVERY_LIMIT: usize = 128;

type ReadyCell = Arc<std::sync::Mutex<Option<oneshot::Sender<std::result::Result<(), String>>>>>;
type ShutdownReply = oneshot::Sender<std::result::Result<(), String>>;
type ZygoteCreateReply = oneshot::Sender<std::result::Result<ZygoteActorHandle, ZygoteCreateError>>;
type ScheduledContainerHandle<'a, 'dev> =
    container::ContainerHandle<'a, 'dev, scheduler::VmHandle<'dev>>;
type ActorJob = Box<dyn FnOnce() + Send + 'static>;
type StdinStep<'a> =
    Pin<Box<dyn Future<Output = std::result::Result<(), scheduler::ExecError>> + 'a>>;

static KALAHARI_SCHEDULER: std::sync::OnceLock<SchedulerInstance> = std::sync::OnceLock::new();
static KALAHARI_ACTOR_RUNTIME: std::sync::OnceLock<std::result::Result<ActorRuntime, String>> =
    std::sync::OnceLock::new();

#[napi(object)]
pub struct PrepareImageOptions {
    pub image: Option<String>,
    pub store_dir: Option<String>,
}

#[napi(object)]
pub struct PreparedImage {
    pub image: String,
    pub source: String,
    pub store_dir: String,
    pub manifest_digest: String,
    pub layers: u32,
    pub already_present: bool,
}

#[derive(Clone)]
#[napi(object)]
pub struct CreateSandboxOptions {
    pub image: Option<String>,
    pub prepare_image: Option<bool>,
    pub store_dir: Option<String>,
    pub worker_path: Option<String>,
    pub memory_mb: Option<u32>,
    pub vcpus: Option<u32>,
    pub timeout_ms: Option<u32>,
    pub output_limit_bytes: Option<u32>,
    pub request_queue_size: Option<u32>,
    pub network: Option<NetworkOptions>,
}

#[derive(Clone)]
#[napi(object)]
pub struct NetworkOptions {
    pub mode: Option<String>,
    pub dns: Option<String>,
    pub dns_mode: Option<String>,
    pub allow_list: Option<Vec<String>>,
}

impl Default for NetworkOptions {
    fn default() -> Self {
        Self {
            mode: Some("unrestricted".to_string()),
            dns: None,
            dns_mode: Some("unrestricted".to_string()),
            allow_list: None,
        }
    }
}

#[napi(object)]
pub struct RunCommandOptions {
    pub command: String,
    pub args: Option<Vec<String>>,
    pub stdin_base64: Option<String>,
    pub env: Option<Vec<String>>,
    pub cwd: Option<String>,
    pub timeout_ms: Option<u32>,
    pub output_limit_bytes: Option<u32>,
}

#[napi(object)]
pub struct CreatePtyOptions {
    pub command: String,
    pub args: Option<Vec<String>>,
    pub env: Option<Vec<String>>,
    pub cwd: Option<String>,
}

#[napi(object)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration_ms: f64,
}

#[napi(object)]
pub struct PtyOutput {
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub exit_code: Option<i32>,
}

struct ActorOptions {
    store_dir: PathBuf,
    image: String,
    requested_image: String,
    worker_path: Option<String>,
    memory_mb: u32,
    vcpus: u32,
    timeout_ms: Option<u32>,
    output_limit_bytes: u32,
    network: NetworkOptions,
}

impl Clone for ActorOptions {
    fn clone(&self) -> Self {
        Self {
            store_dir: self.store_dir.clone(),
            image: self.image.clone(),
            requested_image: self.requested_image.clone(),
            worker_path: self.worker_path.clone(),
            memory_mb: self.memory_mb,
            vcpus: self.vcpus,
            timeout_ms: self.timeout_ms,
            output_limit_bytes: self.output_limit_bytes,
            network: self.network.clone(),
        }
    }
}

struct ActorRuntime {
    jobs: mpsc::UnboundedSender<ActorJob>,
}

enum SandboxRequest {
    RunCommand {
        options: RunCommandOptions,
        reply: oneshot::Sender<std::result::Result<CommandResult, String>>,
    },
    Shutdown {
        reply: Option<ShutdownReply>,
    },
    CreateZygote {
        reply: ZygoteCreateReply,
    },
    StartPty {
        options: CreatePtyOptions,
        reply: oneshot::Sender<std::result::Result<String, String>>,
    },
    ReadPty {
        pty_id: String,
        reply: oneshot::Sender<std::result::Result<Option<PtyOutput>, String>>,
    },
    WritePty {
        pty_id: String,
        data: Vec<u8>,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    ResizePty {
        pty_id: String,
        rows: u32,
        cols: u32,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    ClosePty {
        pty_id: String,
        reply: oneshot::Sender<std::result::Result<(), String>>,
    },
    PtyOutput {
        pty_id: String,
        output: Option<PtyOutput>,
    },
}

enum ZygoteRequest {
    Spawn {
        options: Box<CreateSandboxOptions>,
        reply: oneshot::Sender<std::result::Result<SandboxActorHandle, String>>,
    },
    Destroy {
        reply: Option<ShutdownReply>,
    },
}

struct SandboxActorHandle {
    id: String,
    image: String,
    requested_image: String,
    store_dir: String,
    created_at_ms: f64,
    requests: mpsc::Sender<SandboxRequest>,
}

struct ZygoteActorHandle {
    id: String,
    image: String,
    requested_image: String,
    store_dir: String,
    created_at_ms: f64,
    requests: mpsc::Sender<ZygoteRequest>,
}

enum ActorExit {
    Shutdown,
    Zygote {
        init_handle: scheduler::CommandExecutionHandle,
        reply: ZygoteCreateReply,
    },
}

enum ActorLoopExit {
    Shutdown {
        init: scheduler::CommandExecution,
        shutdown_replies: Vec<ShutdownReply>,
    },
    Zygote {
        init_handle: scheduler::CommandExecutionHandle,
        reply: ZygoteCreateReply,
    },
}

enum ZygoteRequestOutcome {
    Continue(scheduler::CommandExecution),
    Exit(ActorLoopExit),
}

enum CommandOrShutdown {
    Completed(anyhow::Result<CommandResult>),
    Abandoned(anyhow::Error),
    Shutdown { reply: Option<ShutdownReply> },
    RequestChannelClosed,
}

enum RunCommandRequestOutcome {
    Continue { abandoned: bool },
    Shutdown,
}

#[derive(Debug)]
enum ZygoteCreateError {
    Recoverable(String),
    Fatal(String),
}

struct PtySessionState {
    writer: Option<scheduler::StdinWriter>,
    output: PtyOutputState,
}

struct PtyOutputState {
    buffered: VecDeque<Option<PtyOutput>>,
    pending_reads: VecDeque<oneshot::Sender<std::result::Result<Option<PtyOutput>, String>>>,
    closed: bool,
}

struct CommandStdin {
    chunks: VecDeque<Vec<u8>>,
    close_pending: bool,
}

#[derive(Clone, Copy)]
struct CommandDefaults {
    timeout_ms: Option<u32>,
    output_limit_bytes: u32,
}

struct SandboxQuiescence {
    abandoned_foreground_commands: usize,
}

impl PtySessionState {
    const fn new(writer: scheduler::StdinWriter) -> Self {
        Self {
            writer: Some(writer),
            output: PtyOutputState::new(),
        }
    }
}

impl PtyOutputState {
    const fn new() -> Self {
        Self {
            buffered: VecDeque::new(),
            pending_reads: VecDeque::new(),
            closed: false,
        }
    }
}

impl SandboxQuiescence {
    const fn new() -> Self {
        Self {
            abandoned_foreground_commands: 0,
        }
    }

    const fn record_abandoned_foreground_command(&mut self) {
        self.abandoned_foreground_commands = self.abandoned_foreground_commands.saturating_add(1);
    }

    fn zygote_error(&self) -> Option<ZygoteCreateError> {
        (self.abandoned_foreground_commands != 0).then(|| {
            ZygoteCreateError::recoverable(format!(
                "cannot zygote a Kalahari sandbox after {} foreground command(s) were abandoned by timeout or output limit",
                self.abandoned_foreground_commands
            ))
        })
    }
}

impl CommandStdin {
    fn new(stdin: Option<Vec<u8>>) -> Self {
        let chunks = stdin
            .map(|stdin| {
                stdin
                    .chunks(COMMAND_STDIN_CHUNK_SIZE)
                    .map(<[u8]>::to_vec)
                    .collect()
            })
            .unwrap_or_default();
        Self {
            chunks,
            close_pending: true,
        }
    }

    fn next_step<'a>(&mut self, writer: &'a scheduler::StdinWriter) -> Option<StdinStep<'a>> {
        if let Some(chunk) = self.chunks.pop_front() {
            return Some(Box::pin(writer.write_owned(chunk)));
        }
        if self.close_pending {
            self.close_pending = false;
            return Some(Box::pin(writer.close()));
        }
        None
    }
}

impl ZygoteCreateError {
    fn recoverable(message: impl Into<String>) -> Self {
        Self::Recoverable(message.into())
    }

    fn fatal(message: impl Into<String>) -> Self {
        Self::Fatal(message.into())
    }

    const fn is_fatal(&self) -> bool {
        matches!(self, Self::Fatal(_))
    }

    fn into_message(self) -> String {
        match self {
            Self::Recoverable(message) | Self::Fatal(message) => message,
        }
    }
}

/// Long-lived native Kalahari sandbox handle used by public SDK adapters.
#[napi]
pub struct KalahariNativeSandbox {
    id: String,
    image: String,
    requested_image: String,
    store_dir: String,
    created_at_ms: f64,
    destroyed: Arc<AtomicBool>,
    transitioning: Arc<AtomicBool>,
    requests: mpsc::Sender<SandboxRequest>,
}

#[napi]
pub struct KalahariNativeZygote {
    id: String,
    image: String,
    requested_image: String,
    store_dir: String,
    created_at_ms: f64,
    destroyed: Arc<AtomicBool>,
    requests: mpsc::Sender<ZygoteRequest>,
}

#[napi]
pub struct KalahariPtySession {
    id: String,
    sandbox_id: String,
    requests: mpsc::Sender<SandboxRequest>,
    closed: Arc<AtomicBool>,
}

impl KalahariNativeSandbox {
    fn from_actor(handle: SandboxActorHandle) -> Self {
        Self {
            id: handle.id,
            image: handle.image,
            requested_image: handle.requested_image,
            store_dir: handle.store_dir,
            created_at_ms: handle.created_at_ms,
            destroyed: Arc::new(AtomicBool::new(false)),
            transitioning: Arc::new(AtomicBool::new(false)),
            requests: handle.requests,
        }
    }

    fn ensure_active(&self) -> Result<()> {
        self.ensure_active_message().map_err(napi_error)
    }

    fn ensure_active_message(&self) -> std::result::Result<(), String> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(format!("Kalahari sandbox {} is not running", self.id));
        }
        if self.transitioning.load(Ordering::Acquire) {
            return Err(format!(
                "Kalahari sandbox {} is changing lifecycle state",
                self.id
            ));
        }
        Ok(())
    }

    async fn zygote_inner(&self) -> std::result::Result<KalahariNativeZygote, String> {
        self.ensure_active_message()?;
        if self.transitioning.swap(true, Ordering::AcqRel) {
            return Err(format!(
                "Kalahari sandbox {} is changing lifecycle state",
                self.id
            ));
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        let send_result = self
            .requests
            .send(SandboxRequest::CreateZygote { reply: reply_tx })
            .await;
        if send_result.is_err() {
            self.destroyed.store(true, Ordering::Release);
            self.transitioning.store(false, Ordering::Release);
            return Err("Kalahari sandbox worker has stopped".to_string());
        }

        let Ok(reply) = reply_rx.await else {
            self.destroyed.store(true, Ordering::Release);
            self.transitioning.store(false, Ordering::Release);
            return Err("Kalahari sandbox worker dropped zygote reply".to_string());
        };

        match reply {
            Ok(handle) => {
                self.destroyed.store(true, Ordering::Release);
                self.transitioning.store(false, Ordering::Release);
                Ok(KalahariNativeZygote::from_actor(handle))
            }
            Err(error) => {
                if error.is_fatal() {
                    self.destroyed.store(true, Ordering::Release);
                }
                self.transitioning.store(false, Ordering::Release);
                Err(error.into_message())
            }
        }
    }
}

impl KalahariNativeZygote {
    fn from_actor(handle: ZygoteActorHandle) -> Self {
        Self {
            id: handle.id,
            image: handle.image,
            requested_image: handle.requested_image,
            store_dir: handle.store_dir,
            created_at_ms: handle.created_at_ms,
            destroyed: Arc::new(AtomicBool::new(false)),
            requests: handle.requests,
        }
    }
}

#[napi]
impl KalahariNativeSandbox {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[napi(getter)]
    pub fn image(&self) -> String {
        self.image.clone()
    }

    #[napi(getter)]
    pub fn requested_image(&self) -> String {
        self.requested_image.clone()
    }

    #[napi(getter)]
    pub fn store_dir(&self) -> String {
        self.store_dir.clone()
    }

    #[napi(getter)]
    pub const fn created_at_ms(&self) -> f64 {
        self.created_at_ms
    }

    #[napi]
    pub fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::Acquire)
    }

    #[napi]
    pub async fn run_command(&self, options: RunCommandOptions) -> Result<CommandResult> {
        self.ensure_active()?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::RunCommand {
                options,
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped command reply"))?
            .map_err(napi_error)
    }

    #[napi]
    pub async fn zygote(&self) -> Result<KalahariNativeZygote> {
        self.zygote_inner().await.map_err(napi_error)
    }

    #[napi]
    pub async fn destroy(&self) -> Result<()> {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::Shutdown {
                reply: Some(reply_tx),
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped shutdown reply"))?
            .map_err(napi_error)
    }

    #[napi]
    pub async fn create_pty(&self, options: CreatePtyOptions) -> Result<KalahariPtySession> {
        self.ensure_active()?;

        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::StartPty {
                options,
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        let pty_id = reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped pty reply"))?
            .map_err(napi_error)?;

        Ok(KalahariPtySession {
            id: pty_id,
            sandbox_id: self.id.clone(),
            requests: self.requests.clone(),
            closed: Arc::new(AtomicBool::new(false)),
        })
    }
}

#[napi]
impl KalahariNativeZygote {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[napi(getter)]
    pub fn image(&self) -> String {
        self.image.clone()
    }

    #[napi(getter)]
    pub fn requested_image(&self) -> String {
        self.requested_image.clone()
    }

    #[napi(getter)]
    pub fn store_dir(&self) -> String {
        self.store_dir.clone()
    }

    #[napi(getter)]
    pub const fn created_at_ms(&self) -> f64 {
        self.created_at_ms
    }

    #[napi]
    pub fn is_destroyed(&self) -> bool {
        self.destroyed.load(Ordering::Acquire)
    }

    #[napi]
    pub async fn spawn(&self, options: CreateSandboxOptions) -> Result<KalahariNativeSandbox> {
        if self.destroyed.load(Ordering::Acquire) {
            return Err(napi_error(format!(
                "Kalahari zygote {} is destroyed",
                self.id
            )));
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(ZygoteRequest::Spawn {
                options: Box::new(options),
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari zygote worker has stopped"))?;

        let handle = reply_rx
            .await
            .map_err(|_| napi_error("Kalahari zygote worker dropped spawn reply"))?
            .map_err(napi_error)?;
        Ok(KalahariNativeSandbox::from_actor(handle))
    }

    #[napi]
    pub async fn destroy(&self) -> Result<()> {
        if self.destroyed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }

        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(ZygoteRequest::Destroy {
                reply: Some(reply_tx),
            })
            .await
            .map_err(|_| napi_error("Kalahari zygote worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari zygote worker dropped destroy reply"))?
            .map_err(napi_error)
    }
}

#[napi]
impl KalahariPtySession {
    #[napi(getter)]
    pub fn id(&self) -> String {
        self.id.clone()
    }

    #[napi(getter)]
    pub fn sandbox_id(&self) -> String {
        self.sandbox_id.clone()
    }

    #[napi]
    pub async fn read(&self) -> Result<Option<PtyOutput>> {
        if self.closed.load(Ordering::Acquire) {
            return Ok(None);
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::ReadPty {
                pty_id: self.id.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped pty read reply"))?
            .map_err(napi_error)
    }

    #[napi]
    pub async fn write(&self, data: String) -> Result<()> {
        self.write_bytes(data.into_bytes()).await
    }

    #[napi]
    pub async fn write_bytes(&self, data: Vec<u8>) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(napi_error("Kalahari PTY session is closed"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::WritePty {
                pty_id: self.id.clone(),
                data,
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped pty write reply"))?
            .map_err(napi_error)
    }

    #[napi]
    pub async fn resize(&self, rows: u32, cols: u32) -> Result<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(napi_error("Kalahari PTY session is closed"));
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::ResizePty {
                pty_id: self.id.clone(),
                rows,
                cols,
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped pty resize reply"))?
            .map_err(napi_error)
    }

    #[napi]
    pub async fn close(&self) -> Result<()> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.requests
            .send(SandboxRequest::ClosePty {
                pty_id: self.id.clone(),
                reply: reply_tx,
            })
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker has stopped"))?;

        reply_rx
            .await
            .map_err(|_| napi_error("Kalahari sandbox worker dropped pty close reply"))?
            .map_err(napi_error)
    }
}

impl Drop for KalahariNativeSandbox {
    fn drop(&mut self) {
        if !self.destroyed.swap(true, Ordering::AcqRel) {
            match self
                .requests
                .try_send(SandboxRequest::Shutdown { reply: None })
            {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

impl Drop for KalahariNativeZygote {
    fn drop(&mut self) {
        if !self.destroyed.swap(true, Ordering::AcqRel) {
            match self
                .requests
                .try_send(ZygoteRequest::Destroy { reply: None })
            {
                Ok(()) | Err(_) => {}
            }
        }
    }
}

#[napi]
pub fn available() -> bool {
    engine::vmm::available()
}

#[napi]
pub fn default_node_image() -> String {
    DEFAULT_NODE_IMAGE.to_string()
}

#[napi]
pub fn default_store_dir() -> Result<String> {
    default_store_path()
        .map(|path| path_to_string(&path))
        .map_err(napi_error)
}

// Reason: napi-rs macro expansion includes a trailing zero-sized array
// in its callback struct without a `#[repr]` attribute. This is a macro
// implementation detail outside our control.
#[allow(clippy::trailing_empty_array)]
#[napi]
#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
pub async fn prepare_image(options: PrepareImageOptions) -> Result<PreparedImage> {
    let image = options
        .image
        .unwrap_or_else(|| DEFAULT_NODE_IMAGE.to_string());
    let store_dir = store_path_from_option(options.store_dir).map_err(napi_error)?;
    prepare_image_inner(&store_dir, &image)
        .await
        .map_err(napi_error)
}

// Reason: napi-rs macro expansion includes a trailing zero-sized array
// in its callback struct without a `#[repr]` attribute. Outside our control.
#[allow(clippy::trailing_empty_array)]
#[napi]
#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
pub async fn create_sandbox(options: CreateSandboxOptions) -> Result<KalahariNativeSandbox> {
    let requested_image = options
        .image
        .clone()
        .unwrap_or_else(|| DEFAULT_NODE_IMAGE.to_string());
    let store_dir = store_path_from_option(options.store_dir).map_err(napi_error)?;

    let image = if options.prepare_image.unwrap_or(true) {
        prepare_image_inner(&store_dir, &requested_image)
            .await
            .map_err(napi_error)?
            .manifest_digest
    } else {
        requested_image.clone()
    };

    let queue_size = request_queue_size(options.request_queue_size).map_err(napi_error)?;
    let sizing = engine::VmSizing::default();
    let default_memory_mb = u32::try_from(sizing.memory_mb).map_err(napi_error)?;

    let actor_options = ActorOptions {
        store_dir: store_dir.clone(),
        image: image.clone(),
        requested_image: requested_image.clone(),
        worker_path: options.worker_path,
        memory_mb: options.memory_mb.unwrap_or(default_memory_mb),
        vcpus: options.vcpus.unwrap_or(sizing.vcpu_count),
        timeout_ms: options.timeout_ms,
        output_limit_bytes: options.output_limit_bytes.unwrap_or(DEFAULT_OUTPUT_LIMIT),
        network: options.network.unwrap_or_default(),
    };

    let (request_tx, request_rx) = mpsc::channel(queue_size);
    let (ready_tx, ready_rx) = oneshot::channel();
    let ready = Arc::new(std::sync::Mutex::new(Some(ready_tx)));
    spawn_sandbox_actor(actor_options, request_rx, request_tx.clone(), ready)
        .map_err(napi_error)?;

    ready_rx
        .await
        .map_err(|_| napi_error("Kalahari sandbox worker exited before reporting readiness"))?
        .map_err(napi_error)?;

    Ok(KalahariNativeSandbox {
        id: Uuid::new_v4().to_string(),
        image,
        requested_image,
        store_dir: path_to_string(&store_dir),
        created_at_ms: now_ms(),
        destroyed: Arc::new(AtomicBool::new(false)),
        transitioning: Arc::new(AtomicBool::new(false)),
        requests: request_tx,
    })
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_sandbox_actor(
    options: ActorOptions,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: ReadyCell,
) {
    let result = run_sandbox_actor_inner(options, requests, request_tx, &ready).await;

    if let Err(error) = &result {
        send_ready(&ready, Err(error.to_string()));
        log::error!("Kalahari sandbox actor failed: {error:#}");
    }
}

fn spawn_sandbox_actor(
    options: ActorOptions,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: ReadyCell,
) -> anyhow::Result<()> {
    let runtime = actor_runtime()?;
    runtime
        .jobs
        .send(Box::new(move || {
            let actor =
                tokio::task::spawn_local(run_sandbox_actor(options, requests, request_tx, ready));
            drop(actor);
        }))
        .map_err(|_| anyhow::anyhow!("Kalahari actor runtime has stopped"))
}

fn actor_runtime() -> anyhow::Result<&'static ActorRuntime> {
    match KALAHARI_ACTOR_RUNTIME.get_or_init(start_actor_runtime) {
        Ok(runtime) => Ok(runtime),
        Err(error) => Err(anyhow::anyhow!(error.clone())),
    }
}

fn start_actor_runtime() -> std::result::Result<ActorRuntime, String> {
    let (jobs, mut job_rx) = mpsc::unbounded_channel::<ActorJob>();
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();

    std::thread::Builder::new()
        .name("kalahari".to_string())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    match ready_tx.send(Err(format!("create actor runtime: {error}"))) {
                        Ok(()) | Err(_) => {}
                    }
                    return;
                }
            };

            match ready_tx.send(Ok(())) {
                Ok(()) | Err(_) => {}
            }
            let local = tokio::task::LocalSet::new();
            runtime.block_on(local.run_until(async move {
                while let Some(job) = job_rx.recv().await {
                    job();
                }
            }));
        })
        .map_err(|error| format!("spawn actor runtime: {error}"))?;

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .map_err(|error| format!("actor runtime startup: {error}"))?
        .map(|()| ActorRuntime { jobs })
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_sandbox_actor_inner(
    options: ActorOptions,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: &ReadyCell,
) -> anyhow::Result<()> {
    let actor_options = options.clone();
    let vm = engine::build_vm_resources(&options.store_dir)?;
    let image = engine::resolve_image(&options.store_dir, Some(&options.image))?;
    let sizing = engine::VmSizing {
        vcpu_count: options.vcpus,
        memory_mb: usize::try_from(options.memory_mb)?,
    };
    let mut pmem = vec![vm.rootfs.try_clone()?];
    for layer in &image.layers {
        pmem.push(layer.try_clone()?);
    }
    let net = network_backend(&options.network)?;
    let config = engine::vm_config(&vm.rootfs, &image, &sizing, None)?;
    let backends = scheduler::VmBackends::new(scheduler::ConsoleStream::new())
        .with_net(net)
        .with_pmem(pmem);
    let scheduler = scheduler_for(options.worker_path.as_deref())?;
    let machine = scheduler.create_vm(config, backends).await?;
    let machine = machine.load_kernel(vm.kernel_bytes).await?;
    let config_json = serde_json::to_string(&image.config)?;
    let timeout_ms = options.timeout_ms;
    let output_limit_bytes = options.output_limit_bytes;
    let (machine, result) = machine
        .run(async move |handle| {
            let mut handle = handle.start();
            run_actor_in_vm(
                &mut handle,
                requests,
                request_tx,
                ready,
                &config_json,
                timeout_ms,
                output_limit_bytes,
            )
            .await
        })
        .await?;
    finish_sandbox_actor(machine, result?, actor_options).await
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn finish_sandbox_actor<
    F: amla_fuse::fuse::FsBackend + 'static,
    N: amla_core::backends::NetBackend + 'static,
>(
    machine: scheduler::VirtualMachine<scheduler::Parked<F, N>>,
    outcome: ActorExit,
    options: ActorOptions,
) -> anyhow::Result<()> {
    match outcome {
        ActorExit::Shutdown => Ok(()),
        ActorExit::Zygote { init_handle, reply } => {
            let result = match async {
                let zygote = machine.freeze().await?;
                spawn_zygote_actor(options, zygote, init_handle)
            }
            .await
            {
                Ok(handle) => Ok(handle),
                Err(error) => Err(ZygoteCreateError::fatal(error.to_string())),
            };
            send_reply(reply, result);
            Ok(())
        }
    }
}

fn spawn_zygote_actor(
    options: ActorOptions,
    zygote: scheduler::VirtualMachine<scheduler::Zygote>,
    init_handle: scheduler::CommandExecutionHandle,
) -> anyhow::Result<ZygoteActorHandle> {
    let queue_size = request_queue_size(None)?;
    let (request_tx, request_rx) = mpsc::channel(queue_size);
    let handle = ZygoteActorHandle {
        id: Uuid::new_v4().to_string(),
        image: options.image.clone(),
        requested_image: options.requested_image.clone(),
        store_dir: path_to_string(&options.store_dir),
        created_at_ms: now_ms(),
        requests: request_tx,
    };
    let actor =
        tokio::task::spawn_local(run_zygote_actor(options, zygote, init_handle, request_rx));
    drop(actor);
    Ok(handle)
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_zygote_actor(
    options: ActorOptions,
    zygote: scheduler::VirtualMachine<scheduler::Zygote>,
    init_handle: scheduler::CommandExecutionHandle,
    mut requests: mpsc::Receiver<ZygoteRequest>,
) {
    while let Some(request) = requests.recv().await {
        match request {
            ZygoteRequest::Spawn {
                options: spawn_options,
                reply,
            } => {
                let result = spawn_sandbox_from_zygote(
                    &options,
                    &zygote,
                    init_handle.clone(),
                    *spawn_options,
                )
                .await
                .map_err(|error| error.to_string());
                send_reply(reply, result);
            }
            ZygoteRequest::Destroy { reply } => {
                if let Some(reply) = reply {
                    send_reply(reply, Ok(()));
                }
                break;
            }
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn spawn_sandbox_from_zygote(
    base_options: &ActorOptions,
    zygote: &scheduler::VirtualMachine<scheduler::Zygote>,
    init_handle: scheduler::CommandExecutionHandle,
    spawn_options: CreateSandboxOptions,
) -> anyhow::Result<SandboxActorHandle> {
    validate_zygote_spawn_options(&spawn_options)?;
    let queue_size = request_queue_size(spawn_options.request_queue_size)?;
    let child_options = ActorOptions {
        store_dir: base_options.store_dir.clone(),
        image: base_options.image.clone(),
        requested_image: base_options.requested_image.clone(),
        worker_path: base_options.worker_path.clone(),
        memory_mb: base_options.memory_mb,
        vcpus: base_options.vcpus,
        timeout_ms: spawn_options.timeout_ms.or(base_options.timeout_ms),
        output_limit_bytes: spawn_options
            .output_limit_bytes
            .unwrap_or(base_options.output_limit_bytes),
        network: spawn_options
            .network
            .unwrap_or_else(|| base_options.network.clone()),
    };
    let net = network_backend(&child_options.network)?;
    let backends = scheduler::RuntimeBackends::new(scheduler::ConsoleStream::new()).with_net(net);
    let machine = zygote.spawn(backends).await?;
    let (request_tx, request_rx) = mpsc::channel(queue_size);
    let (ready_tx, ready_rx) = oneshot::channel();
    let ready = Arc::new(std::sync::Mutex::new(Some(ready_tx)));
    spawn_existing_sandbox_actor(
        child_options.clone(),
        machine,
        init_handle,
        request_rx,
        request_tx.clone(),
        ready,
    );
    let ready_result = ready_rx.await.map_err(|_| {
        anyhow::anyhow!("Kalahari spawned sandbox exited before reporting readiness")
    })?;
    ready_result.map_err(|error| anyhow::anyhow!(error))?;
    Ok(SandboxActorHandle {
        id: Uuid::new_v4().to_string(),
        image: child_options.image,
        requested_image: child_options.requested_image,
        store_dir: path_to_string(&child_options.store_dir),
        created_at_ms: now_ms(),
        requests: request_tx,
    })
}

fn validate_zygote_spawn_options(options: &CreateSandboxOptions) -> anyhow::Result<()> {
    anyhow::ensure!(
        options.image.is_none()
            && options.prepare_image.is_none()
            && options.store_dir.is_none()
            && options.worker_path.is_none()
            && options.memory_mb.is_none()
            && options.vcpus.is_none(),
        "Kalahari zygote spawn cannot change image, prepareImage, storeDir, workerPath, memoryMb, or vcpus"
    );
    Ok(())
}

fn spawn_existing_sandbox_actor<
    F: amla_fuse::fuse::FsBackend + 'static,
    N: amla_core::backends::NetBackend + 'static,
>(
    options: ActorOptions,
    machine: scheduler::VirtualMachine<scheduler::Parked<F, N>>,
    init_handle: scheduler::CommandExecutionHandle,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: ReadyCell,
) {
    let actor = tokio::task::spawn_local(run_existing_sandbox_actor(
        options,
        machine,
        init_handle,
        requests,
        request_tx,
        ready,
    ));
    drop(actor);
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_existing_sandbox_actor<
    F: amla_fuse::fuse::FsBackend + 'static,
    N: amla_core::backends::NetBackend + 'static,
>(
    options: ActorOptions,
    machine: scheduler::VirtualMachine<scheduler::Parked<F, N>>,
    init_handle: scheduler::CommandExecutionHandle,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: ReadyCell,
) {
    let result = run_existing_sandbox_actor_inner(
        options,
        machine,
        init_handle,
        requests,
        request_tx,
        &ready,
    )
    .await;
    if let Err(error) = &result {
        send_ready(&ready, Err(error.to_string()));
        log::error!("Kalahari spawned sandbox actor failed: {error:#}");
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_existing_sandbox_actor_inner<
    F: amla_fuse::fuse::FsBackend + 'static,
    N: amla_core::backends::NetBackend + 'static,
>(
    options: ActorOptions,
    machine: scheduler::VirtualMachine<scheduler::Parked<F, N>>,
    init_handle: scheduler::CommandExecutionHandle,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: &ReadyCell,
) -> anyhow::Result<()> {
    let actor_options = options.clone();
    let timeout_ms = options.timeout_ms;
    let output_limit_bytes = options.output_limit_bytes;
    let init_id = init_handle.id();
    let (machine, result) = machine
        .run(async move |mut handle| {
            handle.attach(init_handle)?;
            let mut handle = handle.start();
            let mut init = handle
                .take_attached(init_id)
                .ok_or_else(|| anyhow::anyhow!("attached container init was not found"))?;
            drop(init.take_stdout());
            drop(init.take_stderr());
            run_actor_with_existing_container(
                &mut handle,
                init,
                requests,
                request_tx,
                ready,
                timeout_ms,
                output_limit_bytes,
            )
            .await
        })
        .await?;
    finish_sandbox_actor(machine, result?, actor_options).await
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_actor_in_vm(
    handle: &mut scheduler::VmHandle<'_>,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: &ReadyCell,
    config_json: &str,
    timeout_ms: Option<u32>,
    output_limit_bytes: u32,
) -> anyhow::Result<ActorExit> {
    let container = container::init_container(handle, "computesdk", config_json).await?;
    let mut init = container.init;
    drop(init.take_stdout());
    let container_handle = container.handle;
    send_ready(ready, Ok(()));

    match run_actor_request_loop(
        init,
        container_handle,
        requests,
        request_tx,
        timeout_ms,
        output_limit_bytes,
    )
    .await?
    {
        ActorLoopExit::Shutdown {
            init,
            shutdown_replies,
        } => {
            finish_actor_shutdown(handle, init, shutdown_replies).await?;
            Ok(ActorExit::Shutdown)
        }
        ActorLoopExit::Zygote { init_handle, reply } => {
            Ok(ActorExit::Zygote { init_handle, reply })
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_actor_with_existing_container(
    handle: &mut scheduler::VmHandle<'_>,
    init: scheduler::CommandExecution,
    requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    ready: &ReadyCell,
    timeout_ms: Option<u32>,
    output_limit_bytes: u32,
) -> anyhow::Result<ActorExit> {
    send_ready(ready, Ok(()));

    let container_handle = container::ContainerHandle::new(&*handle, "computesdk");
    match run_actor_request_loop(
        init,
        container_handle,
        requests,
        request_tx,
        timeout_ms,
        output_limit_bytes,
    )
    .await?
    {
        ActorLoopExit::Shutdown {
            init,
            shutdown_replies,
        } => {
            finish_actor_shutdown(handle, init, shutdown_replies).await?;
            Ok(ActorExit::Shutdown)
        }
        ActorLoopExit::Zygote { init_handle, reply } => {
            Ok(ActorExit::Zygote { init_handle, reply })
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_actor_request_loop(
    mut init: scheduler::CommandExecution,
    container_handle: ScheduledContainerHandle<'_, '_>,
    mut requests: mpsc::Receiver<SandboxRequest>,
    request_tx: mpsc::Sender<SandboxRequest>,
    timeout_ms: Option<u32>,
    output_limit_bytes: u32,
) -> anyhow::Result<ActorLoopExit> {
    let mut shutdown_replies = Vec::new();
    let mut pending_requests = VecDeque::new();
    let mut pty_sessions: HashMap<String, PtySessionState> = HashMap::new();
    let mut quiescence = SandboxQuiescence::new();
    let command_defaults = CommandDefaults {
        timeout_ms,
        output_limit_bytes,
    };
    while let Some(request) = next_request(&mut requests, &mut pending_requests).await {
        match request {
            SandboxRequest::RunCommand { options, reply } => {
                match handle_run_command_request(
                    &container_handle,
                    &mut requests,
                    &mut pending_requests,
                    &mut shutdown_replies,
                    options,
                    reply,
                    command_defaults,
                )
                .await
                {
                    RunCommandRequestOutcome::Continue { abandoned } => {
                        if abandoned {
                            quiescence.record_abandoned_foreground_command();
                        }
                    }
                    RunCommandRequestOutcome::Shutdown => break,
                }
            }
            SandboxRequest::Shutdown { reply } => {
                begin_actor_shutdown(
                    reply,
                    &mut requests,
                    &mut pending_requests,
                    &mut shutdown_replies,
                );
                break;
            }
            SandboxRequest::CreateZygote { reply } => {
                match handle_create_zygote_request(
                    init,
                    reply,
                    !pty_sessions.is_empty(),
                    &quiescence,
                    &mut requests,
                    &mut pending_requests,
                )
                .await
                {
                    ZygoteRequestOutcome::Continue(next_init) => init = next_init,
                    ZygoteRequestOutcome::Exit(exit) => return Ok(exit),
                }
            }
            pty_request @ (SandboxRequest::PtyOutput { .. }
            | SandboxRequest::StartPty { .. }
            | SandboxRequest::ReadPty { .. }
            | SandboxRequest::WritePty { .. }
            | SandboxRequest::ResizePty { .. }
            | SandboxRequest::ClosePty { .. }) => {
                handle_pty_request(
                    pty_request,
                    &container_handle,
                    &request_tx,
                    &mut pty_sessions,
                )
                .await;
            }
        }
    }

    close_pty_sessions_for_shutdown(&mut pty_sessions);
    drop(container_handle);
    Ok(ActorLoopExit::Shutdown {
        init,
        shutdown_replies,
    })
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn handle_run_command_request(
    container_handle: &ScheduledContainerHandle<'_, '_>,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    shutdown_replies: &mut Vec<ShutdownReply>,
    mut options: RunCommandOptions,
    reply: oneshot::Sender<std::result::Result<CommandResult, String>>,
    defaults: CommandDefaults,
) -> RunCommandRequestOutcome {
    if options.timeout_ms.is_none() {
        options.timeout_ms = defaults.timeout_ms;
    }
    if options.output_limit_bytes.is_none() {
        options.output_limit_bytes = Some(defaults.output_limit_bytes);
    }

    match run_command_until_shutdown(container_handle, requests, pending_requests, options).await {
        CommandOrShutdown::Completed(result) => {
            send_reply(reply, result.map_err(|error| error.to_string()));
            RunCommandRequestOutcome::Continue { abandoned: false }
        }
        CommandOrShutdown::Abandoned(error) => {
            send_reply(reply, Err(error.to_string()));
            RunCommandRequestOutcome::Continue { abandoned: true }
        }
        CommandOrShutdown::Shutdown {
            reply: shutdown_reply,
        } => {
            send_reply(
                reply,
                Err("command cancelled because sandbox is shutting down".to_string()),
            );
            begin_actor_shutdown(shutdown_reply, requests, pending_requests, shutdown_replies);
            RunCommandRequestOutcome::Shutdown
        }
        CommandOrShutdown::RequestChannelClosed => {
            send_reply(
                reply,
                Err("command cancelled because sandbox request channel closed".to_string()),
            );
            begin_actor_shutdown(None, requests, pending_requests, shutdown_replies);
            RunCommandRequestOutcome::Shutdown
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn handle_create_zygote_request(
    init: scheduler::CommandExecution,
    reply: ZygoteCreateReply,
    has_active_pty_sessions: bool,
    quiescence: &SandboxQuiescence,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
) -> ZygoteRequestOutcome {
    if has_active_pty_sessions {
        send_reply(
            reply,
            Err(ZygoteCreateError::recoverable(
                "cannot zygote a Kalahari sandbox with active PTY or process sessions",
            )),
        );
        return ZygoteRequestOutcome::Continue(init);
    }
    if let Some(error) = quiescence.zygote_error() {
        send_reply(reply, Err(error));
        return ZygoteRequestOutcome::Continue(init);
    }

    match init_into_zygote_handle(init).await {
        Ok(init_handle) => {
            close_requests_for_zygote(requests, pending_requests);
            ZygoteRequestOutcome::Exit(ActorLoopExit::Zygote { init_handle, reply })
        }
        Err(error) => {
            let message = error.to_string();
            let init = error.into_command();
            send_reply(
                reply,
                Err(ZygoteCreateError::recoverable(format!(
                    "cannot zygote Kalahari sandbox: {message}"
                ))),
            );
            ZygoteRequestOutcome::Continue(init)
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn init_into_zygote_handle(
    mut init: scheduler::CommandExecution,
) -> std::result::Result<scheduler::CommandExecutionHandle, scheduler::IntoHandleError> {
    // `amla-init` boot output is only a readiness/control signal for Kalahari.
    // Close the visible streams before freezing, then give the scheduler a
    // bounded chance to discard any chunks already forwarded to host channels.
    drop(init.take_stdout());
    drop(init.take_stderr());

    let started = Instant::now();
    loop {
        match init.into_handle() {
            Ok(handle) => return Ok(handle),
            Err(error)
                if into_handle_error_needs_output_drain(error.source())
                    && started.elapsed() < INIT_REATTACH_DRAIN_TIMEOUT =>
            {
                init = error.into_command();
                tokio::time::sleep(INIT_REATTACH_RETRY_DELAY).await;
            }
            Err(error) => return Err(error),
        }
    }
}

fn into_handle_error_needs_output_drain(error: &scheduler::ExecError) -> bool {
    matches!(
        error,
        scheduler::ExecError::NotReattachable { reason }
            if *reason == "stdout/stderr has already been delivered to host channels"
                || *reason == "stdout/stderr reached host while session was being detached"
    )
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn finish_actor_shutdown(
    handle: &mut scheduler::VmHandle<'_>,
    init: scheduler::CommandExecution,
    shutdown_replies: Vec<ShutdownReply>,
) -> anyhow::Result<()> {
    let result = shutdown_container(handle, init).await;
    let reply_result = match &result {
        Ok(()) => Ok(()),
        Err(error) => Err(error.to_string()),
    };
    for reply in shutdown_replies {
        send_reply(reply, reply_result.clone());
    }
    result
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn handle_pty_request(
    request: SandboxRequest,
    container: &ScheduledContainerHandle<'_, '_>,
    request_tx: &mpsc::Sender<SandboxRequest>,
    sessions: &mut HashMap<String, PtySessionState>,
) {
    match request {
        SandboxRequest::StartPty { options, reply } => {
            let result = start_pty(container, options)
                .await
                .map(|command| {
                    let pty_id = Uuid::new_v4().to_string();
                    let writer = command.stdin_writer();
                    sessions.insert(pty_id.clone(), PtySessionState::new(writer));
                    spawn_pty_output_pump(pty_id.clone(), command, request_tx.clone());
                    pty_id
                })
                .map_err(|error| error.to_string());
            send_reply(reply, result);
        }
        SandboxRequest::ReadPty { pty_id, reply } => {
            handle_pty_read(sessions, &pty_id, reply);
        }
        SandboxRequest::WritePty {
            pty_id,
            data,
            reply,
        } => {
            let result = write_pty(sessions, &pty_id, data)
                .await
                .map_err(|error| error.to_string());
            send_reply(reply, result);
        }
        SandboxRequest::ResizePty {
            pty_id,
            rows,
            cols,
            reply,
        } => {
            let result = resize_pty(sessions, &pty_id, rows, cols)
                .await
                .map_err(|error| error.to_string());
            send_reply(reply, result);
        }
        SandboxRequest::ClosePty { pty_id, reply } => {
            let result = close_pty(sessions, &pty_id)
                .await
                .map_err(|error| error.to_string());
            send_reply(reply, result);
        }
        SandboxRequest::PtyOutput { pty_id, output } => {
            handle_pty_output(sessions, &pty_id, output);
        }
        SandboxRequest::RunCommand { .. }
        | SandboxRequest::Shutdown { .. }
        | SandboxRequest::CreateZygote { .. } => {
            unreachable!("non-PTY request passed to PTY handler");
        }
    }
}

fn send_reply<T>(reply: oneshot::Sender<T>, result: T) {
    match reply.send(result) {
        Ok(()) | Err(_) => {}
    }
}

fn begin_actor_shutdown(
    reply: Option<ShutdownReply>,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    shutdown_replies: &mut Vec<ShutdownReply>,
) {
    if let Some(reply) = reply {
        shutdown_replies.push(reply);
    }
    close_requests_for_shutdown(requests, pending_requests, shutdown_replies);
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn next_request(
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
) -> Option<SandboxRequest> {
    if let Some(request) = pending_requests.pop_front() {
        Some(request)
    } else {
        requests.recv().await
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn run_command_until_shutdown(
    container: &ScheduledContainerHandle<'_, '_>,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    options: RunCommandOptions,
) -> CommandOrShutdown {
    let started = Instant::now();
    let output_limit =
        match usize::try_from(options.output_limit_bytes.unwrap_or(DEFAULT_OUTPUT_LIMIT)) {
            Ok(limit) => limit,
            Err(error) => return CommandOrShutdown::Completed(Err(error.into())),
        };
    let timeout_ms = options.timeout_ms;
    let stdin = match decode_stdin(options.stdin_base64.as_deref()) {
        Ok(stdin) => stdin,
        Err(error) => return CommandOrShutdown::Completed(Err(error)),
    };
    let command = match start_container_command_until_shutdown(
        container,
        requests,
        pending_requests,
        &options,
    )
    .await
    {
        Ok(command) => command,
        Err(outcome) => return outcome,
    };
    collect_command_until_shutdown(
        command,
        requests,
        pending_requests,
        output_limit,
        timeout_ms,
        stdin,
        started,
    )
    .await
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn start_pty(
    container: &ScheduledContainerHandle<'_, '_>,
    options: CreatePtyOptions,
) -> anyhow::Result<scheduler::CommandExecution> {
    let argv = command_argv(&options.command, options.args.as_deref());
    let env = options.env.as_deref().unwrap_or_default();
    let mut command = container
        .run_pty(argv.iter().map(String::as_str))
        .env(env.iter().map(String::as_str));
    if let Some(cwd) = options.cwd.as_deref()
        && !cwd.is_empty()
    {
        command = command.cwd(cwd);
    }
    Ok(std::future::IntoFuture::into_future(command).await?)
}

fn spawn_pty_output_pump(
    pty_id: String,
    mut command: scheduler::CommandExecution,
    requests: mpsc::Sender<SandboxRequest>,
) {
    let pump = tokio::task::spawn_local(async move {
        while let Some(event) = command.recv_output().await {
            let output = pty_output_from_event(event);
            if requests
                .send(SandboxRequest::PtyOutput {
                    pty_id: pty_id.clone(),
                    output: Some(output),
                })
                .await
                .is_err()
            {
                return;
            }
        }
        match requests
            .send(SandboxRequest::PtyOutput {
                pty_id,
                output: None,
            })
            .await
        {
            Ok(()) | Err(_) => {}
        }
    });
    drop(pump);
}

fn pty_output_from_event(event: scheduler::OutputEvent) -> PtyOutput {
    match event {
        scheduler::OutputEvent::Stdout(bytes) => PtyOutput {
            stdout: Some(String::from_utf8_lossy(&bytes).into_owned()),
            stderr: None,
            exit_code: None,
        },
        scheduler::OutputEvent::Stderr(bytes) => PtyOutput {
            stdout: None,
            stderr: Some(String::from_utf8_lossy(&bytes).into_owned()),
            exit_code: None,
        },
        scheduler::OutputEvent::Exit(exit_code) => PtyOutput {
            stdout: None,
            stderr: None,
            exit_code: Some(exit_code),
        },
    }
}

fn handle_pty_read(
    sessions: &mut HashMap<String, PtySessionState>,
    pty_id: &str,
    reply: oneshot::Sender<std::result::Result<Option<PtyOutput>, String>>,
) {
    let remove_after_read;
    let result = {
        let Some(session) = sessions.get_mut(pty_id) else {
            send_reply(
                reply,
                Err(format!("Kalahari PTY session {pty_id} was not found")),
            );
            return;
        };
        if let Some(output) = session.output.buffered.pop_front() {
            remove_after_read = session.output.closed && session.output.buffered.is_empty();
            Ok(output)
        } else if session.output.closed {
            remove_after_read = true;
            Ok(None)
        } else {
            session.output.pending_reads.push_back(reply);
            return;
        }
    };

    if remove_after_read {
        sessions.remove(pty_id);
    }
    send_reply(reply, result);
}

#[cfg(test)]
fn handle_pty_output_read(
    output: &mut PtyOutputState,
    reply: oneshot::Sender<std::result::Result<Option<PtyOutput>, String>>,
) {
    if let Some(output) = output.buffered.pop_front() {
        send_reply(reply, Ok(output));
    } else if output.closed {
        send_reply(reply, Ok(None));
    } else {
        output.pending_reads.push_back(reply);
    }
}

fn handle_pty_output(
    sessions: &mut HashMap<String, PtySessionState>,
    pty_id: &str,
    output: Option<PtyOutput>,
) {
    let Some(session) = sessions.get_mut(pty_id) else {
        return;
    };
    if output.is_none() {
        session.writer = None;
    }
    handle_pty_output_event(&mut session.output, output);
    if session.output.closed && session.output.buffered.is_empty() {
        sessions.remove(pty_id);
    }
}

fn handle_pty_output_event(output_state: &mut PtyOutputState, output: Option<PtyOutput>) {
    if output.is_none() {
        output_state.closed = true;
        while let Some(reply) = output_state.pending_reads.pop_front() {
            send_reply(reply, Ok(None));
        }
        return;
    }

    if let Some(reply) = output_state.pending_reads.pop_front() {
        send_reply(reply, Ok(output));
    } else {
        output_state.buffered.push_back(output);
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn write_pty(
    sessions: &HashMap<String, PtySessionState>,
    pty_id: &str,
    data: Vec<u8>,
) -> anyhow::Result<()> {
    let Some(session) = sessions.get(pty_id) else {
        anyhow::bail!("Kalahari PTY session {pty_id} was not found");
    };
    anyhow::ensure!(
        !session.output.closed,
        "Kalahari PTY session {pty_id} is closed"
    );
    let Some(writer) = session.writer.as_ref() else {
        anyhow::bail!("Kalahari PTY session {pty_id} is closed");
    };
    writer.write_owned(data).await?;
    Ok(())
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn resize_pty(
    sessions: &HashMap<String, PtySessionState>,
    pty_id: &str,
    rows: u32,
    cols: u32,
) -> anyhow::Result<()> {
    let Some(session) = sessions.get(pty_id) else {
        anyhow::bail!("Kalahari PTY session {pty_id} was not found");
    };
    anyhow::ensure!(
        !session.output.closed,
        "Kalahari PTY session {pty_id} is closed"
    );
    let Some(writer) = session.writer.as_ref() else {
        anyhow::bail!("Kalahari PTY session {pty_id} is closed");
    };
    writer
        .resize(u16::try_from(rows)?, u16::try_from(cols)?)
        .await?;
    Ok(())
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn close_pty(
    sessions: &mut HashMap<String, PtySessionState>,
    pty_id: &str,
) -> anyhow::Result<()> {
    let Some(session) = sessions.remove(pty_id) else {
        return Ok(());
    };
    close_pty_session(session).await;
    Ok(())
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn close_pty_session(mut session: PtySessionState) {
    while let Some(reply) = session.output.pending_reads.pop_front() {
        send_reply(reply, Ok(None));
    }
    if let Some(writer) = session.writer.take() {
        match writer.close().await {
            Ok(()) | Err(_) => {}
        }
    }
}

fn close_pty_sessions_for_shutdown(sessions: &mut HashMap<String, PtySessionState>) {
    for (_, mut session) in sessions.drain() {
        while let Some(reply) = session.output.pending_reads.pop_front() {
            send_reply(
                reply,
                Err("pty read cancelled because sandbox is shutting down".to_string()),
            );
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn start_container_command_until_shutdown(
    container: &ScheduledContainerHandle<'_, '_>,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    options: &RunCommandOptions,
) -> std::result::Result<scheduler::CommandExecution, CommandOrShutdown> {
    let argv = command_argv(&options.command, options.args.as_deref());
    let env = options.env.as_deref().unwrap_or_default();
    let mut command = container
        .run(argv.iter().map(String::as_str))
        .env(env.iter().map(String::as_str));
    if let Some(cwd) = options.cwd.as_deref()
        && !cwd.is_empty()
    {
        command = command.cwd(cwd);
    }

    let command = std::future::IntoFuture::into_future(command);
    tokio::pin!(command);
    loop {
        tokio::select! {
            result = &mut command => {
                match result {
                    Ok(command) => return Ok(command),
                    Err(error) => {
                        return Err(CommandOrShutdown::Completed(Err(anyhow::Error::from(error))));
                    }
                }
            }
            request = requests.recv() => {
                if let Some(outcome) = buffer_or_shutdown(request, pending_requests) {
                    return Err(outcome);
                }
            }
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn collect_command_until_shutdown(
    mut command: scheduler::CommandExecution,
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    output_limit: usize,
    timeout_ms: Option<u32>,
    stdin: Option<Vec<u8>>,
    started: Instant,
) -> CommandOrShutdown {
    let stdin_writer = command.stdin_writer();
    let mut stdin = CommandStdin::new(stdin);
    let mut stdin_step = stdin.next_step(&stdin_writer);

    let timeout = tokio::time::sleep(std::time::Duration::from_millis(u64::from(
        timeout_ms.unwrap_or(u32::MAX),
    )));
    tokio::pin!(timeout);
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let mut captured = 0usize;

    loop {
        tokio::select! {
            event = command.recv_output() => {
                match event {
                    Some(scheduler::OutputEvent::Stdout(bytes)) => {
                        match add_captured_output(captured, bytes.len(), output_limit) {
                            Ok(next) => captured = next,
                            Err(error) => return CommandOrShutdown::Abandoned(error),
                        }
                        stdout.extend_from_slice(&bytes);
                    }
                    Some(scheduler::OutputEvent::Stderr(bytes)) => {
                        match add_captured_output(captured, bytes.len(), output_limit) {
                            Ok(next) => captured = next,
                            Err(error) => return CommandOrShutdown::Abandoned(error),
                        }
                        stderr.extend_from_slice(&bytes);
                    }
                    Some(scheduler::OutputEvent::Exit(exit_code)) => {
                        return CommandOrShutdown::Completed(Ok(CommandResult {
                            stdout: String::from_utf8_lossy(&stdout).into_owned(),
                            stderr: String::from_utf8_lossy(&stderr).into_owned(),
                            exit_code,
                            duration_ms: started.elapsed().as_secs_f64() * 1000.0,
                        }));
                    }
                    None => {
                        return CommandOrShutdown::Completed(Err(scheduler::ExecError::Disconnected.into()));
                    }
                }
            }
            request = requests.recv() => {
                if let Some(outcome) = buffer_or_shutdown(request, pending_requests) {
                    detach_command_for_shutdown(command);
                    return outcome;
                }
            }
            () = &mut timeout, if timeout_ms.is_some() => {
                let timeout_ms = timeout_ms.unwrap_or(u32::MAX);
                return CommandOrShutdown::Abandoned(anyhow::anyhow!("command timed out after {timeout_ms}ms"));
            }
            result = poll_stdin_step(&mut stdin_step), if stdin_step.is_some() => {
                match result {
                    Ok(()) => {
                        stdin_step = stdin.next_step(&stdin_writer);
                    }
                    Err(error) => {
                        log::debug!("Kalahari command stdin closed early: {error}");
                        stdin_step = None;
                    }
                }
            }
        }
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn poll_stdin_step(
    stdin_step: &mut Option<StdinStep<'_>>,
) -> std::result::Result<(), scheduler::ExecError> {
    match stdin_step {
        Some(step) => step.as_mut().await,
        None => std::future::pending().await,
    }
}

fn decode_stdin(stdin_base64: Option<&str>) -> anyhow::Result<Option<Vec<u8>>> {
    stdin_base64
        .map(|stdin| {
            base64::engine::general_purpose::STANDARD
                .decode(stdin)
                .map_err(anyhow::Error::from)
        })
        .transpose()
}

fn buffer_or_shutdown(
    request: Option<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
) -> Option<CommandOrShutdown> {
    match request {
        Some(SandboxRequest::Shutdown { reply }) => Some(CommandOrShutdown::Shutdown { reply }),
        Some(request) => {
            pending_requests.push_back(request);
            None
        }
        None => Some(CommandOrShutdown::RequestChannelClosed),
    }
}

fn detach_command_for_shutdown(command: scheduler::CommandExecution) {
    match command.into_handle() {
        Ok(_handle) => {}
        Err(error) => {
            drop(error.into_command());
        }
    }
}

fn add_captured_output(captured: usize, chunk_len: usize, limit: usize) -> anyhow::Result<usize> {
    let Some(attempted) = captured.checked_add(chunk_len) else {
        return Err(scheduler::ExecError::OutputLimitExceeded {
            attempted: usize::MAX,
            limit,
        }
        .into());
    };
    if attempted > limit {
        return Err(scheduler::ExecError::OutputLimitExceeded { attempted, limit }.into());
    }
    Ok(attempted)
}

fn close_requests_for_shutdown(
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
    shutdown_replies: &mut Vec<ShutdownReply>,
) {
    requests.close();

    while let Some(request) = pending_requests.pop_front() {
        fail_or_collect_shutdown_request(request, shutdown_replies);
    }

    while let Ok(request) = requests.try_recv() {
        fail_or_collect_shutdown_request(request, shutdown_replies);
    }
}

fn close_requests_for_zygote(
    requests: &mut mpsc::Receiver<SandboxRequest>,
    pending_requests: &mut VecDeque<SandboxRequest>,
) {
    requests.close();

    while let Some(request) = pending_requests.pop_front() {
        fail_or_collect_zygote_request(request);
    }

    while let Ok(request) = requests.try_recv() {
        fail_or_collect_zygote_request(request);
    }
}

fn fail_or_collect_zygote_request(request: SandboxRequest) {
    match request {
        SandboxRequest::RunCommand { reply, .. } => {
            match reply.send(Err(
                "command cancelled because sandbox was converted to a zygote".to_string(),
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::Shutdown { reply } => {
            if let Some(reply) = reply {
                send_reply(reply, Ok(()));
            }
        }
        SandboxRequest::CreateZygote { reply } => {
            send_reply(
                reply,
                Err(ZygoteCreateError::recoverable(
                    "sandbox was already converted to a zygote",
                )),
            );
        }
        SandboxRequest::StartPty { reply, .. } => {
            match reply.send(Err(
                "pty start cancelled because sandbox was converted to a zygote".to_string(),
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::ReadPty { reply, .. } => {
            match reply.send(Err(
                "pty read cancelled because sandbox was converted to a zygote".to_string(),
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::WritePty { reply, .. }
        | SandboxRequest::ResizePty { reply, .. }
        | SandboxRequest::ClosePty { reply, .. } => {
            match reply.send(Err(
                "pty operation cancelled because sandbox was converted to a zygote".to_string(),
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::PtyOutput { .. } => {}
    }
}

fn fail_or_collect_shutdown_request(
    request: SandboxRequest,
    shutdown_replies: &mut Vec<ShutdownReply>,
) {
    match request {
        SandboxRequest::RunCommand { reply, .. } => {
            match reply.send(Err(
                "command cancelled because sandbox is shutting down".to_string()
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::Shutdown { reply } => {
            if let Some(reply) = reply {
                shutdown_replies.push(reply);
            }
        }
        SandboxRequest::CreateZygote { reply } => {
            send_reply(
                reply,
                Err(ZygoteCreateError::recoverable(
                    "zygote creation cancelled because sandbox is shutting down",
                )),
            );
        }
        SandboxRequest::StartPty { reply, .. } => {
            match reply.send(Err(
                "pty start cancelled because sandbox is shutting down".to_string()
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::ReadPty { reply, .. } => {
            match reply.send(Err(
                "pty read cancelled because sandbox is shutting down".to_string()
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::WritePty { reply, .. }
        | SandboxRequest::ResizePty { reply, .. }
        | SandboxRequest::ClosePty { reply, .. } => {
            match reply.send(Err(
                "pty operation cancelled because sandbox is shutting down".to_string(),
            )) {
                Ok(()) | Err(_) => {}
            }
        }
        SandboxRequest::PtyOutput { .. } => {}
    }
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn shutdown_container(
    handle: &mut scheduler::VmHandle<'_>,
    mut init: scheduler::CommandExecution,
) -> anyhow::Result<()> {
    match init.close_stdin().await {
        Ok(()) | Err(_) => {}
    }
    let init_result = tokio::time::timeout(DEFAULT_SHUTDOWN_TIMEOUT, init.wait())
        .await
        .map_or_else(
            |_| {
                Err(anyhow::anyhow!(
                    "amla-init shutdown timed out after {DEFAULT_SHUTDOWN_TIMEOUT:?}"
                ))
            },
            |result| result.map(|_code| ()).map_err(anyhow::Error::from),
        );
    drop(init);
    handle.shutdown().await;
    if let Err(error) = init_result {
        log::debug!("Kalahari graceful container shutdown did not complete: {error}");
    }
    Ok(())
}

#[allow(clippy::future_not_send)] // Reason: captures host-side refs whose generic types lack Sync; future is intentionally !Send.
async fn prepare_image_inner(store_dir: &Path, image: &str) -> anyhow::Result<PreparedImage> {
    let source = ImageSource::parse(image)?;
    let source_string = source.to_string();
    let store = ContainerStore::open(store_dir)?;

    if let Some(stored) = find_image_by_source(&store, &source_string)? {
        store.set_default(&stored.manifest_digest)?;
        return Ok(PreparedImage {
            image: image.to_string(),
            source: source_string,
            store_dir: path_to_string(store_dir),
            manifest_digest: stored.manifest_digest.hex(),
            layers: u32::try_from(stored.metadata.layers.len())?,
            already_present: true,
        });
    }

    let progress = NoProgress;
    let imported = amla_oci::import(&source, &store, &progress).await?;
    Ok(PreparedImage {
        image: image.to_string(),
        source: source_string,
        store_dir: path_to_string(store_dir),
        manifest_digest: imported.manifest_digest.hex(),
        layers: u32::try_from(imported.layers.len())?,
        already_present: false,
    })
}

fn find_image_by_source(
    store: &ContainerStore<amla_container_store::FsBackend>,
    source: &str,
) -> anyhow::Result<Option<StoredImage>> {
    Ok(store
        .list()?
        .into_iter()
        .find(|image| image.metadata.source == source))
}

fn network_backend(
    options: &NetworkOptions,
) -> anyhow::Result<PolicyNetBackend<usernet::SharedBackend>> {
    let mut config = usernet::UserNetConfig::try_default()?;
    if let Some(dns) = options.dns.as_deref() {
        config = config.with_dns(dns.parse()?);
    }

    config = match options.mode.as_deref().unwrap_or("unrestricted") {
        "denyAll" | "deny-all" | "none" => {
            config.with_egress_policy(usernet::EgressPolicy::DenyAll)
        }
        "publicInternet" | "public-internet" => config.with_public_internet_egress(),
        "unrestricted" | "allowAll" | "allow-all" => config.with_unrestricted_egress(),
        mode => anyhow::bail!("unsupported Kalahari network mode: {mode}"),
    };

    config = match options.dns_mode.as_deref().unwrap_or("unrestricted") {
        "denyAll" | "deny-all" | "none" => {
            config.with_dns_forward_policy(usernet::DnsForwardPolicy::DenyAll)
        }
        "useEgressPolicy" | "use-egress-policy" => config.with_dns_forwarding_via_egress_policy(),
        "publicInternet" | "public-internet" => config.with_public_internet_dns_forwarding(),
        "unrestricted" | "allowAll" | "allow-all" => config.with_unrestricted_dns_forwarding(),
        mode => anyhow::bail!("unsupported Kalahari DNS network mode: {mode}"),
    };

    let backend = usernet::UserNetBackend::try_new(config)?;
    let backend = usernet::SharedBackend(Arc::new(backend));
    let packet_policy = match options.allow_list.as_deref() {
        Some(allow_list) if !allow_list.is_empty() => cidr_allow_list_policy(allow_list)?,
        _ => allow_all_packet_policy()?,
    };
    Ok(PolicyNetBackend::new(backend, packet_policy))
}

fn allow_all_packet_policy() -> anyhow::Result<amla_policy_net::PacketNetworkPolicy> {
    Ok(NetworkPolicy::deny_all()
        .allow_dhcp()
        .allow_icmp()
        .allow_subnet(Ipv4Subnet::new(Ipv4Addr::UNSPECIFIED, 0)?, &[0])
        .allow_subnet_v6(Ipv6Subnet::new(Ipv6Addr::UNSPECIFIED, 0)?, &[0])
        .to_packet_policy())
}

fn cidr_allow_list_policy(
    allow_list: &[String],
) -> anyhow::Result<amla_policy_net::PacketNetworkPolicy> {
    if allow_list.len() > 10 {
        anyhow::bail!("network allow list accepts at most 10 CIDR entries");
    }

    let mut policy = NetworkPolicy::deny_all().allow_dhcp();
    for cidr in allow_list {
        let (addr, prefix_len) = parse_ipv4_cidr(cidr)?;
        policy = policy.allow_subnet(Ipv4Subnet::new(addr, prefix_len)?, &[0]);
    }
    Ok(policy.to_packet_policy())
}

fn parse_ipv4_cidr(cidr: &str) -> anyhow::Result<(Ipv4Addr, u8)> {
    let trimmed = cidr.trim();
    let Some((addr, prefix_len)) = trimmed.split_once('/') else {
        anyhow::bail!("network allow list entry must be IPv4 CIDR: {trimmed}");
    };
    if prefix_len.contains('/') {
        anyhow::bail!("network allow list entry must be IPv4 CIDR: {trimmed}");
    }
    let addr: Ipv4Addr = addr.parse()?;
    let prefix_len: u8 = prefix_len.parse()?;
    if prefix_len > 32 {
        anyhow::bail!("network allow list CIDR prefix must be <= 32: {trimmed}");
    }
    Ok((addr, prefix_len))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SchedulerKey {
    worker_path: Option<PathBuf>,
}

struct SchedulerInstance {
    key: SchedulerKey,
    scheduler: scheduler::VmScheduler,
}

fn scheduler_for(worker_path: Option<&str>) -> anyhow::Result<scheduler::VmScheduler> {
    let key = SchedulerKey {
        worker_path: worker_path.map(PathBuf::from),
    };
    let live_shell_limit =
        scheduler::LiveShellLimit::try_from(SCHEDULER_LIVE_SHELL_DISCOVERY_LIMIT)?;
    let instance = KALAHARI_SCHEDULER.get_or_init(|| SchedulerInstance {
        scheduler: scheduler::VmScheduler::new(live_shell_limit, worker_process_for(&key)),
        key: key.clone(),
    });

    if instance.key != key {
        anyhow::bail!(
            "Kalahari scheduler is already initialized with {:?}; requested {:?}",
            instance.key,
            key
        );
    }

    Ok(instance.scheduler.clone())
}

fn worker_process_for(key: &SchedulerKey) -> engine::vmm::WorkerProcessConfig {
    key.worker_path
        .as_ref()
        .map_or_else(engine::worker_process_config, |path| {
            engine::vmm::WorkerProcessConfig::path(path.clone())
        })
}

fn command_argv(command: &str, args: Option<&[String]>) -> Vec<String> {
    let mut command_line = Vec::with_capacity(args.map_or(1, |args| args.len() + 1));
    command_line.push(command.to_string());
    if let Some(args) = args {
        command_line.extend(args.iter().cloned());
    }
    command_line
}

fn send_ready(ready: &ReadyCell, result: std::result::Result<(), String>) {
    let sender = ready
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .take();
    if let Some(sender) = sender {
        match sender.send(result) {
            Ok(()) | Err(_) => {}
        }
    }
}

fn store_path_from_option(path: Option<String>) -> anyhow::Result<PathBuf> {
    path.map_or_else(default_store_path, |path| Ok(PathBuf::from(path)))
}

fn request_queue_size(value: Option<u32>) -> anyhow::Result<usize> {
    let value = value.unwrap_or(DEFAULT_REQUEST_QUEUE_SIZE);
    anyhow::ensure!(value > 0, "request_queue_size must be greater than zero");
    Ok(usize::try_from(value)?)
}

fn default_store_path() -> anyhow::Result<PathBuf> {
    Ok(std::env::current_dir()?.join(".kalahari").join("images"))
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn now_ms() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0.0, |duration| duration.as_secs_f64() * 1000.0)
}

fn napi_error(error: impl std::fmt::Display) -> napi::Error {
    napi::Error::from_reason(error.to_string())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::panic,
    clippy::unwrap_used,
    reason = "unit tests should fail loudly when setup invariants are broken"
)]
mod tests {
    use super::*;

    #[test]
    fn command_argv_preserves_command_and_argument_boundaries() {
        let args = vec![
            "--flag".to_string(),
            "value with spaces".to_string(),
            "quoted'value".to_string(),
        ];

        assert_eq!(
            command_argv("python3", Some(&args)),
            vec!["python3", "--flag", "value with spaces", "quoted'value"]
        );
    }

    #[test]
    fn command_argv_allows_no_arguments() {
        assert_eq!(command_argv("/bin/sh", None), vec!["/bin/sh"]);
    }

    #[test]
    fn request_queue_size_uses_default_and_rejects_zero() {
        assert_eq!(
            request_queue_size(None).expect("default queue size should be valid"),
            usize::try_from(DEFAULT_REQUEST_QUEUE_SIZE).expect("default should fit usize")
        );

        let error = request_queue_size(Some(0)).expect_err("zero must be rejected");
        assert!(error.to_string().contains("greater than zero"));
    }

    #[test]
    fn path_to_string_preserves_utf8_paths() {
        assert_eq!(path_to_string(Path::new("/tmp/kalahari")), "/tmp/kalahari");
    }

    #[test]
    fn store_path_from_option_uses_explicit_path_without_normalizing() {
        assert_eq!(
            store_path_from_option(Some("relative/store".to_string()))
                .expect("explicit store path should be valid"),
            PathBuf::from("relative/store")
        );
    }

    #[test]
    fn default_store_path_is_kalahari_scoped_under_current_directory() {
        let temp = tempfile::tempdir().expect("tempdir should be created");
        let previous = std::env::current_dir().expect("current dir should be readable");
        std::env::set_current_dir(temp.path()).expect("current dir should be set");
        let current = std::env::current_dir().expect("current dir should be readable");

        let path = default_store_path().expect("default store path should be valid");

        std::env::set_current_dir(previous).expect("current dir should be restored");
        assert_eq!(path, current.join(".kalahari").join("images"));
    }

    #[test]
    fn send_ready_only_resolves_first_waiter_once() {
        let (tx, rx) = oneshot::channel();
        let ready = Arc::new(std::sync::Mutex::new(Some(tx)));

        send_ready(&ready, Ok(()));
        send_ready(&ready, Err("late failure".to_string()));

        assert!(ready.lock().expect("ready lock should be valid").is_none());
        assert_eq!(rx.blocking_recv(), Ok(Ok(())));
    }

    #[tokio::test]
    async fn zygote_recoverable_error_leaves_native_sandbox_running() {
        let (tx, mut rx) = mpsc::channel(1);
        let sandbox = test_native_sandbox(tx);
        let worker = tokio::spawn(async move {
            let Some(SandboxRequest::CreateZygote { reply }) = rx.recv().await else {
                panic!("expected zygote request");
            };
            send_reply(
                reply,
                Err(ZygoteCreateError::recoverable("recoverable zygote error")),
            );
        });

        let error = expect_zygote_inner_error(
            sandbox.zygote_inner().await,
            "recoverable error should reject zygote request",
        );

        assert!(error.contains("recoverable zygote error"));
        assert!(!sandbox.is_destroyed());
        assert!(!sandbox.transitioning.load(Ordering::Acquire));
        worker.await.expect("worker should finish");
    }

    #[tokio::test]
    async fn zygote_fatal_error_marks_native_sandbox_destroyed() {
        let (tx, mut rx) = mpsc::channel(1);
        let sandbox = test_native_sandbox(tx);
        let worker = tokio::spawn(async move {
            let Some(SandboxRequest::CreateZygote { reply }) = rx.recv().await else {
                panic!("expected zygote request");
            };
            send_reply(
                reply,
                Err(ZygoteCreateError::fatal("fatal zygote freeze error")),
            );
        });

        let error = expect_zygote_inner_error(
            sandbox.zygote_inner().await,
            "fatal error should reject zygote request",
        );

        assert!(error.contains("fatal zygote freeze error"));
        assert!(sandbox.is_destroyed());
        assert!(!sandbox.transitioning.load(Ordering::Acquire));
        worker.await.expect("worker should finish");
    }

    #[tokio::test]
    async fn zygote_dropped_reply_marks_native_sandbox_destroyed() {
        let (tx, mut rx) = mpsc::channel(1);
        let sandbox = test_native_sandbox(tx);
        let worker = tokio::spawn(async move {
            let Some(SandboxRequest::CreateZygote { reply }) = rx.recv().await else {
                panic!("expected zygote request");
            };
            drop(reply);
        });

        let error = expect_zygote_inner_error(
            sandbox.zygote_inner().await,
            "dropped reply should reject zygote request",
        );

        assert!(error.contains("dropped zygote reply"));
        assert!(sandbox.is_destroyed());
        assert!(!sandbox.transitioning.load(Ordering::Acquire));
        worker.await.expect("worker should finish");
    }

    fn test_native_sandbox(requests: mpsc::Sender<SandboxRequest>) -> KalahariNativeSandbox {
        KalahariNativeSandbox {
            id: "sandbox-test".to_string(),
            image: "node:22-alpine".to_string(),
            requested_image: "node:22-alpine".to_string(),
            store_dir: "/tmp/kalahari-test".to_string(),
            created_at_ms: 0.0,
            destroyed: Arc::new(AtomicBool::new(false)),
            transitioning: Arc::new(AtomicBool::new(false)),
            requests,
        }
    }

    fn expect_zygote_inner_error(
        result: std::result::Result<KalahariNativeZygote, String>,
        context: &'static str,
    ) -> String {
        match result {
            Ok(_) => panic!("{context}"),
            Err(error) => error,
        }
    }

    #[tokio::test]
    #[ignore = "explicit VM boot benchmark; run with `cargo test -p kalahari bench_kalahari_boot_vs_zygote -- --ignored --nocapture`"]
    async fn bench_kalahari_boot_vs_zygote() {
        const CLONES: usize = 8;
        const FRESH: usize = 3;
        const IMAGE: &str = "node:22-alpine";
        const PARALLEL: usize = 4;

        let store_dir = store_path_from_option(None).expect("store path");
        let prepared = prepare_image_inner(&store_dir, IMAGE)
            .await
            .expect("prepare benchmark image");
        let image = prepared.manifest_digest;

        let mut fresh_runs = Vec::new();
        for index in 0..FRESH {
            fresh_runs.push(
                bench_fresh_sandbox(&store_dir, &image, IMAGE, &format!("fresh-{index}\n"))
                    .await
                    .expect("fresh benchmark run"),
            );
        }

        let (base_result, base_boot) =
            measure(bench_create_sandbox(&store_dir, &image, IMAGE)).await;
        let base = base_result.expect("create base sandbox");
        let (base_setup_result, base_setup_command) =
            measure(bench_setup_and_read_state(&base, "zygote-base\n")).await;
        base_setup_result.expect("setup base zygote state");
        let (zygote_result, conversion) = measure(base.zygote_inner()).await;
        let zygote = zygote_result.expect("convert sandbox to zygote");

        let mut sequential_clones = Vec::new();
        let mut parallel_clones = Vec::new();
        let mut cleanup_zygote = Some(zygote);

        if let Some(zygote) = cleanup_zygote.as_ref() {
            for index in 0..CLONES {
                sequential_clones.push(
                    bench_zygote_clone(zygote.requests.clone(), &format!("clone-{index}\n"))
                        .await
                        .expect("sequential zygote clone benchmark"),
                );
            }

            let mut tasks = Vec::new();
            for index in 0..PARALLEL {
                let requests = zygote.requests.clone();
                tasks.push(tokio::spawn(async move {
                    bench_zygote_clone(requests, &format!("parallel-clone-{index}\n")).await
                }));
            }
            for task in tasks {
                parallel_clones.push(
                    task.await
                        .expect("parallel clone task should not panic")
                        .expect("parallel zygote clone benchmark"),
                );
            }
        }

        if let Some(zygote) = cleanup_zygote.take() {
            bench_destroy_zygote(&zygote).await.expect("destroy zygote");
        }

        eprintln!("Kalahari Rust-layer boot benchmark");
        eprintln!("image: {IMAGE}");
        eprintln!("shape: 512 MiB, 1 vCPU");
        print_bench_summary("fresh boot", fresh_runs.iter().map(|run| run.boot));
        print_bench_summary(
            "fresh setup+command",
            fresh_runs.iter().map(|run| run.command),
        );
        print_bench_summary("fresh destroy", fresh_runs.iter().map(|run| run.destroy));
        print_bench_summary("fresh total", fresh_runs.iter().map(|run| run.total));
        eprintln!("zygote base boot: {base_boot:?}");
        eprintln!("zygote base setup+command: {base_setup_command:?}");
        eprintln!("convert sandbox to zygote: {conversion:?}");
        print_bench_summary(
            "sequential clone spawn",
            sequential_clones.iter().map(|run| run.spawn),
        );
        print_bench_summary(
            "sequential clone command",
            sequential_clones.iter().map(|run| run.command),
        );
        print_bench_summary(
            "sequential clone mutation",
            sequential_clones.iter().map(|run| run.mutation),
        );
        print_bench_summary(
            "sequential clone total",
            sequential_clones.iter().map(|run| run.total),
        );
        print_bench_summary(
            "parallel clone spawn",
            parallel_clones.iter().map(|run| run.spawn),
        );
        print_bench_summary(
            "parallel clone command",
            parallel_clones.iter().map(|run| run.command),
        );
        print_bench_summary(
            "parallel clone mutation",
            parallel_clones.iter().map(|run| run.mutation),
        );
        print_bench_summary(
            "parallel clone total",
            parallel_clones.iter().map(|run| run.total),
        );
    }

    struct KalahariBenchFreshRun {
        boot: Duration,
        command: Duration,
        destroy: Duration,
        total: Duration,
    }

    struct KalahariBenchCloneRun {
        command: Duration,
        mutation: Duration,
        spawn: Duration,
        total: Duration,
    }

    async fn bench_fresh_sandbox(
        store_dir: &Path,
        image: &str,
        requested_image: &str,
        state: &str,
    ) -> anyhow::Result<KalahariBenchFreshRun> {
        let started = Instant::now();
        let (sandbox, boot) =
            measure_result(bench_create_sandbox(store_dir, image, requested_image)).await?;
        let command_result = measure_result(bench_setup_and_read_state(&sandbox, state)).await;
        let (destroy_result, destroy) = measure(bench_destroy_sandbox(&sandbox)).await;
        destroy_result?;
        let ((), command) = command_result?;
        Ok(KalahariBenchFreshRun {
            boot,
            command,
            destroy,
            total: started.elapsed(),
        })
    }

    async fn bench_zygote_clone(
        requests: mpsc::Sender<ZygoteRequest>,
        state: &str,
    ) -> anyhow::Result<KalahariBenchCloneRun> {
        let started = Instant::now();
        let (child, spawn) = measure_result(bench_spawn_zygote_from_sender(requests)).await?;
        let command_result = measure_result(bench_read_state(&child, "zygote-base\n")).await;
        let mutation_result = measure_result(bench_setup_and_read_state(&child, state)).await;
        let destroy_result = bench_destroy_sandbox(&child).await;
        destroy_result?;
        let ((), command) = command_result?;
        let ((), mutation) = mutation_result?;
        Ok(KalahariBenchCloneRun {
            command,
            mutation,
            spawn,
            total: started.elapsed(),
        })
    }

    async fn bench_create_sandbox(
        store_dir: &Path,
        image: &str,
        requested_image: &str,
    ) -> anyhow::Result<KalahariNativeSandbox> {
        let queue_size = request_queue_size(Some(128))?;
        let actor_options = ActorOptions {
            store_dir: store_dir.to_path_buf(),
            image: image.to_string(),
            requested_image: requested_image.to_string(),
            worker_path: None,
            memory_mb: 512,
            vcpus: 1,
            timeout_ms: None,
            output_limit_bytes: DEFAULT_OUTPUT_LIMIT,
            network: NetworkOptions::default(),
        };
        let (request_tx, request_rx) = mpsc::channel(queue_size);
        let (ready_tx, ready_rx) = oneshot::channel();
        let ready = Arc::new(std::sync::Mutex::new(Some(ready_tx)));
        spawn_sandbox_actor(actor_options, request_rx, request_tx.clone(), ready)?;
        let ready_result = ready_rx
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari sandbox exited before reporting readiness"))?;
        ready_result.map_err(|error| anyhow::anyhow!(error))?;
        Ok(KalahariNativeSandbox {
            id: Uuid::new_v4().to_string(),
            image: image.to_string(),
            requested_image: requested_image.to_string(),
            store_dir: path_to_string(store_dir),
            created_at_ms: now_ms(),
            destroyed: Arc::new(AtomicBool::new(false)),
            transitioning: Arc::new(AtomicBool::new(false)),
            requests: request_tx,
        })
    }

    async fn bench_spawn_zygote_from_sender(
        requests: mpsc::Sender<ZygoteRequest>,
    ) -> anyhow::Result<KalahariNativeSandbox> {
        let (reply_tx, reply_rx) = oneshot::channel();
        requests
            .send(ZygoteRequest::Spawn {
                options: Box::new(CreateSandboxOptions {
                    image: None,
                    prepare_image: None,
                    store_dir: None,
                    worker_path: None,
                    memory_mb: None,
                    vcpus: None,
                    timeout_ms: None,
                    output_limit_bytes: None,
                    request_queue_size: Some(128),
                    network: None,
                }),
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari zygote worker has stopped"))?;
        let handle = reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari zygote worker dropped spawn reply"))?
            .map_err(|error| anyhow::anyhow!(error))?;
        Ok(KalahariNativeSandbox::from_actor(handle))
    }

    async fn bench_destroy_sandbox(sandbox: &KalahariNativeSandbox) -> anyhow::Result<()> {
        if sandbox.destroyed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        sandbox
            .requests
            .send(SandboxRequest::Shutdown {
                reply: Some(reply_tx),
            })
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari sandbox worker has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari sandbox worker dropped shutdown reply"))?
            .map_err(|error| anyhow::anyhow!(error))
    }

    async fn bench_destroy_zygote(zygote: &KalahariNativeZygote) -> anyhow::Result<()> {
        if zygote.destroyed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        zygote
            .requests
            .send(ZygoteRequest::Destroy {
                reply: Some(reply_tx),
            })
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari zygote worker has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari zygote worker dropped destroy reply"))?
            .map_err(|error| anyhow::anyhow!(error))
    }

    async fn bench_setup_and_read_state(
        sandbox: &KalahariNativeSandbox,
        state: &str,
    ) -> anyhow::Result<()> {
        bench_setup_state(sandbox, state).await?;
        bench_read_state(sandbox, state).await
    }

    async fn bench_setup_state(sandbox: &KalahariNativeSandbox, state: &str) -> anyhow::Result<()> {
        bench_run_command(
            sandbox,
            "@kalahari:fs-mkdir",
            &["/tmp/kalahari-bench"],
            None,
            None,
        )
        .await?;
        bench_run_command(
            sandbox,
            "@kalahari:fs-write",
            &["/tmp/kalahari-bench/state.txt"],
            None,
            Some(state.as_bytes()),
        )
        .await?;
        Ok(())
    }

    async fn bench_read_state(sandbox: &KalahariNativeSandbox, state: &str) -> anyhow::Result<()> {
        let script = concat!(
            "const fs = require('node:fs');",
            "const state = fs.readFileSync('/tmp/kalahari-bench/state.txt', 'utf8');",
            "process.stdout.write(`bench:${state}`);"
        );
        let result = bench_run_command(
            sandbox,
            "node",
            &["-e", script],
            Some("/tmp/kalahari-bench"),
            None,
        )
        .await?;
        assert_eq!(result.stdout, format!("bench:{state}"));
        Ok(())
    }

    async fn bench_run_command(
        sandbox: &KalahariNativeSandbox,
        command: &str,
        args: &[&str],
        cwd: Option<&str>,
        stdin: Option<&[u8]>,
    ) -> anyhow::Result<CommandResult> {
        let (reply_tx, reply_rx) = oneshot::channel();
        sandbox
            .requests
            .send(SandboxRequest::RunCommand {
                options: RunCommandOptions {
                    command: command.to_string(),
                    args: Some(args.iter().map(ToString::to_string).collect()),
                    stdin_base64: stdin
                        .map(|stdin| base64::engine::general_purpose::STANDARD.encode(stdin)),
                    env: None,
                    cwd: cwd.map(ToString::to_string),
                    timeout_ms: Some(10_000),
                    output_limit_bytes: Some(DEFAULT_OUTPUT_LIMIT),
                },
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari sandbox worker has stopped"))?;
        reply_rx
            .await
            .map_err(|_| anyhow::anyhow!("Kalahari sandbox worker dropped command reply"))?
            .map_err(|error| anyhow::anyhow!(error))
    }

    async fn measure<T>(future: impl Future<Output = T>) -> (T, Duration) {
        let started = Instant::now();
        let result = future.await;
        (result, started.elapsed())
    }

    async fn measure_result<T>(
        future: impl Future<Output = anyhow::Result<T>>,
    ) -> anyhow::Result<(T, Duration)> {
        let (result, elapsed) = measure(future).await;
        result.map(|value| (value, elapsed))
    }

    fn print_bench_summary(label: &str, values: impl Iterator<Item = Duration>) {
        let mut values: Vec<_> = values.collect();
        if values.is_empty() {
            eprintln!("{label}: no samples");
            return;
        }
        values.sort();
        let avg = values.iter().sum::<Duration>() / u32::try_from(values.len()).unwrap();
        let min = values[0];
        let p50 = values[(values.len() - 1) / 2];
        let p90 = values[((values.len() * 9).saturating_sub(1)) / 10];
        let max = values[values.len() - 1];
        eprintln!(
            "{label}: samples={} avg={avg:?} p50={p50:?} p90={p90:?} min={min:?} max={max:?}",
            values.len()
        );
    }

    #[test]
    fn network_options_default_to_unrestricted_policy() {
        let options = NetworkOptions::default();
        assert_eq!(options.mode.as_deref(), Some("unrestricted"));
        assert_eq!(options.dns_mode.as_deref(), Some("unrestricted"));
    }

    #[test]
    fn allow_all_packet_policy_admits_ipv4_and_ipv6_any_port() {
        let policy = allow_all_packet_policy().expect("allow-all policy should build");

        assert!(policy.is_allowed(Ipv4Addr::new(203, 0, 113, 10), 443));
        assert!(policy.is_allowed_ip(std::net::IpAddr::V6(Ipv6Addr::LOCALHOST), 8080));
    }

    #[test]
    fn network_backend_rejects_unknown_policy_modes() {
        let Err(error) = network_backend(&NetworkOptions {
            mode: Some("surprise".to_string()),
            dns: None,
            dns_mode: None,
            allow_list: None,
        }) else {
            panic!("unknown mode should be rejected");
        };

        assert!(
            error
                .to_string()
                .contains("unsupported Kalahari network mode")
        );
    }

    #[test]
    fn network_backend_accepts_supported_modes_and_dns_policies() {
        for mode in ["unrestricted", "publicInternet", "denyAll"] {
            network_backend(&NetworkOptions {
                mode: Some(mode.to_string()),
                dns: Some("1.1.1.1".to_string()),
                dns_mode: Some("useEgressPolicy".to_string()),
                allow_list: None,
            })
            .expect("supported network mode should build backend");
        }
    }

    #[test]
    fn network_backend_rejects_unknown_dns_mode_and_bad_dns() {
        let Err(error) = network_backend(&NetworkOptions {
            mode: None,
            dns: None,
            dns_mode: Some("surprise".to_string()),
            allow_list: None,
        }) else {
            panic!("unknown DNS mode should be rejected");
        };
        assert!(
            error
                .to_string()
                .contains("unsupported Kalahari DNS network mode")
        );

        let Err(error) = network_backend(&NetworkOptions {
            mode: None,
            dns: Some("not-an-ip".to_string()),
            dns_mode: None,
            allow_list: None,
        }) else {
            panic!("invalid DNS address should be rejected");
        };
        let error = error.to_string();
        assert!(error.contains("invalid") && error.contains("address"));
    }

    #[test]
    fn cidr_allow_list_policy_accepts_daytona_ipv4_cidr_format() {
        let policy = cidr_allow_list_policy(&[
            "208.80.154.232/32".to_string(),
            "192.168.1.0/24".to_string(),
        ])
        .expect("valid Daytona CIDR list should build a packet policy");

        assert!(policy.is_allowed(Ipv4Addr::new(208, 80, 154, 232), 443));
        assert!(policy.is_allowed(Ipv4Addr::new(192, 168, 1, 50), 22));
        assert!(!policy.is_allowed(Ipv4Addr::new(203, 0, 113, 10), 443));
    }

    #[test]
    fn cidr_allow_list_policy_rejects_daytona_invalid_entries() {
        let error = cidr_allow_list_policy(&["example.com".to_string()])
            .expect_err("hostnames are not valid Daytona network allow list entries");
        assert!(error.to_string().contains("IPv4 CIDR"));

        let too_many = vec!["1.1.1.1/32".to_string(); 11];
        let error = cidr_allow_list_policy(&too_many).expect_err("max 10 CIDRs");
        assert!(error.to_string().contains("at most 10"));
    }

    #[test]
    fn parse_ipv4_cidr_trims_and_validates_prefix() {
        assert_eq!(
            parse_ipv4_cidr(" 10.0.0.0/8 ").expect("valid CIDR"),
            (Ipv4Addr::new(10, 0, 0, 0), 8)
        );

        let error = parse_ipv4_cidr("10.0.0.0/33").expect_err("prefix too large");
        assert!(error.to_string().contains("prefix must be <= 32"));

        let error = parse_ipv4_cidr("10.0.0.0/8/extra").expect_err("extra slash");
        assert!(error.to_string().contains("IPv4 CIDR"));
    }

    #[test]
    fn pty_output_from_event_maps_stdout_stderr_and_exit() {
        let stdout = pty_output_from_event(scheduler::OutputEvent::Stdout(b"hello".to_vec()));
        assert_eq!(stdout.stdout.as_deref(), Some("hello"));
        assert_eq!(stdout.stderr, None);
        assert_eq!(stdout.exit_code, None);

        let stderr = pty_output_from_event(scheduler::OutputEvent::Stderr(b"err".to_vec()));
        assert_eq!(stderr.stdout, None);
        assert_eq!(stderr.stderr.as_deref(), Some("err"));
        assert_eq!(stderr.exit_code, None);

        let exit = pty_output_from_event(scheduler::OutputEvent::Exit(7));
        assert_eq!(exit.stdout, None);
        assert_eq!(exit.stderr, None);
        assert_eq!(exit.exit_code, Some(7));
    }

    #[test]
    fn pty_output_state_buffers_output_until_read() {
        let mut state = PtyOutputState::new();
        handle_pty_output_event(
            &mut state,
            Some(PtyOutput {
                stdout: Some("buffered".to_string()),
                stderr: None,
                exit_code: None,
            }),
        );

        let (tx, rx) = oneshot::channel();
        handle_pty_output_read(&mut state, tx);
        let output = rx
            .blocking_recv()
            .expect("read reply should be sent")
            .expect("read should succeed")
            .expect("buffered output should be returned");
        assert_eq!(output.stdout.as_deref(), Some("buffered"));
        assert!(state.buffered.is_empty());
    }

    #[test]
    fn pty_output_state_pending_read_resolves_on_later_output() {
        let mut state = PtyOutputState::new();
        let (tx, mut rx) = oneshot::channel();
        handle_pty_output_read(&mut state, tx);
        assert_eq!(state.pending_reads.len(), 1);
        assert!(rx.try_recv().is_err());

        handle_pty_output_event(
            &mut state,
            Some(PtyOutput {
                stdout: Some("later".to_string()),
                stderr: None,
                exit_code: None,
            }),
        );

        let output = rx
            .blocking_recv()
            .expect("read reply should be sent")
            .expect("read should succeed")
            .expect("output should be returned");
        assert_eq!(output.stdout.as_deref(), Some("later"));
        assert!(state.pending_reads.is_empty());
    }

    #[test]
    fn pty_output_state_eof_closes_pending_and_future_reads() {
        let mut state = PtyOutputState::new();
        let (pending_tx, pending_rx) = oneshot::channel();
        handle_pty_output_read(&mut state, pending_tx);

        handle_pty_output_event(&mut state, None);
        assert!(state.closed);
        assert!(
            pending_rx
                .blocking_recv()
                .expect("pending read should be sent")
                .expect("pending read should succeed")
                .is_none()
        );

        let (future_tx, future_rx) = oneshot::channel();
        handle_pty_output_read(&mut state, future_tx);
        assert!(
            future_rx
                .blocking_recv()
                .expect("future read should be sent")
                .expect("future read should succeed")
                .is_none()
        );
    }

    #[test]
    fn pty_output_eof_removes_session_without_buffered_output() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "pty".to_string(),
            PtySessionState {
                writer: None,
                output: PtyOutputState::new(),
            },
        );

        handle_pty_output(&mut sessions, "pty", None);

        assert!(!sessions.contains_key("pty"));
    }

    #[test]
    fn pty_output_eof_removes_session_after_buffered_exit_is_read() {
        let mut output = PtyOutputState::new();
        handle_pty_output_event(
            &mut output,
            Some(PtyOutput {
                stdout: None,
                stderr: None,
                exit_code: Some(0),
            }),
        );
        let mut sessions = HashMap::new();
        sessions.insert(
            "pty".to_string(),
            PtySessionState {
                writer: None,
                output,
            },
        );

        handle_pty_output(&mut sessions, "pty", None);
        assert!(sessions.contains_key("pty"));

        let (tx, rx) = oneshot::channel();
        handle_pty_read(&mut sessions, "pty", tx);
        let output = rx
            .blocking_recv()
            .expect("read reply should be sent")
            .expect("read should succeed")
            .expect("exit output should be returned");
        assert_eq!(output.exit_code, Some(0));
        assert!(!sessions.contains_key("pty"));
    }

    #[test]
    fn pty_read_unknown_session_returns_error_without_panic() {
        let mut sessions = HashMap::new();
        let (tx, rx) = oneshot::channel();
        handle_pty_read(&mut sessions, "missing", tx);

        let result = rx.blocking_recv().expect("reply should be sent");
        let Err(error) = result else {
            panic!("missing PTY should fail");
        };
        assert!(error.contains("was not found"));
    }

    #[test]
    fn shutdown_failure_replies_cover_pending_requests() {
        let (run_tx, run_rx) = oneshot::channel();
        let (read_tx, read_rx) = oneshot::channel();
        let (write_tx, write_rx) = oneshot::channel();
        let mut shutdown_replies = Vec::new();

        fail_or_collect_shutdown_request(
            SandboxRequest::RunCommand {
                options: RunCommandOptions {
                    command: "echo".to_string(),
                    args: None,
                    stdin_base64: None,
                    env: None,
                    cwd: None,
                    timeout_ms: None,
                    output_limit_bytes: None,
                },
                reply: run_tx,
            },
            &mut shutdown_replies,
        );
        fail_or_collect_shutdown_request(
            SandboxRequest::ReadPty {
                pty_id: "pty".to_string(),
                reply: read_tx,
            },
            &mut shutdown_replies,
        );
        fail_or_collect_shutdown_request(
            SandboxRequest::WritePty {
                pty_id: "pty".to_string(),
                data: b"input".to_vec(),
                reply: write_tx,
            },
            &mut shutdown_replies,
        );
        fail_or_collect_shutdown_request(
            SandboxRequest::PtyOutput {
                pty_id: "pty".to_string(),
                output: None,
            },
            &mut shutdown_replies,
        );

        let Err(error) = run_rx.blocking_recv().expect("run reply") else {
            panic!("run should fail");
        };
        assert!(error.contains("shutting down"));

        let Err(error) = read_rx.blocking_recv().expect("read reply") else {
            panic!("read should fail");
        };
        assert!(error.contains("shutting down"));

        let Err(error) = write_rx.blocking_recv().expect("write reply") else {
            panic!("write should fail");
        };
        assert!(error.contains("shutting down"));
        assert!(shutdown_replies.is_empty());
    }
}
