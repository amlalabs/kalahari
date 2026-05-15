// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]

//! Ergonomic VMM API with typestate-enforced lifecycle.
//!
//! This crate provides a porcelain layer over `amla-kvm`, offering an easy-to-use,
//! typestate-enforced interface for VM lifecycle operations.
//!
//! # Threading Model
//!
//! vCPUs run in a 1:1 threading model: one OS thread per vCPU, managed by
//! the backend. The VMM interacts with vCPUs via `shell.resume()` futures.
//! Dropping the resume future preempts the vCPU.
//!
//! - **Low latency**: Exit -> handle -> re-enter is immediate
//! - **Fully async**: `run()` and lifecycle transitions are async.
//!
//! # Compiler-Enforced Safety
//!
//! The API uses several Rust type system features to prevent invalid operations:
//!
//! - **Sealed typestate**: The `MachineState` trait is sealed, preventing external
//!   implementations. State transitions consume `self` and return a new type.
//!
//! - **No device Arc exposure**: Devices are accessed via borrowed views tied
//!   to the VM lifetime, preventing reference leaks.
//!
//! # State Machine
//!
//! ```text
//!    create()              load_kernel()
//! ┌─────────┐ ──────────► ┌─────────┐
//! │   New   │             │  Ready  │
//! └─────────┘             └────┬────┘
//!                              │
//!              run ok ┌────────┴────────┐ run error
//!                     ▼                 ▼
//!                ┌─────────┐         dropped
//!                │  Ready  │
//!                └────┬────┘
//!                     │ freeze()
//!                     ▼
//!                ┌─────────┐
//!                │ Zygote  │
//!                └────┬────┘
//!                     │ spawn()
//!                     ▼
//!                ┌─────────┐
//!                │  Ready  │
//!                └─────────┘
//!                     │
//!                     │ park()
//!                     ▼
//!                ┌─────────┐
//!                │ Parked  │
//!                └────┬────┘
//!                     │ resume()
//!                     ▼
//!                ┌─────────┐
//!                │  Ready  │
//!                └─────────┘
//!
//! ```
//!
//! `amla-vm-scheduler` builds on this crate for callers that want
//! scheduler-owned backend pools and live-shell multiplexing.
//!
//! # Example
//!
//! ```no_run
//! # #[tokio::main(flavor = "current_thread")]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! # if !amla_vmm::available() { return Ok(()); }
//! use amla_vmm::{
//!     Backends, ConsoleStream, MemHandle, VirtualMachine, VmConfig, WorkerProcessConfig,
//! };
//! use amla_vmm::backend::BackendPools;
//!
//! // Bring your own kernel + rootfs; the dev-only `amla_guest_rootfs` crate
//! // is used here so the example is self-contained.
//! let kernel = amla_guest_rootfs::KERNEL;
//! let rootfs_image = amla_guest_rootfs::RootfsBuilder::base().build()?;
//! let rootfs = MemHandle::allocate_and_write(c"erofs", rootfs_image.image_size(), |buf| {
//!     rootfs_image.write_to(buf).map_err(std::io::Error::other)
//! })?;
//!
//! let config = VmConfig::default()
//!     .memory_mb(128)
//!     .vcpu_count(1)
//!     .pmem_root(rootfs.size().as_u64());
//! // Pool topology is derived from the same VmConfig used to create the VM.
//! // The worker path is only used by subprocess backends.
//! let pools = BackendPools::new(
//!     1,
//!     &config,
//!     WorkerProcessConfig::path("/usr/local/bin/amla-vm-worker"),
//! )?;
//!
//! let console = ConsoleStream::new();
//! let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
//!     console: &console,
//!     net: None,
//!     fs: None,
//!     pmem: vec![rootfs.try_clone()?],
//! };
//!
//! let vm = VirtualMachine::create(config).await?;
//! let mut vm = vm.load_kernel(&pools, kernel, backends).await?;
//!
//! // The closure receives a Paused `VmHandle`; `.start()` releases the vCPUs.
//! let (_vm, ()) = vm.run(async |vm| {
//!     let vm = vm.start();
//!     let mut cmd = vm.exec(["/bin/amla-guest", "echo", "hello"]).await.unwrap();
//!     let _ = cmd.wait().await;
//! }).await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Network Wiring
//!
//! `Backends::net` is generic over the concrete `NetBackend` type.
//! The amla-container CLI uses a bare `UserNetBackend` by design (no
//! filtering). Programmatic consumers compose layers around it to get
//! filtering, interception, or rewriting:
//!
//! - **Filter** (raw IP/port allowlist + conntrack): wrap with
//!   `amla_policy_net::PolicyNetBackend`, typically via
//!   `NetworkManager::new(packet_policy).create_backend(..)`.
//! - **Intercept / rewrite**: construct the inner `UserNetBackend` with concrete
//!   TCP and DNS policies via `new_with_policies` / `try_new_with_policies`
//!   (`Pass | Drop | Respond | Forward`). For TLS MITM and domain/HTTP policy,
//!   use `amla_tls_proxy_net` as the TCP interceptor so host connect is deferred
//!   until stream evidence is allowed.
//!
//! Pass the outermost backend into `Backends { net: Some(&backend), .. }`.

// 64-bit target enforced by compile_error! in machine.rs — u64→usize casts are lossless.
#![allow(clippy::cast_possible_truncation)]
#![deny(missing_docs)]

mod agent;
pub mod backend;
mod config;

mod console_stream;
mod device;
mod device_waker;
mod devices;
mod error;
mod machine;
mod run_backends;
mod shared_state;
mod state;
mod vcpu_loop;

// Public API - Core types

/// Check if the platform hypervisor is available.
///
/// Performs a cheap, non-destructive probe (e.g. opening `/dev/kvm` on Linux)
/// without creating any persistent state. Useful for test skip-checks.
pub fn available() -> bool {
    backend::BackendPools::available()
}

pub use config::{
    FsConfig, FsRequestQueueCount, GuestPath, KernelCmdlineAtom, NetConfig, PmemDiskConfig,
    PmemImageConfig, VirtioFsTag, VmConfig, VmTopology, VmTopologyEntry,
};
pub use devices::DeviceKind;
pub use error::{ConfigError, DeviceError, Error, Result};
pub use state::{New, Parked, Ready, Zygote};

// VM ownership with typestate
pub use machine::{ResumeParkedError, VirtualMachine};
pub use run_backends::{Backends, SpawnBackends};

// VM handle and exec APIs
pub use agent::{
    CollectedOutput, CommandExecution, CommandExecutionHandle, CommandSpec, CountedReceiver,
    DEFAULT_COLLECT_OUTPUT_LIMIT, ExecArg, ExecBuilder, ExecError, GuestCwd, GuestEnvVar,
    IntoHandleError, MemoryPressureEvent, OutputEvent, Paused, Running, StdinWriter, VmHandle,
};
pub use console_stream::{ConsoleBufferLimits, ConsoleStream};

// Re-export MemHandle — callers need it for Backends.pmem.
pub use amla_core::{WorkerBinary, WorkerProcessConfig};
pub use amla_mem::MemHandle;

/// Subprocess worker entry point. Never returns.
pub async fn worker_main() -> ! {
    backend::worker_main().await
}
