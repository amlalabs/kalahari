# amla-vm-vmm

Ergonomic VMM API with typestate-enforced lifecycle.

Crate name: `amla-vm-vmm`. Library name: `amla_vmm`.

## What It Does

Porcelain layer over the platform hypervisor backend (`amla-vm-kvm` on Linux,
`amla-vm-hvf` on macOS, `amla-vm-hyperv` on Windows). Composes virtio devices,
networking, and filesystem backends into a complete VMM. State transitions
consume `self` and return a new type, so invalid operations are compile errors.

Threading model is 1:1 — one OS thread per vCPU, managed by the backend.
The VMM drives vCPUs through the backend's `resume()` futures; dropping the
resume future preempts the vCPU.

## State Machine

```text
   create()              load_kernel()           run(closure)
┌─────────┐ ──────────► ┌─────────┐ ──────────► ┌─────────┐
│   New   │             │  Ready  │ ◄────────── │  Ready  │
└─────────┘             └────┬────┘              └─────────┘
                             │
                             │ freeze()
                             ▼
                        ┌─────────┐
                        │ Zygote  │
                        └────┬────┘
                             │ spawn()
                             ▼
                        ┌─────────┐
                        │  Ready  │
                        └─────────┘
```

## Public Surface

- `VirtualMachine<S>` — typestate VM handle. `S` is `New`, `Ready<'a, F, N>`, or `Zygote`.
- `VmConfig`, `NetConfig`, `FsConfig`, `PmemDiskConfig`, `PmemImageConfig` — config types.
- `Backends<'a, F, N>` — struct holding a `&dyn ConsoleBackend` (required), an
  optional `&'a N` where `N: NetBackend`, an optional `&'a F` where
  `F: FsBackend` (both monomorphized; use `Null*Backend` defaults when absent),
  and `Vec<MemHandle>` for pmem images.
- `ConsoleStream`, `ConsoleBufferLimits` — bounded async console backend
  implementing `ConsoleBackend` + `AsyncRead` / `AsyncWrite`.
- `VmHandle<'dev, S>` — in-guest control handle passed to the `run()` closure.
  Starts as `Paused` (supports `attach()`), transitions to `Running` via
  `start()` (supports `exec()`, `exec_pty()`).
- `CommandExecution`, `CommandExecutionHandle`, `ExecBuilder`, `ExecError`,
  `StdinWriter`, `OutputEvent`, `CollectedOutput`, `MemoryPressureEvent`.
- `DeviceKind` — enum of devices in the GPA layout.
- `available()` — cheap non-destructive host hypervisor probe.
- `worker_main()` — subprocess worker entry point. Embedders parse their own
  role argument and call this before normal app startup.
- `WorkerProcessConfig` — explicit worker executable and argv passed to
  subprocess backends.
- Re-exports `amla_mem::MemHandle` (needed to construct `Backends.pmem`).

`backend::BackendPools` owns the shell pool and is constructed once per process.

## Where It Fits

Top of the stack. This is the crate end users interact with. Depends on the
platform hypervisor crate (`amla-vm-kvm` / `amla-vm-hvf` / `amla-vm-hyperv`),
the `amla-vm-virtio-*` device crates, `amla-vm-fuse`, `amla-vm-mem`,
`amla-vm-erofs`, `amla-vm-ringbuf`, and `amla-vm-boot`.

## Usage

```rust,ignore
use amla_vmm::backend::BackendPools;
use amla_vmm::{Backends, ConsoleStream, VirtualMachine, VmConfig, WorkerProcessConfig};

let config = VmConfig::default().memory_mb(256).vcpu_count(1);
let pools = BackendPools::new(
    8,
    &config,
    WorkerProcessConfig::path("/usr/local/bin/amla-vm-worker"),
)?;

let console = ConsoleStream::new();
let backends: Backends<'_, amla_fuse::NullFsBackend> = Backends {
    console: &console,
    net: None,
    fs: None,
    pmem: vec![],
};

let vm = VirtualMachine::create(config).await?;
let vm = vm.load_kernel(&pools, &kernel_bytes, backends).await?;

let (vm, ()) = vm.run(async |handle| {
    let handle = handle.start();
    let mut cmd = handle.exec(["echo", "hello"]).await.unwrap();
    cmd.wait().await.unwrap();
}).await?;
drop(vm);

let output = console.drain();
```

Shape notes (verified against `src/machine.rs`):

- `VirtualMachine::create(config)` takes only the config; pools are not bound here.
- `load_kernel(self, &pools, kernel, backends)` consumes the VM and returns
  `VirtualMachine<Ready<'a>>`. Backends borrow lives with the `Ready` state.
- `run(self, f)` takes `f: AsyncFnOnce(VmHandle<'_, Paused>) -> R` and returns
  `Result<(VirtualMachine<Ready<'a>>, R)>`. A successful run returns the healthy
  VM after state is saved; an error consumes and drops the VM.
- The closure receives a `Paused` handle. Call `.start()` to get a `Running`
  handle before calling `.exec()` / `.exec_pty()`.

## Features

- `usernet` — pulls in `amla-vm-usernet`.
- `subprocess` — forwards to `amla-vm-kvm/subprocess`.

The `amla-kvm-worker` binary built from this crate is a sidecar KVM worker
used by the `subprocess` feature. Single-binary embedders can instead pass
`WorkerProcessConfig::current_exe("--their-worker-role")` and dispatch that
role argument to `worker_main()` themselves.
`WorkerProcessConfig::path(...)` must be an absolute path; relative worker
paths are rejected to avoid cwd or `PATH`-dependent host process launches.

## Build / Test

```bash
cargo build -p amla-vm-vmm
cargo test -p amla-vm-vmm
```

## Network Wiring

`Backends::net` is generic over the concrete `NetBackend` type. The amla-container CLI uses a bare `UserNetBackend` by design (no filtering). Programmatic consumers compose layers to get filtering, interception, or rewriting:

- **Filter** (raw IP/port allowlist + conntrack): wrap with `amla_policy_net::PolicyNetBackend`. Typically built via `NetworkManager::new(packet_policy).create_backend(..)`.
- **Intercept / rewrite**: construct the inner `UserNetBackend` with concrete TCP and DNS policies via `new_with_policies` / `try_new_with_policies` (DNS: `Pass | Drop | Respond | Forward`). For TLS MITM and domain/HTTP policy, use `amla_tls_proxy_net` as the TCP policy/interceptor so host connect is deferred until stream evidence is allowed.

Pass the outermost backend into `Backends { net: Some(&backend), .. }`.

## License

AGPL-3.0-or-later OR BUSL-1.1
