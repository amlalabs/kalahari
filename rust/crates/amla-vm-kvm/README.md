# amla-vm-kvm

KVM backend: shell-only VM management.

Crate name: `amla-vm-kvm`. Library name: `amla_kvm`. Linux only — on other
targets the crate is empty.

## Overview

Manages KVM VM fds, vCPU fds, and pre-registered hardware (ioeventfds + irqfds).
Guest memory is owned by the VMM layer (`amla-vm-vmm`, via `amla-vm-mem`); this
crate only registers `MemHandle`s with KVM memory slots through
[`Vm::map_memory`].

Key mechanisms:

- **Shell pooling**: `VmPools` pre-warms KVM shells in a background task and
  drops acquired shells on a background thread. Acquire never blocks.
- **Snapshot / restore**: vCPU registers and irqchip state can be captured
  into a `VmState<'_>` view and restored on a fresh shell — the basis for
  zygote-style fast spawn.

## Quick Start

```rust,ignore
use amla_kvm::{HardwareLayout, Vm, VmPools};

// pool_size = 8 pre-warmed shells, vcpu_count = 1, no device layout.
let pools = VmPools::new(8, 1, HardwareLayout::empty())?;

// Build a shell (memory is registered separately via map_memory).
let vm: Vm<'_> = Vm::builder(&pools).build_shell().await?;

// Drive a vCPU: send a response (None on the first call), await the next exit.
let exit = vm.resume(0, None).await?;
// ... handle exit, then call resume(0, Some(response)) to continue ...

// Preempt before dropping the resume future.
vm.preempt_vcpu(0);
```

There is no `Vm<Paused>` / `Vm<Running>` typestate and no `start()` / `pause()`
method. A `Vm` owns a lightweight clone of its `VmPools` handle so it can
close or drop its shell after the caller's pool reference goes away. vCPU count
is fixed when constructing `VmPools`, not on the builder.

## Public Surface

From `amla_kvm` (Linux only):

- `Vm`, `VmBuilder`, `VmPools` — main VM types (from `builder`, or
  from `subprocess` if the `subprocess` feature is enabled).
- `HardwareLayout` — pre-registered ioeventfd / irqfd layout, used when
  constructing `VmPools`.
- `VcpuSnapshot`, `VmStateSnapshot` — register / irqchip snapshots.
- `IrqLine`, `irqs` — IRQ line helpers. `Vm<'_>` also implements
  `amla_core::IrqFactory`.
- `Result`, `VmmError` — crate error types.
- `boot` — arch-specific boot helpers (selected at compile time).
- `GUEST_PHYS_ADDR`, `page_size` — re-exports from `amla_core` / `amla_mem`.
- `worker_main()` — subprocess worker entry point.
- On x86_64: re-exports of `kvm_bindings::{kvm_fpu, kvm_lapic_state, kvm_regs, kvm_sregs, kvm_xcrs}`.

## Module Structure

```text
src/
├── lib.rs              # Module exports
├── builder/            # Vm, VmBuilder, VmPools
│   ├── mod.rs
│   ├── pools.rs        # VmPools, shell prewarm / acquire / drop
│   └── vm.rs           # Vm: resume, preempt, map_memory, save/restore state
├── arch/               # x86_64 / arm64 arch code + shared mmio
├── irq/                # ShellIrqLine, resampled line support
├── shell.rs            # KVM shell allocation + HardwareLayout
├── vcpu.rs             # vCPU-thread primitives used by the shell
├── device_waker.rs     # Device polling wake-up plumbing
├── subprocess/         # Optional: out-of-process KVM worker (feature `subprocess`)
└── error.rs            # VmmError, Result
```

Boot protocol lives in `amla-vm-boot` (single crate, arch selected at compile time).

## Features

- `subprocess` — enable the subprocess KVM worker (`amla-vm-ipc` + `serde` + `postcard`).

KVM intentionally uses a separate `amla-kvm-worker` executable. It does not
support same-binary integrated worker mode.

## Build / Test

```bash
cargo build -p amla-vm-kvm
cargo test -p amla-vm-kvm
```

Tests require Linux with `/dev/kvm` accessible.

## License

AGPL-3.0-or-later OR BUSL-1.1
