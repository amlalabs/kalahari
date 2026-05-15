# amla-vm-hvf

macOS Hypervisor.framework backend for amla-vm (aarch64 only).

## What It Does

The HVF backend. On macOS / aarch64 this is the real implementation: `hv_vm_*`, `hv_vcpu_*`, GICv3 emulation, and a subprocess worker model that runs each VM's vCPUs in a dedicated child process so a guest cannot compromise the VMM address space. On every other target it compiles as a stub (the `stubs` module re-exports `Vm`, `VmBuilder`, `VmPools`, `HardwareLayout`, `DeviceSlotLayout`) so the workspace still builds, but every constructor returns an error.

Design notes:

- **Subprocess-isolated vCPUs**: vCPUs run in a worker process (`amla-hvf-worker`), not the VMM. IPC goes over `amla-vm-ipc` (ring buffer + doorbell + Mach-port aux transport) — not vsock.
- **Pre-warmed VM pools**: `hv_vm_create` is slow; `VmPools` keeps N VMs hot and hands them to builders on demand.
- **GICv3 emulation**: HVF does not provide an interrupt controller on aarch64, so redistributor and distributor pages are implemented in Rust and wired through the `IrqLine` / `IrqFactory` traits from `amla-vm-core`.
- **Explicit worker launch**: embedders pass the worker executable and argv through `WorkerProcessConfig`. Single-binary clients can self-exec with a role argument and call `worker_main()` after parsing it.

## Private Apple APIs

This backend depends on a handful of **undocumented Hypervisor.framework
SPIs** that are not part of Apple's public API contract:

- `_hv_vcpu_get_context` / `_hv_vcpu_set_context` — raw vCPU state snapshot/restore used for VM fork and resume.
- `_hv_vcpu_config_set_tlbi_workaround` — required for correct behavior on certain Apple Silicon TLB flushes.

Upstream Virtualization.framework links against these same symbols, so
they are stable across current macOS versions, but Apple may remove or
change them in any future release. The `ffi` module documents each call
individually; if a symbol disappears the backend fails at initialization
rather than at runtime. Bootstrap of subprocess Mach-port injection also
probes the private layout of `_posix_spawnattr` — see `amla-vm-ipc`'s
`find_psa_ports_offset` for details.

Forks targeting a long-term stable surface should plan to replace these
with equivalents from Virtualization.framework (public) once their
functionality is covered there.

## Key Types

- `VmPools` — pre-warmed VM pool; `available()` reports backend support
- `Vm` / `VmBuilder` — VM handle plus state / memory / boot wiring
- `HardwareLayout` / `DeviceSlotLayout` — device slot geometry shared with the boot crate
- `worker_main()` — subprocess worker entry point
- `VmmError` — backend error enum

## Where It Fits

Peer to `amla-vm-kvm`, `amla-vm-hyperv`, and `amla-vm-stub`. The VMM composes a chosen backend via `define_backend!` at build time. Depends on `amla-vm-core`, `amla-vm-boot`, `amla-vm-mem`, and (on macOS aarch64) `amla-vm-ipc` for worker-side communication over ringbuf.

## License

AGPL-3.0-or-later OR BUSL-1.1
