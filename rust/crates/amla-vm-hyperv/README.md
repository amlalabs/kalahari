# amla-vm-hyperv

Windows Hyper-V (WHP) backend — stub today.

## What It Does

API-shape-compatible placeholder so `define_backend!(amla_hyperv)` compiles uniformly alongside `amla-vm-kvm`, `amla-vm-hvf`, and `amla-vm-stub`. No Hyper-V (Windows Hypervisor Platform) integration has been implemented: every constructor returns `Err(VmmError)` and every operational method `unreachable!()`s.

The repository is Linux-only today. This crate exists to keep the backend dispatch surface stable and to reserve the slot for a future WHP implementation.

`#![forbid(unsafe_code)]`.

## Key Types

Mirror the other backends:

- `VmPools` — `available()` returns `false`, `new()` returns `Err(VmmError)`
- `Vm` / `VmBuilder` — same methods as `amla-vm-kvm` / `amla-vm-hvf`, all unreachable
- `HardwareLayout` — device slot geometry (shared shape across backends)
- `VmmError` — single-variant error struct (`"hyper-v backend not implemented"`)
- `worker_main()` — subprocess worker stub

## Where It Fits

Peer to `amla-vm-kvm` (Linux), `amla-vm-hvf` (macOS aarch64), and `amla-vm-stub` (catch-all). Depends only on `amla-vm-core`, `amla-vm-boot`, `amla-vm-mem` — same surface as the real backends to keep `define_backend!` wiring uniform.

## License

AGPL-3.0-or-later OR BUSL-1.1
