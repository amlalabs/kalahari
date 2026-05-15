# amla-vm-stub

Stub hypervisor backend for platforms without a real one.

## What It Does

API-shape-compatible stand-in so `define_backend!(amla_stub)` wires up cleanly on any target. `VmPools::available()` returns `false`, `VmPools::new()` returns `Err(VmmError)`, and all operational methods `unreachable!()`. Linux is covered by `amla-vm-kvm` and macOS aarch64 by `amla-vm-hvf`; the stub is what everything else compiles to so build breakage on unsupported platforms is a startup error rather than a link error.

`#![forbid(unsafe_code)]`.

## Key Types

Mirrors the real backends:

- `VmPools` — always unavailable
- `Vm` / `VmBuilder` — same methods as `amla-vm-kvm` / `amla-vm-hvf`, all unreachable
- `HardwareLayout` — shared device slot geometry
- `VmmError` — single-variant error (`"no hypervisor backend on this platform"`)
- `worker_main()` — subprocess worker stub

## Where It Fits

Selected via `define_backend!(amla_stub)` on targets without KVM, HVF, or WHP. Depends only on `amla-vm-core`, `amla-vm-boot`, and `amla-vm-mem` — same surface as the real backends so call sites are target-agnostic.

## License

AGPL-3.0-or-later OR BUSL-1.1
