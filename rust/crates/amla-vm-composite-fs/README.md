# amla-vm-composite-fs

Composable FUSE filesystem wrappers: prefix, merge, overlay.

## What It Does

Stacks FUSE filesystem backends (as defined by `amla-vm-fuse`) into a single namespace without any kernel involvement. All inode remapping, readdir buffer rewriting, and name-collision handling happen in userspace before a response reaches the guest.

Three composition primitives:

- **Mount** — graft a backend under a directory prefix (e.g. mount an inner FS at `.git/`).
- **Overlay** — merge one `DynamicFsBackend` and one `FixedFsBackend` into one namespace using a fixed-low / dynamic-high inode partition; root collisions use overlay semantics where the dynamic upper layer wins.
- **Multi-fixed** — merge N `FixedFsBackend`s into a single `FixedFsBackend`, with each backend occupying a contiguous range of the global inode space.

`#![forbid(unsafe_code)]`. 64-bit only (enforced by `compile_error!`).

## Key Types

- `MountedFsBackend<F>` — inner backend grafted under a validated prefix
- `OverlayFsBackend<D, F>` — dynamic + fixed merge
- `MultiFixedFsBackend<L>` — N-way fixed-backend merge; `L` is an `HList` of
  concrete `FixedFsBackend` types built via the `hlist![…]` macro. Indexed
  dispatch unrolls into direct calls — no vtable, no heap-allocated futures.
- `InvalidMountPrefix` — error returned by `MountedFsBackend::new` for unusable prefixes

## Where It Fits

Layered on top of `amla-vm-fuse` (FsBackend traits) and consumed by the VMM to assemble a guest-visible namespace out of `amla-vm-synthesized-fs`, `amla-vm-redbfs`, EROFS-backed readers, and host passthrough — all presented to the guest over one virtio-fs transport.

## License

AGPL-3.0-or-later OR BUSL-1.1
