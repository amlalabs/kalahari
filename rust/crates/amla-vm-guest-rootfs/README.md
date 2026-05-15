# amla-vm-guest-rootfs

Base guest kernel and unified guest binary, plus a runtime EROFS rootfs assembler.

Crate: `amla-vm-guest-rootfs` (lib name `amla_guest_rootfs`).

## What It Does

Embeds the guest Linux kernel and a statically-linked unified `amla-guest` binary (agent, init, exec, coreutils, optional test subcommands) at build time. The kernel is built automatically by `build.rs` (`kernel/Makefile`) if not already present.

The rootfs EROFS image itself is **not** embedded — it is assembled at runtime by `RootfsBuilder`, which writes the guest binary and a fixed directory skeleton into a fresh EROFS blob (via `amla-vm-erofs`). Container VMs and builder VMs consume this blob as the first virtio-pmem device.

## Exports

- `KERNEL: &[u8]` — embedded guest kernel (`vmlinux` ELF on x86_64, `Image` on aarch64)
- `AMLA_GUEST: &[u8]` — unified static-musl guest binary
- `RootfsBuilder` — EROFS rootfs assembler (re-exported from `rootfs_builder`)

## Features

- `test-binaries` — include test binaries (`/test/*`, `/vm_exit`, `/bin/https_get`) in the unified guest binary. Used by `amla-vm-vmm` integration tests.

## Where It Fits

Dependency of `amla-container` and `amla-vm-vmm` tests. Provides the base rootfs (pmem slot 0) for all VMs.

## Usage

```rust,no_run
let kernel: Vec<u8> = amla_guest_rootfs::KERNEL.to_vec();
let rootfs = amla_guest_rootfs::RootfsBuilder::base()
    .build()?;
# Ok::<(), amla_vm_erofs::ErofsError>(())
```

`RootfsBuilder::base()` returns `Self` (infallible). Only `.build()` is fallible — it surfaces any deferred error from earlier `add_file`/`try_push` calls and finalizes the EROFS blob.

## License

This crate is **`(AGPL-3.0-or-later OR BUSL-1.1) AND GPL-2.0-only`** — an
aggregate of two independently-licensed works:

- **Rust source** (`src/**`, `build.rs`, `RootfsBuilder`, the embedded
  `AMLA_GUEST` binary) is **AGPL-3.0-or-later OR BUSL-1.1**, matching the
  rest of the workspace. See the repository root `LICENSE`.
- **`KERNEL: &[u8]`**, `kernel/Makefile`, and `kernel/patches/*.patch`
  are Linux kernel material and are **GPL-2.0 only**. See
  [`LICENSE-GPL-2.0`](./LICENSE-GPL-2.0) for the license text and
  [`KERNEL-SOURCE.md`](./KERNEL-SOURCE.md) for the source availability
  notice required by GPL-2.0 §3.

Embedding is "mere aggregation" in GPL-2.0's terminology: the Rust code
hands an opaque binary blob to the hypervisor; there is no link-time or
source-level derivation between the Rust crate and the kernel. The two
licenses coexist in the same package under their own terms.

Distributing a binary that links this crate (e.g., `amla-container`)
inherits the GPL-2.0 obligations for the kernel portion: ship the GPL-2.0
text, and either include the kernel source or carry a written offer for
it. `KERNEL-SOURCE.md` in this crate is that written offer and points at
the pinned upstream (`linux-7.0.tar.xz`, SHA-256 in the file), local
patches, and build recipe.
