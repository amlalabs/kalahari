# amla-vm-synthesized-fs

Read-only FUSE filesystem synthesized from in-memory slices and host files.

## What It Does

Builds a FUSE tree programmatically, inode by inode, with all inodes allocated at construction time via a builder. File content comes from either a borrowed `&'a [u8]` (zero-copy) or an owned snapshot copied from a validated host file.

Implements `FixedFsBackend` (from `amla-vm-fuse`). The tree is immutable after `build()`: no create/write/unlink paths. Host-file paths are never reopened after construction.

Path validation on the builder rejects `.`, `..`, empty components, absolute paths, and embedded NUL — so a guest or higher-layer caller cannot sneak a path-traversal component into the synthesized tree.

`#![forbid(unsafe_code)]`, `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`, 64-bit only (enforced by `compile_error!`).

## Key Types

- `SynthesizedFs<'a>` — the backend; `builder()` for construction
- `SynthesizedFsBuilder<'a>` — add files (borrowed or host-file-backed), directories, timestamps, and uid/gid
- Implements `FsBackend` + `FixedFsBackend`

## Where It Fits

One of the concrete filesystem backends sitting above `amla-vm-fuse`. Typically composed via `amla-vm-composite-fs` (`MultiFixedFsBackend` / `OverlayFsBackend`) alongside `amla-vm-redbfs` or an EROFS reader, and presented to the guest over virtio-fs.

## License

AGPL-3.0-or-later OR BUSL-1.1
