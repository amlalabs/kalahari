# amla-vm-redbfs

Writable FUSE filesystem backed by a redb (B-tree) database.

## What It Does

Implements `DynamicFsBackend` (from `amla-vm-fuse`) so it can be used as a virtio-fs mount — typically as the upperdir of an overlayfs inside the guest. All filesystem state lives in a single `.db` file: one table each for inodes, directory entries, 128 KiB file-data chunks, and xattrs.

Transaction model is tuned for the FUSE access pattern:

- Read ops (`lookup`, `getattr`, `readlink`, `access`, `read`, `readdir`, `readdirplus`, `getxattr`, `listxattr`, `get_parent`) use `begin_read()` — no write lock.
- Write ops use `begin_write()` with `Durability::None`: committing a transaction just releases the write lock, no fsync.
- The only path that does a durable commit is an explicit `fsync`. POSIX `close()` (`FUSE_FLUSH`) is a no-op.
- A pre-grow table (`_pregrow`) allocates 32 MiB up front so early writes don't keep triggering host-side `ftruncate`.
- File data is keyed by 64-bit chunk index, with writes and truncates rejected above the explicit redbfs file-size ceiling.

`to_erofs()` streams the current tree into an EROFS image — this is how a writable overlay upper gets promoted to an immutable rootfs layer.

`#![forbid(unsafe_code)]`.

## Key Types

- `RedbFs` — the backend; `open(path)`, `to_erofs(writer)`
- Implements `FsBackend` + `DynamicFsBackend` from `amla-vm-fuse`

## Where It Fits

A concrete filesystem backend consumed by `amla-vm-composite-fs` (as the dynamic side of an overlay) or directly by the virtio-fs device. Depends on `amla-vm-fuse` for the backend trait, `amla-vm-fuse-abi` for errnos, `amla-vm-erofs` for the export path, and `redb` for storage.

## License

AGPL-3.0-or-later OR BUSL-1.1
