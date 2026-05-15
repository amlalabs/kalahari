# amla-vm-fuse

FUSE protocol dispatch and filesystem backend traits for virtio-fs.

## What It Does

Implements the FUSE wire protocol as seen by the VMM-side virtio-fs server. Each virtqueue descriptor chain carries a FUSE request in the readable descriptors and response space in the writable ones:

```text
Readable:  [FuseInHeader (40B)] [opcode-specific args] [optional data]
Writable:  [FuseOutHeader (16B)] [opcode-specific response] [optional data]
```

Handles the full set of opcodes actually used by Linux over virtio-fs (LOOKUP/GETATTR/SETATTR/READDIR/READDIRPLUS/READ/WRITE/CREATE/OPEN/RELEASE/STATFS/XATTR/...). Payload sizes are bounded (`MAX_FUSE_DATA_SIZE = 1 MiB`, `MAX_FUSE_NAME_SIZE = 4 KiB`) so a malicious guest cannot trigger host OOM via oversized descriptor lengths. `#![forbid(unsafe_code)]`.

FUSE is a Linux ABI: errno values and mode bits are defined as protocol constants (in `amla-vm-fuse-abi`) rather than pulled from host `libc`, so the crate compiles on Linux, macOS, and Windows hosts.

## Key Types

- `FsBackend` — base async trait a backend implements (lookup/getattr/readdir/...)
- `FixedFsBackend` — extension for backends with an inode count known at construction
- `DynamicFsBackend` — extension for writable backends (create/write/unlink/...)
- `FuseAttr` / `FuseAttrOut` / `FuseEntryOut` / `FuseDirent` / `FuseInitOut` — wire structs
- `pack_dirent` / `pack_direntplus` — helpers for building readdir response buffers
- `fs_types::rewrite_readdir_inodes` — readdir buffer inode rewriter used by composite backends
- `fuse_abi` — re-export of `amla-vm-fuse-abi` (errnos, `FuseError`)

## Where It Fits

Sits above `amla-vm-virtio` (descriptor chains, guest memory) and below `amla-vm-composite-fs`, `amla-vm-synthesized-fs`, `amla-vm-redbfs`, and the EROFS-backed reader. Was extracted from the virtio-fs device crate so that filesystem backends can be composed and unit-tested without spinning up a virtqueue.

## License

AGPL-3.0-or-later OR BUSL-1.1
