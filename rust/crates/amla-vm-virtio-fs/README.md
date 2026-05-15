# amla-vm-virtio-fs

Thin virtio-fs (device ID 26) MMIO shell. The FUSE request-handling logic
lives elsewhere — this crate only advertises the device and enumerates
queues.

## What It Does

Provides `Fs`, a `VirtioDevice<M>` implementation for virtio-fs. Queues:

- queue 0 — hiprio
- queues 1..=N — request queues (`N = num_request_queues`, `1..=9`)

`process_queue` is a **no-op**. The VMM (`amla-vm-vmm`) drives FUSE
processing asynchronously from the request queues; protocol parsing and
dispatch live in `amla-vm-fuse`.

Features advertised: `VIRTIO_F_VERSION_1` only.

## Key Types

- `Fs` — the device. `Fs::new(num_request_queues: u32)` where
  `num_request_queues ∈ 1..=9`. `Fs::default()` = 1 request queue.
- `HIPRIO_QUEUE` (= 0) — hiprio queue index.
- `FIRST_REQUEST_QUEUE` (= 1) — index of the first request queue.
- `MAX_REQUEST_QUEUES` (= 9) — upper bound, limited by the 512-byte
  `FsState` slot in `amla-vm-virtio`.

## Where the real work happens

- FUSE ABI + request parsing: `amla-vm-fuse`.
- Queue polling, request dispatch (tokio `futures_util::future::join_all`),
  reply writeback: `amla-vm-vmm` (`device.rs`).
- MMIO register dispatch: `amla-vm-virtio-mmio`.

## Usage

```rust
use amla_virtio_fs::Fs;

// 1 hiprio + 4 request queues
let dev = Fs::new(4);
```

## Dependencies

`amla-vm-core`, `amla-vm-virtio`, `amla-vm-fuse`, `bytemuck`.

## License

AGPL-3.0-or-later OR BUSL-1.1
