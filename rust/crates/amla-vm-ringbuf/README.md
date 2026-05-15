# amla-vm-ringbuf

SPSC lock-free ring buffer over shared memory — the universal transport in Amla.

## What It Does

Two unidirectional single-producer/single-consumer rings (host→guest and guest→host) sharing a single shared-memory region with length-prefixed message framing. This is **the** IPC transport in Amla: host↔guest, guest↔guest, and guest-internal. Wayland, the agent control channel, virtio backends in subprocess mode, and the HVF / future KVM worker protocol all ride this ring — **not vsock**.

`#![no_std]` so it compiles into kernel, guest, and host contexts without modification. Verified with Kani in adversarial-writer mode.

## Memory layout

`RingBuffer<N>` where `N` is each ring's data capacity in bytes (power of two):

```text
Offset       Size     Content
0x0000       64B      SharedHeader  (magic=AMRB, version)
0x0040       64B      HG RingHeader (head / tail atomics, 28B pad each)
0x0080       64B      GH RingHeader
0x00C0       N        HG ring data
0x00C0+N     N        GH ring data
Total:       192 + 2*N
```

Messages are `[u32 LE length][payload]`. A zero-length frame is the wrap marker — readers skip to offset 0. Frames never straddle the wrap boundary, so readers can hand out a `&[u8]` pointing directly into the ring.

The default `HostGuestRingBuffer = RingBuffer<HOST_GUEST_RING_SIZE>` is 64 MiB per direction; `MAX_PAYLOAD_SIZE = 16 MiB` is enough for GPU frame data.

## Hardening

- **Adversarial writer**: `try_peek` snapshots the writer's head once per call and bounds the skip distance so a misbehaving peer cannot force the reader into an unbounded loop.
- `advance()` must follow a successful `try_peek()`; misuse returns `RingError::NothingPeeked` rather than silently desynchronizing cursors.
- `SharedHeader` magic + version are validated on attach (`RingError::BadMagic`, `BadVersion`).
- Head/tail cursors are cache-line padded (64B) to avoid false sharing.

## Key Types

- `RingBuffer<N>` — typed region (`#[repr(C)]`, safe to place in shared memory)
- `HostGuestRingBuffer` — 64 MiB default
- `RingWriter<'a>` / `RingReader<'a>` — producer/consumer handles
- `SharedHeader` / `RingHeader` — on-wire layout (cache-aligned, 64B each)
- `RingError` — `{PayloadTooLarge, NothingPeeked, Corrupt, BadMagic, BadVersion}`
- `MAGIC` (`AMRB`), `VERSION` (3), `MAX_PAYLOAD_SIZE` (16 MiB)

## Where It Fits

Leaf-level `no_std` crate. Consumed by `amla-vm-ipc` (host↔worker), the guest agent, the virtio subprocess backends, and anywhere in the stack that needs byte-oriented IPC. Not a replacement for virtqueues — this is a flat byte-stream transport above shared memory, used outside the virtio device model.

## License

AGPL-3.0-or-later OR BUSL-1.1
