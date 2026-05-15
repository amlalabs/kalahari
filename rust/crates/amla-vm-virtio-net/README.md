# amla-vm-virtio-net

Virtio network device (device ID 1) with pluggable backend and optional
multi-queue.

## What It Does

Implements virtio-net with 1..=5 queue pairs (even = RX, odd = TX). When
`queue_pairs > 1`, a control virtqueue is added at index `2 * queue_pairs`
for MQ negotiation (`VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`). The selected active
queue-pair count is stored in mmap-backed `NetControlState`; queues above that
active count are ignored until the driver selects them.

Packet path:

- TX: collects non-writable descriptor buffers, skips the 12-byte
  virtio-net header, and calls `NetBackend::send` once per chain via an
  `IoSlice` vector.
- RX: leases one complete packet from `NetBackend::rx_packet`, proves guest
  descriptor capacity, writes the virtio-net header plus payload to guest
  memory, then commits the lease.

Per-packet size is capped at 65535 bytes to defend against oversized
descriptor chains.

## Features advertised

- Always: `VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC`.
- When `queue_pairs > 1`: additionally `VIRTIO_NET_F_CTRL_VQ |
  VIRTIO_NET_F_MQ`.

That is the complete set. No `STATUS`, `MTU`, `MRG_RXBUF`, `CSUM`, or GSO.

## Key Types

- `Net<'a>` — the device, generic over any `M: GuestMemory` via
  `VirtioDevice<M>`.
- `MAX_QUEUE_PAIRS` (= 5) — upper bound, limited by the 512-byte `NetState`
  slot in `amla-vm-virtio`.

The `NetBackend` trait lives in `amla_core::backends` — not this crate.
`NetConfig` (MAC, status, `max_virtqueue_pairs`, MTU, speed, duplex) is
defined in `amla-vm-virtio`.

## Constructor

```rust
pub fn Net::new<B: NetBackend + ?Sized>(
    backend: &'a B,
    queue_pairs: u16,
    control: &'a mut NetControlState,
) -> Self
```

MAC is written into `NetConfig.mac` by the device setup in `amla-vm-vmm`,
not passed to the constructor.

## Usage

```rust
use amla_core::backends::NetBackend;
use amla_virtio::NetControlState;
use amla_virtio_net::Net;

fn build<'a, B: NetBackend + ?Sized>(
    backend: &'a B,
    control: &'a mut NetControlState,
) -> Net<'a, B> {
    Net::new(backend, 1, control) // single queue pair
}
```

## Where It Fits

Depends on `amla-vm-core` and `amla-vm-virtio`. Backend implementations
live in `amla-vm-tls-proxy-net` (user-mode TLS-aware egress) and any other
`NetBackend` impl.

## License

AGPL-3.0-or-later OR BUSL-1.1
