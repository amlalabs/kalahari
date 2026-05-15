# amla-vm-virtio-rng

Virtio entropy device (device ID 4). The simplest virtio device — a thin
shell that fills guest-writable descriptors from the host's `getrandom()`.

## What It Does

Single request queue. On each kick, pops chains, fills every writable
descriptor via `getrandom::fill`, writes the buffer back to guest memory
with `DescriptorSlice::guest_write`, and pushes the used chain with
`bytes_written`.

Features advertised: `VIRTIO_F_VERSION_1` only.

## Key Types

- `Rng` — a stateless unit struct implementing `VirtioDevice<M>` for any
  `M: GuestMemory`. No `new()`; use `Rng`.

## Usage

```rust
use amla_virtio_rng::Rng;

let rng = Rng;
```

```bash
cargo test -p amla-vm-virtio-rng
```

(Tests live in `src/tests.rs` as a `#[cfg(test)]` module — no `tests/`
directory.)

## Where It Fits

Depends on `amla-vm-core`, `amla-vm-virtio`, `bytemuck`, and `getrandom`.
MMIO transport is supplied by `amla-vm-virtio-mmio`; the VMM
(`amla-vm-vmm`) wires `Rng` into a device slot.

## License

AGPL-3.0-or-later OR BUSL-1.1
