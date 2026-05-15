# amla-vm-virtio

Zero-copy virtio split-queue core: the `VirtioDevice` trait, `QueueView`, and
the `#[repr(C)]` Pod state structs that live in the snapshot mmap.

## What It Does

Implements the virtio 1.0+ split virtqueue with cycle detection and bounds
checking so the VMM can safely process descriptors from untrusted guest
memory. All transport/queue/device state is plain Pod — it lives directly in
the mmap'd VM state region, no serialization.

## Key Types

- `VirtioDevice<M: GuestMemory>` — trait for device implementations. No
  state: devices receive a `QueueView` per kick and process descriptors.
- `QueueView<'a, M>` — zero-copy view over one virtqueue. API: `pop`,
  `push(chain, bytes_written)`, `needs_notification`.
- `DescriptorChain<'a, M>` — lazy iterator over a chain, yielding
  `DescriptorSlice` items. Single-read per descriptor, with cycle detection.
- `DescriptorSlice<'a, M>` — one descriptor's buffer; call `guest_read()` /
  `guest_write()` for volatile access.
- `MmioTransportState` — per-device MMIO register state (40 bytes, Pod).
- `QueueState` — per-virtqueue addresses and cursors (40 bytes, Pod).
- `ConsoleState`, `NetState`, `RngState`, `FsState`, `PmemState`, `MemState`
  — flat Pod structs for each device type, sized to fit a 512-byte slot.
- `ConsoleConfig`, `NetConfig`, `FsConfig`, `PmemConfig`, `MemDeviceConfig`
  — device-specific config blobs.
- `VirtioState` trait — uniform access to `transport`/`queues`/`config`.
- `state_from<T>` / `state_ref<T>` — cast mmap byte slices to a typed Pod
  reference.

## Where It Fits

Sits between `amla-vm-core` (memory/error types, backend traits) and the
per-device crates (`amla-vm-virtio-net`, `-console`, `-rng`, `-fs`, etc.).
The MMIO dispatcher lives in `amla-vm-virtio-mmio`; this crate has no
transport glue — only the queue machinery and Pod layouts.

## Pop / push pairing

Every successful `QueueView::pop` MUST be paired with `push(chain, n)` on the
same view, including error paths (use `push(chain, 0)` on failure). There is
no auto-push via `Drop` — see the doc comment on `QueueView::pop` for
rationale. The popped chain is the completion capability; devices do not
complete queues by naming raw descriptor heads.

## Usage

```rust
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{QueueView, QueueViolation, VirtioDevice};

struct MyDevice;

impl<M: GuestMemory> VirtioDevice<M> for MyDevice {
    fn device_id(&self) -> u32 { 42 }
    fn queue_count(&self) -> usize { 1 }
    fn device_features(&self) -> u64 { amla_virtio::VIRTIO_F_VERSION_1 }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        queue: &mut QueueView<'_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(mut chain) = queue.pop() {
            let mut written = 0u32;
            for step in chain.by_ref() {
                let slice = step?; // walker errors propagate; transport sets DEVICE_NEEDS_RESET
                let _ = slice;
                written = written.saturating_add(1);
            }
            if queue.push(chain, written).is_err() {
                break;
            }
        }
        Ok(())
    }
}
```

State access from mmap bytes:

```rust
use amla_virtio::MmioTransportState;
let transport: &mut MmioTransportState = amla_virtio::state_from(slot_bytes);
```

## Dependencies

`amla-vm-core`, `bytemuck`, `log`.

## License

AGPL-3.0-or-later OR BUSL-1.1
