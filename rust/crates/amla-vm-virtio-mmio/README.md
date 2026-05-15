# amla-vm-virtio-mmio

Virtio MMIO v2 transport. Dispatches register reads/writes for any
`VirtioDevice` implementation.

## What It Does

Implements the register interface from the virtio-mmio spec: feature
negotiation, queue setup (desc/avail/used addresses, `QUEUE_READY`),
status-register state machine, `QUEUE_NOTIFY`, interrupt
status/acknowledge, config-space read/write, and SHM-region selection.

One implementation, works for all device types.

## Address layout

Each device occupies a `0x200`-byte MMIO region. The MMIO window is
over-provisioned to 64 slots at `MMIO_BASE = 0x0A00_0000` (32 KiB total).
Unused slots return `device_id = 0` (not present).

- `NUM_DEVICES = 64` — reserved address-space slots.
- `MAX_ACTIVE_DEVICES` — x86_64 active-device limit (`19`; IOAPIC 24 pins,
  GSI offset 5). ARM64 active-device capacity is owned by
  `amla_boot::arm64::irq`.

## Key Types and Functions

- `MmioTransport<'a, D: VirtioDevice<M>, M: GuestMemory>` — per-device
  register dispatcher. Fields: `transport`, `queues`, `config`, `device`,
  `memory`, `irq`. Methods: `read(offset, size)`, `write(offset, size,
  value)`.
- `resolve_mmio_addr(addr) -> Option<(usize, u64)>` — absolute GPA to
  `(device_index, offset_within_device)`.
- `device_mmio_addr(idx) -> u64` — compile-time MMIO base for a slot.
- `device_gsi(idx) -> u32` — x86_64 GSI for a slot. ARM64 IRQ assignment is
  owned by `amla_boot::arm64::irq`.
- `MMIO_BASE`, `MMIO_DEVICE_SIZE`, `MMIO_TOTAL_SIZE`, `NUM_DEVICES`,
  `MAX_ACTIVE_DEVICES`.
- Register-offset re-exports: `MAGIC_VALUE`, `VERSION`, `DEVICE_ID`,
  `VENDOR_ID_REG`, `QUEUE_NOTIFY`, `INTERRUPT_STATUS`, `STATUS`,
  `CONFIG_GENERATION`.
- Constants: `VIRTIO_MMIO_MAGIC`, `VIRTIO_MMIO_VERSION`.

Note: config-space offsets (`0x100+`) are handled internally; the
`CONFIG_SPACE` constant is *not* re-exported from `lib.rs`.

## Where It Fits

Transport layer between the vCPU MMIO exit handler and individual
`VirtioDevice` implementations. Device state (`MmioTransportState`,
`QueueState`, config bytes) is defined in `amla-vm-virtio`; this crate
provides the register-level dispatch and address routing.

## Usage

```rust
use amla_core::IrqLine;
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{MmioTransportState, QueueState, VirtioDevice};
use amla_virtio_mmio::{MmioTransport, resolve_mmio_addr};

fn handle_exit<D, M>(
    exit_addr: u64,
    value: u64,
    transport: &mut MmioTransportState,
    queues: &mut [QueueState],
    config: &mut [u8],
    device: &mut D,
    memory: &M,
    irq: &dyn IrqLine,
) where
    D: VirtioDevice<M>,
    M: GuestMemory,
{
    if let Some((_dev_idx, offset)) = resolve_mmio_addr(exit_addr) {
        let mut t = MmioTransport::new(transport, queues, config, device, memory, irq);
        t.write(offset, 4, value);
    }
}
```

## Dependencies

`amla-vm-core`, `amla-vm-virtio`, `bytemuck`, `log`.

## License

AGPL-3.0-or-later OR BUSL-1.1
