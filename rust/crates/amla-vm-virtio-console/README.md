# amla-vm-virtio-console

Virtio console device (device ID 3) with MULTIPORT. Port 0 is the serial
console; port 1 is a side-channel for the guest agent.

## What It Does

Implements a 6-queue MULTIPORT console:

- queues 0,1 — port 0 RX/TX (serial console)
- queues 2,3 — control RX/TX (MULTIPORT handshake + port management)
- queues 4,5 — port 1 RX/TX (agent channel)

Features advertised (`device_features`): `VIRTIO_F_VERSION_1 |
VIRTIO_CONSOLE_F_MULTIPORT` — those two bits, nothing else.

`emerg_wr` at config offset 8 is handled via `write_config`, forwarding the
byte to the backend's `emergency_write`.

## Key Types

- `Console<'a>` — the device. Implements `VirtioDevice<M>` for any `M:
  GuestMemory`.
- `AgentPortBackend` — trait for port 1 (host side). `has_pending_rx`,
  `read_rx`, `write_tx`.
- `NullAgentPort` — no-op agent backend for tests or when port 1 is unused.
- `AGENT_TAG_KICK` — kick byte written on port 1 by the agent protocol.

The serial-side backend is `amla_core::backends::ConsoleBackend`, defined in
`amla-vm-core`; it is not re-exported here.

## Constructor

```rust
pub fn Console::new(
    port0: &'a dyn ConsoleBackend,
    port1: &'a mut dyn AgentPortBackend,
    pending_ctrl: &'a mut ConsoleControlState,
) -> Self
```

`pending_ctrl` stores host→guest control messages (`PORT_ADD`,
`CONSOLE_PORT`, `PORT_OPEN`) and is drained on the next control-RX kick. In
the VMM this is the `ConsoleState::control` field, so handshake progress is
part of the mmap-backed VM state.

## Usage

`Console::new` borrows its ports and the `pending_ctrl` state, so the
owning state (usually a device struct) must outlive the `Console`:

```rust,ignore
use amla_core::backends::ConsoleBackend;
use amla_virtio::ConsoleControlState;
use amla_virtio_console::{Console, NullAgentPort};

struct Device {
    port1: NullAgentPort,
    pending: ConsoleControlState,
}

impl Device {
    fn console<'a>(&'a mut self, port0: &'a dyn ConsoleBackend) -> Console<'a> {
        Console::new(port0, &mut self.port1, &mut self.pending)
    }
}
```

## Where It Fits

Depends on `amla-vm-core` (backends, guest memory) and `amla-vm-virtio`
(queue view, feature bits). Consumed by `amla-vm-vmm` for guest console
I/O and by integration tests to capture guest logs.

## License

AGPL-3.0-or-later OR BUSL-1.1
