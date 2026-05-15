# amla-vm-ipc

Inter-process communication fabric for the amla-vm subprocess model.

## What It Does

Universal IPC transport for amla-vm: host↔worker, host↔guest, and cross-process within the VMM. Built on `amla-vm-ringbuf` (SPSC ring over shared memory) plus a small per-OS control path — **not vsock**. This is the single IPC story for the project; Wayland, agent control, virtio backends, and the hypervisor worker protocol all ride the same primitives.

Three composable pieces:

- **Ring buffer** — postcard-serialized data over shared memory (fast, zero-copy reads via `amla-vm-ringbuf`).
- **Doorbell** — notification that ring data is available (4-byte sequence numbers).
- **Aux transport** — out-of-band resource handles (`AuxSlot`): `OwnedFd` + size on Linux, Mach-port send right + size on macOS. Decoupled from the ring so we never serialize an `fd`/port number — the kernel performs the ownership transfer.

A single message can carry both serialized data *and* resources. The `#[derive(IpcMessage)]` macro (see `amla-vm-ipc-derive`) extracts fields marked `#[ipc_resource]` into aux slots automatically; everything else goes through postcard. `IpcResource` is implemented here for `amla_mem::MemHandle`, encoding the read-only/read-write bit into the high bit of `AuxSlot::meta` so a read-only memory handle survives IPC without silently upgrading to RW.

Platform specifics:

- **Linux**: STREAM socketpair doorbell, SEQPACKET socketpair + SCM_RIGHTS for aux, memfd ring bootstrap over the doorbell.
- **macOS**: `AF_LOCAL` socketpair doorbell, Mach messages with port descriptors for aux (no `fileport`), `mach_ports_register` / `mach_ports_lookup` for bootstrap across `fork+exec`.

## Key Types

- `RingBuffer`, `Sender<'a, D, A>`, `Receiver<'a, D, A>` — generic channel parameterized by doorbell and aux transports
- `Subprocess` — spawn a worker with a pre-wired ring, doorbell, and aux socket
- `DoorbellSend` / `DoorbellRecv` / `AuxSend` / `AuxRecv` — platform-agnostic traits
- `AuxSlot` — single OOB resource (fd+meta on Linux, port+meta on macOS)
- `IpcResource` — trait for types that travel via aux (impl'd for `MemHandle`)
- `IpcMessage` — re-exported derive; splits messages into `(Vec<u8>, Vec<AuxSlot>)`
- `Error` — `{Io, Codec, MissingResource, Protocol, Ring}`

## Where It Fits

Sits above `amla-vm-ringbuf` (universal transport) and `amla-vm-mem` (resource sharing), and is consumed by the HVF worker, the KVM worker, the guest agent protocol, and any VMM-internal subprocess that needs to share fds or Mach ports. Unix-only today (Linux + macOS).

## License

AGPL-3.0-or-later OR BUSL-1.1
