# amla-vm-ipc-derive

Proc-macro crate for `#[derive(IpcMessage)]`.

## What It Does

Generates the `IpcMessage` impl for a struct or enum so it can be sent over `amla-vm-ipc`. Fields annotated `#[ipc_resource]` must implement `IpcResource` — they are extracted into `AuxSlot`s during serialization (fds on Linux, Mach port send rights on macOS) and reconstructed during deserialization. Everything else is serialized with postcard.

The macro emits a private `*Wire` type holding just the postcard fields, so the ring buffer carries only POD bytes and the aux transport carries the kernel-level resource handles.

```rust
#[derive(IpcMessage)]
struct MapMemory {
    gpa: u64,
    #[ipc_resource]
    region: MemHandle,
    #[ipc_resource]
    extras: Vec<MemHandle>,
}
```

Works on structs with named fields and on enums (per-variant wire types). Unions and tuple structs are rejected at compile time with a clear error.

## Key Types

- `#[derive(IpcMessage)]` — the only export
- `#[ipc_resource]` — field attribute marking aux-slot fields

## Where It Fits

Sibling to `amla-vm-ipc`; re-exported as `amla_ipc::IpcMessage`. Any message type flowing between VMM and a subprocess worker (HVF worker, future KVM worker, guest agent wrappers) uses this derive rather than hand-writing the `(Vec<u8>, Vec<AuxSlot>)` split.

## License

AGPL-3.0-or-later OR BUSL-1.1
