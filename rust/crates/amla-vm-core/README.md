# amla-vm-core

Shared types, traits, and error types for the amla-vm VMM.

Crate name: `amla-vm-core`. Library name: `amla_core`.

## What It Does

Defines the foundational abstractions shared across VMM crates: the
`VmState<'a>` view over mapped VM state + guest memory, vCPU exit / response
types, MMIO and IRQ traits, backend traits (console / network), and error
types that never panic on guest input.

## Key Types

- `VmState<'a>` — concrete struct at `vm_state/view.rs`. View over a
  host-only metadata mmap plus the guest-visible memory regions. Provides
  section accessors (`header`, `irqchip`, `vcpu_slot`, etc.) and
  volatile GPA access via the `GuestMemory` trait.
- `VmStateHeader`, ring buffer constants, PFN helpers — under `vm_state`.
- `VcpuExit`, `VcpuResponse`, `VcpuError`, `ExitSource` — vCPU exit /
  response protocol used by backends' `resume()` API.
- `IrqLine`, `NullIrqLine` — trait for asserting / deasserting interrupt
  lines, plus a no-op impl.
- `IrqFactory` — backend-agnostic factory for creating resampled IRQ lines.
- `MmioDevice` — trait for MMIO-mapped devices (`read`, `write` take `&self`).
- `DeviceWaker`, `BasicDeviceWaker` — device polling notification plumbing.
- `MemoryMapping`, `MemoryHole`, `MapSource`, `MEMORY_HOLES` — GPA layout helpers.
- `backends::ConsoleBackend`, `backends::NetBackend`, `backends::NullNetBackend` —
  host-side I/O traits implemented by the VMM and network backends.
- `VmmError`, `VirtqueueError` — shared error enums. `VirtqueueError`
  converts into `VmmError::Virtqueue(..)`.

No `Vcpu` trait, no `VcpuTracker`, no `PreemptHandle`, no `IoEventFactory`,
and no typestate markers are defined here. vCPUs are driven via the
backend's `resume(vcpu_index, response)` async method (see `vcpu.rs`);
typestate markers (`New`, `Ready`, `Zygote`) live in `amla-vm-vmm`.

## Architecture Support

- `arm64` module — ARM64 register / system helpers.
- `x86_64` module — x86 register / system helpers.
- `GUEST_PHYS_ADDR` — GPA where guest RAM starts: `0x4000_0000` on
  `aarch64`, `0` elsewhere.
- `BLOCK_SIZE` = 2 MiB, `BLOCK_SIZE_MB` = 2, `MIN_MEMORY_MB` = 128 — block
  alignment / minimum RAM constants used by virtio-mem and the hotplug path.

## Where It Fits

Foundation of the crate graph. Downstream crates depend on `amla-vm-core`
for trait definitions and shared types. Dependencies are small:
`thiserror`, `bytemuck`, `parking_lot`, `log`, `serde`, `postcard`,
`amla-vm-constants`, `amla-vm-ipc`, `amla-vm-mem`.

## Usage

```rust
use amla_core::MmioDevice;

struct MyDevice;

impl MmioDevice for MyDevice {
    fn read(&self, _offset: u64, _size: u8) -> u64 { 0 }
    fn write(&self, _offset: u64, _data: u64, _size: u8) {}
}
```

## License

AGPL-3.0-or-later OR BUSL-1.1
