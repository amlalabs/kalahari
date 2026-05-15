# amla-vm-boot

Linux boot protocol with architecture-specific backends.

## What It Does

Loads a Linux kernel and cmdline into guest physical memory and produces the initial vCPU register state needed to jump into it. The public API is the same on x86_64 and aarch64; target-specific modules are selected at compile time via the `define_arch!` macro, so a missing export on either arch is a compile error rather than a runtime surprise.

- **x86_64**: ELF kernel loading, Linux x86 boot parameters (zero page), identity-mapped long-mode page tables, GDT, MP table for SMP discovery.
- **aarch64**: PE/Image header parsing, flat kernel placement, Device Tree Blob generation with GICv3, PL011 UART, PSCI, and virtio MMIO nodes.
- `arm64::irq`: single source of truth for AMLA ARM64 platform interrupt assignments across DTB SPI cells, GIC INTIDs, and backend IRQ line keys.

## Key Types

- `LinuxBootBuilder<'a>` — uses `new(boot_mem, kernel)` with validated `BootGuestMemory`
- `BootGuestMemory` / `BootRamLayout` — typed guest-address to RAM-backing translation derived from VM-state mappings
- `BootResult` — arch-specific CPU state (`X86BootState` on x86_64, `Arm64VcpuSnapshot` on aarch64) that backends translate into hypervisor register writes
- `BootError` — arch-specific error enum
- `Result<T>` — `Result<T, BootError>`

## Where It Fits

Sits above `amla-vm-core` (guest memory + vCPU traits) and is consumed by every hypervisor backend (`amla-vm-kvm`, `amla-vm-hvf`, `amla-vm-hyperv`, `amla-vm-stub`). The backend takes a `BootResult` and applies it to its own register abstraction before running vCPU 0.

## License

AGPL-3.0-or-later OR BUSL-1.1
