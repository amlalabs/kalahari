# amla-vm-constants

Shared numeric and protocol constants for amla-vm, usable from host and guest.

## What It Does

Holds constants that must be identical on both sides of the host/guest boundary and cannot live in `amla-vm-core` without forming dependency cycles. `#![no_std]`-compatible (the default `"std"` feature is off in `no_std` consumers) so the same crate compiles into guest-side binaries and kernel-adjacent code.

Contents:

- `GUEST_PAGE_SIZE = 4096` — guest kernel always uses 4 KiB pages, independent of host page size (Apple Silicon hosts still present 4 KiB pages to the guest).
- `HOST_FILE_UID` / `HOST_FILE_GID` — owner IDs stamped on host-side filesystems; the guest remaps these via an idmapped bind mount.
- `net` — default gateway/guest IPv4 + IPv6 addresses, netmasks, MACs, and DNS for the user-mode networking stack (10.0.2.0/24 + ULA).
- `protocol` — guest-agent wire protocol: `GuestMessage` / `HostMessage` enums, `MountOp` recursive mount DAG, raw-tag framing for high-throughput stdout/stdin/fs data, and golden-byte tests that pin discriminants.

## Where It Fits

Leaf-level crate with no amla-vm dependencies. Consumed by `amla-vm-core` (guest page size for memory layout), `amla-vm-erofs` (block size), the virtio crates, the user-mode network stack, and the guest agent. The protocol module is the single source of truth for the host↔guest agent wire format carried over `amla-vm-ringbuf`.

## License

AGPL-3.0-or-later OR BUSL-1.1
