# amla-vm-virtio-pmem

virtio-pmem device for persistent-memory exposure.

## What It Does

Implements the virtio-pmem device with a single flush queue. The config region advertises the pmem region's GPA and size; the guest issues `virtio_pmem_req` flush requests and the device responds with `virtio_pmem_resp { type = OK }`. The backing memory is already host-mapped shared RW, so flushes are no-ops on this side — the point of the device is to let the guest kernel treat the region as persistent memory.

In Amla the primary consumer is **DAX-mapped EROFS rootfs images**. The EROFS image is mapped into the guest address space via virtio-pmem, and the guest mounts it with `dax=always` (or `dax=inode`) so reads of file data go directly to the pmem range without allocating page-cache pages inside the guest. This is how we avoid a double-copy of rootfs bytes on boot.

`#![forbid(unsafe_code)]`.

## Key Types

- `Pmem` — the device; zero-sized marker that implements `VirtioDevice`
- Advertises `DEVICE_ID_PMEM` + `VIRTIO_F_VERSION_1`, queue count 1

## Where It Fits

One of the virtio device crates above `amla-vm-virtio`. Wired up by the VMM against an `amla-vm-mem` handle (the EROFS image); paired at boot time with `amla-vm-erofs` for image layout. Separate from `amla-vm-virtio-mem` — pmem exposes a fixed persistent region, virtio-mem hot-plugs ordinary RAM.

## License

AGPL-3.0-or-later OR BUSL-1.1
