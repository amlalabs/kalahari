# Linux kernel — source availability notice

The constant `amla_guest_rootfs::KERNEL: &[u8]`, the files under
`kernel/`, and the patches under `kernel/patches/` are Linux kernel
material, licensed under **GPL-2.0 only**. See
[`LICENSE-GPL-2.0`](./LICENSE-GPL-2.0) for the full license text.

## Complete corresponding source (GPL-2.0 §3(a))

- Upstream: Linux kernel 7.0
- Source tarball: `https://cdn.kernel.org/pub/linux/kernel/v7.x/linux-7.0.tar.xz`
- SHA-256: `bb7f6d80b387c757b7d14bb93028fcb90f793c5c0d367736ee815a100b3891f0`
- Upstream homepage: `https://www.kernel.org/`

## Build configuration

The kernel is built from upstream source plus the local patches in
`kernel/patches/`. `kernel/Makefile` in this crate is the authoritative,
machine-readable build recipe. The configuration is produced by:

1. `allnoconfig` with a 64-bit seed (`CONFIG_64BIT=y` on x86).
2. The `scripts/config` invocation in the `$(KERNEL_BUILD_DIR)/.config` rule,
   which enables virtio-mmio, virtio-{blk,console,rng,balloon,mem,net,fs,pmem},
   overlayfs, erofs, namespaces, cgroups, seccomp, and architecture-specific
   options (KVM paravirt + 8250 UART on x86; GICv3 + PSCI + PL011 on arm64).
3. `olddefconfig` to fill in remaining defaults.

`kernel/Makefile` is the authoritative, machine-readable description of the
build. Reproducing the embedded kernel exactly requires only:

```
cd kernel && make GUEST_ARCH=x86_64   # or GUEST_ARCH=arm64
```

with a Linux host toolchain (`make`, `wget`, `gcc`, `flex`, `bison`, `bc`).

## Patches

The build applies all `.patch` files under `kernel/patches/` (in
lexicographic order, via `patch -p1`) before configuring the kernel,
subject to the version gates encoded in `kernel/Makefile`.
Current patches:

- `0000-ovl-fix-ESTALE-for-FUSE-upper-by-using-linked-dentry.patch` —
  fixes persistent `-ESTALE` on overlayfs with a FUSE/virtiofs upper
  (regression from commit 6b52243f633e).
- `0000-ovl-fix-ESTALE-for-FUSE-upper-by-using-linked-dentry-mainline.patch` —
  same overlayfs fix for kernels whose copy-up tmpfile code uses
  `end_creating(upper)`.
- `0001-dax-check-for-empty-entries-before-pfn_to_page.patch` — avoids
  calling `pfn_to_page()` on empty DAX entries.

## Written offer

In addition to the URL above, the copyright holders of this crate will,
for at least three years from the date of distribution of any binary
built from this crate, provide the complete corresponding source code
of the embedded kernel to any third party, on a medium customarily used
for software interchange, for a charge no more than the cost of
physically performing source distribution. Contact the project
maintainers via the repository listed in `Cargo.toml`.
