# amla-vm-cowtree

Rust bindings for the Linux `cowtree` kernel module — hierarchical copy-on-write memory branching for VM snapshots.

Crate: `amla-vm-cowtree` (lib name `amla_cowtree`). Linux-only; the crate is empty on other targets.

## Overview

The `cowtree` kernel module lets a base memfd back an arbitrary tree of branches. Each branch shares pages with its parent until written; writes trigger a private page copy in the kernel.

```
Base (frozen after first branch)
├── Branch 1 (independent writes)
│   └── Branch 1.1 (nested snapshot)
└── Branch 2 (independent writes)
```

## Usage

```rust,ignore
use amla_cowtree::{CowTree, BranchId};
use std::os::fd::AsFd;

// Create a memfd as base memory (sized, populated).
let base = memfd::MemfdOptions::default().create("base")?;
base.as_file().set_len(256 * 1024 * 1024)?;
// ... write initial content to base ...

// Build a tree.
let mut tree = CowTree::from_base(base.as_fd(), 256 * 1024 * 1024)?;

// Create a branch with an mmap'd view.
let mut branch = tree.branch_mapped(BranchId::BASE)?;

// SAFETY: no other process or thread writes to this mapping while we hold it.
unsafe {
    branch.as_mut_slice()[..4].copy_from_slice(b"test");
}

// Nested branch from `branch`.
let _nested = tree.branch_mapped(branch.id())?;

// Statistics.
let stats = tree.stats()?;
println!("cow={} shared={}", stats.cow_pages, stats.shared_pages);
```

## API

### `CowTree`

| Method | Description |
|--------|-------------|
| `from_base(fd, size)` | Create tree from unsealed memfd |
| `branch(parent_id)` | Create branch, returns `BranchFd` |
| `branch_mapped(parent_id)` | Create branch plus an `mmap` view in one call |
| `stats()` | Tree-level statistics |
| `branch_stats(id)` | Per-branch statistics |
| `tree_id()` | Kernel tree handle |
| `size()` | Memory region size |
| `destroy()` | Explicit teardown (retryable on failure) |

### `BranchFd`

Owned branch fd plus tree cleanup authority. `BranchFd` implements `AsFd` and
`AsRawFd` for mmap/polling integrations, and exposes `id()` for the branch ID.
Keeping it alive also keeps the tree destroy handle alive, so branches cannot
outlive tree cleanup ownership.

| Method | Description |
|--------|-------------|
| `id()` | Branch identifier |
| `tree_id()` | Kernel tree handle |
| `size()` | Memory region size |

### `BranchMapping`

`mmap`'d view of a branch. Owns the underlying `BranchFd` and exposes raw
pointers plus `unsafe` slice accessors.

| Method | Description |
|--------|-------------|
| `id()` | Branch identifier |
| `as_ptr()` / `as_mut_ptr()` | Raw pointer access (safe) |
| `unsafe as_slice()` / `unsafe as_mut_slice()` | Slice view; caller upholds no-concurrent-write |
| `size()` | Mapping size |

### `BranchId`

```rust,ignore
BranchId::BASE        // root branch (id = 0)
BranchId::new(42)     // specific branch
id.as_u64()           // numeric value
```

### `Stats` (from the `ioctl` module)

| Field | Description |
|-------|-------------|
| `total_pages` | Pages in the memory region |
| `cow_pages` | Pages copied-on-write |
| `shared_pages` | Pages still sharing parent |
| `branch_count` | Branches in the tree |

## Design Notes

### Advisory Freeze

When a branch is created, the parent is "frozen" to prevent further writes. The freeze is advisory: existing PTEs remain writable (no TLB flush), and new write faults on the parent produce `SIGBUS`. The caller is responsible for pausing parent writers before branching. This keeps branch creation cheap.

### Kernel Module Interface

The crate talks to `/dev/cowtree` via ioctls: `COWTREE_CREATE_TREE`, `COWTREE_CREATE_BRANCH`, `COWTREE_GET_STATS`.

### Thread Safety

`CowTree` and `BranchFd` are `Send + Sync`; the kernel synchronizes tree-level
operations. Each `BranchMapping` follows standard `mmap` aliasing rules.

## Fallback

When `/dev/cowtree` is unavailable, higher-level consumers (see `amla-vm-mem`) fall back to sealed memfd + `MAP_PRIVATE` — single-level CoW only, no hierarchy, no statistics.

## Errors

```rust,ignore
pub enum Error {
    DeviceOpen(io::Error),
    Ioctl { operation: &'static str, source: io::Error },
    NotFound { tree_id, parent_id },
    Mmap(io::Error),
    Destroyed,
    InvalidSize(usize),
}
```

## Building

```bash
cargo build -p amla-vm-cowtree
cargo test  -p amla-vm-cowtree   # unit tests; integration tests need /dev/cowtree
```

Requires: Linux, `cowtree` kernel module loaded, page-aligned memory size.

## Related

- C header: `src/c/amla-cowtree/module/cowtree.h`
- Consumer: `amla-vm-mem` (integrates `cowtree` with a FUSE-backed fallback)

## License

AGPL-3.0-or-later OR BUSL-1.1
