# amla-vm-mem

Cross-platform guest memory backing with hierarchical copy-on-write.

## What It Does

Owns the platform-specific memory object that sits under every guest RAM region: a memfd on Linux, a Mach memory entry on macOS, a section object on Windows. Exposes a uniform `MemHandle` API for allocation, sharing, mmap, branching, and page release.

CoW is multi-level by design — Amla runs VM fork trees, not pairs. On Linux, branching goes through `amla-vm-cowtree` (a custom `/dev/cowtree` kernel module) so a branch of a branch of a branch stays O(1). **`MAP_PRIVATE` CoW is explicitly rejected**: it is single-layer, cannot be re-forked, and would collapse the fork tree. Backends are selected at `allocate()` time with no fallback silently swapping semantics:

1. CowTree (kernel module, fastest)
2. Eager `sendfile` copy (compatibility path when the module is not loaded)

On macOS, branching uses Mach memory-entry tricks; ownership passes across processes as Mach port send rights (via `amla-vm-ipc`'s aux transport, not `SCM_RIGHTS`/`fileport`). On Windows, section views are backed by paging-file sections.

Handles carry a writable bit. `from_file` and `from_fd_arc_readonly` produce read-only handles; `allocate`, `branch`, and `from_fd_arc` produce writable ones. The bit survives IPC transfer (see `amla-vm-ipc`) so a read-only handle cannot be silently upgraded to `MAP_SHARED` RW on the receiving side.

Sharing is always through `Arc<OwnedFd>` — direct `OwnedFd::try_clone`, `File::try_clone`, and `rustix::io::dup` are banned workspace-wide via `clippy::disallowed_methods`. The one legitimate exception (aux-socket epoll registration needs two fd-table entries for the same kernel fd) opts out explicitly with `#[allow]` and a reason.

## Key Types

- `MemHandle` — platform-specific handle; `allocate`, `branch`, `try_clone` (cheap Arc share), `from_file`, `from_fd_arc`, `from_fd_arc_readonly`, `from_fd_validated`, `from_fd_range` (for EROFS regions embedded in the running executable), `punch_hole`, `is_writable`, `size`
- `MmapSlice` — RAII mmap wrapper; read-only by default, shared RW via `map_handle`
- `map_handle` — shared RW mmap of a writable `MemHandle`
- `PageAlignedLen` — a non-zero `usize` with explicit page-alignment proof; callers choose `round_up` or `from_page_aligned`
- `PageRange` — a checked non-empty page-aligned range contained within a handle, used for page release
- `MemError` — error enum; `sys(&str)` adapter for syscall failures
- `page_size()` — cached native host page size
- `SectionObject` — Windows-only handle type

## Where It Fits

Below the hypervisor backends (`amla-vm-kvm`, `amla-vm-hvf`, `amla-vm-hyperv`, `amla-vm-stub`) which map handles into guest physical space. Above it, `amla-vm-ipc` implements `IpcResource` for `MemHandle` so memory can be shared across VMM subprocesses. On Linux, depends on `amla-vm-cowtree` for the CowTree backend.

For the current research path toward allocator-informed VM memory reclamation,
see [`docs/hyperalloc-kalahari-research.md`](../../../../docs/hyperalloc-kalahari-research.md).

## License

AGPL-3.0-or-later OR BUSL-1.1
