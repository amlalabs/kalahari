// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! macOS platform: Mach VM copy-on-write implementation.
//!
//! Uses `mach_vm_allocate` + `mach_make_memory_entry_64` for zero-copy `CoW`
//! branching. Memory entries (Mach ports) serve as the transfer handle,
//! analogous to Linux's sealed memfd or `CowTree` branch fds.
//!
//! # How it works
//!
//! - **`allocate()`**: `mach_vm_allocate` anonymous pages → `make_memory_entry`
//!   (`MAP_MEM_VM_SHARE`) wraps them as a transferable Mach port.
//! - **`branch()`**: allocates a fresh region, `mach_vm_map(copy=TRUE)` fills
//!   it with `CoW` references to the parent's pages, then wraps as a new entry.
//!   No data is copied until the child writes — the kernel handles `CoW` faults.
//! - **Mapping**: `map_entry_anywhere` / `map_entry_ro_anywhere` create host
//!   mappings from the entry port; the HVF worker passes these to `hv_vm_map`.

#![allow(dead_code)]

use crate::error::{MemError, Result};

// ============================================================================
// Mach VM FFI
// ============================================================================

/// `KERN_SUCCESS` return code.
const KERN_SUCCESS: i32 = 0;

/// Let kernel choose address.
const VM_FLAGS_ANYWHERE: i32 = 0x01;

/// Map at exact address.
const VM_FLAGS_FIXED: i32 = 0x00;

/// Overwrite existing mapping at target address.
const VM_FLAGS_OVERWRITE: i32 = 0x4000;

const VM_PROT_READ: i32 = 0x01;
const VM_PROT_WRITE: i32 = 0x02;

/// No inheritance across fork.
const VM_INHERIT_NONE: u32 = 2;

const MACH_PORT_NULL: u32 = 0;
const MACH_PORT_RIGHT_SEND: i32 = 0;

/// Create a copy-on-write memory entry.
const MAP_MEM_VM_COPY: i32 = 0x0200_0000;

/// Extract a VM range for remap (avoids 128 MiB per-entry cap).
const MAP_MEM_VM_SHARE: i32 = 0x0040_0000;

unsafe extern "C" {
    fn mach_task_self() -> u32;

    fn mach_vm_allocate(target: u32, address: *mut u64, size: u64, flags: i32) -> i32;

    fn mach_vm_deallocate(target: u32, address: u64, size: u64) -> i32;

    fn mach_vm_map(
        target: u32,
        address: *mut u64,
        size: u64,
        mask: u64,
        flags: i32,
        object: u32,
        offset: u64,
        copy: i32, // boolean_t
        cur_protection: i32,
        max_protection: i32,
        inheritance: u32,
    ) -> i32;

    fn mach_make_memory_entry_64(
        target: u32,
        size: *mut u64,
        offset: u64,
        permission: i32,
        object_handle: *mut u32,
        parent_entry: u32,
    ) -> i32;

    fn mach_port_mod_refs(task: u32, name: u32, right: i32, delta: i32) -> i32;

    fn mach_port_deallocate(task: u32, name: u32) -> i32;
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get the current task port.
#[inline]
fn task_self() -> u32 {
    // SAFETY: mach_task_self() is always safe — returns the current task port.
    unsafe { mach_task_self() }
}

/// Check a Mach kernel return code, converting non-zero to `MemError`.
fn check_kern(kr: i32, operation: &'static str) -> Result<()> {
    if kr == KERN_SUCCESS {
        Ok(())
    } else {
        Err(MemError::SystemCall {
            operation,
            source: std::io::Error::from_raw_os_error(kr),
        })
    }
}

/// Allocate a VM region with `mach_vm_allocate`.
pub(crate) fn vm_allocate(size: usize) -> Result<u64> {
    let mut addr: u64 = 0;
    // SAFETY: VM_FLAGS_ANYWHERE lets the kernel pick a safe address;
    // `&raw mut addr` is a local out-param for the chosen address.
    let kr =
        unsafe { mach_vm_allocate(task_self(), &raw mut addr, size as u64, VM_FLAGS_ANYWHERE) };
    check_kern(kr, "mach_vm_allocate")?;
    Ok(addr)
}

/// Deallocate a VM region with `mach_vm_deallocate`.
pub(crate) fn vm_deallocate(addr: u64, size: usize) -> Result<()> {
    // SAFETY: addr/size are from a successful vm_allocate or mmap.
    let kr = unsafe { mach_vm_deallocate(task_self(), addr, size as u64) };
    check_kern(kr, "mach_vm_deallocate")
}

/// Create a shared memory entry port from a VM region.
///
/// The memory entry is a Mach port representing the same physical pages
/// as the original region. Both the original mapping and any new mappings
/// created from the entry share the same memory (no copy-on-write).
///
/// The original region must remain allocated while the entry is in use.
pub(crate) fn make_memory_entry(addr: u64, size: usize) -> Result<(u32, usize)> {
    let mut entry_size = size as u64;
    let mut entry_port: u32 = MACH_PORT_NULL;

    // SAFETY: addr points to a valid VM region of at least `size` bytes.
    // MAP_MEM_VM_SHARE extracts the VM range for remap — without it the
    // kernel caps entries at 128 MiB.
    let kr = unsafe {
        mach_make_memory_entry_64(
            task_self(),
            &raw mut entry_size,
            addr,
            VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_SHARE,
            &raw mut entry_port,
            MACH_PORT_NULL,
        )
    };
    check_kern(kr, "mach_make_memory_entry_64")?;

    if entry_port == MACH_PORT_NULL {
        return Err(MemError::InvalidState {
            expected: "valid memory entry port",
            actual: "MACH_PORT_NULL",
        });
    }

    #[allow(clippy::cast_possible_truncation)]
    Ok((entry_port, entry_size as usize))
}

/// Create a read-only shared memory entry port from a VM region.
///
/// The entry holds a reference to the underlying VM object (file-backed
/// pages). Pages are demand-paged from disk — no eager copy. The entry
/// remains valid after the source mapping is destroyed.
pub(crate) fn make_memory_entry_ro(addr: u64, size: usize) -> Result<(u32, usize)> {
    let mut entry_size = size as u64;
    let mut entry_port: u32 = MACH_PORT_NULL;

    // SAFETY: addr points to a valid VM region of at least `size` bytes.
    let kr = unsafe {
        mach_make_memory_entry_64(
            task_self(),
            &raw mut entry_size,
            addr,
            VM_PROT_READ | MAP_MEM_VM_SHARE,
            &raw mut entry_port,
            MACH_PORT_NULL,
        )
    };
    check_kern(kr, "mach_make_memory_entry_64 (RO)")?;

    if entry_port == MACH_PORT_NULL {
        return Err(MemError::InvalidState {
            expected: "valid memory entry port",
            actual: "MACH_PORT_NULL",
        });
    }

    #[allow(clippy::cast_possible_truncation)]
    Ok((entry_port, entry_size as usize))
}

/// Create a copy-on-write memory entry port from a VM region.
///
/// The entry captures a snapshot of the memory. Writes to new mappings
/// trigger `CoW` — the original region can be safely deallocated.
pub(crate) fn make_memory_entry_cow(addr: u64, size: usize) -> Result<(u32, usize)> {
    let mut entry_size = size as u64;
    let mut entry_port: u32 = MACH_PORT_NULL;

    // SAFETY: addr points to a valid VM region of at least `size` bytes;
    // `&raw mut entry_size` / `&raw mut entry_port` are local out-params.
    // MAP_MEM_VM_COPY gives CoW semantics so the source can be freed.
    let kr = unsafe {
        mach_make_memory_entry_64(
            task_self(),
            &raw mut entry_size,
            addr,
            VM_PROT_READ | VM_PROT_WRITE | MAP_MEM_VM_COPY,
            &raw mut entry_port,
            MACH_PORT_NULL,
        )
    };
    check_kern(kr, "mach_make_memory_entry_64 (CoW)")?;

    if entry_port == MACH_PORT_NULL {
        return Err(MemError::InvalidState {
            expected: "valid memory entry port",
            actual: "MACH_PORT_NULL",
        });
    }

    #[allow(clippy::cast_possible_truncation)]
    Ok((entry_port, entry_size as usize))
}

// ============================================================================
// Fileport: fd ↔ Mach port conversion
// ============================================================================

unsafe extern "C" {
    fn fileport_makeport(fd: libc::c_int, port: *mut u32) -> libc::c_int;
    fn fileport_makefd(port: u32) -> libc::c_int;
}

/// Convert a file descriptor to a Mach send right (fileport).
///
/// The returned port can be sent to another process via Mach messages.
/// The receiver calls `fd_from_fileport` to get a local fd.
pub fn fileport_from_fd(fd: &std::os::fd::OwnedFd) -> Result<u32> {
    use std::os::fd::AsRawFd;
    let mut port: u32 = MACH_PORT_NULL;
    // SAFETY: `fd` is a valid OwnedFd; `&raw mut port` is a local out-param
    // for the returned send right.
    let ret = unsafe { fileport_makeport(fd.as_raw_fd(), &raw mut port) };
    if ret != 0 {
        return Err(MemError::SystemCall {
            operation: "fileport_makeport",
            source: std::io::Error::last_os_error(),
        });
    }
    Ok(port)
}

/// Convert a Mach fileport back to a file descriptor.
///
/// Consumes the send right — the port is no longer valid after this call.
pub fn fd_from_fileport(port: u32) -> Result<std::os::fd::OwnedFd> {
    use std::os::fd::FromRawFd;
    // SAFETY: `port` is a caller-supplied send right; `fileport_makefd`
    // returns a fresh fd on success or <0 on failure (checked below).
    let fd = unsafe { fileport_makefd(port) };
    if fd < 0 {
        return Err(MemError::SystemCall {
            operation: "fileport_makefd",
            source: std::io::Error::last_os_error(),
        });
    }
    // SAFETY: `fd` is a fresh non-negative fd (checked above) with no other
    // owners; OwnedFd takes ownership and closes it on drop.
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

/// Release a send right (decrement user reference count).
pub fn deallocate_port(port: u32) {
    // SAFETY: `port` is a caller-supplied send right; `mach_port_deallocate`
    // decrements the user-ref count and tolerates invalid names (returns an
    // error we intentionally ignore).
    unsafe {
        mach_port_deallocate(task_self(), port);
    }
}

/// Clone a send right by incrementing the user reference count.
///
/// After this call, the caller must eventually call `mach_port_deallocate`
/// to release the additional reference (handled by `MemHandle::drop`).
pub(crate) fn clone_send_right(port: u32) -> Result<()> {
    // SAFETY: port is a valid send right (from make_memory_entry or prior clone).
    let kr = unsafe { mach_port_mod_refs(task_self(), port, MACH_PORT_RIGHT_SEND, 1) };
    check_kern(kr, "mach_port_mod_refs")
}

/// Map a memory entry at a fixed address with `CoW` semantics.
///
/// Uses `VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE` to place the mapping at
/// the exact address, and `copy=TRUE` for copy-on-write.
///
/// # Safety
///
/// Caller must ensure `addr` points to a valid, pre-reserved memory region
/// of at least `size` bytes.
pub(crate) fn map_entry_fixed(
    addr: std::ptr::NonNull<u8>,
    size: usize,
    entry_port: u32,
) -> Result<()> {
    let mut target_addr = addr.as_ptr() as u64;
    // SAFETY: addr is a valid pre-reserved region; entry_port is a valid
    // memory entry. VM_FLAGS_FIXED|VM_FLAGS_OVERWRITE places the mapping
    // at the exact address.
    let kr = unsafe {
        mach_vm_map(
            task_self(),
            &raw mut target_addr,
            size as u64,
            0, // mask
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE,
            entry_port,
            0, // offset
            1, // copy = TRUE (CoW)
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE,
        )
    };
    check_kern(kr, "mach_vm_map")
}

/// Map a memory entry at a kernel-chosen address (shared, no copy).
pub(crate) fn map_entry_anywhere(entry_port: u32, size: usize) -> Result<u64> {
    let mut addr: u64 = 0;
    // mach_vm_map requires page-aligned size.
    let page = crate::page_size();
    let map_size = (size + page - 1) & !(page - 1);
    // SAFETY: `&raw mut addr` is a local out-param; VM_FLAGS_ANYWHERE lets the
    // kernel pick the address; `entry_port` is a valid memory entry send right.
    let kr = unsafe {
        mach_vm_map(
            task_self(),
            &raw mut addr,
            map_size as u64,
            0,
            VM_FLAGS_ANYWHERE,
            entry_port,
            0,
            0, // copy = FALSE (shared)
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE,
        )
    };
    check_kern(kr, "mach_vm_map")?;
    Ok(addr)
}

/// Map a memory entry at a kernel-chosen address as truly read-only.
///
/// `cur_protection = VM_PROT_READ` makes the host mapping genuinely RO — any
/// host write through it traps with SIGBUS. `max_protection` includes
/// `VM_PROT_WRITE` because HVF's `hv_vm_map` checks the host `vm_map_entry`'s
/// `max_protection` (NOT current protection) and rejects with generic
/// `HV_ERROR (0xfae94001)` if `VM_PROT_WRITE` is absent — even when the
/// guest mapping is `HV_MEMORY_READ | HV_MEMORY_EXEC`.
///
/// This split (cur=R, max=RW) gives us both: the worker process literally
/// cannot write through the mapping (kernel-enforced), and HVF still accepts
/// the region for stage-2 mapping into the guest. Verified empirically
/// against Darwin 25.x; see `tests/hvf_maxprot_test.c` style probes.
pub(crate) fn map_entry_ro_anywhere(entry_port: u32, size: usize) -> Result<u64> {
    let mut addr: u64 = 0;
    let page = crate::page_size();
    let map_size = (size + page - 1) & !(page - 1);
    // SAFETY: `&raw mut addr` is a local out-param; VM_FLAGS_ANYWHERE lets the
    // kernel pick the address; `entry_port` is a valid memory entry send right.
    // cur=R / max=RW is deliberate (see doc comment above).
    let kr = unsafe {
        mach_vm_map(
            task_self(),
            &raw mut addr,
            map_size as u64,
            0,
            VM_FLAGS_ANYWHERE,
            entry_port,
            0,
            0,                            // copy = FALSE (shared)
            VM_PROT_READ,                 // cur — kernel-enforced RO
            VM_PROT_READ | VM_PROT_WRITE, // max — required by HVF
            VM_INHERIT_NONE,
        )
    };
    check_kern(kr, "mach_vm_map (RO)")?;
    Ok(addr)
}

/// Map a memory entry at a kernel-chosen address with copy-on-write.
///
/// The mapping gets private `CoW` pages — writes trigger page faults that
/// allocate new physical pages, leaving the entry's backing unchanged.
pub(crate) fn map_entry_cow_anywhere(entry_port: u32, size: usize) -> Result<u64> {
    let mut addr: u64 = 0;
    let page = crate::page_size();
    let map_size = (size + page - 1) & !(page - 1);
    // SAFETY: `&raw mut addr` is a local out-param; VM_FLAGS_ANYWHERE lets the
    // kernel pick the address; `entry_port` is a valid memory entry send right;
    // copy=TRUE requests CoW so writes don't affect the source.
    let kr = unsafe {
        mach_vm_map(
            task_self(),
            &raw mut addr,
            map_size as u64,
            0,
            VM_FLAGS_ANYWHERE,
            entry_port,
            0,
            1, // copy = TRUE (CoW)
            VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE,
            VM_INHERIT_NONE,
        )
    };
    check_kern(kr, "mach_vm_map (CoW)")?;
    Ok(addr)
}
