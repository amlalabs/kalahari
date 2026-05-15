// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Low-level ioctl definitions for `cowtree`.
//!
//! These definitions mirror the C header at `include/cowtree.h`.
//! Most users should use the higher-level [`CowTree`](crate::CowTree) API.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::{BranchId, Error, Result};

// =============================================================================
// Ioctl Numbers (from cowtree.h)
// =============================================================================

/// Ioctl magic number for cowtree
const COWTREE_IOCTL_MAGIC: u8 = 0xB7;

// =============================================================================
// Ioctl Argument Structures (matching C header exactly)
// =============================================================================

/// Arguments for `COWTREE_CREATE_TREE`.
///
/// ```c
/// struct cowtree_create_tree {
///     __s32 base_fd;
///     __u32 flags;
///     __u64 size;
///     __u64 tree_id;  /* out */
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default)]
pub struct CreateTreeArgs {
    /// Input: fd to memfd/shmem file with base content
    pub base_fd: i32,
    /// Input: flags (reserved, must be 0)
    pub flags: u32,
    /// Input: size of the memory region
    pub size: u64,
    /// Output: tree handle
    pub tree_id: u64,
}

/// Arguments for `COWTREE_CREATE_BRANCH`.
///
/// ```c
/// struct cowtree_create_branch {
///     __u64 tree_id;
///     __u64 parent_id;  /* 0 = root/base */
///     __u32 flags;
///     __u32 _pad;
///     __u64 branch_id;  /* out */
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default)]
pub struct CreateBranchArgs {
    /// Input: tree handle from `CREATE_TREE`
    pub tree_id: u64,
    /// Input: parent branch (0 = branch from base/root)
    pub parent_id: u64,
    /// Input: flags (reserved, must be 0)
    pub flags: u32,
    /// Padding (must be 0)
    #[doc(hidden)]
    pub pad: u32,
    /// Output: unique id for this branch
    pub branch_id: u64,
}

/// Statistics for a tree or branch.
///
/// ```c
/// struct cowtree_stats {
///     __u64 tree_id;
///     __u64 branch_id;  /* 0 = tree-level stats */
///     __u64 total_pages;
///     __u64 cow_pages;
///     __u64 shared_pages;
///     __u64 branch_count;
///     __u64 max_cow_pages;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct Stats {
    /// Input: tree to query
    pub tree_id: u64,
    /// Input: branch to query (0 = tree-level stats)
    pub branch_id: u64,
    /// Output: total pages in region
    pub total_pages: u64,
    /// Output: pages copied-on-write
    pub cow_pages: u64,
    /// Output: pages still sharing base/parent
    pub shared_pages: u64,
    /// Output: number of branches in tree
    pub branch_count: u64,
    /// Output: configured page limit (0 = unlimited)
    pub max_cow_pages: u64,
}

/// Global allocation statistics for leak detection.
///
/// ```c
/// struct cowtree_global_stats {
///     __u32 flags;
///     __u32 _pad;
///     __u64 trees_active;
///     __u64 branches_active;
///     __u64 vma_data_active;
///     __u64 inodes_active;
///     __u64 trees_total;
///     __u64 branches_total;
///     __u64 vma_data_total;
///     __u64 inodes_total;
///     __u64 cow_pages_active;
///     __u64 cow_pages_total;
///     __u64 pinned_pages_active;
///     __u64 pinned_pages_total;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default, Clone)]
pub struct GlobalStats {
    /// Input: flags (reserved, must be 0)
    pub flags: u32,
    /// Padding (must be 0)
    #[doc(hidden)]
    pub pad: u32,
    /// Currently allocated trees
    pub trees_active: u64,
    /// Currently allocated branches
    pub branches_active: u64,
    /// Currently allocated `vma_data` structs
    pub vma_data_active: u64,
    /// Currently allocated inodes
    pub inodes_active: u64,
    /// Total trees ever created
    pub trees_total: u64,
    /// Total branches ever created
    pub branches_total: u64,
    /// Total `vma_data` ever created
    pub vma_data_total: u64,
    /// Total inodes ever created
    pub inodes_total: u64,
    /// Currently allocated copy-on-write pages
    pub cow_pages_active: u64,
    /// Total copy-on-write pages ever allocated
    pub cow_pages_total: u64,
    /// Currently pinned pages from parent/base
    pub pinned_pages_active: u64,
    /// Total pages ever pinned
    pub pinned_pages_total: u64,
}

/// Arguments for `COWTREE_DESTROY_TREE`.
///
/// ```c
/// struct cowtree_destroy_tree {
///     __u64 tree_id;
///     __u32 flags;
///     __u32 _pad;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default)]
pub struct DestroyTreeArgs {
    /// Input: tree handle to destroy
    pub tree_id: u64,
    /// Input: flags (reserved, must be 0)
    pub flags: u32,
    /// Padding (must be 0)
    #[doc(hidden)]
    pub pad: u32,
}

// =============================================================================
// Ioctl Macros
// =============================================================================

const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;

const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = 8;
const IOC_SIZESHIFT: u32 = 16;
const IOC_DIRSHIFT: u32 = 30;

/// Build an ioctl request number.
///
/// The ioctl size field is 14 bits (max 16383). The const assert ensures
/// this is caught at compile time for any struct larger than that.
#[allow(clippy::cast_possible_truncation)] // guarded by the assert above
const fn ioc(dir: u32, ty: u8, nr: u8, size: usize) -> libc::Ioctl {
    assert!(
        size <= 0x3FFF,
        "ioctl struct too large for 14-bit size field"
    );
    ((dir << IOC_DIRSHIFT)
        | ((ty as u32) << IOC_TYPESHIFT)
        | ((nr as u32) << IOC_NRSHIFT)
        | ((size as u32) << IOC_SIZESHIFT)) as libc::Ioctl
}

/// _IOWR: Read and write data.
const fn iowr<T>(ty: u8, nr: u8) -> libc::Ioctl {
    ioc(IOC_READ | IOC_WRITE, ty, nr, std::mem::size_of::<T>())
}

/// _IOR: Read data only.
const fn ior<T>(ty: u8, nr: u8) -> libc::Ioctl {
    ioc(IOC_READ, ty, nr, std::mem::size_of::<T>())
}

/// _IOW: Write data only.
const fn iow<T>(ty: u8, nr: u8) -> libc::Ioctl {
    ioc(IOC_WRITE, ty, nr, std::mem::size_of::<T>())
}

/// Arguments for `COWTREE_SET_LIMIT`.
///
/// ```c
/// struct cowtree_set_limit {
///     __u64 tree_id;
///     __u64 branch_id;
///     __u64 max_cow_pages;  /* 0 = unlimited */
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default)]
pub struct SetLimitArgs {
    /// Input: tree handle
    pub tree_id: u64,
    /// Input: branch to limit
    pub branch_id: u64,
    /// Input: page limit (0 = unlimited)
    pub max_cow_pages: u64,
}

/// Arguments for `COWTREE_PUNCH_HOLE`.
///
/// ```c
/// struct cowtree_punch_hole {
///     __u64 tree_id;
///     __u64 branch_id;
///     __u64 offset;
///     __u64 len;
/// };
/// ```
#[repr(C)]
#[derive(Debug, Default)]
pub struct PunchHoleArgs {
    /// Input: tree handle
    pub tree_id: u64,
    /// Input: branch to punch
    pub branch_id: u64,
    /// Input: page-aligned byte offset
    pub offset: u64,
    /// Input: page-aligned byte length
    pub len: u64,
}

// Ioctl request numbers
const COWTREE_CREATE_TREE: libc::Ioctl = iowr::<CreateTreeArgs>(COWTREE_IOCTL_MAGIC, 0x01);
const COWTREE_CREATE_BRANCH: libc::Ioctl = iowr::<CreateBranchArgs>(COWTREE_IOCTL_MAGIC, 0x02);
const COWTREE_GET_STATS: libc::Ioctl = iowr::<Stats>(COWTREE_IOCTL_MAGIC, 0x03);
const COWTREE_GET_GLOBAL_STATS: libc::Ioctl = ior::<GlobalStats>(COWTREE_IOCTL_MAGIC, 0x04);
const COWTREE_DESTROY_TREE: libc::Ioctl = iow::<DestroyTreeArgs>(COWTREE_IOCTL_MAGIC, 0x05);
const COWTREE_SET_LIMIT: libc::Ioctl = iow::<SetLimitArgs>(COWTREE_IOCTL_MAGIC, 0x06);
const COWTREE_PUNCH_HOLE: libc::Ioctl = iow::<PunchHoleArgs>(COWTREE_IOCTL_MAGIC, 0x07);

// =============================================================================
// Ioctl Functions
// =============================================================================

/// Create a new memory tree from a base memfd.
///
/// Returns the `tree_id` handle.
pub fn create_tree(ctl: &impl AsRawFd, base_fd: i32, size: u64) -> Result<u64> {
    let mut args = CreateTreeArgs {
        base_fd,
        flags: 0,
        size,
        tree_id: 0,
    };

    // SAFETY: ctl is a valid fd, args is properly initialized
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_CREATE_TREE, &mut args) };

    if ret < 0 {
        return Err(Error::Ioctl {
            operation: "COWTREE_CREATE_TREE",
            source: io::Error::last_os_error(),
        });
    }

    Ok(args.tree_id)
}

/// Create a branch in an existing tree.
///
/// Returns a new fd that can be mmap'd for copy-on-write access.
/// The ioctl returns the fd as the return value, and sets `branch_id` in args.
pub fn create_branch(
    ctl: &impl AsRawFd,
    tree_id: u64,
    parent_id: u64,
) -> Result<(OwnedFd, BranchId)> {
    let mut args = CreateBranchArgs {
        tree_id,
        parent_id,
        flags: 0,
        pad: 0,
        branch_id: 0,
    };

    // SAFETY: ctl is a valid fd, args is properly initialized
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_CREATE_BRANCH, &mut args) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::ENOENT) => Error::NotFound {
                tree_id,
                parent_id: BranchId::new(parent_id),
            },
            _ => Error::Ioctl {
                operation: "COWTREE_CREATE_BRANCH",
                source: err,
            },
        });
    }

    // SAFETY: The ioctl returned a non-negative value, which is a valid new file
    // descriptor representing the branch. We take ownership immediately via OwnedFd
    // so it will be closed on drop. No other code path holds this fd.
    let fd = unsafe { OwnedFd::from_raw_fd(ret) };
    Ok((fd, BranchId::new(args.branch_id)))
}

/// Get statistics for a tree or branch.
pub fn get_stats(ctl: &impl AsRawFd, tree_id: u64, branch_id: u64) -> Result<Stats> {
    let mut stats = Stats {
        tree_id,
        branch_id,
        ..Default::default()
    };

    // SAFETY: `ctl` is a valid open fd (guaranteed by the `AsRawFd` bound),
    // `COWTREE_GET_STATS` is the correct IOWR ioctl number for a `Stats` struct,
    // and `stats` is a properly initialized `#[repr(C)]` struct at a valid mutable
    // reference. The kernel reads `tree_id`/`branch_id` and writes output fields.
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_GET_STATS, &mut stats) };

    if ret < 0 {
        return Err(Error::Ioctl {
            operation: "COWTREE_GET_STATS",
            source: io::Error::last_os_error(),
        });
    }

    Ok(stats)
}

/// Get global allocation statistics.
pub fn get_global_stats(ctl: &impl AsRawFd) -> Result<GlobalStats> {
    let mut stats = GlobalStats::default();

    // SAFETY: `ctl` is a valid open fd (guaranteed by the `AsRawFd` bound),
    // `COWTREE_GET_GLOBAL_STATS` is the correct IOR ioctl number for a `GlobalStats`
    // struct, and `stats` is a zero-initialized `#[repr(C)]` struct at a valid mutable
    // reference. The kernel writes all output fields without reading any input beyond
    // the reserved `flags` field (which is zero).
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_GET_GLOBAL_STATS, &mut stats) };

    if ret < 0 {
        return Err(Error::Ioctl {
            operation: "COWTREE_GET_GLOBAL_STATS",
            source: io::Error::last_os_error(),
        });
    }

    Ok(stats)
}

/// Set per-branch page limit for host-side memory enforcement.
///
/// A limit of 0 means unlimited.
pub fn set_limit(
    ctl: &impl AsRawFd,
    tree_id: u64,
    branch_id: u64,
    max_cow_pages: u64,
) -> Result<()> {
    let args = SetLimitArgs {
        tree_id,
        branch_id,
        max_cow_pages,
    };

    // SAFETY: `ctl` is a valid open fd (guaranteed by the `AsRawFd` bound),
    // `COWTREE_SET_LIMIT` is the correct IOW ioctl number for a `SetLimitArgs` struct,
    // and `args` is a properly initialized `#[repr(C)]` struct at a valid shared
    // reference. The kernel only reads the struct (write-direction ioctl).
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_SET_LIMIT, &args) };

    if ret < 0 {
        return Err(Error::Ioctl {
            operation: "COWTREE_SET_LIMIT",
            source: io::Error::last_os_error(),
        });
    }

    Ok(())
}

/// Punch a hole in a branch's page cache (reclaim copy-on-write pages).
///
/// Evicts copy-on-write pages for the given byte range, restoring sharing with parent/base.
pub fn punch_hole(
    ctl: &impl AsRawFd,
    tree_id: u64,
    branch_id: u64,
    offset: u64,
    len: u64,
) -> Result<()> {
    let args = PunchHoleArgs {
        tree_id,
        branch_id,
        offset,
        len,
    };

    // SAFETY: `ctl` is a valid open fd (guaranteed by the `AsRawFd` bound),
    // `COWTREE_PUNCH_HOLE` is the correct IOW ioctl number for a `PunchHoleArgs`
    // struct, and `args` is a properly initialized `#[repr(C)]` struct at a valid
    // shared reference. The kernel only reads the struct (write-direction ioctl).
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_PUNCH_HOLE, &args) };

    if ret < 0 {
        return Err(Error::Ioctl {
            operation: "COWTREE_PUNCH_HOLE",
            source: io::Error::last_os_error(),
        });
    }

    Ok(())
}

/// Destroy a tree.
///
/// The tree must have no active branches (returns `EBUSY` if branches exist).
pub fn destroy_tree(ctl: &impl AsRawFd, tree_id: u64) -> Result<()> {
    let args = DestroyTreeArgs {
        tree_id,
        flags: 0,
        pad: 0,
    };

    // SAFETY: `ctl` is a valid open fd (guaranteed by the `AsRawFd` bound),
    // `COWTREE_DESTROY_TREE` is the correct IOW ioctl number for a `DestroyTreeArgs`
    // struct, and `args` is a properly initialized `#[repr(C)]` struct at a valid
    // shared reference. The kernel only reads the struct (write-direction ioctl).
    let ret = unsafe { libc::ioctl(ctl.as_raw_fd(), COWTREE_DESTROY_TREE, &args) };

    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(match err.raw_os_error() {
            Some(libc::EBUSY) => Error::Ioctl {
                operation: "COWTREE_DESTROY_TREE (tree has active branches)",
                source: err,
            },
            Some(libc::ENOENT) => Error::Ioctl {
                operation: "COWTREE_DESTROY_TREE (tree not found)",
                source: err,
            },
            _ => Error::Ioctl {
                operation: "COWTREE_DESTROY_TREE",
                source: err,
            },
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )]
    use super::*;

    // Helper to extract ioctl components (cast to u32 so bit extraction
    // works identically on glibc (c_ulong = u64) and musl (Ioctl = i32)).
    fn ioctl_nr(n: libc::Ioctl) -> u8 {
        (n as u32 & 0xFF) as u8
    }
    fn ioctl_type(n: libc::Ioctl) -> u8 {
        ((n as u32 >> 8) & 0xFF) as u8
    }
    fn ioctl_size(n: libc::Ioctl) -> usize {
        ((n as u32 >> 16) & 0x3FFF) as usize
    }
    fn ioctl_dir(n: libc::Ioctl) -> u32 {
        (n as u32 >> 30) & 0x3
    }

    #[test]
    fn struct_sizes_match_c_layout() {
        assert_eq!(std::mem::size_of::<CreateTreeArgs>(), 24);
        assert_eq!(std::mem::size_of::<CreateBranchArgs>(), 32);
        assert_eq!(std::mem::size_of::<Stats>(), 56);
        assert_eq!(std::mem::size_of::<GlobalStats>(), 104);
        assert_eq!(std::mem::size_of::<DestroyTreeArgs>(), 16);
        assert_eq!(std::mem::size_of::<SetLimitArgs>(), 24);
        assert_eq!(std::mem::size_of::<PunchHoleArgs>(), 32);
    }

    #[test]
    fn struct_alignment() {
        // All structs are repr(C) — alignment must match C ABI
        assert_eq!(std::mem::align_of::<CreateTreeArgs>(), 8);
        assert_eq!(std::mem::align_of::<CreateBranchArgs>(), 8);
        assert_eq!(std::mem::align_of::<Stats>(), 8);
        assert_eq!(std::mem::align_of::<GlobalStats>(), 8);
        assert_eq!(std::mem::align_of::<DestroyTreeArgs>(), 8);
        assert_eq!(std::mem::align_of::<SetLimitArgs>(), 8);
        assert_eq!(std::mem::align_of::<PunchHoleArgs>(), 8);
    }

    #[test]
    fn ioctl_numbers_nr_and_type() {
        assert_eq!(ioctl_nr(COWTREE_CREATE_TREE), 0x01);
        assert_eq!(ioctl_type(COWTREE_CREATE_TREE), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_CREATE_BRANCH), 0x02);
        assert_eq!(ioctl_type(COWTREE_CREATE_BRANCH), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_GET_STATS), 0x03);
        assert_eq!(ioctl_type(COWTREE_GET_STATS), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_GET_GLOBAL_STATS), 0x04);
        assert_eq!(ioctl_type(COWTREE_GET_GLOBAL_STATS), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_DESTROY_TREE), 0x05);
        assert_eq!(ioctl_type(COWTREE_DESTROY_TREE), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_SET_LIMIT), 0x06);
        assert_eq!(ioctl_type(COWTREE_SET_LIMIT), 0xB7);

        assert_eq!(ioctl_nr(COWTREE_PUNCH_HOLE), 0x07);
        assert_eq!(ioctl_type(COWTREE_PUNCH_HOLE), 0xB7);
    }

    #[test]
    fn ioctl_direction_bits() {
        // IOWR = read + write (3), IOR = read (2), IOW = write (1)
        assert_eq!(
            ioctl_dir(COWTREE_CREATE_TREE),
            3,
            "CREATE_TREE should be IOWR"
        );
        assert_eq!(
            ioctl_dir(COWTREE_CREATE_BRANCH),
            3,
            "CREATE_BRANCH should be IOWR"
        );
        assert_eq!(ioctl_dir(COWTREE_GET_STATS), 3, "GET_STATS should be IOWR");
        assert_eq!(
            ioctl_dir(COWTREE_GET_GLOBAL_STATS),
            2,
            "GET_GLOBAL_STATS should be IOR"
        );
        assert_eq!(
            ioctl_dir(COWTREE_DESTROY_TREE),
            1,
            "DESTROY_TREE should be IOW"
        );
        assert_eq!(ioctl_dir(COWTREE_SET_LIMIT), 1, "SET_LIMIT should be IOW");
        assert_eq!(ioctl_dir(COWTREE_PUNCH_HOLE), 1, "PUNCH_HOLE should be IOW");
    }

    #[test]
    fn ioctl_size_encoding() {
        assert_eq!(ioctl_size(COWTREE_CREATE_TREE), 24);
        assert_eq!(ioctl_size(COWTREE_CREATE_BRANCH), 32);
        assert_eq!(ioctl_size(COWTREE_GET_STATS), 56);
        assert_eq!(ioctl_size(COWTREE_GET_GLOBAL_STATS), 104);
        assert_eq!(ioctl_size(COWTREE_DESTROY_TREE), 16);
        assert_eq!(ioctl_size(COWTREE_SET_LIMIT), 24);
        assert_eq!(ioctl_size(COWTREE_PUNCH_HOLE), 32);
    }

    #[test]
    fn ioc_encodes_all_fields() {
        // Test the ioc() function directly with known values
        let nr = 0x42u8;
        let ty = 0xABu8;
        let size = 64usize;
        let dir = IOC_READ | IOC_WRITE;

        let num = ioc(dir, ty, nr, size) as u32;
        assert_eq!(num & 0xFF, u32::from(nr));
        assert_eq!((num >> 8) & 0xFF, u32::from(ty));
        assert_eq!((num >> 16) & 0x3FFF, size as u32);
        assert_eq!((num >> 30) & 0x3, dir);
    }

    #[test]
    fn ioc_zero_size() {
        let num = ioc(IOC_READ, 0xB7, 0x01, 0);
        assert_eq!(ioctl_size(num), 0);
        assert_eq!(ioctl_dir(num), 2);
    }

    #[test]
    fn struct_defaults() {
        let ct = CreateTreeArgs::default();
        assert_eq!(ct.base_fd, 0);
        assert_eq!(ct.flags, 0);
        assert_eq!(ct.size, 0);
        assert_eq!(ct.tree_id, 0);

        let cb = CreateBranchArgs::default();
        assert_eq!(cb.tree_id, 0);
        assert_eq!(cb.pad, 0);
        assert_eq!(cb.branch_id, 0);

        let s = Stats::default();
        assert_eq!(s.total_pages, 0);
        assert_eq!(s.cow_pages, 0);
        assert_eq!(s.shared_pages, 0);
        assert_eq!(s.branch_count, 0);
        assert_eq!(s.max_cow_pages, 0);

        let gs = GlobalStats::default();
        assert_eq!(gs.trees_active, 0);
        assert_eq!(gs.cow_pages_active, 0);
        assert_eq!(gs.pad, 0);

        let dt = DestroyTreeArgs::default();
        assert_eq!(dt.tree_id, 0);
        assert_eq!(dt.pad, 0);

        let sl = SetLimitArgs::default();
        assert_eq!(sl.max_cow_pages, 0);

        let ph = PunchHoleArgs::default();
        assert_eq!(ph.offset, 0);
        assert_eq!(ph.len, 0);
    }

    #[test]
    fn stats_clone() {
        let s = Stats {
            tree_id: 1,
            branch_id: 2,
            total_pages: 100,
            cow_pages: 50,
            shared_pages: 50,
            branch_count: 3,
            max_cow_pages: 200,
        };
        let s2 = s.clone();
        assert_eq!(s.tree_id, s2.tree_id);
        assert_eq!(s.cow_pages, s2.cow_pages);
        assert_eq!(s.max_cow_pages, s2.max_cow_pages);
    }

    #[test]
    fn global_stats_clone() {
        let original = GlobalStats {
            trees_active: 5,
            cow_pages_total: 1000,
            ..Default::default()
        };
        let cloned = original.clone();
        assert_eq!(original.trees_active, cloned.trees_active);
        assert_eq!(original.cow_pages_total, cloned.cow_pages_total);
    }
}
