// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Heterogeneous list of [`FixedFsBackend`]s for
//! [`MultiFixedFsBackend`](crate::MultiFixedFsBackend).
//!
//! Compile-time-typed cons list so that indexed dispatch monomorphizes into
//! direct calls — no vtable, no heap allocation for futures.
//!
//! Shape: `HCons<H, T>` carries one concrete backend `H` plus a tail `T`.
//! `HNil` terminates. Construction via the [`hlist!`](crate::hlist!) macro:
//!
//! ```ignore
//! let list = hlist![gitfs, mounted, synth];
//! // type: HCons<GitFs, HCons<MountedFsBackend<_>, HCons<SynthesizedFs<'_>, HNil>>>
//! ```
//!
//! Each `_at(idx, …)` method on [`FixedList`] recurses once per cons cell —
//! the compiler unrolls this into a chain of `if/else` reducing to a direct
//! call on the head backend. No vtable, no heap allocation for futures.
//!
//! The recursion makes the async state machine depth proportional to N.
//! Kept small (N ≤ ~20) because deeper chains stress LLVM's optimizer and
//! grow state-machine size per op.

use amla_fuse::fuse::{
    FixedFsBackend, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseOpenOut, FuseStatfsOut,
};
use amla_fuse::fuse_abi::FuseError;

/// Empty `HList` — base case of the cons chain.
pub struct HNil;

/// Cons cell holding one backend `head` and the remaining list `tail`.
pub struct HCons<H, T> {
    pub head: H,
    pub tail: T,
}

/// Build an `HList` of backends.
///
/// `hlist![a, b, c]` expands to
/// `HCons { head: a, tail: HCons { head: b, tail: HCons { head: c, tail: HNil } } }`.
#[macro_export]
macro_rules! hlist {
    () => { $crate::hlist::HNil };
    ($head:expr $(, $tail:expr)* $(,)?) => {
        $crate::hlist::HCons {
            head: $head,
            tail: $crate::hlist!($($tail),*),
        }
    };
}

/// Indexed dispatch into an `HList` of [`FixedFsBackend`]s.
///
/// Callers MUST pre-validate `idx` against [`FixedList::len`]; reaching the
/// `HNil` base case means `idx` was `>=` the list length, which is a caller
/// bug. The `HNil` methods [`unreachable!`] on that contract violation
/// rather than synthesizing a plausible-looking `not_found` — swallowing an
/// index-out-of-bounds as a runtime error would mask caller bugs.
// Reason: `#[trait_variant::make(Send)]` injects an additional `Send`
// bound at the macro layer; the explicit `Send + Sync` on the trait
// declaration is required for the non-Send variant. The duplication is
// an artifact of the macro expansion, not a code bug.
#[allow(clippy::trait_duplication_in_bounds)]
#[trait_variant::make(Send)]
pub trait FixedList: Send + Sync {
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn inode_count_at(&self, idx: usize) -> u64;

    async fn init_at(&self, idx: usize) -> Result<FuseInitOut, FuseError>;

    async fn lookup_at(
        &self,
        idx: usize,
        parent: u64,
        name: &[u8],
    ) -> Result<FuseEntryOut, FuseError>;

    async fn forget_at(&self, idx: usize, nodeid: u64, nlookup: u64);

    async fn batch_forget_at(&self, idx: usize, forgets: &[(u64, u64)]);

    async fn getattr_at(&self, idx: usize, nodeid: u64) -> Result<FuseAttrOut, FuseError>;

    async fn readlink_at(&self, idx: usize, nodeid: u64) -> Result<Vec<u8>, FuseError>;

    async fn open_at(&self, idx: usize, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError>;

    async fn read_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;

    async fn release_at(&self, idx: usize, nodeid: u64, fh: u64);

    async fn opendir_at(&self, idx: usize, nodeid: u64) -> Result<FuseOpenOut, FuseError>;

    async fn readdir_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;

    async fn readdirplus_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;

    async fn releasedir_at(&self, idx: usize, nodeid: u64, fh: u64);

    async fn statfs_at(&self, idx: usize) -> Result<FuseStatfsOut, FuseError>;

    async fn access_at(&self, idx: usize, nodeid: u64, mask: u32) -> Result<(), FuseError>;

    async fn getxattr_at(
        &self,
        idx: usize,
        nodeid: u64,
        name: &[u8],
        size: u32,
    ) -> Result<Vec<u8>, FuseError>;

    async fn listxattr_at(&self, idx: usize, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError>;

    async fn get_parent_at(&self, idx: usize, nodeid: u64) -> Result<FuseEntryOut, FuseError>;
}

/// `HNil` is the empty-list terminator. Reaching any `_at` method on it
/// means the caller passed `idx >= FixedList::len()` — a bounds-check
/// violation that belongs at the call site, not swallowed into a runtime
/// `FuseError::not_found`. See the [`FixedList`] trait docs.
fn hnil_oob(idx: usize) -> ! {
    unreachable!("FixedList: idx {idx} out of bounds on HNil base case")
}

impl FixedList for HNil {
    fn len(&self) -> usize {
        0
    }

    fn inode_count_at(&self, idx: usize) -> u64 {
        hnil_oob(idx)
    }

    async fn init_at(&self, idx: usize) -> Result<FuseInitOut, FuseError> {
        hnil_oob(idx)
    }

    async fn lookup_at(
        &self,
        idx: usize,
        _parent: u64,
        _name: &[u8],
    ) -> Result<FuseEntryOut, FuseError> {
        hnil_oob(idx)
    }

    async fn forget_at(&self, idx: usize, _nodeid: u64, _nlookup: u64) {
        hnil_oob(idx)
    }

    async fn batch_forget_at(&self, idx: usize, _forgets: &[(u64, u64)]) {
        hnil_oob(idx)
    }

    async fn getattr_at(&self, idx: usize, _nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        hnil_oob(idx)
    }

    async fn readlink_at(&self, idx: usize, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn open_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _flags: u32,
    ) -> Result<FuseOpenOut, FuseError> {
        hnil_oob(idx)
    }

    async fn read_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn release_at(&self, idx: usize, _nodeid: u64, _fh: u64) {
        hnil_oob(idx)
    }

    async fn opendir_at(&self, idx: usize, _nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        hnil_oob(idx)
    }

    async fn readdir_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn readdirplus_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn releasedir_at(&self, idx: usize, _nodeid: u64, _fh: u64) {
        hnil_oob(idx)
    }

    async fn statfs_at(&self, idx: usize) -> Result<FuseStatfsOut, FuseError> {
        hnil_oob(idx)
    }

    async fn access_at(&self, idx: usize, _nodeid: u64, _mask: u32) -> Result<(), FuseError> {
        hnil_oob(idx)
    }

    async fn getxattr_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _name: &[u8],
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn listxattr_at(
        &self,
        idx: usize,
        _nodeid: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        hnil_oob(idx)
    }

    async fn get_parent_at(&self, idx: usize, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        hnil_oob(idx)
    }
}

impl<H: FixedFsBackend, T: FixedList> FixedList for HCons<H, T> {
    fn len(&self) -> usize {
        1 + self.tail.len()
    }

    fn inode_count_at(&self, idx: usize) -> u64 {
        if idx == 0 {
            self.head.inode_count()
        } else {
            self.tail.inode_count_at(idx - 1)
        }
    }

    async fn init_at(&self, idx: usize) -> Result<FuseInitOut, FuseError> {
        if idx == 0 {
            self.head.init().await
        } else {
            self.tail.init_at(idx - 1).await
        }
    }

    async fn lookup_at(
        &self,
        idx: usize,
        parent: u64,
        name: &[u8],
    ) -> Result<FuseEntryOut, FuseError> {
        if idx == 0 {
            self.head.lookup(parent, name).await
        } else {
            self.tail.lookup_at(idx - 1, parent, name).await
        }
    }

    async fn forget_at(&self, idx: usize, nodeid: u64, nlookup: u64) {
        if idx == 0 {
            self.head.forget(nodeid, nlookup).await;
        } else {
            self.tail.forget_at(idx - 1, nodeid, nlookup).await;
        }
    }

    async fn batch_forget_at(&self, idx: usize, forgets: &[(u64, u64)]) {
        if idx == 0 {
            self.head.batch_forget(forgets).await;
        } else {
            self.tail.batch_forget_at(idx - 1, forgets).await;
        }
    }

    async fn getattr_at(&self, idx: usize, nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        if idx == 0 {
            self.head.getattr(nodeid).await
        } else {
            self.tail.getattr_at(idx - 1, nodeid).await
        }
    }

    async fn readlink_at(&self, idx: usize, nodeid: u64) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.readlink(nodeid).await
        } else {
            self.tail.readlink_at(idx - 1, nodeid).await
        }
    }

    async fn open_at(&self, idx: usize, nodeid: u64, flags: u32) -> Result<FuseOpenOut, FuseError> {
        if idx == 0 {
            self.head.open(nodeid, flags).await
        } else {
            self.tail.open_at(idx - 1, nodeid, flags).await
        }
    }

    async fn read_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.read(nodeid, fh, offset, size).await
        } else {
            self.tail.read_at(idx - 1, nodeid, fh, offset, size).await
        }
    }

    async fn release_at(&self, idx: usize, nodeid: u64, fh: u64) {
        if idx == 0 {
            self.head.release(nodeid, fh).await;
        } else {
            self.tail.release_at(idx - 1, nodeid, fh).await;
        }
    }

    async fn opendir_at(&self, idx: usize, nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        if idx == 0 {
            self.head.opendir(nodeid).await
        } else {
            self.tail.opendir_at(idx - 1, nodeid).await
        }
    }

    async fn readdir_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.readdir(nodeid, fh, offset, size).await
        } else {
            self.tail
                .readdir_at(idx - 1, nodeid, fh, offset, size)
                .await
        }
    }

    async fn readdirplus_at(
        &self,
        idx: usize,
        nodeid: u64,
        fh: u64,
        offset: u64,
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.readdirplus(nodeid, fh, offset, size).await
        } else {
            self.tail
                .readdirplus_at(idx - 1, nodeid, fh, offset, size)
                .await
        }
    }

    async fn releasedir_at(&self, idx: usize, nodeid: u64, fh: u64) {
        if idx == 0 {
            self.head.releasedir(nodeid, fh).await;
        } else {
            self.tail.releasedir_at(idx - 1, nodeid, fh).await;
        }
    }

    async fn statfs_at(&self, idx: usize) -> Result<FuseStatfsOut, FuseError> {
        if idx == 0 {
            self.head.statfs().await
        } else {
            self.tail.statfs_at(idx - 1).await
        }
    }

    async fn access_at(&self, idx: usize, nodeid: u64, mask: u32) -> Result<(), FuseError> {
        if idx == 0 {
            self.head.access(nodeid, mask).await
        } else {
            self.tail.access_at(idx - 1, nodeid, mask).await
        }
    }

    async fn getxattr_at(
        &self,
        idx: usize,
        nodeid: u64,
        name: &[u8],
        size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.getxattr(nodeid, name, size).await
        } else {
            self.tail.getxattr_at(idx - 1, nodeid, name, size).await
        }
    }

    async fn listxattr_at(&self, idx: usize, nodeid: u64, size: u32) -> Result<Vec<u8>, FuseError> {
        if idx == 0 {
            self.head.listxattr(nodeid, size).await
        } else {
            self.tail.listxattr_at(idx - 1, nodeid, size).await
        }
    }

    async fn get_parent_at(&self, idx: usize, nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        if idx == 0 {
            self.head.get_parent(nodeid).await
        } else {
            self.tail.get_parent_at(idx - 1, nodeid).await
        }
    }
}
