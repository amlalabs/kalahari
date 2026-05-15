// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Stub [`FsBackend`] that returns `ENOSYS` for every operation.
//!
//! Useful at call sites that thread `F: FsBackend` through a generic API
//! but pass `Option::None` — the type parameter still needs a concrete type.

use crate::fuse::{FsBackend, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseOpenOut, FuseStatfsOut};
use crate::fuse_abi::FuseError;

/// Returns `ENOSYS` for every backend method.
pub struct NullFsBackend;

impl FsBackend for NullFsBackend {
    async fn init(&self) -> Result<FuseInitOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn lookup(&self, _parent: u64, _name: &[u8]) -> Result<FuseEntryOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn forget(&self, _nodeid: u64, _nlookup: u64) {}
    async fn batch_forget(&self, _forgets: &[(u64, u64)]) {}
    async fn getattr(&self, _nodeid: u64) -> Result<FuseAttrOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn readlink(&self, _nodeid: u64) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn open(&self, _nodeid: u64, _flags: u32) -> Result<FuseOpenOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn read(
        &self,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn release(&self, _nodeid: u64, _fh: u64) {}
    async fn opendir(&self, _nodeid: u64) -> Result<FuseOpenOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn readdir(
        &self,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn readdirplus(
        &self,
        _nodeid: u64,
        _fh: u64,
        _offset: u64,
        _size: u32,
    ) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn releasedir(&self, _nodeid: u64, _fh: u64) {}
    async fn statfs(&self) -> Result<FuseStatfsOut, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn access(&self, _nodeid: u64, _mask: u32) -> Result<(), FuseError> {
        Err(FuseError::no_sys())
    }
    async fn getxattr(&self, _nodeid: u64, _name: &[u8], _size: u32) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn listxattr(&self, _nodeid: u64, _size: u32) -> Result<Vec<u8>, FuseError> {
        Err(FuseError::no_sys())
    }
    async fn get_parent(&self, _nodeid: u64) -> Result<FuseEntryOut, FuseError> {
        Err(FuseError::no_sys())
    }
}
