// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::unwrap_used, clippy::expect_used)]

use amla_core::vm_state::guest_mem::{GuestMemory, GuestWrite};
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_fuse::fuse::collect_regions;
use amla_fuse::fuse::{
    FsBackend, FuseAttrOut, FuseEntryOut, FuseInitOut, FuseOpenOut, FuseServer, FuseStatfsOut,
    OwnedFuseRequest,
};
use amla_fuse::fuse_abi::FuseError;
use amla_virtio::{
    DEVICE_ID_FS, Descriptor, FsState, QueueView, QueueViolation, VIRTIO_F_VERSION_1,
    VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE, VirtioDevice,
};
use bytemuck::Zeroable;

use crate::{Fs, RequestQueueCount};

const MEM_SIZE: usize = TEST_RAM_SIZE;

fn make_test_memory() -> TestMmap {
    test_mmap(MEM_SIZE)
}

/// Minimal `FsBackend` that returns ENOSYS for everything.
struct NullFsBackend;

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

#[test]
fn test_device_id_and_features() {
    let fs = Fs::new(RequestQueueCount::ONE);
    assert_eq!(VirtioDevice::<VmState<'_>>::device_id(&fs), DEVICE_ID_FS);
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&fs), 2); // 1 hiprio + 1 request
    assert_eq!(
        VirtioDevice::<VmState<'_>>::device_features(&fs),
        VIRTIO_F_VERSION_1
    );
}

#[test]
fn test_multi_queue_count() {
    let fs = Fs::new(RequestQueueCount::new(4).unwrap());
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&fs), 5); // 1 hiprio + 4 request

    let fs = Fs::new(RequestQueueCount::MAX);
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&fs), 10); // 1 hiprio + 9 request (max)
}

#[test]
fn test_default_single_request_queue() {
    let fs = Fs::default();
    assert_eq!(VirtioDevice::<VmState<'_>>::queue_count(&fs), 2); // 1 hiprio + 1 request
}

#[test]
fn test_zero_request_queues_is_not_representable() {
    assert!(RequestQueueCount::new(0).is_err());
}

#[test]
fn test_too_many_request_queues_is_not_representable() {
    assert!(RequestQueueCount::new(10).is_err());
}

/// Walk a small request queue and copy the readable side into an owned request.
///
/// Writable regions deliberately do not leave the queue-view closure; production
/// carries them as an opaque deferred completion token instead.
fn collect_test_request(
    vm: &VmState<'_>,
    state: &mut FsState,
    descs: &[Descriptor],
) -> OwnedFuseRequest {
    // Layout: desc table at 0x100, avail ring at 0x200, used ring at 0x300.
    let desc_gpa: u64 = 0x100;
    let avail_gpa: u64 = 0x200;
    let used_gpa: u64 = 0x300;
    state.queues[0] = amla_virtio::QueueState {
        size: 16,
        ready: 1,
        pad0: 0,
        desc_addr: desc_gpa,
        avail_addr: avail_gpa,
        used_addr: used_gpa,
        last_avail_idx: 0,
        last_used_idx: 0,
        generation: 0,
    };
    for (i, d) in descs.iter().enumerate() {
        vm.write_obj(desc_gpa + (i as u64) * 16, d).unwrap();
    }
    // avail.idx = 1, avail.ring[0] = 0 (head index)
    vm.write_obj(avail_gpa + 4u64, &0u16).unwrap();
    vm.write_obj(avail_gpa + 2u64, &1u16).unwrap();
    QueueView::with(0, &mut state.queues[0], vm, VIRTIO_F_VERSION_1, |view| {
        let chain = view.pop().expect("chain expected").into_split().unwrap();
        let regions = collect_regions(&chain);
        let total = regions
            .readable
            .iter()
            .fold(0usize, |acc, desc| acc.saturating_add(desc.len() as usize));
        let mut request = OwnedFuseRequest::with_capacity(total);
        for desc in &regions.readable {
            let dst = request.push_zeroed(desc.len() as usize);
            let n = desc.read_into(0, dst).unwrap();
            assert_eq!(n, dst.len());
        }
        request
    })
    .unwrap()
}

#[test]
fn test_collect_regions_rejects_readable_after_writable() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: FsState = Zeroable::zeroed();

    let desc_gpa: u64 = 0x100;
    let avail_gpa: u64 = 0x200;
    let used_gpa: u64 = 0x300;
    state.queues[0] = amla_virtio::QueueState {
        size: 16,
        ready: 1,
        pad0: 0,
        desc_addr: desc_gpa,
        avail_addr: avail_gpa,
        used_addr: used_gpa,
        last_avail_idx: 0,
        last_used_idx: 0,
        generation: 0,
    };
    let descs = [
        Descriptor {
            addr: 0x3000,
            len: 40,
            flags: VIRTQ_DESC_F_NEXT,
            next: 1,
        },
        Descriptor {
            addr: 0x4000,
            len: 256,
            flags: VIRTQ_DESC_F_WRITE | VIRTQ_DESC_F_NEXT,
            next: 2,
        },
        Descriptor {
            addr: 0x5000,
            len: 8,
            flags: 0,
            next: 0,
        },
    ];
    for (i, d) in descs.iter().enumerate() {
        vm.write_obj(desc_gpa + (i as u64) * 16, d).unwrap();
    }
    vm.write_obj(avail_gpa + 4u64, &0u16).unwrap();
    vm.write_obj(avail_gpa + 2u64, &1u16).unwrap();

    QueueView::with(0, &mut state.queues[0], &vm, VIRTIO_F_VERSION_1, |view| {
        let chain = view.pop().expect("chain expected");
        assert!(matches!(
            chain.into_split(),
            Err(QueueViolation::DescriptorReadableAfterWritable { head_index: 0 })
        ));
    })
    .unwrap();
}

#[tokio::test]
async fn test_fuse_server_malformed_request() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: FsState = Zeroable::zeroed();
    let backend = NullFsBackend;
    let server = FuseServer::new(&backend);

    // 8 bytes is too short for a FuseInHeader (40 bytes)
    {
        let gw = vm.gpa_write(0x3000, 8).unwrap();
        gw.write_from(&[0u8; 8]);
    }

    let request = collect_test_request(
        &vm,
        &mut state,
        &[
            Descriptor {
                addr: 0x3000,
                len: 8,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
            Descriptor {
                addr: 0x4000,
                len: 256,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        ],
    );

    let result = server.dispatch_owned_request(&request).await;
    assert!(result.is_err());
}

#[tokio::test]
async fn test_fuse_server_no_readable_descriptors() {
    let mmap = make_test_memory();
    let vm = make_test_vmstate(&mmap, 0);
    let mut state: FsState = Zeroable::zeroed();
    let backend = NullFsBackend;
    let server = FuseServer::new(&backend);

    let request = collect_test_request(
        &vm,
        &mut state,
        &[Descriptor {
            addr: 0x4000,
            len: 256,
            flags: VIRTQ_DESC_F_WRITE,
            next: 0,
        }],
    );

    let result = server.dispatch_owned_request(&request).await;
    assert!(result.is_err());
}
