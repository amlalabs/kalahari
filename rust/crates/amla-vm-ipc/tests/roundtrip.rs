// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![cfg(unix)]
//! End-to-end tests for amla-ipc: derive macro + MemHandle serialization.
//!
//! Tests the IpcMessage derive macro with `serialize`/`deserialize`.
//! The public API only supports `MemHandle` (not raw fds).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use amla_ipc::{IpcMessage, IpcResource};

// =========================================================================
// Test message types
// =========================================================================

#[derive(IpcMessage, Debug)]
struct SimpleData {
    x: u32,
    y: String,
}

#[derive(IpcMessage, Debug)]
struct SingleMem {
    label: String,
    #[ipc_resource]
    region: amla_mem::MemHandle,
}

#[derive(IpcMessage, Debug)]
struct MultipleMems {
    count: u32,
    #[ipc_resource]
    regions: Vec<amla_mem::MemHandle>,
}

#[derive(IpcMessage, Debug)]
struct OptionalMem {
    name: String,
    #[ipc_resource]
    maybe_region: Option<amla_mem::MemHandle>,
}

#[derive(IpcMessage, Debug)]
struct MixedFields {
    tag: u8,
    #[ipc_resource]
    primary: amla_mem::MemHandle,
    data: Vec<u8>,
    #[ipc_resource]
    extras: Vec<amla_mem::MemHandle>,
    #[ipc_resource]
    optional: Option<amla_mem::MemHandle>,
}

#[derive(IpcMessage, Debug)]
enum ControlMsg {
    Setup {
        vcpu_count: u32,
        #[ipc_resource]
        regions: Vec<amla_mem::MemHandle>,
    },
    Start,
    Pause,
    Shutdown,
}

// =========================================================================
// Helpers
// =========================================================================

/// Create a MemHandle of the given size with a marker byte at offset 0.
fn make_mem(size: usize, marker: u8) -> amla_mem::MemHandle {
    amla_mem::MemHandle::allocate_and_write(c"test", size, |slice| {
        slice[0] = marker;
        Ok(())
    })
    .unwrap()
}

/// Read the marker byte at offset 0 from a MemHandle.
fn read_marker(handle: &amla_mem::MemHandle) -> u8 {
    let mmap = amla_mem::map_handle(handle).unwrap();
    // SAFETY: test-local mapping; reads happen after writes are synchronized
    // by the test protocol.
    (unsafe { mmap.as_slice_unchecked() })[0]
}

// =========================================================================
// Codec-only tests (no transport)
// =========================================================================

#[test]
fn codec_simple_data() {
    let msg = SimpleData {
        x: 42,
        y: "hello".into(),
    };
    let (data, handles) = msg.serialize().unwrap();
    assert!(handles.is_empty());

    let msg2 = SimpleData::deserialize(&data, handles).unwrap();
    assert_eq!(msg2.x, 42);
    assert_eq!(msg2.y, "hello");
}

#[test]
fn codec_single_mem() {
    let region = make_mem(4096, 0xAB);
    let msg = SingleMem {
        label: "test".into(),
        region,
    };
    let (data, handles) = msg.serialize().unwrap();
    assert_eq!(handles.len(), 1);

    let msg2 = SingleMem::deserialize(&data, handles).unwrap();
    assert_eq!(msg2.label, "test");
    assert_eq!(read_marker(&msg2.region), 0xAB);
    assert_eq!(*msg2.region.size(), amla_mem::page_size());
}

#[test]
fn codec_multiple_mems() {
    let regions: Vec<_> = (0..3).map(|i| make_mem(4096, i as u8)).collect();
    let msg = MultipleMems { count: 3, regions };
    let (data, handles) = msg.serialize().unwrap();
    assert_eq!(handles.len(), 3);

    let msg2 = MultipleMems::deserialize(&data, handles).unwrap();
    assert_eq!(msg2.count, 3);
    for (i, region) in msg2.regions.iter().enumerate() {
        assert_eq!(read_marker(region), i as u8);
    }
}

#[test]
fn codec_optional_mem_some() {
    let region = make_mem(4096, 0xCD);
    let msg = OptionalMem {
        name: "present".into(),
        maybe_region: Some(region),
    };
    let (data, handles) = msg.serialize().unwrap();
    assert_eq!(handles.len(), 1);

    let msg2 = OptionalMem::deserialize(&data, handles).unwrap();
    assert_eq!(read_marker(msg2.maybe_region.as_ref().unwrap()), 0xCD);
}

#[test]
fn codec_optional_mem_none() {
    let msg = OptionalMem {
        name: "absent".into(),
        maybe_region: None,
    };
    let (data, handles) = msg.serialize().unwrap();
    assert!(handles.is_empty());

    let msg2 = OptionalMem::deserialize(&data, handles).unwrap();
    assert!(msg2.maybe_region.is_none());
}

#[test]
fn codec_enum_with_mems() {
    let regions: Vec<_> = (0..2).map(|_| make_mem(4096, 0x42)).collect();
    let msg = ControlMsg::Setup {
        vcpu_count: 4,
        regions,
    };
    let (data, handles) = msg.serialize().unwrap();
    assert_eq!(handles.len(), 2);

    let msg2 = ControlMsg::deserialize(&data, handles).unwrap();
    match msg2 {
        ControlMsg::Setup {
            vcpu_count,
            regions,
        } => {
            assert_eq!(vcpu_count, 4);
            assert_eq!(regions.len(), 2);
        }
        _ => panic!("wrong variant"),
    }
}

#[test]
fn codec_enum_unit_variant() {
    let msg = ControlMsg::Start;
    let (data, handles) = msg.serialize().unwrap();
    assert!(handles.is_empty());

    let msg2 = ControlMsg::deserialize(&data, handles).unwrap();
    assert!(matches!(msg2, ControlMsg::Start));
}

#[test]
fn codec_mixed_fields() {
    let primary = make_mem(4096, 0x11);
    let extras: Vec<_> = (0..2).map(|i| make_mem(4096, 0x20 + i)).collect();
    let optional = make_mem(4096, 0x33);

    let msg = MixedFields {
        tag: 7,
        primary,
        data: vec![1, 2, 3],
        extras,
        optional: Some(optional),
    };

    let (data, handles) = msg.serialize().unwrap();
    assert_eq!(handles.len(), 4); // 1 primary + 2 extras + 1 optional

    let msg2 = MixedFields::deserialize(&data, handles).unwrap();
    assert_eq!(msg2.tag, 7);
    assert_eq!(msg2.data, vec![1, 2, 3]);
    assert_eq!(read_marker(&msg2.primary), 0x11);
    assert_eq!(read_marker(&msg2.extras[0]), 0x20);
    assert_eq!(read_marker(&msg2.extras[1]), 0x21);
    assert_eq!(read_marker(msg2.optional.as_ref().unwrap()), 0x33);
}

#[test]
fn serialize_clones_handles() {
    // Verify that serialize clones (dups) the handles, not moves them.
    let region = make_mem(4096, 0xEE);
    let original_size = *region.size() as u64;
    let msg = SingleMem {
        label: "dup-test".into(),
        region,
    };
    let (data, slots) = msg.serialize().unwrap();

    // The slots vec should contain a dup.
    // meta encodes size in bits 0..62 and writable flag in bit 63.
    assert_eq!(slots.len(), 1);
    assert_eq!(slots[0].meta & !(1u64 << 63), original_size);

    // Deserialize with the duped slots.
    let msg2 = SingleMem::deserialize(&data, slots).unwrap();
    assert_eq!(read_marker(&msg2.region), 0xEE);
}

#[test]
fn codec_rejects_unused_slot_for_no_resource_message() {
    let msg = SimpleData {
        x: 1,
        y: "extra".into(),
    };
    let (data, slots) = msg.serialize().unwrap();
    assert!(slots.is_empty());

    let extra = amla_mem::MemHandle::into_slot(make_mem(4096, 0xF0)).unwrap();
    let err = SimpleData::deserialize(&data, vec![extra]).unwrap_err();
    assert!(matches!(err, amla_ipc::Error::UnusedResource(0)));
}

#[test]
fn codec_rejects_unused_slot_for_resource_message() {
    let msg = SingleMem {
        label: "one".into(),
        region: make_mem(4096, 0xF1),
    };
    let (data, mut slots) = msg.serialize().unwrap();
    slots.push(amla_mem::MemHandle::into_slot(make_mem(4096, 0xF2)).unwrap());

    let err = SingleMem::deserialize(&data, slots).unwrap_err();
    assert!(matches!(err, amla_ipc::Error::UnusedResource(1)));
}

#[test]
fn codec_rejects_duplicate_resource_index() {
    #[derive(serde::Serialize)]
    struct MultipleMemsWire {
        count: u32,
        regions: Vec<u32>,
    }

    let data = postcard::to_allocvec(&MultipleMemsWire {
        count: 2,
        regions: vec![0, 0],
    })
    .unwrap();
    let slot = amla_mem::MemHandle::into_slot(make_mem(4096, 0xF3)).unwrap();

    let err = MultipleMems::deserialize(&data, vec![slot]).unwrap_err();
    assert!(matches!(err, amla_ipc::Error::MissingResource(0)));
}
