// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![allow(clippy::panic)]

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_core::vm_state::{TEST_RAM_SIZE, make_test_vmstate, test_mmap};
use amla_virtio::{Descriptor, QueueState, QueueView, VIRTIO_F_VERSION_1};
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use std::fmt::Debug;

const RAM_SIZE: usize = TEST_RAM_SIZE;
const QUEUE_SIZE: u16 = 256;
const DESC_GPA: u64 = 0x0000;
const AVAIL_GPA: u64 = 0x4000;
const USED_GPA: u64 = 0x8000;

fn must<T, E: Debug>(result: Result<T, E>, context: &str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => panic!("{context}: {error:?}"),
    }
}

fn write_desc(vm: &impl GuestMemory, idx: u16, desc: Descriptor) {
    let gpa = DESC_GPA + u64::from(idx) * 16;
    must(vm.write_le_u64(gpa, desc.addr), "write descriptor addr");
    must(vm.write_le_u32(gpa + 8, desc.len), "write descriptor len");
    must(
        vm.write_le_u16(gpa + 12, desc.flags),
        "write descriptor flags",
    );
    must(
        vm.write_le_u16(gpa + 14, desc.next),
        "write descriptor next",
    );
}

fn populate_queue(vm: &impl GuestMemory) {
    for idx in 0..QUEUE_SIZE {
        write_desc(
            vm,
            idx,
            Descriptor {
                addr: 0x10000 + u64::from(idx) * 64,
                len: 0,
                flags: 0,
                next: 0,
            },
        );
        must(
            vm.write_le_u16(AVAIL_GPA + 4 + u64::from(idx) * 2, idx),
            "write avail ring entry",
        );
    }
    must(
        vm.write_le_u16(AVAIL_GPA + 2, QUEUE_SIZE),
        "write avail idx",
    );
}

const fn queue_state() -> QueueState {
    QueueState {
        desc_addr: DESC_GPA,
        avail_addr: AVAIL_GPA,
        used_addr: USED_GPA,
        generation: 0,
        last_avail_idx: 0,
        last_used_idx: 0,
        size: QUEUE_SIZE,
        ready: 1,
        pad0: 0,
    }
}

fn bench_pop_walk_push(c: &mut Criterion) {
    let mmap = test_mmap(RAM_SIZE);
    let vm = make_test_vmstate(&mmap, 0);
    populate_queue(&vm);

    c.bench_function("queue_pop_walk_push_256_zero_len", |b| {
        b.iter(|| {
            let mut state = queue_state();
            let completions = must(
                QueueView::with(0, &mut state, &vm, VIRTIO_F_VERSION_1, |view| {
                    let mut completions = 0u16;
                    while let Some(chain) = view.pop() {
                        let chain = must(chain.into_split(), "collect descriptors");
                        black_box(chain.readable());
                        black_box(chain.writable());
                        must(view.push(chain.complete_zero()), "push used entry");
                        completions = completions.wrapping_add(1);
                    }
                    completions
                }),
                "create queue view",
            );
            black_box(completions);
        });
    });
}

criterion_group!(benches, bench_pop_walk_push);
criterion_main!(benches);
