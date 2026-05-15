// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{QueueRunner, QueueState, WritableDescriptor};

fn writable_descriptor_cannot_escape_pop_view<'t, 'm, M: GuestMemory>(
    runner: &mut QueueRunner<'t, 'm, M>,
    queue: &mut QueueState,
) -> Vec<WritableDescriptor<'static, 'm, M>> {
    runner
        .pop_view(0, queue, |view, _ctx| {
            let chain = view.pop().unwrap().into_split().unwrap();
            Ok(chain.writable().to_vec())
        })
        .unwrap()
}

fn main() {}
