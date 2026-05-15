// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{CompletedDescriptorChain, QueueView};

fn completion_cannot_cross_queue_brand<'left, 'right, 'q, 'm, M: GuestMemory>(
    view: &mut QueueView<'left, 'q, 'm, M>,
    completion: CompletedDescriptorChain<'right>,
) {
    let _ = view.push(completion);
}

fn main() {}
