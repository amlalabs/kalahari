// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{QueuePopContext, SplitDescriptorChain};

fn deferred_completion_cannot_cross_pop_context_brand<'ctx, 'chain, 'm, M: GuestMemory>(
    context: &mut QueuePopContext<'ctx>,
    chain: SplitDescriptorChain<'chain, 'm, M>,
) {
    let _ = context.defer_split_completion(chain);
}

fn main() {}
