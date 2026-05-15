// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{ReadableDescriptorChain, WrittenBytes};

fn readable_chain_cannot_complete_nonzero<M: GuestMemory>(
    chain: ReadableDescriptorChain<'_, '_, M>,
    written: WrittenBytes,
) {
    let _completion = chain.complete(written);
}

fn main() {}
