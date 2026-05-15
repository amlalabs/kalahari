// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::SplitDescriptorChain;

fn writable_addr_is_not_public<'brand, 'm, M: GuestMemory>(
    chain: &SplitDescriptorChain<'brand, 'm, M>,
) -> u64 {
    chain.writable()[0].addr()
}

fn main() {}
