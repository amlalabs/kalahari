// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Virtio pmem device — persistent memory.
//!
//! Single queue for flush requests. Config exposes the pmem region's GPA and size.
//!
//! The backing is always read-only, so `flush` is a no-op: the guest cannot
//! have dirtied the region, and there is nothing for the host to persist.
//! Responding OK here is accurate, not a durability lie. A future writable
//! pmem backing must add real `msync`/`fdatasync` — returning OK without
//! syncing would silently break guest crash-consistency.

#[cfg(test)]
mod tests;

use amla_core::vm_state::guest_mem::GuestMemory;
use amla_virtio::{DEVICE_ID_PMEM, QueueView, QueueViolation, VIRTIO_F_VERSION_1, VirtioDevice};

const VIRTIO_PMEM_REQ_TYPE_FLUSH: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_OK: u32 = 0;
const VIRTIO_PMEM_RESP_TYPE_ERROR: u32 = 1;

/// Virtio persistent memory device.
pub struct Pmem;

impl<M: GuestMemory> VirtioDevice<M> for Pmem {
    fn device_id(&self) -> u32 {
        DEVICE_ID_PMEM
    }

    fn queue_count(&self) -> usize {
        1
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_split()?;
            chain.require_readable_bytes(4)?;
            chain.require_writable_bytes(4)?;

            let request_type = read_request_type(&chain)?;
            let response_type = if request_type == VIRTIO_PMEM_REQ_TYPE_FLUSH {
                VIRTIO_PMEM_RESP_TYPE_OK
            } else {
                VIRTIO_PMEM_RESP_TYPE_ERROR
            };

            // virtio-pmem replies are exactly one struct virtio_pmem_resp
            // (le32 type) — only the first writable slot carries it. Backing
            // is read-only, so "flush" has nothing to sync; OK is honest.
            let response = response_type.to_le_bytes();
            queue.push_split_bytes(chain, &response)?;
        }
        Ok(())
    }
}

fn read_request_type<M: GuestMemory>(
    chain: &amla_virtio::SplitDescriptorChain<'_, '_, M>,
) -> Result<u32, QueueViolation> {
    let mut request = [0u8; 4];
    let mut read = 0usize;
    for slice in chain.readable() {
        if read == request.len() {
            break;
        }
        let n = slice.read_into_checked(0, &mut request[read..])?;
        read += n;
    }

    if read < request.len() {
        return Err(QueueViolation::DescriptorReadableCapacityTooSmall {
            head_index: chain.head_index(),
            required: request.len(),
            available: read,
        });
    }

    Ok(u32::from_le_bytes(request))
}
