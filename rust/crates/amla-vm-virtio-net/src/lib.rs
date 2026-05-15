// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Virtio net device — network I/O for the guest.
//!
//! Supports 1..=5 queue pairs (even=RX, odd=TX). When `queue_pairs > 1`,
//! a control virtqueue is added at index `2*N` for MQ negotiation.
//!
//! TX: collect descriptor `(addr, len)` pairs, create `IoSlice` references into
//! guest memory (skipping the virtio-net header), then one `backend.send()`.
//!
//! RX: lease a complete backend packet, preflight the descriptor and used-ring
//! publication, then commit backend consumption only after guest delivery.

#[cfg(test)]
mod tests;

use std::io::IoSlice;

use amla_core::backends::{NetBackend, NetRxPacketLease};
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead};
use amla_virtio::{
    DEVICE_ID_NET, NetControlState, QueueView, QueueViolation, ReadCap, ReadableDescriptor,
    VIRTIO_F_VERSION_1, VIRTIO_NET_F_CTRL_VQ, VIRTIO_NET_F_MAC, VIRTIO_NET_F_MQ, VirtioDevice,
};
use std::num::NonZeroU32;

/// Cap applied to every descriptor-based `guest_read` on the net data path.
/// Matches `MAX_PACKET_SIZE`; any descriptor longer than a full packet is
/// clamped rather than materialized in full.
#[allow(clippy::cast_possible_truncation, clippy::unwrap_used)]
const NET_READ_CAP: ReadCap = ReadCap::new(NonZeroU32::new(MAX_PACKET_SIZE as u32).unwrap());

/// Virtio-net base header size before the optional `num_buffers` tail.
const VIRTIO_NET_BASE_HDR_SIZE: usize = 10;

/// Virtio-net header size used by modern Linux when `VIRTIO_F_VERSION_1` is
/// negotiated.
///
/// Linux sets `vi->hdr_len` to `sizeof(struct virtio_net_hdr_mrg_rxbuf)` for
/// modern devices even when `VIRTIO_NET_F_MRG_RXBUF` is not negotiated. The
/// final two bytes are the `num_buffers` field; this device never consumes it
/// because mergeable RX buffers are not offered.
const VIRTIO_NET_HDR_SIZE: usize = 12;

/// Virtio-net header size as `u32` for descriptor offsets.
const VIRTIO_NET_HDR_SIZE_U32: u32 = 12;

/// Maximum backend payload bytes for one RX packet.
const MAX_RX_PAYLOAD_SIZE: usize = MAX_PACKET_SIZE - VIRTIO_NET_HDR_SIZE;

/// Maximum number of queue pairs (limited by 512-byte device slot).
pub const MAX_QUEUE_PAIRS: u16 = 5;

/// Return the exact virtqueue count for a validated max queue-pair count.
///
/// Single-queue devices expose RX/TX only. Multi-queue devices expose
/// RX/TX for every queue pair plus one control queue.
#[must_use]
pub const fn queue_count_for_pairs(queue_pairs: u16) -> usize {
    let data_queues = 2 * queue_pairs as usize;
    if queue_pairs > 1 {
        data_queues + 1
    } else {
        data_queues
    }
}

/// Maximum bytes in a single TX or RX packet (header + payload).
///
/// Without `GSO`/`TSO`/`MRG_RXBUF` (none negotiated), each descriptor chain is one
/// Ethernet frame. 65535 is generous — real frames are ~1514 — but defends
/// against a malicious guest crafting huge descriptor chains to exhaust VMM
/// memory.
const MAX_PACKET_SIZE: usize = 65535;

/// Control queue command classes.
const VIRTIO_NET_CTRL_MQ: u8 = 4;
/// Control queue MQ commands.
const VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET: u8 = 0;
/// Control queue ACK values.
const VIRTIO_NET_OK: u8 = 0;
const VIRTIO_NET_ERR: u8 = 1;

/// Virtio net device with configurable multi-queue.
pub struct Net<'a, B: NetBackend + ?Sized> {
    backend: &'a B,
    max_queue_pairs: u16,
    control: &'a mut NetControlState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NoOffloadTxHeader;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct UnsupportedTxHeader([u8; VIRTIO_NET_HDR_SIZE]);

impl NoOffloadTxHeader {
    fn parse(raw: [u8; VIRTIO_NET_HDR_SIZE]) -> Result<Self, UnsupportedTxHeader> {
        if raw[..VIRTIO_NET_BASE_HDR_SIZE] == [0u8; VIRTIO_NET_BASE_HDR_SIZE] {
            Ok(Self)
        } else {
            Err(UnsupportedTxHeader(raw))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum NetCtrlAction {
    SetQueuePairs(u16),
}

impl<'a, B: NetBackend + ?Sized> Net<'a, B> {
    /// Create a net device with the given maximum number of queue pairs (1..=5).
    ///
    /// When `queue_pairs == 1`, behaves as a legacy single-queue device
    /// (no control queue, no MQ feature bits).
    pub fn new(backend: &'a B, queue_pairs: u16, control: &'a mut NetControlState) -> Self {
        assert!(
            (1..=MAX_QUEUE_PAIRS).contains(&queue_pairs),
            "queue_pairs must be 1..={MAX_QUEUE_PAIRS}"
        );
        let mut net = Self {
            backend,
            max_queue_pairs: queue_pairs,
            control,
        };
        net.normalize_active_queue_pairs();
        net
    }

    const fn active_queue_pairs(&self) -> u16 {
        self.control.active_queue_pairs
    }

    fn normalize_active_queue_pairs(&mut self) {
        if !(1..=self.max_queue_pairs).contains(&self.control.active_queue_pairs) {
            self.control.active_queue_pairs = 1;
        }
    }
}

impl<M: GuestMemory, B: NetBackend + ?Sized> VirtioDevice<M> for Net<'_, B> {
    fn device_id(&self) -> u32 {
        DEVICE_ID_NET
    }

    fn queue_count(&self) -> usize {
        queue_count_for_pairs(self.max_queue_pairs)
    }

    fn device_features(&self) -> u64 {
        let mut features = VIRTIO_F_VERSION_1 | VIRTIO_NET_F_MAC;
        if self.max_queue_pairs > 1 {
            features |= VIRTIO_NET_F_CTRL_VQ | VIRTIO_NET_F_MQ;
        }
        features
    }

    fn process_queue(
        &mut self,
        queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        let data_queues = 2 * self.max_queue_pairs as usize;
        if self.max_queue_pairs > 1 && queue_idx == data_queues {
            self.process_ctrl(queue)
        } else if queue_idx < 2 * self.active_queue_pairs() as usize {
            if queue_idx.is_multiple_of(2) {
                self.process_rx(queue)
            } else {
                self.process_tx(queue)
            }
        } else if queue_idx < data_queues {
            log::debug!(
                "virtio-net: ignoring inactive queue {queue_idx}; active queue pairs={}",
                self.active_queue_pairs()
            );
            Ok(())
        } else {
            log::warn!(
                "virtio-net: guest kicked queue {queue_idx} beyond queue_count {}",
                <Self as VirtioDevice<M>>::queue_count(self)
            );
            Ok(())
        }
    }

    fn reset(&mut self) {
        self.control.active_queue_pairs = 1;
    }
}

impl<B: NetBackend + ?Sized> Net<'_, B> {
    /// TX: copy guest data into one contiguous host buffer, then send.
    fn process_tx<M: GuestMemory>(
        &self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_readable()?;
            chain.require_readable_bytes(VIRTIO_NET_HDR_SIZE)?;

            let mut hdr = [0u8; VIRTIO_NET_HDR_SIZE];
            match read_descriptor_bytes(chain.descriptors(), 0, &mut hdr) {
                Ok(()) => {}
                Err(DescriptorReadError::Short) => {
                    return Err(QueueViolation::DescriptorReadableCapacityTooSmall {
                        head_index: chain.head_index(),
                        required: VIRTIO_NET_HDR_SIZE,
                        available: chain.readable_len(),
                    });
                }
                Err(DescriptorReadError::Access(e)) => return Err(e),
            }
            if let Err(UnsupportedTxHeader(hdr)) = NoOffloadTxHeader::parse(hdr) {
                log::warn!(
                    "virtio-net TX: dropping packet with unsupported virtio-net header {hdr:02x?}"
                );
                queue.push(chain.complete_zero())?;
                continue;
            }

            // Single pass: bound total length against MAX_PACKET_SIZE while
            // copying payload bytes (post-virtio-header) into one Vec. A u64
            // running total defends against u32 wrap on 32-bit hosts.
            let mut payload: Vec<u8> = Vec::new();
            let mut total_len: u64 = 0;
            let mut skip = VIRTIO_NET_HDR_SIZE_U32;
            let mut oversize = false;
            for slice in chain.descriptors() {
                total_len = total_len.saturating_add(u64::from(slice.len()));
                if total_len > MAX_PACKET_SIZE as u64 {
                    oversize = true;
                    continue;
                }
                let n = slice.len();
                if skip >= n {
                    skip -= n;
                    continue;
                }
                let gs = slice.guest_read_at_checked(skip, NET_READ_CAP)?;
                gs.extend_vec(&mut payload);
                skip = 0;
            }

            if oversize {
                log::warn!(
                    "virtio-net TX: dropping oversized packet ({total_len} bytes, max {MAX_PACKET_SIZE})"
                );
                queue.push(chain.complete_zero())?;
                continue;
            }

            queue.validate_next_completion()?;
            if !payload.is_empty()
                && let Err(e) = self.backend.send(&[IoSlice::new(&payload)])
            {
                log::warn!(
                    "virtio-net TX: backend send failed ({} bytes): {e}",
                    payload.len(),
                );
                return Err(QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_NET,
                    operation: "net_tx_backend_send",
                });
            }

            queue.push(chain.complete_zero())?;
        }
        Ok(())
    }

    /// RX: borrow a backend packet and consume it only after guest completion.
    fn process_rx<M: GuestMemory>(
        &self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(lease) = self.backend.rx_packet().map_err(|e| {
            log::warn!("virtio-net RX: backend lease failed: {e}");
            QueueViolation::DeviceOperationFailed {
                device_id: DEVICE_ID_NET,
                operation: "net_rx_backend_lease",
            }
        })? {
            let packet = lease.packet();
            let packet_len = packet.len();
            if packet_len == 0 || packet_len > MAX_RX_PAYLOAD_SIZE {
                log::warn!("virtio-net RX: backend offered invalid packet length {packet_len}");
                return Err(QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_NET,
                    operation: "net_rx_backend_packet_len",
                });
            }

            let Some(chain) = queue.pop() else { break };
            let chain = chain.into_writable()?;
            let total_written = VIRTIO_NET_HDR_SIZE.checked_add(packet_len).ok_or(
                QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_NET,
                    operation: "net_rx_packet_len_overflow",
                },
            )?;
            let prepared = queue.prepare_writable_bytes(chain, total_written)?;

            let mut response = vec![0u8; total_written];
            response[VIRTIO_NET_HDR_SIZE..].copy_from_slice(packet);
            queue.push_prepared_writable_bytes(prepared, &response)?;
            lease.commit().map_err(|e| {
                log::warn!("virtio-net RX: backend lease commit failed: {e}");
                QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_NET,
                    operation: "net_rx_backend_commit",
                }
            })?;
        }
        Ok(())
    }

    /// Process the control virtqueue.
    fn process_ctrl<M: GuestMemory>(
        &mut self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_split()?;
            chain.require_writable_bytes(1)?;

            let (ack, action) = self.decode_ctrl_command(chain.readable())?;
            queue.validate_next_completion()?;
            queue.push_split_bytes(chain, &[ack])?;
            if let Some(action) = action {
                self.apply_ctrl_action(action);
            }
        }
        Ok(())
    }

    /// Decode and validate one control-queue command from its readable
    /// descriptor regions. Returns `VIRTIO_NET_OK` / `VIRTIO_NET_ERR`.
    ///
    /// Per virtio 1.2 §5.1.6.5.4, `MQ_VQ_PAIRS_SET` takes a 2-byte payload
    /// (`struct virtio_net_ctrl_mq { le16 virtqueue_pairs; }`) which MUST
    /// satisfy `1 ≤ virtqueue_pairs ≤ max_virtqueue_pairs`. Linux's
    /// `virtio_net` typically splits the header and payload across two
    /// readable descriptors, so we read across the chain.
    fn decode_ctrl_command<M: GuestMemory>(
        &self,
        readable: &[ReadableDescriptor<'_, '_, M>],
    ) -> Result<(u8, Option<NetCtrlAction>), QueueViolation> {
        let mut hdr = [0u8; 2];
        match read_descriptor_bytes(readable, 0, &mut hdr) {
            Ok(()) => {}
            Err(DescriptorReadError::Short) => return Ok((VIRTIO_NET_ERR, None)),
            Err(DescriptorReadError::Access(e)) => return Err(e),
        }
        let class = hdr[0];
        let cmd = hdr[1];
        if (class, cmd) != (VIRTIO_NET_CTRL_MQ, VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET) {
            log::debug!("virtio-net: unknown ctrl class={class} cmd={cmd}");
            return Ok((VIRTIO_NET_ERR, None));
        }

        let mut payload = [0u8; 2];
        match read_descriptor_bytes(readable, 2, &mut payload) {
            Ok(()) => {}
            Err(DescriptorReadError::Short) => {
                log::warn!("virtio-net: CTRL_MQ VQ_PAIRS_SET missing 2-byte payload");
                return Ok((VIRTIO_NET_ERR, None));
            }
            Err(DescriptorReadError::Access(e)) => return Err(e),
        }
        let virtqueue_pairs = u16::from_le_bytes(payload);
        if virtqueue_pairs < 1 || virtqueue_pairs > self.max_queue_pairs {
            log::warn!(
                "virtio-net: CTRL_MQ VQ_PAIRS_SET virtqueue_pairs={virtqueue_pairs} outside [1, {}]",
                self.max_queue_pairs
            );
            return Ok((VIRTIO_NET_ERR, None));
        }
        Ok((
            VIRTIO_NET_OK,
            Some(NetCtrlAction::SetQueuePairs(virtqueue_pairs)),
        ))
    }

    fn apply_ctrl_action(&mut self, action: NetCtrlAction) {
        match action {
            NetCtrlAction::SetQueuePairs(virtqueue_pairs) => {
                self.control.active_queue_pairs = virtqueue_pairs;
                log::debug!("virtio-net: CTRL_MQ VQ_PAIRS_SET virtqueue_pairs={virtqueue_pairs}");
            }
        }
    }
}

enum DescriptorReadError {
    Short,
    Access(QueueViolation),
}

/// Read `dst.len()` bytes starting at logical `offset` across a sequence of
/// readable descriptor slices, treating the chain as one logical buffer.
/// Returns `Short` if the chain runs out before `dst` is filled and `Access`
/// if a validated descriptor buffer cannot be read.
fn read_descriptor_bytes<M: GuestMemory>(
    readable: &[ReadableDescriptor<'_, '_, M>],
    offset: u32,
    dst: &mut [u8],
) -> Result<(), DescriptorReadError> {
    let mut cursor = offset;
    let mut written = 0usize;
    for slice in readable {
        let slice_len = slice.len();
        if cursor >= slice_len {
            cursor -= slice_len;
            continue;
        }
        let buf = &mut dst[written..];
        let n = slice
            .read_into_checked(cursor, buf)
            .map_err(DescriptorReadError::Access)?;
        cursor = 0;
        written += n;
        if written == dst.len() {
            return Ok(());
        }
    }
    if written == dst.len() {
        Ok(())
    } else {
        Err(DescriptorReadError::Short)
    }
}
