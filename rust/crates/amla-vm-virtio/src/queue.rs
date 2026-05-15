// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Zero-copy virtqueue access.
//!
//! [`QueueView`] overlays guest memory using addresses from [`QueueState`].
//! All memory ordering (fences), ring index arithmetic, and notification
//! suppression logic lives here — devices never touch any of it.

use crate::descriptor::{
    DescriptorBuffer, DescriptorChain, DescriptorRef, ReadableDescriptor, WritableDescriptor,
};
use crate::{QueueState, VIRTIO_F_EVENT_IDX, VIRTIO_F_INDIRECT_DESC, VRING_AVAIL_F_NO_INTERRUPT};
use amla_core::vm_state::guest_mem::{GuestMemory, GuestWrite};
use std::fmt;
use std::marker::PhantomData;
use std::sync::atomic::{Ordering, fence};

// =============================================================================
// Avail Ring Layout (virtio spec 2.7.6)
// =============================================================================
//
// struct virtq_avail {
//     le16 flags;           // offset 0
//     le16 idx;             // offset 2
//     le16 ring[queue_size]; // offset 4
//     le16 used_event;      // offset 4 + 2*queue_size  (if EVENT_IDX)
// };

/// Offset of `flags` in avail ring.
const AVAIL_FLAGS_OFFSET: u64 = 0;
/// Offset of `idx` in avail ring.
const AVAIL_IDX_OFFSET: u64 = 2;
/// Offset of `ring[]` in avail ring.
const AVAIL_RING_OFFSET: u64 = 4;

// =============================================================================
// Used Ring Layout (virtio spec 2.7.8)
// =============================================================================
//
// struct virtq_used_elem {
//     le32 id;    // descriptor chain head index
//     le32 len;   // total bytes written by device
// };
//
// struct virtq_used {
//     le16 flags;                    // offset 0
//     le16 idx;                      // offset 2
//     virtq_used_elem ring[queue_size]; // offset 4
//     le16 avail_event;              // offset 4 + 8*queue_size  (if EVENT_IDX)
// };

/// Offset of `idx` in used ring.
const USED_IDX_OFFSET: u64 = 2;
/// Offset of `ring[]` in used ring.
const USED_RING_OFFSET: u64 = 4;

// =============================================================================
// QueueView
// =============================================================================

/// Type marker for a queue whose transport-level ready invariants were checked.
#[derive(Debug)]
pub struct ReadyQueue;

/// A driver-visible virtqueue protocol violation.
///
/// The transport treats these as fatal for the device instance: it sets
/// `DEVICE_NEEDS_RESET` and requires a full queue reset before more work is
/// accepted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum QueueViolation {
    /// `QueueView::try_new` was called for a queue that is not ready.
    QueueNotReady,
    /// Queue size is neither zero nor a power of two.
    InvalidQueueSize {
        /// Queue size from `QueueState`.
        size: u16,
    },
    /// Failed to read `avail.idx`.
    AvailIdxReadFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// `avail.idx` moved forward by more than the queue size.
    AvailIndexJump {
        /// Driver-published available index.
        avail_idx: u16,
        /// VMM cursor before the pop attempt.
        last_avail_idx: u16,
        /// Queue size.
        size: u16,
    },
    /// Failed to read an entry from `avail.ring`.
    AvailEntryReadFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// Failed to read `avail.flags`.
    AvailFlagsReadFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// Failed to read `used_event`.
    UsedEventReadFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// `avail.ring` referenced a descriptor outside the configured queue.
    DescriptorIndexOutOfRange {
        /// Descriptor index read from `avail.ring`.
        index: u16,
        /// Queue size.
        queue_size: u16,
    },
    /// Failed to write `avail_event` for `VIRTIO_F_EVENT_IDX`.
    AvailEventWriteFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// Device attempted to publish a head descriptor outside the queue.
    HeadIndexOutOfRange {
        /// Head descriptor index passed to `push`.
        index: u16,
        /// Queue size.
        queue_size: u16,
    },
    /// Failed to write a used-ring entry.
    UsedEntryWriteFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// Device attempted to publish more used entries than the queue can hold.
    UsedRingPublishTooLarge {
        /// Number of used entries requested.
        count: usize,
        /// Queue size.
        queue_size: u16,
    },
    /// Device attempted to publish a used-ring length that cannot fit in the
    /// virtio `used_elem.len` field.
    UsedLengthTooLarge {
        /// Head descriptor index being completed.
        head_index: u16,
        /// Completion length the device attempted to publish.
        bytes: usize,
    },
    /// Device attempted to publish entries from more than one queue instance
    /// in a single batch.
    UsedRingMixedQueueTokens {
        /// Queue index selected for the batch.
        queue_idx: usize,
    },
    /// A synchronous device returned after popping descriptor chains without
    /// publishing the matching used-ring entries.
    UncompletedDescriptorChains {
        /// Chains popped from the avail ring during this queue run.
        popped: usize,
        /// Used-ring entries published during this queue run.
        pushed: usize,
    },
    /// A device-internal operation failed after queue descriptors were
    /// accepted but before a valid used-ring completion could be published.
    DeviceOperationFailed {
        /// Virtio device ID.
        device_id: u32,
        /// Static operation name.
        operation: &'static str,
    },
    /// Device code prepared one used-ring length but wrote a different number
    /// of response bytes into the descriptor buffers.
    DescriptorResponseLengthMismatch {
        /// Head descriptor index where the write began.
        head_index: u16,
        /// Prepared used-ring byte count.
        expected: usize,
        /// Bytes actually written through the guarded writer.
        actual: usize,
    },
    /// Failed to write `used.idx`.
    UsedIdxWriteFailed {
        /// Guest physical address that failed.
        addr: u64,
    },
    /// Computing a ring GPA (`base + offset`) overflowed `u64`. The driver
    /// programmed a queue address near `u64::MAX` so a plain add would wrap
    /// to a small value and alias unrelated guest memory.
    RingAddressOverflow {
        /// Ring base GPA (e.g. `avail_addr` or `used_addr`).
        base: u64,
        /// Byte offset added to the base.
        offset: u64,
    },

    // -------------------------------------------------------------------------
    // Descriptor walk and shape violations. These are returned while converting
    // a raw popped chain into a typed completion chain, before `push` is
    // available to device code.
    // -------------------------------------------------------------------------
    /// A descriptor's `NEXT` pointer references an index outside the queue.
    DescriptorNextIndexOutOfRange {
        /// Next-descriptor index the chain tried to advance to.
        index: u16,
        /// Configured queue size.
        queue_size: u16,
    },
    /// A descriptor chain exceeded `queue_size` steps without terminating.
    DescriptorChainTooLong {
        /// Head descriptor index where the walk began.
        head_index: u16,
        /// Queue size that bounded the walk.
        queue_size: u16,
    },
    /// A single descriptor had both `VIRTQ_DESC_F_NEXT` and
    /// `VIRTQ_DESC_F_INDIRECT` set — forbidden by spec §2.7.5.3.1.
    DescriptorNextAndIndirectSet {
        /// Descriptor index with the invalid flag combination.
        index: u16,
    },
    /// Failed to read a descriptor entry from the direct table.
    DescriptorReadFailed {
        /// Guest physical address of the descriptor that failed to read.
        addr: u64,
    },
    /// A descriptor's `addr + len` overflowed `u64`, or the buffer fell
    /// outside guest RAM (failed descriptor range validation).
    DescriptorBufferOutOfRange {
        /// Buffer base GPA.
        addr: u64,
        /// Buffer length.
        len: u32,
    },
    /// A previously range-validated device-readable descriptor buffer failed
    /// during the actual guest-memory read.
    DescriptorBufferReadFailed {
        /// Buffer base GPA.
        addr: u64,
        /// Buffer length.
        len: u32,
    },
    /// A previously range-validated device-writable descriptor buffer failed
    /// during the actual guest-memory write.
    DescriptorBufferWriteFailed {
        /// Buffer base GPA.
        addr: u64,
        /// Buffer length.
        len: u32,
    },
    /// A device-readable descriptor appeared after a device-writable
    /// descriptor in one chain. Split virtqueues require all readable
    /// descriptors before all writable descriptors.
    DescriptorReadableAfterWritable {
        /// Head descriptor index where the walk began.
        head_index: u16,
    },
    /// A queue that accepts only device-readable descriptors received a
    /// device-writable descriptor.
    DescriptorUnexpectedWritable {
        /// Head descriptor index where the walk began.
        head_index: u16,
    },
    /// A queue that accepts only device-writable descriptors received a
    /// device-readable descriptor.
    DescriptorUnexpectedReadable {
        /// Head descriptor index where the walk began.
        head_index: u16,
    },
    /// A descriptor chain did not provide enough device-readable bytes for
    /// the queue operation's fixed request shape.
    DescriptorReadableCapacityTooSmall {
        /// Head descriptor index where the walk began.
        head_index: u16,
        /// Minimum readable bytes required by the device.
        required: usize,
        /// Readable bytes supplied by the driver.
        available: usize,
    },
    /// A descriptor chain did not provide enough device-writable bytes for
    /// the queue operation's fixed response shape.
    DescriptorWritableCapacityTooSmall {
        /// Head descriptor index where the walk began.
        head_index: u16,
        /// Minimum writable bytes required by the device.
        required: usize,
        /// Writable bytes supplied by the driver.
        available: usize,
    },
    /// Summing writable descriptor lengths overflowed host `usize`.
    DescriptorWritableLengthOverflow {
        /// Head descriptor index where the walk began.
        head_index: u16,
    },
    /// Driver set `VIRTQ_DESC_F_INDIRECT` without negotiating
    /// `VIRTIO_F_INDIRECT_DESC`.
    IndirectDescriptorNotNegotiated {
        /// Descriptor index that set the un-negotiated flag.
        index: u16,
    },
    /// Indirect-descriptor table GPA + length overflowed or fell outside
    /// guest RAM.
    IndirectTableOutOfRange {
        /// Indirect table base GPA.
        addr: u64,
        /// Indirect table length in bytes.
        len: u32,
    },
    /// Indirect-descriptor table length is zero or not a multiple of 16
    /// (the descriptor size).
    IndirectTableInvalidLength {
        /// Table length in bytes.
        len: u32,
    },
    /// Indirect-descriptor table has more entries than the per-chain cap.
    IndirectTableTooLarge {
        /// Entries the guest requested.
        entries: u32,
        /// Configured maximum (`MAX_INDIRECT_TABLE_LEN`).
        max_entries: u16,
    },
    /// Failed to read an entry from a guest-memory indirect-descriptor table.
    IndirectEntryReadFailed {
        /// GPA of the indirect-table entry that failed to read.
        addr: u64,
    },
    /// An indirect descriptor's `NEXT` pointer references an index outside
    /// the indirect table.
    IndirectDescriptorIndexOutOfRange {
        /// `NEXT` index the chain tried to advance to.
        index: u16,
        /// Indirect table length.
        table_len: u16,
    },
    /// An indirect descriptor chain exceeded the indirect-table size in
    /// steps without terminating.
    IndirectDescriptorChainTooLong {
        /// Indirect table length that bounded the walk.
        table_len: u16,
    },
    /// An indirect-table entry set `VIRTQ_DESC_F_INDIRECT` (nesting is
    /// forbidden by spec §2.7.5.3.1).
    NestedIndirectDescriptor {
        /// Indirect-table index of the offending entry.
        index: u16,
    },
    /// A virtqueue ring's address range fell outside guest RAM, or the
    /// worst-case ring length wrapped `u64`. Checked once on the
    /// `QueueReady=0 → 1` transition. Once accepted, every per-access
    /// offset addition in `pop`/`push`/`needs_notification` is guaranteed
    /// not to wrap, because the spec forbids the driver from changing
    /// `QueueNum` or queue address registers while ready
    /// (virtio 1.2 §4.2.2.2).
    RingAddressInvalid {
        /// Which ring failed: `"desc"`, `"avail"`, or `"used"`.
        region: &'static str,
        /// Ring base GPA the guest configured.
        addr: u64,
        /// Ring length required by negotiated features.
        len: u64,
    },
    /// A split virtqueue ring base did not meet the spec alignment.
    RingAddressUnaligned {
        /// Which ring failed: `"desc"`, `"avail"`, or `"used"`.
        region: &'static str,
        /// Ring base GPA the guest configured.
        addr: u64,
        /// Required byte alignment.
        align: u64,
    },
}

impl fmt::Display for QueueViolation {
    #[allow(clippy::too_many_lines)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::QueueNotReady => write!(f, "queue is not ready"),
            Self::InvalidQueueSize { size } => write!(f, "invalid queue size {size}"),
            Self::AvailIdxReadFailed { addr } => {
                write!(f, "failed to read avail.idx at {addr:#x}")
            }
            Self::AvailIndexJump {
                avail_idx,
                last_avail_idx,
                size,
            } => write!(
                f,
                "avail.idx jumped too far: avail_idx={avail_idx}, last_avail_idx={last_avail_idx}, size={size}"
            ),
            Self::AvailEntryReadFailed { addr } => {
                write!(f, "failed to read avail.ring entry at {addr:#x}")
            }
            Self::AvailFlagsReadFailed { addr } => {
                write!(f, "failed to read avail.flags at {addr:#x}")
            }
            Self::UsedEventReadFailed { addr } => {
                write!(f, "failed to read used_event at {addr:#x}")
            }
            Self::DescriptorIndexOutOfRange { index, queue_size } => {
                write!(
                    f,
                    "descriptor index {index} outside queue size {queue_size}"
                )
            }
            Self::AvailEventWriteFailed { addr } => {
                write!(f, "failed to write avail_event at {addr:#x}")
            }
            Self::HeadIndexOutOfRange { index, queue_size } => {
                write!(
                    f,
                    "head descriptor index {index} outside queue size {queue_size}"
                )
            }
            Self::UsedEntryWriteFailed { addr } => {
                write!(f, "failed to write used-ring entry at {addr:#x}")
            }
            Self::UsedRingPublishTooLarge { count, queue_size } => write!(
                f,
                "attempted to publish {count} used-ring entries into queue size {queue_size}"
            ),
            Self::UsedLengthTooLarge { head_index, bytes } => write!(
                f,
                "descriptor chain from head {head_index} attempted to publish {bytes} used bytes, exceeding u32::MAX"
            ),
            Self::UsedRingMixedQueueTokens { queue_idx } => write!(
                f,
                "used-ring publisher received mixed queue tokens for queue {queue_idx}"
            ),
            Self::UncompletedDescriptorChains { popped, pushed } => write!(
                f,
                "device returned with {popped} popped descriptor chains but {pushed} used entries"
            ),
            Self::DeviceOperationFailed {
                device_id,
                operation,
            } => write!(
                f,
                "device {device_id} failed internal operation: {operation}"
            ),
            Self::DescriptorResponseLengthMismatch {
                head_index,
                expected,
                actual,
            } => write!(
                f,
                "descriptor chain from head {head_index} wrote {actual} response bytes, expected {expected}"
            ),
            Self::UsedIdxWriteFailed { addr } => write!(f, "failed to write used.idx at {addr:#x}"),
            Self::RingAddressOverflow { base, offset } => {
                write!(f, "ring address {base:#x} + {offset:#x} overflows u64")
            }
            Self::DescriptorNextIndexOutOfRange { index, queue_size } => write!(
                f,
                "descriptor NEXT pointer {index} outside queue size {queue_size}"
            ),
            Self::DescriptorChainTooLong {
                head_index,
                queue_size,
            } => write!(
                f,
                "descriptor chain from head {head_index} exceeded {queue_size} steps"
            ),
            Self::DescriptorNextAndIndirectSet { index } => write!(
                f,
                "descriptor {index} has NEXT and INDIRECT flags set simultaneously"
            ),
            Self::DescriptorReadFailed { addr } => {
                write!(f, "failed to read descriptor at {addr:#x}")
            }
            Self::DescriptorBufferOutOfRange { addr, len } => {
                write!(f, "descriptor buffer {addr:#x}..+{len} outside guest RAM")
            }
            Self::DescriptorBufferReadFailed { addr, len } => {
                write!(f, "failed to read descriptor buffer {addr:#x}..+{len}")
            }
            Self::DescriptorBufferWriteFailed { addr, len } => {
                write!(f, "failed to write descriptor buffer {addr:#x}..+{len}")
            }
            Self::DescriptorReadableAfterWritable { head_index } => write!(
                f,
                "descriptor chain from head {head_index} has readable descriptor after writable descriptor",
            ),
            Self::DescriptorUnexpectedWritable { head_index } => write!(
                f,
                "descriptor chain from head {head_index} contains a writable descriptor on a readable-only queue",
            ),
            Self::DescriptorUnexpectedReadable { head_index } => write!(
                f,
                "descriptor chain from head {head_index} contains a readable descriptor on a writable-only queue",
            ),
            Self::DescriptorReadableCapacityTooSmall {
                head_index,
                required,
                available,
            } => write!(
                f,
                "descriptor chain from head {head_index} has {available} readable bytes, need {required}",
            ),
            Self::DescriptorWritableCapacityTooSmall {
                head_index,
                required,
                available,
            } => write!(
                f,
                "descriptor chain from head {head_index} has {available} writable bytes, need {required}",
            ),
            Self::DescriptorWritableLengthOverflow { head_index } => write!(
                f,
                "descriptor chain from head {head_index} writable byte count overflows usize",
            ),
            Self::IndirectDescriptorNotNegotiated { index } => write!(
                f,
                "descriptor {index} set INDIRECT but VIRTIO_F_INDIRECT_DESC was not negotiated",
            ),
            Self::IndirectTableOutOfRange { addr, len } => {
                write!(f, "indirect table {addr:#x}..+{len} outside guest RAM")
            }
            Self::IndirectTableInvalidLength { len } => write!(
                f,
                "indirect table length {len} is zero or not a multiple of 16",
            ),
            Self::IndirectTableTooLarge {
                entries,
                max_entries,
            } => write!(
                f,
                "indirect table {entries} entries exceeds cap {max_entries}",
            ),
            Self::IndirectEntryReadFailed { addr } => {
                write!(f, "failed to read indirect-table entry at {addr:#x}")
            }
            Self::IndirectDescriptorIndexOutOfRange { index, table_len } => write!(
                f,
                "indirect descriptor NEXT pointer {index} outside table size {table_len}",
            ),
            Self::IndirectDescriptorChainTooLong { table_len } => {
                write!(f, "indirect descriptor chain exceeded {table_len} steps")
            }
            Self::NestedIndirectDescriptor { index } => write!(
                f,
                "indirect-table entry {index} set INDIRECT (nesting forbidden)",
            ),
            Self::RingAddressInvalid { region, addr, len } => write!(
                f,
                "{region} ring {addr:#x}..+{len} outside guest RAM or wraps u64",
            ),
            Self::RingAddressUnaligned {
                region,
                addr,
                align,
            } => write!(f, "{region} ring {addr:#x} is not aligned to {align} bytes"),
        }
    }
}

impl std::error::Error for QueueViolation {}

/// Compute `base + offset` as a guest-physical ring address, returning a
/// queue violation on `u64` overflow.
///
/// All ring address math goes through this helper: descriptor table, avail
/// ring, and used ring all live at guest-programmed `u64` GPAs, so a hostile
/// driver can pick a base near `u64::MAX` to make a plain add wrap to a small
/// value and alias unrelated guest memory.
#[inline]
fn ring_addr(base: u64, offset: u64) -> Result<u64, QueueViolation> {
    base.checked_add(offset)
        .ok_or(QueueViolation::RingAddressOverflow { base, offset })
}

/// Queue lifecycle generation captured while popping descriptors.
///
/// This is an ABA guard for delayed or misrouted completions. A driver can
/// reset and reuse the same queue slot, descriptor head, and ring addresses;
/// generation is the queue-instance identity that changes on reset.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueGeneration(u64);

impl QueueGeneration {
    /// Capture the current generation from a queue state.
    #[must_use]
    pub(crate) const fn current(queue: &QueueState) -> Self {
        Self(queue.generation)
    }

    /// Return whether the queue still has the captured generation.
    #[must_use]
    pub(crate) const fn matches(self, queue: &QueueState) -> bool {
        self.0 == queue.generation
    }
}

/// Queue identity and generation captured while popping descriptors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct QueueClaim {
    queue_idx: usize,
    generation: QueueGeneration,
}

impl QueueClaim {
    pub(crate) const fn current(queue_idx: usize, queue: &QueueState) -> Self {
        Self {
            queue_idx,
            generation: QueueGeneration::current(queue),
        }
    }

    pub(crate) const fn queue_idx(self) -> usize {
        self.queue_idx
    }

    pub(crate) const fn matches(self, queue: &QueueState) -> bool {
        self.generation.matches(queue)
    }
}

/// A descriptor chain that was consumed from a virtqueue's available ring.
///
/// This raw ownership token cannot be completed directly. Device code must
/// first convert it into one of the typed chain wrappers, which validates the
/// descriptor walk and records whether buffers are readable, writable, or
/// split request/response. Only the typed wrappers implement
/// [`CompletableDescriptorChain`], so malformed chains cannot be acknowledged
/// by accidentally calling [`QueueView::push`].
pub struct PoppedDescriptorChain<'brand, 'm, M: GuestMemory> {
    claim: QueueClaim,
    chain: DescriptorChain<'brand, 'm, M>,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
}

impl<'brand, 'm, M: GuestMemory> PoppedDescriptorChain<'brand, 'm, M> {
    fn new(claim: QueueClaim, chain: DescriptorChain<'brand, 'm, M>) -> Self {
        Self {
            claim,
            chain,
            _brand: PhantomData,
        }
    }

    const fn claim(&self) -> QueueClaim {
        self.claim
    }

    const fn memory(&self) -> &'m M {
        self.chain.memory()
    }

    /// The head descriptor index consumed from the avail ring.
    #[must_use]
    pub const fn head_index(&self) -> u16 {
        self.chain.head_index()
    }

    /// Validate and collect a queue that must contain only device-readable descriptors.
    pub fn into_readable(
        mut self,
    ) -> Result<ReadableDescriptorChain<'brand, 'm, M>, QueueViolation> {
        let head_index = self.head_index();
        let mut descriptors = Vec::new();
        for desc in self.chain.by_ref() {
            match desc? {
                DescriptorRef::Readable(desc) => descriptors.push(desc),
                DescriptorRef::Writable(_) => {
                    return Err(QueueViolation::DescriptorUnexpectedWritable { head_index });
                }
            }
        }
        Ok(ReadableDescriptorChain {
            chain: self,
            descriptors,
        })
    }

    /// Validate and collect a queue that must contain only device-writable descriptors.
    pub fn into_writable(
        mut self,
    ) -> Result<WritableDescriptorChain<'brand, 'm, M>, QueueViolation> {
        let head_index = self.head_index();
        let mut descriptors = Vec::new();
        for desc in self.chain.by_ref() {
            match desc? {
                DescriptorRef::Readable(_) => {
                    return Err(QueueViolation::DescriptorUnexpectedReadable { head_index });
                }
                DescriptorRef::Writable(desc) => descriptors.push(desc),
            }
        }
        Ok(WritableDescriptorChain {
            chain: self,
            descriptors,
        })
    }

    /// Validate and collect a split chain with readable descriptors before writable descriptors.
    pub fn into_split(mut self) -> Result<SplitDescriptorChain<'brand, 'm, M>, QueueViolation> {
        let head_index = self.head_index();
        let mut readable = Vec::new();
        let mut writable = Vec::new();
        for desc in self.chain.by_ref() {
            match desc? {
                DescriptorRef::Readable(desc) => {
                    if !writable.is_empty() {
                        return Err(QueueViolation::DescriptorReadableAfterWritable { head_index });
                    }
                    readable.push(desc);
                }
                DescriptorRef::Writable(desc) => writable.push(desc),
            }
        }
        Ok(SplitDescriptorChain {
            chain: self,
            readable,
            writable,
        })
    }
}

mod sealed {
    use amla_core::vm_state::guest_mem::GuestMemory;

    pub trait CompletableDescriptorChain<'brand, 'm, M: GuestMemory> {
        fn head_index(&self) -> u16;
        fn writable_len_for_completion(&self) -> usize;
    }
}

/// A validated popped descriptor chain that can be completed to the used ring.
///
/// The trait is sealed so device code cannot forge a completion capability
/// from a raw descriptor head. Implementations exist only for the typed chain
/// wrappers returned by [`PoppedDescriptorChain`].
pub trait CompletableDescriptorChain<'brand, 'm, M: GuestMemory>:
    sealed::CompletableDescriptorChain<'brand, 'm, M>
{
    /// The descriptor head index consumed from the available ring.
    #[must_use]
    fn head_index(&self) -> u16 {
        sealed::CompletableDescriptorChain::head_index(self)
    }

    /// Writable capacity that may be reported in the used-ring length field.
    #[must_use]
    fn writable_len_for_completion(&self) -> usize {
        sealed::CompletableDescriptorChain::writable_len_for_completion(self)
    }
}

/// Checked byte count for the virtio used-ring `len` field.
///
/// Values are produced by writable descriptor chains or queue tokens after
/// comparing the requested length with the writable descriptor capacity. A
/// zero value is always valid, including for read-only chains.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct WrittenBytes(u32);

impl WrittenBytes {
    /// A completion that reports no device-written bytes.
    #[must_use]
    pub const fn zero() -> Self {
        Self(0)
    }

    /// Return the checked used-ring byte count.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    pub(crate) fn checked(
        head_index: u16,
        writable_len: usize,
        bytes: usize,
    ) -> Result<Self, QueueViolation> {
        if bytes > writable_len {
            return Err(QueueViolation::DescriptorWritableCapacityTooSmall {
                head_index,
                required: bytes,
                available: writable_len,
            });
        }
        let bytes = u32::try_from(bytes)
            .map_err(|_| QueueViolation::UsedLengthTooLarge { head_index, bytes })?;
        Ok(Self(bytes))
    }
}

/// A descriptor chain consumed into an exact used-ring completion.
///
/// Device code obtains this by calling `complete_zero()` on a readable chain.
/// Writable/split chains are completed inside [`QueueView::push_writable_bytes`]
/// or [`QueueView::push_split_bytes`] after queue-owned response writes. The
/// queue can then publish the completion without accepting a raw byte count.
#[derive(Debug, Eq, PartialEq)]
pub struct CompletedDescriptorChain<'brand> {
    claim: QueueClaim,
    head_index: u16,
    bytes_written: WrittenBytes,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
}

impl CompletedDescriptorChain<'_> {
    fn new(claim: QueueClaim, head_index: u16, bytes_written: WrittenBytes) -> Self {
        Self {
            claim,
            head_index,
            bytes_written,
            _brand: PhantomData,
        }
    }
}

/// A writable descriptor completion whose guest-visible publication path has
/// already been validated.
///
/// Device code uses this when it must perform non-rollbackable backend I/O
/// before writing response bytes. Constructing the token validates the used
/// ring and the writable descriptor prefix for the exact response length; the
/// token can then be consumed to publish the matching response.
pub struct PreparedWritableCompletion<'brand, 'm, M: GuestMemory> {
    chain: WritableDescriptorChain<'brand, 'm, M>,
    reservation: ReservedUsedRingEntry,
    written: WrittenBytes,
}

/// Opaque writable descriptor regions captured for delayed completion.
///
/// This type intentionally exposes only aggregate capacity. Raw guest
/// addresses stay crate-private and are used only by [`QueueRunner`](crate::QueueRunner)
/// after it has revalidated queue generation and used-ring writability.
#[derive(Debug)]
pub struct DeferredWritableRegions {
    regions: Vec<WritableRegion>,
    capacity: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WritableRegion {
    pub(crate) addr: u64,
    pub(crate) len: u32,
}

/// Heap reservation charged for one deferred writable descriptor region.
pub const DEFERRED_WRITABLE_REGION_RESERVED_BYTES: usize = std::mem::size_of::<WritableRegion>();

impl DeferredWritableRegions {
    fn from_descriptors<M: GuestMemory>(
        head_index: u16,
        descriptors: Vec<WritableDescriptor<'_, '_, M>>,
    ) -> Result<Self, QueueViolation> {
        let mut capacity = 0usize;
        let mut regions = Vec::with_capacity(descriptors.len());
        for desc in descriptors {
            capacity = capacity
                .checked_add(desc.len() as usize)
                .ok_or(QueueViolation::DescriptorWritableLengthOverflow { head_index })?;
            regions.push(WritableRegion {
                addr: desc.addr(),
                len: desc.len(),
            });
        }
        Ok(Self { regions, capacity })
    }

    /// Total writable bytes captured from the popped descriptor chain.
    #[must_use]
    pub const fn capacity(&self) -> usize {
        self.capacity
    }

    pub(crate) const fn reserved_bytes(&self) -> usize {
        self.regions
            .capacity()
            .saturating_mul(std::mem::size_of::<WritableRegion>())
    }

    pub(crate) fn validate_write_prefix<M: GuestMemory>(
        &self,
        memory: &M,
        head_index: u16,
        total: usize,
    ) -> Result<(), QueueViolation> {
        if total > self.capacity {
            return Err(QueueViolation::DescriptorWritableCapacityTooSmall {
                head_index,
                required: total,
                available: self.capacity,
            });
        }

        let mut remaining = total;
        for region in &self.regions {
            if remaining == 0 {
                break;
            }
            let len = (region.len as usize).min(remaining);
            if len != 0 {
                memory.validate_write_range(region.addr, len).map_err(|_| {
                    QueueViolation::DescriptorBufferWriteFailed {
                        addr: region.addr,
                        len: region.len,
                    }
                })?;
                remaining -= len;
            }
        }
        if remaining == 0 {
            Ok(())
        } else {
            Err(QueueViolation::DescriptorWritableCapacityTooSmall {
                head_index,
                required: total,
                available: total - remaining,
            })
        }
    }

    pub(crate) fn regions(&self) -> &[WritableRegion] {
        &self.regions
    }
}

struct DescriptorWriteGuard<'a, 'm, M: GuestMemory> {
    memory: &'m M,
    writable: &'a DeferredWritableRegions,
    head_index: u16,
    expected: WrittenBytes,
    region_idx: usize,
    region_offset: u32,
    written: usize,
}

impl<'a, 'm, M: GuestMemory> DescriptorWriteGuard<'a, 'm, M> {
    pub(crate) const fn new(
        memory: &'m M,
        writable: &'a DeferredWritableRegions,
        head_index: u16,
        expected: WrittenBytes,
    ) -> Self {
        Self {
            memory,
            writable,
            head_index,
            expected,
            region_idx: 0,
            region_offset: 0,
            written: 0,
        }
    }

    const fn expected_bytes(&self) -> usize {
        self.expected.get() as usize
    }

    const fn remaining_bytes(&self) -> usize {
        self.expected_bytes().saturating_sub(self.written)
    }

    fn write_from(&mut self, src: &[u8]) -> Result<usize, QueueViolation> {
        let remaining_budget = self.remaining_bytes();
        if src.len() > remaining_budget {
            return Err(QueueViolation::DescriptorResponseLengthMismatch {
                head_index: self.head_index,
                expected: self.expected_bytes(),
                actual: self.written.saturating_add(src.len()),
            });
        }

        let mut src_pos = 0usize;
        while src_pos < src.len() {
            let Some(region) = self.writable.regions().get(self.region_idx) else {
                break;
            };
            let region_remaining =
                (region.len as usize).saturating_sub(self.region_offset as usize);
            if region_remaining == 0 {
                self.region_idx += 1;
                self.region_offset = 0;
                continue;
            }

            let chunk = (src.len() - src_pos).min(region_remaining);
            let Some(addr) = region.addr.checked_add(u64::from(self.region_offset)) else {
                return Err(QueueViolation::DescriptorBufferWriteFailed {
                    addr: region.addr,
                    len: region.len,
                });
            };
            let gw = self.memory.gpa_write(addr, chunk).map_err(|_| {
                QueueViolation::DescriptorBufferWriteFailed {
                    addr: region.addr,
                    len: region.len,
                }
            })?;
            gw.write_from(&src[src_pos..src_pos + chunk]);
            src_pos += chunk;
            self.written = self.written.checked_add(chunk).ok_or(
                QueueViolation::DescriptorWritableLengthOverflow {
                    head_index: self.head_index,
                },
            )?;
            let chunk_u32 = u32::try_from(chunk).map_err(|_| {
                QueueViolation::DescriptorWritableLengthOverflow {
                    head_index: self.head_index,
                }
            })?;
            self.region_offset = self.region_offset.saturating_add(chunk_u32);
            if self.region_offset >= region.len {
                self.region_idx += 1;
                self.region_offset = 0;
            }
        }
        Ok(src_pos)
    }

    const fn finish_exact(self) -> Result<(), QueueViolation> {
        let expected = self.expected_bytes();
        if self.written != expected {
            return Err(QueueViolation::DescriptorResponseLengthMismatch {
                head_index: self.head_index,
                expected,
                actual: self.written,
            });
        }
        Ok(())
    }
}

fn write_response_bytes<M: GuestMemory>(
    memory: &M,
    writable: &DeferredWritableRegions,
    head_index: u16,
    written: WrittenBytes,
    response: &[u8],
) -> Result<(), QueueViolation> {
    if response.len() != written.get() as usize {
        return Err(QueueViolation::DescriptorResponseLengthMismatch {
            head_index,
            expected: written.get() as usize,
            actual: response.len(),
        });
    }
    let mut writer = DescriptorWriteGuard::new(memory, writable, head_index, written);
    let n = writer.write_from(response)?;
    if n != response.len() {
        return Err(QueueViolation::DescriptorResponseLengthMismatch {
            head_index,
            expected: response.len(),
            actual: n,
        });
    }
    writer.finish_exact()
}

fn validate_writable_descriptor_prefix<M: GuestMemory>(
    memory: &M,
    head_index: u16,
    descriptors: &[WritableDescriptor<'_, '_, M>],
    capacity: usize,
    total: usize,
) -> Result<(), QueueViolation> {
    if total > capacity {
        return Err(QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index,
            required: total,
            available: capacity,
        });
    }

    let mut remaining = total;
    for desc in descriptors {
        if remaining == 0 {
            break;
        }
        let len = (desc.len() as usize).min(remaining);
        if len != 0 {
            memory.validate_write_range(desc.addr(), len).map_err(|_| {
                QueueViolation::DescriptorBufferWriteFailed {
                    addr: desc.addr(),
                    len: desc.len(),
                }
            })?;
            remaining -= len;
        }
    }
    if remaining == 0 {
        Ok(())
    } else {
        Err(QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index,
            required: total,
            available: total - remaining,
        })
    }
}

/// A popped chain proven to contain only device-readable descriptors.
pub struct ReadableDescriptorChain<'brand, 'm, M: GuestMemory> {
    chain: PoppedDescriptorChain<'brand, 'm, M>,
    descriptors: Vec<ReadableDescriptor<'brand, 'm, M>>,
}

impl<'brand, 'm, M: GuestMemory> ReadableDescriptorChain<'brand, 'm, M> {
    /// The descriptor head index consumed from the available ring.
    #[must_use]
    pub const fn head_index(&self) -> u16 {
        self.chain.head_index()
    }

    /// Device-readable descriptor buffers.
    #[must_use]
    pub fn descriptors(&self) -> &[ReadableDescriptor<'brand, 'm, M>] {
        &self.descriptors
    }

    /// Total readable bytes supplied by the driver.
    #[must_use]
    pub fn readable_len(&self) -> usize {
        descriptor_total_len(&self.descriptors)
    }

    /// Require at least `required` device-readable bytes.
    pub fn require_readable_bytes(&self, required: usize) -> Result<(), QueueViolation> {
        require_readable_descriptor_bytes(self.head_index(), self.readable_len(), required)
    }

    /// Complete this read-only chain with a zero used-ring length.
    #[must_use]
    pub fn complete_zero(self) -> CompletedDescriptorChain<'brand> {
        CompletedDescriptorChain::new(self.chain.claim(), self.head_index(), WrittenBytes::zero())
    }
}

impl<'brand, 'm, M: GuestMemory> sealed::CompletableDescriptorChain<'brand, 'm, M>
    for ReadableDescriptorChain<'brand, 'm, M>
{
    fn head_index(&self) -> u16 {
        self.head_index()
    }

    fn writable_len_for_completion(&self) -> usize {
        0
    }
}

impl<'brand, 'm, M: GuestMemory> CompletableDescriptorChain<'brand, 'm, M>
    for ReadableDescriptorChain<'brand, 'm, M>
{
}

/// A popped chain proven to contain only device-writable descriptors.
pub struct WritableDescriptorChain<'brand, 'm, M: GuestMemory> {
    chain: PoppedDescriptorChain<'brand, 'm, M>,
    descriptors: Vec<WritableDescriptor<'brand, 'm, M>>,
}

impl<'brand, 'm, M: GuestMemory> WritableDescriptorChain<'brand, 'm, M> {
    /// The descriptor head index consumed from the available ring.
    #[must_use]
    pub const fn head_index(&self) -> u16 {
        self.chain.head_index()
    }

    /// Device-writable descriptor buffers.
    #[must_use]
    pub fn descriptors(&self) -> &[WritableDescriptor<'brand, 'm, M>] {
        &self.descriptors
    }

    /// Total writable bytes supplied by the driver.
    #[must_use]
    pub fn writable_len(&self) -> usize {
        descriptor_total_len(&self.descriptors)
    }

    /// Require at least `required` device-writable bytes.
    pub fn require_writable_bytes(&self, required: usize) -> Result<(), QueueViolation> {
        require_writable_descriptor_bytes(self.head_index(), self.writable_len(), required)
    }

    /// Check a used-ring byte count against this chain's writable capacity.
    pub fn written_bytes(&self, bytes: usize) -> Result<WrittenBytes, QueueViolation> {
        WrittenBytes::checked(self.head_index(), self.writable_len(), bytes)
    }

    fn validate_response_prefix(&self, bytes: usize) -> Result<WrittenBytes, QueueViolation> {
        let written = self.written_bytes(bytes)?;
        validate_writable_descriptor_prefix(
            self.chain.memory(),
            self.head_index(),
            &self.descriptors,
            self.writable_len(),
            bytes,
        )?;
        Ok(written)
    }

    pub(crate) fn complete_with_response(
        self,
        written: WrittenBytes,
        response: &[u8],
    ) -> Result<CompletedDescriptorChain<'brand>, QueueViolation> {
        let head_index = self.head_index();
        let writable_len = self.writable_len();
        let claim = self.chain.claim();
        let memory = self.chain.memory();
        WrittenBytes::checked(head_index, writable_len, written.get() as usize)?;
        let writable = self.into_deferred_writable_regions()?;
        writable.validate_write_prefix(memory, head_index, written.get() as usize)?;
        write_response_bytes(memory, &writable, head_index, written, response)?;
        Ok(CompletedDescriptorChain::new(claim, head_index, written))
    }

    /// Complete this writable chain with a zero used-ring length.
    #[must_use]
    pub fn complete_zero(self) -> CompletedDescriptorChain<'brand> {
        CompletedDescriptorChain::new(self.chain.claim(), self.head_index(), WrittenBytes::zero())
    }

    pub(crate) fn into_deferred_writable_regions(
        self,
    ) -> Result<DeferredWritableRegions, QueueViolation> {
        DeferredWritableRegions::from_descriptors(self.head_index(), self.descriptors)
    }
}

impl<'brand, 'm, M: GuestMemory> sealed::CompletableDescriptorChain<'brand, 'm, M>
    for WritableDescriptorChain<'brand, 'm, M>
{
    fn head_index(&self) -> u16 {
        self.head_index()
    }

    fn writable_len_for_completion(&self) -> usize {
        self.writable_len()
    }
}

impl<'brand, 'm, M: GuestMemory> CompletableDescriptorChain<'brand, 'm, M>
    for WritableDescriptorChain<'brand, 'm, M>
{
}

/// A popped split-chain with all readable descriptors before all writable descriptors.
pub struct SplitDescriptorChain<'brand, 'm, M: GuestMemory> {
    chain: PoppedDescriptorChain<'brand, 'm, M>,
    readable: Vec<ReadableDescriptor<'brand, 'm, M>>,
    writable: Vec<WritableDescriptor<'brand, 'm, M>>,
}

impl<'brand, 'm, M: GuestMemory> SplitDescriptorChain<'brand, 'm, M> {
    /// The descriptor head index consumed from the available ring.
    #[must_use]
    pub const fn head_index(&self) -> u16 {
        self.chain.head_index()
    }

    /// Device-readable descriptor buffers.
    #[must_use]
    pub fn readable(&self) -> &[ReadableDescriptor<'brand, 'm, M>] {
        &self.readable
    }

    /// Device-writable descriptor buffers.
    #[must_use]
    pub fn writable(&self) -> &[WritableDescriptor<'brand, 'm, M>] {
        &self.writable
    }

    /// Total readable bytes supplied by the driver.
    #[must_use]
    pub fn readable_len(&self) -> usize {
        descriptor_total_len(&self.readable)
    }

    /// Total writable bytes supplied by the driver.
    #[must_use]
    pub fn writable_len(&self) -> usize {
        descriptor_total_len(&self.writable)
    }

    /// Require at least `required` device-readable bytes.
    pub fn require_readable_bytes(&self, required: usize) -> Result<(), QueueViolation> {
        require_readable_descriptor_bytes(self.head_index(), self.readable_len(), required)
    }

    /// Require at least `required` device-writable bytes.
    pub fn require_writable_bytes(&self, required: usize) -> Result<(), QueueViolation> {
        require_writable_descriptor_bytes(self.head_index(), self.writable_len(), required)
    }

    /// Check a used-ring byte count against this chain's writable capacity.
    pub fn written_bytes(&self, bytes: usize) -> Result<WrittenBytes, QueueViolation> {
        WrittenBytes::checked(self.head_index(), self.writable_len(), bytes)
    }

    pub(crate) fn complete_with_response(
        self,
        written: WrittenBytes,
        response: &[u8],
    ) -> Result<CompletedDescriptorChain<'brand>, QueueViolation> {
        let head_index = self.head_index();
        let writable_len = self.writable_len();
        let claim = self.chain.claim();
        let memory = self.chain.memory();
        WrittenBytes::checked(head_index, writable_len, written.get() as usize)?;
        let writable = self.into_deferred_writable_regions()?;
        writable.validate_write_prefix(memory, head_index, written.get() as usize)?;
        write_response_bytes(memory, &writable, head_index, written, response)?;
        Ok(CompletedDescriptorChain::new(claim, head_index, written))
    }

    /// Complete this split chain with a zero used-ring length.
    #[must_use]
    pub fn complete_zero(self) -> CompletedDescriptorChain<'brand> {
        CompletedDescriptorChain::new(self.chain.claim(), self.head_index(), WrittenBytes::zero())
    }

    pub(crate) fn into_deferred_writable_regions(
        self,
    ) -> Result<DeferredWritableRegions, QueueViolation> {
        DeferredWritableRegions::from_descriptors(self.head_index(), self.writable)
    }
}

impl<'brand, 'm, M: GuestMemory> sealed::CompletableDescriptorChain<'brand, 'm, M>
    for SplitDescriptorChain<'brand, 'm, M>
{
    fn head_index(&self) -> u16 {
        self.head_index()
    }

    fn writable_len_for_completion(&self) -> usize {
        self.writable_len()
    }
}

impl<'brand, 'm, M: GuestMemory> CompletableDescriptorChain<'brand, 'm, M>
    for SplitDescriptorChain<'brand, 'm, M>
{
}

fn descriptor_total_len<M: GuestMemory, A>(
    descriptors: &[DescriptorBuffer<'_, '_, M, A>],
) -> usize {
    descriptors.iter().fold(0usize, |total, desc| {
        total.saturating_add(desc.len() as usize)
    })
}

const fn require_readable_descriptor_bytes(
    head_index: u16,
    available: usize,
    required: usize,
) -> Result<(), QueueViolation> {
    if available < required {
        Err(QueueViolation::DescriptorReadableCapacityTooSmall {
            head_index,
            required,
            available,
        })
    } else {
        Ok(())
    }
}

const fn require_writable_descriptor_bytes(
    head_index: u16,
    available: usize,
    required: usize,
) -> Result<(), QueueViolation> {
    if available < required {
        Err(QueueViolation::DescriptorWritableCapacityTooSmall {
            head_index,
            required,
            available,
        })
    } else {
        Ok(())
    }
}

/// Zero-copy view over a virtqueue's rings in guest memory.
///
/// `'q` is the lifetime of the queue-state mutable borrow (short — held only
/// for the duration of one queue-processing cycle). `'m` is the lifetime of
/// the guest-memory shared borrow (long — survives the cycle and any
/// typed descriptors collected from a chain). The split lets devices
/// (notably virtio-fs) hold scatter-gather slices across an `await` without
/// keeping the queue-state mutex locked.
pub struct QueueView<'brand, 'q, 'm, M: GuestMemory, State = ReadyQueue> {
    claim: QueueClaim,
    state: &'q mut QueueState,
    memory: &'m M,
    driver_features: u64,
    /// `last_used_idx` at `QueueView` creation — needed for `EVENT_IDX` notification check.
    batch_start_used_idx: u16,
    violation: Option<QueueViolation>,
    popped_chains: usize,
    pushed_entries: usize,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
    _state: PhantomData<State>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReservedUsedRingEntry {
    head_idx: u16,
    bytes_written: u32,
    used_idx_before: u16,
    used_idx_after: u16,
    entry_id_gpa: u64,
    entry_len_gpa: u64,
    used_idx_gpa: u64,
}

impl<'brand, 'q, 'm, M: GuestMemory> QueueView<'brand, 'q, 'm, M> {
    /// Build a queue view with a fresh brand and run `f` against it.
    ///
    /// The higher-ranked brand lifetime prevents synchronous completions
    /// produced from one view from being pushed into another view. Async
    /// devices must convert popped chains into deferred completion capabilities
    /// via [`QueuePopContext`](crate::QueuePopContext) before leaving the closure.
    #[cfg(any(test, kani, feature = "test-utils"))]
    #[doc(hidden)]
    pub fn with<R>(
        queue_idx: usize,
        state: &'q mut QueueState,
        memory: &'m M,
        driver_features: u64,
        f: impl for<'view> FnOnce(&mut QueueView<'view, 'q, 'm, M>) -> R,
    ) -> Result<R, QueueViolation> {
        let mut view =
            QueueView::<'_, 'q, 'm, M>::try_new(queue_idx, state, memory, driver_features)?;
        Ok(f(&mut view))
    }

    /// Create a new `QueueView` without returning transport-state errors.
    ///
    /// This is intentionally test/debug-only. Production queue processing must
    /// use [`Self::try_new`] so guest-controlled queue state can be rejected
    /// cleanly instead of relying on debug assertions.
    #[cfg(any(test, kani))]
    #[doc(hidden)]
    pub fn new(
        queue_idx: usize,
        state: &'q mut QueueState,
        memory: &'m M,
        driver_features: u64,
    ) -> Self {
        debug_assert!(state.ready != 0, "QueueView::new: queue is not ready");
        debug_assert!(
            state.size == 0 || state.size.is_power_of_two(),
            "QueueView::new: state.size={} is not zero or a power of two",
            state.size,
        );
        Self::from_checked_state(queue_idx, state, memory, driver_features)
    }

    /// Create a new `QueueView` after validating transport-level queue state.
    pub(crate) fn try_new(
        queue_idx: usize,
        state: &'q mut QueueState,
        memory: &'m M,
        driver_features: u64,
    ) -> Result<Self, QueueViolation> {
        if state.ready == 0 {
            return Err(QueueViolation::QueueNotReady);
        }
        if state.size != 0 && !state.size.is_power_of_two() {
            return Err(QueueViolation::InvalidQueueSize { size: state.size });
        }
        Ok(Self::from_checked_state(
            queue_idx,
            state,
            memory,
            driver_features,
        ))
    }

    fn from_checked_state(
        queue_idx: usize,
        state: &'q mut QueueState,
        memory: &'m M,
        driver_features: u64,
    ) -> Self {
        let batch_start = state.last_used_idx;
        let claim = QueueClaim::current(queue_idx, state);
        Self {
            claim,
            state,
            memory,
            driver_features,
            batch_start_used_idx: batch_start,
            violation: None,
            popped_chains: 0,
            pushed_entries: 0,
            _brand: PhantomData,
            _state: PhantomData,
        }
    }

    const fn record_violation<T>(
        &mut self,
        violation: QueueViolation,
    ) -> Result<T, QueueViolation> {
        self.violation = Some(violation);
        Err(violation)
    }

    fn checked_ring_addr_for_publish(
        &mut self,
        base: u64,
        offset: u64,
    ) -> Result<u64, QueueViolation> {
        base.checked_add(offset).map_or_else(
            || self.record_violation(QueueViolation::RingAddressOverflow { base, offset }),
            Ok,
        )
    }

    /// Pop the next available descriptor chain.
    ///
    /// Returns `None` if the queue is empty or a queue violation was recorded.
    /// Issues an `Acquire` fence after reading the avail ring index.
    ///
    /// # Pop/push pairing contract
    ///
    /// A successful `pop` consumes one head from the avail ring and returns a
    /// raw popped chain that must first be converted into a typed descriptor
    /// chain with [`PoppedDescriptorChain::into_readable`],
    /// [`PoppedDescriptorChain::into_writable`], or
    /// [`PoppedDescriptorChain::into_split`].
    ///
    /// Conversion walks and validates the descriptors. If conversion returns
    /// `Err(QueueViolation)`, the chain is malformed and cannot be passed to
    /// [`Self::push`]. The transport reset path must handle the violation
    /// instead of publishing a used entry for attacker-controlled descriptors.
    ///
    /// If conversion succeeds, the typed chain must be paired with one matching
    /// `push(chain, n)` on the same `QueueView`, including device-specific
    /// processing error paths. In that clean-walk case, `push(chain, 0)` is the
    /// usual way to release a buffer when the device could not produce a normal
    /// response.
    ///
    /// We intentionally do not implement `Drop` on `DescriptorChain` to
    /// auto-push, because (a) push can fail writing to guest memory and Drop
    /// can't return errors, and (b) the device always knows `bytes_written`,
    /// which a Drop impl cannot determine.
    pub fn pop(&mut self) -> Option<PoppedDescriptorChain<'brand, 'm, M>> {
        match self.pop_strict() {
            Ok(chain) => chain,
            Err(violation) => {
                log::warn!("virtqueue violation: {violation}");
                None
            }
        }
    }

    /// Pop the next available descriptor chain, returning protocol violations explicitly.
    ///
    /// Any returned `Err` is also recorded as the queue's sticky violation.
    pub fn pop_strict(
        &mut self,
    ) -> Result<Option<PoppedDescriptorChain<'brand, 'm, M>>, QueueViolation> {
        match self.pop_strict_inner() {
            Ok(chain) => Ok(chain),
            Err(violation) => self.record_violation(violation),
        }
    }

    fn pop_strict_inner(
        &mut self,
    ) -> Result<Option<PoppedDescriptorChain<'brand, 'm, M>>, QueueViolation> {
        if self.violation.is_some() {
            return Ok(None);
        }
        if self.state.size == 0 {
            return Ok(None);
        }

        // Read avail->idx from guest memory
        let avail_idx_gpa = ring_addr(self.state.avail_addr, AVAIL_IDX_OFFSET)?;
        let avail_idx = self.memory.read_le_u16(avail_idx_gpa).map_err(|_| {
            QueueViolation::AvailIdxReadFailed {
                addr: avail_idx_gpa,
            }
        })?;

        // Acquire fence: ensure we see descriptor writes that happened before
        // the guest incremented avail_idx.
        fence(Ordering::Acquire);

        // Nothing available?
        if avail_idx == self.state.last_avail_idx {
            return Ok(None);
        }

        // Avail index window check: a malicious guest could jump avail_idx
        // by more than queue_size.
        let window = avail_idx.wrapping_sub(self.state.last_avail_idx);
        if window > self.state.size {
            return Err(QueueViolation::AvailIndexJump {
                avail_idx,
                last_avail_idx: self.state.last_avail_idx,
                size: self.state.size,
            });
        }

        // Read the descriptor index from avail ring
        let ring_idx = self.state.last_avail_idx & (self.state.size - 1);
        let ring_entry_gpa = ring_addr(
            self.state.avail_addr,
            AVAIL_RING_OFFSET + u64::from(ring_idx) * 2,
        )?;
        let desc_idx = self.memory.read_le_u16(ring_entry_gpa).map_err(|_| {
            QueueViolation::AvailEntryReadFailed {
                addr: ring_entry_gpa,
            }
        })?;

        if desc_idx >= self.state.size {
            return Err(QueueViolation::DescriptorIndexOutOfRange {
                index: desc_idx,
                queue_size: self.state.size,
            });
        }

        let new_last_avail_idx = self.state.last_avail_idx.wrapping_add(1);

        // Write avail_event if EVENT_IDX is negotiated. This tells the guest
        // "don't kick me until avail_idx passes this value".
        if self.driver_features & VIRTIO_F_EVENT_IDX != 0 {
            let avail_event_gpa = ring_addr(
                self.state.used_addr,
                USED_RING_OFFSET + u64::from(self.state.size) * 8,
            )?;
            self.memory
                .write_le_u16(avail_event_gpa, new_last_avail_idx)
                .map_err(|_| QueueViolation::AvailEventWriteFailed {
                    addr: avail_event_gpa,
                })?;
        }

        self.state.last_avail_idx = new_last_avail_idx;
        self.popped_chains = self.popped_chains.saturating_add(1);
        let indirect_enabled = self.driver_features & VIRTIO_F_INDIRECT_DESC != 0;

        Ok(Some(PoppedDescriptorChain::new(
            self.claim,
            DescriptorChain::new(
                self.memory,
                desc_idx,
                self.state.desc_addr,
                self.state.size,
                indirect_enabled,
            ),
        )))
    }

    /// Push a completed descriptor chain to the used ring.
    #[allow(clippy::needless_pass_by_value)]
    pub fn push(
        &mut self,
        completion: CompletedDescriptorChain<'brand>,
    ) -> Result<(), QueueViolation> {
        self.validate_completion_claim(completion.claim)?;
        self.push_head(completion.head_index, completion.bytes_written.get())
            .map(|_| ())
    }

    /// Write a writable-only descriptor response and publish its used-ring entry.
    ///
    /// The queue validates the used-ring publish slot and descriptor write
    /// ranges before writing response bytes. Safe callers provide only an
    /// immutable response buffer, so they cannot write guest bytes and then
    /// abort before used-ring publication.
    pub fn push_writable_bytes(
        &mut self,
        chain: WritableDescriptorChain<'brand, 'm, M>,
        response: &[u8],
    ) -> Result<(), QueueViolation> {
        let written = chain.written_bytes(response.len())?;
        let reservation = self.reserve_next_used_entry(chain.head_index(), written.get())?;
        let completion = chain.complete_with_response(written, response)?;
        self.publish_reserved_completion(reservation, completion)
    }

    /// Validate a writable response completion before side-effecting backend I/O.
    ///
    /// The returned token proves that the exact response length fits the
    /// writable descriptors, that the descriptor write ranges are accessible,
    /// and that the next used-ring entry can be published. The token must be
    /// consumed by [`Self::push_prepared_writable_bytes`] to complete the
    /// popped descriptor chain.
    pub fn prepare_writable_bytes(
        &mut self,
        chain: WritableDescriptorChain<'brand, 'm, M>,
        response_len: usize,
    ) -> Result<PreparedWritableCompletion<'brand, 'm, M>, QueueViolation> {
        let written = chain.validate_response_prefix(response_len)?;
        let reservation = self.reserve_next_used_entry(chain.head_index(), written.get())?;
        Ok(PreparedWritableCompletion {
            chain,
            reservation,
            written,
        })
    }

    /// Publish a response through a token returned by [`Self::prepare_writable_bytes`].
    pub fn push_prepared_writable_bytes(
        &mut self,
        prepared: PreparedWritableCompletion<'brand, 'm, M>,
        response: &[u8],
    ) -> Result<(), QueueViolation> {
        let PreparedWritableCompletion {
            chain,
            reservation,
            written,
        } = prepared;
        let completion = chain.complete_with_response(written, response)?;
        self.publish_reserved_completion(reservation, completion)
    }

    /// Write a split descriptor response and publish its used-ring entry.
    ///
    /// The queue validates the used-ring publish slot and descriptor write
    /// ranges before writing response bytes. Safe callers provide only an
    /// immutable response buffer, so they cannot write guest bytes and then
    /// abort before used-ring publication.
    pub fn push_split_bytes(
        &mut self,
        chain: SplitDescriptorChain<'brand, 'm, M>,
        response: &[u8],
    ) -> Result<(), QueueViolation> {
        let written = chain.written_bytes(response.len())?;
        let reservation = self.reserve_next_used_entry(chain.head_index(), written.get())?;
        let completion = chain.complete_with_response(written, response)?;
        self.publish_reserved_completion(reservation, completion)
    }

    pub(crate) fn push_deferred_writable_bytes(
        &mut self,
        claim: QueueClaim,
        head_index: u16,
        writable: &DeferredWritableRegions,
        response: &[u8],
        written: WrittenBytes,
    ) -> Result<(), QueueViolation> {
        self.validate_completion_claim(claim)?;
        let reservation = self.reserve_next_used_entry(head_index, written.get())?;
        writable.validate_write_prefix(self.memory, head_index, response.len())?;
        write_response_bytes(self.memory, writable, head_index, written, response)?;
        let completion = CompletedDescriptorChain::new(claim, head_index, written);
        self.publish_reserved_completion(reservation, completion)
    }

    fn validate_completion_claim(&mut self, claim: QueueClaim) -> Result<(), QueueViolation> {
        if claim == self.claim && claim.matches(self.state) {
            return Ok(());
        }

        let violation = QueueViolation::UsedRingMixedQueueTokens {
            queue_idx: self.claim.queue_idx(),
        };
        self.record_violation(violation)
    }

    /// Push a raw descriptor head to the used ring.
    ///
    /// This is crate-private so centralized async completion code can publish a
    /// head carried by a queue token. External virtio devices must complete via
    /// [`Self::push`], which consumes a typed chain converted from
    /// [`Self::pop`].
    pub(crate) fn push_head(
        &mut self,
        head_idx: u16,
        bytes_written: u32,
    ) -> Result<u32, QueueViolation> {
        self.push_batch(std::iter::once((head_idx, bytes_written)))
    }

    /// Push completed descriptor chains to the used ring and publish `used.idx` once.
    ///
    /// Entries are written before one release fence and one `used.idx` update.
    /// This is equivalent to repeated [`Self::push`] calls from the guest's
    /// perspective, but avoids publishing partially visible batches.
    pub(crate) fn push_batch<I>(&mut self, entries: I) -> Result<u32, QueueViolation>
    where
        I: IntoIterator<Item = (u16, u32)>,
        I::IntoIter: Clone + ExactSizeIterator,
    {
        if let Some(violation) = self.violation {
            return Err(violation);
        }
        if self.state.size == 0 {
            return Ok(0);
        }

        let entries = entries.into_iter();
        let count = entries.len();
        if count == 0 {
            return Ok(0);
        }
        if count > self.state.size as usize {
            let violation = QueueViolation::UsedRingPublishTooLarge {
                count,
                queue_size: self.state.size,
            };
            return self.record_violation(violation);
        }

        for (head_idx, bytes_written) in entries.clone() {
            if head_idx >= self.state.size {
                let violation = QueueViolation::HeadIndexOutOfRange {
                    index: head_idx,
                    queue_size: self.state.size,
                };
                return self.record_violation(violation);
            }
            self.validate_next_used_entry_shape(head_idx, bytes_written)?;
        }

        for (offset, (head_idx, bytes_written)) in entries.enumerate() {
            let Ok(offset) = u16::try_from(offset) else {
                let violation = QueueViolation::UsedRingPublishTooLarge {
                    count,
                    queue_size: self.state.size,
                };
                return self.record_violation(violation);
            };
            let used_idx = self.state.last_used_idx.wrapping_add(offset) & (self.state.size - 1);
            let entry_offset = USED_RING_OFFSET + u64::from(used_idx) * 8;
            let entry_gpa =
                self.checked_ring_addr_for_publish(self.state.used_addr, entry_offset)?;
            let entry_len_gpa = self.checked_ring_addr_for_publish(entry_gpa, 4)?;

            // Write used ring entry: le32 id + le32 len.
            if self
                .memory
                .write_le_u32(entry_gpa, u32::from(head_idx))
                .is_err()
            {
                return self
                    .record_violation(QueueViolation::UsedEntryWriteFailed { addr: entry_gpa });
            }
            if self
                .memory
                .write_le_u32(entry_len_gpa, bytes_written)
                .is_err()
            {
                return self.record_violation(QueueViolation::UsedEntryWriteFailed {
                    addr: entry_len_gpa,
                });
            }
        }

        // Release fence: ensure the used ring entries are visible to the guest
        // before it observes the bumped used->idx.
        fence(Ordering::Release);

        // Publish the new used->idx to guest memory BEFORE advancing our own
        // cursor. If the write fails, the view is faulted and the transport
        // requires reset before accepting more queue work.
        let Ok(count_u16) = u16::try_from(count) else {
            let violation = QueueViolation::UsedRingPublishTooLarge {
                count,
                queue_size: self.state.size,
            };
            return self.record_violation(violation);
        };
        let new_used_idx = self.state.last_used_idx.wrapping_add(count_u16);
        let used_idx_gpa =
            self.checked_ring_addr_for_publish(self.state.used_addr, USED_IDX_OFFSET)?;
        if self
            .memory
            .write_le_u16(used_idx_gpa, new_used_idx)
            .is_err()
        {
            return self
                .record_violation(QueueViolation::UsedIdxWriteFailed { addr: used_idx_gpa });
        }
        self.state.last_used_idx = new_used_idx;
        self.pushed_entries = self.pushed_entries.saturating_add(usize::from(count_u16));

        // SeqCst fence to order this store before the subsequent used_event
        // load in needs_notification (virtio spec 2.7.10). Release alone is
        // not a store-load barrier on aarch64; without SeqCst a stale
        // used_event read can suppress a needed kick.
        fence(Ordering::SeqCst);
        Ok(u32::from(count_u16))
    }

    fn reserve_next_used_entry(
        &mut self,
        head_idx: u16,
        bytes_written: u32,
    ) -> Result<ReservedUsedRingEntry, QueueViolation> {
        if let Some(violation) = self.violation {
            return Err(violation);
        }
        if self.state.size == 0 {
            return self.record_violation(QueueViolation::QueueNotReady);
        }
        self.validate_next_used_entry_shape(head_idx, bytes_written)?;

        let used_idx = self.state.last_used_idx & (self.state.size - 1);
        let entry_offset = USED_RING_OFFSET + u64::from(used_idx) * 8;
        let entry_id_gpa =
            self.checked_ring_addr_for_publish(self.state.used_addr, entry_offset)?;
        let entry_len_gpa = self.checked_ring_addr_for_publish(entry_id_gpa, 4)?;
        let used_idx_gpa =
            self.checked_ring_addr_for_publish(self.state.used_addr, USED_IDX_OFFSET)?;
        self.validate_used_scalar_writes(entry_id_gpa, entry_len_gpa, used_idx_gpa)?;

        Ok(ReservedUsedRingEntry {
            head_idx,
            bytes_written,
            used_idx_before: self.state.last_used_idx,
            used_idx_after: self.state.last_used_idx.wrapping_add(1),
            entry_id_gpa,
            entry_len_gpa,
            used_idx_gpa,
        })
    }

    const fn validate_next_used_entry_shape(
        &mut self,
        head_idx: u16,
        _bytes_written: u32,
    ) -> Result<(), QueueViolation> {
        if self.state.size == 0 {
            return Ok(());
        }
        if head_idx >= self.state.size {
            return self.record_violation(QueueViolation::HeadIndexOutOfRange {
                index: head_idx,
                queue_size: self.state.size,
            });
        }
        Ok(())
    }

    fn validate_used_scalar_writes(
        &mut self,
        entry_id_gpa: u64,
        entry_len_gpa: u64,
        used_idx_gpa: u64,
    ) -> Result<(), QueueViolation> {
        if self.memory.validate_write_le_u32(entry_id_gpa).is_err() {
            return self
                .record_violation(QueueViolation::UsedEntryWriteFailed { addr: entry_id_gpa });
        }
        if self.memory.validate_write_le_u32(entry_len_gpa).is_err() {
            return self.record_violation(QueueViolation::UsedEntryWriteFailed {
                addr: entry_len_gpa,
            });
        }
        if self.memory.validate_write_le_u16(used_idx_gpa).is_err() {
            return self
                .record_violation(QueueViolation::UsedIdxWriteFailed { addr: used_idx_gpa });
        }
        Ok(())
    }

    #[allow(clippy::needless_pass_by_value)]
    fn publish_reserved_completion(
        &mut self,
        reservation: ReservedUsedRingEntry,
        completion: CompletedDescriptorChain<'brand>,
    ) -> Result<(), QueueViolation> {
        self.validate_completion_claim(completion.claim)?;
        if reservation.head_idx != completion.head_index
            || reservation.bytes_written != completion.bytes_written.get()
            || reservation.used_idx_before != self.state.last_used_idx
        {
            return self.record_violation(QueueViolation::UsedRingMixedQueueTokens {
                queue_idx: self.claim.queue_idx(),
            });
        }

        if self
            .memory
            .write_le_u32(reservation.entry_id_gpa, u32::from(reservation.head_idx))
            .is_err()
        {
            return self.record_violation(QueueViolation::UsedEntryWriteFailed {
                addr: reservation.entry_id_gpa,
            });
        }
        if self
            .memory
            .write_le_u32(reservation.entry_len_gpa, reservation.bytes_written)
            .is_err()
        {
            return self.record_violation(QueueViolation::UsedEntryWriteFailed {
                addr: reservation.entry_len_gpa,
            });
        }

        fence(Ordering::Release);

        if self
            .memory
            .write_le_u16(reservation.used_idx_gpa, reservation.used_idx_after)
            .is_err()
        {
            return self.record_violation(QueueViolation::UsedIdxWriteFailed {
                addr: reservation.used_idx_gpa,
            });
        }
        self.state.last_used_idx = reservation.used_idx_after;
        self.pushed_entries = self.pushed_entries.saturating_add(1);
        fence(Ordering::SeqCst);
        Ok(())
    }

    /// Validate that the next `count` used-ring entries and `used.idx` are writable.
    ///
    /// Async devices use this before committing response bytes into guest
    /// descriptor buffers, so an invalid used ring faults the queue before any
    /// delayed response data becomes visible without a matching used entry.
    pub fn validate_used_ring_writes(&self, count: usize) -> Result<(), QueueViolation> {
        if let Some(violation) = self.violation {
            return Err(violation);
        }
        if count == 0 || self.state.size == 0 {
            return Ok(());
        }
        if count > self.state.size as usize {
            return Err(QueueViolation::UsedRingPublishTooLarge {
                count,
                queue_size: self.state.size,
            });
        }

        let used_idx_gpa = ring_addr(self.state.used_addr, USED_IDX_OFFSET)?;
        self.memory
            .validate_write_le_u16(used_idx_gpa)
            .map_err(|_| QueueViolation::UsedIdxWriteFailed { addr: used_idx_gpa })?;

        for offset in 0..count {
            let offset =
                u16::try_from(offset).map_err(|_| QueueViolation::UsedRingPublishTooLarge {
                    count,
                    queue_size: self.state.size,
                })?;
            let used_idx = self.state.last_used_idx.wrapping_add(offset) & (self.state.size - 1);
            let entry_gpa = ring_addr(
                self.state.used_addr,
                USED_RING_OFFSET + u64::from(used_idx) * 8,
            )?;
            let entry_len_gpa = ring_addr(entry_gpa, 4)?;
            self.memory
                .validate_write_le_u32(entry_gpa)
                .map_err(|_| QueueViolation::UsedEntryWriteFailed { addr: entry_gpa })?;
            self.memory
                .validate_write_le_u32(entry_len_gpa)
                .map_err(|_| QueueViolation::UsedEntryWriteFailed {
                    addr: entry_len_gpa,
                })?;
        }

        Ok(())
    }

    /// Validate that one completion can be published and record the fault on
    /// this view if the used ring is not writable.
    pub fn validate_next_completion(&mut self) -> Result<(), QueueViolation> {
        if let Err(violation) = self.validate_used_ring_writes(1) {
            self.violation = Some(violation);
            return Err(violation);
        }
        Ok(())
    }

    /// Check if the guest wants notification (should we inject an IRQ?).
    ///
    /// Supports both legacy flags and `EVENT_IDX` notification suppression.
    pub fn needs_notification(&self) -> Result<bool, QueueViolation> {
        if self.state.size == 0 {
            return Ok(false);
        }

        if self.driver_features & VIRTIO_F_EVENT_IDX != 0 {
            // EVENT_IDX path: read used_event from avail ring
            let used_event_gpa = ring_addr(
                self.state.avail_addr,
                AVAIL_RING_OFFSET + u64::from(self.state.size) * 2,
            )?;
            let used_event = self.memory.read_le_u16(used_event_gpa).map_err(|_| {
                QueueViolation::UsedEventReadFailed {
                    addr: used_event_gpa,
                }
            })?;

            // vring_need_event: check if used_event falls in [old, new)
            Ok(vring_need_event(
                used_event,
                self.state.last_used_idx,
                self.batch_start_used_idx,
            ))
        } else {
            // Legacy flags path: check VRING_AVAIL_F_NO_INTERRUPT
            let flags_gpa = ring_addr(self.state.avail_addr, AVAIL_FLAGS_OFFSET)?;
            let flags: u16 = self
                .memory
                .read_le_u16(flags_gpa)
                .map_err(|_| QueueViolation::AvailFlagsReadFailed { addr: flags_gpa })?;
            Ok(flags & VRING_AVAIL_F_NO_INTERRUPT == 0)
        }
    }

    /// Get the underlying queue state.
    pub const fn state(&self) -> &QueueState {
        self.state
    }

    /// Validate the sync-device pop/push contract for this queue run.
    ///
    /// Async users intentionally pop in one critical section and publish in a
    /// later one through deferred completion capabilities; they must not call
    /// this. `QueueRunner` calls it only for synchronous
    /// `VirtioDevice::process_queue` runs, where a cleanly popped descriptor
    /// must be returned to the guest before the device reports success.
    pub const fn validate_sync_completion_balance(&self) -> Result<(), QueueViolation> {
        if self.popped_chains == self.pushed_entries {
            Ok(())
        } else {
            Err(QueueViolation::UncompletedDescriptorChains {
                popped: self.popped_chains,
                pushed: self.pushed_entries,
            })
        }
    }

    /// Validate the async pop/completion-capability contract for this queue run.
    ///
    /// Async callers pop descriptor chains in one critical section and publish
    /// completions later. Every successfully popped chain must therefore be
    /// converted into exactly one deferred completion capability before the
    /// pop closure returns.
    pub(crate) const fn validate_async_completion_balance(
        &self,
        issued_completions: usize,
    ) -> Result<(), QueueViolation> {
        if self.popped_chains == issued_completions {
            Ok(())
        } else {
            Err(QueueViolation::UncompletedDescriptorChains {
                popped: self.popped_chains,
                pushed: issued_completions,
            })
        }
    }

    /// Return the first queue violation observed by this view.
    #[must_use]
    pub const fn violation(&self) -> Option<QueueViolation> {
        self.violation
    }

    /// Take the first queue violation observed by this view.
    pub const fn take_violation(&mut self) -> Option<QueueViolation> {
        self.violation.take()
    }
}

// =============================================================================
// Queue layout validator
// =============================================================================

/// Validate a per-queue ring layout against the guest memory map.
///
/// Per virtio 1.2 §2.7.1, the split-virtqueue rings have these extents:
/// - descriptor table: `16 * queue_size` bytes
/// - available ring: `4 + 2 * queue_size` bytes, plus `used_event` with `EVENT_IDX`
/// - used ring: `4 + 8 * queue_size` bytes, plus `avail_event` with `EVENT_IDX`
///
/// Callers run this on the `QueueReady=0 → 1` transition. Per virtio 1.2
/// §4.2.2.2, the driver MUST NOT change `QueueNum` or any queue address
/// register while `QueueReady` is set, so once this check passes, every
/// per-access GPA computation in `pop` / `push` / `needs_notification` is
/// guaranteed not to wrap `u64`.
pub fn validate_queue_layout<M: GuestMemory>(
    state: &QueueState,
    memory: &M,
    driver_features: u64,
) -> Result<(), QueueViolation> {
    if state.size == 0 || !state.size.is_power_of_two() {
        return Err(QueueViolation::InvalidQueueSize { size: state.size });
    }
    let qsize = u64::from(state.size);
    // Max queue_size is 32768 (15 bits, virtio 1.2 §2.7), so all of these
    // are well below `usize::MAX` even on 32-bit hosts.
    let event_idx = driver_features & VIRTIO_F_EVENT_IDX != 0;
    let desc_len = 16 * qsize;
    let avail_len = 4 + 2 * qsize + u64::from(event_idx) * 2;
    let used_len = 4 + 8 * qsize + u64::from(event_idx) * 2;

    let check =
        |region: &'static str,
         addr: u64,
         len: u64,
         align: u64,
         writable: bool|
         -> Result<(), QueueViolation> {
            if !addr.is_multiple_of(align) {
                return Err(QueueViolation::RingAddressUnaligned {
                    region,
                    addr,
                    align,
                });
            }
            let len_usize = usize::try_from(len)
                .map_err(|_| QueueViolation::RingAddressInvalid { region, addr, len })?;
            let result = if writable {
                memory.validate_write_range(addr, len_usize)
            } else {
                memory.validate_read_range(addr, len_usize)
            };
            result.map_err(|_| QueueViolation::RingAddressInvalid { region, addr, len })
        };

    check("desc", state.desc_addr, desc_len, 16, false)?;
    check("avail", state.avail_addr, avail_len, 2, false)?;
    check("used", state.used_addr, used_len, 4, true)?;
    Ok(())
}

// =============================================================================
// EVENT_IDX helper
// =============================================================================

/// Check if an event index falls within a wrapping window `[old, new)`.
///
/// From the virtio spec: returns true if notification is required.
/// Uses wrapping u16 arithmetic to handle batched completions and wrap-around.
#[inline]
const fn vring_need_event(event_idx: u16, new_idx: u16, old_idx: u16) -> bool {
    new_idx.wrapping_sub(event_idx).wrapping_sub(1) < new_idx.wrapping_sub(old_idx)
}

#[cfg(test)]
mod vring_tests {
    use super::*;

    #[test]
    fn test_vring_need_event_basic() {
        // event_idx=0, new=1, old=0 → 1 is in [0,1) → need event
        assert!(vring_need_event(0, 1, 0));
    }

    #[test]
    fn test_vring_need_event_no_progress() {
        // new == old → no progress → no event
        assert!(!vring_need_event(0, 0, 0));
        assert!(!vring_need_event(5, 5, 5));
    }

    #[test]
    fn test_vring_need_event_behind() {
        // event_idx=5, new=3, old=2 → 5 not in [2,3) → no event
        assert!(!vring_need_event(5, 3, 2));
    }

    #[test]
    fn test_vring_need_event_wrapping() {
        // Wrap-around: old=0xFFFE, new=0x0001, event_idx=0xFFFF
        // Window is [0xFFFE, 0x0001) which contains 0xFFFF and 0x0000
        assert!(vring_need_event(0xFFFF, 0x0001, 0xFFFE));
        assert!(vring_need_event(0x0000, 0x0001, 0xFFFE));
    }

    #[test]
    fn test_vring_need_event_batch() {
        // Batched completions: old=0, new=5, event_idx=3
        // [0,5) contains 3 → need event
        assert!(vring_need_event(3, 5, 0));
        // event_idx=5 → not in [0,5) → no event
        assert!(!vring_need_event(5, 5, 0));
    }

    #[test]
    fn test_uncompleted_descriptor_counts_do_not_wrap_at_u16() {
        let violation = QueueViolation::UncompletedDescriptorChains {
            popped: usize::from(u16::MAX) + 1,
            pushed: 0,
        };

        assert!(violation.to_string().contains("65536 popped"));
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        /// No progress (new == old) never triggers an event, regardless of event_idx.
        #[test]
        fn no_progress_means_no_event(event_idx: u16, idx: u16) {
            prop_assert!(!vring_need_event(event_idx, idx, idx));
        }

        /// If old < new (no wrap) and event_idx is in [old, new), the event fires.
        /// We test this by constructing the event_idx to be inside the window.
        #[test]
        fn event_in_window_fires(
            old in any::<u16>(),
            // Window size 1..=256 to keep it tractable.
            window in 1u16..=256,
            // Offset into the window for event_idx.
            offset in 0u16..256,
        ) {
            let new = old.wrapping_add(window);
            let event_idx = old.wrapping_add(offset % window);
            prop_assert!(vring_need_event(event_idx, new, old));
        }

        /// If event_idx == new (just past the window), no event fires.
        #[test]
        fn event_at_new_does_not_fire(old: u16, window in 1u16..=1000) {
            let new = old.wrapping_add(window);
            // event_idx == new is outside [old, new)
            prop_assert!(!vring_need_event(new, new, old));
        }

        /// The function never panics for any u16 inputs.
        #[test]
        fn never_panics(event_idx: u16, new_idx: u16, old_idx: u16) {
            let _ = vring_need_event(event_idx, new_idx, old_idx);
        }
    }
}

// =============================================================================
// Kani formal verification
//
// These harnesses exercise the REAL queue operations with symbolic guest
// memory, proving safety properties for ALL possible guest inputs.
// Follows the Firecracker approach: concrete memory backing, symbolic
// cursors and ring contents, real function calls.
// =============================================================================

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use crate::QueueState;
    use amla_core::VmmError;
    use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead, GuestWrite};

    // =====================================================================
    // Kani GuestMemory: fixed-size byte array filled with kani::any()
    // =====================================================================

    /// Guest memory backed by a fixed byte array. Kani explores all
    /// possible contents, simulating an adversarial guest.
    struct KaniMem {
        buf: [u8; Self::SIZE],
    }

    impl KaniMem {
        /// 256 bytes — covers descriptor table (4×16=64B) + avail ring (14B)
        /// + used ring (38B) for Q_SIZE=4, while keeping Kani tractable
        /// (< 5 min per harness). 4KB causes 24M+ program steps.
        const SIZE: usize = 256;

        fn new_symbolic() -> Self {
            Self { buf: kani::any() }
        }
    }

    #[derive(Clone)]
    struct KaniSlice(Vec<u8>);
    #[derive(Clone)]
    struct KaniSliceMut(usize);

    impl GuestRead for KaniSlice {
        fn read_to(&self, buf: &mut [u8]) {
            buf.copy_from_slice(&self.0);
        }
        fn to_vec(&self) -> Vec<u8> {
            self.0.clone()
        }
        fn read_byte(&self, offset: usize) -> u8 {
            self.0[offset]
        }
        fn len(&self) -> usize {
            self.0.len()
        }
        fn offset(&self, off: usize, len: usize) -> Self {
            Self(self.0[off..off + len].to_vec())
        }
        fn extend_vec(&self, vec: &mut Vec<u8>) {
            vec.extend_from_slice(&self.0);
        }
    }

    impl GuestWrite for KaniSliceMut {
        fn write_from(&self, _data: &[u8]) {}
        fn write_at(&self, _off: usize, _data: &[u8]) {}
        fn write_byte(&self, _offset: usize, _val: u8) {}
        fn fill(&self, _val: u8) {}
        fn len(&self) -> usize {
            self.0
        }
        fn offset(self, _off: usize, len: usize) -> Self {
            Self(len)
        }
    }

    impl KaniMem {
        fn range(&self, addr: u64, len: usize) -> Result<std::ops::Range<usize>, VmmError> {
            let start =
                usize::try_from(addr).map_err(|_| VmmError::AddressOverflow { addr, size: len })?;
            let end = start
                .checked_add(len)
                .ok_or(VmmError::AddressOverflow { addr, size: len })?;
            if end > self.buf.len() {
                return Err(VmmError::MemoryOutOfBounds {
                    addr,
                    size: len,
                    memory_size: self.buf.len(),
                });
            }
            Ok(start..end)
        }
    }

    impl GuestMemory for KaniMem {
        type Slice<'m>
            = KaniSlice
        where
            Self: 'm;
        type SliceMut<'m>
            = KaniSliceMut
        where
            Self: 'm;

        fn gpa_read(&self, addr: u64, len: usize) -> Result<KaniSlice, VmmError> {
            let r = self.range(addr, len)?;
            Ok(KaniSlice(self.buf[r].to_vec()))
        }

        fn gpa_write(&self, _addr: u64, len: usize) -> Result<KaniSliceMut, VmmError> {
            Ok(KaniSliceMut(len))
        }

        fn read_obj<T: bytemuck::Pod>(&self, addr: u64) -> Result<T, VmmError> {
            let r = self.range(addr, core::mem::size_of::<T>())?;
            Ok(bytemuck::pod_read_unaligned(&self.buf[r]))
        }

        fn write_obj<T: bytemuck::NoUninit>(&self, _addr: u64, _val: &T) -> Result<(), VmmError> {
            Ok(())
        }

        fn read_le_u16(&self, addr: u64) -> Result<u16, VmmError> {
            let r = self.range(addr, 2)?;
            Ok(u16::from_le_bytes([
                self.buf[r.start],
                self.buf[r.start + 1],
            ]))
        }

        fn read_le_u32(&self, addr: u64) -> Result<u32, VmmError> {
            let r = self.range(addr, 4)?;
            Ok(u32::from_le_bytes([
                self.buf[r.start],
                self.buf[r.start + 1],
                self.buf[r.start + 2],
                self.buf[r.start + 3],
            ]))
        }

        fn read_le_u64(&self, addr: u64) -> Result<u64, VmmError> {
            let r = self.range(addr, 8)?;
            Ok(u64::from_le_bytes([
                self.buf[r.start],
                self.buf[r.start + 1],
                self.buf[r.start + 2],
                self.buf[r.start + 3],
                self.buf[r.start + 4],
                self.buf[r.start + 5],
                self.buf[r.start + 6],
                self.buf[r.start + 7],
            ]))
        }

        fn write_le_u16(&self, _addr: u64, _val: u16) -> Result<(), VmmError> {
            Ok(())
        }

        fn write_le_u32(&self, _addr: u64, _val: u32) -> Result<(), VmmError> {
            Ok(())
        }

        fn write_le_u64(&self, _addr: u64, _val: u64) -> Result<(), VmmError> {
            Ok(())
        }

        fn validate_read_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
            self.range(addr, len).map(drop)
        }

        fn validate_write_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
            self.range(addr, len).map(drop)
        }
    }

    // Queue size for proofs — 4 entries keeps Kani tractable while
    // exercising all ring arithmetic paths (masking, wrap-around).
    const Q_SIZE: u16 = 4;

    // Fixed memory layout within the 256-byte symbolic buffer:
    //   0x000..0x03F: descriptor table (4 entries × 16 bytes = 64 bytes)
    //   0x040..0x04F: avail ring (flags + idx + ring[4] + used_event = 14 bytes)
    //   0x050..0x07F: used ring (flags + idx + ring[4]×8 + avail_event = 38 bytes)
    //   0x080..0x0FF: data buffers
    const DESC_ADDR: u64 = 0x000;
    const AVAIL_ADDR: u64 = 0x040;
    const USED_ADDR: u64 = 0x050;

    fn symbolic_queue_state() -> QueueState {
        QueueState {
            size: Q_SIZE,
            ready: 1,
            pad0: 0,
            desc_addr: DESC_ADDR,
            avail_addr: AVAIL_ADDR,
            used_addr: USED_ADDR,
            last_avail_idx: kani::any(),
            last_used_idx: kani::any(),
            generation: 0,
        }
    }

    // =====================================================================
    // Proof 1: vring_need_event matches the virtio spec for ALL u16 inputs.
    //
    // The clever subtraction trick must produce the same result as the
    // straightforward "is event_idx in [old, new)?" definition.
    // =====================================================================

    /// Spec reference: event_idx ∈ [old, new) in wrapping u16 space.
    fn spec_need_event(event_idx: u16, new_idx: u16, old_idx: u16) -> bool {
        let window = new_idx.wrapping_sub(old_idx);
        if window == 0 {
            return false;
        }
        event_idx.wrapping_sub(old_idx) < window
    }

    #[kani::proof]
    fn proof_vring_need_event_matches_spec() {
        let event_idx: u16 = kani::any();
        let new_idx: u16 = kani::any();
        let old_idx: u16 = kani::any();

        assert_eq!(
            vring_need_event(event_idx, new_idx, old_idx),
            spec_need_event(event_idx, new_idx, old_idx),
        );
    }

    // =====================================================================
    // Proof 2: QueueView::pop() never panics and never accesses OOB memory.
    //
    // With fully symbolic guest memory (256B of kani::any()), symbolic
    // last_avail_idx, and a fixed queue layout, we prove pop() is safe
    // for ALL possible guest states.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_pop_never_panics() {
        let mem = KaniMem::new_symbolic();
        let mut state = symbolic_queue_state();
        let features: u64 = kani::any();

        let mut qv = QueueView::new(0, &mut state, &mem, features);

        // Call real pop() — Kani verifies no panic, no OOB access.
        // The return value is Option<PoppedDescriptorChain>, which may be
        // None (empty queue, invalid descriptor, OOB, etc.).
        let _chain = qv.pop();
    }

    // =====================================================================
    // Proof 3: QueueView::push_head() never panics for any valid head_idx.
    //
    // Async publication uses raw heads internally after token validation.
    // We prove that low-level used-ring publication never panics for any queue state.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_push_never_panics() {
        let mem = KaniMem::new_symbolic();
        let mut state = symbolic_queue_state();

        let mut qv = QueueView::new(0, &mut state, &mem, 0);

        let head_idx: u16 = kani::any();
        let bytes_written: u32 = kani::any();

        // push may return Ok or Err (if a scalar ring write fails), but must not panic
        let _result = qv.push_head(head_idx, bytes_written);
    }

    // =====================================================================
    // Proof 4: needs_notification() never panics for any guest state.
    //
    // This is the function Firecracker proved — it reads used_event
    // from guest-controlled memory and computes vring_need_event().
    // We prove it never panics for ANY guest memory contents and
    // ANY combination of feature flags (legacy vs EVENT_IDX).
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_needs_notification_never_panics() {
        let mem = KaniMem::new_symbolic();
        let mut state = symbolic_queue_state();
        let features: u64 = kani::any();

        let qv = QueueView::new(0, &mut state, &mem, features);

        // Must not panic regardless of guest memory contents or features
        let _notify = qv.needs_notification();
    }

    // =====================================================================
    // Proof 5: pop() followed by push() maintains ring invariants.
    //
    // The used ring index must advance by exactly 1 after push().
    // This is the core correctness property for the completion path.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_pop_push_advances_used_idx() {
        let mem = KaniMem::new_symbolic();
        let mut state = symbolic_queue_state();

        let saved_used_idx = state.last_used_idx;

        let mut qv = QueueView::new(0, &mut state, &mem, 0);

        if let Some(chain) = qv.pop() {
            let head = chain.head_index();
            if qv.push_head(head, 0).is_ok() {
                // Used index must have advanced by exactly 1
                assert_eq!(qv.state().last_used_idx, saved_used_idx.wrapping_add(1));
            }
        }
    }

    // =====================================================================
    // Proof 6: pop() advances avail cursor by exactly 1.
    //
    // Each successful pop() must consume exactly one avail ring entry.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_pop_advances_avail_idx() {
        let mem = KaniMem::new_symbolic();
        let mut state = symbolic_queue_state();

        let saved_avail_idx = state.last_avail_idx;

        let mut qv = QueueView::new(0, &mut state, &mem, 0);

        if qv.pop().is_some() {
            assert_eq!(qv.state().last_avail_idx, saved_avail_idx.wrapping_add(1));
        } else {
            // pop() returned None — avail cursor must not have moved
            assert_eq!(qv.state().last_avail_idx, saved_avail_idx);
        }
    }

    // =====================================================================
    // Proof 7: Queue addresses within buffer never escape allocation.
    //
    // The guest sets desc_addr, avail_addr, used_addr to arbitrary GPAs.
    // We prove that all scalar ring metadata calls from pop()/push() are
    // either within our 256B buffer or return Err (never OOB access).
    // This is the Firecracker MMIO-overlap class of bug — a guest placing
    // queue rings at addresses that overlap device MMIO or other structures.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_adversarial_queue_addresses_safe() {
        let mem = KaniMem::new_symbolic();

        // Guest controls ALL queue addresses — they can point anywhere
        let mut state = QueueState {
            size: Q_SIZE,
            ready: 1,
            pad0: 0,
            desc_addr: kani::any(),
            avail_addr: kani::any(),
            used_addr: kani::any(),
            last_avail_idx: kani::any(),
            last_used_idx: kani::any(),
            generation: 0,
        };

        // Constrain addresses so Kani can explore both in-bounds
        // and OOB paths tractably (buffer is 256 bytes)
        kani::assume(state.desc_addr <= 256);
        kani::assume(state.avail_addr <= 256);
        kani::assume(state.used_addr <= 256);

        let features: u64 = kani::any();
        let mut qv = QueueView::new(0, &mut state, &mem, features);

        // These must not panic — OOB accesses return None/Err
        if let Some(chain) = qv.pop() {
            let head = chain.head_index();
            let _ = qv.push_head(head, 0);
        }
        let _notify = qv.needs_notification();
    }

    // =====================================================================
    // Proof 8: Descriptor chain walk never panics with symbolic memory.
    //
    // DescriptorChain iterates lazily, reading one descriptor per next().
    // With fully symbolic guest memory, we prove the walk never panics
    // and always terminates.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(4)] // Q_SIZE_SMALL(2) + 1 for loop exit + 1 margin
    fn proof_descriptor_chain_walk_safe() {
        let mem = KaniMem::new_symbolic();
        let head_idx: u16 = kani::any();
        const Q_SIZE_SMALL: u16 = 2;
        kani::assume(head_idx < Q_SIZE_SMALL);

        let chain =
            crate::descriptor::DescriptorChain::new(&mem, head_idx, DESC_ADDR, Q_SIZE_SMALL, false);

        for _slice in chain {}
    }
}
