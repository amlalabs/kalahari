// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Descriptor chain iterator with lazy single-read walk.
//!
//! [`DescriptorChain`] walks the guest descriptor table lazily, reading each
//! descriptor exactly once at `next()` time. No heap allocation for direct
//! chains. Indirect tables are heap-copied on encounter since they live at
//! arbitrary guest GPAs.
//!
//! Each descriptor field is read exactly once with typed little-endian scalar
//! loads; no field re-reads. The security boundary is
//! `validate_read_range()` / `validate_write_range()`, which prevents buffer
//! addresses from escaping guest RAM and records descriptor direction in the
//! Rust type before device code can perform I/O.

use crate::{
    Descriptor, QueueViolation, VIRTQ_DESC_F_INDIRECT, VIRTQ_DESC_F_NEXT, VIRTQ_DESC_F_WRITE,
};
use amla_core::VmmError;
use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead};
use std::marker::PhantomData;
use std::num::NonZeroU32;

/// Maximum number of entries in an indirect descriptor table. Matches the
/// Linux guest kernel's `MAX_INDIRECT_ENTRIES = 128`. Without this cap a
/// single guest kick could force a 1 MiB host allocation (65535 × 16 B).
const MAX_INDIRECT_TABLE_LEN: u16 = 128;

// =============================================================================
// ReadCap — mandatory structural cap on guest-derived reads
// =============================================================================

/// Maximum bytes a single `guest_read` may materialize from guest memory.
///
/// Every path that builds a volatile view from a [`ReadableDescriptor`] takes a
/// `ReadCap` — there is no uncapped variant. The cap is enforced inside
/// `ReadableDescriptor::guest_read[_at]` by clamping `min(desc.len, cap)`, so
/// no device can forget it (and no guest-controlled `slice.len` can drive
/// a 4 GiB allocation).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReadCap(NonZeroU32);

impl ReadCap {
    /// Construct a read cap. Zero is rejected at the type level — callers
    /// that want "nothing to read" should not call `guest_read` at all.
    #[must_use]
    pub const fn new(bytes: NonZeroU32) -> Self {
        Self(bytes)
    }

    /// The cap in bytes as `u32` (always ≥ 1).
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0.get()
    }
}

// =============================================================================
// Typed descriptor buffers — volatile views into guest memory
// =============================================================================

/// Marker for a descriptor the device may read from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceReadable;

/// Marker for a descriptor the device may write to.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceWritable;

/// A typed view into a guest memory buffer described by one virtio descriptor.
///
/// The `addr` and `len` are snapshotted from little-endian scalar loads.
/// Fields are intentionally private. Direction is carried by the `Access`
/// type parameter: readable descriptors expose only read APIs, and writable
/// descriptors expose only write APIs. There is no method that takes a runtime
/// `writable` boolean and then allows both directions.
///
/// The `'m` lifetime is the guest-memory borrow. The `'brand` lifetime is the
/// fresh queue-view brand, so descriptors cannot be returned from the
/// queue-processing closure or [`QueueRunner::pop_view`](crate::QueueRunner::pop_view).
/// Async devices that need delayed completion must convert writable buffers
/// into an opaque deferred completion token while still inside the pop closure.
///
/// [`QueueView`]: crate::QueueView
pub struct DescriptorBuffer<'brand, 'm, M: GuestMemory, Access> {
    pub(crate) memory: &'m M,
    pub(crate) addr: u64,
    pub(crate) len: u32,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
    _access: PhantomData<Access>,
}

impl<M: GuestMemory, Access> Clone for DescriptorBuffer<'_, '_, M, Access> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<M: GuestMemory, Access> Copy for DescriptorBuffer<'_, '_, M, Access> {}

/// A descriptor the device may read from.
pub type ReadableDescriptor<'brand, 'm, M> = DescriptorBuffer<'brand, 'm, M, DeviceReadable>;

/// A descriptor the device may write to.
pub type WritableDescriptor<'brand, 'm, M> = DescriptorBuffer<'brand, 'm, M, DeviceWritable>;

impl<M: GuestMemory, Access> std::fmt::Debug for DescriptorBuffer<'_, '_, M, Access> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DescriptorBuffer")
            .field("addr", &format_args!("{:#x}", self.addr))
            .field("len", &self.len)
            .finish_non_exhaustive()
    }
}

impl<'m, M: GuestMemory, Access> DescriptorBuffer<'_, 'm, M, Access> {
    pub(crate) const fn new(memory: &'m M, addr: u64, len: u32) -> Self {
        Self {
            memory,
            addr,
            len,
            _brand: PhantomData,
            _access: PhantomData,
        }
    }

    /// Guest physical address captured from this descriptor.
    #[must_use]
    pub(crate) const fn addr(&self) -> u64 {
        self.addr
    }

    /// Length of this descriptor's buffer in bytes (guest-controlled).
    #[must_use]
    pub const fn len(&self) -> u32 {
        self.len
    }

    /// `true` if the buffer has zero length.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn clamped_access(&self, offset: u32, cap: u32) -> Result<(u64, u32), VmmError> {
        let len = clamp_len(self.len, offset, cap);
        if len == 0 {
            return Ok((self.addr, 0));
        }
        let addr = self
            .addr
            .checked_add(u64::from(offset))
            .ok_or(VmmError::AddressOverflow {
                addr: self.addr,
                size: len as usize,
            })?;
        Ok((addr, len))
    }
}

impl<M: GuestMemory> ReadableDescriptor<'_, '_, M> {
    /// Get a volatile read view of this descriptor's buffer, clamped at
    /// `min(desc.len, cap.get())` bytes.
    pub fn guest_read(&self, cap: ReadCap) -> Result<M::Slice<'_>, VmmError> {
        self.guest_read_at(0, cap)
    }

    /// Like `guest_read` but starts at `offset` into the descriptor buffer.
    /// Returns an empty slice if `offset >= desc.len`.
    pub fn guest_read_at(&self, offset: u32, cap: ReadCap) -> Result<M::Slice<'_>, VmmError> {
        let (addr, len) = self.clamped_access(offset, cap.get())?;
        self.memory.gpa_read(addr, len as usize)
    }

    /// Like [`Self::guest_read_at`] but reports a queue violation on access
    /// failure, suitable for device `process_queue` implementations.
    pub fn guest_read_at_checked(
        &self,
        offset: u32,
        cap: ReadCap,
    ) -> Result<M::Slice<'_>, QueueViolation> {
        self.guest_read_at(offset, cap)
            .map_err(|_| self.descriptor_buffer_read_failed())
    }

    /// Read up to `dst.len()` bytes from the descriptor buffer starting at
    /// `offset`. Returns the number of bytes actually read (bounded by
    /// `min(dst.len(), desc.len - offset)`). Non-allocating — the cap is the
    /// caller's stack- or heap-owned buffer size.
    pub fn read_into(&self, offset: u32, dst: &mut [u8]) -> Result<usize, VmmError> {
        let avail = self.len.saturating_sub(offset) as usize;
        let n = avail.min(dst.len());
        if n == 0 {
            return Ok(0);
        }
        let addr = self
            .addr
            .checked_add(u64::from(offset))
            .ok_or(VmmError::AddressOverflow {
                addr: self.addr,
                size: n,
            })?;
        let gs = self.memory.gpa_read(addr, n)?;
        gs.read_to(&mut dst[..n]);
        Ok(n)
    }

    /// Like [`Self::read_into`] but reports a queue violation on access
    /// failure, suitable for device `process_queue` implementations.
    pub fn read_into_checked(&self, offset: u32, dst: &mut [u8]) -> Result<usize, QueueViolation> {
        self.read_into(offset, dst)
            .map_err(|_| self.descriptor_buffer_read_failed())
    }

    /// Read a fixed-size `Pod` from the descriptor buffer at `offset`. The
    /// `T`-sized stack copy *is* the cap, so this needs no `ReadCap`.
    /// Errors if `offset + size_of::<T>() > desc.len`.
    pub fn read_obj_at<T: bytemuck::Pod>(&self, offset: u32) -> Result<T, VmmError> {
        let size = std::mem::size_of::<T>();
        let avail = self.len.saturating_sub(offset) as usize;
        if avail < size {
            return Err(VmmError::AddressOverflow {
                addr: self.addr,
                size,
            });
        }
        let addr = self
            .addr
            .checked_add(u64::from(offset))
            .ok_or(VmmError::AddressOverflow {
                addr: self.addr,
                size,
            })?;
        self.memory.read_obj(addr)
    }

    const fn descriptor_buffer_read_failed(&self) -> QueueViolation {
        QueueViolation::DescriptorBufferReadFailed {
            addr: self.addr,
            len: self.len,
        }
    }
}

/// Direction-tagged descriptor yielded by the chain walker.
#[derive(Clone, Copy)]
pub enum DescriptorRef<'brand, 'm, M: GuestMemory> {
    /// Device-readable descriptor.
    Readable(ReadableDescriptor<'brand, 'm, M>),
    /// Device-writable descriptor.
    Writable(WritableDescriptor<'brand, 'm, M>),
}

impl<M: GuestMemory> std::fmt::Debug for DescriptorRef<'_, '_, M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Readable(desc) => f.debug_tuple("Readable").field(desc).finish(),
            Self::Writable(desc) => f.debug_tuple("Writable").field(desc).finish(),
        }
    }
}

impl<'brand, 'm, M: GuestMemory> DescriptorRef<'brand, 'm, M> {
    /// Guest physical address captured from this descriptor.
    #[must_use]
    pub const fn addr(&self) -> u64 {
        match self {
            Self::Readable(desc) => desc.addr(),
            Self::Writable(desc) => desc.addr(),
        }
    }

    /// Length of this descriptor's buffer in bytes.
    #[must_use]
    pub const fn len(&self) -> u32 {
        match self {
            Self::Readable(desc) => desc.len(),
            Self::Writable(desc) => desc.len(),
        }
    }

    /// True if this descriptor has zero bytes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return true if this descriptor is device-readable.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        matches!(self, Self::Readable(_))
    }

    /// Return true if this descriptor is device-writable.
    #[must_use]
    pub const fn is_writable(&self) -> bool {
        matches!(self, Self::Writable(_))
    }

    /// Borrow this descriptor as a readable descriptor, if it is readable.
    #[must_use]
    pub const fn as_readable(&self) -> Option<&ReadableDescriptor<'brand, 'm, M>> {
        match self {
            Self::Readable(desc) => Some(desc),
            Self::Writable(_) => None,
        }
    }

    /// Borrow this descriptor as a writable descriptor, if it is writable.
    #[must_use]
    pub const fn as_writable(&self) -> Option<&WritableDescriptor<'brand, 'm, M>> {
        match self {
            Self::Readable(_) => None,
            Self::Writable(desc) => Some(desc),
        }
    }
}

/// Clamp a descriptor range to `min(len - offset, cap)`, saturating at 0.
fn clamp_len(len: u32, offset: u32, cap: u32) -> u32 {
    len.saturating_sub(offset).min(cap)
}

// =============================================================================
// DescriptorChain — lazy single-read iterator
// =============================================================================

/// Iterator over a chain of virtio descriptors.
///
/// Zero heap allocation for direct chains. Each `next()` call reads one
/// descriptor from guest memory via typed little-endian scalar loads, validates
/// it, and yields a `Result<DescriptorRef<'brand, 'm, M>, QueueViolation>`. The walk
/// follows `next` pointers through the guest's descriptor table, bounded by
/// `queue_size` to prevent cycles.
///
/// **End vs. error:** the iterator distinguishes a clean end-of-chain
/// (`Some(Ok(_))` until `None`) from a structural defect (`Some(Err(v))`
/// followed by `None`). Devices `?`-propagate the `Err` so the caller-side
/// `push()` can refuse to publish a used entry for a malformed chain.
///
/// Indirect descriptors trigger a heap copy of the indirect table (since
/// it lives at an arbitrary guest GPA with arbitrary size).
pub struct DescriptorChain<'brand, 'm, M: GuestMemory> {
    memory: &'m M,
    head_idx: u16,
    desc_table_gpa: u64,
    queue_size: u16,
    indirect_enabled: bool,
    seen_writable: bool,
    state: WalkState,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
}

/// Walk state machine for the iterator.
enum WalkState {
    /// Walking the direct descriptor table.
    Direct {
        next_idx: Option<u16>,
        steps_remaining: u16,
    },
    /// Walking an indirect table (heap-copied from guest memory).
    Indirect {
        table: Vec<Descriptor>,
        table_len: u16,
        next_idx: Option<u16>,
        steps_remaining: u16,
    },
    /// Chain finished cleanly or a violation was already yielded.
    Done,
}

impl<'brand, 'm, M: GuestMemory> DescriptorChain<'brand, 'm, M> {
    /// Create a new chain starting at `head_idx`.
    pub(crate) fn new(
        memory: &'m M,
        head_idx: u16,
        desc_table_gpa: u64,
        queue_size: u16,
        indirect_enabled: bool,
    ) -> Self {
        Self {
            memory,
            head_idx,
            desc_table_gpa,
            queue_size,
            indirect_enabled,
            seen_writable: false,
            state: WalkState::Direct {
                next_idx: Some(head_idx),
                steps_remaining: queue_size,
            },
            _brand: PhantomData,
        }
    }

    /// The head descriptor index (used when calling `queue.push()`).
    #[must_use]
    pub const fn head_index(&self) -> u16 {
        self.head_idx
    }

    pub(crate) const fn memory(&self) -> &'m M {
        self.memory
    }

    /// Validate that a descriptor's buffer is within guest memory bounds.
    /// Returns `Err(DescriptorBufferOutOfRange)` if the buffer overflows or
    /// escapes guest RAM.
    fn validate_buffer(
        memory: &M,
        desc: &Descriptor,
        writable: bool,
    ) -> Result<(), QueueViolation> {
        if desc.len == 0 {
            return Ok(());
        }
        let oob = QueueViolation::DescriptorBufferOutOfRange {
            addr: desc.addr,
            len: desc.len,
        };
        let Some(_end) = u64::from(desc.len).checked_add(desc.addr) else {
            return Err(oob);
        };
        let result = if writable {
            memory.validate_write_range(desc.addr, desc.len as usize)
        } else {
            memory.validate_read_range(desc.addr, desc.len as usize)
        };
        result.map_err(|_| oob)
    }

    fn slice_from_desc_checked(
        &mut self,
        desc: &Descriptor,
    ) -> Result<DescriptorRef<'brand, 'm, M>, QueueViolation> {
        let writable = desc.flags & VIRTQ_DESC_F_WRITE != 0;
        Self::validate_buffer(self.memory, desc, writable)?;
        if writable {
            self.seen_writable = true;
        } else if self.seen_writable {
            return Err(QueueViolation::DescriptorReadableAfterWritable {
                head_index: self.head_idx,
            });
        }

        if writable {
            Ok(DescriptorRef::Writable(WritableDescriptor::new(
                self.memory,
                desc.addr,
                desc.len,
            )))
        } else {
            Ok(DescriptorRef::Readable(ReadableDescriptor::new(
                self.memory,
                desc.addr,
                desc.len,
            )))
        }
    }

    /// Read one virtio descriptor via explicit little-endian scalar fields.
    fn read_descriptor_at(
        &self,
        desc_gpa: u64,
        map_error: impl Fn(u64) -> QueueViolation,
    ) -> Result<Descriptor, QueueViolation> {
        let len_gpa = desc_gpa.checked_add(8).ok_or_else(|| map_error(desc_gpa))?;
        let flags_gpa = desc_gpa
            .checked_add(12)
            .ok_or_else(|| map_error(desc_gpa))?;
        let next_gpa = desc_gpa
            .checked_add(14)
            .ok_or_else(|| map_error(desc_gpa))?;

        let addr = self
            .memory
            .read_le_u64(desc_gpa)
            .map_err(|_| map_error(desc_gpa))?;
        let len = self
            .memory
            .read_le_u32(len_gpa)
            .map_err(|_| map_error(len_gpa))?;
        let flags = self
            .memory
            .read_le_u16(flags_gpa)
            .map_err(|_| map_error(flags_gpa))?;
        let next = self
            .memory
            .read_le_u16(next_gpa)
            .map_err(|_| map_error(next_gpa))?;

        Ok(Descriptor {
            addr,
            len,
            flags,
            next,
        })
    }

    /// Read one descriptor from the direct descriptor table.
    fn read_direct(&self, idx: u16) -> Result<Descriptor, QueueViolation> {
        if idx >= self.queue_size {
            return Err(QueueViolation::DescriptorNextIndexOutOfRange {
                index: idx,
                queue_size: self.queue_size,
            });
        }
        let desc_gpa = self.desc_table_gpa.checked_add(u64::from(idx) * 16).ok_or(
            QueueViolation::DescriptorReadFailed {
                addr: self.desc_table_gpa,
            },
        )?;
        self.read_descriptor_at(desc_gpa, |addr| QueueViolation::DescriptorReadFailed {
            addr,
        })
    }

    /// Enter an indirect table: validate, copy from guest, switch state.
    /// Returns the first slice (or violation) of the indirect walk.
    fn enter_indirect(
        &mut self,
        idx: u16,
        desc: &Descriptor,
    ) -> Result<DescriptorRef<'brand, 'm, M>, QueueViolation> {
        if desc.flags & VIRTQ_DESC_F_NEXT != 0 {
            return Err(QueueViolation::DescriptorNextAndIndirectSet { index: idx });
        }
        if desc.flags & VIRTQ_DESC_F_WRITE != 0 {
            return Err(QueueViolation::DescriptorUnexpectedWritable {
                head_index: self.head_idx,
            });
        }
        if desc.len == 0 || !desc.len.is_multiple_of(16) {
            return Err(QueueViolation::IndirectTableInvalidLength { len: desc.len });
        }
        if self
            .memory
            .validate_read_range(desc.addr, desc.len as usize)
            .is_err()
        {
            return Err(QueueViolation::IndirectTableOutOfRange {
                addr: desc.addr,
                len: desc.len,
            });
        }
        let entry_count = desc.len / 16;
        let table_len =
            u16::try_from(entry_count).map_err(|_| QueueViolation::IndirectTableTooLarge {
                entries: entry_count,
                max_entries: MAX_INDIRECT_TABLE_LEN,
            })?;
        if table_len > MAX_INDIRECT_TABLE_LEN {
            return Err(QueueViolation::IndirectTableTooLarge {
                entries: u32::from(table_len),
                max_entries: MAX_INDIRECT_TABLE_LEN,
            });
        }

        // Copy the indirect table from guest memory. This is the one place
        // we heap-allocate; MAX_INDIRECT_TABLE_LEN bounds it to 2 KiB.
        let mut ind_table = vec![Descriptor::ZERO; table_len as usize];
        for i in 0..table_len {
            let gpa = desc
                .addr
                .checked_add(u64::from(i) * 16)
                .ok_or(QueueViolation::IndirectEntryReadFailed { addr: desc.addr })?;
            let d = self
                .read_descriptor_at(gpa, |addr| QueueViolation::IndirectEntryReadFailed { addr })?;
            ind_table[i as usize] = d;
        }

        self.state = WalkState::Indirect {
            table: ind_table,
            table_len,
            next_idx: Some(0),
            steps_remaining: table_len,
        };
        self.next_indirect()
            .ok_or(QueueViolation::IndirectDescriptorChainTooLong { table_len })?
    }

    /// Advance the indirect walk, yielding the next descriptor (or violation).
    fn next_indirect(&mut self) -> Option<Result<DescriptorRef<'brand, 'm, M>, QueueViolation>> {
        let (idx, desc) = {
            let WalkState::Indirect {
                table,
                table_len,
                next_idx,
                steps_remaining,
            } = &mut self.state
            else {
                return None;
            };
            let idx = (*next_idx).take()?;
            if *steps_remaining == 0 {
                return Some(Err(QueueViolation::IndirectDescriptorChainTooLong {
                    table_len: *table_len,
                }));
            }
            *steps_remaining -= 1;

            if usize::from(idx) >= table.len() {
                return Some(Err(QueueViolation::IndirectDescriptorIndexOutOfRange {
                    index: idx,
                    table_len: *table_len,
                }));
            }
            (idx, table[usize::from(idx)])
        };

        if desc.flags & VIRTQ_DESC_F_INDIRECT != 0 {
            return Some(Err(QueueViolation::NestedIndirectDescriptor { index: idx }));
        }
        if desc.flags & VIRTQ_DESC_F_NEXT != 0
            && let WalkState::Indirect { next_idx, .. } = &mut self.state
        {
            *next_idx = Some(desc.next);
        }
        Some(self.slice_from_desc_checked(&desc))
    }
}

impl<'brand, 'm, M: GuestMemory> Iterator for DescriptorChain<'brand, 'm, M> {
    type Item = Result<DescriptorRef<'brand, 'm, M>, QueueViolation>;

    fn next(&mut self) -> Option<Self::Item> {
        match &mut self.state {
            WalkState::Done => None,

            WalkState::Direct {
                next_idx,
                steps_remaining,
            } => {
                let idx = (*next_idx).take()?;
                if *steps_remaining == 0 {
                    self.state = WalkState::Done;
                    return Some(Err(QueueViolation::DescriptorChainTooLong {
                        head_index: self.head_idx,
                        queue_size: self.queue_size,
                    }));
                }
                *steps_remaining -= 1;

                // Descriptor fields are read once from guest memory; no re-reads.
                let desc = match self.read_direct(idx) {
                    Ok(d) => d,
                    Err(v) => {
                        self.state = WalkState::Done;
                        return Some(Err(v));
                    }
                };

                if desc.flags & VIRTQ_DESC_F_INDIRECT != 0 {
                    if !self.indirect_enabled {
                        self.state = WalkState::Done;
                        return Some(Err(QueueViolation::IndirectDescriptorNotNegotiated {
                            index: idx,
                        }));
                    }
                    let result = self.enter_indirect(idx, &desc);
                    if result.is_err() {
                        self.state = WalkState::Done;
                    }
                    return Some(result);
                }

                if desc.flags & VIRTQ_DESC_F_NEXT != 0
                    && let WalkState::Direct { next_idx: ni, .. } = &mut self.state
                {
                    *ni = Some(desc.next);
                }

                match self.slice_from_desc_checked(&desc) {
                    Ok(slice) => Some(Ok(slice)),
                    Err(v) => {
                        self.state = WalkState::Done;
                        Some(Err(v))
                    }
                }
            }

            WalkState::Indirect { .. } => {
                let result = self.next_indirect();
                if matches!(result, Some(Err(_)) | None) {
                    self.state = WalkState::Done;
                }
                result
            }
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use amla_core::vm_state::guest_mem::{GuestRead, GuestWrite};
    use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, VmStateHeader};

    /// Generous cap for test I/O — every test payload fits in 4 KiB.
    const TEST_READ_CAP: ReadCap = ReadCap::new(NonZeroU32::new(4096).unwrap());

    /// Guest RAM size for VM-state-backed tests.
    const RAM_SIZE: usize = TEST_RAM_SIZE;
    /// GPA where data buffers start.
    const DATA_BASE: u64 = 0x800;

    fn make_test_buf() -> TestMmap {
        amla_core::vm_state::test_mmap(RAM_SIZE)
    }

    #[allow(clippy::cast_possible_truncation)]
    fn ram_offset(mmap: &TestMmap) -> usize {
        // SAFETY: test VM-state metadata is not concurrently mutated here.
        let bytes = unsafe { mmap.as_slice_unchecked() };
        let header: &VmStateHeader =
            bytemuck::from_bytes(&bytes[..std::mem::size_of::<VmStateHeader>()]);
        header.ram_offset as usize
    }

    fn make_state(mmap: &TestMmap) -> VmState<'_> {
        amla_core::vm_state::make_test_vmstate(mmap, 0)
    }

    /// Get a mutable slice for writing test data into the mmap.
    #[allow(clippy::cast_possible_truncation)]
    fn buf_mut(mmap: &mut TestMmap) -> &mut [u8] {
        // SAFETY: test-only. `mmap.as_mut_ptr()` returns a valid pointer to
        // `mmap.len()` bytes of `MAP_SHARED` memory owned by `mmap`; the
        // returned slice borrows through `mmap`'s `&mut` lifetime, so the
        // borrow checker enforces exclusivity on the mmap while the slice
        // is live.
        unsafe { std::slice::from_raw_parts_mut(mmap.as_mut_ptr(), mmap.len()) }
    }

    fn write_desc(mmap: &mut TestMmap, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
        let off = ram_offset(mmap) + usize::from(idx) * 16;
        let buf = buf_mut(mmap);
        buf[off..off + 8].copy_from_slice(&addr.to_le_bytes());
        buf[off + 8..off + 12].copy_from_slice(&len.to_le_bytes());
        buf[off + 12..off + 14].copy_from_slice(&flags.to_le_bytes());
        buf[off + 14..off + 16].copy_from_slice(&next.to_le_bytes());
    }

    /// Host offset for a GPA within the test mmap.
    #[allow(clippy::cast_possible_truncation)]
    fn host_off(mmap: &TestMmap, gpa: u64) -> usize {
        ram_offset(mmap) + gpa as usize
    }

    fn assert_next_ok<M: GuestMemory>(chain: &mut DescriptorChain<'_, '_, M>) {
        assert!(matches!(chain.next(), Some(Ok(_))));
    }

    fn assert_next_violation<M: GuestMemory>(
        chain: &mut DescriptorChain<'_, '_, M>,
        matches_expected: impl FnOnce(QueueViolation) -> bool,
        expected: &str,
    ) {
        match chain.next() {
            Some(Err(v)) if matches_expected(v) => {}
            other => panic!("expected {expected}, got {other:?}"),
        }
        assert!(chain.next().is_none());
    }

    #[test]
    fn single_descriptor() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 64, 0, 0);
        let data_off = host_off(&buf, DATA_BASE);
        buf_mut(&mut buf)[data_off..data_off + 5].copy_from_slice(b"hello");
        let state = make_state(&buf);

        let chain = DescriptorChain::new(&state, 0, 0, 4, false);
        let slices: Vec<_> = chain.map(Result::unwrap).collect();
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].addr(), DATA_BASE);
        assert_eq!(slices[0].len(), 64);
        assert!(!slices[0].is_writable());
        assert_eq!(
            &slices[0]
                .as_readable()
                .unwrap()
                .guest_read(TEST_READ_CAP)
                .unwrap()
                .to_vec()[..5],
            b"hello"
        );
    }

    #[test]
    fn chained_descriptors() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 32, VIRTQ_DESC_F_NEXT, 1);
        write_desc(&mut buf, 1, DATA_BASE + 32, 16, VIRTQ_DESC_F_NEXT, 2);
        write_desc(&mut buf, 2, DATA_BASE + 48, 8, VIRTQ_DESC_F_WRITE, 0);
        let state = make_state(&buf);

        let slices: Vec<_> = DescriptorChain::new(&state, 0, 0, 4, false)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(slices.len(), 3);
        assert!(!slices[0].is_writable());
        assert!(!slices[1].is_writable());
        assert!(slices[2].is_writable());
        assert_eq!(slices[0].len() + slices[1].len() + slices[2].len(), 56);
    }

    #[test]
    fn head_index_preserved() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 2, DATA_BASE, 10, 0, 0);
        let state = make_state(&buf);

        let chain = DescriptorChain::new(&state, 2, 0, 4, false);
        assert_eq!(chain.head_index(), 2);
    }

    #[test]
    fn zero_length_buffer_is_valid() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 0, 0, 0);
        let state = make_state(&buf);

        let slices: Vec<_> = DescriptorChain::new(&state, 0, 0, 4, false)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(slices.len(), 1);
        assert_eq!(slices[0].len(), 0);
    }

    #[test]
    fn oob_buffer_stops_iteration() {
        let mut buf = make_test_buf();
        write_desc(
            &mut buf,
            0,
            DATA_BASE,
            u32::try_from(RAM_SIZE).unwrap() + 1,
            0,
            0,
        );
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, false);
        assert_next_violation(
            &mut chain,
            |v| {
                matches!(
                    v,
                    QueueViolation::DescriptorBufferOutOfRange {
                        addr: DATA_BASE,
                        len,
                    } if len == u32::try_from(RAM_SIZE).unwrap() + 1
                )
            },
            "DescriptorBufferOutOfRange",
        );
    }

    #[test]
    fn index_out_of_queue_stops_iteration() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 10, 0, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 5, 0, 4, false);
        assert_next_violation(
            &mut chain,
            |v| {
                matches!(
                    v,
                    QueueViolation::DescriptorNextIndexOutOfRange {
                        index: 5,
                        queue_size: 4,
                    }
                )
            },
            "DescriptorNextIndexOutOfRange",
        );
    }

    #[test]
    fn cycle_detection_stops_chain() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 8, VIRTQ_DESC_F_NEXT, 1);
        write_desc(&mut buf, 1, DATA_BASE + 8, 8, VIRTQ_DESC_F_NEXT, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 2, false);
        assert_next_ok(&mut chain);
        assert_next_ok(&mut chain);
        assert_next_violation(
            &mut chain,
            |v| {
                matches!(
                    v,
                    QueueViolation::DescriptorChainTooLong {
                        head_index: 0,
                        queue_size: 2,
                    }
                )
            },
            "DescriptorChainTooLong",
        );
    }

    #[test]
    fn indirect_descriptor_table() {
        let mut buf = make_test_buf();
        let indirect_gpa: u64 = 0x400;
        write_desc(&mut buf, 0, indirect_gpa, 32, VIRTQ_DESC_F_INDIRECT, 0);

        let it = host_off(&buf, indirect_gpa);
        let b = buf_mut(&mut buf);
        let d0_addr = DATA_BASE;
        b[it..it + 8].copy_from_slice(&d0_addr.to_le_bytes());
        b[it + 8..it + 12].copy_from_slice(&16u32.to_le_bytes());
        b[it + 12..it + 14].copy_from_slice(&VIRTQ_DESC_F_NEXT.to_le_bytes());
        b[it + 14..it + 16].copy_from_slice(&1u16.to_le_bytes());

        let d1_addr = DATA_BASE + 16;
        b[it + 16..it + 24].copy_from_slice(&d1_addr.to_le_bytes());
        b[it + 24..it + 28].copy_from_slice(&24u32.to_le_bytes());
        b[it + 28..it + 30].copy_from_slice(&VIRTQ_DESC_F_WRITE.to_le_bytes());
        b[it + 30..it + 32].copy_from_slice(&0u16.to_le_bytes());

        let state = make_state(&buf);
        let slices: Vec<_> = DescriptorChain::new(&state, 0, 0, 4, true)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(slices.len(), 2);
        assert_eq!(slices[0].addr(), DATA_BASE);
        assert_eq!(slices[0].len(), 16);
        assert!(!slices[0].is_writable());
        assert_eq!(slices[1].addr(), DATA_BASE + 16);
        assert_eq!(slices[1].len(), 24);
        assert!(slices[1].is_writable());
    }

    #[test]
    fn indirect_rejected_when_not_negotiated() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, 0x400, 16, VIRTQ_DESC_F_INDIRECT, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, false);
        assert_next_violation(
            &mut chain,
            |v| {
                matches!(
                    v,
                    QueueViolation::IndirectDescriptorNotNegotiated { index: 0 }
                )
            },
            "IndirectDescriptorNotNegotiated",
        );
    }

    #[test]
    fn indirect_with_next_flag_rejected() {
        let mut buf = make_test_buf();
        write_desc(
            &mut buf,
            0,
            0x400,
            16,
            VIRTQ_DESC_F_INDIRECT | VIRTQ_DESC_F_NEXT,
            1,
        );
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, true);
        assert_next_violation(
            &mut chain,
            |v| matches!(v, QueueViolation::DescriptorNextAndIndirectSet { index: 0 }),
            "DescriptorNextAndIndirectSet",
        );
    }

    #[test]
    fn indirect_bad_len_rejected() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, 0x400, 17, VIRTQ_DESC_F_INDIRECT, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, true);
        assert_next_violation(
            &mut chain,
            |v| matches!(v, QueueViolation::IndirectTableInvalidLength { len: 17 }),
            "IndirectTableInvalidLength",
        );
    }

    #[test]
    fn indirect_zero_len_rejected() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, 0x400, 0, VIRTQ_DESC_F_INDIRECT, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, true);
        assert_next_violation(
            &mut chain,
            |v| matches!(v, QueueViolation::IndirectTableInvalidLength { len: 0 }),
            "IndirectTableInvalidLength",
        );
    }

    #[test]
    fn nested_indirect_rejected() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, 0x400, 16, VIRTQ_DESC_F_INDIRECT, 0);
        let it = host_off(&buf, 0x400);
        let b = buf_mut(&mut buf);
        b[it..it + 8].copy_from_slice(&DATA_BASE.to_le_bytes());
        b[it + 8..it + 12].copy_from_slice(&16u32.to_le_bytes());
        b[it + 12..it + 14].copy_from_slice(&VIRTQ_DESC_F_INDIRECT.to_le_bytes());
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, true);
        assert_next_violation(
            &mut chain,
            |v| matches!(v, QueueViolation::NestedIndirectDescriptor { index: 0 }),
            "NestedIndirectDescriptor",
        );
    }

    #[test]
    fn indirect_oversized_table_rejected() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, 0x400, 0x10_0000, VIRTQ_DESC_F_INDIRECT, 0);
        let state = make_state(&buf);

        let mut chain = DescriptorChain::new(&state, 0, 0, 4, true);
        assert_next_violation(
            &mut chain,
            |v| {
                matches!(
                    v,
                    QueueViolation::IndirectTableTooLarge {
                        entries: 65_536,
                        max_entries: MAX_INDIRECT_TABLE_LEN,
                    }
                )
            },
            "IndirectTableTooLarge",
        );
    }

    #[test]
    fn writable_flag_propagated() {
        let mut buf = make_test_buf();
        write_desc(&mut buf, 0, DATA_BASE, 32, VIRTQ_DESC_F_WRITE, 0);
        let state = make_state(&buf);

        let slices: Vec<_> = DescriptorChain::new(&state, 0, 0, 4, false)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(slices.len(), 1);
        assert!(slices[0].is_writable());
    }

    // =========================================================================
    // MockMemory — TOCTOU fault injection
    // =========================================================================

    use std::cell::RefCell;

    struct MockMemory {
        buf: RefCell<Vec<u8>>,
    }

    impl MockMemory {
        fn new(size: usize) -> Self {
            Self {
                buf: RefCell::new(vec![0u8; size]),
            }
        }

        fn write_desc(&self, idx: u16, addr: u64, len: u32, flags: u16, next: u16) {
            let off = usize::from(idx) * 16;
            let mut buf = self.buf.borrow_mut();
            buf[off..off + 8].copy_from_slice(&addr.to_le_bytes());
            buf[off + 8..off + 12].copy_from_slice(&len.to_le_bytes());
            buf[off + 12..off + 14].copy_from_slice(&flags.to_le_bytes());
            buf[off + 14..off + 16].copy_from_slice(&next.to_le_bytes());
        }

        fn mutate(&self, f: impl FnOnce(&mut Vec<u8>)) {
            f(&mut self.buf.borrow_mut());
        }
    }

    #[derive(Clone)]
    struct MockSlice(Vec<u8>);

    impl GuestRead for MockSlice {
        fn read_to(&self, buf: &mut [u8]) {
            assert_eq!(buf.len(), self.0.len());
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

    #[derive(Clone)]
    struct MockSliceMut(usize);

    impl GuestWrite for MockSliceMut {
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

    fn oob(addr: u64, size: usize, memory_size: usize) -> VmmError {
        VmmError::MemoryOutOfBounds {
            addr,
            size,
            memory_size,
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    impl GuestMemory for MockMemory {
        type Slice<'m>
            = MockSlice
        where
            Self: 'm;
        type SliceMut<'m>
            = MockSliceMut
        where
            Self: 'm;

        fn gpa_read(&self, addr: u64, len: usize) -> Result<MockSlice, VmmError> {
            let start = addr as usize;
            let buf = self.buf.borrow();
            let end = start
                .checked_add(len)
                .ok_or_else(|| oob(addr, len, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, len, buf.len()));
            }
            Ok(MockSlice(buf[start..end].to_vec()))
        }

        fn gpa_write(&self, addr: u64, len: usize) -> Result<MockSliceMut, VmmError> {
            self.validate_range(addr, len)?;
            Ok(MockSliceMut(len))
        }

        fn read_obj<T: bytemuck::Pod>(&self, addr: u64) -> Result<T, VmmError> {
            let size = core::mem::size_of::<T>();
            let start = addr as usize;
            let buf = self.buf.borrow();
            let end = start
                .checked_add(size)
                .ok_or_else(|| oob(addr, size, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, size, buf.len()));
            }
            Ok(bytemuck::pod_read_unaligned(&buf[start..end]))
        }

        fn write_obj<T: bytemuck::NoUninit>(&self, _addr: u64, _val: &T) -> Result<(), VmmError> {
            Ok(())
        }

        fn read_le_u16(&self, addr: u64) -> Result<u16, VmmError> {
            let start = addr as usize;
            let buf = self.buf.borrow();
            let end = start
                .checked_add(2)
                .ok_or_else(|| oob(addr, 2, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, 2, buf.len()));
            }
            Ok(u16::from_le_bytes([buf[start], buf[start + 1]]))
        }

        fn read_le_u32(&self, addr: u64) -> Result<u32, VmmError> {
            let start = addr as usize;
            let buf = self.buf.borrow();
            let end = start
                .checked_add(4)
                .ok_or_else(|| oob(addr, 4, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, 4, buf.len()));
            }
            Ok(u32::from_le_bytes([
                buf[start],
                buf[start + 1],
                buf[start + 2],
                buf[start + 3],
            ]))
        }

        fn read_le_u64(&self, addr: u64) -> Result<u64, VmmError> {
            let start = addr as usize;
            let buf = self.buf.borrow();
            let end = start
                .checked_add(8)
                .ok_or_else(|| oob(addr, 8, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, 8, buf.len()));
            }
            Ok(u64::from_le_bytes([
                buf[start],
                buf[start + 1],
                buf[start + 2],
                buf[start + 3],
                buf[start + 4],
                buf[start + 5],
                buf[start + 6],
                buf[start + 7],
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
            self.validate_range(addr, len)
        }

        fn validate_write_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
            self.validate_range(addr, len)
        }
    }

    impl MockMemory {
        fn validate_range(&self, addr: u64, len: usize) -> Result<(), VmmError> {
            let buf = self.buf.borrow();
            let start = usize::try_from(addr).map_err(|_| oob(addr, len, buf.len()))?;
            let end = start
                .checked_add(len)
                .ok_or_else(|| oob(addr, len, buf.len()))?;
            if end > buf.len() {
                return Err(oob(addr, len, buf.len()));
            }
            Ok(())
        }
    }

    // =========================================================================
    // TOCTOU tests
    //
    // With lazy single-read, each descriptor is read exactly once at next()
    // time. The direct table is NOT eagerly copied — mutations between
    // next() calls are visible for not-yet-read descriptors. This is safe:
    // the guest controls all addresses anyway, and range validation
    // prevents escaping guest RAM.
    //
    // Indirect tables ARE heap-copied at encounter time, so mutations
    // after the indirect descriptor is first iterated have no effect.
    // =========================================================================

    /// Direct descriptor: mutation BEFORE `next()` is visible (lazy read).
    /// This is expected — the guest always controls descriptor contents.
    #[test]
    fn lazy_read_sees_pre_iteration_mutation() {
        let mem = MockMemory::new(4096);
        mem.write_desc(0, 0x800, 64, 0, 0);

        let mut chain = DescriptorChain::new(&mem, 0, 0, 4, false);

        // Guest rewrites before we iterate.
        mem.write_desc(0, 0x900, 32, VIRTQ_DESC_F_WRITE, 0);

        let slice = chain.next().unwrap().unwrap();
        // Lazy read: we see the mutation (this is fine — guest controls addresses).
        assert_eq!(slice.addr(), 0x900);
        assert_eq!(slice.len(), 32);
        assert!(slice.is_writable());
    }

    #[test]
    fn checked_descriptor_read_failure_is_queue_violation() {
        let mem = MockMemory::new(4096);
        mem.write_desc(0, 0x800, 4, 0, 0);
        let mut chain = DescriptorChain::new(&mem, 0, 0, 4, false);
        let DescriptorRef::Readable(slice) = chain.next().unwrap().unwrap() else {
            panic!("expected readable descriptor");
        };

        mem.mutate(|buf| buf.truncate(0x802));

        let mut dst = [0u8; 4];
        assert!(matches!(
            slice.read_into_checked(0, &mut dst),
            Err(QueueViolation::DescriptorBufferReadFailed {
                addr: 0x800,
                len: 4,
            })
        ));
    }

    /// Indirect table: mutation after iterator hits the indirect descriptor
    /// does NOT affect yielded values (table is heap-copied at encounter).
    #[test]
    fn indirect_table_copied_at_encounter() {
        let mem = MockMemory::new(4096);
        mem.write_desc(0, 0x400, 32, VIRTQ_DESC_F_INDIRECT, 0);

        let indirect_base = 0x400_usize;
        mem.mutate(|buf| {
            buf[indirect_base..indirect_base + 8].copy_from_slice(&0x800u64.to_le_bytes());
            buf[indirect_base + 8..indirect_base + 12].copy_from_slice(&16u32.to_le_bytes());
            buf[indirect_base + 12..indirect_base + 14]
                .copy_from_slice(&VIRTQ_DESC_F_NEXT.to_le_bytes());
            buf[indirect_base + 14..indirect_base + 16].copy_from_slice(&1u16.to_le_bytes());

            buf[indirect_base + 16..indirect_base + 24].copy_from_slice(&0x810u64.to_le_bytes());
            buf[indirect_base + 24..indirect_base + 28].copy_from_slice(&24u32.to_le_bytes());
            buf[indirect_base + 28..indirect_base + 30]
                .copy_from_slice(&VIRTQ_DESC_F_WRITE.to_le_bytes());
            buf[indirect_base + 30..indirect_base + 32].copy_from_slice(&0u16.to_le_bytes());
        });

        let mut chain = DescriptorChain::new(&mem, 0, 0, 4, true);

        // First next() reads the outer indirect descriptor and copies the table.
        let s0 = chain.next().unwrap().unwrap();
        assert_eq!(s0.addr(), 0x800);

        // Guest mutates the indirect table — no effect, already copied.
        mem.mutate(|buf| {
            buf[indirect_base + 16..indirect_base + 24].copy_from_slice(&0xDEADu64.to_le_bytes());
        });

        let s1 = chain.next().unwrap().unwrap();
        assert_eq!(
            s1.addr(),
            0x810,
            "indirect entry from copy, not guest mutation"
        );
    }

    /// Cycle injection: guest rewires desc1→desc0 between reads.
    /// With lazy reads, this creates a cycle. The `steps_remaining`
    /// countdown catches it.
    #[test]
    fn lazy_cycle_injection_bounded() {
        let mem = MockMemory::new(4096);
        mem.write_desc(0, 0x800, 16, VIRTQ_DESC_F_NEXT, 1);
        mem.write_desc(1, 0x810, 16, 0, 0); // no NEXT

        let mut chain = DescriptorChain::new(&mem, 0, 0, 2, false);

        // Read desc0 (NEXT→1)
        let s0 = chain.next().unwrap().unwrap();
        assert_eq!(s0.addr(), 0x800);

        // Guest rewires desc1 to point back to desc0
        mem.write_desc(1, 0x810, 16, VIRTQ_DESC_F_NEXT, 0);

        // Read desc1 — sees NEXT→0, but steps_remaining prevents infinite loop
        let s1 = chain.next().unwrap().unwrap();
        assert_eq!(s1.addr(), 0x810);

        // Chain ends: steps_remaining=0 → walker emits a violation, then None.
        assert!(matches!(
            chain.next(),
            Some(Err(QueueViolation::DescriptorChainTooLong { .. }))
        ));
        assert!(chain.next().is_none());
    }
}
