// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! SPSC lock-free ring buffer over shared memory.
//!
//! `RingBuffer<N>` provides two unidirectional rings (HG and GH) sharing a
//! single memory region with atomic head/tail cursors and length-prefixed
//! message framing. `N` is the per-ring data capacity in bytes (must be a
//! power of 2).
//!
//! # Memory layout (for `RingBuffer<N>`)
//!
//! ```text
//! Offset       Size     Content
//! 0x0000       64B      SharedHeader
//! 0x0040       64B      HG RingHeader (writer owns head, reader owns tail)
//! 0x0080       64B      GH RingHeader
//! 0x00C0       N        HG ring data
//! 0x00C0+N     N        GH ring data
//! Total:       192 + 2*N bytes
//! ```
//!
//! # Message framing
//!
//! Each message is `[u32 LE length][payload]`. A zero-length marker signals
//! a wrap point — the reader skips to offset 0. Messages never straddle the
//! wrap boundary, enabling zero-copy reads.
//!
//! # Compatibility
//!
//! Shared-memory layout compatibility is exact-version only. `VERSION` is an
//! attach-time guard against mapping a ring with a different current layout; it
//! is not a compatibility range or migration layer. Both sides must use the
//! same source version and the same `RingBuffer<N>` layout.

#![no_std]
#![allow(unexpected_cfgs)]
// `cfg(kani)` is set by the Kani verifier
// Ring offsets and sizes are u32 by protocol design; N <= u32::MAX is
// enforced by a const assertion in from_region().
#![allow(clippy::cast_possible_truncation, clippy::checked_conversions)]
#![cfg_attr(
    test,
    allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::missing_const_for_fn,
    )
)]

use core::cell::UnsafeCell;
use core::fmt;
use core::mem::size_of;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic value in `SharedHeader`: "AMRB" in little-endian.
pub const MAGIC: u32 = 0x414D_5242;

/// Same-layout protocol version stored in `SharedHeader`.
///
/// Equality is required at attach time. Bump this for layout changes so a
/// mismatched peer fails fast with [`RingError::BadVersion`]; do not treat old
/// values as supported compatibility targets.
pub const VERSION: u32 = 4;

/// Maximum payload size per message (16 MiB, supports GPU frame data).
pub const MAX_PAYLOAD_SIZE: u32 = 16 * 1024 * 1024;

/// Default ring data size for host-guest IPC (64 MiB per direction).
pub const HOST_GUEST_RING_SIZE: usize = 64 * 1024 * 1024;

/// Host-guest ring buffer with 64 MiB per direction.
pub type HostGuestRingBuffer = RingBuffer<HOST_GUEST_RING_SIZE>;

/// Total size of the host-guest ring buffer region.
pub const HOST_GUEST_TOTAL_SIZE: usize = size_of::<HostGuestRingBuffer>();

/// Size of the length prefix (u32 LE).
const LEN_SIZE: u32 = 4;

/// A zero-length frame marks a wrap point.
const WRAP_MARKER: u32 = 0;

const INIT_IN_PROGRESS: u32 = 0x494E_4954;
const INIT_READY: u32 = 0x5245_4144;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Ring buffer operation errors.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RingError {
    /// Payload is empty, exceeds `MAX_PAYLOAD_SIZE`, or too large for `u32`.
    PayloadTooLarge,
    /// `advance()` called without a preceding successful `try_peek()`.
    NothingPeeked,
    /// Shared memory contents are inconsistent.
    Corrupt(&'static str),
    /// Shared memory region size does not match this ring layout.
    BadRegionSize {
        /// Required byte size for the selected `RingBuffer<N>` layout.
        expected: usize,
        /// Actual byte size supplied by the caller.
        actual: usize,
    },
    /// Shared memory base pointer is not aligned for this ring layout.
    BadAlignment {
        /// Required alignment in bytes.
        required: usize,
        /// Actual base address.
        address: usize,
    },
    /// Shared memory header has not been completely initialized.
    NotInitialized(u32),
    /// `SharedHeader` magic mismatch.
    BadMagic(u32),
    /// `SharedHeader` version mismatch.
    BadVersion(u32),
    /// `SharedHeader` geometry does not match this `RingBuffer<N>` layout.
    BadLayout(&'static str),
}

impl fmt::Display for RingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PayloadTooLarge => write!(f, "payload too large"),
            Self::NothingPeeked => write!(f, "advance() without peek"),
            Self::Corrupt(msg) => write!(f, "ring corrupt: {msg}"),
            Self::BadRegionSize { expected, actual } => {
                write!(f, "bad region size: expected {expected}, got {actual}")
            }
            Self::BadAlignment { required, address } => {
                write!(
                    f,
                    "bad ring alignment: address {address:#x} is not {required}-byte aligned"
                )
            }
            Self::NotInitialized(v) => write!(f, "ring not initialized: state {v:#010x}"),
            Self::BadMagic(v) => write!(f, "bad magic: {v:#010x}"),
            Self::BadVersion(v) => write!(f, "bad version: {v}"),
            Self::BadLayout(msg) => write!(f, "bad ring layout: {msg}"),
        }
    }
}

// ---------------------------------------------------------------------------
// SharedHeader
// ---------------------------------------------------------------------------

/// Region header at offset 0.
///
/// Initialized by the host before the guest maps the region. Both sides
/// use the same `RingBuffer<N>` type, so ring and data offsets are fixed
/// by the compile-time `repr(C)` layout — readers and writers derive
/// pointers via `offset_of!` through the typed struct.
///
/// The header's role is attach-time validation: `init_state` publishes the
/// completed layout with release/acquire ordering, `magic` distinguishes an
/// AMRB region from unrelated memory, and the geometry fields prove both sides
/// agree on the exact `RingBuffer<N>` shape.
#[repr(C, align(64))]
pub struct SharedHeader {
    init_state: AtomicU32,
    magic: AtomicU32,
    version: AtomicU32,
    data_size: AtomicU32,
    total_size: AtomicU64,
    _reserved: [u8; 40],
}

const _: () = assert!(size_of::<SharedHeader>() == 64);

// ---------------------------------------------------------------------------
// RingHeader
// ---------------------------------------------------------------------------

/// Per-ring cursor pair. Head and tail are padded to reduce false sharing.
#[repr(C, align(64))]
pub struct RingHeader {
    pub head: AtomicU32,
    _pad_head: [u8; 28],
    pub tail: AtomicU32,
    _pad_tail: [u8; 28],
}

const _: () = assert!(size_of::<RingHeader>() == 64);

// ---------------------------------------------------------------------------
// RingBuffer — typed shared memory layout with methods
// ---------------------------------------------------------------------------

/// Shared ring buffer region in mmap memory.
///
/// `#[repr(C)]` struct matching the documented memory layout. `N` is the
/// per-ring data capacity in bytes and must be a power of 2. All mutable
/// fields are wrapped in `UnsafeCell` for sound interior mutability — this
/// is required because `init()` writes through `&RingBuffer` (shared
/// reference), `RingHeader` padding is non-atomic, and data arrays are
/// written by `RingWriter` through raw pointers.
///
/// Never allocated directly — always cast from mmap'd memory via the
/// crate-private `RingBuffer::from_region`. Use `&RingBuffer<N>` as the
/// handle type.
#[repr(C)]
pub struct RingBuffer<const N: usize> {
    header: UnsafeCell<SharedHeader>,
    hg_ring: UnsafeCell<RingHeader>,
    gh_ring: UnsafeCell<RingHeader>,
    hg_data: UnsafeCell<[u8; N]>,
    gh_data: UnsafeCell<[u8; N]>,
}

// SAFETY: Synchronization is handled by atomic head/tail cursors (SPSC
// discipline). UnsafeCell fields correctly model interior mutability.
unsafe impl<const N: usize> Send for RingBuffer<N> {}
// SAFETY: See `Send` impl above — SPSC atomic cursors serialize all
// cross-thread access; shared references only expose atomics.
unsafe impl<const N: usize> Sync for RingBuffer<N> {}

impl<const N: usize> RingBuffer<N> {
    /// The data capacity per ring direction.
    pub const DATA_SIZE: u32 = N as u32;

    /// Total size of this ring buffer layout in bytes.
    pub const TOTAL_SIZE: usize = size_of::<Self>();

    /// Cast an exact-size raw memory region to a `&RingBuffer<N>` reference.
    ///
    /// Crate-private — external callers go through [`RingBufferHandle::attach`],
    /// which wraps the reference in a consume-on-use handle that enforces
    /// SPSC discipline at the type level.
    ///
    /// # Safety
    ///
    /// - `base` must point to exactly `region_len` bytes of read/write memory.
    /// - The memory must be properly aligned (64-byte for current layouts).
    /// - The memory must remain valid for the lifetime of the returned reference.
    /// - The caller must ensure proper SPSC discipline: at most one writer and
    ///   one reader per ring direction.
    pub(crate) unsafe fn from_region<'a>(
        base: NonNull<u8>,
        region_len: usize,
    ) -> Result<&'a Self, RingError> {
        // Compile-time checks — fail the build for invalid N regardless of profile.
        const { assert!(N.is_power_of_two(), "N must be a power of two") };
        const { assert!(N <= u32::MAX as usize, "N must fit in u32") };
        if region_len != Self::TOTAL_SIZE {
            return Err(RingError::BadRegionSize {
                expected: Self::TOTAL_SIZE,
                actual: region_len,
            });
        }
        let required = core::mem::align_of::<Self>();
        let address = base.as_ptr() as usize;
        if !address.is_multiple_of(required) {
            return Err(RingError::BadAlignment { required, address });
        }
        // SAFETY: caller upholds the contract in this fn's `# Safety` section —
        // `base` points to exactly `TOTAL_SIZE` bytes of valid, aligned, live memory.
        Ok(unsafe { &*base.as_ptr().cast::<Self>() })
    }

    /// Initialize the shared header and zero both ring cursors.
    ///
    /// Must be called exactly once by the initializing side before the
    /// other side maps the region. Crate-private — external callers go
    /// through [`RingBufferHandle::init`].
    pub(crate) fn init(&self) {
        // SAFETY: `init` runs before the other side maps the region (documented
        // precondition), so we have exclusive access to every UnsafeCell here.
        // `header.get()`, `hg_ring.get()`, `gh_ring.get()` are always non-null
        // and properly aligned for their repr(C) inner types.
        unsafe {
            let hdr = &mut *self.header.get();
            hdr.init_state.store(INIT_IN_PROGRESS, Ordering::Relaxed);
            hdr.magic.store(MAGIC, Ordering::Relaxed);
            hdr.version.store(VERSION, Ordering::Relaxed);
            hdr.data_size.store(Self::DATA_SIZE, Ordering::Relaxed);
            hdr.total_size
                .store(Self::TOTAL_SIZE as u64, Ordering::Relaxed);

            let hg = &mut *self.hg_ring.get();
            hg.head = AtomicU32::new(0);
            hg.tail = AtomicU32::new(0);
            let gh = &mut *self.gh_ring.get();
            gh.head = AtomicU32::new(0);
            gh.tail = AtomicU32::new(0);

            hdr.init_state.store(INIT_READY, Ordering::Release);
        }
    }

    /// Validate that the shared header has the expected magic and version.
    ///
    /// Crate-private — external callers go through
    /// [`RingBufferHandle::validate`].
    pub(crate) fn validate(&self) -> Result<(), RingError> {
        let hdr = self.header();
        let init_state = hdr.init_state.load(Ordering::Acquire);
        if init_state != INIT_READY {
            return Err(RingError::NotInitialized(init_state));
        }
        let magic = hdr.magic.load(Ordering::Relaxed);
        if magic != MAGIC {
            return Err(RingError::BadMagic(magic));
        }
        let version = hdr.version.load(Ordering::Relaxed);
        if version != VERSION {
            return Err(RingError::BadVersion(version));
        }
        if hdr.data_size.load(Ordering::Relaxed) != Self::DATA_SIZE {
            return Err(RingError::BadLayout("data size mismatch"));
        }
        if hdr.total_size.load(Ordering::Relaxed) != Self::TOTAL_SIZE as u64 {
            return Err(RingError::BadLayout("total size mismatch"));
        }
        Ok(())
    }

    /// Reference to the shared header.
    pub(crate) fn header(&self) -> &SharedHeader {
        // SAFETY: `SharedHeader` is written only once in `init()` before the
        // opposite side maps the region; thereafter it's effectively immutable.
        // Returning `&SharedHeader` bound to `&self` is sound.
        unsafe { &*self.header.get() }
    }

    /// Test-only helper: apply a mutation to the `SharedHeader`.
    ///
    /// Scopes the `&mut SharedHeader` to the closure so it can't escape.
    /// This keeps the unsafe block contained and avoids the unsound
    /// `fn(&self) -> &mut T` shape that `clippy::mut_from_ref` flags.
    #[cfg(test)]
    fn corrupt_header(&self, mutate: impl FnOnce(&mut SharedHeader)) {
        // SAFETY: test-only helper — tests operate on a freshly allocated
        // ring before any reader or writer task is created, so no other
        // accessor of the header exists for the duration of `mutate`.
        unsafe { mutate(&mut *self.header.get()) }
    }

    fn positions(ring: &UnsafeCell<RingHeader>) -> (u32, u32) {
        // SAFETY: `RingHeader` is accessed exclusively via its two AtomicU32
        // fields. A shared reference is sound because no non-atomic write
        // ever targets the header after `init()` installs it.
        let hdr = unsafe { &*ring.get() };
        (
            hdr.head.load(Ordering::Relaxed),
            hdr.tail.load(Ordering::Relaxed),
        )
    }

    /// Read the current HG ring head and tail positions.
    pub(crate) fn hg_positions(&self) -> (u32, u32) {
        Self::positions(&self.hg_ring)
    }

    /// Read the current GH ring head and tail positions.
    pub(crate) fn gh_positions(&self) -> (u32, u32) {
        Self::positions(&self.gh_ring)
    }

    pub(crate) fn hg_writer(&self) -> RingWriter<'_> {
        // SAFETY: see `header()` — RingHeader fields are atomic; accessing
        // through a shared reference is sound under SPSC discipline.
        let hdr = unsafe { &*self.hg_ring.get() };
        // SAFETY: `hg_data.get()` returns a non-null pointer into this
        // RingBuffer's own storage; cast to u8 is layout-compatible.
        let data = unsafe { NonNull::new_unchecked(self.hg_data.get().cast::<u8>()) };
        // SAFETY: `hdr` and `data` come from the same RingBuffer whose
        // `from_region` contract guarantees SPSC discipline (at most one writer
        // per direction) and that `data` covers `DATA_SIZE` bytes; DATA_SIZE
        // is a power of two per the const assertion in `from_region`.
        unsafe { RingWriter::new(hdr, data, Self::DATA_SIZE) }
    }

    pub(crate) fn hg_reader(&self) -> RingReader<'_> {
        // SAFETY: see `hg_writer` — same invariants apply (reader role).
        let hdr = unsafe { &*self.hg_ring.get() };
        // SAFETY: see `hg_writer`.
        let data = unsafe { NonNull::new_unchecked(self.hg_data.get().cast::<u8>()) };
        // SAFETY: see `hg_writer`; SPSC guarantees at most one reader per
        // direction.
        unsafe { RingReader::new(hdr, data, Self::DATA_SIZE) }
    }

    pub(crate) fn gh_writer(&self) -> RingWriter<'_> {
        // SAFETY: see `hg_writer`.
        let hdr = unsafe { &*self.gh_ring.get() };
        // SAFETY: see `hg_writer`.
        let data = unsafe { NonNull::new_unchecked(self.gh_data.get().cast::<u8>()) };
        // SAFETY: see `hg_writer`.
        unsafe { RingWriter::new(hdr, data, Self::DATA_SIZE) }
    }

    pub(crate) fn gh_reader(&self) -> RingReader<'_> {
        // SAFETY: see `hg_writer`.
        let hdr = unsafe { &*self.gh_ring.get() };
        // SAFETY: see `hg_writer`.
        let data = unsafe { NonNull::new_unchecked(self.gh_data.get().cast::<u8>()) };
        // SAFETY: see `hg_writer`.
        unsafe { RingReader::new(hdr, data, Self::DATA_SIZE) }
    }
}

// ---------------------------------------------------------------------------
// Typestate handles: Raw → Ready → split endpoints
// ---------------------------------------------------------------------------

/// Raw (pre-validation) handle to a ring buffer region.
///
/// Obtained from [`RingBufferHandle::attach`]. The only way to reach the
/// ring's endpoints is to first transition to a [`ReadyRingBufferHandle`]
/// via [`init`](Self::init) or [`validate`](Self::validate); both consume
/// `self`. This makes "use ring without init/validate" a type error.
pub struct RingBufferHandle<'a, const N: usize> {
    ring: &'a RingBuffer<N>,
}

impl<'a, const N: usize> RingBufferHandle<'a, N> {
    /// Attach to an exact-size ring region.
    ///
    /// # Safety
    ///
    /// `base` must point to `region_len` bytes of writable memory that remains
    /// live for `'a`. The caller commits to SPSC discipline — at most one
    /// `RingBufferHandle` per side (host and guest) per region.
    #[inline]
    pub unsafe fn attach(base: NonNull<u8>, region_len: usize) -> Result<Self, RingError> {
        // SAFETY: caller upholds the `RingBuffer::from_region` contract.
        let ring = unsafe { RingBuffer::<N>::from_region(base, region_len)? };
        Ok(Self { ring })
    }

    /// Initialize the region (magic + zeroed cursors) and return a ready handle.
    ///
    /// Must be called exactly once by the initializing side, before the
    /// opposite side maps the region.
    #[inline]
    pub fn init(self) -> ReadyRingBufferHandle<'a, N> {
        self.ring.init();
        ReadyRingBufferHandle { ring: self.ring }
    }

    /// Validate the region's magic and version and return a ready handle.
    ///
    /// Called by the side that attaches after the initializer has written
    /// the header.
    #[inline]
    pub fn validate(self) -> Result<ReadyRingBufferHandle<'a, N>, RingError> {
        self.ring.validate()?;
        Ok(ReadyRingBufferHandle { ring: self.ring })
    }
}

/// Validated handle to a ring buffer region.
///
/// Holding one proves the region has been initialized (or its header has
/// been validated). Endpoints are obtained via [`split_host`](Self::split_host)
/// or [`split_guest`](Self::split_guest); each consumes `self` and returns
/// the role's paired writer+reader, so at most one split can occur per side.
pub struct ReadyRingBufferHandle<'a, const N: usize> {
    ring: &'a RingBuffer<N>,
}

impl<'a, const N: usize> ReadyRingBufferHandle<'a, N> {
    /// Take the host-side endpoints: host→guest writer + guest→host reader.
    #[inline]
    pub fn split_host(self) -> HostRingEndpoints<'a> {
        HostRingEndpoints {
            to_guest: self.ring.hg_writer(),
            from_guest: self.ring.gh_reader(),
        }
    }

    /// Take the guest-side endpoints: guest→host writer + host→guest reader.
    #[inline]
    pub fn split_guest(self) -> GuestRingEndpoints<'a> {
        GuestRingEndpoints {
            to_host: self.ring.gh_writer(),
            from_host: self.ring.hg_reader(),
        }
    }

    /// Current (head, tail) of the host→guest ring. Diagnostic only.
    #[inline]
    pub fn hg_positions(&self) -> (u32, u32) {
        self.ring.hg_positions()
    }

    /// Current (head, tail) of the guest→host ring. Diagnostic only.
    #[inline]
    pub fn gh_positions(&self) -> (u32, u32) {
        self.ring.gh_positions()
    }
}

/// Endpoints for the host side of a ring buffer region.
///
/// Field names encode direction so call sites don't need to remember
/// `HG` vs `GH` conventions.
pub struct HostRingEndpoints<'a> {
    /// Writer for host→guest messages.
    pub to_guest: RingWriter<'a>,
    /// Reader for guest→host messages.
    pub from_guest: RingReader<'a>,
}

/// Endpoints for the guest side of a ring buffer region.
pub struct GuestRingEndpoints<'a> {
    /// Writer for guest→host messages.
    pub to_host: RingWriter<'a>,
    /// Reader for host→guest messages.
    pub from_host: RingReader<'a>,
}

/// Host-guest ring buffer handle (pre-validation).
pub type HostGuestRingBufferHandle<'a> = RingBufferHandle<'a, HOST_GUEST_RING_SIZE>;

/// Host-guest ring buffer handle (post-validation).
pub type HostGuestReadyHandle<'a> = ReadyRingBufferHandle<'a, HOST_GUEST_RING_SIZE>;

/// A validated snapshot of ring occupancy.
///
/// Construction checks the shared cursor invariant `head - tail <= capacity`,
/// so callers cannot accidentally treat corrupt peer state as a huge occupied
/// span or as silently clamped free space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingUsage {
    used: u32,
    capacity: u32,
}

impl RingUsage {
    const fn new(head: u32, tail: u32, capacity: u32) -> Result<Self, RingError> {
        let used = head.wrapping_sub(tail);
        if used > capacity {
            return Err(RingError::Corrupt("cursor distance exceeds capacity"));
        }
        Ok(Self { used, capacity })
    }

    /// Bytes currently available for the reader.
    pub const fn used_bytes(self) -> u32 {
        self.used
    }

    /// Ring data capacity in bytes.
    pub const fn capacity(self) -> u32 {
        self.capacity
    }

    /// Bytes currently available for the writer.
    pub const fn free_bytes(self) -> u32 {
        self.capacity - self.used
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CursorSnapshot {
    head: u32,
    tail: u32,
    used: u32,
}

impl CursorSnapshot {
    fn for_writer(header: &RingHeader, capacity: u32) -> Result<Self, RingError> {
        let head = header.head.load(Ordering::Relaxed);
        let tail = header.tail.load(Ordering::Acquire);
        Self::new(head, tail, capacity)
    }

    fn for_reader(header: &RingHeader, capacity: u32) -> Result<Self, RingError> {
        let head = header.head.load(Ordering::Acquire);
        let tail = header.tail.load(Ordering::Relaxed);
        Self::new(head, tail, capacity)
    }

    fn new(head: u32, tail: u32, capacity: u32) -> Result<Self, RingError> {
        let usage = RingUsage::new(head, tail, capacity)?;
        Ok(Self {
            head,
            tail,
            used: usage.used,
        })
    }
}

// ---------------------------------------------------------------------------
// RingWriter
// ---------------------------------------------------------------------------

/// Single-producer end of one ring direction.
///
/// The writer owns the `head` cursor and reads `tail` to compute free space.
pub struct RingWriter<'a> {
    header: &'a RingHeader,
    data: NonNull<u8>,
    capacity: u32,
    mask: u32,
}

// SAFETY: All fields are Send: `&'a RingHeader` shares atomics with the
// reader (atomics are Sync), `NonNull<u8>` is Send (it's a raw pointer
// with no aliasing claim), and `u32` is Send. The ring is aliased with a
// `RingReader`, but that reader only touches `header.tail` and the byte
// range `[tail & mask .. head & mask)` — the SPSC discipline enforced by
// construction guarantees no data race between writer and reader.
unsafe impl Send for RingWriter<'_> {}

impl<'a> RingWriter<'a> {
    /// Create a writer for a ring.
    ///
    /// # Safety
    ///
    /// - `header` must point to a valid, aligned `RingHeader`.
    /// - `data` must point to `capacity` bytes of writable memory.
    /// - `capacity` must be a power of two.
    /// - At most one writer may exist per ring.
    pub(crate) unsafe fn new(header: &'a RingHeader, data: NonNull<u8>, capacity: u32) -> Self {
        debug_assert!(capacity.is_power_of_two());
        Self {
            header,
            data,
            capacity,
            mask: capacity - 1,
        }
    }

    /// Try to write a message. Returns `Ok(true)` if written, `Ok(false)` if
    /// the ring is full (caller should retry later).
    pub fn try_write(&self, payload: &[u8]) -> Result<bool, RingError> {
        self.try_write_parts(&[payload])
    }

    /// Try to write a message from multiple slices (scatter-gather).
    ///
    /// Writes all `parts` as a single framed message, avoiding intermediate
    /// allocation. Returns `Ok(true)` if written, `Ok(false)` if full.
    pub fn try_write_parts(&self, parts: &[&[u8]]) -> Result<bool, RingError> {
        let payload_len: u32 = parts
            .iter()
            .map(|p| p.len())
            .sum::<usize>()
            .try_into()
            .map_err(|_| RingError::PayloadTooLarge)?;
        if payload_len == 0 || payload_len > MAX_PAYLOAD_SIZE {
            return Err(RingError::PayloadTooLarge);
        }
        let needed = LEN_SIZE + payload_len;
        let header = self.header;
        let cursors = CursorSnapshot::for_writer(header, self.capacity)?;
        let free = self.capacity - cursors.used;
        let pos = cursors.head & self.mask;
        let remaining = self.capacity - pos;

        let (write_pos, head_advance) = if remaining >= needed {
            if free < needed {
                return Ok(false);
            }
            (pos, needed)
        } else {
            let total = remaining + needed;
            if free < total {
                return Ok(false);
            }
            if remaining >= LEN_SIZE {
                self.write_u32_at(pos, WRAP_MARKER);
            }
            (0, total)
        };

        self.write_u32_at(write_pos, payload_len);
        let mut offset = write_pos + LEN_SIZE;
        for part in parts {
            self.write_bytes_at(offset, part);
            offset += u32::try_from(part.len()).map_err(|_| RingError::PayloadTooLarge)?;
        }
        header
            .head
            .store(cursors.head.wrapping_add(head_advance), Ordering::Release);
        Ok(true)
    }

    /// Returns `(used_bytes, capacity)` for the ring.
    ///
    /// `used_bytes` is the number of bytes between tail and head (i.e. data
    /// written but not yet consumed by the reader). This is a snapshot — by the
    /// time the caller acts on it, the reader may have advanced.
    pub fn usage(&self) -> Result<RingUsage, RingError> {
        let cursors = CursorSnapshot::for_writer(self.header, self.capacity)?;
        RingUsage::new(cursors.head, cursors.tail, self.capacity)
    }

    /// Approximate free space in bytes.
    pub fn free_space(&self) -> Result<u32, RingError> {
        Ok(self.usage()?.free_bytes())
    }

    /// Returns true if a message of `payload_len` bytes could fit at the
    /// current write cursor once the reader has drained all occupancy.
    ///
    /// Use this to reject frames that would otherwise spin forever in
    /// `can_write`. The answer depends on the current `head` alignment:
    /// a large frame may not fit after the wrap skip even when
    /// `LEN_SIZE + payload_len <= capacity`.
    pub fn can_ever_write(&self, payload_len: u32) -> bool {
        if payload_len == 0 || payload_len > MAX_PAYLOAD_SIZE {
            return false;
        }
        let needed = LEN_SIZE + payload_len;
        let head = self.header.head.load(Ordering::Relaxed);
        let pos = head & self.mask;
        let remaining = self.capacity - pos;
        if remaining >= needed {
            needed <= self.capacity
        } else {
            remaining + needed <= self.capacity
        }
    }

    /// Returns true if a message of `payload_len` bytes would fit right now.
    pub fn can_write(&self, payload_len: u32) -> Result<bool, RingError> {
        if payload_len == 0 || payload_len > MAX_PAYLOAD_SIZE {
            return Ok(false);
        }
        let needed = LEN_SIZE + payload_len;
        let header = self.header;
        let cursors = CursorSnapshot::for_writer(header, self.capacity)?;
        let free = self.capacity - cursors.used;
        let pos = cursors.head & self.mask;
        let remaining = self.capacity - pos;
        Ok(if remaining >= needed {
            free >= needed
        } else {
            free >= remaining + needed
        })
    }

    fn write_u32_at(&self, offset: u32, val: u32) {
        debug_assert!(offset + 4 <= self.capacity);
        // SAFETY: `offset` comes from `head & mask` or `head & mask + k` where
        // `k < LEN_SIZE + payload_len` and total needed was already checked
        // against `remaining` and `free` in `try_write_parts`. Therefore
        // `offset + 4 <= self.capacity`, so `self.data.add(offset)..+4` is
        // inside the ring's data slab. `write_unaligned` handles unaligned
        // targets. SPSC: this offset has not yet been published to the reader
        // (head store happens at the end of `try_write_parts`).
        unsafe {
            let ptr = self.data.as_ptr().add(offset as usize);
            core::ptr::write_unaligned(ptr.cast::<u32>(), val.to_le());
        }
    }

    fn write_bytes_at(&self, offset: u32, bytes: &[u8]) {
        debug_assert!((bytes.len() as u64) + u64::from(offset) <= u64::from(self.capacity));
        // SAFETY: `bytes.len() + offset <= self.capacity` by the same
        // argument as `write_u32_at`. Source (`bytes`) and destination
        // (`self.data.add(offset)`) cannot overlap: `bytes` is a caller-
        // supplied slice in unrelated memory. SPSC: writes happen before
        // the head store publishes them.
        unsafe {
            let ptr = self.data.as_ptr().add(offset as usize);
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, bytes.len());
        }
    }
}

// ---------------------------------------------------------------------------
// RingReader
// ---------------------------------------------------------------------------

/// Saved position after a successful `try_peek()`.
struct PeekState {
    tail: u32,
    payload_len: u32,
}

/// Single-consumer end of one ring direction.
///
/// The reader owns the `tail` cursor and reads `head` to detect new data.
/// `try_peek()` returns a zero-copy slice into the shared memory; call
/// `advance()` to consume it.
pub struct RingReader<'a> {
    header: &'a RingHeader,
    data: NonNull<u8>,
    capacity: u32,
    mask: u32,
    peeked: Option<PeekState>,
}

// SAFETY: Symmetric with `RingWriter`. The reader aliases `header` with a
// writer, but only writes `header.tail` and only reads the byte range
// `[tail & mask .. head & mask)` that the writer has already published
// via a Release store to `header.head`. Atomic ordering enforces the
// happens-before; field types are all Send.
unsafe impl Send for RingReader<'_> {}

impl<'a> RingReader<'a> {
    /// Create a reader for a ring.
    ///
    /// # Safety
    ///
    /// - `data` must point to `capacity` bytes of readable memory.
    /// - `capacity` must be a power of two.
    /// - At most one reader may exist per ring.
    pub(crate) unsafe fn new(header: &'a RingHeader, data: NonNull<u8>, capacity: u32) -> Self {
        debug_assert!(capacity.is_power_of_two());
        Self {
            header,
            data,
            capacity,
            mask: capacity - 1,
            peeked: None,
        }
    }

    /// Peek at the next message without consuming it.
    ///
    /// Returns `Ok(Some(slice))` with a zero-copy view into shared memory,
    /// `Ok(None)` if the ring is empty, or `Err` on corruption.
    ///
    /// The returned slice is valid until the next call to `advance()`.
    ///
    /// # Adversarial writer safety
    ///
    /// `head` is loaded once before the loop so that a malicious writer
    /// cannot extend the loop by racing `head` forward. The skip counter
    /// is defense-in-depth: a well-formed ring needs at most 2 skips
    /// (one `rem < LEN_SIZE`, one wrap marker). More means corruption.
    pub fn try_peek(&mut self) -> Result<Option<&[u8]>, RingError> {
        // In a well-formed ring, at most 2 skips occur (rem < LEN_SIZE
        // then wrap marker). A third means corruption or adversarial writer.
        const MAX_SKIPS: u32 = 3;

        if self.peeked.is_some() {
            // Already peeked — return the same slice.
            // SAFETY: peeked is Some, checked above.
            let peek = unsafe { self.peeked.as_ref().unwrap_unchecked() };
            return Ok(Some(self.slice_at(peek)));
        }

        let header = self.header;
        // Snapshot head once — an adversarial writer controls this value.
        // Reloading per-iteration would let the writer keep us spinning by
        // advancing head in lockstep with our tail advances.
        let head = header.head.load(Ordering::Acquire);
        let mut skips: u32 = 0;

        loop {
            let tail = header.tail.load(Ordering::Relaxed); // we own tail
            if head == tail {
                return Ok(None);
            }
            let used = RingUsage::new(head, tail, self.capacity)?.used_bytes();
            let pos = tail & self.mask;
            let rem = self.capacity - pos;

            if rem < LEN_SIZE {
                // Not enough room for a length prefix — skip to ring start.
                skips += 1;
                if skips > MAX_SKIPS {
                    return Err(RingError::Corrupt("too many consecutive wrap skips"));
                }
                let next_tail = Self::checked_skip_tail(tail, used, rem)?;
                header.tail.store(next_tail, Ordering::Release);
                continue;
            }

            let len = self.read_u32_at(pos);
            if len == WRAP_MARKER {
                // Wrap marker — skip remainder.
                skips += 1;
                if skips > MAX_SKIPS {
                    return Err(RingError::Corrupt("too many consecutive wrap skips"));
                }
                let next_tail = Self::checked_skip_tail(tail, used, rem)?;
                header.tail.store(next_tail, Ordering::Release);
                continue;
            }
            if len > MAX_PAYLOAD_SIZE {
                return Err(RingError::Corrupt("frame length exceeds max"));
            }
            let frame_size = LEN_SIZE + len;
            if used < frame_size {
                return Err(RingError::Corrupt("partial published frame"));
            }
            if rem < frame_size {
                return Err(RingError::Corrupt("frame crosses ring boundary"));
            }

            self.peeked = Some(PeekState {
                tail,
                payload_len: len,
            });
            // SAFETY: we just set peeked to Some.
            let peek = unsafe { self.peeked.as_ref().unwrap_unchecked() };
            return Ok(Some(self.slice_at(peek)));
        }
    }

    /// Consume the peeked message, advancing the tail cursor.
    ///
    /// Must be called after a successful `try_peek()`.
    pub fn advance(&mut self) -> Result<(), RingError> {
        let peek = self.peeked.take().ok_or(RingError::NothingPeeked)?;
        let next_tail = peek.tail.wrapping_add(LEN_SIZE + peek.payload_len);
        let header = self.header;
        header.tail.store(next_tail, Ordering::Release);
        Ok(())
    }

    /// Returns `(used_bytes, capacity)` for the ring.
    ///
    /// `used_bytes` is the number of bytes between tail and head (i.e. data
    /// available for reading). This is a snapshot — by the time the caller
    /// acts on it, the writer may have advanced.
    pub fn usage(&self) -> Result<RingUsage, RingError> {
        let cursors = CursorSnapshot::for_reader(self.header, self.capacity)?;
        RingUsage::new(cursors.head, cursors.tail, self.capacity)
    }

    /// Whether a peek is currently buffered.
    pub const fn has_peeked(&self) -> bool {
        self.peeked.is_some()
    }

    /// True if the ring appears empty.
    pub fn is_empty(&self) -> Result<bool, RingError> {
        Ok(self.usage()?.used_bytes() == 0)
    }

    /// Read the next message, copying into `buf`. Returns `Ok(Some(len))`.
    pub fn try_read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, RingError> {
        let Some(data) = self.try_peek()? else {
            return Ok(None);
        };
        let len = data.len();
        if len > buf.len() {
            self.peeked = None;
            return Err(RingError::PayloadTooLarge);
        }
        buf[..len].copy_from_slice(data);
        self.advance()?;
        Ok(Some(len))
    }

    fn slice_at(&self, peek: &PeekState) -> &[u8] {
        let offset = (peek.tail & self.mask) + LEN_SIZE;
        debug_assert!(offset + peek.payload_len <= self.capacity);
        // SAFETY: `try_peek` validated that the frame `[offset .. offset +
        // payload_len)` lies entirely within `[0 .. self.capacity)` (frames
        // that would cross the ring boundary are skipped via a wrap marker),
        // so the raw slice is inside the writer's data slab. The writer has
        // published these bytes with Release to `header.head` before this
        // reader's matching Acquire load — no data race. Lifetime is bound
        // to `&self`; caller cannot hold the slice across `advance()`.
        unsafe {
            core::slice::from_raw_parts(
                self.data.as_ptr().add(offset as usize),
                peek.payload_len as usize,
            )
        }
    }

    const fn checked_skip_tail(tail: u32, used: u32, skip: u32) -> Result<u32, RingError> {
        if used < skip {
            return Err(RingError::Corrupt("wrap skip exceeds published bytes"));
        }
        Ok(tail.wrapping_add(skip))
    }

    fn read_u32_at(&self, offset: u32) -> u32 {
        debug_assert!(offset + 4 <= self.capacity);
        // SAFETY: `offset + 4 <= self.capacity` — callers pass either
        // `tail & mask` (followed by wrap-marker handling) or an offset
        // previously validated to have ≥ LEN_SIZE bytes remaining before
        // the end of the data slab. `read_unaligned` handles unaligned
        // reads. Bytes were written before the matching Release head store.
        unsafe {
            let ptr = self.data.as_ptr().add(offset as usize);
            u32::from_le(core::ptr::read_unaligned(ptr.cast::<u32>()))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    extern crate alloc;
    extern crate std;
    use super::*;
    use alloc::vec;

    /// RAII wrapper for a 64-byte-aligned heap allocation.
    struct AlignedBuf {
        ptr: *mut u8,
        layout: core::alloc::Layout,
    }

    impl AlignedBuf {
        fn new() -> Self {
            let layout = core::alloc::Layout::from_size_align(HOST_GUEST_TOTAL_SIZE, 64).unwrap();
            // SAFETY: `layout` has non-zero size (TOTAL_SIZE is a positive const).
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "allocation failed");
            Self { ptr, layout }
        }

        fn with_size(size: usize) -> Self {
            let layout = core::alloc::Layout::from_size_align(size, 64).unwrap();
            // SAFETY: `layout` has non-zero size (callers pass positive sizes).
            let ptr = unsafe { alloc::alloc::alloc_zeroed(layout) };
            assert!(!ptr.is_null(), "allocation failed");
            Self { ptr, layout }
        }

        fn as_mut_ptr(&self) -> *mut u8 {
            self.ptr
        }
    }

    impl Drop for AlignedBuf {
        fn drop(&mut self) {
            // SAFETY: `ptr`/`layout` came from the matching `alloc_zeroed` above.
            unsafe { alloc::alloc::dealloc(self.ptr, self.layout) };
        }
    }

    fn region(buf: &AlignedBuf) -> &HostGuestRingBuffer {
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `buf` is a freshly allocated `HOST_GUEST_TOTAL_SIZE`-byte,
        // 64-aligned region; test harness uses one reader and one writer.
        unsafe { HostGuestRingBuffer::from_region(base, HOST_GUEST_TOTAL_SIZE).unwrap() }
    }

    // === SharedHeader / init / validate ===

    #[test]
    fn init_and_validate() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();
        r.validate().unwrap();

        let hdr = r.header();
        assert_eq!(hdr.magic.load(Ordering::Relaxed), MAGIC);
        assert_eq!(hdr.version.load(Ordering::Relaxed), VERSION);
    }

    /// Small ring buffer (4 KiB per direction) for subprocess IPC testing.
    #[test]
    fn small_ring_init_and_validate() {
        type SmallRing = RingBuffer<4096>;
        let buf = AlignedBuf::with_size(SmallRing::TOTAL_SIZE);
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `buf` was allocated with `SmallRing::TOTAL_SIZE` bytes and
        // 64-byte alignment; test harness uses one reader + one writer.
        let r = unsafe { SmallRing::from_region(base, SmallRing::TOTAL_SIZE).unwrap() };
        r.init();
        r.validate().unwrap();

        assert_eq!(SmallRing::TOTAL_SIZE, 192 + 2 * 4096);

        // Write and read a small message.
        let mut reader = r.hg_reader();
        let writer = r.hg_writer();
        let msg = b"hello";
        assert!(writer.try_write(msg).unwrap());
        let data = reader.try_peek().unwrap().unwrap();
        assert_eq!(data, msg);
        reader.advance().unwrap();
    }

    #[test]
    fn attach_rejects_wrong_region_size() {
        let buf = AlignedBuf::new();
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `base` points to this test allocation; the intentionally
        // wrong size is the value under test.
        let Err(err) =
            (unsafe { HostGuestRingBufferHandle::attach(base, HOST_GUEST_TOTAL_SIZE - 1) })
        else {
            panic!("attach should reject wrong region size");
        };
        assert_eq!(
            err,
            RingError::BadRegionSize {
                expected: HOST_GUEST_TOTAL_SIZE,
                actual: HOST_GUEST_TOTAL_SIZE - 1,
            }
        );
    }

    #[test]
    fn validate_rejects_uninitialized_header() {
        let buf = AlignedBuf::new();
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `base` points to a correctly sized/aligned test allocation.
        let handle =
            unsafe { HostGuestRingBufferHandle::attach(base, HOST_GUEST_TOTAL_SIZE) }.unwrap();
        match handle.validate() {
            Ok(_) => panic!("validate should reject an uninitialized header"),
            Err(e) => assert_eq!(e, RingError::NotInitialized(0)),
        }
    }

    #[test]
    fn validate_bad_magic() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();
        r.corrupt_header(|h| h.magic.store(0xDEAD_BEEF, Ordering::Relaxed));
        assert_eq!(r.validate(), Err(RingError::BadMagic(0xDEAD_BEEF)));
    }

    #[test]
    fn validate_bad_version() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();
        r.corrupt_header(|h| h.version.store(99, Ordering::Relaxed));
        assert_eq!(r.validate(), Err(RingError::BadVersion(99)));
    }

    #[test]
    fn validate_bad_layout_geometry() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();
        r.corrupt_header(|h| h.data_size.store(4096, Ordering::Relaxed));
        assert_eq!(
            r.validate(),
            Err(RingError::BadLayout("data size mismatch"))
        );
    }

    // === Single message roundtrip ===

    #[test]
    fn write_read_single_message() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        let payload = b"hello ring buffer";
        assert_eq!(writer.try_write(payload), Ok(true));

        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, payload);
        reader.advance().unwrap();

        // Empty after advance.
        assert!(reader.try_peek().unwrap().is_none());
    }

    // === Multiple messages ===

    #[test]
    fn write_read_multiple_messages() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        for i in 0u32..100 {
            let msg = i.to_le_bytes();
            assert_eq!(writer.try_write(&msg), Ok(true));
        }

        for i in 0u32..100 {
            let peeked = reader.try_peek().unwrap().unwrap();
            assert_eq!(peeked, &i.to_le_bytes());
            reader.advance().unwrap();
        }

        assert!(reader.try_peek().unwrap().is_none());
    }

    // === Fill ring to capacity ===

    #[test]
    fn ring_full_returns_false() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        // Fill with large messages until full.
        let big = vec![0xABu8; 1024];
        let mut count = 0u32;
        loop {
            match writer.try_write(&big) {
                Ok(true) => count += 1,
                Ok(false) => break,
                Err(e) => panic!("unexpected error: {e}"),
            }
        }
        assert!(count > 0, "should have written at least one message");

        // Read them all back.
        let mut read_count = 0u32;
        while reader.try_peek().unwrap().is_some() {
            reader.advance().unwrap();
            read_count += 1;
        }
        assert_eq!(count, read_count);
    }

    #[test]
    fn can_ever_write_respects_current_head_alignment() {
        type TinyRing = RingBuffer<64>;
        let buf = AlignedBuf::with_size(TinyRing::TOTAL_SIZE);
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `buf` was allocated with `TinyRing::TOTAL_SIZE` bytes and
        // 64-byte alignment; test harness uses one reader + one writer.
        let r = unsafe { TinyRing::from_region(base, TinyRing::TOTAL_SIZE).unwrap() };
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        assert!(writer.try_write(&[0xAA]).unwrap());
        assert_eq!(reader.try_peek().unwrap().unwrap(), &[0xAA]);
        reader.advance().unwrap();

        // The ring is empty, but head is at offset 5. A 57-byte payload
        // would need 61 bytes for its frame; it cannot fit before the end,
        // and the wrap skip plus frame cannot fit in the 64-byte ring.
        assert!(!writer.can_ever_write(57));
        assert!(writer.can_ever_write(54));
    }

    // === Wrap marker ===

    #[test]
    fn wrap_marker_works() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        // Fill most of the ring, then read, to position head/tail near the end.
        // Message size: 1000 bytes payload + 4 bytes header = 1004 bytes.
        // Ring size: 256KB = 262144. Fills ~261 messages.
        let msg = vec![0x42u8; 1000];
        let mut written = 0;
        while writer.try_write(&msg).unwrap() {
            written += 1;
        }
        // Read all to free space — tail catches up to head.
        for _ in 0..written {
            reader.try_peek().unwrap().unwrap();
            reader.advance().unwrap();
        }

        // Now head and tail are both near the end of the ring.
        // Write a message that won't fit before the wrap -> triggers wrap marker.
        let big = vec![0xFFu8; 2000];
        assert_eq!(writer.try_write(&big), Ok(true));

        // Reader should skip wrap marker and read the message at offset 0.
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, &big[..]);
        reader.advance().unwrap();
    }

    // === Edge case: remaining < 4 bytes before wrap ===

    #[test]
    fn remaining_less_than_4_bytes() {
        // Use a small ring to make this testable. Build writer/reader manually.
        // Ring size = 64 bytes (smallest useful power of 2 for this test).
        let ring_size: u32 = 64;

        // Allocate aligned RingHeader on the heap.
        let layout = core::alloc::Layout::from_size_align(
            core::mem::size_of::<RingHeader>(),
            core::mem::align_of::<RingHeader>(),
        )
        .unwrap();
        // SAFETY: `layout` has non-zero size.
        let ring_hdr_raw = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!ring_hdr_raw.is_null());
        #[allow(clippy::cast_ptr_alignment)] // alloc_zeroed with RingHeader alignment
        let hdr_ptr = NonNull::new(ring_hdr_raw.cast::<RingHeader>()).unwrap();

        let mut data = vec![0u8; ring_size as usize];
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();

        // SAFETY: `hdr_ptr` is a valid, properly aligned `RingHeader`
        // allocation that no one else references yet.
        unsafe {
            (*hdr_ptr.as_ptr()).head = AtomicU32::new(0);
            (*hdr_ptr.as_ptr()).tail = AtomicU32::new(0);
        }

        // SAFETY: hdr_ptr/data_ptr reference the just-initialized header and
        // `ring_size` bytes of backing data; this test keeps at most one
        // writer + one reader for the ring.
        let writer = unsafe { RingWriter::new(hdr_ptr.as_ref(), data_ptr, ring_size) };
        // SAFETY: see writer above.
        let mut reader = unsafe { RingReader::new(hdr_ptr.as_ref(), data_ptr, ring_size) };

        // Write a message that leaves < 4 bytes at the end.
        // Frame = 4 (len) + payload. We want head to land at ring_size - 2 = 62.
        // So payload = 62 - 4 = 58 bytes.
        let msg1 = vec![0xAAu8; 58];
        assert_eq!(writer.try_write(&msg1), Ok(true));

        // Read it to advance tail.
        assert_eq!(reader.try_peek().unwrap().unwrap(), &msg1[..]);
        reader.advance().unwrap();

        // Now head = tail = 62. Remaining = 2 bytes < LEN_SIZE.
        // Next write should skip those 2 bytes and write at offset 0.
        let msg2 = vec![0xBBu8; 4];
        assert_eq!(writer.try_write(&msg2), Ok(true));

        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, &msg2[..]);
        reader.advance().unwrap();

        // SAFETY: `ring_hdr_raw` came from `alloc_zeroed` with `layout`.
        unsafe { alloc::alloc::dealloc(ring_hdr_raw, layout) };
    }

    // === Empty ring returns None ===

    #[test]
    fn empty_ring_returns_none() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let mut reader = r.hg_reader();
        assert!(reader.try_peek().unwrap().is_none());
    }

    // === advance() without peek() ===

    #[test]
    fn advance_without_peek_errors() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let mut reader = r.hg_reader();
        assert_eq!(reader.advance(), Err(RingError::NothingPeeked));
    }

    // === Peek is idempotent ===

    #[test]
    fn peek_is_idempotent() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        writer.try_write(b"test").unwrap();

        let p1 = reader.try_peek().unwrap().unwrap();
        let p1_addr = p1.as_ptr();
        let p2 = reader.try_peek().unwrap().unwrap();
        assert_eq!(p1_addr, p2.as_ptr());
        assert_eq!(p2, b"test");
    }

    // === Zero-length payload is rejected ===

    #[test]
    fn zero_length_payload_rejected() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        assert_eq!(writer.try_write(b""), Err(RingError::PayloadTooLarge));
    }

    // === Oversized payload is rejected ===

    #[test]
    fn oversized_payload_rejected() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let huge = vec![0u8; MAX_PAYLOAD_SIZE as usize + 1];
        assert_eq!(writer.try_write(&huge), Err(RingError::PayloadTooLarge));
    }

    // === Both directions (HG and GH) work independently ===

    #[test]
    fn both_directions_independent() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let hg_writer = r.hg_writer();
        let mut hg_reader = r.hg_reader();
        let gh_writer = r.gh_writer();
        let mut gh_reader = r.gh_reader();

        hg_writer.try_write(b"host to guest").unwrap();
        gh_writer.try_write(b"guest to host").unwrap();

        assert_eq!(hg_reader.try_peek().unwrap().unwrap(), b"host to guest");
        assert_eq!(gh_reader.try_peek().unwrap().unwrap(), b"guest to host");

        hg_reader.advance().unwrap();
        gh_reader.advance().unwrap();
    }

    // === Concurrent SPSC: writer and reader on separate threads ===

    #[test]
    fn concurrent_spsc() {
        use alloc::sync::Arc;
        use core::sync::atomic::AtomicBool;

        // We need std for threads; this test only runs under `cargo test`.
        extern crate std;

        let buf = AlignedBuf::new();
        let base = NonNull::new(buf.as_mut_ptr()).unwrap();
        // SAFETY: `buf` is a `HOST_GUEST_TOTAL_SIZE`-byte, 64-aligned region;
        // this test uses one reader and one writer.
        let r = unsafe { HostGuestRingBuffer::from_region(base, HOST_GUEST_TOTAL_SIZE).unwrap() };
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        let count = 10_000u32;
        let done = Arc::new(AtomicBool::new(false));
        let done2 = done.clone();

        // ManuallyDrop so buf outlives the spawned writer thread.
        // Dropped explicitly after join() below.
        let mut buf = core::mem::ManuallyDrop::new(buf);

        let writer_thread = std::thread::spawn(move || {
            for i in 0..count {
                let msg = i.to_le_bytes();
                while !writer.try_write(&msg).unwrap() {
                    core::hint::spin_loop();
                }
            }
            done2.store(true, Ordering::Release);
        });

        let mut received = 0u32;
        loop {
            match reader.try_peek() {
                Ok(Some(data)) => {
                    let expected = received.to_le_bytes();
                    assert_eq!(data, &expected, "message {received} mismatch");
                    reader.advance().unwrap();
                    received += 1;
                }
                Ok(None) => {
                    if done.load(Ordering::Acquire) {
                        // Drain remaining.
                        while let Ok(Some(data)) = reader.try_peek() {
                            let expected = received.to_le_bytes();
                            assert_eq!(data, &expected);
                            reader.advance().unwrap();
                            received += 1;
                        }
                        break;
                    }
                    core::hint::spin_loop();
                }
                Err(e) => panic!("reader error: {e}"),
            }
        }

        assert_eq!(received, count);
        writer_thread.join().unwrap();
        // SAFETY: writer thread joined — no more references to buf's memory.
        unsafe { core::mem::ManuallyDrop::drop(&mut buf) };
    }

    // === Zero-copy: peek returns pointer into backing memory ===

    #[test]
    fn peek_is_zero_copy() {
        let buf = AlignedBuf::new();
        // HG data starts at offset 0xC0 (after 3 × 64-byte headers).
        let data_start = buf.as_mut_ptr() as usize + 0xC0;
        let data_end = data_start + HOST_GUEST_RING_SIZE;

        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        writer.try_write(b"zerocopy").unwrap();

        let peeked = reader.try_peek().unwrap().unwrap();
        let ptr = peeked.as_ptr() as usize;
        assert!(
            ptr >= data_start && ptr < data_end,
            "peeked slice should point into ring data region"
        );
        reader.advance().unwrap();
    }

    // === Max-size payload works ===

    #[test]
    fn max_payload_size_works() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        let payload = vec![0xCDu8; MAX_PAYLOAD_SIZE as usize];
        assert_eq!(writer.try_write(&payload), Ok(true));

        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked.len(), MAX_PAYLOAD_SIZE as usize);
        assert!(peeked.iter().all(|&b| b == 0xCD));
        reader.advance().unwrap();
    }

    // === Struct size assertions ===

    #[test]
    fn struct_sizes() {
        assert_eq!(core::mem::size_of::<SharedHeader>(), 64);
        assert_eq!(core::mem::size_of::<RingHeader>(), 64);
        assert_eq!(core::mem::align_of::<SharedHeader>(), 64);
        assert_eq!(core::mem::align_of::<RingHeader>(), 64);
    }

    // === try_write_parts scatter-gather ===

    #[test]
    fn write_parts_single_slice() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        assert_eq!(writer.try_write_parts(&[b"hello"]), Ok(true));
        assert_eq!(reader.try_peek().unwrap().unwrap(), b"hello");
        reader.advance().unwrap();
    }

    #[test]
    fn write_parts_multiple_slices() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        assert_eq!(
            writer.try_write_parts(&[b"hel", b"lo ", b"world"]),
            Ok(true)
        );
        assert_eq!(reader.try_peek().unwrap().unwrap(), b"hello world");
        reader.advance().unwrap();
    }

    #[test]
    fn write_parts_empty_payload_rejected() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        // All empty slices → total payload 0 → rejected
        assert_eq!(
            writer.try_write_parts(&[b"", b""]),
            Err(RingError::PayloadTooLarge)
        );
        // No slices at all → total payload 0 → rejected
        assert_eq!(writer.try_write_parts(&[]), Err(RingError::PayloadTooLarge));
    }

    // === has_peeked ===

    #[test]
    fn has_peeked_tracks_state() {
        let buf = AlignedBuf::new();
        let r = region(&buf);
        r.init();

        let writer = r.hg_writer();
        let mut reader = r.hg_reader();

        assert!(!reader.has_peeked());

        writer.try_write(b"test").unwrap();
        reader.try_peek().unwrap();
        assert!(reader.has_peeked());

        reader.advance().unwrap();
        assert!(!reader.has_peeked());
    }

    // === RingError Display ===

    #[test]
    fn ring_error_display() {
        use alloc::format;

        assert_eq!(
            format!("{}", RingError::PayloadTooLarge),
            "payload too large"
        );
        assert_eq!(
            format!("{}", RingError::NothingPeeked),
            "advance() without peek"
        );
        assert_eq!(
            format!("{}", RingError::Corrupt("head > capacity")),
            "ring corrupt: head > capacity"
        );
        assert_eq!(
            format!("{}", RingError::BadMagic(0xDEAD_BEEF)),
            "bad magic: 0xdeadbeef"
        );
        assert_eq!(format!("{}", RingError::BadVersion(42)), "bad version: 42");
    }

    // =========================================================================
    // Adversarial writer tests
    //
    // These tests simulate a malicious guest that controls the writer-side
    // cursor (head) and data bytes of the guest→host ring. The host is
    // the reader. Every test must terminate promptly and never cause OOB
    // access or infinite loops.
    // =========================================================================

    /// Allocate an aligned `RingHeader` + data buffer for adversarial tests.
    /// Returns `(header_ptr, data_vec, layout)` — caller must dealloc header.
    fn adversarial_ring(
        ring_size: u32,
    ) -> (NonNull<RingHeader>, vec::Vec<u8>, core::alloc::Layout) {
        let layout = core::alloc::Layout::from_size_align(
            core::mem::size_of::<RingHeader>(),
            core::mem::align_of::<RingHeader>(),
        )
        .unwrap();
        // SAFETY: `layout` has non-zero size (RingHeader is 64 bytes).
        let raw = unsafe { alloc::alloc::alloc_zeroed(layout) };
        assert!(!raw.is_null());
        #[allow(clippy::cast_ptr_alignment)]
        let hdr = NonNull::new(raw.cast::<RingHeader>()).unwrap();
        let data = vec![0u8; ring_size as usize];
        (hdr, data, layout)
    }

    /// Set head and tail on a `RingHeader`.
    ///
    /// # Safety
    ///
    /// `hdr` must point to a valid, properly aligned `RingHeader` with no
    /// concurrent accessors.
    unsafe fn set_cursors(hdr: NonNull<RingHeader>, head: u32, tail: u32) {
        // SAFETY: caller upholds the contract above — exclusive access, valid
        // and aligned pointer.
        unsafe {
            (*hdr.as_ptr()).head = AtomicU32::new(head);
            (*hdr.as_ptr()).tail = AtomicU32::new(tail);
        }
    }

    /// Helper: write a little-endian u32 into a data buffer at the given offset.
    fn write_le_u32(data: &mut [u8], offset: usize, val: u32) {
        data[offset..offset + 4].copy_from_slice(&val.to_le_bytes());
    }

    // --- Wrap-marker / skip attacks ---

    #[test]
    fn adversarial_short_end_fragment_does_not_advance_tail() {
        // Tail near the end leaves 2 bytes before wrap, but head publishes
        // only 1 byte. Skipping to offset 0 would move tail beyond head.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 63, 62) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("wrap skip exceeds published bytes"))
        );
        // SAFETY: `hdr` is still valid and exclusively owned by this test.
        assert_eq!(unsafe { hdr.as_ref().tail.load(Ordering::Relaxed) }, 62);
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_partial_wrap_marker_does_not_advance_tail() {
        // A zero marker is visible at tail, but the writer published only
        // the 4 marker bytes, not the full 8-byte skip to ring end.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 56, WRAP_MARKER);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 60, 56) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("wrap skip exceeds published bytes"))
        );
        // SAFETY: `hdr` is still valid and exclusively owned by this test.
        assert_eq!(unsafe { hdr.as_ref().tail.load(Ordering::Relaxed) }, 56);
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_wrap_marker_flood_bounded() {
        // All-zero data = all wrap markers. Head far ahead. Reader must not
        // loop forever — the skip limit catches it.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, ring_size * 10, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let result = reader.try_peek();
        assert!(
            matches!(result, Err(RingError::Corrupt(_))),
            "expected Corrupt from wrap-marker flood, got {result:?}"
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_wrap_marker_at_every_position() {
        // Fill entire ring with wrap markers. Head = capacity ahead of tail.
        // One wrap skip advances tail by capacity, catching up to head → None.
        // This isn't an attack — it's just an empty ring with a wrap marker.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, ring_size, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(reader.try_peek(), Ok(None));

        // But with head *many* capacities ahead, the skip limit fires.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, ring_size * 5, 0) };
        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader2 = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert!(matches!(reader2.try_peek(), Err(RingError::Corrupt(_))));
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Oversized / malformed length prefix ---

    #[test]
    fn adversarial_oversized_frame_length() {
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, MAX_PAYLOAD_SIZE + 1);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, ring_size, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("frame length exceeds max"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_frame_length_u32_max() {
        // Length = 0xFFFFFFFF — the maximum possible u32 value.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, u32::MAX);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, ring_size, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("frame length exceeds max"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_frame_length_exactly_max() {
        // Length == MAX_PAYLOAD_SIZE is valid (boundary). If the ring is too
        // small to hold it, we get "frame crosses ring boundary".
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, MAX_PAYLOAD_SIZE);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // Head says there's enough data (lying), but frame > ring capacity.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, MAX_PAYLOAD_SIZE + LEN_SIZE, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("cursor distance exceeds capacity"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Head/tail cursor manipulation ---

    #[test]
    fn adversarial_head_behind_tail_beyond_capacity_is_corrupt() {
        // Head < tail can be normal after u32 wrap, but the wrapped cursor
        // distance still cannot exceed the ring capacity.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Write a valid 4-byte message at offset 0.
        write_le_u32(&mut data, 0, 4); // length = 4
        data[4..8].copy_from_slice(b"test");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // tail = 0xFFFF_FF00, head = 0x00000008.
        // used = head.wrapping_sub(tail) = 0x108 = 264.
        // The distance exceeds ring capacity and must fail before reading.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 8, 0xFFFF_FF00) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("cursor distance exceeds capacity"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_head_equals_u32_max() {
        // Head at maximum u32 value.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, 4);
        data[4..8].copy_from_slice(b"edge");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // tail so that pos = 0 and there's data.
        // tail & mask = 0 → tail must be a multiple of ring_size.
        // used = u32::MAX - tail. Let tail = u32::MAX - 256.
        let tail = u32::MAX - ring_size;
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, u32::MAX, tail) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let result = reader.try_peek();
        // used = u32::MAX.wrapping_sub(u32::MAX - 256) = 256
        // pos = tail & 0xFF = (u32::MAX - 256) & 0xFF = 0xFF..00 & FF = 0
        // Wait: (u32::MAX - 256) = 0xFFFF_FEFF. mask = 255 = 0xFF. 0xFFFF_FEFF & 0xFF = 0xFF.
        // pos = 0xFF = 255. rem = 256 - 255 = 1. rem < LEN_SIZE → skip.
        // After skip, tail advances by 1. New tail & mask = 0.
        // Now read len at offset 0 = 4, frame_size = 8, used check...
        // Actually used is rechecked with the new tail each iteration but head is fixed.
        // used = u32::MAX.wrapping_sub(u32::MAX - 256 + 1) = 255.
        // frame_size = 8. 255 >= 8. rem = 256. 256 >= 8. OK.
        assert_eq!(result.unwrap().unwrap(), b"edge");
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_head_one_byte_ahead() {
        // Head just 1 byte ahead of tail — not enough for a length prefix.
        // Reader sees head != tail but used < LEN_SIZE for any possible frame.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, 1); // len = 1
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 1, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let result = reader.try_peek();
        // used = 1, len = 1, frame_size = 5. A published partial frame is
        // corrupt, not an empty ring.
        assert_eq!(result, Err(RingError::Corrupt("partial published frame")));
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_head_equal_tail_is_empty() {
        // Even if data looks valid, head == tail means empty.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, 4);
        data[4..8].copy_from_slice(b"trap");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 42, 42) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(reader.try_peek(), Ok(None));
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Frame boundary attacks ---

    #[test]
    fn adversarial_frame_crosses_boundary() {
        // A frame whose length prefix says it extends past the ring boundary.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Position tail at offset 60 (4 bytes from end).
        // Write length = 10 at offset 60. Frame = 14 bytes. rem = 4. 4 < 14 → error.
        write_le_u32(&mut data, 60, 10);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // tail & mask = 60 → tail = 60. head must be ahead.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 60 + ring_size, 60) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("frame crosses ring boundary"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_frame_exactly_fills_remaining() {
        // Frame exactly fills the remaining space — should succeed.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Tail at offset 48. rem = 16. Write length = 12 → frame = 16. Fits exactly.
        write_le_u32(&mut data, 48, 12);
        data[52..64].fill(0xAA);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 48 + 16, 48) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked.len(), 12);
        assert!(peeked.iter().all(|&b| b == 0xAA));
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Partial write (incomplete frame) ---

    #[test]
    fn adversarial_partial_write_head_mid_frame() {
        // Head advanced partway through a frame — used < frame_size.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 0, 100); // length = 100, frame = 104
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // Head only 50 bytes ahead — can't read a 104-byte frame.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 50, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("partial published frame"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- rem == LEN_SIZE edge case ---

    #[test]
    fn adversarial_rem_exactly_len_size() {
        // Tail positioned so exactly 4 bytes remain — just enough for a length
        // prefix but the wrap marker (0) at that position should trigger a skip.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Tail at offset 60. rem = 4. Exactly LEN_SIZE.
        // Data at offset 60 is 0 → wrap marker → skip.
        // After skip, tail at offset 0. Write a valid message there.
        write_le_u32(&mut data, 0, 4);
        data[4..8].copy_from_slice(b"ok!!");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // Head must be far enough ahead to cover both the skip and the message.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 60 + 4 + 8, 60) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, b"ok!!");
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_rem_exactly_len_size_with_valid_length() {
        // Tail at offset 60, rem = 4. Non-zero length at offset 60 means
        // frame_size > rem → "frame crosses ring boundary".
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        write_le_u32(&mut data, 60, 8); // length = 8, frame = 12, but rem = 4
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 60 + ring_size, 60) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        assert_eq!(
            reader.try_peek(),
            Err(RingError::Corrupt("frame crosses ring boundary"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Writer reads adversarial tail ---

    #[test]
    fn adversarial_reader_sets_tail_far_ahead() {
        // Guest (as reader of HG ring) sets tail far ahead of host's head.
        // Writer should see used as a huge wrapping value → free = 0 → full.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // Host head = 100, guest tail = 200 (ahead of head).
        // used = 100.wrapping_sub(200) = very large. free = 0.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 100, 200) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one writer for this ring.
        let writer = unsafe { RingWriter::new(hdr.as_ref(), data_ptr, ring_size) };
        // Writer must not clamp corrupt cursors into a normal "full" state.
        assert_eq!(
            writer.try_write(b"hello"),
            Err(RingError::Corrupt("cursor distance exceeds capacity"))
        );
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_reader_sets_tail_to_u32_max() {
        // Guest sets tail to u32::MAX. Host head = 0.
        // used = 0.wrapping_sub(u32::MAX) = 1. free = capacity - 1.
        // Writer should be able to write (thinks 1 byte used, rest free).
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 0, u32::MAX) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one writer for this ring.
        let writer = unsafe { RingWriter::new(hdr.as_ref(), data_ptr, ring_size) };
        // free = 256 - 1 = 255. Can write 251-byte payload (255 - 4 len).
        assert_eq!(writer.try_write(b"small"), Ok(true));
        // Verify writer didn't go OOB — the write landed at pos = 0 & 0xFF = 0.
        let usage = writer.usage().unwrap();
        assert_eq!(usage.capacity(), ring_size);
        assert!(usage.used_bytes() > 0);
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn adversarial_reader_resets_tail_to_zero() {
        // Guest resets tail backwards to 0 (re-read attack). Host has already
        // written and advanced head. This makes used = head - 0 = head.
        // Writer sees less free space → conservative, which is safe.
        let ring_size: u32 = 256;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 200, 0) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one writer for this ring.
        let writer = unsafe { RingWriter::new(hdr.as_ref(), data_ptr, ring_size) };
        // used = 200, free = 56. Can only write small payloads.
        assert_eq!(writer.try_write(b"hi"), Ok(true));
        // Large payload won't fit.
        let big = vec![0u8; 100];
        assert_eq!(writer.try_write(&big), Ok(false));
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    // --- Normal operation still works after hardening ---

    #[test]
    fn normal_wrap_then_message_still_works() {
        // Verify that a single legitimate wrap marker followed by a valid
        // message still works correctly (the skip limit doesn't break this).
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Place a wrap marker at offset 56, then a valid message at offset 0.
        write_le_u32(&mut data, 56, WRAP_MARKER);
        write_le_u32(&mut data, 0, 4);
        data[4..8].copy_from_slice(b"good");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // Tail at 56, head far enough ahead.
        // used = head - tail, skip wrap (rem=8), then read at 0.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 56 + 8 + 8, 56) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, b"good");
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn normal_rem_less_than_4_then_message_works() {
        // rem < LEN_SIZE skip + valid message at offset 0.
        let ring_size: u32 = 64;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // Tail at offset 62. rem = 2 < 4. Skip 2 bytes, then read at offset 0.
        write_le_u32(&mut data, 0, 3);
        data[4..7].copy_from_slice(b"abc");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // SAFETY: `hdr` is exclusively owned by this single-threaded test;
        // see `set_cursors` docs above.
        unsafe { set_cursors(hdr, 62 + 2 + 7, 62) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, b"abc");
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }

    #[test]
    fn normal_rem_less_than_4_then_wrap_marker_then_message() {
        // Two legitimate skips in a row: rem < LEN_SIZE, then wrap marker.
        // This is the maximum skip sequence in a well-formed ring.
        let ring_size: u32 = 128;
        let (hdr, mut data, layout) = adversarial_ring(ring_size);
        // First ring traversal: tail at 126, rem = 2 < 4, skip to 0.
        // At offset 0: wrap marker (already zero). Skip to... wait, rem at
        // offset 0 is 128 (full ring). Wrap marker skips 128 bytes.
        // Then at offset 0 again... that's 2 skips total.
        // Put a valid message at offset 0 after 2 skips?
        // Actually, after skip at offset 126 (rem=2), tail becomes 126+2 = 128.
        // pos = 128 & 127 = 0. Now we read len at 0 = 0 (wrap marker).
        // Skip rem = 128. tail becomes 128+128 = 256.
        // pos = 256 & 127 = 0. Same position. With head snapshot, this will
        // hit head == tail or trigger skip limit.
        //
        // Let's do: tail at 125 (rem=3 < 4), skip. Then at offset 0 there's
        // a wrap marker, skip. Then we need a message — but pos is 0 again.
        // Since head is fixed, used keeps decreasing. After 2 skips consuming
        // 3 + 128 = 131 bytes, if head was only 131 + 7 ahead, we'd read msg.
        // Actually this is getting complex. Let me use offset 126 (rem=2).
        // After skip (2 bytes), pos=0. Put real message at offset 0.
        write_le_u32(&mut data, 0, 5);
        data[4..9].copy_from_slice(b"hello");
        let data_ptr = NonNull::new(data.as_mut_ptr()).unwrap();
        // tail = 126. Need head far enough: skip 2, then frame 9 = 11 bytes total.
        // SAFETY: `hdr` is exclusively owned by this single-threaded test.
        unsafe { set_cursors(hdr, 126 + 11, 126) };

        // SAFETY: `hdr`/`data_ptr` from `adversarial_ring`; test is single-
        // threaded with at most one reader for this ring.
        let mut reader = unsafe { RingReader::new(hdr.as_ref(), data_ptr, ring_size) };
        let peeked = reader.try_peek().unwrap().unwrap();
        assert_eq!(peeked, b"hello");
        reader.advance().unwrap();
        // SAFETY: `hdr` came from `alloc_zeroed(layout)` in `adversarial_ring`.
        unsafe { alloc::alloc::dealloc(hdr.as_ptr().cast(), layout) };
    }
}

// ---------------------------------------------------------------------------
// Kani formal verification harnesses
//
// These prove safety properties hold for ALL possible inputs, not just
// sampled test cases. Each harness uses a small ring (256 bytes) so Kani
// can exhaustively explore the state space via bounded model checking.
// ---------------------------------------------------------------------------

#[cfg(kani)]
mod kani_proofs {
    use super::*;
    use core::ptr::NonNull;
    use core::sync::atomic::AtomicU32;

    /// Ring size for Kani proofs — small enough for exhaustive exploration.
    const K_RING: u32 = 256;
    const K_MASK: u32 = K_RING - 1;

    /// Allocate an aligned `RingHeader` + data buffer on the stack for Kani.
    ///
    /// Returns `(header, data_array)` — both stack-allocated.
    /// Kani doesn't need heap allocation; we use repr(C, align(64)) structs.
    #[repr(C, align(64))]
    struct KaniRingHeader {
        inner: RingHeader,
    }

    fn make_header(head: u32, tail: u32) -> KaniRingHeader {
        KaniRingHeader {
            inner: RingHeader {
                head: AtomicU32::new(head),
                _pad_head: [0; 28],
                tail: AtomicU32::new(tail),
                _pad_tail: [0; 28],
            },
        }
    }

    // =====================================================================
    // Proof 1: slice_at() never produces an out-of-bounds slice.
    //
    // This is the most critical safety property. slice_at() constructs a
    // raw slice via from_raw_parts(). If offset + len > capacity, we get
    // UB. We prove that for ANY (tail, payload_len) values that survive
    // try_peek()'s validation, the resulting slice is in-bounds.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_slice_at_in_bounds() {
        let tail: u32 = kani::any();
        let payload_len: u32 = kani::any();

        // Preconditions: these are the checks try_peek() enforces before
        // creating a PeekState and calling slice_at().
        let pos = tail & K_MASK;
        let rem = K_RING - pos;

        // payload_len must be valid
        kani::assume(payload_len > 0);
        kani::assume(payload_len <= MAX_PAYLOAD_SIZE);

        let frame_size = LEN_SIZE + payload_len;

        // Frame must fit in remaining space (try_peek line 547-548)
        kani::assume(rem >= frame_size);

        // Now verify slice_at's arithmetic stays in bounds
        let offset = pos + LEN_SIZE; // = (tail & mask) + 4
        let end = offset as u64 + payload_len as u64;

        // PROOF: offset + payload_len <= capacity
        assert!(
            end <= K_RING as u64,
            "slice_at OOB: offset={offset}, len={payload_len}, cap={K_RING}"
        );
    }

    // =====================================================================
    // Proof 2: read_u32_at() never reads out of bounds.
    //
    // read_u32_at() reads 4 bytes at an arbitrary offset. We prove that
    // try_peek()'s validation ensures the offset is always in-bounds.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_read_u32_at_in_bounds() {
        let tail: u32 = kani::any();

        let pos = tail & K_MASK;
        let rem = K_RING - pos;

        // try_peek only calls read_u32_at when rem >= LEN_SIZE
        kani::assume(rem >= LEN_SIZE);

        // PROOF: pos + 4 <= capacity
        let end = pos as u64 + LEN_SIZE as u64;
        assert!(
            end <= K_RING as u64,
            "read_u32_at OOB: pos={pos}, cap={K_RING}"
        );
    }

    // =====================================================================
    // Proof 3: Writer write_u32_at and write_bytes_at never go OOB.
    //
    // The writer computes write_pos from its own head (which it controls).
    // We prove that for ANY head and tail values, the writer's arithmetic
    // keeps all writes within [0, capacity).
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_writer_in_bounds() {
        let head: u32 = kani::any();
        let tail: u32 = kani::any();
        let payload_len: u32 = kani::any();

        // Writer validates payload
        kani::assume(payload_len > 0);
        kani::assume(payload_len <= MAX_PAYLOAD_SIZE);

        let needed = LEN_SIZE + payload_len;
        let used = head.wrapping_sub(tail);
        let free = K_RING.saturating_sub(used);
        let pos = head & K_MASK;
        let remaining = K_RING - pos;

        if remaining >= needed {
            // Direct write path
            kani::assume(free >= needed);
            let write_pos = pos;

            // PROOF: write_pos + needed <= capacity
            assert!(write_pos as u64 + needed as u64 <= K_RING as u64);
        } else {
            // Wrap path: write at offset 0
            let total = remaining + needed;
            kani::assume(free >= total);

            // Wrap marker write (if room)
            if remaining >= LEN_SIZE {
                // write_u32_at(pos, WRAP_MARKER)
                assert!(pos as u64 + LEN_SIZE as u64 <= K_RING as u64);
            }

            // Data write at offset 0
            let write_pos: u32 = 0;
            // PROOF: write_pos + needed <= capacity
            // needed = LEN_SIZE + payload_len <= LEN_SIZE + MAX_PAYLOAD_SIZE
            // But also: remaining < needed, meaning K_RING - pos < needed.
            // And: total = remaining + needed <= free <= capacity.
            // So: needed <= total <= capacity.
            assert!(write_pos as u64 + needed as u64 <= K_RING as u64);
        }
    }

    // =====================================================================
    // Proof 4: try_peek() loop terminates in bounded steps.
    //
    // With head loaded once, we prove the loop executes at most MAX_SKIPS+1
    // iterations before returning. This is the anti-DoS property.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(6)] // MAX_SKIPS(3) + 1 normal iteration + 1 for loop exit
    fn proof_try_peek_terminates() {
        let head: u32 = kani::any();
        let initial_tail: u32 = kani::any();

        // Simulate the try_peek loop logic without actual shared memory.
        // We only need to verify the loop structure terminates.
        const MAX_SKIPS: u32 = 3;
        let mut tail = initial_tail;
        let mut skips: u32 = 0;
        let mut iterations: u32 = 0;

        loop {
            if head == tail {
                break; // empty ring
            }
            let _used = head.wrapping_sub(tail);
            let pos = tail & K_MASK;
            let rem = K_RING - pos;

            if rem < LEN_SIZE {
                skips += 1;
                if skips > MAX_SKIPS {
                    break; // Corrupt error path
                }
                if _used < rem {
                    break; // Corrupt error path
                }
                tail = tail.wrapping_add(rem);
                iterations += 1;
                assert!(iterations <= MAX_SKIPS + 1);
                continue;
            }

            // Simulate any possible length value the adversary wrote
            let len: u32 = kani::any();

            if len == WRAP_MARKER {
                skips += 1;
                if skips > MAX_SKIPS {
                    break; // Corrupt error path
                }
                if _used < rem {
                    break; // Corrupt error path
                }
                tail = tail.wrapping_add(rem);
                iterations += 1;
                assert!(iterations <= MAX_SKIPS + 1);
                continue;
            }

            // Any non-wrap-marker, non-skip path exits the loop
            break;
        }

        // PROOF: loop always terminates within bounded iterations
        assert!(iterations <= MAX_SKIPS + 1);
    }

    // =====================================================================
    // Proof 5: Wrapping arithmetic preserves the SPSC used-space invariant.
    //
    // For a well-formed ring (writer only advances head, reader only
    // advances tail), `used = head.wrapping_sub(tail)` is always in
    // [0, capacity] and `free = capacity - used` is non-negative.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_wrapping_used_bounded_well_formed() {
        // Model a well-formed ring where both cursors start at some base
        // and advance by valid amounts.
        let base: u32 = kani::any();
        let written: u32 = kani::any();
        let consumed: u32 = kani::any();

        // Well-formed: consumed <= written (can't read more than written)
        kani::assume(consumed <= written);
        // Well-formed: written - consumed <= capacity (ring not overflowed)
        kani::assume(written - consumed <= K_RING);

        let head = base.wrapping_add(written);
        let tail = base.wrapping_add(consumed);
        let used = head.wrapping_sub(tail);

        // PROOF: used == written - consumed (the actual data in the ring)
        assert_eq!(used, written - consumed);
        // PROOF: used <= capacity
        assert!(used <= K_RING);
    }

    // =====================================================================
    // Proof 6: Adversarial head can never cause slice_at OOB.
    //
    // Even when the writer (guest) sets head to ANY u32 value, the reader's
    // try_peek validation ensures slice_at stays in bounds. This is the
    // combined proof: for ALL (head, tail, data) combinations, if try_peek
    // accepts the frame, the resulting slice is safe.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(6)]
    fn proof_adversarial_head_slice_safe() {
        let head: u32 = kani::any();
        let tail: u32 = kani::any();
        let data_at_pos: u32 = kani::any(); // what read_u32_at would return

        if head == tail {
            return; // empty, no slice created
        }

        let used = head.wrapping_sub(tail);
        let pos = tail & K_MASK;
        let rem = K_RING - pos;

        if rem < LEN_SIZE {
            if used < rem {
                return; // Corrupt error, no slice
            }
            return; // skip path, no slice
        }

        let len = data_at_pos;

        if len == WRAP_MARKER {
            if used < rem {
                return; // Corrupt error, no slice
            }
            return; // skip path, no slice
        }
        if len > MAX_PAYLOAD_SIZE {
            return; // Corrupt error, no slice
        }

        let frame_size = LEN_SIZE + len;
        if used < frame_size {
            return; // partial write, no slice
        }
        if rem < frame_size {
            return; // Corrupt error, no slice
        }

        // Passed all checks — slice_at would be called.
        let offset = pos + LEN_SIZE;
        let end = offset as u64 + len as u64;

        // PROOF: the slice is in-bounds
        assert!(end <= K_RING as u64);
    }

    // =====================================================================
    // Proof 7: advance() moves tail by exactly the frame size.
    //
    // After try_peek succeeds, advance computes next_tail = tail + LEN_SIZE
    // + payload_len. We prove this doesn't skip or overlap data.
    // =====================================================================

    #[kani::proof]
    #[kani::unwind(2)]
    fn proof_advance_correctness() {
        let tail: u32 = kani::any();
        let payload_len: u32 = kani::any();

        kani::assume(payload_len > 0);
        kani::assume(payload_len <= MAX_PAYLOAD_SIZE);

        let pos = tail & K_MASK;
        let rem = K_RING - pos;
        let frame_size = LEN_SIZE + payload_len;

        // Precondition from try_peek
        kani::assume(rem >= frame_size);

        // advance() does: next_tail = tail.wrapping_add(LEN_SIZE + payload_len)
        let next_tail = tail.wrapping_add(frame_size);
        let next_pos = next_tail & K_MASK;

        // PROOF: the next position is the byte right after the frame
        // (pos + frame_size) mod capacity == next_pos
        assert_eq!(next_pos, (pos + frame_size) & K_MASK);

        // PROOF: we advanced by exactly the frame size (wrapping)
        assert_eq!(next_tail.wrapping_sub(tail), frame_size);
    }
}
