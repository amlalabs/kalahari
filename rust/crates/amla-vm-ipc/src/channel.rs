// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Generic IPC channel — parameterized over doorbell and aux transport.
//!
//! # Cancel safety
//!
//! [`Sender::send`] and [`Sender::reserve_send`] are cancel-safe: dropping
//! their futures at any `.await` point never leaves a partial frame (ring
//! data without its promised FDs, or vice-versa) visible to the peer.
//!
//! The two-phase [`reserve_send`](Sender::reserve_send) /
//! [`commit`](SendPermit::commit) API exposes this explicitly:
//!
//! * **reserve** — serializes the message, validates it, waits until the
//!   ring has room, and assigns a transport sequence number. No data is
//!   transferred; cancellation is peer-invisible.
//! * **commit** — sends aux slots (async), then writes the ring frame
//!   (sync, no `.await`), then kicks the doorbell (async, idempotent).
//!   Because the ring write is synchronous and immediately follows the
//!   aux send, there is no `.await` point where FDs could be delivered
//!   without their ring frame.
//!
//! # Compatibility
//!
//! The channel frame is a same-version transport detail. It records only a
//! sequence number, aux-slot count, and postcard payload bytes; message schema
//! compatibility is provided by running matching endpoint code, not by an
//! in-frame version negotiation layer.

use std::future::Future;
use std::io;
use std::time::Instant;

use amla_vm_ringbuf::{RingReader, RingWriter};

use crate::{AuxSlot, IpcMessage};

// ============================================================================
// Traits
// ============================================================================

pub trait DoorbellSend: Send + Sync {
    fn kick(&self, seq: u32) -> impl Future<Output = io::Result<()>> + Send;
}

pub trait DoorbellRecv: Send {
    fn wait_kick(&self) -> impl Future<Output = io::Result<()>> + Send;
    fn drain(&self) -> io::Result<()>;
}

/// Aux-transport sender.
///
/// # Contract
///
/// `send_slots` must be **all-or-nothing**: either the future resolves
/// `Ok(())` and *all* slots have been delivered to the peer's receive
/// buffer, or it resolves `Err` / is dropped and *no* slots are
/// delivered.  This is required for the channel's cancel-safety
/// guarantee — if an implementation delivers a subset of slots before
/// its future returns `Ready`, cancellation after that point can
/// desynchronize the aux stream and the ring.
///
/// Both platform implementations satisfy this: Linux uses a single
/// SEQPACKET `sendmsg` (kernel-atomic), macOS uses a single `mach_msg`.
pub trait AuxSend: Send + Sync {
    fn send_slots(
        &self,
        seq: u32,
        slots: Vec<AuxSlot>,
    ) -> impl Future<Output = io::Result<()>> + Send;
}

pub trait AuxRecv: Send {
    fn recv_slots(
        &mut self,
        seq: u32,
        count: usize,
    ) -> impl Future<Output = io::Result<Vec<AuxSlot>>> + Send;
}

/// Hard upper bound on aux slots (fds / Mach ports) per IPC message.
///
/// Must stay below the kernel's per-`sendmsg` ceiling (SCM_MAX_FD = 253 on
/// Linux).  Validated in [`Sender::reserve_send`] so an oversized batch is
/// rejected before any transfer begins.
const MAX_SLOTS_PER_MSG: usize = 64;
const FRAME_HEADER_LEN: usize = 8;
const CHANNEL_POISONED: &str = "channel is poisoned after a failed commit or receive";

// ============================================================================
// Sender
// ============================================================================

pub struct Sender<'a, D: DoorbellSend, A: AuxSend> {
    writer: RingWriter<'a>,
    doorbell: D,
    aux: A,
    seq: u32,
    poisoned: bool,
}

impl<'a, D: DoorbellSend, A: AuxSend> Sender<'a, D, A> {
    pub(crate) fn new(writer: RingWriter<'a>, doorbell: D, aux: A) -> Self {
        Self {
            writer,
            doorbell,
            aux,
            seq: 1,
            poisoned: false,
        }
    }

    /// Serialize `msg` and wait until the ring has room, returning a
    /// [`SendPermit`] that can be [`commit`](SendPermit::commit)ted or
    /// [`abort`](SendPermit::abort)ed.
    ///
    /// Cancel-safe: dropping the future (or the returned permit) before
    /// `commit` never transfers any data to the peer.
    pub async fn reserve_send<M: IpcMessage>(
        &mut self,
        msg: M,
    ) -> crate::Result<SendPermit<'_, 'a, D, A>> {
        if self.poisoned {
            return Err(crate::Error::Protocol(CHANNEL_POISONED));
        }

        let t0 = Instant::now();

        let (data, slots) = msg.serialize().map_err(|e| {
            log::error!("[channel] serialize FAILED: {e:?}");
            e
        })?;
        let t_ser = t0.elapsed();

        let slot_count = u32::try_from(slots.len())
            .map_err(|_| crate::Error::Protocol("slot count overflows u32"))?;

        if slots.len() > MAX_SLOTS_PER_MSG {
            return Err(crate::Error::Protocol(
                "too many aux slots for a single message",
            ));
        }

        let payload_len = u32::try_from(FRAME_HEADER_LEN + data.len())
            .map_err(|_| crate::Error::Protocol("frame too large for ring"))?;

        // Validate the frame will ever fit.  can_write() returns false
        // forever for frames that exceed the ring's max payload size,
        // which would cause an infinite spin below.
        if !self.writer.can_ever_write(payload_len) {
            return Err(crate::Error::Protocol("frame exceeds ring capacity"));
        }

        // Spin until the ring has room.  Cancel-safe: no side-effects yet.
        let mut ring_spins = 0u32;
        loop {
            if self.writer.can_write(payload_len)? {
                break;
            }
            ring_spins += 1;
            tokio::task::yield_now().await;
        }

        log::trace!(
            "ipc reserve ser={t_ser:?} spins={ring_spins} data={}B slots={slot_count}",
            data.len(),
        );

        let seq = self.seq;
        self.seq = self.seq.wrapping_add(1);

        // Build the same-version ring frame:
        // [seq: u32 LE][slot_count: u32 LE][postcard data].
        let mut frame = Vec::with_capacity(payload_len as usize);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&slot_count.to_le_bytes());
        frame.extend_from_slice(&data);

        Ok(SendPermit {
            sender: self,
            seq,
            slot_count,
            frame,
            slots,
        })
    }

    /// Convenience wrapper: serialize, reserve, and commit in one call.
    ///
    /// Equivalent to `self.reserve_send(msg).await?.commit().await`.
    /// Cancel-safe (see [`reserve_send`](Self::reserve_send)).
    pub async fn send<M: IpcMessage>(&mut self, msg: M) -> crate::Result<()> {
        self.reserve_send(msg).await?.commit().await
    }
}

// ============================================================================
// SendPermit
// ============================================================================

/// A staged send that has been serialized and validated but not yet
/// transmitted.  Dropping without calling [`commit`](Self::commit) is
/// equivalent to [`abort`](Self::abort) — no bytes or file descriptors
/// reach the peer.
///
/// # Cancel safety
///
/// * **Drop before `commit`**: clean — nothing was transferred.
/// * **Cancel during `commit`**: if cancelled during the aux-slot send,
///   nothing is in the ring — the peer sees nothing (SEQPACKET sends are
///   atomic per message).  Once aux slots are delivered the ring write is
///   synchronous, so there is no `.await` where FDs could exist without
///   their ring frame.
pub struct SendPermit<'s, 'a, D: DoorbellSend, A: AuxSend> {
    sender: &'s mut Sender<'a, D, A>,
    seq: u32,
    slot_count: u32,
    frame: Vec<u8>,
    slots: Vec<AuxSlot>,
}

impl<D: DoorbellSend, A: AuxSend> SendPermit<'_, '_, D, A> {
    /// Transmit the staged frame to the peer.
    ///
    /// Sends aux slots first (async), then writes the ring frame
    /// (synchronous — ring space was pre-validated by `reserve_send`),
    /// then kicks the doorbell (async, idempotent).
    pub async fn commit(self) -> crate::Result<()> {
        let SendPermit {
            sender,
            seq,
            slot_count,
            frame,
            slots,
        } = self;
        let t0 = Instant::now();

        // 1. Send aux slots FIRST.  This is the only cancellable `.await`
        //    before the ring write.  If cancelled here, no ring frame
        //    exists — clean abort.
        if !slots.is_empty()
            && let Err(e) = sender.aux.send_slots(seq, slots).await
        {
            sender.poisoned = true;
            log::error!("[channel] send_slots FAILED: {e}");
            return Err(crate::Error::Io(e));
        }

        // 2. Ring write — synchronous. Space was pre-validated by
        //    reserve_send and cannot shrink (we hold &mut Sender, so no
        //    other writer exists; the reader can only free space).
        //
        //    No `.await` between this and step 1, so cancellation cannot
        //    separate the FD transfer from the ring frame.
        let written = match sender.writer.try_write_parts(&[&frame]) {
            Ok(written) => written,
            Err(e) => {
                sender.poisoned = true;
                log::error!("[channel] ring write FAILED: {e}");
                return Err(crate::Error::from(e));
            }
        };
        if !written {
            // Aux slots were already delivered — the channel is now
            // permanently desynchronized.  This should never happen
            // (we hold &mut Sender so no other writer exists, and the
            // reader can only free space), but if it does, surface it
            // loudly rather than silently losing a frame.
            log::error!(
                "[channel] ring write returned false after reserve — channel desynchronized"
            );
            sender.poisoned = true;
            return Err(crate::Error::Protocol(
                "ring space vanished after reserve (channel desynchronized)",
            ));
        }

        // 3. Doorbell kick — async but idempotent.  Losing it only
        //    delays delivery; the receiver's spin/epoll loop will
        //    eventually see the ring data.
        if let Err(e) = sender.doorbell.kick(seq).await {
            sender.poisoned = true;
            log::error!("[channel] kick FAILED: {e}");
            return Err(crate::Error::Io(e));
        }

        let t_total = t0.elapsed();
        if t_total.as_micros() > 500 {
            log::trace!(
                "ipc commit seq={seq} total={t_total:?} data={}B slots={slot_count}",
                frame.len() - FRAME_HEADER_LEN,
            );
        }

        Ok(())
    }

    /// Abandon the staged send without transmitting anything.
    ///
    /// Equivalent to dropping the permit.  Provided for readability at
    /// call sites that want to make the intent explicit.
    pub fn abort(self) {
        drop(self);
    }
}

// ============================================================================
// Receiver
// ============================================================================

pub struct Receiver<'a, D: DoorbellRecv, A: AuxRecv> {
    reader: RingReader<'a>,
    doorbell: D,
    aux: A,
    poisoned: bool,
}

impl<'a, D: DoorbellRecv, A: AuxRecv> Receiver<'a, D, A> {
    pub(crate) fn new(reader: RingReader<'a>, doorbell: D, aux: A) -> Self {
        Self {
            reader,
            doorbell,
            aux,
            poisoned: false,
        }
    }

    pub async fn recv<M: IpcMessage>(&mut self) -> crate::Result<M> {
        if self.poisoned {
            return Err(crate::Error::Protocol(CHANNEL_POISONED));
        }

        let t0 = Instant::now();

        // Fast path: check a few times before falling into epoll. Most
        // messages land in the ring within microseconds of the previous
        // send. Interleave short spin bursts with yields so we don't
        // starve other tasks on the same tokio executor thread.
        for round in 0..4u32 {
            for _ in 0..8 {
                if self.reader.try_peek()?.is_some() {
                    return self.take_and_decode::<M>(&t0, 0, round).await;
                }
                std::hint::spin_loop();
            }
            tokio::task::yield_now().await;
        }

        // Slow path: drain doorbell and wait via epoll.
        let mut drain_count = 0u32;
        let mut wait_count = 0u32;
        loop {
            self.doorbell.drain()?;
            drain_count += 1;

            if self.reader.try_peek()?.is_some() {
                return self
                    .take_and_decode::<M>(&t0, drain_count, wait_count)
                    .await;
            }

            wait_count += 1;
            self.doorbell.wait_kick().await?;

            if self.reader.try_peek()?.is_some() {
                return self
                    .take_and_decode::<M>(&t0, drain_count, wait_count)
                    .await;
            }
        }
    }

    /// Decode the peeked frame, then consume it only after successful deserialize.
    /// Caller must ensure try_peek() just returned Some.
    async fn take_and_decode<M: IpcMessage>(
        &mut self,
        t0: &Instant,
        drain_count: u32,
        wait_count: u32,
    ) -> crate::Result<M> {
        let frame = self
            .reader
            .try_peek()?
            .ok_or(crate::Error::Protocol("frame vanished"))?;
        if frame.len() < FRAME_HEADER_LEN {
            self.poisoned = true;
            return Err(crate::Error::Protocol("ring frame too short"));
        }
        let seq = u32::from_le_bytes(
            frame[..4]
                .try_into()
                .map_err(|_| crate::Error::Protocol("ring sequence truncated"))?,
        );
        let slot_count = u32::from_le_bytes(
            frame[4..8]
                .try_into()
                .map_err(|_| crate::Error::Protocol("ring slot count truncated"))?,
        );
        let data = frame[FRAME_HEADER_LEN..].to_vec();

        if slot_count as usize > MAX_SLOTS_PER_MSG {
            self.poisoned = true;
            return Err(crate::Error::Protocol(
                "peer sent frame with slot_count exceeding MAX_SLOTS_PER_MSG",
            ));
        }

        // Recv aux slots BEFORE advancing the ring: if recv_slots fails the
        // ring frame stays un-advanced (the peek cache holds it) so the fd
        // payload and its owning ring frame can never desynchronize.
        let slots = if slot_count > 0 {
            let slots = match self.aux.recv_slots(seq, slot_count as usize).await {
                Ok(slots) => slots,
                Err(e) => {
                    self.poisoned = true;
                    return Err(crate::Error::Io(e));
                }
            };
            if slots.len() != slot_count as usize {
                self.poisoned = true;
                return Err(crate::Error::Protocol(
                    "aux transport returned unexpected slot count",
                ));
            }
            slots
        } else {
            Vec::new()
        };
        let msg = match M::deserialize(&data, slots) {
            Ok(msg) => msg,
            Err(e) => {
                self.poisoned = true;
                return Err(e);
            }
        };
        self.reader.advance()?;
        let t_total = t0.elapsed();

        if t_total.as_micros() > 500 || wait_count > 0 {
            log::trace!(
                "ipc recv total={t_total:?} data={}B slots={slot_count} drains={drain_count} waits={wait_count}",
                data.len()
            );
        }

        Ok(msg)
    }
}
