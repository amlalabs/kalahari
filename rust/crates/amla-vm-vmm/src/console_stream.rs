// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Async stream for virtio-console I/O.
//!
//! `ConsoleStream` is the single type for console I/O. It implements both
//! `ConsoleBackend` (for the device side) and `AsyncRead`/`AsyncWrite`
//! (for the host side). It is `Clone` — all clones share the same buffers.

use std::collections::VecDeque;
use std::io;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use parking_lot::Mutex;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use amla_core::backends::RxWaker;

const DEFAULT_CONSOLE_BUFFER_BYTES: NonZeroUsize = NonZeroUsize::new(1024 * 1024).unwrap();

struct OutputState {
    data: VecDeque<u8>,
    waker: Option<Waker>,
}

struct InputState {
    data: VecDeque<u8>,
    capacity_waker: Option<Waker>,
}

/// Byte limits for host-side console buffering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleBufferLimits {
    output_bytes: NonZeroUsize,
    input_bytes: NonZeroUsize,
}

impl ConsoleBufferLimits {
    /// Create console buffer limits.
    pub const fn new(output_bytes: NonZeroUsize, input_bytes: NonZeroUsize) -> Self {
        Self {
            output_bytes,
            input_bytes,
        }
    }

    /// Maximum buffered guest-to-host output bytes.
    pub const fn output_bytes(self) -> NonZeroUsize {
        self.output_bytes
    }

    /// Maximum buffered host-to-guest input bytes.
    pub const fn input_bytes(self) -> NonZeroUsize {
        self.input_bytes
    }
}

impl Default for ConsoleBufferLimits {
    fn default() -> Self {
        Self {
            output_bytes: DEFAULT_CONSOLE_BUFFER_BYTES,
            input_bytes: DEFAULT_CONSOLE_BUFFER_BYTES,
        }
    }
}

struct ConsoleStreamInner {
    /// Guest-to-host output + async waker (locked together so the waker
    /// is always woken when new data arrives, with no gap).
    output: Mutex<OutputState>,
    /// Host-to-guest input (`AsyncWrite` pushes, `ConsoleBackend::read` drains).
    input: Mutex<InputState>,
    limits: ConsoleBufferLimits,
    /// Set by `run()` via `set_rx_waker` -- wakes device loop when host writes input.
    rx_waker: Mutex<Option<RxWaker>>,
}

/// Async stream for virtio-console I/O.
///
/// - [`AsyncRead`]: Reads guest console output (device writes to here)
/// - [`AsyncWrite`]: Sends input to guest console (here to device reads)
///
/// Implements `ConsoleBackend` so it can be used directly as the console
/// device backend.
///
/// `Clone` -- all clones share the same underlying buffers.
pub struct ConsoleStream {
    inner: Arc<ConsoleStreamInner>,
}

impl Clone for ConsoleStream {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl Default for ConsoleStream {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleStream {
    /// Create a new console stream.
    pub fn new() -> Self {
        Self::with_buffer_limits(ConsoleBufferLimits::default())
    }

    /// Create a console stream with explicit host-side buffer limits.
    pub fn with_buffer_limits(limits: ConsoleBufferLimits) -> Self {
        Self {
            inner: Arc::new(ConsoleStreamInner {
                output: Mutex::new(OutputState {
                    data: VecDeque::new(),
                    waker: None,
                }),
                input: Mutex::new(InputState {
                    data: VecDeque::new(),
                    capacity_waker: None,
                }),
                limits,
                rx_waker: Mutex::new(None),
            }),
        }
    }

    /// Drain all buffered output synchronously.
    ///
    /// Returns all pending data without blocking. Useful after `run()` returns —
    /// the vCPU scope has exited so all output is already in the buffer.
    pub fn drain(&mut self) -> Vec<u8> {
        self.inner.output.lock().data.drain(..).collect()
    }
}

impl amla_core::backends::ConsoleBackend for ConsoleStream {
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn write(&self, data: &[u8]) -> io::Result<()> {
        // Tee guest console output to stderr when AMLA_CONSOLE=1. A failed
        // tee write (broken pipe, etc.) shouldn't block the underlying
        // console buffer below; log once at debug.
        if std::env::var("AMLA_CONSOLE").as_deref() == Ok("1")
            && let Err(e) = io::Write::write_all(&mut io::stderr(), data)
        {
            log::debug!("console tee to stderr failed: {e}");
        }
        let mut output = self.inner.output.lock();
        let remaining = self
            .inner
            .limits
            .output_bytes
            .get()
            .saturating_sub(output.data.len());
        if remaining < data.len() {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "console output buffer full",
            ));
        }
        output.data.extend(data);
        if let Some(waker) = output.waker.take() {
            waker.wake();
        }
        Ok(())
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut input = self.inner.input.lock();
        if input.data.is_empty() {
            return Err(io::Error::new(io::ErrorKind::WouldBlock, "no input"));
        }
        let n = buf.len().min(input.data.len());
        for (dst, src) in buf[..n].iter_mut().zip(input.data.drain(..n)) {
            *dst = src;
        }
        if let Some(waker) = input.capacity_waker.take() {
            waker.wake();
        }
        Ok(n)
    }

    fn has_pending_input(&self) -> bool {
        !self.inner.input.lock().data.is_empty()
    }

    fn set_rx_waker(&self, waker: Option<RxWaker>) {
        let mut slot = self.inner.rx_waker.lock();
        if let Some(old) = std::mem::replace(&mut *slot, waker) {
            old.cancel();
        }
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    fn clone_writer(&self) -> Option<Box<dyn amla_core::backends::ConsoleBackend>> {
        Some(Box::new(self.clone()))
    }
}

impl AsyncRead for ConsoleStream {
    // Reason: output mutex guard spans the empty-check, waker registration,
    // and data drain so the wake-up sequence is atomic.
    #[allow(clippy::significant_drop_tightening)]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut output = self.inner.output.lock();
        if output.data.is_empty() {
            output.waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.remaining().min(output.data.len());
        let (front, back) = output.data.as_slices();
        if n <= front.len() {
            buf.put_slice(&front[..n]);
        } else {
            buf.put_slice(front);
            buf.put_slice(&back[..n - front.len()]);
        }
        output.data.drain(..n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ConsoleStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut input = self.inner.input.lock();
        let remaining = self
            .inner
            .limits
            .input_bytes
            .get()
            .saturating_sub(input.data.len());
        if remaining == 0 {
            input.capacity_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let accepted = buf.len().min(remaining);
        input.data.extend(buf[..accepted].iter().copied());
        drop(input);
        // Wake device worker to deliver data to guest via RX queue.
        if let Some(waker) = self.inner.rx_waker.lock().as_ref() {
            waker.wake();
        }
        Poll::Ready(Ok(accepted))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use amla_core::backends::ConsoleBackend;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn limits(output_bytes: usize, input_bytes: usize) -> ConsoleBufferLimits {
        ConsoleBufferLimits::new(
            NonZeroUsize::new(output_bytes).unwrap(),
            NonZeroUsize::new(input_bytes).unwrap(),
        )
    }

    // ── ConsoleBackend (device side) ──────────────────────────────────

    #[tokio::test]
    async fn backend_write_delivers_to_stream() {
        let console = ConsoleStream::new();
        let mut reader = console.clone();
        ConsoleBackend::write(&console, b"hello").unwrap();
        let mut buf = [0u8; 16];
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[test]
    fn backend_write_is_bounded() {
        let console = ConsoleStream::with_buffer_limits(limits(4, 16));
        let err = ConsoleBackend::write(&console, b"abcdef").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
        assert!(console.clone().drain().is_empty());

        ConsoleBackend::write(&console, b"abcd").unwrap();
        let err = ConsoleBackend::write(&console, b"x").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        let mut drainable = console.clone();
        assert_eq!(drainable.drain(), b"abcd");
        ConsoleBackend::write(&console, b"z").unwrap();
    }

    #[test]
    fn backend_read_returns_wouldblock_when_empty() {
        let console = ConsoleStream::new();
        let mut buf = [0u8; 16];
        let err = ConsoleBackend::read(&console, &mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn backend_read_drains_input() {
        let console = ConsoleStream::new();
        console.inner.input.lock().data.extend(b"world");
        let mut buf = [0u8; 16];
        let n = ConsoleBackend::read(&console, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
        assert!(!console.has_pending_input());
    }

    #[test]
    fn backend_has_pending_input_tracks_state() {
        let console = ConsoleStream::new();
        assert!(!console.has_pending_input());
        console.inner.input.lock().data.extend(b"x");
        assert!(console.has_pending_input());
    }

    // ── AsyncWrite (host → guest) ─────────────────────────────────────

    #[tokio::test]
    async fn stream_write_pushes_to_input() {
        let console = ConsoleStream::new();
        let mut writer = console.clone();
        writer.write_all(b"input data").await.unwrap();
        assert!(console.has_pending_input());
        let mut buf = [0u8; 32];
        let n = ConsoleBackend::read(&console, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"input data");
    }

    #[tokio::test]
    async fn stream_write_is_bounded() {
        let console = ConsoleStream::with_buffer_limits(limits(16, 3));
        let mut writer = console.clone();
        let written = AsyncWriteExt::write(&mut writer, b"abcd").await.unwrap();
        assert_eq!(written, 3);

        let mut buf = [0u8; 8];
        let n = ConsoleBackend::read(&console, &mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");
    }

    #[tokio::test]
    async fn stream_write_empty_returns_zero() {
        let mut stream = ConsoleStream::new();
        let n = AsyncWriteExt::write(&mut stream, b"").await.unwrap();
        assert_eq!(n, 0);
    }

    // ── AsyncRead (guest → host) ──────────────────────────────────────

    #[tokio::test]
    async fn stream_read_partial_chunk() {
        let console = ConsoleStream::new();
        let mut reader = console.clone();
        ConsoleBackend::write(&console, b"0123456789").unwrap();
        let mut buf = [0u8; 4];
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"0123");
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"4567");
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"89");
    }

    // ── drain ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn drain_collects_all_buffered_output() {
        let console = ConsoleStream::new();
        let mut sink = console.clone();
        ConsoleBackend::write(&console, b"aaa").unwrap();
        ConsoleBackend::write(&console, b"bbb").unwrap();
        // Read partially.
        let mut reader = console.clone();
        let mut buf = [0u8; 2];
        let n = AsyncReadExt::read(&mut reader, &mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"aa");
        // Drain should get the rest.
        let output = sink.drain();
        assert_eq!(output, b"abbb");
    }

    #[test]
    fn drain_empty_returns_empty() {
        let mut console = ConsoleStream::new();
        assert!(console.drain().is_empty());
    }

    // ── rx_waker ──────────────────────────────────────────────────────

    #[tokio::test]
    async fn rx_waker_called_on_write() {
        let console = ConsoleStream::new();
        let called = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let called_clone = Arc::clone(&called);
        console.set_rx_waker(Some(RxWaker::new(move || {
            called_clone.store(true, std::sync::atomic::Ordering::SeqCst);
        })));
        let mut writer = console.clone();
        writer.write_all(b"ping").await.unwrap();
        assert!(called.load(std::sync::atomic::Ordering::SeqCst));
    }
}
