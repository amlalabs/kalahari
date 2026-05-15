// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Streaming per-frame async tap around [`http_body::Body`].
//!
//! Wraps an inner body + the [`HttpMitmHandler`]. For each data frame, awaits
//! `on_*_chunk` and then emits the (possibly mutated) chunk. For response
//! bodies, after the inner reaches EOF cleanly, awaits `on_response_end` —
//! if the handler pushed trailing bytes into the provided `BytesMut`, they're
//! emitted as one final data frame. Then `on_complete` fires as the terminal
//! observability hook.
//!
//! ## Error-path contract
//!
//! If the inner body returns `Err` mid-stream (upstream transport error,
//! guest RST mid-body), the tap:
//!
//! 1. **Skips** `on_response_end` — appending trailing bytes to a broken
//!    stream is nonsensical.
//! 2. **Still fires** `on_complete` with
//!    [`ResponseOutcome::Aborted`][crate::handler::ResponseOutcome::Aborted]
//!    before propagating the error. Handlers that track per-response
//!    metrics / state must see the event.
//!
//! Clean ends carry `ResponseOutcome::Completed`. `on_complete` fires
//! inline on every terminal state the per-frame state machine reaches
//! (`Done` via clean end, or `RunningComplete → Done` via inner error).
//! It does NOT fire when hyper drops the body from the outside without
//! a final poll — that path happens on guest mid-response RSTs (the
//! egress pipe breaks, hyper abandons the response future). Handlers
//! with exact start/complete counting accept a small skew there, same
//! as any HTTP middleware.
//!
//! ## Boxing (load-bearing on stable Rust)
//!
//! Per-frame futures stored as `Pin<Box<dyn Future + Send>>` — one heap
//! allocation per HTTP body chunk. `HttpMitmHandler` uses RPITIT `async fn`
//! whose return types are anonymous per-implementor, so the futures cannot
//! be stored in a named associated-type field without type-alias-impl-trait
//! (TAIT), which is nightly-only. On stable the erasure is the price of
//! admission; on typical traffic (~16 KiB TLS records) the allocation cost
//! is negligible next to AEAD encryption.
//!
//! Trailer frames (`Frame::trailers`) are passed through unchanged. The tap
//! only targets data frames.

use bytes::{Bytes, BytesMut};
use http_body::{Body, Frame, SizeHint};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use http::StatusCode;

use crate::handler::{HttpMitmHandler, HttpRequestHeaders, ResponseOutcome};

type ChunkFuture = Pin<Box<dyn Future<Output = Bytes> + Send + 'static>>;
type EndFuture = Pin<Box<dyn Future<Output = BytesMut> + Send + 'static>>;
type CompleteFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// Request vs. response tapping. Different callbacks fire in each direction,
/// and only response tapping runs the end/complete tail.
#[derive(Debug, Clone, Copy)]
enum TapKind {
    Request,
    Response { status: StatusCode },
}

/// Tap state machine. Transitions:
///
/// ```text
/// Idle ─ inner frame is data ──► Tapping ─ future resolves ──► Idle
/// Idle ─ inner EOF (request)  ──► Done
/// Idle ─ inner EOF (response) ──► RunningEnd ──► emit trailing? ──► RunningComplete ──► Done
/// Idle ─ inner frame is trailers ──► Idle (frame passed through unchanged)
/// Idle ─ inner err ──► Idle (error bubbled)
/// ```
enum State {
    Idle,
    Tapping(ChunkFuture),
    RunningEnd(EndFuture),
    /// Emit `bytes` as a final data frame on the next poll, then switch to
    /// `RunningComplete(complete)`. Holding the complete future here avoids
    /// rebuilding it and avoids a `&mut self` call during poll.
    EmitEnd {
        bytes: Bytes,
        complete: CompleteFuture,
    },
    RunningComplete(CompleteFuture),
    Done,
}

/// Streaming per-frame tap around an inner [`http_body::Body`].
pub struct TappedBody<B, H>
where
    B: Body,
{
    inner: B,
    handler: Arc<H>,
    req_h: Arc<HttpRequestHeaders>,
    kind: TapKind,
    state: State,
    /// Set once inner `poll_frame` has yielded `None`. Guards against polling
    /// a drained inner (contract violation of some bodies) and picks the
    /// response-tail branch.
    inner_done: bool,
    /// Set when the inner body returns `Err` mid-stream. We still run the
    /// `on_complete(Aborted)` hook before surfacing the error, so the
    /// handler can't silently miss the response.
    pending_error: Option<B::Error>,
}

impl<B: Body, H: HttpMitmHandler> TappedBody<B, H> {
    pub(crate) const fn new_request(
        inner: B,
        req_h: Arc<HttpRequestHeaders>,
        handler: Arc<H>,
    ) -> Self {
        Self {
            inner,
            handler,
            req_h,
            kind: TapKind::Request,
            state: State::Idle,
            inner_done: false,
            pending_error: None,
        }
    }

    pub(crate) const fn new_response(
        inner: B,
        req_h: Arc<HttpRequestHeaders>,
        handler: Arc<H>,
        status: StatusCode,
    ) -> Self {
        Self {
            inner,
            handler,
            req_h,
            kind: TapKind::Response { status },
            state: State::Idle,
            inner_done: false,
            pending_error: None,
        }
    }
}

impl<B, H> Body for TappedBody<B, H>
where
    B: Body<Data = Bytes> + Unpin,
    // `Option<B::Error>` is stored in `pending_error`, so the whole
    // `TappedBody` is `Unpin` only when `B::Error` is. Every hyper body
    // type we target satisfies this trivially (`hyper::Error`, `Infallible`,
    // etc. are all `Unpin`), so constraining it here is free.
    B::Error: Unpin,
    H: HttpMitmHandler,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, B::Error>>> {
        // Safe: `TappedBody` is `Unpin` under the impl bounds above, so
        // projecting to `&mut Self` is fine. Using `get_mut()` makes that
        // explicit rather than relying on `Pin`'s `DerefMut`-via-Unpin,
        // which also lets us drop the unused `mut self` warning.
        let this = self.get_mut();
        loop {
            // First: resolve any in-flight async step.
            match &mut this.state {
                State::Done => return Poll::Ready(None),

                State::Tapping(fut) => {
                    let chunk = ready!(fut.as_mut().poll(cx));
                    this.state = State::Idle;
                    return Poll::Ready(Some(Ok(Frame::data(chunk))));
                }

                State::RunningEnd(fut) => {
                    let trailing = ready!(fut.as_mut().poll(cx));
                    let complete = this.build_complete_future(ResponseOutcome::Completed);
                    if trailing.is_empty() {
                        this.state = State::RunningComplete(complete);
                        continue;
                    }
                    // Emit the trailing frame this poll; run on_complete on
                    // the next poll (only one `Poll::Ready(Some(frame))` per
                    // `poll_frame` call).
                    this.state = State::EmitEnd {
                        bytes: trailing.freeze(),
                        complete,
                    };
                    continue;
                }

                State::EmitEnd { .. } => {
                    // Take ownership via replace so we can move `bytes`
                    // into the frame and `complete` into the next state.
                    let prev = std::mem::replace(&mut this.state, State::Idle);
                    let State::EmitEnd { bytes, complete } = prev else {
                        unreachable!("outer match guarded this variant");
                    };
                    this.state = State::RunningComplete(complete);
                    return Poll::Ready(Some(Ok(Frame::data(bytes))));
                }

                State::RunningComplete(fut) => {
                    ready!(fut.as_mut().poll(cx));
                    this.state = State::Done;
                    // If the body aborted mid-stream, surface the error
                    // *after* the on_complete(Aborted) hook has fired.
                    if let Some(err) = this.pending_error.take() {
                        return Poll::Ready(Some(Err(err)));
                    }
                    return Poll::Ready(None);
                }

                State::Idle => {}
            }

            // State::Idle: drive the inner body forward.
            if this.inner_done {
                // Response: start the tail. Request: we're done.
                match this.kind {
                    TapKind::Request => {
                        this.state = State::Done;
                        return Poll::Ready(None);
                    }
                    TapKind::Response { .. } => {
                        let handler = Arc::clone(&this.handler);
                        let req_h = Arc::clone(&this.req_h);
                        this.state = State::RunningEnd(Box::pin(async move {
                            let mut trailing = BytesMut::new();
                            handler.on_response_end(&req_h, &mut trailing).await;
                            trailing
                        }));
                        continue;
                    }
                }
            }

            match ready!(Pin::new(&mut this.inner).poll_frame(cx)) {
                None => {
                    this.inner_done = true;
                }
                Some(Err(e)) => {
                    // Body aborted. For request-side taps there's no tail
                    // hook, so surface the error directly. For response-side
                    // taps we defer the error and run on_complete(Aborted)
                    // first so handlers see exactly one terminal event per
                    // response — skip on_response_end since appending to a
                    // broken stream is meaningless.
                    match this.kind {
                        TapKind::Request => return Poll::Ready(Some(Err(e))),
                        TapKind::Response { .. } => {
                            this.inner_done = true;
                            this.pending_error = Some(e);
                            let complete = this.build_complete_future(ResponseOutcome::Aborted);
                            this.state = State::RunningComplete(complete);
                        }
                    }
                }
                Some(Ok(frame)) => {
                    // `Frame::into_data` returns `Result<Data, Frame>` —
                    // the Err arm is the non-data case (trailers, future
                    // frame types). Forwarding it unchanged + scheduling
                    // the tap on the data arm uses no `.expect()` and
                    // tolerates future Frame kinds gracefully.
                    match frame.into_data() {
                        Ok(chunk) => {
                            let handler = Arc::clone(&this.handler);
                            let req_h = Arc::clone(&this.req_h);
                            let kind = this.kind;
                            this.state = State::Tapping(Box::pin(async move {
                                let mut chunk = chunk;
                                match kind {
                                    TapKind::Request => {
                                        handler.on_request_chunk(&req_h, &mut chunk).await;
                                    }
                                    TapKind::Response { .. } => {
                                        handler.on_response_chunk(&req_h, &mut chunk).await;
                                    }
                                }
                                chunk
                            }));
                        }
                        Err(frame) => return Poll::Ready(Some(Ok(frame))),
                    }
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.state, State::Done)
    }

    fn size_hint(&self) -> SizeHint {
        // The inner body may know, but tapping can append trailing bytes on
        // the response side, so we'd be lying if we forwarded. Report unknown.
        SizeHint::default()
    }
}

impl<B: Body, H: HttpMitmHandler> TappedBody<B, H> {
    /// Build the `on_complete` future with the given outcome.
    ///
    /// Only valid when `kind` is `Response` — request taps have no tail
    /// hooks. The `TapKind::Request` branch steers to `State::Done`
    /// directly (see the `State::Idle` arm in `poll_frame`) and never
    /// constructs a complete future. A fake `0` status would be
    /// indistinguishable from a real status code, so we hard-fail instead
    /// of silently defaulting.
    fn build_complete_future(&self, outcome: ResponseOutcome) -> CompleteFuture {
        let status = match self.kind {
            TapKind::Response { status } => status,
            TapKind::Request => unreachable!(
                "build_complete_future called on request tap — this violates the body state machine invariant"
            ),
        };
        let handler = Arc::clone(&self.handler);
        let req_h = Arc::clone(&self.req_h);
        Box::pin(async move {
            handler.on_complete(&req_h, status, outcome).await;
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handler::HttpRequestHeaders;
    use http::{HeaderMap, Method, Uri};
    use http_body_util::{BodyExt, StreamBody};
    use parking_lot::Mutex;
    use std::convert::Infallible;

    fn dummy_req_h() -> Arc<HttpRequestHeaders> {
        Arc::new(HttpRequestHeaders {
            method: Method::GET,
            uri: Uri::from_static("/"),
            hostname: "example.com".into(),
            headers: HeaderMap::new(),
        })
    }

    type ChunkMutator = Box<dyn Fn(&mut Bytes) + Send + Sync>;

    /// Records every handler call and can inject chunk mutations / trailing
    /// bytes so tests can assert on per-frame behavior.
    #[derive(Default)]
    struct RecorderHandler {
        request_chunks: Mutex<Vec<Bytes>>,
        response_chunks: Mutex<Vec<Bytes>>,
        trailing: Mutex<BytesMut>,
        end_called: Mutex<bool>,
        completed: Mutex<Option<(StatusCode, ResponseOutcome)>>,
        mutate_response_chunk: Mutex<Option<ChunkMutator>>,
        end_bytes: Mutex<Option<Bytes>>,
    }

    impl HttpMitmHandler for RecorderHandler {
        async fn on_request_chunk(&self, _req: &HttpRequestHeaders, chunk: &mut Bytes) {
            self.request_chunks.lock().push(chunk.clone());
        }
        async fn on_response_chunk(&self, _req: &HttpRequestHeaders, chunk: &mut Bytes) {
            if let Some(f) = self.mutate_response_chunk.lock().as_ref() {
                f(chunk);
            }
            self.response_chunks.lock().push(chunk.clone());
        }
        async fn on_response_end(&self, _req: &HttpRequestHeaders, trailing: &mut BytesMut) {
            *self.end_called.lock() = true;
            let end_bytes = {
                let guard = self.end_bytes.lock();
                guard.clone()
            };
            if let Some(b) = end_bytes {
                trailing.extend_from_slice(&b);
            }
            *self.trailing.lock() = trailing.clone();
        }
        async fn on_complete(
            &self,
            _req: &HttpRequestHeaders,
            status: StatusCode,
            outcome: ResponseOutcome,
        ) {
            *self.completed.lock() = Some((status, outcome));
        }
    }

    /// Build a body from `chunks`. Each chunk becomes a `Frame::data`.
    fn body_from_chunks(chunks: Vec<Bytes>) -> impl Body<Data = Bytes, Error = Infallible> + Unpin {
        let stream = futures::stream::iter(
            chunks
                .into_iter()
                .map(|c| Ok::<_, Infallible>(Frame::data(c))),
        );
        StreamBody::new(stream)
    }

    async fn collect_body<B: Body<Data = Bytes> + Unpin>(mut body: B) -> Vec<Bytes> {
        let mut out = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame.ok().unwrap();
            if let Ok(data) = frame.into_data() {
                out.push(data);
            }
        }
        out
    }

    #[tokio::test]
    async fn response_chunks_reach_handler_and_pass_through() {
        let handler: Arc<RecorderHandler> = Arc::new(RecorderHandler::default());
        let body = body_from_chunks(vec![
            Bytes::from_static(b"hello "),
            Bytes::from_static(b"world"),
        ]);
        let tapped =
            TappedBody::new_response(body, dummy_req_h(), Arc::clone(&handler), StatusCode::OK);
        let out = collect_body(tapped).await;
        // Two data frames should emerge unchanged.
        assert_eq!(
            out,
            vec![Bytes::from_static(b"hello "), Bytes::from_static(b"world")]
        );
        // Handler saw both chunks.
        let seen = handler.response_chunks.lock().clone();
        assert_eq!(
            seen,
            vec![Bytes::from_static(b"hello "), Bytes::from_static(b"world")]
        );
        // on_complete fired with the expected status.
        assert_eq!(
            *handler.completed.lock(),
            Some((StatusCode::OK, ResponseOutcome::Completed))
        );
    }

    #[tokio::test]
    async fn response_chunks_mutated_in_place() {
        let handler = Arc::new(RecorderHandler {
            mutate_response_chunk: Mutex::new(Some(Box::new(|c: &mut Bytes| {
                // Uppercase each byte.
                let mut buf = BytesMut::from(&c[..]);
                for b in buf.iter_mut() {
                    *b = b.to_ascii_uppercase();
                }
                *c = buf.freeze();
            }))),
            ..Default::default()
        });
        let body = body_from_chunks(vec![Bytes::from_static(b"abc"), Bytes::from_static(b"def")]);
        let tapped =
            TappedBody::new_response(body, dummy_req_h(), Arc::clone(&handler), StatusCode::OK);
        let out = collect_body(tapped).await;
        assert_eq!(
            out,
            vec![Bytes::from_static(b"ABC"), Bytes::from_static(b"DEF")]
        );
    }

    #[tokio::test]
    async fn response_end_appends_trailing_frame() {
        let handler = Arc::new(RecorderHandler {
            end_bytes: Mutex::new(Some(Bytes::from_static(b"__MARKER__"))),
            ..Default::default()
        });
        let body = body_from_chunks(vec![Bytes::from_static(b"payload")]);
        let tapped =
            TappedBody::new_response(body, dummy_req_h(), Arc::clone(&handler), StatusCode::OK);
        let out = collect_body(tapped).await;
        assert_eq!(
            out,
            vec![
                Bytes::from_static(b"payload"),
                Bytes::from_static(b"__MARKER__")
            ],
        );
        assert_eq!(
            *handler.completed.lock(),
            Some((StatusCode::OK, ResponseOutcome::Completed))
        );
    }

    #[tokio::test]
    async fn empty_response_end_does_not_emit_extra_frame() {
        let handler: Arc<RecorderHandler> = Arc::new(RecorderHandler::default());
        let body = body_from_chunks(vec![Bytes::from_static(b"only")]);
        let tapped =
            TappedBody::new_response(body, dummy_req_h(), Arc::clone(&handler), StatusCode::OK);
        let out = collect_body(tapped).await;
        assert_eq!(out, vec![Bytes::from_static(b"only")]);
        assert_eq!(
            *handler.completed.lock(),
            Some((StatusCode::OK, ResponseOutcome::Completed))
        );
    }

    #[tokio::test]
    async fn request_tap_does_not_fire_end_or_complete() {
        let handler: Arc<RecorderHandler> = Arc::new(RecorderHandler {
            end_bytes: Mutex::new(Some(Bytes::from_static(b"SHOULD_NOT_APPEAR"))),
            ..Default::default()
        });
        let body = body_from_chunks(vec![
            Bytes::from_static(b"req1"),
            Bytes::from_static(b"req2"),
        ]);
        let tapped = TappedBody::new_request(body, dummy_req_h(), Arc::clone(&handler));
        let out = collect_body(tapped).await;
        // Request path: just the chunks, no end, no complete.
        assert_eq!(
            out,
            vec![Bytes::from_static(b"req1"), Bytes::from_static(b"req2")]
        );
        let seen = handler.request_chunks.lock().clone();
        assert_eq!(
            seen,
            vec![Bytes::from_static(b"req1"), Bytes::from_static(b"req2")]
        );
        assert!(
            handler.completed.lock().is_none(),
            "request path must NOT fire on_complete",
        );
    }

    #[tokio::test]
    async fn empty_body_still_fires_end_and_complete_for_response() {
        let handler = Arc::new(RecorderHandler {
            end_bytes: Mutex::new(Some(Bytes::from_static(b"only-end"))),
            ..Default::default()
        });
        let body = body_from_chunks(vec![]);
        let tapped = TappedBody::new_response(
            body,
            dummy_req_h(),
            Arc::clone(&handler),
            StatusCode::NO_CONTENT,
        );
        let out = collect_body(tapped).await;
        assert_eq!(out, vec![Bytes::from_static(b"only-end")]);
        assert_eq!(
            *handler.completed.lock(),
            Some((StatusCode::NO_CONTENT, ResponseOutcome::Completed))
        );
    }

    /// Body that yields `chunks`, then returns `Err(failure)` on the next
    /// poll. Exercises the error tail in `TappedBody::poll_frame`.
    fn body_with_error(
        chunks: Vec<Bytes>,
        failure: &'static str,
    ) -> impl Body<Data = Bytes, Error = &'static str> + Unpin {
        let frames: Vec<Result<Frame<Bytes>, &'static str>> = chunks
            .into_iter()
            .map(|c| Ok(Frame::data(c)))
            .chain(std::iter::once(Err(failure)))
            .collect();
        StreamBody::new(futures::stream::iter(frames))
    }

    #[tokio::test]
    async fn mid_body_error_fires_on_complete_aborted_and_skips_on_response_end() {
        let handler = Arc::new(RecorderHandler {
            // If on_response_end were (incorrectly) called, it would push
            // these bytes as a final frame. The assertion below confirms it
            // wasn't.
            end_bytes: Mutex::new(Some(Bytes::from_static(b"SHOULD_NOT_APPEAR"))),
            ..Default::default()
        });
        let body = body_with_error(
            vec![Bytes::from_static(b"partial")],
            "upstream transport kaput",
        );
        let mut tapped =
            TappedBody::new_response(body, dummy_req_h(), Arc::clone(&handler), StatusCode::OK);

        // First frame: the partial data passes through.
        let frame = tapped.frame().await.unwrap().unwrap();
        assert_eq!(frame.into_data().ok(), Some(Bytes::from_static(b"partial")));

        // Second frame: the error — but only AFTER on_complete(Aborted) ran.
        let frame = tapped.frame().await.unwrap();
        let err = frame.expect_err("expected Err after partial body");
        assert_eq!(err, "upstream transport kaput");

        // Handler observed the clean-up event.
        assert_eq!(
            *handler.completed.lock(),
            Some((StatusCode::OK, ResponseOutcome::Aborted)),
            "on_complete must fire with Aborted on mid-body error",
        );
        // on_response_end did NOT fire.
        assert!(
            !*handler.end_called.lock(),
            "on_response_end must NOT fire on mid-body error",
        );
    }
}
