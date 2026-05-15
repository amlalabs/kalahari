// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! User-facing MITM handler API.
//!
//! The [`HttpMitmHandler`] trait receives parsed HTTP request/response events
//! after TLS decryption, at each of:
//! - **Headers**: mutate in-place to rewrite (e.g., inject `Authorization`).
//!   Return [`MitmAction::Block`] to synthesize an error response without
//!   contacting upstream.
//! - **Chunks**: mutate each body chunk as it streams past. Chunks can be
//!   grown, shrunk, or emptied; the guest's wire length reflects whatever
//!   the handler leaves. Response bodies can also append a trailing frame
//!   via [`on_response_end`]. (`Content-Length` is proxy-owned for streamed
//!   MITM bodies; handlers do not see upstream/request lengths and must not
//!   add their own.)
//! - **End-of-body**: optionally emit a trailing chunk (e.g., append a marker
//!   or usage summary to a response). The wire format is chosen by the proxy
//!   from the streamed body.
//!   Only fires on a clean end — skipped if the response body was aborted
//!   mid-flight.
//! - **Complete**: fires inline on every terminal state the per-frame
//!   body state machine reaches — clean end (`Completed`), inner-body
//!   transport error (`Aborted`). Does **not** fire on a pathological
//!   early drop of the response body by hyper itself (guest RST
//!   mid-response breaks the egress pipe, hyper drops the in-flight
//!   body future). Handlers that count starts-vs-completions will see a
//!   small skew from guest-disconnect events; metric frameworks handle
//!   this the same way they do for any mid-request client drop.
//!
//! # Streaming-only contract
//!
//! There is no full-body `on_request(req: HttpRequest)` mode — chunks stream
//! past the handler as hyper emits them. Handlers that need the full body
//! must accumulate into their own `BytesMut` across `on_*_chunk` calls and
//! apply the transform at [`on_response_end`] (response side) or during
//! forwarding (request side). This aligns with hyper's native body model.
//!
//! # Monomorphized trait (no `dyn HttpMitmHandler`)
//!
//! The trait uses native `async fn`, which is not object-safe. Callers
//! construct [`TlsMitmInterceptor<H>`][crate::TlsMitmInterceptor] with a
//! concrete handler type and pass `Arc<H>` through. This saves one heap
//! allocation per method call versus the previous `#[async_trait]` shape
//! and eliminates the `dyn` vtable lookup.
//!
//! # Cancel safety
//!
//! Each async method may be dropped at any `.await` if the connection closes
//! or the task is aborted. Handlers must not leave external state partially
//! written — accumulate locally, commit atomically at [`on_complete`].
//!
//! # The well-behaved handler contract
//!
//! An [`HttpMitmHandler`] runs in-process inside the MITM proxy task. It is
//! trusted code under the same process-level invariants as the network
//! stack itself — not a sandboxed plugin. The proxy keeps its guarantees
//! tight by holding the handler to a small, explicit contract:
//!
//! ## Rules handlers must uphold
//!
//! 1. **Every `async fn` makes forward progress.** No infinite loops
//!    without an `.await` yielding point, no busy-polling that starves the
//!    hyper task. The handler runs on the same task as `hyper`'s
//!    `serve_connection` — a stuck handler hangs the whole guest
//!    connection until the outer eviction path kicks in.
//! 2. **Drop-safety.** Each method may be cancelled at any `.await` if
//!    the connection closes or the task is aborted. Don't leave external
//!    state half-written — accumulate locally, commit at
//!    [`on_complete`]. The proxy fires `on_complete` inline on every
//!    terminal body-state-machine transition (clean end, inner transport
//!    error); it does **not** fire when hyper drops the response future
//!    from the outside on a pathological guest mid-response RST.
//!    Handlers that absolutely must observe every request should count
//!    `on_request_headers` starts and accept a small skew on
//!    guest-disconnect, as any HTTP middleware does.
//! 3. **No silent fallbacks.** If the handler can't produce a required
//!    value (e.g. an API key is missing, a policy store is unreachable),
//!    return [`MitmAction::Block`] with an appropriate error status —
//!    don't substitute a default, don't "forward without the header",
//!    don't swallow the error. The guest seeing a 5xx is the correct
//!    failure signal.
//! 4. **Mutations preserve wire validity.** The handler can freely rewrite
//!    end-to-end headers and per-chunk bodies, but must stay within what the
//!    `http` crate + hyper's serializer will accept. Scheme, authority, `Host`,
//!    `Content-Length`, and transfer framing are proxy-owned for MITM streams.
//!    The crate's `xlate` module translates guest/origin protocol boundary
//!    artifacts before handler output is committed; it does not silently repair
//!    invalid fields introduced by the handler.
//!
//! ## What the proxy will NOT do
//!
//! 1. **No defensive timeouts on handler callbacks.** There is no
//!    watchdog around `on_request_headers` / `on_*_chunk` /
//!    `on_response_headers` / `on_response_end` / `on_complete`. A
//!    handler that hangs hangs the guest connection. Fix the handler;
//!    the proxy won't hedge.
//! 2. **No silent error swallowing.** Every proxy-internal failure path
//!    (upstream send failed, URI reassembly failed, handler `Block`
//!    fired) produces a concrete status visible to the guest **and**
//!    fires `on_complete` so handler-side metrics see it.
//!    `ResponseOutcome::Aborted` is reserved for mid-body transport
//!    errors — handlers that need "did this capture finish cleanly" check
//!    that discriminator, not a silent missing call.
//! 3. **No backwards-compatibility shims.** Trait changes take the form
//!    of compiler errors at the impl sites, not deprecated defaults. The
//!    RPITIT `async fn` shape means there's no stable `dyn
//!    HttpMitmHandler` anyway; every handler is monomorphized at its
//!    construction site.
//!
//! Matching guidance applies one layer down at the owned-stream
//! `TrustedTcpInterceptor` level (see `amla-vm-interceptor` top-level docs).
//!
//! [`on_response_headers`]: HttpMitmHandler::on_response_headers
//! [`on_response_end`]: HttpMitmHandler::on_response_end
//! [`on_complete`]: HttpMitmHandler::on_complete

use std::future::Future;

use bytes::{Bytes, BytesMut};
use http::{HeaderMap, Method, Response, StatusCode, Uri};

/// Action to take after inspecting a header set.
///
/// `Block` carries a full [`http::Response<Bytes>`] so handlers can synthesize
/// JSON, HTML, or any fixed-size body. Use [`MitmAction::block_status`] for
/// the common empty-body case.
#[derive(Debug)]
pub enum MitmAction {
    /// Pass through, possibly with headers mutated in place.
    Forward,
    /// Return a synthesized response to the guest; upstream is never contacted.
    ///
    /// The body is a single `Bytes` — streaming blocks don't make sense
    /// (handlers can always `on_response_chunk`-transform a real upstream
    /// response instead if they need streaming). If the handler-supplied
    /// response carries an explicit `Content-Length`, it must exactly match
    /// the `Bytes` length or the block response is rejected.
    Block(Response<Bytes>),
}

impl MitmAction {
    /// Shorthand for `Block` with an empty body and the given status.
    ///
    /// Uses `Response::new` + `status_mut` (both infallible) rather than the
    /// fallible builder API — the status is already a typed `StatusCode`,
    /// so the only way builder-form construction fails is on invalid input
    /// that this signature cannot accept.
    pub fn block_status(status: StatusCode) -> Self {
        let mut resp = Response::new(Bytes::new());
        *resp.status_mut() = status;
        Self::Block(resp)
    }
}

/// Header-only view of an HTTP request.
///
/// `uri` is origin-form (path + query only, never scheme+authority) — the
/// proxy handles cross-protocol scheme/authority plumbing via SNI + upstream
/// ALPN negotiation. Handlers that want to rewrite the path assign a new
/// `Uri::from_static("/new")` or `parse::<Uri>()` result. A handler-produced
/// absolute URI is rejected as invalid output.
///
/// `hostname` is the SNI hostname captured during the TLS handshake.
/// Authoritative across both h1 and h2 — don't fish it out of `Host:` /
/// `:authority`.
#[derive(Debug, Clone)]
pub struct HttpRequestHeaders {
    pub method: Method,
    pub uri: Uri,
    pub hostname: String,
    pub headers: HeaderMap,
}

/// Header-only view of an HTTP response.
///
/// No `reason` phrase: RFC 7230 §3.1.2 declares the phrase semantically
/// meaningless, and h2 drops it entirely. Handlers never consumed it.
#[derive(Debug, Clone)]
pub struct HttpResponseHeaders {
    pub status: StatusCode,
    pub headers: HeaderMap,
}

/// How a response ended, as reported to [`HttpMitmHandler::on_complete`].
///
/// `on_complete` fires inline on every terminal state the body state
/// machine reaches — the outcome distinguishes a clean end (`Completed`)
/// from an inner-body transport error (`Aborted`). It does **not** fire
/// when hyper itself drops the in-flight response future (guest RST
/// mid-response breaks the egress pipe, which makes hyper abandon the
/// body from the outside). Handlers that count starts-vs-completions will
/// see a skew proportional to guest-disconnect rate — treat that the same
/// way any HTTP framework handles a client drop mid-response.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum ResponseOutcome {
    /// The response body reached EOF and was fully emitted to the guest.
    /// [`HttpMitmHandler::on_response_end`] has already fired.
    Completed,
    /// The inner body yielded `Err` mid-stream (upstream transport error).
    /// `on_response_end` does **not** fire on this path (appending trailing
    /// bytes to a broken stream is nonsensical).
    Aborted,
}

/// Async, streaming MITM handler.
///
/// Default implementations forward everything unchanged, so handlers only
/// override what they need. The trait uses return-position `impl Future + Send`
/// (RPITIT) rather than bare `async fn`, because the proxy runs inside hyper's
/// `serve_connection`, which requires `Send` futures for h2 stream scheduling.
/// A bare `async fn` in trait yields an opaque future whose `Send`-ness is
/// inferred per-implementation and *not* guaranteed at the trait boundary —
/// that breaks the h2 path. Explicit `+ Send` here forces every implementor
/// to produce a Send future at monomorphization.
///
/// `'static` is required so the handler `Arc<H>` can be captured by the
/// trusted interceptor future.
pub trait HttpMitmHandler: Send + Sync + 'static {
    /// Called when request headers have been parsed, before any body.
    ///
    /// Mutate `req` in place to rewrite the outgoing request. Return
    /// [`MitmAction::Block`] to synthesize an error response to the guest
    /// without contacting upstream.
    fn on_request_headers(
        &self,
        _req: &mut HttpRequestHeaders,
    ) -> impl Future<Output = MitmAction> + Send {
        async { MitmAction::Forward }
    }

    /// Called for each chunk of request body before it is forwarded upstream.
    ///
    /// The handler can mutate `chunk` in place (e.g., to redact). It cannot
    /// drop or split the chunk; to drop content, replace with
    /// `Bytes::new()`. To grow the body, buffer in handler state and emit
    /// the result on the last chunk (handler must track this itself).
    fn on_request_chunk(
        &self,
        _req: &HttpRequestHeaders,
        _chunk: &mut Bytes,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Called when response headers have arrived from upstream.
    ///
    /// Mutate `resp` in place to rewrite. Return [`MitmAction::Block`] to
    /// replace the entire response with a synthesized one. `Content-Length` is
    /// proxy-owned for streamed responses and is not present in `resp`; adding
    /// it here is rejected.
    fn on_response_headers(
        &self,
        _req: &HttpRequestHeaders,
        _resp: &mut HttpResponseHeaders,
    ) -> impl Future<Output = MitmAction> + Send {
        async { MitmAction::Forward }
    }

    /// Called for each chunk of response body before it is forwarded to the
    /// guest. Mutate in place; cannot change chunk count.
    fn on_response_chunk(
        &self,
        _req: &HttpRequestHeaders,
        _chunk: &mut Bytes,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Called after the upstream response body has ended, before the guest
    /// sees the final frame.
    ///
    /// If the handler appends bytes to `trailing`, they are emitted as a
    /// final data frame. Useful for trailers, markers, or usage summaries.
    ///
    /// The proxy owns response body framing, so appending bytes here is safe
    /// without any handler-side header adjustment.
    fn on_response_end(
        &self,
        _req: &HttpRequestHeaders,
        _trailing: &mut BytesMut,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }

    /// Observability hook: called inline on every terminal state the body
    /// state machine reaches. "Response" here means "whatever status the
    /// guest sees" — forwarded upstream responses, handler blocks, and
    /// proxy-synthesized error statuses (502 on upstream failure, 500 on
    /// handler-produced malformed URIs, etc.).
    ///
    /// Fires once per request in the common paths:
    /// - Clean end: [`ResponseOutcome::Completed`] after
    ///   [`on_response_end`][Self::on_response_end].
    /// - Mid-body inner transport error:
    ///   [`ResponseOutcome::Aborted`] before the error bubbles up.
    /// - Blocked / proxy-synthesized status:
    ///   [`ResponseOutcome::Completed`] (fully-known body).
    ///
    /// Does **not** fire when hyper drops the in-flight response body
    /// from the outside — this happens when the guest RSTs mid-response
    /// and the egress pipe breaks. Handlers that count every
    /// `on_request_headers` start against `on_complete` ends will see a
    /// skew proportional to guest-disconnect rate. That matches how any
    /// HTTP middleware handles client drop mid-response.
    ///
    /// - `status` is the final status sent to the guest (the handler's,
    ///   if it blocked; otherwise upstream's, or a proxy-synthesized
    ///   status on internal errors).
    /// - `outcome == Aborted` means the body actually started streaming
    ///   and then got truncated by an upstream transport error. Treat it
    ///   as "do not commit this capture" in metrics / external writes.
    fn on_complete(
        &self,
        _req: &HttpRequestHeaders,
        _status: StatusCode,
        _outcome: ResponseOutcome,
    ) -> impl Future<Output = ()> + Send {
        async {}
    }
}
