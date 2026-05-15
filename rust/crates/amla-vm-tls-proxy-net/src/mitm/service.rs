// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! `hyper::service_fn` that drives a single request/response exchange
//! through the user's [`HttpMitmHandler`].
//!
//! Flow:
//! 1. Extract [`HttpRequestHeaders`] from the incoming hyper request.
//! 2. Call `on_request_headers`. [`MitmAction::Block`] short-circuits.
//! 3. Wrap the request body in a [`TappedBody`] and forward to the upstream
//!    actor via its command channel.
//! 4. Await the upstream response. Channel/send errors → 502.
//! 5. Extract [`HttpResponseHeaders`]; call `on_response_headers`; handle
//!    `Block` the same way.
//! 6. Wrap the response body in a [`TappedBody`] so per-chunk hooks +
//!    `on_response_end` + `on_complete` fire as the guest reads.
//!
//! The returned `Result<_, Infallible>` means hyper's server keeps the guest
//! connection alive across upstream errors — each error becomes a synthesized
//! 502 response, not a connection teardown.

use bytes::Bytes;
use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::uri::PathAndQuery;
use http::{HeaderMap, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use std::convert::Infallible;
use std::fmt;
use std::sync::Arc;
use tokio::time::timeout;

use crate::MitmTimeouts;
use crate::handler::{
    HttpMitmHandler, HttpRequestHeaders, HttpResponseHeaders, MitmAction, ResponseOutcome,
};
use crate::mitm::body::TappedBody;
use crate::mitm::upstream::{Protocol, UpstreamBody, UpstreamEndpoint, UpstreamSender};
use crate::mitm::xlate;

/// Body type on the wire to the guest.
// Unsync body: `TappedBody`'s internal `BoxFuture` is `Send` but not `Sync`
// (async blocks over `Arc<H>` state-machine-erase to a `Send`-only future).
// Hyper doesn't require `Sync` on response bodies, so `UnsyncBoxBody` is
// the right choice.
pub type GuestBody = http_body_util::combinators::UnsyncBoxBody<Bytes, hyper::Error>;

/// Process one guest request end-to-end.
///
/// `guest_proto` / `host_proto` are the ALPN-negotiated HTTP versions on each
/// leg. When they differ this function delegates the RFC 7540 §8.1.2 boundary
/// translation and post-handler validation to [`xlate`]. Boundary artifacts
/// from the guest/origin may be stripped; h2-invalid headers introduced by the
/// trusted handler are rejected instead of silently repaired.
///
/// Every branch that returns a synthesized status (`Block`, malformed request,
/// dead upstream, handler-produced garbage) funnels through [`blocked_response`].
/// No silent fallbacks: if a required value can't be produced, we fail loudly
/// with an appropriate HTTP error.
#[allow(clippy::too_many_lines)]
pub async fn proxy_request<H: HttpMitmHandler>(
    req: Request<Incoming>,
    handler: Arc<H>,
    upstream: UpstreamEndpoint,
    origin: Arc<xlate::OriginAuthority>,
    guest_proto: Protocol,
    timeouts: MitmTimeouts,
) -> Result<Response<GuestBody>, Infallible> {
    log::trace!(
        "proxy_request: {} {} host={}",
        req.method(),
        req.uri(),
        origin.host()
    );
    let (req, mut req_h) = match bind_guest_request_or_421(req, handler.as_ref(), &origin).await {
        Ok(bound) => bound,
        Err(response) => return Ok(response),
    };

    if let Err(e) = normalize_request_for_handler(&mut req_h) {
        log::warn!("proxy_request: failed to normalize request for handler: {e}");
        handler
            .on_complete(
                &req_h,
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed,
            )
            .await;
        return Ok(status_response(StatusCode::INTERNAL_SERVER_ERROR));
    }
    xlate::sanitize_request_for_handler(&mut req_h.headers, guest_proto);
    let pre_handler_req_headers = req_h.headers.clone();

    // 1. Guest-request header hook. A `Block` here produces a complete
    //    synthesized response (no upstream contact, no body streaming), so
    //    the `on_complete` observability hook fires with `Completed` and the
    //    handler-chosen status — upholding the trait's "exactly once per
    //    response" guarantee.
    if let Some(response) =
        run_request_headers_or_block(handler.as_ref(), &mut req_h, guest_proto).await
    {
        return Ok(response);
    }

    let req_h = Arc::new(req_h);

    // 2. Rebuild upstream request from mutated headers; tap the body.
    //    `build_upstream_request` fails only on a handler-induced URI that
    //    can't be reassembled into a valid `http::Uri`. Proxy-owned authority
    //    and framing are validated immediately after, before any host contact.
    let upstream_req =
        match build_upstream_request(req.into_request(), &req_h, Arc::clone(&handler)) {
            Ok(r) => r,
            Err(status) => {
                handler
                    .on_complete(&req_h, status, ResponseOutcome::Completed)
                    .await;
                return Ok(status_response(status));
            }
        };

    if let Err(e) = validate_handler_request_output(&upstream_req) {
        log::warn!("proxy_request: handler produced invalid request output: {e}");
        handler
            .on_complete(
                &req_h,
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed,
            )
            .await;
        return Ok(status_response(StatusCode::INTERNAL_SERVER_ERROR));
    }

    // 2a. Open the host leg lazily. This is intentionally after the
    //     request-header hook and upstream-request rebuild so `Block` and
    //     handler-produced malformed requests never contact the origin.
    let (upstream_sender, host_proto) = match open_upstream_or_502(
        &upstream,
        upstream_req.method().clone(),
        upstream_req.uri().clone(),
        handler.as_ref(),
        &req_h,
    )
    .await
    {
        Ok(pair) => pair,
        Err(response) => return Ok(response),
    };

    // 2b. Cross-protocol hygiene for the host leg.
    let upstream_req = match finalize_request_for_host_or_500(
        upstream_req,
        handler.as_ref(),
        &req_h,
        &origin,
        guest_proto,
        host_proto,
        &pre_handler_req_headers,
    )
    .await
    {
        Ok(req) => req,
        Err(response) => return Ok(response),
    };

    // 3. Dispatch directly via the cloned `UpstreamSender`. hyper's h1
    //    serializes internally; h2 multiplexes. Any send error (closed
    //    connection, protocol error, etc.) becomes a synthesized 502 — the
    //    guest connection stays alive for the next request.
    log::trace!("proxy_request: sending upstream");
    let upstream_resp = match send_upstream_or_502(
        &upstream_sender,
        upstream_req,
        handler.as_ref(),
        &req_h,
        timeouts,
    )
    .await
    {
        Ok(response) => response,
        Err(response) => return Ok(response),
    };
    log::trace!(
        "proxy_request: got upstream response, status={}",
        upstream_resp.status()
    );

    // 4. Guest-response header hook. A `Block` here replaces the upstream
    //    response wholesale; the upstream body future is dropped, so no
    //    tap chain runs — fire `on_complete` directly with the handler-
    //    chosen status, same rule as the request-block branch above.
    let (mut parts, body) = upstream_resp.into_parts();
    // Translate origin/guest boundary headers before the handler sees them.
    // Anything invalid that appears after `on_response_headers` is handler
    // output and is rejected below instead of stripped.
    xlate::sanitize_response_for_handler(&mut parts.headers, guest_proto);
    let mut resp_h = to_response_headers(&parts);
    match handler.on_response_headers(&req_h, &mut resp_h).await {
        MitmAction::Block(response) => {
            return Ok(handler_block_response_or_500(
                handler.as_ref(),
                &req_h,
                response,
                guest_proto,
                "response block response",
            )
            .await);
        }
        MitmAction::Forward => {
            if let Err(e) = validate_handler_response_output(&resp_h.headers) {
                log::warn!("proxy_request: handler produced invalid response output: {e}");
                return Ok(complete_with_status(
                    handler.as_ref(),
                    &req_h,
                    StatusCode::INTERNAL_SERVER_ERROR,
                )
                .await);
            }
            apply_response_headers(&mut parts, resp_h);
            if let Some(response) = validate_response_for_guest_or_500(
                &parts.headers,
                handler.as_ref(),
                &req_h,
                guest_proto,
            )
            .await
            {
                return Ok(response);
            }
        }
    }

    // 5. Tap the response body for per-chunk / end / complete hooks.
    let status = parts.status;
    let tapped = TappedBody::new_response(body, Arc::clone(&req_h), Arc::clone(&handler), status);
    let boxed: GuestBody = tapped.boxed_unsync();
    Ok(Response::from_parts(parts, boxed))
}

async fn bind_guest_request_or_421<'a, H: HttpMitmHandler>(
    req: Request<Incoming>,
    handler: &H,
    origin: &'a xlate::OriginAuthority,
) -> Result<
    (
        xlate::OriginCheckedRequest<'a, Incoming>,
        HttpRequestHeaders,
    ),
    Response<GuestBody>,
> {
    let req_h = to_request_headers(&req, origin.host());
    match xlate::OriginCheckedRequest::new(req, origin) {
        Ok(req) => Ok((req, req_h)),
        Err(e) => {
            log::warn!(
                "proxy_request: rejecting request authority before handler/upstream dispatch: {e}"
            );
            handler
                .on_complete(
                    &req_h,
                    StatusCode::MISDIRECTED_REQUEST,
                    ResponseOutcome::Completed,
                )
                .await;
            Err(status_response(StatusCode::MISDIRECTED_REQUEST))
        }
    }
}

async fn open_upstream_or_502<H: HttpMitmHandler>(
    upstream: &UpstreamEndpoint,
    method: http::Method,
    uri: http::Uri,
    handler: &H,
    req_h: &HttpRequestHeaders,
) -> Result<(UpstreamSender, Protocol), Response<GuestBody>> {
    match upstream.sender_and_protocol().await {
        Ok(pair) => Ok(pair),
        Err(e) => {
            let status = e.guest_status();
            log::warn!(
                "proxy_request: upstream initialization failed for {method} {uri}: {e:#} -> {status}"
            );
            handler
                .on_complete(req_h, status, ResponseOutcome::Completed)
                .await;
            Err(status_response(status))
        }
    }
}

async fn send_upstream_or_502<H: HttpMitmHandler>(
    upstream_sender: &UpstreamSender,
    req: Request<UpstreamBody>,
    handler: &H,
    req_h: &HttpRequestHeaders,
    timeouts: MitmTimeouts,
) -> Result<Response<Incoming>, Response<GuestBody>> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    match timeout(
        timeouts.upstream_response_headers(),
        upstream_sender.send_request(req),
    )
    .await
    {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(e)) => {
            let source = std::error::Error::source(&e).map(std::string::ToString::to_string);
            log::warn!(
                "proxy_request: upstream send_request failed for {method} {uri}: \
                 {e:#} (source: {source:?}) -> 502"
            );
            handler
                .on_complete(req_h, StatusCode::BAD_GATEWAY, ResponseOutcome::Completed)
                .await;
            Err(status_response(StatusCode::BAD_GATEWAY))
        }
        Err(_) => {
            log::warn!(
                "proxy_request: upstream response headers timed out for {method} {uri} \
                 after {:?} -> 504",
                timeouts.upstream_response_headers(),
            );
            handler
                .on_complete(
                    req_h,
                    StatusCode::GATEWAY_TIMEOUT,
                    ResponseOutcome::Completed,
                )
                .await;
            Err(status_response(StatusCode::GATEWAY_TIMEOUT))
        }
    }
}

async fn run_request_headers_or_block<H: HttpMitmHandler>(
    handler: &H,
    req_h: &mut HttpRequestHeaders,
    guest_proto: Protocol,
) -> Option<Response<GuestBody>> {
    match handler.on_request_headers(req_h).await {
        MitmAction::Block(response) => Some(
            handler_block_response_or_500(
                handler,
                req_h,
                response,
                guest_proto,
                "request block response",
            )
            .await,
        ),
        MitmAction::Forward => None,
    }
}

async fn finalize_request_for_host_or_500<H: HttpMitmHandler>(
    req: Request<UpstreamBody>,
    handler: &H,
    req_h: &HttpRequestHeaders,
    origin: &xlate::OriginAuthority,
    guest_proto: Protocol,
    host_proto: Protocol,
    pre_handler_headers: &HeaderMap,
) -> Result<Request<UpstreamBody>, Response<GuestBody>> {
    let req = match xlate::OriginCheckedRequest::new(req, origin) {
        Ok(req) => req,
        Err(e) => {
            log::warn!("proxy_request: rejecting request authority after handler: {e}");
            return Err(
                complete_with_status(handler, req_h, StatusCode::MISDIRECTED_REQUEST).await,
            );
        }
    };

    match xlate::finalize_request_for_host(req, guest_proto, host_proto, pre_handler_headers) {
        Ok(req) => Ok(req.into_request()),
        Err(xlate::RequestFinalizeError::Authority(e)) => {
            log::warn!("proxy_request: rejecting request authority after handler: {e}");
            Err(complete_with_status(handler, req_h, StatusCode::MISDIRECTED_REQUEST).await)
        }
        Err(xlate::RequestFinalizeError::H2Header(e)) => {
            log::warn!("proxy_request: handler produced invalid request headers: {e}");
            Err(complete_with_status(handler, req_h, StatusCode::INTERNAL_SERVER_ERROR).await)
        }
    }
}

async fn validate_response_for_guest_or_500<H: HttpMitmHandler>(
    headers: &HeaderMap,
    handler: &H,
    req_h: &HttpRequestHeaders,
    guest_proto: Protocol,
) -> Option<Response<GuestBody>> {
    match xlate::validate_response_for_guest(headers, guest_proto) {
        Ok(()) => None,
        Err(e) => {
            log::warn!("proxy_request: handler produced invalid response headers: {e}");
            Some(complete_with_status(handler, req_h, StatusCode::INTERNAL_SERVER_ERROR).await)
        }
    }
}

async fn complete_with_status<H: HttpMitmHandler>(
    handler: &H,
    req_h: &HttpRequestHeaders,
    status: StatusCode,
) -> Response<GuestBody> {
    handler
        .on_complete(req_h, status, ResponseOutcome::Completed)
        .await;
    status_response(status)
}

async fn handler_block_response_or_500<H: HttpMitmHandler>(
    handler: &H,
    req_h: &HttpRequestHeaders,
    response: Response<Bytes>,
    guest_proto: Protocol,
    context: &'static str,
) -> Response<GuestBody> {
    let status = response.status();
    match blocked_response(response, guest_proto) {
        Ok(response) => {
            handler
                .on_complete(req_h, status, ResponseOutcome::Completed)
                .await;
            response
        }
        Err(e) => {
            log::warn!("proxy_request: handler produced invalid {context}: {e}");
            complete_with_status(handler, req_h, StatusCode::INTERNAL_SERVER_ERROR).await
        }
    }
}

/// Adapt a handler-supplied `Response<Bytes>` into the guest-bound body type.
///
/// The body is fixed-size, so a handler-supplied `Content-Length` is accepted
/// only when it exactly matches `bytes.len()`. Stale values are rejected rather
/// than silently stripped or repaired.
fn blocked_response(
    response: Response<Bytes>,
    guest_proto: Protocol,
) -> Result<Response<GuestBody>, InvalidHandlerOutput> {
    let (parts, bytes) = response.into_parts();
    validate_content_length_exact(&parts.headers, bytes.len())?;
    validate_handler_block_response_output(&parts.headers, guest_proto)?;
    let body: GuestBody = Full::new(bytes)
        .map_err(|never: Infallible| match never {})
        .boxed_unsync();
    Ok(Response::from_parts(parts, body))
}

/// Synthesize a body-less response with the given status. Used for proxy-
/// internal error paths (502 from a dead upstream, etc.) — handlers express
/// their own errors via [`MitmAction::Block`] + [`MitmAction::block_status`].
fn status_response(status: StatusCode) -> Response<GuestBody> {
    let body: GuestBody = Full::new(Bytes::new())
        .map_err(|never: Infallible| match never {})
        .boxed_unsync();
    let mut resp = Response::new(body);
    *resp.status_mut() = status;
    resp
}

/// Extract headers view from a hyper `Request<Incoming>`.
///
/// `hostname` comes from SNI (the MITM task captures it during peek) and is
/// authoritative; for h1, the `Host:` header and request-target scheme may
/// not match SNI (legacy proxy quirks, absolute-form URIs). Trust SNI.
///
/// Clones the `HeaderMap` because the handler may mutate it and we still
/// need the original `Request<Incoming>` intact to reuse the body. This is
/// one allocation per request; the header count is small.
fn to_request_headers(req: &Request<Incoming>, hostname: &str) -> HttpRequestHeaders {
    HttpRequestHeaders {
        method: req.method().clone(),
        uri: req.uri().clone(),
        hostname: hostname.to_string(),
        headers: req.headers().clone(),
    }
}

/// Normalize the handler-visible request boundary.
///
/// Handlers operate on origin-form request targets and the authoritative
/// `hostname` field. Scheme, authority, `Host`, and transfer framing are
/// proxy-owned and reconstructed later from TLS origin metadata.
fn normalize_request_for_handler(
    req_h: &mut HttpRequestHeaders,
) -> Result<(), InvalidHandlerOutput> {
    let path_and_query = req_h
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    let mut parts = http::uri::Parts::default();
    parts.path_and_query = Some(path_and_query);
    match http::Uri::from_parts(parts) {
        Ok(uri) => {
            req_h.uri = uri;
            Ok(())
        }
        Err(e) => Err(InvalidHandlerOutput::new(format!(
            "failed to normalize handler URI {}: {e}",
            req_h.uri
        ))),
    }
}

/// Extract headers view from upstream response parts.
fn to_response_headers(parts: &http::response::Parts) -> HttpResponseHeaders {
    HttpResponseHeaders {
        status: parts.status,
        headers: parts.headers.clone(),
    }
}

/// Apply (possibly handler-mutated) `resp_h` back onto the response parts.
///
/// No fallibility: the `HeaderMap` on `resp_h` was type-validated by the
/// `http` crate at construction, and proxy-owned framing was validated before
/// this point.
fn apply_response_headers(parts: &mut http::response::Parts, resp_h: HttpResponseHeaders) {
    parts.status = resp_h.status;
    parts.headers = resp_h.headers;
}

/// Build the upstream request from a hyper `Request<Incoming>` plus the
/// (already-hooked) request headers.
///
/// `req_h.uri` is handler-controlled origin-form. The proxy deliberately does
/// not backfill scheme or authority from the original request here; host-leg
/// finalization reconstructs proxy-owned authority from TLS origin metadata
/// after validating that the handler did not reintroduce it.
///
/// # Failure
///
/// `Uri::from_parts` can still fail on genuinely nonsensical combinations a
/// handler might have produced. Surface those as `INTERNAL_SERVER_ERROR` so
/// the guest sees a 500 and production logs record the handler bug.
fn build_upstream_request<H: HttpMitmHandler>(
    req: Request<Incoming>,
    req_h: &Arc<HttpRequestHeaders>,
    handler: Arc<H>,
) -> Result<Request<UpstreamBody>, StatusCode> {
    let body = req.into_body();
    let tapped = TappedBody::new_request(body, Arc::clone(req_h), handler);
    let boxed: UpstreamBody = tapped.boxed_unsync();

    let uri = http::Uri::from_parts(req_h.uri.clone().into_parts()).map_err(|e| {
        log::warn!(
            "upstream URI reassembly failed for {} {}: {e}",
            req_h.method,
            req_h.uri,
        );
        StatusCode::INTERNAL_SERVER_ERROR
    })?;

    let mut out = Request::new(boxed);
    *out.method_mut() = req_h.method.clone();
    *out.uri_mut() = uri;
    *out.headers_mut() = req_h.headers.clone();
    Ok(out)
}

#[derive(Debug, Clone)]
struct InvalidHandlerOutput {
    reason: String,
}

impl InvalidHandlerOutput {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for InvalidHandlerOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for InvalidHandlerOutput {}

fn validate_handler_request_output<B>(req: &Request<B>) -> Result<(), InvalidHandlerOutput> {
    if req.uri().scheme().is_some() {
        return Err(InvalidHandlerOutput::new(
            "request URI scheme is proxy-owned; handler URI must be origin-form",
        ));
    }
    if req.uri().authority().is_some() {
        return Err(InvalidHandlerOutput::new(
            "request URI authority is proxy-owned; handler URI must be origin-form",
        ));
    }
    reject_proxy_owned_header(req.headers(), &HOST, "request Host header")?;
    reject_proxy_owned_header(req.headers(), &CONTENT_LENGTH, "request Content-Length")?;
    reject_proxy_owned_header(
        req.headers(),
        &TRANSFER_ENCODING,
        "request Transfer-Encoding",
    )?;
    Ok(())
}

fn validate_handler_response_output(headers: &HeaderMap) -> Result<(), InvalidHandlerOutput> {
    reject_proxy_owned_header(headers, &CONTENT_LENGTH, "response Content-Length")?;
    reject_proxy_owned_header(headers, &TRANSFER_ENCODING, "response Transfer-Encoding")
}

fn validate_handler_block_response_output(
    headers: &HeaderMap,
    guest_proto: Protocol,
) -> Result<(), InvalidHandlerOutput> {
    reject_proxy_owned_header(headers, &TRANSFER_ENCODING, "response Transfer-Encoding")?;
    xlate::validate_response_for_guest(headers, guest_proto)
        .map_err(|error| InvalidHandlerOutput::new(format!("{error}")))?;
    Ok(())
}

fn reject_proxy_owned_header(
    headers: &HeaderMap,
    name: &http::header::HeaderName,
    label: &'static str,
) -> Result<(), InvalidHandlerOutput> {
    if headers.contains_key(name) {
        return Err(InvalidHandlerOutput::new(format!(
            "{label} is proxy-owned and must not be set by handlers"
        )));
    }
    Ok(())
}

fn validate_content_length_exact(
    headers: &HeaderMap,
    expected_len: usize,
) -> Result<(), InvalidHandlerOutput> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Ok(());
    };
    if values.next().is_some() {
        return Err(InvalidHandlerOutput::new(
            "block response has multiple Content-Length headers",
        ));
    }
    let observed = value.to_str().map_err(|_| {
        InvalidHandlerOutput::new("block response Content-Length is not valid ASCII")
    })?;
    let parsed = observed.parse::<u64>().map_err(|_| {
        InvalidHandlerOutput::new("block response Content-Length is not a decimal length")
    })?;
    let expected = u64::try_from(expected_len)
        .map_err(|_| InvalidHandlerOutput::new("block response body is too large"))?;
    if parsed != expected {
        return Err(InvalidHandlerOutput::new(format!(
            "block response Content-Length {parsed} does not match body length {expected}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mitm::upstream::UpstreamSender;
    use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
    use hyper::service::service_fn;
    use hyper_util::rt::TokioIo;
    use parking_lot::Mutex;

    struct TestHandler {
        block_request: Option<StatusCode>,
        inject_header: Option<(HeaderName, HeaderValue)>,
        block_response: Option<StatusCode>,
        inject_response_header: Option<(HeaderName, HeaderValue)>,
        response_header_tag: Option<HeaderValue>,
        observed_requests: Mutex<Vec<HttpRequestHeaders>>,
        observed_responses: Mutex<Vec<HttpResponseHeaders>>,
        completions: Mutex<Vec<(StatusCode, ResponseOutcome)>>,
    }

    impl TestHandler {
        fn new() -> Self {
            Self {
                block_request: None,
                inject_header: None,
                block_response: None,
                inject_response_header: None,
                response_header_tag: None,
                observed_requests: Mutex::new(Vec::new()),
                observed_responses: Mutex::new(Vec::new()),
                completions: Mutex::new(Vec::new()),
            }
        }
    }

    impl HttpMitmHandler for TestHandler {
        async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
            self.observed_requests.lock().push(req.clone());
            if let Some(s) = self.block_request {
                return MitmAction::block_status(s);
            }
            if let Some((k, v)) = self.inject_header.as_ref() {
                req.headers.insert(k.clone(), v.clone());
            }
            MitmAction::Forward
        }
        async fn on_response_headers(
            &self,
            _req: &HttpRequestHeaders,
            resp: &mut HttpResponseHeaders,
        ) -> MitmAction {
            self.observed_responses.lock().push(resp.clone());
            if let Some(s) = self.block_response {
                return MitmAction::block_status(s);
            }
            if let Some((k, v)) = self.inject_response_header.as_ref() {
                resp.headers.insert(k.clone(), v.clone());
            }
            if let Some(tag) = self.response_header_tag.as_ref() {
                resp.headers
                    .insert(HeaderName::from_static("x-mitm-tag"), tag.clone());
            }
            MitmAction::Forward
        }
        async fn on_complete(
            &self,
            _req: &HttpRequestHeaders,
            status: StatusCode,
            outcome: ResponseOutcome,
        ) {
            self.completions.lock().push((status, outcome));
        }
    }

    /// Spawn a hyper h1 server that records requests and returns canned
    /// responses. Returns (upstream sender, recorded requests). The sender
    /// is `UpstreamSender` — cloneable, callable directly; hyper internally
    /// serializes on the h1 connection.
    ///
    /// The connection driver future is spawned here (test-only) so callers
    /// don't have to wire it into their own select!. Production uses
    /// `tokio::join!(serve_connection, conn_driver)` in `run_proxy`.
    async fn spawn_upstream<F, Fut>(
        service: F,
    ) -> (
        UpstreamSender,
        std::sync::Arc<Mutex<Vec<(Method, Uri, HeaderMap, Bytes)>>>,
    )
    where
        F: Fn(Method, Uri, HeaderMap, Bytes) -> Fut + Send + Sync + 'static + Clone,
        Fut: std::future::Future<Output = Result<http::Response<GuestBody>, Infallible>> + Send,
    {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let recorded = std::sync::Arc::new(Mutex::new(Vec::new()));
        let recorded_for_task = recorded.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: http::Request<Incoming>| {
                let service = service.clone();
                let recorded = recorded_for_task.clone();
                async move {
                    let method = req.method().clone();
                    let uri = req.uri().clone();
                    let headers = req.headers().clone();
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    recorded.lock().push((
                        method.clone(),
                        uri.clone(),
                        headers.clone(),
                        body.clone(),
                    ));
                    service(method, uri, headers, body).await
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(server_side), svc)
                .await
            {
                log::debug!("test spawn_upstream h1 serve_connection ended: {e}");
            }
        });
        let (sender, conn) =
            crate::mitm::upstream::handshake(client_side, crate::mitm::upstream::Protocol::Http1)
                .await
                .expect("handshake");
        tokio::spawn(conn);
        (sender, recorded)
    }

    /// Drive a full request/response through `proxy_request` and assert.
    /// Uses real hyper pairs on both sides so Request<Incoming> is real.
    /// Returns the raw guest-side response for the test to assert on.
    async fn run_proxy_request_e2e<H: HttpMitmHandler>(
        handler: Arc<H>,
        method: &str,
        path: &str,
        body: Bytes,
        upstream_service: impl Fn(
            Method,
            Uri,
            HeaderMap,
            Bytes,
        ) -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<http::Response<GuestBody>, Infallible>>
                    + Send,
            >,
        >
        + Send
        + Sync
        + 'static
        + Clone,
    ) -> (http::response::Parts, Bytes) {
        let (upstream_tx, _recorded) = spawn_upstream(upstream_service).await;

        // Build a mini h1 server on guest-side to get a real Request<Incoming>.
        let (guest_client, guest_server) = tokio::io::duplex(64 * 1024);

        let handler_clone = Arc::clone(&handler);
        let upstream_tx_clone = upstream_tx.clone();
        let origin = Arc::new(xlate::OriginAuthority::new("test.example.com", 443));
        // Server task: runs proxy_request for whatever request comes in.
        // Fixed at h1↔h1 here — cross-protocol paths are exercised by
        // dedicated tests below.
        let server_task = tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler_clone);
                let upstream = upstream_tx_clone.clone();
                let origin = Arc::clone(&origin);
                async move {
                    proxy_request(
                        req,
                        handler,
                        UpstreamEndpoint::ready(upstream, Protocol::Http1),
                        origin,
                        Protocol::Http1,
                        MitmTimeouts::default(),
                    )
                    .await
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(guest_server), svc)
                .await
            {
                log::debug!("test run_proxy_request_e2e guest-side serve_connection ended: {e}");
            }
        });

        // Client-side: send a request and drain the response body. Draining
        // *before* dropping the sender is load-bearing: streamed MITM
        // responses use proxy-owned framing, so the guest-side hyper
        // connection won't close until the body is fully consumed —
        // leaving `server_task.await` hung below.
        let (mut sender, client_conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(guest_client))
                .await
                .expect("client handshake");
        tokio::spawn(async move {
            if let Err(e) = client_conn.await {
                log::debug!("test run_proxy_request_e2e client_conn ended: {e}");
            }
        });
        let req = Request::builder()
            .method(method)
            .uri(path)
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = sender.send_request(req).await.expect("send");
        let (parts, resp_body) = resp.into_parts();
        let body_bytes = resp_body.collect().await.expect("collect body").to_bytes();

        drop(sender);
        if let Err(e) = server_task.await {
            log::debug!("test run_proxy_request_e2e server_task join ended: {e}");
        }
        (parts, body_bytes)
    }

    #[tokio::test]
    async fn block_on_request_headers_skips_upstream() {
        let handler = Arc::new(TestHandler {
            block_request: Some(StatusCode::FORBIDDEN),
            ..TestHandler::new()
        });
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();
        let service = move |_m, _u, _h, _b| {
            let cc = cc.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = Full::new(Bytes::from_static(b"should-not-reach"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };
        let (parts, _body) = run_proxy_request_e2e(
            Arc::clone(&handler),
            "GET",
            "/anything",
            Bytes::new(),
            service,
        )
        .await;
        assert_eq!(parts.status, 403);
        assert_eq!(
            call_count.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "upstream must NOT be called when Block at request headers"
        );
        // `on_complete` must still fire exactly once on the block path — the
        // "exactly once per response" trait guarantee covers blocked responses.
        let completions = handler.completions.lock().clone();
        assert_eq!(
            completions,
            vec![(StatusCode::FORBIDDEN, ResponseOutcome::Completed)]
        );
    }

    #[tokio::test]
    async fn request_headers_mutation_reaches_upstream() {
        let handler = Arc::new(TestHandler {
            inject_header: Some((
                HeaderName::from_static("authorization"),
                HeaderValue::from_static("Bearer sk-test"),
            )),
            ..TestHandler::new()
        });
        let seen_auth: std::sync::Arc<Mutex<Option<String>>> =
            std::sync::Arc::new(Mutex::new(None));
        let seen_auth_c = seen_auth.clone();
        let service = move |_m, _u, headers: HeaderMap, _b| {
            let seen_auth = seen_auth_c.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let auth = headers
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        .map(str::to_string);
                    *seen_auth.lock() = auth;
                    let body = Full::new(Bytes::from_static(b"ok"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };
        let (parts, body) = run_proxy_request_e2e(handler, "GET", "/", Bytes::new(), service).await;
        assert_eq!(parts.status, 200);
        assert_eq!(body, Bytes::from_static(b"ok"));
        assert_eq!(
            seen_auth.lock().clone(),
            Some("Bearer sk-test".to_string()),
            "upstream must receive injected Authorization header"
        );
    }

    #[tokio::test]
    async fn handler_injected_host_header_is_rejected_before_upstream() {
        let handler = Arc::new(TestHandler {
            inject_header: Some((HOST, HeaderValue::from_static("test.example.com"))),
            ..TestHandler::new()
        });
        let handler_for_assert = Arc::clone(&handler);
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();
        let service = move |_m, _u, _h, _b| {
            let cc = cc.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = Full::new(Bytes::from_static(b"should-not-reach"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };

        let (parts, body) = run_proxy_request_e2e(handler, "GET", "/", Bytes::new(), service).await;

        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_eq!(
            handler_for_assert.completions.lock().clone(),
            vec![(
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed
            )]
        );
    }

    #[tokio::test]
    async fn handler_injected_request_content_length_is_rejected_before_upstream() {
        let handler = Arc::new(TestHandler {
            inject_header: Some((CONTENT_LENGTH, HeaderValue::from_static("999"))),
            ..TestHandler::new()
        });
        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();
        let service = move |_m, _u, _h, _b| {
            let cc = cc.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = Full::new(Bytes::from_static(b"should-not-reach"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };

        let (parts, body) =
            run_proxy_request_e2e(handler, "POST", "/", Bytes::from_static(b"abc"), service).await;

        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn handler_absolute_request_uri_is_rejected_before_upstream() {
        struct AbsoluteUriHandler;
        impl HttpMitmHandler for AbsoluteUriHandler {
            async fn on_request_headers(&self, req: &mut HttpRequestHeaders) -> MitmAction {
                req.uri = "https://test.example.com/absolute".parse().unwrap();
                MitmAction::Forward
            }
        }

        let call_count = std::sync::Arc::new(std::sync::atomic::AtomicU32::new(0));
        let cc = call_count.clone();
        let service = move |_m, _u, _h, _b| {
            let cc = cc.clone();
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    cc.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    let body = Full::new(Bytes::from_static(b"should-not-reach"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };

        let (parts, body) = run_proxy_request_e2e(
            Arc::new(AbsoluteUriHandler),
            "GET",
            "/",
            Bytes::new(),
            service,
        )
        .await;

        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
        assert_eq!(call_count.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn block_on_response_headers_replaces_response() {
        let handler = Arc::new(TestHandler {
            block_response: Some(StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS),
            ..TestHandler::new()
        });
        let service = move |_m, _u, _h, _b| {
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let body = Full::new(Bytes::from_static(b"original"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };
        let (parts, body) =
            run_proxy_request_e2e(Arc::clone(&handler), "GET", "/", Bytes::new(), service).await;
        assert_eq!(parts.status, 451);
        assert!(
            body.is_empty(),
            "blocked response should have empty body, got {body:?}"
        );
        let completions = handler.completions.lock().clone();
        assert_eq!(
            completions,
            vec![(
                StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS,
                ResponseOutcome::Completed
            )]
        );
    }

    #[tokio::test]
    async fn handler_injected_response_content_length_is_rejected() {
        let handler = Arc::new(TestHandler {
            inject_response_header: Some((CONTENT_LENGTH, HeaderValue::from_static("999"))),
            ..TestHandler::new()
        });
        let handler_for_assert = Arc::clone(&handler);
        let service = move |_m, _u, _h, _b| {
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let body = Full::new(Bytes::from_static(b"origin"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        };

        let (parts, body) = run_proxy_request_e2e(handler, "GET", "/", Bytes::new(), service).await;

        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
        assert_eq!(
            handler_for_assert.completions.lock().clone(),
            vec![(
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed
            )]
        );
    }

    #[tokio::test]
    async fn origin_chunked_response_is_not_treated_as_handler_output() {
        let handler = Arc::new(TestHandler::new());
        let handler_for_assert = Arc::clone(&handler);
        let service = move |_m, _u, _h, _b| {
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let body = Full::new(Bytes::from_static(b"origin"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder()
                        .status(200)
                        .header(TRANSFER_ENCODING, "chunked")
                        .body(body)
                        .unwrap())
                });
            fut
        };

        let (parts, body) = run_proxy_request_e2e(handler, "GET", "/", Bytes::new(), service).await;

        assert_eq!(parts.status, 200);
        assert_eq!(body, Bytes::from_static(b"origin"));
        let observed = handler_for_assert.observed_responses.lock().clone();
        assert_eq!(observed.len(), 1);
        assert!(
            observed[0].headers.get(TRANSFER_ENCODING).is_none(),
            "origin Transfer-Encoding is proxy-owned framing, not handler-visible metadata"
        );
    }

    #[tokio::test]
    async fn block_response_mismatched_content_length_is_rejected() {
        struct BadLengthBlocker;
        impl HttpMitmHandler for BadLengthBlocker {
            async fn on_request_headers(&self, _req: &mut HttpRequestHeaders) -> MitmAction {
                MitmAction::Block(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header(CONTENT_LENGTH, "999")
                        .body(Bytes::from_static(b"abc"))
                        .unwrap(),
                )
            }
        }
        let service = |_m,
                       _u,
                       _h,
                       _b|
         -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<http::Response<GuestBody>, Infallible>>
                    + Send,
            >,
        > {
            Box::pin(async move {
                let body = Full::new(Bytes::from_static(b"never"))
                    .map_err(|never| match never {})
                    .boxed_unsync();
                Ok(Response::builder().status(200).body(body).unwrap())
            })
        };

        let (parts, body) = run_proxy_request_e2e(
            Arc::new(BadLengthBlocker),
            "GET",
            "/",
            Bytes::new(),
            service,
        )
        .await;

        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
    }

    #[test]
    fn streamed_handler_response_transfer_encoding_is_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));

        let err = validate_handler_response_output(&headers).unwrap_err();
        assert!(err.to_string().contains("Transfer-Encoding"), "{err}");
    }

    #[test]
    fn block_response_transfer_encoding_is_rejected() {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(TRANSFER_ENCODING, "chunked")
            .body(Bytes::from_static(b"blocked"))
            .unwrap();

        let err = blocked_response(response, Protocol::Http1).unwrap_err();
        assert!(err.to_string().contains("Transfer-Encoding"), "{err}");
    }

    #[test]
    fn h2_block_response_forbidden_headers_are_rejected() {
        let response = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(http::header::CONNECTION, "close")
            .body(Bytes::from_static(b"blocked"))
            .unwrap();

        let err = blocked_response(response, Protocol::Http2).unwrap_err();
        assert!(err.to_string().contains("HTTP/2"), "{err}");
    }

    #[tokio::test]
    async fn block_with_body_reaches_guest() {
        // `MitmAction::Block` now carries a full `Response<Bytes>` so handlers
        // can return a non-empty error body (e.g. a JSON explanation).
        struct BodyBlocker;
        impl HttpMitmHandler for BodyBlocker {
            async fn on_request_headers(&self, _req: &mut HttpRequestHeaders) -> MitmAction {
                MitmAction::Block(
                    Response::builder()
                        .status(StatusCode::FORBIDDEN)
                        .header("content-type", "application/json")
                        .body(Bytes::from_static(br#"{"error":"blocked"}"#))
                        .unwrap(),
                )
            }
        }
        let service = |_m,
                       _u,
                       _h,
                       _b|
         -> std::pin::Pin<
            Box<
                dyn std::future::Future<Output = Result<http::Response<GuestBody>, Infallible>>
                    + Send,
            >,
        > {
            Box::pin(async move {
                let body = Full::new(Bytes::from_static(b"never"))
                    .map_err(|never| match never {})
                    .boxed_unsync();
                Ok(Response::builder().status(200).body(body).unwrap())
            })
        };
        let (parts, body) =
            run_proxy_request_e2e(Arc::new(BodyBlocker), "GET", "/", Bytes::new(), service).await;
        assert_eq!(parts.status, 403);
        assert_eq!(body, Bytes::from_static(br#"{"error":"blocked"}"#));
        assert_eq!(
            parts
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok()),
            Some("application/json"),
        );
    }

    #[tokio::test]
    async fn upstream_error_becomes_502() {
        let handler = Arc::new(TestHandler::new());

        // Simulate dead upstream: handshake against a duplex whose other
        // side closes immediately. The first `send_request` after the
        // connection dies will return `Err`, which the service layer must
        // translate to 502.
        let (_client_side, server_side) = tokio::io::duplex(64 * 1024);
        // Keep `_client_side` alive so the duplex half doesn't drop on us —
        // we handshake against the other half and then drop it to simulate
        // upstream collapse mid-request.
        let (client_side_for_handshake, server_side_dropper) = tokio::io::duplex(64 * 1024);
        drop(server_side_dropper);
        drop(server_side);
        let (upstream_sender, conn) =
            crate::mitm::upstream::handshake(client_side_for_handshake, Protocol::Http1)
                .await
                .expect("handshake");
        tokio::spawn(conn);

        let (guest_client, guest_server) = tokio::io::duplex(64 * 1024);
        let handler_clone = Arc::clone(&handler);
        let origin = Arc::new(xlate::OriginAuthority::new("test.example.com", 443));
        tokio::spawn(async move {
            let upstream_sender = upstream_sender;
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler_clone);
                let upstream = upstream_sender.clone();
                let origin = Arc::clone(&origin);
                async move {
                    proxy_request(
                        req,
                        handler,
                        UpstreamEndpoint::ready(upstream, Protocol::Http1),
                        origin,
                        Protocol::Http1,
                        MitmTimeouts::default(),
                    )
                    .await
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(guest_server), svc)
                .await
            {
                log::debug!(
                    "test upstream_error_becomes_502 guest-side serve_connection ended: {e}"
                );
            }
        });

        let (mut sender, client_conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(guest_client))
                .await
                .unwrap();
        tokio::spawn(async move {
            if let Err(e) = client_conn.await {
                log::debug!("test upstream_error_becomes_502 client_conn ended: {e}");
            }
        });
        let req = Request::builder()
            .method("GET")
            .uri("/")
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = sender.send_request(req).await.expect("send");
        assert_eq!(resp.status(), 502);
        // `on_complete` is awaited inside `proxy_request` before the 502
        // response is returned, so by the time `send_request` resolves the
        // hook has already fired. No yield / sleep needed.
        let completions = handler.completions.lock().clone();
        assert_eq!(
            completions,
            vec![(StatusCode::BAD_GATEWAY, ResponseOutcome::Completed)],
            "upstream failure must still fire on_complete exactly once"
        );
    }

    // --- Cross-protocol tests ----------------------------------------------
    //
    // Strategy: wire a real hyper guest-side and a real hyper upstream-side,
    // where each side uses its own protocol (h1 or h2). This exercises the
    // full `proxy_request` path including xlate's header/URI sanitization.

    /// Spin up an h2 upstream on a duplex pair and return an `UpstreamSender`
    /// plus a Mutex-backed record of what the upstream observed.
    async fn spawn_upstream_h2() -> (
        UpstreamSender,
        std::sync::Arc<Mutex<Vec<(Method, Uri, HeaderMap, Bytes)>>>,
    ) {
        use hyper_util::rt::TokioExecutor;
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let recorded = std::sync::Arc::new(Mutex::new(Vec::new()));
        let rec_for_task = recorded.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: http::Request<Incoming>| {
                let rec = rec_for_task.clone();
                async move {
                    let method = req.method().clone();
                    let uri = req.uri().clone();
                    let headers = req.headers().clone();
                    let body = req.into_body().collect().await.unwrap().to_bytes();
                    rec.lock().push((method, uri, headers, body));
                    let body = Full::new(Bytes::from_static(b"upstream-h2-ok"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok::<_, Infallible>(Response::builder().status(200).body(body).unwrap())
                }
            });
            if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(server_side), svc)
                .await
            {
                log::debug!("test spawn_upstream_h2 serve_connection ended: {e}");
            }
        });
        let (sender, conn) = crate::mitm::upstream::handshake(client_side, Protocol::Http2)
            .await
            .expect("h2 handshake");
        tokio::spawn(conn);
        (sender, recorded)
    }

    /// Run a request through `proxy_request` with the guest driven by a real
    /// hyper h1 client and the upstream driven by an h2 server.
    async fn run_h1_to_h2_e2e<H: HttpMitmHandler>(
        handler: Arc<H>,
        method: &str,
        uri_str: &str,
        host_header: Option<&str>,
        body: Bytes,
    ) -> (
        http::response::Parts,
        Bytes,
        Vec<(Method, Uri, HeaderMap, Bytes)>,
    ) {
        let (upstream_tx, recorded) = spawn_upstream_h2().await;
        let (guest_client, guest_server) = tokio::io::duplex(64 * 1024);

        let handler_clone = Arc::clone(&handler);
        let upstream_tx_clone = upstream_tx.clone();
        let origin = Arc::new(xlate::OriginAuthority::new("origin.example.com", 443));
        let server_task = tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler_clone);
                let upstream = upstream_tx_clone.clone();
                let origin = Arc::clone(&origin);
                async move {
                    proxy_request(
                        req,
                        handler,
                        UpstreamEndpoint::ready(upstream, Protocol::Http2),
                        origin,
                        Protocol::Http1,
                        MitmTimeouts::default(),
                    )
                    .await
                }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(guest_server), svc)
                .await
            {
                log::debug!("test run_h1_to_h2_e2e guest-side serve_connection ended: {e}");
            }
        });

        let (mut sender, client_conn) =
            hyper::client::conn::http1::handshake(TokioIo::new(guest_client))
                .await
                .expect("client handshake");
        tokio::spawn(async move {
            if let Err(e) = client_conn.await {
                log::debug!("test run_h1_to_h2_e2e client_conn ended: {e}");
            }
        });
        let mut builder = Request::builder().method(method).uri(uri_str);
        if let Some(h) = host_header {
            builder = builder.header("host", h);
        }
        let req = builder
            .body(
                Full::new(body)
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = sender.send_request(req).await.expect("send");
        let (parts, resp_body) = resp.into_parts();
        let body_bytes = resp_body.collect().await.expect("body").to_bytes();
        drop(sender);
        if let Err(e) = server_task.await {
            log::debug!("test run_h1_to_h2_e2e server_task join ended: {e}");
        }
        (parts, body_bytes, recorded.lock().clone())
    }

    #[tokio::test]
    async fn h1_guest_to_h2_host_rejects_handler_injected_h2_forbidden_headers() {
        // h1→h2 boundary translation may strip guest-origin hop-by-hop
        // headers, but a trusted handler injecting them is a handler bug.
        // Do not silently repair it before forwarding to h2.
        let handler = Arc::new(TestHandler {
            inject_header: Some((
                HeaderName::from_static("connection"),
                HeaderValue::from_static("close"),
            )),
            ..TestHandler::new()
        });
        let handler_for_assert = Arc::clone(&handler);
        let (parts, body, recorded) = run_h1_to_h2_e2e(
            handler,
            "GET",
            "/ping",
            Some("origin.example.com"),
            Bytes::new(),
        )
        .await;
        assert_eq!(parts.status, 500);
        assert!(body.is_empty());
        assert!(
            recorded.is_empty(),
            "invalid handler output must not reach h2 upstream"
        );
        assert_eq!(
            handler_for_assert.completions.lock().clone(),
            vec![(
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed
            )]
        );
    }

    #[tokio::test]
    async fn h1_guest_to_h2_host_uses_sni_when_host_header_missing() {
        // Direct xlate-level test — hyper's h1 client auto-adds Host, so we
        // can't drive this end-to-end without Host via the hyper client.
        use crate::mitm::upstream::UpstreamBody;
        let req: http::Request<UpstreamBody> = http::Request::builder()
            .method("GET")
            .uri("/path")
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let pre_handler_headers = req.headers().clone();
        let origin = xlate::OriginAuthority::new("sni.example.com", 443);
        let req = xlate::OriginCheckedRequest::new(req, &origin).unwrap();
        let req = crate::mitm::xlate::finalize_request_for_host(
            req,
            Protocol::Http1,
            Protocol::Http2,
            &pre_handler_headers,
        )
        .unwrap();
        assert_eq!(req.request().uri().host(), Some("sni.example.com"));
        assert_eq!(req.request().uri().scheme_str(), Some("https"));
        assert!(req.request().headers().get("host").is_none());
    }

    /// h2 guest → h1 host: hyper's h2 server puts `:authority` in URI
    /// authority; xlate must synthesize a `Host:` header from that before
    /// dispatch to the h1 upstream.
    #[tokio::test]
    // Reason: lock guard intentionally spans the entire body so that
    // the operation observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    async fn h2_guest_to_h1_host_synthesizes_host_header() {
        use hyper_util::rt::TokioExecutor;

        let handler = Arc::new(TestHandler::new());

        let (upstream_tx, recorded) = spawn_upstream(|_m, _u, headers, _b| {
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let host = headers
                        .get("host")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let body = Full::new(Bytes::from(host))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        })
        .await;

        let (guest_client, guest_server) = tokio::io::duplex(64 * 1024);

        let handler_clone = Arc::clone(&handler);
        let upstream_tx_clone = upstream_tx.clone();
        let origin = Arc::new(xlate::OriginAuthority::new("origin.example.com", 443));
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler_clone);
                let upstream = upstream_tx_clone.clone();
                let origin = Arc::clone(&origin);
                async move {
                    proxy_request(
                        req,
                        handler,
                        UpstreamEndpoint::ready(upstream, Protocol::Http1),
                        origin,
                        Protocol::Http2,
                        MitmTimeouts::default(),
                    )
                    .await
                }
            });
            if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(guest_server), svc)
                .await
            {
                log::debug!(
                    "test h2_guest_to_h1_host_synthesizes_host_header guest-side serve_connection ended: {e}"
                );
            }
        });

        let (mut sender, client_conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(guest_client))
                .await
                .expect("h2 client handshake");
        tokio::spawn(async move {
            if let Err(e) = client_conn.await {
                log::debug!(
                    "test h2_guest_to_h1_host_synthesizes_host_header client_conn ended: {e}"
                );
            }
        });

        let req = Request::builder()
            .method("GET")
            .uri("https://origin.example.com/x")
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = sender.send_request(req).await.expect("send");
        let (parts, resp_body) = resp.into_parts();
        let body_bytes = resp_body.collect().await.expect("body").to_bytes();

        assert_eq!(parts.status, 200);
        assert_eq!(body_bytes, Bytes::from_static(b"origin.example.com"));
        let observed = handler.observed_requests.lock().clone();
        assert_eq!(observed.len(), 1);
        assert_eq!(observed[0].uri, Uri::from_static("/x"));
        assert!(observed[0].headers.get(HOST).is_none());

        let rec = recorded.lock();
        assert_eq!(rec.len(), 1);
        let (_method, _uri, headers, _b) = &rec[0];
        let host = headers.get("host").and_then(|v| v.to_str().ok());
        assert_eq!(host, Some("origin.example.com"));
    }

    #[tokio::test]
    async fn h2_guest_rejects_handler_injected_h2_forbidden_response_header() {
        use hyper_util::rt::TokioExecutor;

        let handler = Arc::new(TestHandler {
            inject_response_header: Some((
                HeaderName::from_static("connection"),
                HeaderValue::from_static("close"),
            )),
            ..TestHandler::new()
        });

        let (upstream_tx, _recorded) = spawn_upstream(|_m, _u, _headers, _b| {
            let fut: std::pin::Pin<Box<dyn std::future::Future<Output = _> + Send>> =
                Box::pin(async move {
                    let body = Full::new(Bytes::from_static(b"origin"))
                        .map_err(|never| match never {})
                        .boxed_unsync();
                    Ok(Response::builder().status(200).body(body).unwrap())
                });
            fut
        })
        .await;

        let (guest_client, guest_server) = tokio::io::duplex(64 * 1024);

        let handler_clone = Arc::clone(&handler);
        let upstream_tx_clone = upstream_tx.clone();
        let origin = Arc::new(xlate::OriginAuthority::new("origin.example.com", 443));
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let handler = Arc::clone(&handler_clone);
                let upstream = upstream_tx_clone.clone();
                let origin = Arc::clone(&origin);
                async move {
                    proxy_request(
                        req,
                        handler,
                        UpstreamEndpoint::ready(upstream, Protocol::Http1),
                        origin,
                        Protocol::Http2,
                        MitmTimeouts::default(),
                    )
                    .await
                }
            });
            if let Err(e) = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(guest_server), svc)
                .await
            {
                log::debug!(
                    "test h2_guest_rejects_handler_injected_h2_forbidden_response_header guest-side serve_connection ended: {e}"
                );
            }
        });

        let (mut sender, client_conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(guest_client))
                .await
                .expect("h2 client handshake");
        tokio::spawn(async move {
            if let Err(e) = client_conn.await {
                log::debug!(
                    "test h2_guest_rejects_handler_injected_h2_forbidden_response_header client_conn ended: {e}"
                );
            }
        });

        let req = Request::builder()
            .method("GET")
            .uri("https://origin.example.com/x")
            .body(
                http_body_util::Empty::<Bytes>::new()
                    .map_err(|never| match never {})
                    .boxed_unsync(),
            )
            .unwrap();
        let resp = sender.send_request(req).await.expect("send");
        let (parts, resp_body) = resp.into_parts();
        let body_bytes = resp_body.collect().await.expect("body").to_bytes();

        assert_eq!(parts.status, 500);
        assert!(body_bytes.is_empty());
        assert_eq!(
            handler.completions.lock().clone(),
            vec![(
                StatusCode::INTERNAL_SERVER_ERROR,
                ResponseOutcome::Completed
            )]
        );
    }
}
