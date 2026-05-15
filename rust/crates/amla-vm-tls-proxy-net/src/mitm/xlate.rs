// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Cross-protocol (h1 ↔ h2) header and URI sanitization.
//!
//! # What problem this solves
//!
//! Hyper's `http::Request<B>` and `http::Response<B>` types are
//! protocol-agnostic: the same value is accepted by both the h1 and h2
//! client/server APIs. That makes cross-protocol proxying *almost* free —
//! except the HTTP/2 spec (RFC 7540 §8.1.2) forbids a set of h1 hop-by-hop
//! headers that hyper's h2 client/server will reject as malformed. We also
//! have to paper over the `Host:` header ↔ `:authority` pseudo-header split
//! so that whichever protocol we're speaking on the wire sees the identifier
//! it expects.
//!
//! This module does only the RFC-mandated minimum. It is called from two
//! boundaries in `service::proxy_request`:
//!
//!   * `finalize_request_for_host` — just before the request is dispatched to
//!     the upstream actor. Knows the host-leg protocol.
//!   * `sanitize_response_for_handler` — before response headers are exposed
//!     to the handler. Knows the guest-leg protocol and removes proxy-owned
//!     framing before trusted code can mutate headers.
//!
//! # Design choices (pinned here so future readers understand *why*)
//!
//! 1. **Boundary translation is not handler repair.** Connection-specific
//!    headers that came from the guest/origin can be stripped as h1↔h2
//!    protocol translation. Headers introduced or changed by the trusted
//!    handler after its callback are validated instead; invalid h2 state is
//!    rejected by the service layer rather than silently repaired.
//!
//! 2. **HTTP authority is evidence, not routing state.**
//!    The target origin is fixed by the TLS/SYN metadata captured before HTTP
//!    parsing. `Host` / `:authority` may be absent and synthesized from that
//!    origin, but if either is present it must match the fixed origin. This
//!    deliberately rejects domain-fronting-style `SNI != Host` requests: policy
//!    is evaluated before decryption, so letting HTTP headers retarget the
//!    upstream would bypass that policy.
//!
//! 3. **Only `TE: trailers` is preserved when stripping; any other `TE` value
//!    is dropped.** This matches RFC 7540 §8.1.2.2 literally.
//!
//! 4. **This module does not touch body framing.** hyper's h1/h2 serializers
//!    handle the chunked↔frames translation off our `http_body::Body` trait
//!    impl transparently. `TappedBody` passes trailer frames through, so
//!    trailer semantics survive the crossing.

use std::{borrow::Cow, fmt, net::Ipv6Addr};

use http::header::{CONTENT_LENGTH, HOST, TRANSFER_ENCODING};
use http::uri::{Authority, PathAndQuery, Scheme};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Uri};

use crate::mitm::upstream::{Protocol, UpstreamBody};

const DEFAULT_HTTPS_PORT: u16 = 443;

/// Origin selected by pre-HTTP metadata: SNI or explicit no-SNI IP identity
/// plus the TCP destination port.
///
/// HTTP translation treats this as the only routing authority. Guest or
/// handler-provided `Host` / `:authority` values must match this value; missing
/// values are synthesized from it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OriginAuthority {
    host: String,
    port: u16,
}

impl OriginAuthority {
    pub(crate) fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }

    pub(crate) fn host(&self) -> &str {
        &self.host
    }

    fn authority_string(&self) -> String {
        let host = host_for_authority(&self.host);
        if self.port == DEFAULT_HTTPS_PORT {
            host.into_owned()
        } else {
            format!("{host}:{}", self.port)
        }
    }
}

/// Request newtype that carries the proof that its HTTP authority matches the
/// pre-HTTP origin selected by SNI/no-SNI TCP identity.
#[derive(Debug)]
pub struct OriginCheckedRequest<'a, B> {
    request: Request<B>,
    origin: &'a OriginAuthority,
}

impl<'a, B> OriginCheckedRequest<'a, B> {
    pub(crate) fn new(
        request: Request<B>,
        origin: &'a OriginAuthority,
    ) -> Result<Self, AuthorityError> {
        check_request_authority(&request, origin)?;
        Ok(Self { request, origin })
    }

    pub(crate) const fn request(&self) -> &Request<B> {
        &self.request
    }

    pub(crate) fn into_request(self) -> Request<B> {
        self.request
    }

    const fn request_mut(&mut self) -> &mut Request<B> {
        &mut self.request
    }

    const fn origin(&self) -> &OriginAuthority {
        self.origin
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum AuthoritySource {
    Uri,
    HostHeader,
}

impl fmt::Display for AuthoritySource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Uri => f.write_str("request URI authority"),
            Self::HostHeader => f.write_str("Host header"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityErrorKind {
    Invalid,
    DuplicateHostHeaders,
    Mismatch { observed: String },
}

/// A request attempted to use an HTTP authority different from the fixed TLS
/// origin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityError {
    source: AuthoritySource,
    expected: String,
    kind: AuthorityErrorKind,
}

impl AuthorityError {
    fn invalid(source: AuthoritySource, origin: &OriginAuthority) -> Self {
        Self {
            source,
            expected: origin.authority_string(),
            kind: AuthorityErrorKind::Invalid,
        }
    }

    fn duplicate_host_headers(origin: &OriginAuthority) -> Self {
        Self {
            source: AuthoritySource::HostHeader,
            expected: origin.authority_string(),
            kind: AuthorityErrorKind::DuplicateHostHeaders,
        }
    }

    fn mismatch(source: AuthoritySource, origin: &OriginAuthority, observed: String) -> Self {
        Self {
            source,
            expected: origin.authority_string(),
            kind: AuthorityErrorKind::Mismatch { observed },
        }
    }
}

impl fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.kind {
            AuthorityErrorKind::Invalid => {
                write!(f, "{} is not a valid HTTP authority", self.source)
            }
            AuthorityErrorKind::DuplicateHostHeaders => {
                write!(f, "request has multiple Host headers")
            }
            AuthorityErrorKind::Mismatch { observed } => write!(
                f,
                "{} {observed:?} does not match TLS origin {:?}",
                self.source, self.expected
            ),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// Headers RFC 7540 §8.1.2.2 prohibits in HTTP/2 messages, plus a few close
/// relatives (`proxy-connection`, `keep-alive`) that proxies commonly see.
/// `te` gets special handling below (only `trailers` is legal).
const H2_FORBIDDEN_HEADERS: &[&str] = &[
    "connection",
    "transfer-encoding",
    "keep-alive",
    "proxy-connection",
    "upgrade",
];

/// A handler-produced header set cannot be serialized as HTTP/2.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidH2Header {
    name: HeaderName,
}

impl InvalidH2Header {
    const fn new(name: HeaderName) -> Self {
        Self { name }
    }
}

impl fmt::Display for InvalidH2Header {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "header {:?} is not allowed on an HTTP/2 leg", self.name)
    }
}

impl std::error::Error for InvalidH2Header {}

/// Final request validation can fail either because handler output is not
/// serializable on an h2 leg or because it attempts to route outside the
/// already selected TLS origin.
#[derive(Debug)]
pub enum RequestFinalizeError {
    Authority(AuthorityError),
    H2Header(InvalidH2Header),
}

impl fmt::Display for RequestFinalizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Authority(e) => e.fmt(f),
            Self::H2Header(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for RequestFinalizeError {}

impl From<AuthorityError> for RequestFinalizeError {
    fn from(value: AuthorityError) -> Self {
        Self::Authority(value)
    }
}

impl From<InvalidH2Header> for RequestFinalizeError {
    fn from(value: InvalidH2Header) -> Self {
        Self::H2Header(value)
    }
}

/// Remove hop-by-hop / connection-specific headers that must not appear in
/// an h2 message. Called on both requests (to h2 upstream) and responses
/// (to h2 guest). Operates in-place on a `HeaderMap`.
///
/// Also drops `TE` unless its *only* value is `trailers` (RFC 7540 §8.1.2.2).
/// No case-insensitive trimming / multi-value parsing is done — if the client
/// sent `TE: trailers, deflate` we drop the whole header, which is stricter
/// than the spec requires but correct (the forbidden codings have no effect
/// in h2 anyway).
fn strip_h2_forbidden(headers: &mut HeaderMap) {
    let names = h2_forbidden_targets(headers);
    strip_header_names(headers, names);
}

/// Strip h2-forbidden boundary headers, optionally refusing to strip headers
/// that were introduced or changed after a handler callback.
fn strip_h2_forbidden_checked(
    headers: &mut HeaderMap,
    pre_handler_headers: Option<&HeaderMap>,
) -> Result<(), InvalidH2Header> {
    let names = h2_forbidden_targets(headers);

    if let Some(before) = pre_handler_headers {
        for name in &names {
            if !same_header_values(headers, before, name) {
                return Err(InvalidH2Header::new(name.clone()));
            }
        }
    }

    strip_header_names(headers, names);
    Ok(())
}

/// Validate a post-handler header set that is about to be serialized on an h2
/// leg. Unlike [`strip_h2_forbidden`], this never mutates or repairs.
fn validate_h2_headers(headers: &HeaderMap) -> Result<(), InvalidH2Header> {
    let names = h2_forbidden_targets(headers);
    if let Some(name) = names.into_iter().next() {
        return Err(InvalidH2Header::new(name));
    }
    Ok(())
}

fn h2_forbidden_targets(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut names = h2_forbidden_present(headers);
    for name in connection_listed_headers(headers) {
        push_unique(&mut names, name);
    }
    names
}

fn strip_header_names(headers: &mut HeaderMap, names: Vec<HeaderName>) {
    for name in names {
        while headers.remove(&name).is_some() {}
    }
}

fn h2_forbidden_present(headers: &HeaderMap) -> Vec<HeaderName> {
    let mut names = Vec::new();
    for name in H2_FORBIDDEN_HEADERS {
        let name = HeaderName::from_static(name);
        if headers.contains_key(&name) {
            push_unique(&mut names, name);
        }
    }

    // TE: only `trailers` is legal on h2.
    let te_allowed = headers
        .get("te")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("trailers"));
    if headers.contains_key("te") && !te_allowed {
        push_unique(&mut names, HeaderName::from_static("te"));
    }

    // `Host` is not on RFC 7540's forbidden list, but this proxy uses
    // `:authority` from the URI on h2 legs. Duplicating it as a regular
    // header is invalid proxy output for our boundary.
    if headers.contains_key(HOST) {
        push_unique(&mut names, HOST);
    }

    names
}

fn connection_listed_headers(headers: &HeaderMap) -> Vec<HeaderName> {
    // RFC 7540 §8.1.2.2: when translating h1→h2, headers *named in* the
    // `Connection:` header value are hop-by-hop and must also be removed.
    // Skipping tokens that aren't valid header names (e.g. "close", or
    // garbage containing CRLF) is safe: they can't name a real header.
    headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .filter_map(|t| HeaderName::try_from(t).ok())
        .collect()
}

fn same_header_values(left: &HeaderMap, right: &HeaderMap, name: &HeaderName) -> bool {
    let mut left_values = left.get_all(name).iter();
    let mut right_values = right.get_all(name).iter();
    loop {
        match (left_values.next(), right_values.next()) {
            (None, None) => return true,
            (Some(a), Some(b)) if a == b => {}
            _ => return false,
        }
    }
}

fn push_unique(names: &mut Vec<HeaderName>, name: HeaderName) {
    if !names.contains(&name) {
        names.push(name);
    }
}

/// Normalize request headers before the handler callback sees them.
///
/// `Host` and `Content-Length` are proxy-owned: the handler gets the fixed
/// `hostname` field plus a streaming body, and finalization reconstructs
/// authority/framing from proxy state. For h1 guests, hop-by-hop and
/// transfer-coding headers also describe the guest wire connection, not
/// end-to-end request intent. Strip all of these before handler mutation so
/// later finalization can reject any reintroduced values as handler output.
pub fn sanitize_request_for_handler(headers: &mut HeaderMap, guest_proto: Protocol) {
    let mut names = Vec::new();
    if headers.contains_key(HOST) {
        push_unique(&mut names, HOST);
    }
    if headers.contains_key(CONTENT_LENGTH) {
        push_unique(&mut names, CONTENT_LENGTH);
    }

    if guest_proto == Protocol::Http1 {
        for name in H2_FORBIDDEN_HEADERS {
            let name = HeaderName::from_static(name);
            if headers.contains_key(&name) {
                push_unique(&mut names, name);
            }
        }
        for name in connection_listed_headers(headers) {
            push_unique(&mut names, name);
        }
        if headers.contains_key("te") {
            push_unique(&mut names, HeaderName::from_static("te"));
        }
    }

    for name in names {
        while headers.remove(&name).is_some() {}
    }
}

/// Ensure the request URI has scheme + authority set so hyper's h2 client can
/// generate `:scheme` and `:authority` pseudo-headers. Always uses `https`
/// for the scheme because this module is only reached after the MITM has
/// already terminated TLS on the host leg — anything else is a bug.
///
/// `origin` is the authority captured before HTTP parsing; used when the
/// incoming URI lacks an authority (which happens when the guest spoke h1 and
/// sent an origin-form request-line like `GET /foo HTTP/1.1`).
fn ensure_h2_uri(
    checked: &mut OriginCheckedRequest<'_, UpstreamBody>,
) -> Result<(), AuthorityError> {
    let origin_authority = checked.origin().authority_string();
    let existing_authority = checked.request().uri().authority().cloned();
    let existing_pq = checked
        .request()
        .uri()
        .path_and_query()
        .cloned()
        // Empty path is illegal in h2 (`:path` must be non-empty for origin
        // requests). Default to "/" — matches what hyper's h1 client would
        // have put on the wire for `GET` to the root.
        .unwrap_or_else(|| PathAndQuery::from_static("/"));

    let authority = match existing_authority {
        Some(a) => a,
        None => match Authority::try_from(origin_authority.as_str()) {
            Ok(a) => a,
            Err(e) => {
                // `origin` came from SNI or an explicit no-SNI IP rule, so
                // this path is vanishingly rare.
                log::warn!(
                    "xlate: origin authority {origin_authority:?} is not a valid HTTP authority ({e}); \
                     rejecting request"
                );
                return Err(AuthorityError::invalid(
                    AuthoritySource::Uri,
                    checked.origin(),
                ));
            }
        },
    };

    let mut parts = checked.request().uri().clone().into_parts();
    parts.scheme = Some(Scheme::HTTPS);
    parts.authority = Some(authority);
    parts.path_and_query = Some(existing_pq);
    match Uri::from_parts(parts) {
        Ok(new_uri) => {
            *checked.request_mut().uri_mut() = new_uri;
            Ok(())
        }
        Err(e) => {
            log::debug!("xlate: failed to rebuild URI with authority+scheme: {e}");
            Err(AuthorityError::invalid(
                AuthoritySource::Uri,
                checked.origin(),
            ))
        }
    }
}

/// Ensure a `Host:` header is present on a request that's going to an h1
/// upstream. If the guest spoke h2, hyper's h2 server maps `:authority` into
/// `uri.authority()` and does NOT synthesize a `Host` header — but h1 servers
/// require it (RFC 7230 §5.4).
///
/// Existing `Host` values are validated against `origin`; missing values are
/// synthesized from it. The URI authority, if any, is also only evidence and
/// must match the same origin.
fn ensure_host_header(
    checked: &mut OriginCheckedRequest<'_, UpstreamBody>,
) -> Result<(), AuthorityError> {
    if checked.request().headers().contains_key(HOST) {
        return Ok(());
    }
    let authority_str = checked.origin().authority_string();
    match HeaderValue::try_from(authority_str.as_str()) {
        Ok(v) => {
            checked.request_mut().headers_mut().insert(HOST, v);
            Ok(())
        }
        Err(e) => {
            log::warn!(
                "xlate: cannot build Host header from {authority_str:?} ({e}); \
                 rejecting request"
            );
            Err(AuthorityError::invalid(
                AuthoritySource::HostHeader,
                checked.origin(),
            ))
        }
    }
}

fn check_request_authority<B>(
    req: &Request<B>,
    origin: &OriginAuthority,
) -> Result<(), AuthorityError> {
    if let Some(authority) = req.uri().authority() {
        check_authority_matches_origin(AuthoritySource::Uri, authority, origin)?;
    }

    let mut hosts = req.headers().get_all(HOST).iter();
    if let Some(host) = hosts.next() {
        if hosts.next().is_some() {
            return Err(AuthorityError::duplicate_host_headers(origin));
        }
        let host = host
            .to_str()
            .map_err(|_| AuthorityError::invalid(AuthoritySource::HostHeader, origin))?;
        let authority = Authority::try_from(host)
            .map_err(|_| AuthorityError::invalid(AuthoritySource::HostHeader, origin))?;
        check_authority_matches_origin(AuthoritySource::HostHeader, &authority, origin)?;
    }

    Ok(())
}

fn check_authority_matches_origin(
    source: AuthoritySource,
    authority: &Authority,
    origin: &OriginAuthority,
) -> Result<(), AuthorityError> {
    if authority.as_str().contains('@') {
        return Err(AuthorityError::invalid(source, origin));
    }
    let observed_port = authority.port_u16().unwrap_or(DEFAULT_HTTPS_PORT);
    if observed_port != origin.port || !authority_host_matches(authority.host(), &origin.host) {
        return Err(AuthorityError::mismatch(
            source,
            origin,
            authority.as_str().to_string(),
        ));
    }
    Ok(())
}

fn authority_host_matches(observed: &str, expected: &str) -> bool {
    observed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map_or_else(
            || observed.eq_ignore_ascii_case(expected),
            |unbracketed| unbracketed.eq_ignore_ascii_case(expected),
        )
}

fn host_for_authority(host: &str) -> Cow<'_, str> {
    if host.parse::<Ipv6Addr>().is_ok() {
        Cow::Owned(format!("[{host}]"))
    } else {
        Cow::Borrowed(host)
    }
}

/// Cross-protocol request rewriter. Called exactly once per request, right
/// before dispatch to the upstream actor.
///
/// # Authority resolution (h2 host leg)
///
/// The target origin must end up in `uri.authority()` so hyper's h2 client
/// emits a valid `:authority` pseudo-header. The proxy no longer derives that
/// authority from HTTP headers: SNI/no-SNI TCP identity is the fixed origin,
/// and HTTP authority fields are accepted only when they match it.
fn translate_request_for_host<'a>(
    mut req: OriginCheckedRequest<'a, UpstreamBody>,
    guest_proto: Protocol,
    host_proto: Protocol,
    pre_handler_headers: Option<&HeaderMap>,
) -> Result<OriginCheckedRequest<'a, UpstreamBody>, RequestFinalizeError> {
    match (guest_proto, host_proto) {
        (_, Protocol::Http2) => {
            ensure_h2_uri(&mut req)?;
            strip_h2_forbidden_checked(req.request_mut().headers_mut(), pre_handler_headers)?;
            validate_h2_headers(req.request().headers())?;
            Ok(req)
        }
        (_, Protocol::Http1) => {
            // h2 guests carry `:authority` in the URI and do not emit `Host`.
            // h1 handlers can also remove Host. Both cases are repaired from
            // the fixed origin after validating any explicit authority.
            ensure_host_header(&mut req)?;
            Ok(req)
        }
    }
}

/// Finalize a handler-mutated request for the host leg.
///
/// When the host leg is h2, h1 boundary headers that existed before the
/// handler and were left unchanged can still be translated away. Newly added
/// or modified h2-forbidden headers are rejected so trusted handler output is
/// never silently repaired.
pub fn finalize_request_for_host<'a>(
    req: OriginCheckedRequest<'a, UpstreamBody>,
    guest_proto: Protocol,
    host_proto: Protocol,
    pre_handler_headers: &HeaderMap,
) -> Result<OriginCheckedRequest<'a, UpstreamBody>, RequestFinalizeError> {
    translate_request_for_host(req, guest_proto, host_proto, Some(pre_handler_headers))
}

/// Cross-protocol response normalizer called before the handler sees upstream
/// response headers.
///
/// For the h1→h2 direction we strip connection-specific headers that are
/// invalid on the guest leg. `Content-Length` is always stripped before the
/// handler because the response body is streamed through `TappedBody`.
/// `Transfer-Encoding` is also stripped for every guest protocol because it is
/// proxy-owned wire framing from the origin leg, not handler-visible response
/// metadata. If a handler reintroduces either header, the service layer rejects
/// that output instead of deleting it.
pub fn sanitize_response_for_handler(headers: &mut HeaderMap, guest_proto: Protocol) {
    while headers.remove(CONTENT_LENGTH).is_some() {}
    while headers.remove(TRANSFER_ENCODING).is_some() {}
    if guest_proto == Protocol::Http2 {
        strip_h2_forbidden(headers);
    }
}

/// Validate a handler-mutated response before guest-side serialization.
pub fn validate_response_for_guest(
    headers: &HeaderMap,
    guest_proto: Protocol,
) -> Result<(), InvalidH2Header> {
    if guest_proto == Protocol::Http2 {
        validate_h2_headers(headers)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};

    fn empty_body() -> UpstreamBody {
        Empty::<Bytes>::new()
            .map_err(|never| match never {})
            .boxed_unsync()
    }

    fn origin(host: &str) -> OriginAuthority {
        OriginAuthority::new(host, DEFAULT_HTTPS_PORT)
    }

    fn checked(
        req: Request<UpstreamBody>,
        origin: &OriginAuthority,
    ) -> OriginCheckedRequest<'_, UpstreamBody> {
        OriginCheckedRequest::new(req, origin).unwrap()
    }

    #[test]
    fn strip_removes_all_h2_forbidden_headers() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("close"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("keep-alive", HeaderValue::from_static("timeout=5"));
        h.insert("proxy-connection", HeaderValue::from_static("close"));
        h.insert("upgrade", HeaderValue::from_static("websocket"));
        h.insert("host", HeaderValue::from_static("example.com"));
        h.insert("x-keep", HeaderValue::from_static("keep-me"));

        strip_h2_forbidden(&mut h);

        assert!(h.get("connection").is_none());
        assert!(h.get("transfer-encoding").is_none());
        assert!(h.get("keep-alive").is_none());
        assert!(h.get("proxy-connection").is_none());
        assert!(h.get("upgrade").is_none());
        assert!(h.get("host").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "keep-me");
    }

    #[test]
    fn strip_removes_headers_named_in_connection_value() {
        // RFC 7540 §8.1.2.2: all header names listed in `Connection:` must be
        // removed when crossing to h2 — otherwise a guest can smuggle
        // hop-by-hop headers past the strip list.
        let mut h = HeaderMap::new();
        h.insert(
            "connection",
            HeaderValue::from_static("close, x-custom-hop"),
        );
        h.insert("x-custom-hop", HeaderValue::from_static("leaked"));
        h.insert("x-keep", HeaderValue::from_static("keep-me"));
        strip_h2_forbidden(&mut h);
        assert!(
            h.get("x-custom-hop").is_none(),
            "header named in Connection must be stripped"
        );
        assert!(h.get("connection").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "keep-me");
    }

    #[test]
    fn strip_handles_multiple_connection_headers_and_whitespace() {
        let mut h = HeaderMap::new();
        h.append("connection", HeaderValue::from_static("  x-one  "));
        h.append("connection", HeaderValue::from_static("x-two , x-three"));
        h.insert("x-one", HeaderValue::from_static("v1"));
        h.insert("x-two", HeaderValue::from_static("v2"));
        h.insert("x-three", HeaderValue::from_static("v3"));
        h.insert("x-four", HeaderValue::from_static("v4"));
        strip_h2_forbidden(&mut h);
        assert!(h.get("x-one").is_none());
        assert!(h.get("x-two").is_none());
        assert!(h.get("x-three").is_none());
        assert_eq!(h.get("x-four").unwrap(), "v4");
    }

    #[test]
    fn te_trailers_is_preserved_other_te_values_are_dropped() {
        let mut h = HeaderMap::new();
        h.insert("te", HeaderValue::from_static("trailers"));
        strip_h2_forbidden(&mut h);
        assert_eq!(h.get("te").unwrap(), "trailers");

        let mut h = HeaderMap::new();
        h.insert("te", HeaderValue::from_static("deflate"));
        strip_h2_forbidden(&mut h);
        assert!(h.get("te").is_none());

        let mut h = HeaderMap::new();
        h.insert("te", HeaderValue::from_static("trailers, deflate"));
        strip_h2_forbidden(&mut h);
        // Mixed codings → drop whole header; see module doc design note 3.
        assert!(h.get("te").is_none());
    }

    #[test]
    fn sanitize_request_for_handler_strips_h1_boundary_headers() {
        let mut h = HeaderMap::new();
        h.insert("connection", HeaderValue::from_static("close, x-hop"));
        h.insert("x-hop", HeaderValue::from_static("one"));
        h.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        h.insert("host", HeaderValue::from_static("example.com"));
        h.insert("content-length", HeaderValue::from_static("12"));
        h.insert("x-keep", HeaderValue::from_static("keep-me"));

        sanitize_request_for_handler(&mut h, Protocol::Http1);

        assert!(h.get("connection").is_none());
        assert!(h.get("x-hop").is_none());
        assert!(h.get("transfer-encoding").is_none());
        assert!(h.get("host").is_none());
        assert!(h.get("content-length").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "keep-me");
    }

    #[test]
    fn sanitize_request_for_handler_strips_proxy_owned_h2_headers() {
        let mut h = HeaderMap::new();
        h.insert("host", HeaderValue::from_static("example.com"));
        h.insert("content-length", HeaderValue::from_static("12"));
        h.insert("x-keep", HeaderValue::from_static("keep-me"));

        sanitize_request_for_handler(&mut h, Protocol::Http2);

        assert!(h.get("host").is_none());
        assert!(h.get("content-length").is_none());
        assert_eq!(h.get("x-keep").unwrap(), "keep-me");
    }

    #[test]
    fn ensure_h2_uri_promotes_path_only_uri() {
        let origin = origin("example.com");
        let req = Request::builder()
            .uri("/foo?x=1")
            .body(empty_body())
            .unwrap();
        let mut req = checked(req, &origin);
        ensure_h2_uri(&mut req).unwrap();
        assert_eq!(req.request().uri().scheme_str(), Some("https"));
        assert_eq!(
            req.request().uri().authority().unwrap().as_str(),
            "example.com"
        );
        assert_eq!(
            req.request().uri().path_and_query().unwrap().as_str(),
            "/foo?x=1"
        );
    }

    #[test]
    fn ensure_h2_uri_accepts_matching_existing_authority() {
        let origin = origin("real.example.com");
        let req = Request::builder()
            .uri("https://real.example.com/bar")
            .body(empty_body())
            .unwrap();
        let mut req = checked(req, &origin);
        ensure_h2_uri(&mut req).unwrap();
        assert_eq!(
            req.request().uri().authority().unwrap().as_str(),
            "real.example.com"
        );
    }

    #[test]
    fn origin_checked_request_rejects_mismatched_uri_authority() {
        let origin = origin("sni.example.com");
        let req = Request::builder()
            .uri("https://fronted.example.com/bar")
            .body(empty_body())
            .unwrap();
        let err = OriginCheckedRequest::new(req, &origin).unwrap_err();
        assert!(matches!(
            err.kind,
            AuthorityErrorKind::Mismatch { observed } if observed == "fronted.example.com"
        ));
    }

    #[test]
    fn ensure_h2_uri_defaults_empty_path_to_slash() {
        // `*` is the only legal path-less h1 form for OPTIONS; the proxy
        // shouldn't see it in practice, but defend anyway.
        let origin = origin("example.com");
        let req = Request::builder()
            .uri("https://example.com")
            .body(empty_body())
            .unwrap();
        let mut req = checked(req, &origin);
        ensure_h2_uri(&mut req).unwrap();
        assert_eq!(req.request().uri().path_and_query().unwrap().as_str(), "/");
    }

    #[test]
    fn ensure_host_header_adds_when_missing() {
        let origin = origin("sni.example.com");
        let req = Request::builder().uri("/foo").body(empty_body()).unwrap();
        let mut req = checked(req, &origin);
        ensure_host_header(&mut req).unwrap();
        assert_eq!(
            req.request().headers().get(HOST).unwrap(),
            "sni.example.com"
        );
    }

    #[test]
    fn ensure_host_header_accepts_matching_uri_authority() {
        let origin = origin("example.com");
        let req = Request::builder()
            .uri("https://example.com/foo")
            .body(empty_body())
            .unwrap();
        let mut req = checked(req, &origin);
        ensure_host_header(&mut req).unwrap();
        assert_eq!(req.request().headers().get(HOST).unwrap(), "example.com");
    }

    #[test]
    fn origin_checked_request_rejects_mismatched_host_header() {
        let origin = origin("sni.example.com");
        let req = Request::builder()
            .uri("/foo")
            .header(HOST, "handler-set.example.com")
            .body(empty_body())
            .unwrap();
        let err = OriginCheckedRequest::new(req, &origin).unwrap_err();
        assert!(matches!(
            err.kind,
            AuthorityErrorKind::Mismatch { observed } if observed == "handler-set.example.com"
        ));
    }

    #[test]
    fn sanitize_request_for_h2_strips_and_promotes_uri() {
        let req = Request::builder()
            .uri("/foo")
            .header("connection", "close")
            .header("transfer-encoding", "chunked")
            .header("host", "example.com")
            .body(empty_body())
            .unwrap();
        let pre_handler_headers = req.headers().clone();
        let origin = origin("example.com");
        let req = checked(req, &origin);
        let req =
            finalize_request_for_host(req, Protocol::Http1, Protocol::Http2, &pre_handler_headers)
                .unwrap();
        assert!(req.request().headers().get("connection").is_none());
        assert!(req.request().headers().get("transfer-encoding").is_none());
        assert!(
            req.request().headers().get("host").is_none(),
            "Host dropped for h2"
        );
        assert_eq!(req.request().uri().scheme_str(), Some("https"));
        assert_eq!(
            req.request().uri().authority().unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn sanitize_request_for_h2_rejects_host_sni_mismatch() {
        let req = Request::builder()
            .uri("/foo")
            .header("host", "fronted.example.com")
            .body(empty_body())
            .unwrap();
        let origin = origin("sni.example.com");
        let err = OriginCheckedRequest::new(req, &origin).unwrap_err();

        assert!(matches!(
            err,
            AuthorityError {
                kind: AuthorityErrorKind::Mismatch { observed },
                ..
            } if observed == "fronted.example.com"
        ));
    }

    #[test]
    fn finalize_request_for_h2_strips_unchanged_boundary_headers() {
        let pre_handler_headers = {
            let mut h = HeaderMap::new();
            h.insert("connection", HeaderValue::from_static("close, x-hop"));
            h.insert("x-hop", HeaderValue::from_static("one"));
            h.insert("host", HeaderValue::from_static("example.com"));
            h
        };
        let req = Request::builder()
            .uri("/foo")
            .header("connection", "close, x-hop")
            .header("x-hop", "one")
            .header("host", "example.com")
            .body(empty_body())
            .unwrap();

        let origin = origin("example.com");
        let req = checked(req, &origin);
        let req =
            finalize_request_for_host(req, Protocol::Http1, Protocol::Http2, &pre_handler_headers)
                .unwrap();

        assert!(req.request().headers().get("connection").is_none());
        assert!(req.request().headers().get("x-hop").is_none());
        assert!(req.request().headers().get("host").is_none());
        assert_eq!(
            req.request().uri().authority().unwrap().as_str(),
            "example.com"
        );
    }

    #[test]
    fn finalize_request_for_h2_rejects_handler_injected_forbidden_header() {
        let pre_handler_headers = HeaderMap::new();
        let req = Request::builder()
            .uri("/foo")
            .header("connection", "close")
            .body(empty_body())
            .unwrap();

        let origin = origin("sni.example.com");
        let req = checked(req, &origin);
        let err =
            finalize_request_for_host(req, Protocol::Http1, Protocol::Http2, &pre_handler_headers)
                .unwrap_err();

        assert!(matches!(
            err,
            RequestFinalizeError::H2Header(InvalidH2Header { name })
                if name == HeaderName::from_static("connection")
        ));
    }

    #[test]
    fn finalize_request_for_h2_rejects_handler_modified_host_authority() {
        let req = Request::builder()
            .uri("/foo")
            .header("host", "other.example.com")
            .body(empty_body())
            .unwrap();

        let origin = origin("example.com");
        let err = OriginCheckedRequest::new(req, &origin).unwrap_err();

        assert!(matches!(
            err,
            AuthorityError {
                kind: AuthorityErrorKind::Mismatch { observed },
                ..
            } if observed == "other.example.com"
        ));
    }

    #[test]
    fn sanitize_h2_guest_to_h1_host_synthesizes_host_from_uri() {
        let req = Request::builder()
            .uri("https://real.example.com/foo")
            .body(empty_body())
            .unwrap();
        let pre_handler_headers = req.headers().clone();
        let origin = origin("real.example.com");
        let req = checked(req, &origin);
        let req =
            finalize_request_for_host(req, Protocol::Http2, Protocol::Http1, &pre_handler_headers)
                .unwrap();
        assert_eq!(
            req.request().headers().get(HOST).unwrap(),
            "real.example.com"
        );
    }

    #[test]
    fn sanitize_h1_guest_to_h1_host_synthesizes_missing_host_from_origin() {
        let req = Request::builder().uri("/foo").body(empty_body()).unwrap();
        let pre_handler_headers = req.headers().clone();
        let origin = origin("sni.example.com");
        let req = checked(req, &origin);
        let req =
            finalize_request_for_host(req, Protocol::Http1, Protocol::Http1, &pre_handler_headers)
                .unwrap();
        assert_eq!(
            req.request().headers().get(HOST).unwrap(),
            "sni.example.com"
        );
    }

    #[test]
    fn sanitize_response_for_h2_guest_strips_forbidden() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("content-length", HeaderValue::from_static("4"));
        headers.insert("content-type", HeaderValue::from_static("text/plain"));
        sanitize_response_for_handler(&mut headers, Protocol::Http2);
        assert!(headers.get("connection").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert!(headers.get("content-length").is_none());
        assert_eq!(headers.get("content-type").unwrap(), "text/plain");
    }

    #[test]
    fn validate_response_for_h2_guest_rejects_forbidden_handler_output() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));

        let err = validate_response_for_guest(&headers, Protocol::Http2).unwrap_err();

        assert_eq!(err.name, HeaderName::from_static("connection"));
    }

    #[test]
    fn sanitize_response_for_h1_guest_strips_proxy_owned_framing_only() {
        let mut headers = HeaderMap::new();
        headers.insert("connection", HeaderValue::from_static("close"));
        headers.insert("content-length", HeaderValue::from_static("4"));
        headers.insert("transfer-encoding", HeaderValue::from_static("chunked"));
        headers.insert("x-custom", HeaderValue::from_static("v"));
        sanitize_response_for_handler(&mut headers, Protocol::Http1);
        assert_eq!(headers.get("connection").unwrap(), "close");
        assert!(headers.get("content-length").is_none());
        assert!(headers.get("transfer-encoding").is_none());
        assert_eq!(headers.get("x-custom").unwrap(), "v");
    }
}
