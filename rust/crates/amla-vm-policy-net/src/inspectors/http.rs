// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! HTTP protocol inspector
//!
//! Inspects HTTP/1.1 requests and enforces method/path policies.
//! Follows fail-closed: malformed requests are denied.
//!
//! Each packet on a keep-alive TCP connection is parsed: the inspector
//! maintains per-flow parser state so pipelined requests on the same
//! connection are each evaluated against policy. A deny on any request
//! poisons the connection for all future packets.
//!
//! Limitations:
//! - HTTP/2 binary framing not yet supported (would need HPACK decoder)
//! - CONNECT is unconditionally denied: tunnels make subsequent bytes on the
//!   connection opaque to every inspector (not new HTTP requests, wrong port
//!   for the TLS inspector), so permitting it defeats DPI.
//! - `Transfer-Encoding` is denied outright: chunked would require a streaming
//!   decoder, and `Transfer-Encoding` plus `Content-Length` is a classic
//!   request-smuggling vector.

use super::sticky_lru::StickyLruCache;
use super::{ConnectionKey, EvidenceParser, InspectionResult};
use parking_lot::{Mutex, RwLock};
use std::collections::HashSet;
use std::sync::Arc;

// =============================================================================
// HTTP Inspector
// =============================================================================

/// Max bytes to accumulate while waiting for end-of-headers `\r\n\r\n`.
/// Matches the TLS inspector's per-flow buffer bound so a guest can't dribble
/// a 1-GiB header value past policy.
const MAX_HEADER_BUFFER: usize = 32 * 1024;

/// Per-connection parser state, shared across `inspect` calls via `Arc<Mutex>`.
struct FlowState {
    /// Bytes received since the last completed request boundary, waiting for
    /// `\r\n\r\n`. Once the headers parse, consumed bytes are drained.
    buffer: Vec<u8>,
    /// Bytes still to skip for the current request's body. Zero when the
    /// parser is looking for the next request line.
    body_remaining: u64,
}

/// Value stored in the inspector's per-flow state table.
#[derive(Clone)]
enum HttpCacheValue {
    /// Parser state for an in-progress connection. Inserted non-sticky so
    /// legitimate flows churn out of the cache under pressure.
    Flow(Arc<Mutex<FlowState>>),
    /// Terminal deny. Inserted sticky so a guest can't flood the cache to
    /// flush its denial.
    Denied(String),
}

/// Inspector for HTTP/1.x protocol
///
/// Checks HTTP request methods and paths against policies.
///
/// CONNECT is always denied regardless of `allow_method` /
/// `with_methods` configuration: CONNECT tunnels turn the rest of the TCP
/// connection opaque to every inspector, so letting it through would bypass
/// DPI entirely.
pub struct HttpInspector {
    /// Allowed HTTP methods (GET, POST, etc.)
    allowed_methods: RwLock<HashSet<String>>,
    /// Blocked path patterns (glob-style)
    blocked_paths: RwLock<Vec<String>>,
    /// Allowed path patterns (if set, only these are allowed)
    allowed_paths: RwLock<Option<Vec<String>>>,
    /// Per-connection parser state and sticky denials.
    connections: StickyLruCache<ConnectionKey, HttpCacheValue>,
}

impl HttpInspector {
    /// Create a new HTTP inspector allowing common methods
    pub fn new() -> Self {
        let mut methods = HashSet::new();
        methods.insert("GET".to_string());
        methods.insert("POST".to_string());
        methods.insert("PUT".to_string());
        methods.insert("DELETE".to_string());
        methods.insert("HEAD".to_string());
        methods.insert("OPTIONS".to_string());
        methods.insert("PATCH".to_string());

        Self {
            allowed_methods: RwLock::new(methods),
            blocked_paths: RwLock::new(Vec::new()),
            allowed_paths: RwLock::new(None),
            connections: StickyLruCache::new(10000),
        }
    }

    /// Create with specific allowed methods
    pub fn with_methods(methods: &[&str]) -> Self {
        let mut allowed = HashSet::new();
        for method in methods {
            allowed.insert(method.to_uppercase());
        }
        Self {
            allowed_methods: RwLock::new(allowed),
            blocked_paths: RwLock::new(Vec::new()),
            allowed_paths: RwLock::new(None),
            connections: StickyLruCache::new(10000),
        }
    }

    /// Allow a specific HTTP method
    ///
    /// Clears cached per-connection decisions so the new config takes effect
    /// on subsequent packets for all connections.
    pub fn allow_method(&self, method: &str) {
        self.allowed_methods.write().insert(method.to_uppercase());
        self.connections.clear();
    }

    /// Block a specific HTTP method
    ///
    /// Clears cached per-connection decisions so the new config takes effect
    /// on subsequent packets for all connections.
    pub fn block_method(&self, method: &str) {
        self.allowed_methods.write().remove(&method.to_uppercase());
        self.connections.clear();
    }

    /// Block a path pattern (supports * wildcard)
    ///
    /// Clears cached per-connection decisions so the new config takes effect
    /// on subsequent packets for all connections.
    pub fn block_path(&self, pattern: &str) {
        self.blocked_paths.write().push(pattern.to_string());
        self.connections.clear();
    }

    /// Set maximum tracked connections
    pub fn set_max_connections(&mut self, max: usize) {
        self.connections.set_max_entries(max);
    }

    /// Set allowed paths (if set, only these are allowed)
    ///
    /// Clears cached per-connection decisions so the new config takes effect
    /// on subsequent packets for all connections.
    pub fn set_allowed_paths(&self, patterns: &[&str]) {
        *self.allowed_paths.write() = Some(
            patterns
                .iter()
                .map(std::string::ToString::to_string)
                .collect(),
        );
        self.connections.clear();
    }

    /// Check if a path matches a pattern (simple glob with * wildcard)
    fn path_matches(pattern: &str, path: &str) -> bool {
        if pattern == "*" {
            return true;
        }

        if let Some(prefix) = pattern.strip_suffix("/*") {
            // Pattern like "/api/*" - match prefix with or without trailing content
            return path.starts_with(prefix)
                && (path.len() == prefix.len()
                    || path.as_bytes().get(prefix.len()) == Some(&b'/'));
        }

        if let Some(prefix) = pattern.strip_suffix('*') {
            return path.starts_with(prefix);
        }

        if let Some(suffix) = pattern.strip_prefix('*') {
            return path.ends_with(suffix);
        }

        pattern == path
    }

    /// Check if a path is blocked
    fn is_path_blocked(&self, path: &str) -> bool {
        let blocked = self.blocked_paths.read();
        let result = blocked
            .iter()
            .any(|pattern| Self::path_matches(pattern, path));
        drop(blocked);
        result
    }

    /// Check if a path is allowed (when allowlist is set)
    fn is_path_allowed(&self, path: &str) -> bool {
        let allowed = self.allowed_paths.read();
        match &*allowed {
            None => true, // No allowlist means all paths allowed (check blocklist separately)
            Some(patterns) => {
                for pattern in patterns {
                    if Self::path_matches(pattern, path) {
                        return true;
                    }
                }
                false
            }
        }
    }

    /// Parse HTTP request line
    fn parse_request_line(payload: &[u8]) -> Result<(String, String), &'static str> {
        // Find end of request line
        let line_end = payload
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or("No CRLF in HTTP request")?;

        let request_line = std::str::from_utf8(&payload[..line_end])
            .map_err(|_| "Invalid UTF-8 in HTTP request line")?;

        // Parse: METHOD SP URI SP VERSION
        let parts: Vec<&str> = request_line.split(' ').collect();
        if parts.len() < 2 {
            return Err("Invalid HTTP request line format");
        }

        let method = parts[0].to_uppercase();
        let uri = parts[1].to_string();

        // Validate method looks reasonable
        if method.is_empty() || method.len() > 16 {
            return Err("Invalid HTTP method");
        }

        // Extract path from URI (may be full URL or just path)
        let path = if uri.starts_with('/') {
            // Absolute path
            uri.split('?').next().unwrap_or(&uri).to_string()
        } else if let Some(after_scheme) = uri.strip_prefix("https://") {
            // Full URL with https
            after_scheme.find('/').map_or_else(
                || "/".to_string(),
                |path_start| {
                    after_scheme[path_start..]
                        .split('?')
                        .next()
                        .unwrap_or("/")
                        .to_string()
                },
            )
        } else if let Some(after_scheme) = uri.strip_prefix("http://") {
            // Full URL with http
            after_scheme.find('/').map_or_else(
                || "/".to_string(),
                |path_start| {
                    after_scheme[path_start..]
                        .split('?')
                        .next()
                        .unwrap_or("/")
                        .to_string()
                },
            )
        } else if method == "CONNECT" {
            // CONNECT uses host:port as URI
            uri
        } else {
            return Err("Invalid HTTP URI format");
        };

        Ok((method, path))
    }

    /// Check the request line against method/path policy and return the
    /// request body length. Returns `Err(reason)` to deny the connection.
    ///
    /// `headers` includes the request line and header block terminated by
    /// the trailing `\r\n\r\n`.
    fn decide_request(&self, headers: &[u8]) -> Result<u64, String> {
        let (method, path) =
            Self::parse_request_line(headers).map_err(|e| format!("HTTP parse error: {e}"))?;
        log::trace!("HTTP request: {method} {path}");

        if method == "CONNECT" {
            return Err("HTTP CONNECT not allowed: tunnels defeat DPI".to_string());
        }
        if !self.allowed_methods.read().contains(&method) {
            return Err(format!("HTTP method not allowed: {method}"));
        }
        if self.is_path_blocked(&path) {
            return Err(format!("HTTP path blocked: {path}"));
        }
        if !self.is_path_allowed(&path) {
            return Err(format!("HTTP path not in allowlist: {path}"));
        }

        // Find the CRLF that ends the request line so we scan only the
        // header fields. We already parsed the request line successfully,
        // so this position must exist.
        let request_line_end = headers
            .windows(2)
            .position(|w| w == b"\r\n")
            .ok_or_else(|| "HTTP parse error: missing request-line CRLF".to_string())?;
        let header_region = &headers[request_line_end + 2..];
        parse_body_length(header_region)
    }

    /// Upgrade the cached entry for `key` to a sticky terminal Deny.
    fn poison(&self, key: &ConnectionKey, reason: &str) {
        self.connections.insert(
            *key,
            HttpCacheValue::Denied(reason.to_string()),
            true,
            |k| {
                log::warn!(
                    "HTTP inspector: evicting Deny entry {k:?} — state table full of denies"
                );
            },
        );
    }

    /// Reclassify parser state in the cache.
    ///
    /// A flow with partial headers or body skip state is sticky: evicting it
    /// would let later bytes be parsed as a fresh request and bypass policy.
    /// Clean request-boundary state remains evictable so idle allowed flows do
    /// not pin the bounded table.
    fn cache_flow(&self, key: &ConnectionKey, flow: Arc<Mutex<FlowState>>, sticky: bool) {
        self.connections
            .insert(*key, HttpCacheValue::Flow(flow), sticky, |k| {
                log::warn!(
                    "HTTP inspector: evicting in-progress parser state {k:?} — state table full"
                );
            });
    }

    /// Fetch the flow state for `key`, creating a fresh one if needed. If
    /// `key` is already poisoned with a sticky Deny, returns the reason.
    fn get_or_create_flow(&self, key: &ConnectionKey) -> Result<Arc<Mutex<FlowState>>, String> {
        match self.connections.peek(key) {
            Some(HttpCacheValue::Denied(reason)) => {
                self.connections.touch(key);
                Err(reason)
            }
            Some(HttpCacheValue::Flow(flow)) => {
                self.connections.touch(key);
                Ok(flow)
            }
            None => {
                let flow = Arc::new(Mutex::new(FlowState {
                    buffer: Vec::new(),
                    body_remaining: 0,
                }));
                self.connections.insert(
                    *key,
                    HttpCacheValue::Flow(Arc::clone(&flow)),
                    false,
                    |_| {},
                );
                Ok(flow)
            }
        }
    }
}

/// Walk header fields for `Content-Length` / `Transfer-Encoding`. Returns
/// the body length on success, or an error string for denials.
///
/// Fails closed:
/// - Any `Transfer-Encoding` header → error (chunked decoding is out of
///   scope; mixing with `Content-Length` is a smuggling vector).
/// - Multiple conflicting `Content-Length` values → error.
/// - Malformed `Content-Length` → error.
fn parse_body_length(header_region: &[u8]) -> Result<u64, String> {
    let mut content_length: Option<u64> = None;
    let mut rest = header_region;
    loop {
        let Some(pos) = rest.windows(2).position(|w| w == b"\r\n") else {
            // No more CRLF — decide_request only calls us with a complete
            // header block, so the last iteration should leave `rest`
            // pointing at the final CRLF we already consumed.
            if !rest.is_empty() {
                return Err("HTTP parse error: malformed header block".to_string());
            }
            break;
        };
        let line = &rest[..pos];
        rest = &rest[pos + 2..];
        if line.is_empty() {
            // End-of-headers CRLF.
            break;
        }
        // Split "Name: Value". Value may have leading/trailing OWS.
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            return Err("HTTP parse error: header missing colon".to_string());
        };
        let name = &line[..colon];
        let value = line[colon + 1..]
            .iter()
            .copied()
            .skip_while(|&b| b == b' ' || b == b'\t')
            .collect::<Vec<u8>>();
        let value_str = std::str::from_utf8(&value)
            .map_err(|_| "HTTP parse error: non-UTF-8 header value".to_string())?
            .trim_end_matches([' ', '\t']);

        if header_name_eq(name, b"transfer-encoding") {
            return Err(format!(
                "HTTP Transfer-Encoding not supported for DPI: {value_str}",
            ));
        }
        if header_name_eq(name, b"content-length") {
            let parsed: u64 = value_str
                .parse()
                .map_err(|_| format!("HTTP parse error: bad Content-Length: {value_str}"))?;
            if let Some(existing) = content_length
                && existing != parsed
            {
                return Err(format!(
                    "HTTP parse error: conflicting Content-Length ({existing} vs {parsed})",
                ));
            }
            content_length = Some(parsed);
        }
    }
    Ok(content_length.unwrap_or(0))
}

/// Case-insensitive ASCII compare for an HTTP header name.
fn header_name_eq(name: &[u8], expected_lowercase: &[u8]) -> bool {
    name.len() == expected_lowercase.len()
        && name
            .iter()
            .zip(expected_lowercase)
            .all(|(a, b)| a.eq_ignore_ascii_case(b))
}

impl Default for HttpInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceParser for HttpInspector {
    fn inspect(
        &self,
        key: &ConnectionKey,
        payload: &[u8],
        _is_first_packet: bool,
    ) -> InspectionResult {
        let flow = match self.get_or_create_flow(key) {
            Err(reason) => return InspectionResult::Deny(reason),
            Ok(flow) => flow,
        };

        let mut state = flow.lock();
        state.buffer.extend_from_slice(payload);

        loop {
            // Skip body bytes left over from the current request.
            if state.body_remaining > 0 {
                let skip = state
                    .buffer
                    .len()
                    .min(usize::try_from(state.body_remaining).unwrap_or(usize::MAX));
                state.buffer.drain(..skip);
                state.body_remaining -= skip as u64;
                if state.body_remaining > 0 {
                    // Still more body to come on a later packet.
                    drop(state);
                    self.cache_flow(key, Arc::clone(&flow), true);
                    return InspectionResult::Allow;
                }
            }

            // Look for the end of the next request's headers.
            let header_end = state
                .buffer
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4);
            let Some(header_end) = header_end else {
                if state.buffer.len() > MAX_HEADER_BUFFER {
                    let reason = format!("HTTP headers exceed {MAX_HEADER_BUFFER}-byte buffer");
                    drop(state);
                    self.poison(key, &reason);
                    return InspectionResult::Deny(reason);
                }
                // More bytes needed to complete the header block.
                let sticky = !state.buffer.is_empty();
                drop(state);
                self.cache_flow(key, Arc::clone(&flow), sticky);
                return InspectionResult::Allow;
            };

            // Parse and apply policy to this request.
            let header_bytes: Vec<u8> = state.buffer.drain(..header_end).collect();
            match self.decide_request(&header_bytes) {
                Err(reason) => {
                    log::debug!("HTTP deny: {reason}");
                    drop(state);
                    self.poison(key, &reason);
                    return InspectionResult::Deny(reason);
                }
                Ok(body_len) => {
                    state.body_remaining = body_len;
                    // Loop: drain the body (if any) and look for a pipelined
                    // next request.
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "HTTP"
    }

    fn clear_state(&self) {
        self.connections.clear();
    }

    fn connection_count(&self) -> usize {
        self.connections.len()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn make_http_request(method: &str, path: &str) -> Vec<u8> {
        format!("{method} {path} HTTP/1.1\r\nHost: example.com\r\n\r\n").into_bytes()
    }

    fn dummy_key() -> ConnectionKey {
        ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            80,
            6, // TCP
        )
    }

    #[test]
    fn test_http_request_parsing() {
        let req = make_http_request("GET", "/api/v1/users");
        let (method, path) = HttpInspector::parse_request_line(&req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/api/v1/users");
    }

    #[test]
    fn test_http_allow_get() {
        let inspector = HttpInspector::new();
        let req = make_http_request("GET", "/api/v1");

        let result = inspector.inspect(&dummy_key(), &req, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_allow_post() {
        let inspector = HttpInspector::new();
        let req = make_http_request("POST", "/api/v1/data");

        let result = inspector.inspect(&dummy_key(), &req, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_block_method() {
        let inspector = HttpInspector::with_methods(&["GET", "POST"]);
        let req = make_http_request("DELETE", "/api/v1/users/123");

        let result = inspector.inspect(&dummy_key(), &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_http_block_path() {
        let inspector = HttpInspector::new();
        inspector.block_path("/admin/*");

        let req = make_http_request("GET", "/admin/users");
        let result = inspector.inspect(&dummy_key(), &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));

        // Non-admin path should be allowed
        let key2 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12346,
            80,
            6,
        );
        let req = make_http_request("GET", "/api/v1/users");
        let result = inspector.inspect(&key2, &req, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_allowed_paths() {
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/api/*", "/health"]);

        // Allowed path
        let req = make_http_request("GET", "/api/v1/data");
        let result = inspector.inspect(&dummy_key(), &req, true);
        assert_eq!(result, InspectionResult::Allow);

        // Health check
        let key2 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12346,
            80,
            6,
        );
        let req = make_http_request("GET", "/health");
        let result = inspector.inspect(&key2, &req, true);
        assert_eq!(result, InspectionResult::Allow);

        // Disallowed path
        let key3 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12347,
            80,
            6,
        );
        let req = make_http_request("GET", "/admin/users");
        let result = inspector.inspect(&key3, &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_path_matching() {
        // Exact match
        assert!(HttpInspector::path_matches("/api/v1", "/api/v1"));
        assert!(!HttpInspector::path_matches("/api/v1", "/api/v2"));

        // Wildcard prefix
        assert!(HttpInspector::path_matches("/api/*", "/api/v1"));
        assert!(HttpInspector::path_matches("/api/*", "/api/v1/users"));
        assert!(!HttpInspector::path_matches("/api/*", "/other"));

        // Wildcard suffix
        assert!(HttpInspector::path_matches("*.json", "/data.json"));
        assert!(!HttpInspector::path_matches("*.json", "/data.xml"));

        // Universal wildcard
        assert!(HttpInspector::path_matches("*", "/anything"));
    }

    #[test]
    fn test_http_malformed_rejected() {
        let inspector = HttpInspector::new();

        // No CRLF
        let req = b"GET /api/v1 HTTP/1.1";
        let result = inspector.inspect(&dummy_key(), req, true);
        // Single incomplete packet: parser waits for `\r\n\r\n`. The
        // malformed-ness only surfaces once we exceed the buffer bound or
        // the connection closes with no further data; forwarding a 20-byte
        // fragment is harmless because the handshake can't progress without
        // subsequent packets that WILL be parsed.
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_connect_always_denied() {
        let inspector = HttpInspector::new();

        let req = b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let key = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            443,
            6,
        );
        let result = inspector.inspect(&key, req, true);
        assert_eq!(
            result,
            InspectionResult::Deny("HTTP CONNECT not allowed: tunnels defeat DPI".to_string())
        );

        // Even after opting CONNECT into allowed_methods, it must still be denied.
        inspector.allow_method("CONNECT");
        let key2 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12346,
            443,
            6,
        );
        let result = inspector.inspect(&key2, req, true);
        assert_eq!(
            result,
            InspectionResult::Deny("HTTP CONNECT not allowed: tunnels defeat DPI".to_string()),
            "allow_method(\"CONNECT\") must not defeat the hard-deny"
        );

        // And via the with_methods constructor too.
        let inspector2 = HttpInspector::with_methods(&["CONNECT", "GET"]);
        let result = inspector2.inspect(&key, req, true);
        assert_eq!(
            result,
            InspectionResult::Deny("HTTP CONNECT not allowed: tunnels defeat DPI".to_string()),
            "with_methods(&[\"CONNECT\", ...]) must not defeat the hard-deny"
        );
    }

    #[test]
    fn test_http_method_case_insensitive() {
        let inspector = HttpInspector::new();

        let req = b"get /api/v1 HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let result = inspector.inspect(&dummy_key(), req, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_uri_with_http_scheme() {
        let req = make_http_request("GET", "http://example.com/path");
        let (method, path) = HttpInspector::parse_request_line(&req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_http_uri_with_https_scheme() {
        let req = make_http_request("GET", "https://example.com/path");
        let (method, path) = HttpInspector::parse_request_line(&req).unwrap();
        assert_eq!(method, "GET");
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_http_uri_with_http_no_path() {
        let req = make_http_request("GET", "http://example.com");
        let (_, path) = HttpInspector::parse_request_line(&req).unwrap();
        assert_eq!(path, "/");
    }

    #[test]
    fn test_http_uri_http_host_extraction_correct() {
        let req = make_http_request("GET", "http://example.com/api/v1");
        let (_, path) = HttpInspector::parse_request_line(&req).unwrap();
        assert_eq!(path, "/api/v1");
    }

    #[test]
    fn test_http_uri_non_ascii_no_panic() {
        // Non-ASCII at position 7 in an http:// URI
        let req = b"GET http://\xc3\xa9xample.com/path HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Should not panic - either returns Ok or Err
        let result = std::panic::catch_unwind(|| HttpInspector::parse_request_line(req));
        assert!(
            result.is_ok(),
            "parse_request_line panicked on non-ASCII URI"
        );
    }

    #[test]
    fn test_http_subsequent_body_bytes_forwarded() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let req = make_http_request("GET", "/api");

        // First request lands allowed.
        let result = inspector.inspect(&key, &req, true);
        assert_eq!(result, InspectionResult::Allow);
        assert_eq!(inspector.connection_count(), 1);

        // A stray fragment on the same connection that isn't a complete
        // request: the parser buffers it and returns Allow until enough
        // bytes arrive or the buffer bound is exceeded.
        let result = inspector.inspect(&key, b"body data", false);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_http_block_method_clears_cache() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let req = make_http_request("DELETE", "/api/v1/users/123");

        // DELETE is allowed by default
        let result = inspector.inspect(&key, &req, true);
        assert_eq!(result, InspectionResult::Allow);
        assert_eq!(inspector.connection_count(), 1);

        // Block DELETE — cache must be cleared
        inspector.block_method("DELETE");
        assert_eq!(
            inspector.connection_count(),
            0,
            "block_method must clear cache"
        );

        // Re-inspect same connection: should now be denied
        let result = inspector.inspect(&key, &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_http_block_path_clears_cache() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let req = make_http_request("GET", "/admin/users");

        // Initially allowed (no blocked paths)
        let result = inspector.inspect(&key, &req, true);
        assert_eq!(result, InspectionResult::Allow);

        // Block /admin/* — cache must be cleared
        inspector.block_path("/admin/*");
        assert_eq!(
            inspector.connection_count(),
            0,
            "block_path must clear cache"
        );

        // Re-inspect: should now be denied
        let result = inspector.inspect(&key, &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_http_set_allowed_paths_clears_cache() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let req = make_http_request("GET", "/other");

        // Initially allowed (no path allowlist)
        let result = inspector.inspect(&key, &req, true);
        assert_eq!(result, InspectionResult::Allow);

        // Set allowed paths to only /api/* — cache must be cleared
        inspector.set_allowed_paths(&["/api/*"]);
        assert_eq!(
            inspector.connection_count(),
            0,
            "set_allowed_paths must clear cache"
        );

        // Re-inspect: /other is not in /api/* → denied
        let result = inspector.inspect(&key, &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_http_deny_is_sticky_under_eviction_pressure() {
        // Attackers should not be able to flood the state table with allowed
        // connections to push their own Deny out of the cache and regain a
        // "clean slate". The Deny must stick until every slot is a Deny.
        let mut inspector = HttpInspector::with_methods(&["GET"]);
        inspector.set_max_connections(4);

        // Step 1: attacker's connection is denied (DELETE not allowed).
        let attacker = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 99),
            Ipv4Addr::new(1, 2, 3, 4),
            60000,
            80,
            6,
        );
        let denied_req = make_http_request("DELETE", "/api/v1");
        let result = inspector.inspect(&attacker, &denied_req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));

        // Step 2: flood the cache with allowed GETs to force eviction.
        let allowed_req = make_http_request("GET", "/api/v1");
        for port in 50000u16..50020 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(1, 2, 3, 4),
                port,
                80,
                6,
            );
            assert_eq!(
                inspector.inspect(&key, &allowed_req, true),
                InspectionResult::Allow,
            );
        }

        // Step 3: attacker retries — cached Deny must survive the flood.
        let result = inspector.inspect(&attacker, &denied_req, false);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "Deny must survive eviction pressure; got {result:?}"
        );
    }

    #[test]
    fn test_http_incomplete_headers_are_sticky_under_eviction_pressure() {
        // Partial parser state must survive cache churn. If it is evicted, a
        // split forbidden request can be reinterpreted from a later boundary.
        let mut inspector = HttpInspector::with_methods(&["GET"]);
        inspector.block_path("/admin/*");
        inspector.set_max_connections(4);

        let attacker = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 99),
            Ipv4Addr::new(1, 2, 3, 4),
            60000,
            80,
            6,
        );
        assert_eq!(
            inspector.inspect(
                &attacker,
                b"GET /admin/secret HTTP/1.1\r\nHost: x\r\n",
                true
            ),
            InspectionResult::Allow
        );

        let allowed_req = make_http_request("GET", "/api/v1");
        for port in 50000u16..50020 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(1, 2, 3, 4),
                port,
                80,
                6,
            );
            assert_eq!(
                inspector.inspect(&key, &allowed_req, true),
                InspectionResult::Allow
            );
        }

        let result = inspector.inspect(&attacker, b"\r\n", false);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "in-progress parser state must survive eviction pressure; got {result:?}"
        );
    }

    #[test]
    fn test_http_allow_method_clears_cache() {
        let inspector = HttpInspector::with_methods(&["GET"]);
        let key = dummy_key();
        let req = make_http_request("PATCH", "/api");

        // PATCH not in allowed methods → denied
        let result = inspector.inspect(&key, &req, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
        assert_eq!(inspector.connection_count(), 1);

        // Allow PATCH — cache must be cleared
        inspector.allow_method("PATCH");
        assert_eq!(
            inspector.connection_count(),
            0,
            "allow_method must clear cache"
        );

        // Re-inspect: should now be allowed
        let result = inspector.inspect(&key, &req, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    // =========================================================================
    // Keep-alive / pipelining regression tests (H6)
    // =========================================================================

    #[test]
    fn test_http_pipelined_forbidden_request_denied_same_packet() {
        // Attack: a single packet containing "GET /allowed" followed by
        // "POST /forbidden" must surface the forbidden request. The old
        // inspector cached the first verdict per 5-tuple and let the
        // pipelined request through unseen.
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/ok/*"]);
        let key = dummy_key();
        let mut payload = Vec::new();
        payload.extend_from_slice(b"GET /ok/1 HTTP/1.1\r\nHost: x\r\n\r\n");
        payload.extend_from_slice(
            b"POST /admin/delete HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
        );
        let result = inspector.inspect(&key, &payload, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_pipelined_forbidden_request_denied_across_packets() {
        // Keep-alive with separate TCP segments: first an allowed request,
        // then a forbidden one on the same connection. Each segment must
        // re-parse; the second must deny.
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/ok/*"]);
        let key = dummy_key();

        let first = b"GET /ok/1 HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(
            inspector.inspect(&key, first, true),
            InspectionResult::Allow
        );

        let second = b"POST /admin/delete HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let result = inspector.inspect(&key, second, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_content_length_body_skipped_then_next_request_parsed() {
        // Request 1 has a 5-byte body. A forbidden request is pipelined
        // immediately after. The parser must skip exactly 5 body bytes and
        // then parse (and deny) the next request.
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/ok/*"]);
        let key = dummy_key();
        let mut payload = Vec::new();
        payload.extend_from_slice(b"POST /ok/1 HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\n");
        payload.extend_from_slice(b"HELLO");
        payload.extend_from_slice(b"POST /admin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n");
        let result = inspector.inspect(&key, &payload, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_body_split_across_packets() {
        // Body arrives in a later packet than the request line. The parser
        // must hold the remaining body count across calls, then parse the
        // forbidden pipelined request that follows.
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/ok/*"]);
        let key = dummy_key();

        let first = b"POST /ok/1 HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nPART1";
        assert_eq!(
            inspector.inspect(&key, first, true),
            InspectionResult::Allow
        );

        let second = b"PART2POST /admin HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n";
        let result = inspector.inspect(&key, second, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_transfer_encoding_chunked_denied() {
        // Transfer-Encoding is denied outright: chunked decoding is out of
        // scope, and mixing TE + Content-Length is a smuggling vector.
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let req = b"POST /api HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n";
        let result = inspector.inspect(&key, req, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_header_bomb_denied() {
        // A guest that dribbles headers without ever emitting \r\n\r\n must
        // hit the 32 KiB header-buffer bound and get a sticky Deny.
        let inspector = HttpInspector::new();
        let key = dummy_key();
        let bomb: Vec<u8> = b"GET / HTTP/1.1\r\nX-Spam: "
            .iter()
            .copied()
            .chain(std::iter::repeat_n(b'a', MAX_HEADER_BUFFER + 1024))
            .collect();
        let result = inspector.inspect(&key, &bomb, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );

        // Subsequent packets on the same key must stay denied.
        let result = inspector.inspect(&key, b"more", false);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_conflicting_content_length_denied() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        // Two different Content-Length values — smuggling vector; fail closed.
        let req =
            b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n";
        let result = inspector.inspect(&key, req, true);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "got {result:?}"
        );
    }

    #[test]
    fn test_http_duplicate_content_length_same_value_allowed() {
        // Same value repeated is permitted by RFC 7230 §3.3.2.
        let inspector = HttpInspector::new();
        inspector.set_allowed_paths(&["/api"]);
        let key = dummy_key();
        let req =
            b"POST /api HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nHELLO";
        assert_eq!(inspector.inspect(&key, req, true), InspectionResult::Allow);
    }

    #[test]
    fn test_http_request_line_split_across_packets() {
        let inspector = HttpInspector::new();
        let key = dummy_key();
        // Half a request line in the first packet — buffer, not error.
        let result = inspector.inspect(&key, b"GET /ap", true);
        assert_eq!(result, InspectionResult::Allow);
        // Second packet completes it.
        let result = inspector.inspect(&key, b"i HTTP/1.1\r\nHost: x\r\n\r\n", false);
        assert_eq!(result, InspectionResult::Allow);
    }
}
