// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used, clippy::panic))]
//! TLS `ClientHello` byte parser.
//!
//! Stateless, fail-closed parser for SNI, ALPN, and ECH detection. Handles
//! handshake-message reassembly across multiple TLS records (RFC 5246 §6.2)
//! so large `ClientHello` messages with post-quantum key shares parse
//! correctly even when split.
//!
//! The caller feeds an accumulated byte buffer (zero or more TLS records)
//! and gets back a [`ParseOutcome`]. Malformed SNI is a parse error, so a
//! successfully parsed [`ClientHello`] contains only validated policy evidence.

// =============================================================================
// TLS Constants
// =============================================================================

/// TLS record type: Handshake
const TLS_HANDSHAKE: u8 = 22;
/// TLS handshake type: `ClientHello`
const TLS_CLIENT_HELLO: u8 = 1;
/// TLS extension: Server Name Indication (RFC 6066)
const EXT_SNI: u16 = 0x0000;
/// TLS extension: Application-Layer Protocol Negotiation (RFC 7301)
const EXT_ALPN: u16 = 0x0010;
/// TLS extension: Encrypted Client Hello (draft-ietf-tls-esni)
const EXT_ECH: u16 = 0xFE0D;
/// Maximum TLS plaintext record length before encryption.
const MAX_TLS_RECORD_LEN: usize = 16 * 1024;
/// Maximum first handshake message buffered by this parser.
pub const MAX_CLIENT_HELLO: usize = 32 * 1024;

// =============================================================================
// Public API
// =============================================================================

/// Outcome of feeding TLS record bytes to the parser.
#[derive(Debug, Clone)]
pub enum ParseOutcome {
    /// Valid prefix; need more bytes. Caller should buffer and retry.
    Incomplete,
    /// A complete `ClientHello` was parsed. Inspect the struct fields to
    /// decide policy.
    Parsed(ClientHello),
    /// Bytes are well-formed TLS records but not a `ClientHello` handshake
    /// (e.g., first byte isn't `TLS_HANDSHAKE` record, or the handshake
    /// message type isn't `ClientHello`).
    NotClientHello,
    /// Malformed. Fail-closed semantics expected at the caller.
    Malformed(&'static str),
}

/// Parsed `ClientHello` data relevant to policy decisions.
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// SNI extension state. See [`SniField`].
    pub sni: SniField,
    /// ALPN offers advertised by the client, if the extension was present.
    /// `Some(vec)` means the extension was present and structurally valid.
    /// `None` means the extension was absent.
    pub alpn_offers: Option<Vec<Vec<u8>>>,
    /// True iff the Encrypted Client Hello extension (0xFE0D) was present.
    /// When true, the visible SNI (if any) is a decoy per draft-ietf-tls-esni.
    pub has_ech: bool,
}

/// State of the SNI (Server Name Indication) extension in the parsed
/// `ClientHello`.
#[derive(Debug, Clone)]
pub enum SniField {
    /// SNI extension absent.
    Absent,
    /// SNI extension present with a validated DNS hostname, canonicalized to
    /// lowercase ASCII.
    HostName(String),
}

/// Parse TLS record bytes into a [`ParseOutcome`].
///
/// Handles handshake-message reassembly across multiple TLS records. Pure:
/// stateless; caller owns buffering if they need to re-feed.
#[must_use]
pub fn parse(bytes: &[u8]) -> ParseOutcome {
    match reassemble(bytes) {
        Reassembled::Incomplete => ParseOutcome::Incomplete,
        Reassembled::NotHandshake => ParseOutcome::NotClientHello,
        Reassembled::Malformed(reason) => ParseOutcome::Malformed(reason),
        Reassembled::Ok(handshake) => parse_handshake(&handshake),
    }
}

/// Extract ALPN offers from a buffer that may be a prefix of a `ClientHello`.
///
/// Returns `Ok(None)` if no complete `ClientHello` can be located yet, or if
/// the complete `ClientHello` has no ALPN extension. Malformed TLS and non-
/// `ClientHello` input return `Err` so callers cannot confuse bad evidence
/// with absent ALPN.
///
/// Thin wrapper over [`parse`]; retained for callers that only want the
/// ALPN field without pattern-matching the full outcome.
pub fn extract_alpn_offers(bytes: &[u8]) -> Result<Option<Vec<Vec<u8>>>, &'static str> {
    match parse(bytes) {
        ParseOutcome::Incomplete => Ok(None),
        ParseOutcome::Parsed(ch) => Ok(ch.alpn_offers),
        ParseOutcome::NotClientHello => Err("not a ClientHello"),
        ParseOutcome::Malformed(reason) => Err(reason),
    }
}

// =============================================================================
// Internals
// =============================================================================

enum Reassembled {
    /// Successfully reassembled; buffer is the concatenated handshake body
    /// (one or more handshake messages back-to-back, starting with the
    /// handshake header: type(1) + length(3)).
    Ok(Vec<u8>),
    /// Valid prefix, need more bytes.
    Incomplete,
    /// First record isn't a TLS Handshake record.
    NotHandshake,
    /// TLS records are structurally invalid.
    Malformed(&'static str),
}

/// Walk one or more contiguous TLS Handshake records and concatenate their
/// bodies. A `ClientHello` can legitimately span multiple records for
/// post-quantum key shares or many extensions. Non-handshake records after
/// the first are left untouched — the caller may pass a buffer that contains
/// a `ClientHello` followed by a `ChangeCipherSpec`, and we return once the
/// handshake stream ends.
fn reassemble(buf: &[u8]) -> Reassembled {
    let mut pos = 0;
    let mut handshake = Vec::new();
    let mut records_seen = 0;
    let mut first_message_len = None;

    while pos < buf.len() {
        if pos + 5 > buf.len() {
            return Reassembled::Incomplete;
        }
        if buf[pos] != TLS_HANDSHAKE {
            if records_seen == 0 {
                return Reassembled::NotHandshake;
            }
            return Reassembled::Malformed("non-handshake record before complete ClientHello");
        }
        let record_len = u16::from_be_bytes([buf[pos + 3], buf[pos + 4]]) as usize;
        if record_len > MAX_TLS_RECORD_LEN {
            return Reassembled::Malformed("TLS record length exceeds maximum plaintext size");
        }
        let total = 5 + record_len;
        if pos + total > buf.len() {
            return Reassembled::Incomplete;
        }
        if handshake.len().saturating_add(record_len) > MAX_CLIENT_HELLO {
            return Reassembled::Malformed("ClientHello exceeds parser limit");
        }

        handshake.extend_from_slice(&buf[pos + 5..pos + total]);
        pos += total;
        records_seen += 1;

        if handshake.first().is_some_and(|ty| *ty != TLS_CLIENT_HELLO) {
            return Reassembled::Ok(handshake);
        }

        if first_message_len.is_none() && handshake.len() >= 4 {
            let handshake_len = ((handshake[1] as usize) << 16)
                | ((handshake[2] as usize) << 8)
                | (handshake[3] as usize);
            let Some(total_len) = handshake_len.checked_add(4) else {
                return Reassembled::Malformed("ClientHello length overflow");
            };
            if total_len > MAX_CLIENT_HELLO {
                return Reassembled::Malformed("ClientHello exceeds parser limit");
            }
            first_message_len = Some(total_len);
        }

        if let Some(total_len) = first_message_len
            && handshake.len() >= total_len
        {
            handshake.truncate(total_len);
            return Reassembled::Ok(handshake);
        }
    }

    if records_seen == 0 {
        return Reassembled::Incomplete;
    }
    Reassembled::Incomplete
}

/// Parse a reassembled handshake stream into a `ParseOutcome`. Expects the
/// first message to be a `ClientHello`; subsequent bytes (if any) are
/// ignored — the caller only cares about the first handshake message.
fn parse_handshake(handshake: &[u8]) -> ParseOutcome {
    if handshake.first().is_some_and(|ty| *ty != TLS_CLIENT_HELLO) {
        return ParseOutcome::NotClientHello;
    }

    // Handshake header: type(1) + length(3) — may straddle records so this
    // check must happen after reassembly.
    if handshake.len() < 4 {
        return ParseOutcome::Incomplete;
    }

    let handshake_len =
        ((handshake[1] as usize) << 16) | ((handshake[2] as usize) << 8) | (handshake[3] as usize);
    if handshake_len + 4 > MAX_CLIENT_HELLO {
        return ParseOutcome::Malformed("ClientHello exceeds parser limit");
    }

    if handshake.len() < 4 + handshake_len {
        return ParseOutcome::Incomplete;
    }

    let body = &handshake[4..4 + handshake_len];
    parse_client_hello_body(body)
}

/// Parse the `ClientHello` message body (everything after the handshake
/// header). Layout:
/// - version (2)
/// - random (32)
/// - `session_id_len` (1) + `session_id`
/// - `cipher_suites_len` (2) + `cipher_suites`
/// - `compression_methods_len` (1) + `compression_methods`
/// - `extensions_len` (2) + extensions  (optional in TLS 1.2)
fn parse_client_hello_body(body: &[u8]) -> ParseOutcome {
    if body.len() < 34 {
        return ParseOutcome::Malformed("ClientHello too short");
    }

    let mut pos = 34; // version + random

    if pos >= body.len() {
        return ParseOutcome::Malformed("ClientHello: missing session_id length");
    }
    let session_id_len = body[pos] as usize;
    pos += 1;
    if session_id_len > 32 {
        return ParseOutcome::Malformed("ClientHello: session_id too long");
    }
    if pos + session_id_len > body.len() {
        return ParseOutcome::Malformed("ClientHello: session_id truncated");
    }
    pos += session_id_len;

    if pos + 2 > body.len() {
        return ParseOutcome::Malformed("ClientHello: missing cipher_suites length");
    }
    let cipher_suites_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;
    if cipher_suites_len == 0 {
        return ParseOutcome::Malformed("ClientHello: empty cipher_suites");
    }
    if !cipher_suites_len.is_multiple_of(2) {
        return ParseOutcome::Malformed("ClientHello: odd cipher_suites length");
    }
    if pos + cipher_suites_len > body.len() {
        return ParseOutcome::Malformed("ClientHello: cipher_suites truncated");
    }
    pos += cipher_suites_len;

    if pos >= body.len() {
        return ParseOutcome::Malformed("ClientHello: missing compression_methods length");
    }
    let compression_len = body[pos] as usize;
    pos += 1;
    if compression_len == 0 {
        return ParseOutcome::Malformed("ClientHello: empty compression_methods");
    }
    if pos + compression_len > body.len() {
        return ParseOutcome::Malformed("ClientHello: compression_methods truncated");
    }
    pos += compression_len;

    // Extensions block is optional in TLS 1.2 (TLS 1.3 mandates it, but the
    // parser accepts either). If any bytes remain, they must be the complete
    // extensions length field plus exactly that many extension bytes.
    if pos == body.len() {
        return ParseOutcome::Parsed(ClientHello {
            sni: SniField::Absent,
            alpn_offers: None,
            has_ech: false,
        });
    }
    if pos + 2 > body.len() {
        return ParseOutcome::Malformed("ClientHello: trailing byte before extensions length");
    }

    let extensions_len = u16::from_be_bytes([body[pos], body[pos + 1]]) as usize;
    pos += 2;

    if pos + extensions_len > body.len() {
        return ParseOutcome::Malformed("ClientHello: extensions truncated");
    }
    if pos + extensions_len != body.len() {
        return ParseOutcome::Malformed("ClientHello: trailing bytes after extensions");
    }

    let extensions = &body[pos..pos + extensions_len];
    walk_extensions(extensions)
}

/// Walk the extensions block of a `ClientHello` and collect SNI, ALPN, and
/// ECH state. Continues through all extensions so callers can observe SNI
/// and `has_ech` together.
fn walk_extensions(mut data: &[u8]) -> ParseOutcome {
    let mut sni = SniField::Absent;
    let mut alpn_offers: Option<Vec<Vec<u8>>> = None;
    let mut has_ech = false;
    let mut seen_extensions = Vec::new();

    while !data.is_empty() {
        if data.len() < 4 {
            return ParseOutcome::Malformed("ClientHello: trailing extension bytes");
        }
        let ext_type = u16::from_be_bytes([data[0], data[1]]);
        let ext_len = u16::from_be_bytes([data[2], data[3]]) as usize;
        if data.len() < 4 + ext_len {
            return ParseOutcome::Malformed("ClientHello: extension truncated");
        }
        let ext_data = &data[4..4 + ext_len];
        if seen_extensions.contains(&ext_type) {
            return ParseOutcome::Malformed("ClientHello: duplicate extension");
        }
        seen_extensions.push(ext_type);

        match ext_type {
            EXT_SNI => {
                sni = match parse_sni_extension(ext_data) {
                    Ok(sni) => sni,
                    Err(reason) => return ParseOutcome::Malformed(reason),
                };
            }
            EXT_ALPN => {
                alpn_offers = match parse_alpn_extension(ext_data) {
                    Ok(offers) => Some(offers),
                    Err(reason) => return ParseOutcome::Malformed(reason),
                };
            }
            EXT_ECH => {
                has_ech = true;
            }
            _ => {}
        }

        data = &data[4 + ext_len..];
    }

    ParseOutcome::Parsed(ClientHello {
        sni,
        alpn_offers,
        has_ech,
    })
}

/// Parse the SNI extension payload (RFC 6066 `ServerNameList`).
///
/// Layout:
/// - `server_name_list_len` (2)
/// - for each entry:
///     - `name_type` (1)
///     - `name_len` (2)
///     - name bytes
///
/// Only `name_type == 0` (host name) is supported. A zero-length hostname, IP
/// literal, non-ASCII name, or malformed DNS name is a protocol violation.
fn parse_sni_extension(data: &[u8]) -> Result<SniField, &'static str> {
    if data.len() < 2 {
        return Err("SNI extension too short");
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err("SNI: list length exceeds extension");
    }
    if data.len() != 2 + list_len {
        return Err("SNI: trailing bytes after server_name_list");
    }
    let list = &data[2..2 + list_len];

    // Walk the full list so trailing or duplicate entries cannot be hidden
    // behind an otherwise-valid first hostname.
    let mut pos = 0;
    let mut hostname: Option<String> = None;
    while pos < list.len() {
        if list.len() - pos < 3 {
            return Err("SNI: list entry too short");
        }
        let name_type = list[pos];
        let name_len = u16::from_be_bytes([list[pos + 1], list[pos + 2]]) as usize;
        pos += 3;

        if list.len() - pos < name_len {
            return Err("SNI: hostname truncated");
        }
        if name_type != 0 {
            return Err("unsupported SNI name_type");
        }
        if name_len == 0 {
            return Err("zero-length HostName");
        }
        if hostname.is_some() {
            return Err("SNI: duplicate HostName");
        }

        match std::str::from_utf8(&list[pos..pos + name_len]) {
            Ok(s) => hostname = Some(validate_dns_name(s)?),
            Err(_) => return Err("SNI: invalid UTF-8"),
        }
        pos += name_len;
    }

    hostname.map_or(Err("SNI: empty server_name_list"), |host| {
        Ok(SniField::HostName(host))
    })
}

fn validate_dns_name(name: &str) -> Result<String, &'static str> {
    if name.parse::<std::net::IpAddr>().is_ok() {
        return Err("SNI: IP literal HostName not permitted");
    }
    if !name.is_ascii() {
        return Err("SNI: HostName must be ASCII DNS name");
    }
    if name.len() > 253 {
        return Err("SNI: HostName exceeds DNS name length");
    }
    if name.ends_with('.') {
        return Err("SNI: HostName must not have trailing dot");
    }

    let mut saw_label = false;
    for label in name.split('.') {
        saw_label = true;
        if label.is_empty() {
            return Err("SNI: HostName contains empty label");
        }
        if label.len() > 63 {
            return Err("SNI: HostName label exceeds DNS length");
        }
        let bytes = label.as_bytes();
        if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
            return Err("SNI: HostName label has leading or trailing hyphen");
        }
        if !bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err("SNI: HostName contains invalid character");
        }
    }
    if !saw_label {
        return Err("SNI: empty server_name_list");
    }

    Ok(name.to_ascii_lowercase())
}

/// Parse the ALPN extension payload (RFC 7301).
///
/// Layout:
/// - `protocol_name_list_len` (2)
/// - for each entry:
///     - `proto_len` (1)
///     - proto bytes
///
/// Returns the advertised protocols. Length violations are malformed instead
/// of partial evidence: callers may use ALPN for policy decisions, so a broken
/// ALPN extension must fail closed just like a broken TLS extension envelope.
fn parse_alpn_extension(data: &[u8]) -> Result<Vec<Vec<u8>>, &'static str> {
    if data.len() < 2 {
        return Err("ALPN extension too short");
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    if data.len() < 2 + list_len {
        return Err("ALPN: protocol_name_list truncated");
    }
    if data.len() != 2 + list_len {
        return Err("ALPN: trailing bytes after protocol_name_list");
    }
    let mut list = &data[2..2 + list_len];
    let mut protos = Vec::new();
    while !list.is_empty() {
        let proto_len = list[0] as usize;
        if proto_len == 0 {
            return Err("ALPN: zero-length protocol name");
        }
        if list.len() < 1 + proto_len {
            return Err("ALPN: protocol name truncated");
        }
        protos.push(list[1..=proto_len].to_vec());
        list = &list[1 + proto_len..];
    }
    if protos.is_empty() {
        return Err("ALPN: empty protocol_name_list");
    }
    Ok(protos)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── Fixture builders ────────────────────────────────────────────────

    fn hs_len_bytes(len: usize) -> [u8; 3] {
        [
            u8::try_from((len >> 16) & 0xFF).unwrap(),
            u8::try_from((len >> 8) & 0xFF).unwrap(),
            u8::try_from(len & 0xFF).unwrap(),
        ]
    }

    fn u16_bytes(len: usize) -> [u8; 2] {
        u16::try_from(len).unwrap().to_be_bytes()
    }

    /// Build a minimal TLS `ClientHello` with an optional SNI hostname.
    fn build_client_hello(hostname: Option<&str>) -> Vec<u8> {
        let mut ch_body = Vec::new();
        ch_body.extend_from_slice(&[0x03, 0x03]); // TLS 1.2
        ch_body.extend_from_slice(&[0u8; 32]); // random
        ch_body.push(0x00); // session_id: empty
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]); // cipher_suites
        ch_body.extend_from_slice(&[0x01, 0x00]); // compression

        let mut extensions = Vec::new();
        if let Some(host) = hostname {
            let host_bytes = host.as_bytes();
            let name_entry_len = 3 + host_bytes.len();
            let list_len = name_entry_len;
            let ext_data_len = 2 + list_len;
            extensions.extend_from_slice(&[0x00, 0x00]); // SNI
            extensions.extend_from_slice(&u16_bytes(ext_data_len));
            extensions.extend_from_slice(&u16_bytes(list_len));
            extensions.push(0x00);
            extensions.extend_from_slice(&u16_bytes(host_bytes.len()));
            extensions.extend_from_slice(host_bytes);
        }

        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(&extensions);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&hs_len_bytes(ch_body.len()));
        handshake.extend_from_slice(&ch_body);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&u16_bytes(handshake.len()));
        record.extend_from_slice(&handshake);
        record
    }

    fn wrap_ch_body(body: &[u8]) -> Vec<u8> {
        let mut hs = vec![0x01];
        hs.extend_from_slice(&hs_len_bytes(body.len()));
        hs.extend_from_slice(body);
        let mut rec = vec![0x16, 0x03, 0x01];
        rec.extend_from_slice(&u16_bytes(hs.len()));
        rec.extend_from_slice(&hs);
        rec
    }

    fn build_client_hello_with_extensions(extensions: &[u8]) -> Vec<u8> {
        let mut ch_body = ch_prefix();
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.extend_from_slice(&[0x01, 0x00]);
        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(extensions);
        wrap_ch_body(&ch_body)
    }

    fn build_alpn_client_hello(payload: &[u8]) -> Vec<u8> {
        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x10]);
        extensions.extend_from_slice(&u16_bytes(payload.len()));
        extensions.extend_from_slice(payload);
        build_client_hello_with_extensions(&extensions)
    }

    fn ch_prefix() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0u8; 32]);
        body.push(0x00);
        body
    }

    /// Build an SNI `ClientHello` using explicit record framing, matching the
    /// shape of `make_client_hello` from the old `policy-net` test suite.
    fn make_client_hello_policy_style(sni: &str) -> Vec<u8> {
        build_client_hello(Some(sni))
    }

    /// Build a `ClientHello` split across `num_records` TLS records.
    fn build_multi_record(hostname: &str, num_records: usize) -> Vec<u8> {
        let full = build_client_hello(Some(hostname));
        let handshake = &full[5..];
        let chunk_size = handshake.len().div_ceil(num_records);
        let mut result = Vec::new();
        for chunk in handshake.chunks(chunk_size) {
            result.push(0x16);
            result.extend_from_slice(&[0x03, 0x01]);
            result.extend_from_slice(&u16_bytes(chunk.len()));
            result.extend_from_slice(chunk);
        }
        result
    }

    // ── Helpers for asserting outcomes ──────────────────────────────────

    fn assert_sni(bytes: &[u8], expected: &str) {
        match parse(bytes) {
            ParseOutcome::Parsed(ch) => match ch.sni {
                SniField::HostName(h) => assert_eq!(h, expected),
                other @ SniField::Absent => {
                    panic!("expected HostName({expected}), got {other:?}")
                }
            },
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    fn assert_sni_malformed(bytes: &[u8]) {
        match parse(bytes) {
            ParseOutcome::Malformed(_) => {}
            other => panic!("expected Malformed SNI parse, got {other:?}"),
        }
    }

    fn assert_sni_absent(bytes: &[u8]) {
        match parse(bytes) {
            ParseOutcome::Parsed(ch) => match ch.sni {
                SniField::Absent => {}
                other @ SniField::HostName(_) => {
                    panic!("expected SniField::Absent, got {other:?}")
                }
            },
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    fn assert_incomplete(bytes: &[u8]) {
        match parse(bytes) {
            ParseOutcome::Incomplete => {}
            other => panic!("expected Incomplete, got {other:?}"),
        }
    }

    fn assert_malformed(bytes: &[u8]) {
        match parse(bytes) {
            ParseOutcome::Malformed(_) => {}
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    fn assert_not_client_hello(bytes: &[u8]) {
        match parse(bytes) {
            ParseOutcome::NotClientHello => {}
            other => panic!("expected NotClientHello, got {other:?}"),
        }
    }

    // ── Happy path ──────────────────────────────────────────────────────

    #[test]
    fn parses_single_record_sni() {
        let data = build_client_hello(Some("api.openai.com"));
        assert_sni(&data, "api.openai.com");
    }

    #[test]
    fn parses_no_sni_as_absent() {
        let data = build_client_hello(None);
        assert_sni_absent(&data);
    }

    #[test]
    fn parses_long_hostname() {
        let hostname = [
            "a".repeat(60),
            "b".repeat(60),
            "c".repeat(60),
            "example".to_string(),
            "com".to_string(),
        ]
        .join(".");
        let data = build_client_hello(Some(&hostname));
        assert_sni(&data, &hostname);
    }

    #[test]
    fn byte_by_byte_feed_completes_at_last_byte() {
        let data = build_client_hello(Some("example.com"));
        for i in 0..data.len() - 1 {
            assert_incomplete(&data[..=i]);
        }
        assert_sni(&data, "example.com");
    }

    // ── SNI not first extension ────────────────────────────────────────

    #[test]
    fn sni_after_other_extension() {
        let hostname = "deep.example.com";
        let mut ch_body = ch_prefix();
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x17]); // some non-SNI ext type
        extensions.extend_from_slice(&[0x00, 0x05]);
        extensions.extend_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee]);

        let host_bytes = hostname.as_bytes();
        let name_entry_len = 3 + host_bytes.len();
        let list_len = name_entry_len;
        let ext_data_len = 2 + list_len;
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&u16_bytes(ext_data_len));
        extensions.extend_from_slice(&u16_bytes(list_len));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16_bytes(host_bytes.len()));
        extensions.extend_from_slice(host_bytes);

        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(&extensions);

        let data = wrap_ch_body(&ch_body);
        assert_sni(&data, hostname);
    }

    // ── Malformed / truncated ───────────────────────────────────────────

    #[test]
    fn not_tls_handshake_returns_not_client_hello() {
        assert_not_client_hello(b"GET / HTTP/1.1\r\n");
    }

    #[test]
    fn wrong_handshake_type_returns_not_client_hello() {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x04];
        record.extend_from_slice(&[0x02, 0x00, 0x00, 0x00]);
        assert_not_client_hello(&record);
    }

    #[test]
    fn truncated_record_header_incomplete() {
        assert_incomplete(&[0x16, 0x03, 0x01]);
    }

    #[test]
    fn record_length_exceeds_data_incomplete() {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x64]; // len=100
        record.extend_from_slice(&[0u8; 10]);
        assert_incomplete(&record);
    }

    #[test]
    fn record_length_exceeds_tls_plaintext_max_is_malformed() {
        let record = vec![0x16, 0x03, 0x01, 0x40, 0x01]; // len=16385
        assert_malformed(&record);
    }

    #[test]
    fn handshake_length_exceeds_record_incomplete() {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x08];
        record.push(0x01);
        record.extend_from_slice(&[0x00, 0x00, 0x64]);
        record.extend_from_slice(&[0u8; 4]);
        assert_incomplete(&record);
    }

    #[test]
    fn zero_length_record_is_incomplete() {
        // Handshake header may straddle records; empty body is not an error
        // on its own.
        let record = vec![0x16, 0x03, 0x01, 0x00, 0x00];
        assert_incomplete(&record);
    }

    #[test]
    fn client_hello_body_too_short() {
        let mut record = vec![0x16, 0x03, 0x01, 0x00, 0x06];
        record.push(0x01);
        record.extend_from_slice(&[0x00, 0x00, 0x02]);
        record.extend_from_slice(&[0x03, 0x03]);
        assert_malformed(&record);
    }

    #[test]
    fn truncated_before_cipher_suites_length() {
        let body = ch_prefix();
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn oversized_session_id_is_malformed() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0u8; 33]);
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn empty_cipher_suites_is_malformed() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x00]);
        body.extend_from_slice(&[0x01, 0x00]);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn odd_cipher_suites_length_is_malformed() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x01, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn truncated_before_compression_methods() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02]);
        body.extend_from_slice(&[0x00, 0xFF]);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn empty_compression_methods_is_malformed() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]);
        body.push(0x00);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn no_extensions_block_is_absent_sni() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]);
        body.extend_from_slice(&[0x01, 0x00]);
        let record = wrap_ch_body(&body);
        assert_sni_absent(&record);
    }

    #[test]
    fn extensions_total_length_exceeds_body() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&[0x03, 0xe7]); // ext_len=999
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn trailing_byte_before_extensions_length_is_malformed() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.push(0xaa);

        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn extensions_length_must_consume_body() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&[0x00, 0x00]);
        body.push(0xaa);

        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn extensions_block_rejects_trailing_header_fragment() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);
        body.extend_from_slice(&[0x00, 0x01]);
        body.push(0xaa);

        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    #[test]
    fn extension_length_exceeds_extensions_block() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x10]);
        extensions.extend_from_slice(&[0x00, 0x99]); // 153 but no data follows

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_malformed(&record);
    }

    // ── SNI structure errors ────────────────────────────────────────────

    #[test]
    fn sni_extension_too_short() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]); // SNI
        extensions.extend_from_slice(&[0x00, 0x01]); // ext_len=1
        extensions.push(0x00);

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_list_length_exceeds_ext_data() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]); // SNI
        extensions.extend_from_slice(&[0x00, 0x02]); // ext_len=2
        extensions.extend_from_slice(&[0x00, 0x99]); // list_len=153

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_unknown_name_type_invalid_strict() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x08]);
        extensions.extend_from_slice(&[0x00, 0x06]);
        extensions.push(0x01); // name_type = 1 (unsupported)
        extensions.extend_from_slice(&[0x00, 0x03]);
        extensions.extend_from_slice(b"foo");

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_zero_length_hostname_invalid() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&[0x00, 0x05]);
        extensions.extend_from_slice(&[0x00, 0x03]);
        extensions.push(0x00); // host_name
        extensions.extend_from_slice(&[0x00, 0x00]); // zero-length

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_invalid_utf8_invalid() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let bad = &[0xff, 0xfe, 0x80, 0x81];
        let name_entry_len = 3 + bad.len();
        let list_len = name_entry_len;
        let ext_data_len = 2 + list_len;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&u16_bytes(ext_data_len));
        extensions.extend_from_slice(&u16_bytes(list_len));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16_bytes(bad.len()));
        extensions.extend_from_slice(bad);

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_extension_rejects_trailing_bytes_after_list() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let host = b"example.com";
        let list_len = 3 + host.len();
        let ext_data_len = 2 + list_len + 1;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&u16_bytes(ext_data_len));
        extensions.extend_from_slice(&u16_bytes(list_len));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16_bytes(host.len()));
        extensions.extend_from_slice(host);
        extensions.push(0xaa);

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_list_rejects_trailing_partial_entry_after_hostname() {
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        body.extend_from_slice(&[0x01, 0x00]);

        let host = b"example.com";
        let list_len = 3 + host.len() + 1;
        let ext_data_len = 2 + list_len;

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&u16_bytes(ext_data_len));
        extensions.extend_from_slice(&u16_bytes(list_len));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16_bytes(host.len()));
        extensions.extend_from_slice(host);
        extensions.push(0xaa);

        body.extend_from_slice(&u16_bytes(extensions.len()));
        body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    #[test]
    fn sni_ip_literal_hostname_invalid() {
        let ipv4 = build_client_hello(Some("127.0.0.1"));
        assert_sni_malformed(&ipv4);

        let ipv6 = build_client_hello(Some("2001:db8::1"));
        assert_sni_malformed(&ipv6);
    }

    #[test]
    fn sni_hostname_is_canonicalized_to_lowercase() {
        let data = build_client_hello(Some("API.OpenAI.COM"));
        assert_sni(&data, "api.openai.com");
    }

    #[test]
    fn sni_rejects_non_dns_hostnames() {
        for host in [
            "bad host.example",
            "example.com.",
            ".example.com",
            "example..com",
            "-bad.example",
            "bad-.example",
            "exa_mple.com",
            "bücher.example",
        ] {
            let record = build_client_hello(Some(host));
            assert_sni_malformed(&record);
        }
    }

    #[test]
    fn sni_name_entry_truncated_inside_valid_ext() {
        // The SNI extension's outer ext_len is honest, but inside the list
        // the name_len claims more bytes than the list contains. This must
        // surface as Malformed (fail-closed), not a parse crash.
        let mut body = ch_prefix();
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0xFF]);
        body.extend_from_slice(&[0x01, 0x00]);

        // list body: name_type(1) + name_len(2) = 3 bytes, claiming name_len=32
        let mut ext = Vec::new();
        ext.extend_from_slice(&[0x00, 0x00]); // SNI
        ext.extend_from_slice(&[0x00, 0x05]); // ext_len = 5 (honest)
        ext.extend_from_slice(&[0x00, 0x03]); // list_len = 3
        ext.push(0x00); // host_name
        ext.extend_from_slice(&[0x00, 0x20]); // name_len = 32 (no bytes follow)

        body.extend_from_slice(&u16_bytes(ext.len()));
        body.extend_from_slice(&ext);
        let record = wrap_ch_body(&body);
        assert_sni_malformed(&record);
    }

    // ── ECH ─────────────────────────────────────────────────────────────

    #[test]
    fn ech_extension_sets_flag_alongside_sni() {
        let mut ch_body = ch_prefix();
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();

        // ECH first
        extensions.extend_from_slice(&[0xFE, 0x0D]);
        extensions.extend_from_slice(&[0x00, 0x04]);
        extensions.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);

        // Decoy SNI follows
        let decoy = b"decoy.example.com";
        let name_entry_len = 3 + decoy.len();
        let list_len = name_entry_len;
        let ext_data_len = 2 + list_len;
        extensions.extend_from_slice(&[0x00, 0x00]);
        extensions.extend_from_slice(&u16_bytes(ext_data_len));
        extensions.extend_from_slice(&u16_bytes(list_len));
        extensions.push(0x00);
        extensions.extend_from_slice(&u16_bytes(decoy.len()));
        extensions.extend_from_slice(decoy);

        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(&extensions);

        let record = wrap_ch_body(&ch_body);
        match parse(&record) {
            ParseOutcome::Parsed(ch) => {
                assert!(ch.has_ech, "ECH flag must be set");
                // Parser surfaces the decoy SNI alongside the ECH flag;
                // callers decide whether to use it.
                match ch.sni {
                    SniField::HostName(h) => assert_eq!(h, "decoy.example.com"),
                    other @ SniField::Absent => panic!("expected decoy HostName, got {other:?}"),
                }
            }
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    // ── ALPN ────────────────────────────────────────────────────────────

    #[test]
    fn alpn_offers_extracted_when_present() {
        let mut ch_body = ch_prefix();
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        // ALPN layout:
        //   ext_type(2) + ext_len(2) + list_len(2) + [ (1)+proto ]*
        // Two protos: "h2" (3 bytes framed) + "http/1.1" (9 bytes framed) = 12
        extensions.extend_from_slice(&[0x00, 0x10]); // ALPN
        extensions.extend_from_slice(&[0x00, 0x0e]); // ext_len = 14 (2 + 12)
        extensions.extend_from_slice(&[0x00, 0x0c]); // list_len = 12
        extensions.push(0x02);
        extensions.extend_from_slice(b"h2");
        extensions.push(0x08);
        extensions.extend_from_slice(b"http/1.1");

        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&ch_body);

        match parse(&record) {
            ParseOutcome::Parsed(ch) => {
                let offers = ch.alpn_offers.expect("ALPN must be Some");
                assert_eq!(offers.len(), 2);
                assert_eq!(offers[0], b"h2");
                assert_eq!(offers[1], b"http/1.1");
            }
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    #[test]
    fn alpn_absent_when_no_extension() {
        let data = build_client_hello(Some("example.com"));
        match parse(&data) {
            ParseOutcome::Parsed(ch) => assert!(ch.alpn_offers.is_none()),
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    #[test]
    fn extract_alpn_offers_helper_matches_parse() {
        let mut ch_body = ch_prefix();
        ch_body.extend_from_slice(&[0x00, 0x02, 0x00, 0xff]);
        ch_body.extend_from_slice(&[0x01, 0x00]);

        let mut extensions = Vec::new();
        extensions.extend_from_slice(&[0x00, 0x10]);
        extensions.extend_from_slice(&[0x00, 0x0e]);
        extensions.extend_from_slice(&[0x00, 0x0c]);
        extensions.push(0x02);
        extensions.extend_from_slice(b"h2");
        extensions.push(0x08);
        extensions.extend_from_slice(b"http/1.1");

        ch_body.extend_from_slice(&u16_bytes(extensions.len()));
        ch_body.extend_from_slice(&extensions);
        let record = wrap_ch_body(&ch_body);

        let offers = extract_alpn_offers(&record)
            .unwrap()
            .expect("helper must return Some");
        assert_eq!(offers, vec![b"h2".to_vec(), b"http/1.1".to_vec()]);
    }

    #[test]
    fn extract_alpn_offers_returns_none_on_absent() {
        let data = build_client_hello(Some("example.com"));
        assert!(extract_alpn_offers(&data).unwrap().is_none());
    }

    #[test]
    fn extract_alpn_offers_returns_none_on_incomplete() {
        assert!(extract_alpn_offers(&[0x16, 0x03, 0x01]).unwrap().is_none());
    }

    #[test]
    fn alpn_extension_too_short_is_malformed() {
        let record = build_alpn_client_hello(&[0x00]);
        assert_malformed(&record);
    }

    #[test]
    fn alpn_list_length_exceeds_extension_is_malformed() {
        let record = build_alpn_client_hello(&[0x00, 0x03, 0x02, b'h']);
        assert_malformed(&record);
    }

    #[test]
    fn alpn_rejects_trailing_bytes_after_list() {
        let record = build_alpn_client_hello(&[0x00, 0x03, 0x02, b'h', b'2', 0xaa]);
        assert_malformed(&record);
    }

    #[test]
    fn alpn_rejects_truncated_protocol_name_instead_of_partial_offer() {
        let record = build_alpn_client_hello(&[0x00, 0x05, 0x02, b'h', b'2', 0x08, 0xaa]);

        assert_malformed(&record);
        assert!(extract_alpn_offers(&record).is_err());
    }

    #[test]
    fn alpn_rejects_zero_length_protocol_name() {
        let record = build_alpn_client_hello(&[0x00, 0x01, 0x00]);
        assert_malformed(&record);
    }

    #[test]
    fn alpn_rejects_empty_protocol_name_list() {
        let record = build_alpn_client_hello(&[0x00, 0x00]);
        assert_malformed(&record);
    }

    #[test]
    fn duplicate_sni_extension_is_malformed() {
        let mut first = build_client_hello(Some("one.example.com"));
        let body_start = 5 + 4;
        let ext_len_pos = body_start + 34 + 1 + 4 + 2;
        let extensions_start = ext_len_pos + 2;
        let extension = first[extensions_start..].to_vec();
        first.extend_from_slice(&extension);

        let body_len = first.len() - body_start;
        let ext_len = first.len() - extensions_start;
        first[6..9].copy_from_slice(&hs_len_bytes(body_len));
        first[ext_len_pos..ext_len_pos + 2].copy_from_slice(&u16_bytes(ext_len));
        let record_len = first.len() - 5;
        first[3..5].copy_from_slice(&u16_bytes(record_len));

        assert_malformed(&first);
    }

    #[test]
    fn duplicate_alpn_extension_is_malformed() {
        let alpn = [0x00, 0x03, 0x02, b'h', b'2'];
        let mut extensions = Vec::new();
        for _ in 0..2 {
            extensions.extend_from_slice(&[0x00, 0x10]);
            extensions.extend_from_slice(&u16_bytes(alpn.len()));
            extensions.extend_from_slice(&alpn);
        }

        let record = build_client_hello_with_extensions(&extensions);
        assert_malformed(&record);
    }

    #[test]
    fn duplicate_unknown_extension_is_malformed() {
        let mut extensions = Vec::new();
        for _ in 0..2 {
            extensions.extend_from_slice(&[0x12, 0x34]);
            extensions.extend_from_slice(&[0x00, 0x00]);
        }

        let record = build_client_hello_with_extensions(&extensions);
        assert_malformed(&record);
    }

    // ── Multi-record reassembly ────────────────────────────────────────

    #[test]
    fn multi_record_two() {
        let data = build_multi_record("multi.example.com", 2);
        assert_sni(&data, "multi.example.com");
    }

    #[test]
    fn multi_record_three() {
        let data = build_multi_record("three.example.com", 3);
        assert_sni(&data, "three.example.com");
    }

    #[test]
    fn multi_record_followed_by_non_handshake() {
        let mut data = build_client_hello(Some("mixed.example.com"));
        data.extend_from_slice(&[0x14, 0x03, 0x01, 0x00, 0x01, 0x01]); // ChangeCipherSpec
        assert_sni(&data, "mixed.example.com");
    }

    #[test]
    fn complete_client_hello_followed_by_partial_handshake_still_parses() {
        let mut data = build_client_hello(Some("complete.example.com"));
        data.extend_from_slice(&[0x16, 0x03, 0x01, 0x00]); // partial next record
        assert_sni(&data, "complete.example.com");
    }

    #[test]
    fn non_handshake_before_complete_client_hello_is_malformed() {
        let data = build_multi_record("mixed-before-complete.example.com", 2);
        let first_record_len = 5 + u16::from_be_bytes([data[3], data[4]]) as usize;
        let mut mixed = data[..first_record_len].to_vec();
        mixed.extend_from_slice(&[0x14, 0x03, 0x01, 0x00, 0x01, 0x01]);
        assert_malformed(&mixed);
    }

    #[test]
    fn multi_record_partial_second() {
        let data = build_multi_record("partial.example.com", 2);
        let truncated = &data[..data.len() - 5];
        assert_incomplete(truncated);
    }

    // ── Policy-style fixture (cross-check against old tls.rs tests) ────

    #[test]
    fn policy_style_fixture_parses_sni() {
        let data = make_client_hello_policy_style("api.openai.com");
        assert_sni(&data, "api.openai.com");
    }

    // ── Cached-error equivalent: parse is stateless, so we assert twice ─

    #[test]
    fn stateless_parse_is_idempotent() {
        let data = build_client_hello(Some("idempotent.example.com"));
        assert_sni(&data, "idempotent.example.com");
        // Same input, different caller state — must give the same answer.
        assert_sni(&data, "idempotent.example.com");
    }
}
