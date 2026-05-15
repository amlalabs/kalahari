// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! TLS protocol inspector
//!
//! Extracts Server Name Indication (SNI) from TLS `ClientHello` messages
//! and enforces hostname allowlist policies.
//!
//! Follows fail-closed:
//! - Missing SNI → DENY
//! - Encrypted Client Hello (ECH) → DENY (documented limitation)
//! - Malformed `ClientHello` → DENY

use super::sticky_lru::StickyLruCache;
use super::{ConnectionKey, EvidenceParser, InspectionResult, matches_any_pattern};
use amla_tls_parse::{ParseOutcome, SniField, parse as parse_client_hello};
use parking_lot::RwLock;
use std::collections::HashSet;

// =============================================================================
// Connection State
// =============================================================================

/// Maximum bytes buffered per connection while waiting for a complete
/// `ClientHello`. Set to 32 KiB — post-quantum key shares (e.g. ML-KEM /
/// Kyber) can push a `ClientHello` beyond 16 KiB.
const MAX_BUFFER_PER_CONNECTION: usize = 32 * 1024;

/// State for a TLS connection
#[derive(Debug, Clone)]
enum TlsConnectionState {
    /// Collecting bytes for a not-yet-complete `ClientHello` that was
    /// fragmented across multiple TCP segments or TLS records.
    Buffering { buf: Vec<u8> },
    /// SNI extracted, decision made
    Decided { allowed: bool, sni: Option<String> },
}

impl TlsConnectionState {
    fn is_decided_deny(&self) -> bool {
        matches!(self, Self::Decided { allowed: false, .. })
    }
}

// =============================================================================
// TLS Inspector
// =============================================================================

/// Inspector for TLS protocol
///
/// Extracts SNI from `ClientHello` and checks against allowed hostnames.
/// Missing SNI is denied (fail-closed).
pub struct TlsInspector {
    /// Allowed hostnames (exact or wildcard)
    allowed_hosts: RwLock<HashSet<String>>,
    /// Per-connection state. `Decided{allowed:false}` entries are sticky so a
    /// flood of junk connections can't evict a cached Deny.
    connections: StickyLruCache<ConnectionKey, TlsConnectionState>,
}

impl TlsInspector {
    /// Create a new TLS inspector
    pub fn new() -> Self {
        Self {
            allowed_hosts: RwLock::new(HashSet::new()),
            connections: StickyLruCache::new(10000),
        }
    }

    /// Create with initial allowed hosts
    pub fn with_allowed(hosts: &[&str]) -> Self {
        let mut allowed = HashSet::new();
        for host in hosts {
            allowed.insert(host.to_lowercase());
        }
        Self {
            allowed_hosts: RwLock::new(allowed),
            connections: StickyLruCache::new(10000),
        }
    }

    /// Add an allowed hostname
    ///
    /// Clears cached per-connection decisions so the new config takes effect
    /// on subsequent packets for all connections.
    pub fn allow_host(&self, host: &str) {
        self.allowed_hosts.write().insert(host.to_lowercase());
        self.connections.clear();
    }

    /// Set maximum tracked connections
    pub fn set_max_connections(&mut self, max: usize) {
        self.connections.set_max_entries(max);
    }

    /// Check if a hostname is allowed
    fn is_host_allowed(&self, host: &str) -> bool {
        matches_any_pattern(host, &self.allowed_hosts.read())
    }

    /// Insert or update a connection entry.
    ///
    /// `Decided{allowed:false}` entries are sticky — see `StickyLruCache`.
    /// An eviction that falls back to a sticky entry is warn-logged so the
    /// security-relevant "state table full of denies" case is observable.
    fn record_decision(&self, key: &ConnectionKey, state: TlsConnectionState) {
        let sticky = state.is_decided_deny();
        self.connections.insert(*key, state, sticky, |k| {
            log::warn!(
                "TLS inspector: evicting Decided-Deny entry {k:?} — state table full of denies"
            );
        });
    }
}

impl Default for TlsInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceParser for TlsInspector {
    #[allow(clippy::too_many_lines)] // State machine + outcome mapping is a single unit
    fn inspect(
        &self,
        key: &ConnectionKey,
        payload: &[u8],
        is_first_packet: bool,
    ) -> InspectionResult {
        // Single peek covers both branches: fast-path out on a cached
        // terminal decision, otherwise start from the pending Buffering
        // bytes (or empty if this is the first fragment). Peeking twice
        // would clone the Buffering buffer redundantly on every fragment.
        let mut buf = match self.connections.peek(key) {
            Some(TlsConnectionState::Decided { allowed, sni }) => {
                self.connections.touch(key);
                return if allowed {
                    InspectionResult::Allow
                } else {
                    InspectionResult::Deny(format!(
                        "TLS SNI not allowed: {}",
                        sni.as_deref().unwrap_or("<none>")
                    ))
                };
            }
            Some(TlsConnectionState::Buffering { buf }) => buf,
            None => {
                if !is_first_packet {
                    return InspectionResult::NeedMoreData;
                }
                Vec::new()
            }
        };

        buf.extend_from_slice(payload);

        // Bound per-connection memory. A cooperating client's ClientHello
        // fits easily in 32 KiB; exceeding that is either a protocol abuse
        // or a resource-exhaustion attempt.
        if buf.len() > MAX_BUFFER_PER_CONNECTION {
            self.record_decision(
                key,
                TlsConnectionState::Decided {
                    allowed: false,
                    sni: None,
                },
            );
            return InspectionResult::Deny(
                "TLS: ClientHello exceeds buffer limit (fail-closed)".to_string(),
            );
        }

        let outcome = parse_client_hello(&buf);
        let sni = match outcome {
            ParseOutcome::Incomplete => {
                self.record_decision(key, TlsConnectionState::Buffering { buf });
                return InspectionResult::NeedMoreData;
            }
            ParseOutcome::Parsed(ch) if ch.has_ech => {
                log::debug!("TLS parse error (fail-closed): ECH present");
                self.record_decision(
                    key,
                    TlsConnectionState::Decided {
                        allowed: false,
                        sni: None,
                    },
                );
                return InspectionResult::Deny(
                    "TLS parse error: Encrypted Client Hello (ECH) not supported".to_string(),
                );
            }
            ParseOutcome::Parsed(ch) => match ch.sni {
                SniField::HostName(s) => s,
                SniField::Absent => {
                    self.record_decision(
                        key,
                        TlsConnectionState::Decided {
                            allowed: false,
                            sni: None,
                        },
                    );
                    return InspectionResult::Deny("TLS: missing SNI (fail-closed)".to_string());
                }
            },
            ParseOutcome::NotClientHello => {
                log::debug!("TLS parse error (fail-closed): not a ClientHello");
                self.record_decision(
                    key,
                    TlsConnectionState::Decided {
                        allowed: false,
                        sni: None,
                    },
                );
                return InspectionResult::Deny(
                    "TLS parse error: Not a TLS handshake record".to_string(),
                );
            }
            ParseOutcome::Malformed(e) => {
                log::debug!("TLS parse error (fail-closed): {e}");
                self.record_decision(
                    key,
                    TlsConnectionState::Decided {
                        allowed: false,
                        sni: None,
                    },
                );
                return InspectionResult::Deny(format!("TLS parse error: {e}"));
            }
        };

        log::trace!("TLS SNI: {sni}");

        let allowed = self.is_host_allowed(&sni);
        self.record_decision(
            key,
            TlsConnectionState::Decided {
                allowed,
                sni: Some(sni.clone()),
            },
        );

        if allowed {
            InspectionResult::Allow
        } else {
            InspectionResult::Deny(format!("TLS SNI not in allowlist: {sni}"))
        }
    }

    fn name(&self) -> &'static str {
        "TLS"
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
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::cast_possible_truncation
    )]
    use super::*;
    use std::net::Ipv4Addr;

    // Local fixture constants; the parser constants now live in
    // amla-vm-tls-parse but the test fixtures still need them to emit
    // correctly framed bytes.
    const TLS_HANDSHAKE: u8 = 22;
    const TLS_CLIENT_HELLO: u8 = 1;

    /// Create a TLS `ClientHello` with SNI
    fn make_client_hello(sni: &str) -> Vec<u8> {
        let mut hello = Vec::new();

        // === TLS Record Header ===
        hello.push(TLS_HANDSHAKE); // Content type: Handshake
        hello.extend_from_slice(&[0x03, 0x01]); // Version: TLS 1.0 (for record layer)
        // Length placeholder (will fill later)
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        // === Handshake Header ===
        hello.push(TLS_CLIENT_HELLO); // Handshake type: ClientHello
        // Length placeholder (will fill later)
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        // === ClientHello ===
        let client_hello_start = hello.len();

        // Version: TLS 1.2
        hello.extend_from_slice(&[0x03, 0x03]);

        // Random: 32 bytes
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID: empty
        hello.push(0);

        // Cipher suites: 2 suites
        hello.extend_from_slice(&[0x00, 0x04]); // Length
        hello.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        hello.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // Compression methods: null only
        hello.push(0x01);
        hello.push(0x00);

        // === Extensions ===
        let extensions_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]); // Placeholder

        let extensions_start = hello.len();

        // SNI extension
        hello.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
        let sni_bytes = sni.as_bytes();
        let sni_ext_len = 2 + 1 + 2 + sni_bytes.len();
        hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes()); // Extension length
        hello.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes()); // Server name list length
        hello.push(0x00); // Name type: hostname
        hello.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes()); // Name length
        hello.extend_from_slice(sni_bytes);

        // Fill in lengths
        let extensions_len = hello.len() - extensions_start;
        hello[extensions_len_pos..extensions_len_pos + 2]
            .copy_from_slice(&(extensions_len as u16).to_be_bytes());

        let client_hello_len = hello.len() - client_hello_start;
        hello[handshake_len_pos] = ((client_hello_len >> 16) & 0xFF) as u8;
        hello[handshake_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        hello[handshake_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let record_len = hello.len() - 5;
        hello[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_len as u16).to_be_bytes());

        hello
    }

    /// Create a `ClientHello` without SNI
    fn make_client_hello_no_sni() -> Vec<u8> {
        let mut hello = Vec::new();

        // TLS Record Header
        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        // Handshake Header
        hello.push(TLS_CLIENT_HELLO);
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        let client_hello_start = hello.len();

        // Version + Random
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID: empty
        hello.push(0);

        // Cipher suites
        hello.extend_from_slice(&[0x00, 0x02]);
        hello.extend_from_slice(&[0x13, 0x01]);

        // Compression
        hello.push(0x01);
        hello.push(0x00);

        // No extensions at all
        hello.extend_from_slice(&[0x00, 0x00]);

        // Fill lengths
        let client_hello_len = hello.len() - client_hello_start;
        hello[handshake_len_pos] = ((client_hello_len >> 16) & 0xFF) as u8;
        hello[handshake_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        hello[handshake_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let record_len = hello.len() - 5;
        hello[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_len as u16).to_be_bytes());

        hello
    }

    fn dummy_key() -> ConnectionKey {
        ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            443,
            6, // TCP
        )
    }

    #[test]
    fn test_tls_fragmented_client_hello_across_packets() {
        // A well-formed ClientHello split byte-by-byte into many "packets"
        // must reassemble correctly — this is the scenario the policy-net
        // inspector previously false-denied as "TLS record truncated".
        let inspector = TlsInspector::with_allowed(&["api.openai.com"]);
        let hello = make_client_hello("api.openai.com");
        let key = dummy_key();

        // All but the last byte should return NeedMoreData.
        for (i, byte) in hello.iter().take(hello.len() - 1).enumerate() {
            let r = inspector.inspect(&key, &[*byte], i == 0);
            assert_eq!(
                r,
                InspectionResult::NeedMoreData,
                "fragment byte {i} should buffer, got {r:?}"
            );
        }
        // Final byte completes the parse.
        let final_r = inspector.inspect(&key, &[*hello.last().unwrap()], false);
        assert_eq!(final_r, InspectionResult::Allow);
    }

    #[test]
    fn test_tls_sni_extraction() {
        // Smoke-test that the inspector's fixture format parses cleanly
        // through the shared parser. Deep parser coverage lives in
        // amla-vm-tls-parse's own test module.
        let hello = make_client_hello("api.openai.com");
        match parse_client_hello(&hello) {
            ParseOutcome::Parsed(ch) => match ch.sni {
                SniField::HostName(s) => assert_eq!(s, "api.openai.com"),
                other @ SniField::Absent => panic!("expected HostName, got {other:?}"),
            },
            other => panic!("expected Parsed, got {other:?}"),
        }
    }

    #[test]
    fn test_tls_allow_sni() {
        let inspector = TlsInspector::with_allowed(&["api.openai.com"]);
        let hello = make_client_hello("api.openai.com");

        let result = inspector.inspect(&dummy_key(), &hello, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_tls_deny_unlisted_sni() {
        let inspector = TlsInspector::with_allowed(&["api.openai.com"]);
        let hello = make_client_hello("evil.com");

        let result = inspector.inspect(&dummy_key(), &hello, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_tls_wildcard_sni() {
        let inspector = TlsInspector::with_allowed(&["*.github.com"]);

        let hello = make_client_hello("api.github.com");
        let result = inspector.inspect(&dummy_key(), &hello, true);
        assert_eq!(result, InspectionResult::Allow);

        // Different connection key for different SNI test
        let key2 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 5),
            12346,
            443,
            6,
        );
        let hello = make_client_hello("github.com");
        let result = inspector.inspect(&key2, &hello, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_tls_missing_sni_denied() {
        let inspector = TlsInspector::with_allowed(&["*"]);
        let hello = make_client_hello_no_sni();

        let result = inspector.inspect(&dummy_key(), &hello, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_tls_malformed_denied() {
        let inspector = TlsInspector::with_allowed(&["*"]);

        // Non-handshake record type (0x15 = Alert) — can't be a ClientHello,
        // so deny. Note: a short-but-valid prefix like [0x16, 0x03, 0x01]
        // is NOT malformed — the inspector now buffers those pending more
        // bytes, which is required for legitimately fragmented ClientHellos.
        let mut payload = vec![0x15, 0x03, 0x01, 0x00, 0x02, 0x02, 0x28];
        let result = inspector.inspect(&dummy_key(), &payload, true);
        assert!(matches!(result, InspectionResult::Deny(_)));

        // Valid handshake prefix that's too short to parse yet: buffers.
        payload.clear();
        payload.extend_from_slice(&[0x16, 0x03, 0x01]);
        let result2 = inspector.inspect(
            &ConnectionKey::new(
                Ipv4Addr::new(10, 0, 0, 2),
                Ipv4Addr::new(1, 2, 3, 4),
                1234,
                443,
                6,
            ),
            &payload,
            true,
        );
        assert_eq!(result2, InspectionResult::NeedMoreData);
    }

    #[test]
    fn test_tls_connection_state_cached() {
        let inspector = TlsInspector::with_allowed(&["api.openai.com"]);
        let key = dummy_key();
        let hello = make_client_hello("api.openai.com");

        // First packet establishes state
        let result = inspector.inspect(&key, &hello, true);
        assert_eq!(result, InspectionResult::Allow);
        assert_eq!(inspector.connection_count(), 1);

        // Subsequent packets use cached state
        let result = inspector.inspect(&key, &[0u8; 100], false);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_tls_clear_state() {
        let inspector = TlsInspector::with_allowed(&["test.com"]);
        let hello = make_client_hello("test.com");

        drop(inspector.inspect(&dummy_key(), &hello, true));
        assert_eq!(inspector.connection_count(), 1);

        inspector.clear_state();
        assert_eq!(inspector.connection_count(), 0);
    }

    #[test]
    fn test_tls_ech_extension_denied() {
        // Build a ClientHello with both SNI and ECH extensions
        let mut hello = Vec::new();

        // TLS Record Header
        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        // Handshake Header
        hello.push(TLS_CLIENT_HELLO);
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        let client_hello_start = hello.len();

        // Version + Random
        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);

        // Session ID: empty
        hello.push(0);

        // Cipher suites
        hello.extend_from_slice(&[0x00, 0x02]);
        hello.extend_from_slice(&[0x13, 0x01]);

        // Compression
        hello.push(0x01);
        hello.push(0x00);

        // Extensions
        let extensions_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let extensions_start = hello.len();

        // SNI extension
        let sni = b"test.com";
        let sni_ext_len = 2 + 1 + 2 + sni.len();
        hello.extend_from_slice(&[0x00, 0x00]); // Extension type: SNI
        hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        hello.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes());
        hello.push(0x00); // Name type: hostname
        hello.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hello.extend_from_slice(sni);

        // ECH extension (0xFE0D)
        hello.extend_from_slice(&0xFE0Du16.to_be_bytes()); // Extension type: ECH
        hello.extend_from_slice(&[0x00, 0x04]); // Extension length: 4
        hello.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // Dummy ECH data

        // Fill in lengths
        let extensions_len = hello.len() - extensions_start;
        hello[extensions_len_pos..extensions_len_pos + 2]
            .copy_from_slice(&(extensions_len as u16).to_be_bytes());

        let client_hello_len = hello.len() - client_hello_start;
        hello[handshake_len_pos] = ((client_hello_len >> 16) & 0xFF) as u8;
        hello[handshake_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        hello[handshake_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let record_len = hello.len() - 5;
        hello[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_len as u16).to_be_bytes());

        let inspector = TlsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &hello, true);
        // ECH should cause denial even with valid SNI
        assert!(matches!(result, InspectionResult::Deny(ref msg) if msg.contains("ECH")));
    }

    #[test]
    fn test_tls_eviction_at_max() {
        let mut inspector = TlsInspector::with_allowed(&["test.com"]);
        inspector.set_max_connections(5);

        for i in 0u16..10 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(1, 2, 3, 4),
                12345 + i,
                443,
                6,
            );
            let hello = make_client_hello("test.com");
            drop(inspector.inspect(&key, &hello, true));
        }

        // LRU-bounded, should never exceed cap.
        assert_eq!(inspector.connection_count(), 5);
    }

    #[test]
    fn test_tls_deny_is_sticky_under_eviction_pressure() {
        // An attacker denies themselves once, then tries to flood the state
        // table with allowed connections to push their own Deny out of the
        // cache and regain a "clean slate". The Deny must stick.
        let mut inspector = TlsInspector::with_allowed(&["good.com"]);
        inspector.set_max_connections(4);

        let attacker = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 200),
            Ipv4Addr::new(1, 2, 3, 4),
            55555,
            443,
            6,
        );
        // Step 1: attacker's connection is denied.
        let evil = make_client_hello("evil.com");
        assert!(matches!(
            inspector.inspect(&attacker, &evil, true),
            InspectionResult::Deny(_)
        ));

        // Step 2: flood with legitimate allowed connections, far exceeding cap.
        for i in 0u16..50 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(1, 2, 3, 4),
                20000 + i,
                443,
                6,
            );
            let hello = make_client_hello("good.com");
            drop(inspector.inspect(&key, &hello, true));
        }

        // Step 3: attacker retries. The cached Deny must still be there,
        // *not* NeedMoreData or any "free packet" state.
        let result = inspector.inspect(&attacker, &[0u8; 16], false);
        assert!(
            matches!(result, InspectionResult::Deny(_)),
            "Deny must survive eviction pressure; got {result:?}"
        );
    }

    #[test]
    fn test_tls_buffering_is_dropped_under_eviction_pressure() {
        // A `Buffering` entry that gets evicted must not re-combine with a
        // later segment to produce an `Allow`. After eviction the accumulator
        // restarts from scratch, so a mid-handshake remainder alone cannot
        // masquerade as a fresh ClientHello.
        let mut inspector = TlsInspector::with_allowed(&["good.com"]);
        inspector.set_max_connections(4);

        let attacker = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 201),
            Ipv4Addr::new(1, 2, 3, 4),
            44444,
            443,
            6,
        );
        let full = make_client_hello("good.com");
        assert!(
            full.len() > 60,
            "fixture precondition: ClientHello long enough to split"
        );
        let split_at = 40;
        let (seg1, seg2) = full.split_at(split_at);

        // Step 1: partial ClientHello → Buffering.
        let first = inspector.inspect(&attacker, seg1, true);
        assert_eq!(
            first,
            InspectionResult::NeedMoreData,
            "partial ClientHello should buffer; got {first:?}"
        );

        // Step 2: flood so the attacker's Buffering entry is definitely evicted.
        // Each victim connection is also left in Buffering by sending only its
        // first segment, guaranteeing LRU churn on Buffering entries specifically.
        for i in 0u16..50 {
            let key = ConnectionKey::new(
                Ipv4Addr::new(10, 0, 2, 15),
                Ipv4Addr::new(1, 2, 3, 4),
                30000 + i,
                443,
                6,
            );
            let other = make_client_hello("good.com");
            let (otherseg1, _) = other.split_at(split_at);
            drop(inspector.inspect(&key, otherseg1, true));
        }

        // Step 3: attacker's remaining bytes arrive. seg2 is the *middle* of
        // a handshake, not a record header — parsed alone it must not look
        // like a fresh valid ClientHello that could Allow. Acceptable outcomes
        // are NeedMoreData (re-buffering into a fresh window) or Deny; the
        // forbidden outcome is Allow.
        let result = inspector.inspect(&attacker, seg2, true);
        assert!(
            !matches!(result, InspectionResult::Allow),
            "evicted Buffering state must not produce Allow on stray remainder; got {result:?}",
        );
    }

    #[test]
    fn test_tls_unsupported_sni_name_type() {
        // Build a ClientHello with name_type = 1 (not hostname)
        let mut hello = Vec::new();

        hello.push(TLS_HANDSHAKE);
        hello.extend_from_slice(&[0x03, 0x01]);
        let record_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);

        hello.push(TLS_CLIENT_HELLO);
        let handshake_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00, 0x00]);

        let client_hello_start = hello.len();

        hello.extend_from_slice(&[0x03, 0x03]);
        hello.extend_from_slice(&[0u8; 32]);
        hello.push(0); // session ID
        hello.extend_from_slice(&[0x00, 0x02]);
        hello.extend_from_slice(&[0x13, 0x01]);
        hello.push(0x01);
        hello.push(0x00);

        let extensions_len_pos = hello.len();
        hello.extend_from_slice(&[0x00, 0x00]);
        let extensions_start = hello.len();

        // SNI extension with name_type = 1 (unsupported)
        let name = b"test.com";
        let sni_ext_len = 2 + 1 + 2 + name.len();
        hello.extend_from_slice(&[0x00, 0x00]); // SNI extension
        hello.extend_from_slice(&(sni_ext_len as u16).to_be_bytes());
        hello.extend_from_slice(&((sni_ext_len - 2) as u16).to_be_bytes());
        hello.push(0x01); // Name type: NOT hostname (unsupported)
        hello.extend_from_slice(&(name.len() as u16).to_be_bytes());
        hello.extend_from_slice(name);

        let extensions_len = hello.len() - extensions_start;
        hello[extensions_len_pos..extensions_len_pos + 2]
            .copy_from_slice(&(extensions_len as u16).to_be_bytes());

        let client_hello_len = hello.len() - client_hello_start;
        hello[handshake_len_pos] = ((client_hello_len >> 16) & 0xFF) as u8;
        hello[handshake_len_pos + 1] = ((client_hello_len >> 8) & 0xFF) as u8;
        hello[handshake_len_pos + 2] = (client_hello_len & 0xFF) as u8;

        let record_len = hello.len() - 5;
        hello[record_len_pos..record_len_pos + 2]
            .copy_from_slice(&(record_len as u16).to_be_bytes());

        let inspector = TlsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &hello, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_tls_not_first_packet_no_state() {
        // Non-first packet with no cached state should request more data
        let inspector = TlsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &[0u8; 100], false);
        assert_eq!(result, InspectionResult::NeedMoreData);
    }

    #[test]
    fn test_tls_name() {
        let inspector = TlsInspector::new();
        assert_eq!(inspector.name(), "TLS");
    }

    #[test]
    fn test_tls_allow_host_clears_cache() {
        // Start with no allowed hosts — connection denied
        let inspector = TlsInspector::new();
        let key = dummy_key();
        let hello = make_client_hello("api.openai.com");

        let result = inspector.inspect(&key, &hello, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
        assert_eq!(inspector.connection_count(), 1);

        // Allow the host — cache must be cleared
        inspector.allow_host("api.openai.com");
        assert_eq!(
            inspector.connection_count(),
            0,
            "allow_host must clear cache"
        );

        // Re-inspect: should now be allowed
        let result = inspector.inspect(&key, &hello, true);
        assert_eq!(result, InspectionResult::Allow);
    }
}
