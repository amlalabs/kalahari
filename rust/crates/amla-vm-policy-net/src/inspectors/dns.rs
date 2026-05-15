// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! DNS protocol inspector
//!
//! Inspects DNS queries and enforces domain allowlist/denylist policies.
//! Follows fail-closed: malformed queries are denied.

use super::{ConnectionKey, EvidenceParser, InspectionResult, matches_any_pattern};
use parking_lot::RwLock;
use std::collections::HashSet;

// =============================================================================
// DNS Inspector
// =============================================================================

/// Inspector for DNS protocol
///
/// Checks DNS query domain names against allowed/blocked lists.
/// Supports wildcard matching (e.g., `*.github.com`).
pub struct DnsInspector {
    /// Allowed domains (exact match or wildcard)
    allowed_domains: RwLock<HashSet<String>>,
    /// Blocked domains (exact match or wildcard)
    blocked_domains: RwLock<HashSet<String>>,
    /// Whether to block domains not in allowlist (default: true for fail-closed)
    block_unlisted: bool,
}

impl DnsInspector {
    /// Create a new DNS inspector
    ///
    /// By default, blocks all domains not explicitly allowed (fail-closed).
    pub fn new() -> Self {
        Self {
            allowed_domains: RwLock::new(HashSet::new()),
            blocked_domains: RwLock::new(HashSet::new()),
            block_unlisted: true,
        }
    }

    /// Create with initial allowed domains
    pub fn with_allowed(domains: &[&str]) -> Self {
        let mut allowed = HashSet::new();
        for domain in domains {
            allowed.insert(domain.to_lowercase());
        }
        Self {
            allowed_domains: RwLock::new(allowed),
            blocked_domains: RwLock::new(HashSet::new()),
            block_unlisted: true,
        }
    }

    /// Add a blocked domain
    pub fn block_domain(&self, domain: &str) {
        self.blocked_domains.write().insert(domain.to_lowercase());
    }

    /// Check if a domain matches an allowlist entry
    fn is_domain_allowed(&self, domain: &str) -> bool {
        matches_any_pattern(domain, &self.allowed_domains.read())
    }

    /// Check if a domain is explicitly blocked
    fn is_domain_blocked(&self, domain: &str) -> bool {
        matches_any_pattern(domain, &self.blocked_domains.read())
    }

    /// Parse DNS query and extract domain name
    fn parse_dns_query(payload: &[u8]) -> Result<String, &'static str> {
        // DNS header is 12 bytes
        if payload.len() < 12 {
            return Err("DNS packet too short");
        }

        // Check QR bit (should be 0 for query)
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_query = (flags & 0x8000) == 0;
        if !is_query {
            return Err("Not a DNS query");
        }

        // Check question count — only single-question queries are supported.
        // Real resolvers almost always send exactly 1 question. Rejecting
        // QDCOUNT != 1 prevents bypasses where an attacker places an allowed
        // domain first and a blocked domain second.
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount != 1 {
            return Err("DNS query must have exactly 1 question");
        }

        // Parse the question's domain name (starts at byte 12)
        let mut pos = 12;
        let mut domain_parts = Vec::new();

        loop {
            if pos >= payload.len() {
                return Err("DNS name truncated");
            }

            let label_len = payload[pos] as usize;

            // Check for compression pointer (not allowed in queries, fail-closed)
            if label_len & 0xC0 == 0xC0 {
                return Err("DNS compression not supported");
            }

            if label_len == 0 {
                break; // End of domain name
            }

            if label_len > 63 {
                return Err("DNS label too long");
            }

            pos += 1;
            if pos + label_len > payload.len() {
                return Err("DNS label truncated");
            }

            let label = std::str::from_utf8(&payload[pos..pos + label_len])
                .map_err(|_| "Invalid UTF-8 in DNS label")?;
            domain_parts.push(label.to_string());
            pos += label_len;

            // Safety limit
            if domain_parts.len() > 127 {
                return Err("Too many DNS labels");
            }
        }

        // pos points at the null terminator byte. After it, QTYPE (2 bytes) +
        // QCLASS (2 bytes) must be present. That's pos + 1 + 4 = pos + 5.
        if pos + 5 > payload.len() {
            return Err("DNS question truncated (missing QTYPE/QCLASS)");
        }

        if domain_parts.is_empty() {
            return Err("Empty DNS domain");
        }

        Ok(domain_parts.join("."))
    }
}

impl Default for DnsInspector {
    fn default() -> Self {
        Self::new()
    }
}

impl EvidenceParser for DnsInspector {
    fn inspect(
        &self,
        _key: &ConnectionKey,
        payload: &[u8],
        _is_first_packet: bool,
    ) -> InspectionResult {
        // Parse DNS query
        let domain = match Self::parse_dns_query(payload) {
            Ok(d) => d,
            Err(e) => {
                log::debug!("DNS parse error (fail-closed): {e}");
                return InspectionResult::Deny(format!("DNS parse error: {e}"));
            }
        };

        log::trace!("DNS query for: {domain}");

        // Check blocklist first (takes precedence)
        if self.is_domain_blocked(&domain) {
            return InspectionResult::Deny(format!("DNS domain blocked: {domain}"));
        }

        // Check allowlist
        if self.is_domain_allowed(&domain) {
            return InspectionResult::Allow;
        }

        // Not in allowlist
        if self.block_unlisted {
            InspectionResult::Deny(format!("DNS domain not in allowlist: {domain}"))
        } else {
            InspectionResult::Allow
        }
    }

    fn name(&self) -> &'static str {
        "DNS"
    }

    fn clear_state(&self) {
        // DNS inspector is stateless (per-packet)
    }

    fn connection_count(&self) -> usize {
        0 // Stateless
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

    /// Create a simple DNS query packet for testing
    fn make_dns_query(domain: &str) -> Vec<u8> {
        let mut packet = Vec::new();

        // DNS header (12 bytes)
        packet.extend_from_slice(&[
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query, recursion desired
            0x00, 0x01, // QDCOUNT: 1 question
            0x00, 0x00, // ANCOUNT: 0
            0x00, 0x00, // NSCOUNT: 0
            0x00, 0x00, // ARCOUNT: 0
        ]);

        // Question section: domain name in DNS format
        for label in domain.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0); // Null terminator

        // QTYPE (A record) and QCLASS (IN)
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);

        packet
    }

    fn dummy_key() -> ConnectionKey {
        ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(8, 8, 8, 8),
            12345,
            53,
            17, // UDP
        )
    }

    #[test]
    fn test_dns_query_parsing() {
        let packet = make_dns_query("api.openai.com");
        let domain = DnsInspector::parse_dns_query(&packet).unwrap();
        assert_eq!(domain, "api.openai.com");
    }

    #[test]
    fn test_dns_query_parsing_subdomain() {
        let packet = make_dns_query("www.example.co.uk");
        let domain = DnsInspector::parse_dns_query(&packet).unwrap();
        assert_eq!(domain, "www.example.co.uk");
    }

    #[test]
    fn test_dns_allow_exact() {
        let inspector = DnsInspector::with_allowed(&["api.openai.com"]);
        let packet = make_dns_query("api.openai.com");

        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_dns_deny_unlisted() {
        let inspector = DnsInspector::with_allowed(&["api.openai.com"]);
        let packet = make_dns_query("evil.com");

        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_dns_wildcard_allow() {
        let inspector = DnsInspector::with_allowed(&["*.github.com"]);

        // Subdomain should match
        let packet = make_dns_query("api.github.com");
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);

        // Deep subdomain should match
        let packet = make_dns_query("raw.githubusercontent.github.com");
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);

        // Base domain should also match
        let packet = make_dns_query("github.com");
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_dns_blocklist_precedence() {
        let inspector = DnsInspector::with_allowed(&["*.example.com"]);
        inspector.block_domain("evil.example.com");

        // Blocked subdomain should be denied even though parent is allowed
        let packet = make_dns_query("evil.example.com");
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(matches!(result, InspectionResult::Deny(_)));

        // Other subdomains should still be allowed
        let packet = make_dns_query("good.example.com");
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_dns_case_insensitive() {
        let inspector = DnsInspector::with_allowed(&["API.OpenAI.COM"]);
        let packet = make_dns_query("api.openai.com");

        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert_eq!(result, InspectionResult::Allow);
    }

    #[test]
    fn test_dns_malformed_rejected() {
        let inspector = DnsInspector::with_allowed(&["*"]);

        // Too short
        let result = inspector.inspect(&dummy_key(), &[0u8; 5], true);
        assert!(matches!(result, InspectionResult::Deny(_)));

        // Empty domain
        let mut packet = make_dns_query("test.com");
        packet[12] = 0; // Zero out first label length
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_dns_query_truncated_qtype() {
        // Create DNS packet with valid domain but missing QTYPE/QCLASS
        let mut packet = Vec::new();
        // DNS header (12 bytes)
        packet.extend_from_slice(&[
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags: standard query
            0x00, 0x01, // QDCOUNT: 1
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        // Question: "test.com" in DNS format
        packet.push(4);
        packet.extend_from_slice(b"test");
        packet.push(3);
        packet.extend_from_slice(b"com");
        packet.push(0); // Null terminator
        // NO QTYPE/QCLASS bytes - truncated!

        let inspector = DnsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &packet, true);
        // Should be denied due to truncated question section
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_dns_response_rejected() {
        let mut packet = make_dns_query("test.com");
        // Set QR bit to 1 (response)
        packet[2] |= 0x80;

        let inspector = DnsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }

    #[test]
    fn test_dns_multi_question_rejected() {
        // QDCOUNT=2: an attacker could place an allowed domain first and a
        // blocked domain second to bypass single-question parsing.
        let mut packet = make_dns_query("allowed.com");
        // Patch QDCOUNT from 1 to 2
        packet[4] = 0x00;
        packet[5] = 0x02;

        let inspector = DnsInspector::with_allowed(&["allowed.com"]);
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(
            matches!(result, InspectionResult::Deny(ref msg) if msg.contains("exactly 1 question")),
            "QDCOUNT=2 must be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_dns_zero_questions_rejected() {
        let mut packet = make_dns_query("test.com");
        // Patch QDCOUNT from 1 to 0
        packet[4] = 0x00;
        packet[5] = 0x00;

        let inspector = DnsInspector::with_allowed(&["test.com"]);
        let result = inspector.inspect(&dummy_key(), &packet, true);
        assert!(matches!(result, InspectionResult::Deny(_)));
    }
}
