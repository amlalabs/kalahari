// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Internal protocol parser helpers.
//!
//! The packet backend does not call these helpers. Stream lifecycle policy uses
//! [`crate::Evidence`] and [`crate::EvidencePolicyDecision`]; these modules keep
//! protocol parser state and tests close to policy-net until the parser APIs are
//! fully normalized around evidence emission.

#[cfg(test)]
pub mod dns;
#[cfg(test)]
pub mod http;
#[cfg(test)]
pub mod sticky_lru;
#[cfg(test)]
pub mod tls;

#[cfg(test)]
use std::collections::HashSet;
use std::net::IpAddr;

// =============================================================================
// Wildcard Matching
// =============================================================================

/// Check if a name matches any pattern in a set (exact or wildcard).
///
/// Wildcard patterns like `*.example.com` match the bare apex
/// `example.com` AND any subdomain at any depth — `sub.example.com`,
/// `a.b.c.example.com`, and so on. This is the conventional allowlist
/// semantic used by DNS wildcards and most firewalls. Callers who want
/// single-label-only wildcards must implement that separately.
///
/// The name is compared case-insensitively.
///
/// This is the shared matching logic used by the DNS and TLS inspectors.
#[cfg(test)]
pub fn matches_any_pattern(name: &str, patterns: &HashSet<String>) -> bool {
    let name_lower = name.to_lowercase();

    // Check exact match
    if patterns.contains(&name_lower) {
        return true;
    }

    // Check wildcard matches. Only accept `*` (match-all) and `*.domain`
    // (match any name whose domain is `domain` or a subdomain of it). A bare
    // `*com` pattern — which previously matched `notfoo.com` because
    // `ends_with("com")` ignored the domain boundary — is rejected.
    for pattern in patterns {
        let Some(suffix) = pattern.strip_prefix('*') else {
            continue;
        };
        if suffix.is_empty() {
            return true;
        }
        let Some(bare) = suffix.strip_prefix('.') else {
            log::warn!("ignoring malformed wildcard pattern {pattern:?}; use `*.domain` form");
            continue;
        };
        // `*.example.com` matches `foo.example.com` (via ends_with with the
        // leading dot) and `example.com` itself (via exact compare to bare).
        if name_lower.ends_with(suffix) || name_lower == bare {
            return true;
        }
    }

    false
}

// =============================================================================
// Inspection Result
// =============================================================================

/// Result of protocol inspection
#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum InspectionResult {
    /// Allow the connection/packet
    Allow,
    /// Deny with reason
    Deny(String),
    /// Need more data to make a decision (for multi-packet protocols)
    NeedMoreData,
}

// =============================================================================
// Connection Key
// =============================================================================

/// Unique identifier for a connection (for stateful tracking)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8, // TCP=6, UDP=17
}

impl ConnectionKey {
    /// Create a new connection key
    pub fn new(
        src_ip: impl Into<IpAddr>,
        dst_ip: impl Into<IpAddr>,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self {
            src_ip: src_ip.into(),
            dst_ip: dst_ip.into(),
            src_port,
            dst_port,
            protocol,
        }
    }

    /// Create the reverse key (for response packets)
    #[must_use]
    pub const fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }
}

// =============================================================================
// Evidence Parser Trait
// =============================================================================

/// Trait for crate-internal protocol parser test adapters.
#[cfg(test)]
#[allow(dead_code)]
pub trait EvidenceParser: Send + Sync {
    /// Parse a packet/connection payload.
    ///
    /// # Arguments
    /// * `key` - Connection identifier
    /// * `payload` - Protocol payload (after IP/TCP/UDP headers)
    /// * `is_first_packet` - Whether this is the first packet of the connection
    ///
    /// # Returns
    /// * `InspectionResult::Allow` - Packet/connection is allowed
    /// * `InspectionResult::Deny(reason)` - Packet/connection is denied
    /// * `InspectionResult::NeedMoreData` - Need more packets to decide
    fn inspect(
        &self,
        key: &ConnectionKey,
        payload: &[u8],
        is_first_packet: bool,
    ) -> InspectionResult;

    /// Get the name of this inspector (for logging)
    fn name(&self) -> &'static str;

    /// Clear all connection state (for cleanup)
    fn clear_state(&self);

    /// Get current number of tracked connections
    fn connection_count(&self) -> usize;
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_connection_key() {
        let key = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            443,
            6, // TCP
        );

        let reverse = key.reverse();
        assert_eq!(reverse.src_ip, IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert_eq!(reverse.dst_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 2, 15)));
        assert_eq!(reverse.src_port, 443);
        assert_eq!(reverse.dst_port, 12345);
    }

    #[test]
    fn test_matches_any_pattern_exact() {
        let patterns: HashSet<String> = ["example.com", "api.openai.com"]
            .iter()
            .map(ToString::to_string)
            .collect();
        assert!(matches_any_pattern("example.com", &patterns));
        assert!(matches_any_pattern("api.openai.com", &patterns));
        assert!(!matches_any_pattern("evil.com", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_wildcard() {
        let patterns: HashSet<String> = std::iter::once("*.github.com".to_string()).collect();
        // Subdomain matches
        assert!(matches_any_pattern("api.github.com", &patterns));
        assert!(matches_any_pattern(
            "raw.githubusercontent.github.com",
            &patterns
        ));
        // Base domain matches (wildcard strips leading dot)
        assert!(matches_any_pattern("github.com", &patterns));
        // Non-matching
        assert!(!matches_any_pattern("evil.com", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_wildcard_deep_subdomain() {
        let patterns: HashSet<String> = std::iter::once("*.example.com".to_string()).collect();
        // Documented: wildcard matches subdomains at arbitrary depth.
        assert!(matches_any_pattern("a.b.c.example.com", &patterns));
        assert!(matches_any_pattern("x.y.example.com", &patterns));
        assert!(matches_any_pattern("sub.example.com", &patterns));
        assert!(matches_any_pattern("example.com", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_case_insensitive() {
        let patterns: HashSet<String> = std::iter::once("api.openai.com".to_string()).collect();
        assert!(matches_any_pattern("API.OPENAI.COM", &patterns));
        assert!(matches_any_pattern("Api.OpenAI.Com", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_empty_set() {
        let patterns: HashSet<String> = HashSet::new();
        assert!(!matches_any_pattern("anything.com", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_bare_star() {
        let patterns: HashSet<String> = std::iter::once("*".to_string()).collect();
        assert!(matches_any_pattern("anything.com", &patterns));
        assert!(matches_any_pattern("sub.domain.example.org", &patterns));
    }

    #[test]
    fn test_matches_any_pattern_wildcard_no_dot() {
        // Pattern "*com" is malformed (no `.` after `*`) — must be rejected
        // outright so that `*com` does NOT match `notfoo.com` via plain
        // suffix match. Use `*.com` for that intent.
        let patterns: HashSet<String> = std::iter::once("*com".to_string()).collect();
        assert!(!matches_any_pattern("example.com", &patterns));
        assert!(!matches_any_pattern("co", &patterns));
        // Sanity: the proper form does match.
        let proper: HashSet<String> = std::iter::once("*.com".to_string()).collect();
        assert!(matches_any_pattern("example.com", &proper));
        assert!(matches_any_pattern("com", &proper)); // bare-suffix exact match
        assert!(!matches_any_pattern("notfoocom", &proper));
    }

    #[test]
    fn test_connection_key_hash() {
        use std::collections::HashSet;

        let key1 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            443,
            6,
        );

        let key2 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12345,
            443,
            6,
        );

        let key3 = ConnectionKey::new(
            Ipv4Addr::new(10, 0, 2, 15),
            Ipv4Addr::new(1, 2, 3, 4),
            12346, // Different port
            443,
            6,
        );

        let mut set = HashSet::new();
        set.insert(key1);

        assert!(set.contains(&key2)); // Same key
        assert!(!set.contains(&key3)); // Different key
    }
}
