// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Stateful connection tracking for inbound packet filtering
//!
//! Tracks outbound connections so that inbound packets can be verified as
//! responses to allowed outbound traffic. Follows a **fail-closed** model:
//! inbound packets without a matching outbound entry are denied.

use std::collections::HashMap;
use std::time::Instant;

use crate::ConnectionKey;

// =============================================================================
// TCP Flag Constants
// =============================================================================

pub const TCP_FIN: u8 = 0x01;
pub const TCP_SYN: u8 = 0x02;
pub const TCP_RST: u8 = 0x04;
pub const TCP_ACK: u8 = 0x10;

// =============================================================================
// TCP State
// =============================================================================

/// TCP connection state for the stateful firewall
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// SYN sent, waiting for SYN-ACK
    SynSent,
    /// Connection established (SYN-ACK received or non-SYN packet seen)
    Established,
    /// FIN sent, connection closing
    FinWait,
}

// =============================================================================
// Connection State
// =============================================================================

/// Per-connection tracking state
#[derive(Debug, Clone)]
pub struct ConnState {
    /// TCP state machine (None for UDP)
    pub tcp_state: Option<TcpState>,
    /// Last packet seen (for timeout eviction)
    pub last_seen: Instant,
}

// =============================================================================
// Connection Table
// =============================================================================

/// Stateful connection tracking table
///
/// Records outbound connections and checks whether inbound packets are
/// valid responses. Entries are evicted on timeout or when the table
/// reaches its capacity bound.
pub struct ConnectionTable {
    entries: HashMap<ConnectionKey, ConnState>,
    pub(crate) max_entries: usize,
    /// Counter for periodic eviction
    packet_counter: u64,
    eviction_interval: u64,
    /// Cumulative count of outbound flows dropped because the table was full
    /// even after an eviction pass. Exposed via [`table_full_drops`] so that
    /// the VMM can surface the pressure in metrics / logs — a non-zero,
    /// growing value here means policy-net is dropping new flows silently
    /// from the guest's perspective.
    ///
    /// [`table_full_drops`]: ConnectionTable::table_full_drops
    table_full_drops: u64,
    // Timeout configuration
    pub(crate) udp_timeout_secs: u64,
    tcp_established_timeout_secs: u64,
    tcp_fin_timeout_secs: u64,
}

impl Default for ConnectionTable {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTable {
    /// Maximum tracked connections before rejecting new entries
    const DEFAULT_MAX_ENTRIES: usize = 65_536;
    /// Evict expired entries every N packets
    const DEFAULT_EVICTION_INTERVAL: u64 = 10_000;

    /// Create a new connection table with default settings.
    ///
    /// Defaults: UDP 60s, TCP established 300s, TCP FIN 30s, max 65536 entries.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: Self::DEFAULT_MAX_ENTRIES,
            packet_counter: 0,
            eviction_interval: Self::DEFAULT_EVICTION_INTERVAL,
            table_full_drops: 0,
            udp_timeout_secs: 60,
            tcp_established_timeout_secs: 300,
            tcp_fin_timeout_secs: 30,
        }
    }

    /// Cumulative count of outbound flows dropped because the table was full
    /// even after an eviction pass. A monotonically-increasing value here
    /// indicates `max_entries` is undersized for the offered load — new
    /// flows are being silently dropped from the guest's perspective.
    #[must_use]
    pub const fn table_full_drops(&self) -> u64 {
        self.table_full_drops
    }

    /// Record an allowed outbound connection.
    ///
    /// For TCP, tracks SYN/FIN/RST state transitions.
    /// For UDP, creates or refreshes the entry timestamp.
    /// Entries beyond `max_entries` are silently dropped.
    pub fn record_outbound(&mut self, key: ConnectionKey, tcp_flags: Option<u8>) {
        // Periodic eviction
        self.packet_counter += 1;
        if self.packet_counter.is_multiple_of(self.eviction_interval) {
            self.evict_expired();
        }

        if let Some(existing) = self.entries.get_mut(&key) {
            // Update existing entry
            existing.last_seen = Instant::now();
            if let (Some(flags), Some(state)) = (tcp_flags, &mut existing.tcp_state) {
                if flags & TCP_RST != 0 {
                    // RST → transition to FinWait for a short hold-down period
                    // rather than immediate removal. This ensures in-flight
                    // inbound packets are still accepted, and prevents the
                    // 5-tuple from being instantly reused without hold-down.
                    *state = TcpState::FinWait;
                    return;
                }
                if flags & TCP_FIN != 0 {
                    *state = TcpState::FinWait;
                } else if *state == TcpState::SynSent && flags & TCP_ACK != 0 {
                    *state = TcpState::Established;
                }
            }
            return;
        }

        // New entry — check capacity (try eviction before rejecting)
        if self.entries.len() >= self.max_entries {
            self.evict_expired();
            if self.entries.len() >= self.max_entries {
                self.table_full_drops = self.table_full_drops.saturating_add(1);
                log::warn!(
                    "Connection table full ({} entries, cumulative drops={}), dropping new entry",
                    self.entries.len(),
                    self.table_full_drops,
                );
                return;
            }
        }

        let now = Instant::now();
        let tcp_state = tcp_flags.map(|flags| {
            if flags & TCP_SYN != 0 {
                TcpState::SynSent
            } else {
                // Mid-stream (e.g. retransmit or recovery) — treat as established
                TcpState::Established
            }
        });

        self.entries.insert(
            key,
            ConnState {
                tcp_state,
                last_seen: now,
            },
        );
    }

    /// Check whether an inbound packet has a matching outbound connection.
    ///
    /// The caller should pass the *inbound* packet's key (src=remote, dst=guest).
    /// This method reverses it to look up the outbound entry.
    /// Also refreshes the timestamp on match.
    pub fn allows_inbound(&mut self, inbound_key: &ConnectionKey) -> bool {
        let outbound_key = inbound_key.reverse();
        let (udp_t, tcp_est_t, tcp_fin_t) = (
            self.udp_timeout_secs,
            self.tcp_established_timeout_secs,
            self.tcp_fin_timeout_secs,
        );
        if let Some(entry) = self.entries.get_mut(&outbound_key) {
            let timeout = match entry.tcp_state {
                None => udp_t,
                Some(TcpState::SynSent | TcpState::Established) => tcp_est_t,
                Some(TcpState::FinWait) => tcp_fin_t,
            };
            if entry.last_seen.elapsed().as_secs() > timeout {
                self.entries.remove(&outbound_key);
                return false;
            }
            entry.last_seen = Instant::now();
            true
        } else {
            false
        }
    }

    /// Remove all entries whose last-seen time exceeds their timeout.
    pub fn evict_expired(&mut self) {
        let udp_timeout = self.udp_timeout_secs;
        let tcp_est_timeout = self.tcp_established_timeout_secs;
        let tcp_fin_timeout = self.tcp_fin_timeout_secs;

        self.entries.retain(|_, entry| {
            let elapsed = entry.last_seen.elapsed().as_secs();
            let timeout = match entry.tcp_state {
                None => udp_timeout,
                Some(TcpState::SynSent | TcpState::Established) => tcp_est_timeout,
                Some(TcpState::FinWait) => tcp_fin_timeout,
            };
            elapsed <= timeout
        });
    }

    /// Number of tracked connections.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Backdate all entries by the given duration (for testing timeout eviction).
    #[cfg(test)]
    pub(crate) fn backdate_all(&mut self, duration: std::time::Duration) {
        for entry in self.entries.values_mut() {
            entry.last_seen -= duration;
        }
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn tcp_key(src_port: u16, dst_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            src_port,
            dst_port,
            6, // TCP
        )
    }

    fn udp_key(src_port: u16, dst_port: u16) -> ConnectionKey {
        ConnectionKey::new(
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(8, 8, 8, 8),
            src_port,
            dst_port,
            17, // UDP
        )
    }

    #[test]
    fn test_record_and_allow_tcp() {
        let mut table = ConnectionTable::new();
        let key = tcp_key(12345, 443);

        // No entry yet — inbound denied
        let inbound = key.reverse();
        assert!(!table.allows_inbound(&inbound));

        // Record outbound SYN
        table.record_outbound(key, Some(TCP_SYN));
        assert_eq!(table.len(), 1);

        // Inbound from server allowed
        assert!(table.allows_inbound(&inbound));
    }

    #[test]
    fn test_record_and_allow_udp() {
        let mut table = ConnectionTable::new();
        let key = udp_key(54321, 53);

        table.record_outbound(key, None);
        assert_eq!(table.len(), 1);

        let inbound = key.reverse();
        assert!(table.allows_inbound(&inbound));
    }

    #[test]
    fn test_inbound_denied_without_outbound() {
        let mut table = ConnectionTable::new();
        let inbound = tcp_key(443, 12345).reverse();
        assert!(!table.allows_inbound(&inbound));
    }

    #[test]
    fn test_tcp_state_transitions() {
        let mut table = ConnectionTable::new();
        let key = tcp_key(12345, 80);

        // SYN
        table.record_outbound(key, Some(TCP_SYN));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::SynSent));

        // ACK → Established
        table.record_outbound(key, Some(TCP_ACK));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::Established));

        // FIN → FinWait
        table.record_outbound(key, Some(TCP_FIN | TCP_ACK));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::FinWait));
    }

    #[test]
    fn test_tcp_rst_transitions_to_fin_wait() {
        let mut table = ConnectionTable::new();
        let key = tcp_key(12345, 80);

        table.record_outbound(key, Some(TCP_SYN));
        assert_eq!(table.len(), 1);

        // RST transitions to FinWait (short hold-down) instead of removing
        table.record_outbound(key, Some(TCP_RST));
        assert_eq!(table.len(), 1);
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::FinWait));
    }

    #[test]
    fn test_max_entries_cap() {
        let mut table = ConnectionTable::new();
        table.max_entries = 2;

        let k1 = udp_key(1, 53);
        let k2 = udp_key(2, 53);
        let k3 = udp_key(3, 53);

        table.record_outbound(k1, None);
        table.record_outbound(k2, None);
        assert_eq!(table.table_full_drops(), 0);
        table.record_outbound(k3, None); // should be dropped

        assert_eq!(table.len(), 2);
        assert_eq!(table.table_full_drops(), 1);
        assert!(!table.allows_inbound(&k3.reverse()));
    }

    #[test]
    fn test_evict_expired() {
        let mut table = ConnectionTable::new();
        table.udp_timeout_secs = 0; // immediate timeout

        let key = udp_key(54321, 53);
        table.record_outbound(key, None);
        assert_eq!(table.len(), 1);

        // Force the entry to be expired
        table.entries.get_mut(&key).unwrap().last_seen = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        table.evict_expired();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_allows_inbound_evicts_expired() {
        let mut table = ConnectionTable::new();
        table.udp_timeout_secs = 0;

        let key = udp_key(54321, 53);
        table.record_outbound(key, None);

        // Backdate the entry
        table.entries.get_mut(&key).unwrap().last_seen = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();

        // allows_inbound should reject expired entries
        assert!(!table.allows_inbound(&key.reverse()));
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn test_mid_stream_tcp_treated_as_established() {
        let mut table = ConnectionTable::new();
        let key = tcp_key(12345, 80);

        // Non-SYN TCP (e.g. retransmit) → Established
        table.record_outbound(key, Some(TCP_ACK));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::Established));
    }

    #[test]
    fn test_default_is_new() {
        let table = ConnectionTable::default();
        assert!(table.is_empty());
    }

    #[test]
    fn test_periodic_eviction_triggers() {
        let mut table = ConnectionTable::new();
        table.eviction_interval = 3; // trigger every 3 packets
        table.udp_timeout_secs = 0; // immediate timeout

        // Insert one entry, then backdate it
        let stale = udp_key(1, 53);
        table.record_outbound(stale, None);
        table.entries.get_mut(&stale).unwrap().last_seen = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();

        // packet_counter is 1 after the first insert. Send 2 more to reach 3.
        let k2 = udp_key(2, 53);
        table.record_outbound(k2, None); // counter=2, no eviction
        assert_eq!(table.len(), 2); // stale still present

        let k3 = udp_key(3, 53);
        table.record_outbound(k3, None); // counter=3, triggers evict_expired()
        // stale entry should have been evicted
        assert!(!table.allows_inbound(&stale.reverse()));
    }

    #[test]
    fn test_tcp_fin_wait_timeout_shorter() {
        let mut table = ConnectionTable::new();
        table.tcp_fin_timeout_secs = 0; // immediate FIN timeout
        table.tcp_established_timeout_secs = 300; // long established timeout

        let key = tcp_key(12345, 443);
        table.record_outbound(key, Some(TCP_SYN));
        table.record_outbound(key, Some(TCP_ACK)); // Established
        table.record_outbound(key, Some(TCP_FIN | TCP_ACK)); // FinWait

        // Backdate entry
        table.entries.get_mut(&key).unwrap().last_seen = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();

        // FinWait timeout is 0, so should be evicted
        let inbound = key.reverse();
        assert!(!table.allows_inbound(&inbound));
    }

    #[test]
    fn test_evict_expired_mixed_tcp_states() {
        let mut table = ConnectionTable::new();
        table.tcp_established_timeout_secs = 0;
        table.tcp_fin_timeout_secs = 0;
        table.udp_timeout_secs = 300; // keep UDP alive

        let tcp_key_val = tcp_key(1, 80);
        let udp_key_val = udp_key(2, 53);

        table.record_outbound(tcp_key_val, Some(TCP_SYN));
        table.record_outbound(udp_key_val, None);
        assert_eq!(table.len(), 2);

        // Backdate both
        for entry in table.entries.values_mut() {
            entry.last_seen -= std::time::Duration::from_secs(1);
        }

        table.evict_expired();
        // TCP expired (timeout=0), UDP still alive (timeout=300)
        assert_eq!(table.len(), 1);
        assert!(table.allows_inbound(&udp_key_val.reverse()));
        assert!(!table.entries.contains_key(&tcp_key_val));
    }

    #[test]
    fn test_allows_inbound_fin_wait_path() {
        // Exercise the FinWait arm in allows_inbound timeout selection
        let mut table = ConnectionTable::new();
        table.tcp_fin_timeout_secs = 300; // long timeout

        let key = tcp_key(12345, 443);
        table.record_outbound(key, Some(TCP_SYN));
        table.record_outbound(key, Some(TCP_FIN | TCP_ACK));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::FinWait));

        // Should still be allowed (timeout is 300s)
        let inbound = key.reverse();
        assert!(table.allows_inbound(&inbound));
    }

    #[test]
    fn test_evict_expired_fin_wait() {
        let mut table = ConnectionTable::new();
        table.tcp_fin_timeout_secs = 0; // immediate FIN timeout

        let key = tcp_key(12345, 443);
        table.record_outbound(key, Some(TCP_SYN));
        table.record_outbound(key, Some(TCP_FIN | TCP_ACK));
        assert_eq!(table.entries[&key].tcp_state, Some(TcpState::FinWait));

        // Backdate and evict
        table.entries.get_mut(&key).unwrap().last_seen = Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .unwrap();
        table.evict_expired();
        assert_eq!(table.len(), 0, "FinWait entry should be evicted");
    }

    #[test]
    fn test_record_outbound_refreshes_timestamp() {
        let mut table = ConnectionTable::new();
        let key = udp_key(54321, 53);

        table.record_outbound(key, None);
        let first_seen = table.entries[&key].last_seen;

        // Small delay, then re-record
        std::thread::sleep(std::time::Duration::from_millis(1));
        table.record_outbound(key, None);
        let second_seen = table.entries[&key].last_seen;

        assert!(second_seen > first_seen);
    }

    #[test]
    fn test_table_full_evicts_before_rejecting() {
        let mut table = ConnectionTable::new();
        table.max_entries = 2;
        table.udp_timeout_secs = 0; // immediate timeout

        let k1 = udp_key(1, 53);
        let k2 = udp_key(2, 53);
        table.record_outbound(k1, None);
        table.record_outbound(k2, None);
        assert_eq!(table.len(), 2);

        // Backdate both so they're expired
        for entry in table.entries.values_mut() {
            entry.last_seen -= std::time::Duration::from_secs(1);
        }

        // Third entry should succeed after eviction of expired entries
        let k3 = udp_key(3, 53);
        table.record_outbound(k3, None);
        assert_eq!(table.len(), 1); // only k3 remains
        assert!(table.allows_inbound(&k3.reverse()));
    }

    #[test]
    fn test_tcp_rst_allows_inbound_during_holddown() {
        let mut table = ConnectionTable::new();
        table.tcp_fin_timeout_secs = 30; // hold-down period

        let key = tcp_key(12345, 80);
        table.record_outbound(key, Some(TCP_SYN));
        table.record_outbound(key, Some(TCP_RST));

        // Entry is in FinWait, not removed — inbound still accepted
        let inbound = key.reverse();
        assert!(table.allows_inbound(&inbound));
    }
}
