// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Network manager for per-VM backend creation with isolation
//!
//! Provides factory for creating isolated `PolicyNetBackend` instances per VM.
//! Each VM gets:
//! - Fresh `PolicyNetBackend` wrapping a new inner backend
//! - Isolated NAT state (no port collisions)
//! - Per-VM metrics tracking
//! - Shared packet policy (updates apply to all VMs from same zygote)

use crate::{PacketNetworkPolicy, PolicyMetrics, PolicyMetricsSnapshot, PolicyNetBackend};
use amla_core::backends::NetBackend;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

// =============================================================================
// VM Network Handle
// =============================================================================

/// Handle to a VM's network state
#[derive(Clone)]
pub struct VmNetworkHandle {
    /// VM identifier
    vm_id: u64,
    /// Reference to the manager
    manager: Arc<NetworkManagerInner>,
}

impl VmNetworkHandle {
    /// Get metrics for this VM
    pub fn metrics(&self) -> Option<PolicyMetricsSnapshot> {
        self.manager
            .vm_metrics
            .read()
            .get(&self.vm_id)
            .map(|m| m.snapshot())
    }

    /// Get VM ID
    pub const fn vm_id(&self) -> u64 {
        self.vm_id
    }
}

// =============================================================================
// Network Manager
// =============================================================================

/// Manages network backends for multiple VMs spawned from a zygote
///
/// Each zygote can have one `NetworkManager`. When spawning VMs, call
/// `create_backend()` to get an isolated backend for each new VM.
pub struct NetworkManager {
    inner: Arc<NetworkManagerInner>,
}

struct NetworkManagerInner {
    /// Shared raw packet policy (applied to all backends)
    packet_policy: Arc<PacketNetworkPolicy>,
    /// Per-VM metrics
    vm_metrics: RwLock<HashMap<u64, Arc<PolicyMetrics>>>,
    /// Next VM ID counter
    next_vm_id: AtomicU64,
}

impl NetworkManager {
    /// Create a new network manager with the given raw packet policy.
    pub fn new(packet_policy: PacketNetworkPolicy) -> Self {
        Self {
            inner: Arc::new(NetworkManagerInner {
                packet_policy: Arc::new(packet_policy),
                vm_metrics: RwLock::new(HashMap::new()),
                next_vm_id: AtomicU64::new(1),
            }),
        }
    }

    /// Create a new isolated backend for a VM.
    ///
    /// The returned [`PolicyNetBackend`] is a packet admission and conntrack
    /// wrapper only. Domain, DNS, SNI, HTTP, and body policy run in the stream
    /// lifecycle before usernet dials the host.
    ///
    /// # Arguments
    /// * `inner_factory` - Factory function to create the inner backend (e.g., `UserNetBackend`)
    ///
    /// # Returns
    /// A tuple of (`PolicyNetBackend`, `VmNetworkHandle`) for network I/O and metrics access
    pub fn create_backend<I, F>(&self, inner_factory: F) -> (PolicyNetBackend<I>, VmNetworkHandle)
    where
        I: NetBackend,
        F: FnOnce() -> I,
    {
        let vm_id = self.inner.next_vm_id.fetch_add(1, Ordering::Relaxed);
        let inner = inner_factory();

        let backend = PolicyNetBackend::with_shared_packet_policy(
            inner,
            Arc::clone(&self.inner.packet_policy),
        );

        // Track metrics
        let metrics = backend.metrics();
        self.inner.vm_metrics.write().insert(vm_id, metrics);

        let handle = VmNetworkHandle {
            vm_id,
            manager: Arc::clone(&self.inner),
        };

        (backend, handle)
    }

    /// Get aggregate metrics across all VMs
    pub fn aggregate_metrics(&self) -> PolicyMetricsSnapshot {
        let mut total = PolicyMetricsSnapshot::default();
        for metrics in self.inner.vm_metrics.read().values() {
            let snap = metrics.snapshot();
            total.allowed += snap.allowed;
            total.denied += snap.denied;
            total.parse_errors += snap.parse_errors;
            total.fragmented += snap.fragmented;
            total.unknown_protocol += snap.unknown_protocol;
            total.bad_checksum += snap.bad_checksum;
            total.bytes_allowed += snap.bytes_allowed;
            total.bytes_denied += snap.bytes_denied;
        }
        total
    }

    /// Get metrics for a specific VM
    pub fn vm_metrics(&self, vm_id: u64) -> Option<PolicyMetricsSnapshot> {
        self.inner
            .vm_metrics
            .read()
            .get(&vm_id)
            .map(|m| m.snapshot())
    }

    /// Get all VM IDs managed by this manager
    pub fn vm_ids(&self) -> Vec<u64> {
        self.inner.vm_metrics.read().keys().copied().collect()
    }

    /// Number of VMs with backends from this manager
    pub fn vm_count(&self) -> usize {
        self.inner.vm_metrics.read().len()
    }

    /// Remove a VM's tracking (call when VM terminates)
    pub fn remove_vm(&self, vm_id: u64) {
        self.inner.vm_metrics.write().remove(&vm_id);
    }

    /// Get the shared raw packet policy.
    pub fn packet_policy(&self) -> &PacketNetworkPolicy {
        &self.inner.packet_policy
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NetworkPolicy, packet};
    use std::io::{self, IoSlice};

    /// Mock backend for testing
    struct MockBackend;

    impl NetBackend for MockBackend {
        type RxPacket<'a> = amla_core::backends::NoRxPacket;

        fn send(&self, _bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
            Ok(())
        }

        fn rx_packet(&self) -> io::Result<Option<Self::RxPacket<'_>>> {
            Ok(None)
        }

        fn set_nonblocking(&self, _: bool) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn test_create_isolated_backends() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(std::net::Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let manager = NetworkManager::new(policy.to_packet_policy());

        // Create two backends
        let (backend1, handle1) = manager.create_backend(|| MockBackend);
        let (_backend2, handle2) = manager.create_backend(|| MockBackend);

        // They should have different VM IDs
        assert_ne!(handle1.vm_id(), handle2.vm_id());

        // Send a packet through backend1
        let packet = packet::tests::make_tcp_packet([10, 0, 2, 15], [1, 2, 3, 4], 12345, 443);
        drop(backend1.send(&[IoSlice::new(&packet)]));

        // Backend1 should have metrics, backend2 should not
        let m1 = handle1.metrics().unwrap();
        let m2 = handle2.metrics().unwrap();
        assert_eq!(m1.allowed, 1);
        assert_eq!(m2.allowed, 0);

        // Aggregate should show total
        let agg = manager.aggregate_metrics();
        assert_eq!(agg.allowed, 1);
    }

    #[test]
    fn test_shared_policy() {
        let policy = NetworkPolicy::builder()
            .allow_host_port(std::net::Ipv4Addr::new(8, 8, 8, 8), 53)
            .build();
        let manager = NetworkManager::new(policy.to_packet_policy());

        let (backend1, _) = manager.create_backend(|| MockBackend);
        let (backend2, _) = manager.create_backend(|| MockBackend);

        // Both should use same policy
        let packet = packet::tests::make_udp_packet([10, 0, 2, 15], [8, 8, 8, 8], 12345, 53);

        drop(backend1.send(&[IoSlice::new(&packet)]));
        drop(backend2.send(&[IoSlice::new(&packet)]));

        // Both allowed by same policy
        let agg = manager.aggregate_metrics();
        assert_eq!(agg.allowed, 2);
    }

    #[test]
    fn test_vm_count() {
        let manager = NetworkManager::new(NetworkPolicy::builder().build().to_packet_policy());

        assert_eq!(manager.vm_count(), 0);

        let (_, h1) = manager.create_backend(|| MockBackend);
        assert_eq!(manager.vm_count(), 1);

        let (_, h2) = manager.create_backend(|| MockBackend);
        assert_eq!(manager.vm_count(), 2);

        manager.remove_vm(h1.vm_id());
        assert_eq!(manager.vm_count(), 1);

        manager.remove_vm(h2.vm_id());
        assert_eq!(manager.vm_count(), 0);
    }

    #[test]
    fn test_vm_metrics_nonexistent() {
        let manager = NetworkManager::new(NetworkPolicy::builder().build().to_packet_policy());

        // No VM with ID 999 exists
        let metrics = manager.vm_metrics(999);
        assert!(metrics.is_none());
    }

    #[test]
    fn test_vm_ids() {
        let manager = NetworkManager::new(NetworkPolicy::builder().build().to_packet_policy());

        assert!(manager.vm_ids().is_empty());

        let (_, h1) = manager.create_backend(|| MockBackend);
        let (_, h2) = manager.create_backend(|| MockBackend);

        let mut ids = manager.vm_ids();
        ids.sort_unstable();
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&h1.vm_id()));
        assert!(ids.contains(&h2.vm_id()));
    }

    #[test]
    fn test_packet_policy_accessor() {
        let policy = NetworkPolicy::builder()
            .name("test-policy")
            .allow_host_port(std::net::Ipv4Addr::new(1, 2, 3, 4), 443)
            .build();
        let manager = NetworkManager::new(policy.to_packet_policy());

        let p = manager.packet_policy();
        assert_eq!(p.name, Some("test-policy".to_string()));
        assert!(!p.rules.is_empty());
    }
}
