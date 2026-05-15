// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::time::Instant;
use std::collections::VecDeque;

use crate::{MAX_QUEUE_SIZE, UserNetError, UserNetResult};

/// Virtual network device that bridges between virtio-net and smoltcp
pub struct VirtualDevice {
    /// Packets from guest (to be processed by smoltcp)
    pub(crate) rx_queue: VecDeque<Vec<u8>>,

    /// Packets to guest (from smoltcp)
    pub(crate) tx_queue: VecDeque<Vec<u8>>,

    /// MTU
    mtu: usize,

    /// Counter for dropped tx packets (queue full)
    pub(crate) dropped_tx_count: u64,
}

impl VirtualDevice {
    pub(crate) fn new(mtu: usize) -> Self {
        Self {
            rx_queue: VecDeque::with_capacity(MAX_QUEUE_SIZE),
            tx_queue: VecDeque::with_capacity(MAX_QUEUE_SIZE),
            mtu,
            dropped_tx_count: 0,
        }
    }

    /// Queue a packet from the guest for processing
    pub(crate) fn queue_from_guest(&mut self, packet: Vec<u8>) -> UserNetResult<()> {
        if self.rx_queue.len() >= MAX_QUEUE_SIZE {
            return Err(UserNetError::QueueFull);
        }
        self.rx_queue.push_back(packet);
        Ok(())
    }

    /// Get a packet to send to the guest
    pub(crate) fn dequeue_to_guest(&mut self) -> Option<Vec<u8>> {
        self.tx_queue.pop_front()
    }

    /// Return an uncommitted guest-bound packet to the front of the queue.
    pub(crate) fn requeue_to_guest_front(&mut self, packet: Vec<u8>) {
        self.tx_queue.push_front(packet);
    }

    /// Check if there are packets ready for the guest
    pub(crate) fn has_packets_for_guest(&self) -> bool {
        !self.tx_queue.is_empty()
    }

    /// Check if the guest transmit queue has room for another packet.
    pub(crate) fn can_enqueue_to_guest(&self) -> bool {
        self.tx_queue.len() < MAX_QUEUE_SIZE
    }

    /// Push a packet to the `tx_queue` if under `MAX_QUEUE_SIZE`.
    /// Returns true if enqueued, false if dropped.
    pub(crate) fn enqueue_to_guest(&mut self, packet: Vec<u8>) -> bool {
        if self.can_enqueue_to_guest() {
            self.tx_queue.push_back(packet);
            true
        } else {
            self.dropped_tx_count += 1;
            if self.dropped_tx_count % 1000 == 1 {
                log::warn!(
                    "usernet: tx_queue full, dropped {} packets to guest so far",
                    self.dropped_tx_count
                );
            }
            false
        }
    }
}

/// RX token for smoltcp
pub struct VirtualRxToken {
    buffer: Vec<u8>,
}

impl RxToken for VirtualRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

/// TX token for smoltcp
pub struct VirtualTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    dropped_tx_count: &'a mut u64,
}

impl TxToken for VirtualTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = vec![0u8; len];
        let result = f(&mut buffer);
        if self.queue.len() < MAX_QUEUE_SIZE {
            self.queue.push_back(buffer);
        } else {
            *self.dropped_tx_count += 1;
            if *self.dropped_tx_count % 1000 == 1 {
                log::warn!(
                    "usernet: tx_queue full, dropped {} packets to guest so far",
                    self.dropped_tx_count
                );
            }
        }
        result
    }
}

impl Device for VirtualDevice {
    type RxToken<'a> = VirtualRxToken;
    type TxToken<'a> = VirtualTxToken<'a>;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        if let Some(buffer) = self.rx_queue.pop_front() {
            Some((
                VirtualRxToken { buffer },
                VirtualTxToken {
                    queue: &mut self.tx_queue,
                    dropped_tx_count: &mut self.dropped_tx_count,
                },
            ))
        } else {
            None
        }
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.tx_queue.len() < MAX_QUEUE_SIZE {
            Some(VirtualTxToken {
                queue: &mut self.tx_queue,
                dropped_tx_count: &mut self.dropped_tx_count,
            })
        } else {
            None
        }
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = self.mtu;
        caps.max_burst_size = Some(1);
        caps
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ── queue_from_guest / dequeue_to_guest ───────────────────────────

    #[test]
    fn dequeue_fifo_order() {
        let mut dev = VirtualDevice::new(1500);
        dev.queue_from_guest(vec![1, 2]).unwrap();
        dev.queue_from_guest(vec![3, 4]).unwrap();
        dev.queue_from_guest(vec![5, 6]).unwrap();
        assert_eq!(dev.dequeue_to_guest(), None); // dequeue is from tx_queue
        // queue_from_guest puts into rx_queue, not tx_queue
        assert_eq!(dev.rx_queue.pop_front().unwrap(), vec![1, 2]);
        assert_eq!(dev.rx_queue.pop_front().unwrap(), vec![3, 4]);
        assert_eq!(dev.rx_queue.pop_front().unwrap(), vec![5, 6]);
    }

    #[test]
    fn queue_from_guest_rejects_at_capacity() {
        let mut dev = VirtualDevice::new(1500);
        for _ in 0..MAX_QUEUE_SIZE {
            dev.queue_from_guest(vec![0xAA]).unwrap();
        }
        assert!(dev.queue_from_guest(vec![0xFF]).is_err());
        assert_eq!(dev.rx_queue.len(), MAX_QUEUE_SIZE);
    }

    #[test]
    fn queue_from_guest_accepts_after_drain() {
        let mut dev = VirtualDevice::new(1500);
        for _ in 0..MAX_QUEUE_SIZE {
            dev.queue_from_guest(vec![0xAA]).unwrap();
        }
        // Full — drain one
        dev.rx_queue.pop_front();
        // Should accept again
        dev.queue_from_guest(vec![0xAB]).unwrap();
        assert_eq!(dev.rx_queue.len(), MAX_QUEUE_SIZE);
    }

    // ── enqueue_to_guest / dequeue_to_guest ───────────────────────────

    #[test]
    fn enqueue_dequeue_fifo() {
        let mut dev = VirtualDevice::new(1500);
        assert!(dev.enqueue_to_guest(vec![10, 20]));
        assert!(dev.enqueue_to_guest(vec![30, 40]));
        assert_eq!(dev.dequeue_to_guest(), Some(vec![10, 20]));
        assert_eq!(dev.dequeue_to_guest(), Some(vec![30, 40]));
        assert_eq!(dev.dequeue_to_guest(), None);
    }

    #[test]
    fn has_packets_for_guest_reflects_tx_queue() {
        let mut dev = VirtualDevice::new(1500);
        assert!(!dev.has_packets_for_guest());
        dev.enqueue_to_guest(vec![1]);
        assert!(dev.has_packets_for_guest());
        dev.dequeue_to_guest();
        assert!(!dev.has_packets_for_guest());
    }

    #[test]
    fn enqueue_drops_increment_counter() {
        let mut dev = VirtualDevice::new(1500);
        for _ in 0..MAX_QUEUE_SIZE {
            assert!(dev.enqueue_to_guest(vec![0]));
        }
        assert_eq!(dev.dropped_tx_count, 0);

        // First drop
        assert!(!dev.enqueue_to_guest(vec![0]));
        assert_eq!(dev.dropped_tx_count, 1);

        // More drops
        assert!(!dev.enqueue_to_guest(vec![0]));
        assert!(!dev.enqueue_to_guest(vec![0]));
        assert_eq!(dev.dropped_tx_count, 3);

        // Queue length unchanged
        assert_eq!(dev.tx_queue.len(), MAX_QUEUE_SIZE);
    }

    // ── smoltcp Device trait ──────────────────────────────────────────

    #[test]
    fn receive_returns_none_when_empty() {
        let mut dev = VirtualDevice::new(1500);
        assert!(dev.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn receive_returns_tokens_and_consumes_rx() {
        let mut dev = VirtualDevice::new(1500);
        dev.rx_queue.push_back(vec![0xDE, 0xAD]);

        let (rx, tx) = dev.receive(Instant::from_millis(0)).unwrap();

        // RxToken should yield the queued packet
        let data = rx.consume(<[u8]>::to_vec);
        assert_eq!(data, vec![0xDE, 0xAD]);

        // TxToken should enqueue into tx_queue
        tx.consume(4, |buf| {
            buf.copy_from_slice(&[1, 2, 3, 4]);
        });
        assert_eq!(dev.tx_queue.len(), 1);
        assert_eq!(dev.tx_queue[0], vec![1, 2, 3, 4]);
    }

    #[test]
    fn receive_drains_rx_queue_in_order() {
        let mut dev = VirtualDevice::new(1500);
        dev.rx_queue.push_back(vec![1]);
        dev.rx_queue.push_back(vec![2]);

        let (rx1, _tx1) = dev.receive(Instant::from_millis(0)).unwrap();
        assert_eq!(rx1.consume(|b| b[0]), 1);

        let (rx2, _tx2) = dev.receive(Instant::from_millis(0)).unwrap();
        assert_eq!(rx2.consume(|b| b[0]), 2);

        assert!(dev.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn transmit_returns_token_when_space() {
        let mut dev = VirtualDevice::new(1500);
        let tx = dev.transmit(Instant::from_millis(0)).unwrap();
        tx.consume(3, |buf| {
            buf[0] = 0xAA;
            buf[1] = 0xBB;
            buf[2] = 0xCC;
        });
        assert_eq!(dev.tx_queue.pop_front().unwrap(), vec![0xAA, 0xBB, 0xCC]);
    }

    #[test]
    fn transmit_returns_none_when_full() {
        let mut dev = VirtualDevice::new(1500);
        for _ in 0..MAX_QUEUE_SIZE {
            dev.tx_queue.push_back(vec![0]);
        }
        assert!(dev.transmit(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn tx_token_drops_packet_when_queue_full() {
        let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
        for _ in 0..MAX_QUEUE_SIZE {
            queue.push_back(vec![0]);
        }
        let mut drop_count: u64 = 0;
        let tx = VirtualTxToken {
            queue: &mut queue,
            dropped_tx_count: &mut drop_count,
        };
        // consume should still return the result, but the packet is dropped
        let result = tx.consume(10, |buf| {
            buf[0] = 42;
            buf[0]
        });
        assert_eq!(result, 42);
        // Queue length unchanged
        assert_eq!(queue.len(), MAX_QUEUE_SIZE);
        // Drop counter incremented
        assert_eq!(drop_count, 1);
    }

    // ── capabilities ──────────────────────────────────────────────────

    #[test]
    fn capabilities_reflect_mtu() {
        let dev = VirtualDevice::new(9000); // jumbo frame MTU
        let caps = dev.capabilities();
        assert_eq!(caps.medium, Medium::Ethernet);
        assert_eq!(caps.max_transmission_unit, 9000);
        assert_eq!(caps.max_burst_size, Some(1));
    }

    #[test]
    fn new_device_starts_clean() {
        let dev = VirtualDevice::new(1500);
        assert!(dev.rx_queue.is_empty());
        assert!(dev.tx_queue.is_empty());
        assert_eq!(dev.dropped_tx_count, 0);
    }
}
