// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! MMIO transport conformance tests.

#[cfg(not(target_arch = "aarch64"))]
use crate::device_gsi;
use crate::transport::{
    CONFIG_GENERATION, CONFIG_SPACE, DEVICE_FEATURES, DEVICE_FEATURES_SEL, DEVICE_ID,
    DRIVER_FEATURES, DRIVER_FEATURES_SEL, INTERRUPT_ACK, INTERRUPT_STATUS, MAGIC_VALUE,
    MmioTransport, QUEUE_AVAIL_HIGH, QUEUE_AVAIL_LOW, QUEUE_DESC_HIGH, QUEUE_DESC_LOW,
    QUEUE_NOTIFY, QUEUE_NUM, QUEUE_NUM_MAX, QUEUE_READY, QUEUE_SEL, QUEUE_USED_HIGH,
    QUEUE_USED_LOW, SHM_BASE_HIGH, SHM_BASE_LOW, SHM_LEN_HIGH, SHM_LEN_LOW, SHM_SEL, STATUS,
    VENDOR_ID_REG, VERSION, VIRTIO_MMIO_MAGIC, VIRTIO_MMIO_VERSION,
};
use crate::{MMIO_BASE, MMIO_DEVICE_SIZE, device_mmio_addr, resolve_mmio_addr};
use amla_core::num::{hi32, lo32};
use amla_core::vm_state::guest_mem::GuestMemory;
use amla_core::vm_state::{TEST_RAM_SIZE, TestMmap, VmState, make_test_vmstate, test_mmap};
use amla_core::{IrqLine, NullIrqLine};
use amla_virtio::{
    ConsoleState, DEVICE_ID_CONSOLE, INT_CONFIG, QueueView, QueueViolation, STATUS_ACKNOWLEDGE,
    STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER, STATUS_DRIVER_OK, STATUS_FEATURES_OK, VENDOR_ID,
    VIRTIO_CONSOLE_F_MULTIPORT, VIRTIO_F_VERSION_1, VirtioDevice,
};
use bytemuck::Zeroable;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

const READY_STATUS: u32 =
    STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;

// =============================================================================
// Test Helpers
// =============================================================================

/// Guest RAM size for VM-state-backed tests.
const RAM_SIZE: usize = TEST_RAM_SIZE;

/// Create a test mmap with a valid `VmState` header and RAM section.
fn make_test_buf() -> TestMmap {
    test_mmap(RAM_SIZE)
}

/// Create a `VmState` view over the test mmap.
fn make_state(mmap: &TestMmap) -> VmState<'_> {
    make_test_vmstate(mmap, 0)
}

/// Minimal console device for testing.
struct TestDevice;

impl VirtioDevice<VmState<'_>> for TestDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_CONSOLE
    }

    fn queue_count(&self) -> usize {
        6
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT
    }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, VmState<'_>>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_split()?;
            queue.push(chain.complete_zero())?;
        }
        Ok(())
    }

    fn write_config(&mut self, config: &mut [u8], offset: usize, data: &[u8]) {
        if offset + data.len() <= config.len() {
            config[offset..offset + data.len()].copy_from_slice(data);
        }
    }
}

/// Device with a configurable active queue count for transport-bound tests.
struct LimitedQueueDevice {
    queue_count: usize,
    process_count: usize,
}

impl LimitedQueueDevice {
    fn new(queue_count: usize) -> Self {
        Self {
            queue_count,
            process_count: 0,
        }
    }
}

impl VirtioDevice<VmState<'_>> for LimitedQueueDevice {
    fn device_id(&self) -> u32 {
        DEVICE_ID_CONSOLE
    }

    fn queue_count(&self) -> usize {
        self.queue_count
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1
    }

    fn process_queue(
        &mut self,
        _queue_idx: usize,
        _queue: &mut QueueView<'_, '_, '_, VmState<'_>>,
    ) -> Result<(), QueueViolation> {
        self.process_count += 1;
        Ok(())
    }
}

/// IRQ line that records assert/deassert calls.
struct TestIrqLine {
    asserted: AtomicBool,
    assert_count: AtomicU32,
}

impl TestIrqLine {
    fn new() -> Self {
        Self {
            asserted: AtomicBool::new(false),
            assert_count: AtomicU32::new(0),
        }
    }

    fn is_asserted(&self) -> bool {
        self.asserted.load(Ordering::Relaxed)
    }
}

impl IrqLine for TestIrqLine {
    fn assert(&self) {
        self.asserted.store(true, Ordering::Relaxed);
        self.assert_count.fetch_add(1, Ordering::Relaxed);
    }

    fn deassert(&self) {
        self.asserted.store(false, Ordering::Relaxed);
    }
}

fn make_transport<'a>(
    state: &'a mut ConsoleState,
    device: &'a mut TestDevice,
    mem: &'a VmState<'a>,
    irq: &'a dyn IrqLine,
) -> MmioTransport<'a, TestDevice, VmState<'a>> {
    MmioTransport::new(
        &mut state.transport,
        &mut state.queues,
        bytemuck::bytes_of_mut(&mut state.config),
        device,
        mem,
        irq,
    )
}

fn zeroed_state() -> ConsoleState {
    Zeroable::zeroed()
}

// =============================================================================
// Identification Register Tests
// =============================================================================

#[test]
fn test_magic_value() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);
    assert_eq!(t.read(MAGIC_VALUE, 4), u64::from(VIRTIO_MMIO_MAGIC));
}

#[test]
fn test_version() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);
    assert_eq!(t.read(VERSION, 4), u64::from(VIRTIO_MMIO_VERSION));
}

#[test]
fn test_device_id() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);
    assert_eq!(t.read(DEVICE_ID, 4), u64::from(DEVICE_ID_CONSOLE));
}

#[test]
fn test_vendor_id() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);
    assert_eq!(t.read(VENDOR_ID_REG, 4), u64::from(VENDOR_ID));
}

// =============================================================================
// Status Register Tests
// =============================================================================

#[test]
fn test_status_transitions() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(STATUS, 4), 0);
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE));
    assert_eq!(t.read(STATUS, 4), u64::from(STATUS_ACKNOWLEDGE));
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    assert_eq!(
        t.read(STATUS, 4),
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER)
    );
}

#[test]
fn test_status_reset() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = TestIrqLine::new();
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE));
    assert_eq!(t.read(STATUS, 4), u64::from(STATUS_ACKNOWLEDGE));
    t.write(STATUS, 4, 0);
    assert_eq!(t.read(STATUS, 4), 0);
    assert!(!irq.is_asserted());
}

#[test]
fn test_status_reset_bumps_queue_generation() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].generation = 41;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(STATUS, 4, 0);
    }

    assert_eq!(state.queues[0].size, 0);
    assert_eq!(state.queues[0].ready, 0);
    assert_eq!(state.queues[0].generation, 42);
}

#[test]
fn test_nonzero_status_writes_are_monotonic() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE));

    assert_eq!(
        t.read(STATUS, 4),
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER),
        "nonzero STATUS writes must add bits only; STATUS=0 is the only clear path",
    );
}

// =============================================================================
// Feature Negotiation Tests
// =============================================================================

#[test]
fn test_feature_negotiation() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    // Read device features
    t.write(DEVICE_FEATURES_SEL, 4, 0);
    let low = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();
    let expected_low = lo32(VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT);
    assert_eq!(low, expected_low);
    t.write(DEVICE_FEATURES_SEL, 4, 1);
    let high = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();
    let expected_high = hi32(VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT);
    assert_eq!(high, expected_high);

    // Write driver features (accept all)
    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, u64::from(low));
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, u64::from(high));

    // Set FEATURES_OK
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_ne!(status & STATUS_FEATURES_OK, 0, "FEATURES_OK should be set");
}

#[test]
fn test_features_ok_rejected_without_version_1() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    // Don't negotiate VIRTIO_F_VERSION_1
    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, 0);
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, 0);

    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_eq!(
        status & STATUS_FEATURES_OK,
        0,
        "FEATURES_OK should be cleared"
    );
}

#[test]
fn test_invalid_features_ok_combined_with_driver_ok_clears_both() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    // First write an invalid FEATURES_OK transition and illegally include
    // DRIVER_OK in the same status write. Neither bit may latch.
    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, 0);
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, 0);
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_eq!(status & STATUS_FEATURES_OK, 0);
    assert_eq!(status & STATUS_DRIVER_OK, 0);

    // After fixing features, FEATURES_OK may be accepted, but DRIVER_OK still
    // requires its own later write after the driver has re-read STATUS.
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_ne!(status & STATUS_FEATURES_OK, 0);
    assert_eq!(status & STATUS_DRIVER_OK, 0);
}

#[test]
fn test_features_ok_rejected_superset() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    // Request features the device doesn't offer
    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, 0xFFFF_FFFF);
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, 0xFFFF_FFFF);

    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_eq!(status & STATUS_FEATURES_OK, 0);
}

#[test]
fn test_driver_features_frozen_after_features_ok() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    // Negotiate features (accept all device features)
    t.write(DEVICE_FEATURES_SEL, 4, 0);
    let feat_low = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();
    t.write(DEVICE_FEATURES_SEL, 4, 1);
    let feat_high = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();

    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, u64::from(feat_low));
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, u64::from(feat_high));

    // Set FEATURES_OK
    t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
    t.write(
        STATUS,
        4,
        u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
    );
    let status = u32::try_from(t.read(STATUS, 4)).unwrap();
    assert_ne!(status & STATUS_FEATURES_OK, 0);

    // Try to change driver features after FEATURES_OK — must be rejected
    t.write(DRIVER_FEATURES_SEL, 4, 0);
    t.write(DRIVER_FEATURES, 4, 0); // try to clear low features
    t.write(DRIVER_FEATURES_SEL, 4, 1);
    t.write(DRIVER_FEATURES, 4, 0); // try to clear high features

    // Features must be unchanged
    assert_eq!(
        state.transport.driver_features,
        u64::from(feat_low) | (u64::from(feat_high) << 32),
        "driver features must not change after FEATURES_OK"
    );
}

#[test]
fn test_driver_ok_rejected_without_prior_features_ok() {
    // virtio 1.2 §3.1.1: the driver must set FEATURES_OK, re-read STATUS to
    // confirm it stuck, and only then set DRIVER_OK. The transport refuses
    // any DRIVER_OK transition where FEATURES_OK was not accepted in a
    // *prior* status write — including (a) a guest that skipped FEATURES_OK
    // entirely and (b) a guest that wrote both bits in one MMIO transaction.
    // Failure mode is "strip DRIVER_OK", with no DEVICE_NEEDS_RESET so a
    // recovering driver can finish the handshake by re-reading STATUS.
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let irq = NullIrqLine;

    // (a) Driver jumps straight to DRIVER_OK with no FEATURES_OK ever.
    {
        let mut state = zeroed_state();
        let mut dev = TestDevice;
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_DRIVER_OK),
        );
        let status = u32::try_from(t.read(STATUS, 4)).unwrap();
        assert_eq!(status & STATUS_DRIVER_OK, 0, "DRIVER_OK must be stripped");
        assert_eq!(
            status & STATUS_DEVICE_NEEDS_RESET,
            0,
            "invalid DRIVER_OK transition is not a NEEDS_RESET condition",
        );
    }

    // (b) Driver writes FEATURES_OK and DRIVER_OK in a single transaction
    // — must be rejected because it skipped the mandatory STATUS re-read.
    {
        let mut state = zeroed_state();
        let mut dev = TestDevice;
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        // VIRTIO_F_VERSION_1 lives in the high half of the feature bitmap.
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK),
        );
        let status = u32::try_from(t.read(STATUS, 4)).unwrap();
        assert_ne!(
            status & STATUS_FEATURES_OK,
            0,
            "FEATURES_OK must be accepted (features are valid)",
        );
        assert_eq!(
            status & STATUS_DRIVER_OK,
            0,
            "combined FEATURES_OK|DRIVER_OK write must reject DRIVER_OK",
        );
        assert_eq!(status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    // (c) Once FEATURES_OK has landed in its own write, DRIVER_OK is allowed.
    {
        let mut state = zeroed_state();
        let mut dev = TestDevice;
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        // VIRTIO_F_VERSION_1 lives in the high half of the feature bitmap.
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK),
        );
        let status = u32::try_from(t.read(STATUS, 4)).unwrap();
        assert_ne!(status & STATUS_DRIVER_OK, 0, "DRIVER_OK accepted");
    }
}

// =============================================================================
// Queue Setup Tests
// =============================================================================

#[test]
fn test_queue_sel_and_num_max() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    t.write(QUEUE_SEL, 4, 0);
    assert_eq!(t.read(QUEUE_NUM_MAX, 4), 256);
    t.write(QUEUE_SEL, 4, 1);
    assert_eq!(t.read(QUEUE_NUM_MAX, 4), 256);
    t.write(QUEUE_SEL, 4, 5);
    assert_eq!(t.read(QUEUE_NUM_MAX, 4), 256);
    // Nonexistent queues
    t.write(QUEUE_SEL, 4, 6);
    assert_eq!(t.read(QUEUE_NUM_MAX, 4), 0);
    t.write(QUEUE_SEL, 4, 999);
    assert_eq!(t.read(QUEUE_NUM_MAX, 4), 0);
}

#[test]
fn test_queue_registers_use_active_queue_bound() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = LimitedQueueDevice::new(2);
    let irq = NullIrqLine;

    // Stale state outside the active bound must not be visible/configurable.
    state.queues[2].ready = 1;
    state.queues[2].size = 32;

    {
        let mut t = MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            bytemuck::bytes_of_mut(&mut state.config),
            &mut dev,
            &mem,
            &irq,
        );

        t.write(QUEUE_SEL, 4, 1);
        assert_eq!(t.read(QUEUE_NUM_MAX, 4), 256);

        t.write(QUEUE_SEL, 4, 2);
        assert_eq!(t.read(QUEUE_NUM_MAX, 4), 0);
        assert_eq!(t.read(QUEUE_READY, 4), 0);

        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1234);
        t.write(QUEUE_READY, 4, 1);
        t.write(QUEUE_NOTIFY, 4, 2);
    }

    assert_eq!(state.queues[2].ready, 1);
    assert_eq!(state.queues[2].size, 32);
    assert_eq!(state.queues[2].desc_addr, 0);
    assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    assert_eq!(dev.process_count, 0);
}

#[test]
fn test_queue_num_power_of_2() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    // Select queue 0, set valid size 16
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
    }
    assert_eq!(state.queues[0].size, 16);

    // 15 is not power of 2 — rejected, stays 16
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_NUM, 4, 15);
    }
    assert_eq!(state.queues[0].size, 16);

    // 0 is invalid — rejected, stays 16
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_NUM, 4, 0);
    }
    assert_eq!(state.queues[0].size, 16);

    // 256 is valid
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_NUM, 4, 256);
    }
    assert_eq!(state.queues[0].size, 256);

    // 512 exceeds queue_max_size (256) — rejected
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_NUM, 4, 512);
    }
    assert_eq!(state.queues[0].size, 256);
}

#[test]
fn test_queue_num_rejects_truncating_large_value() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_NUM, 4, u64::from(u32::MAX));
    }

    assert_eq!(state.queues[0].size, 16);
}

#[test]
fn test_queue_ready() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0); // select queue 0
        t.write(QUEUE_NUM, 4, 16);
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
        assert_eq!(t.read(QUEUE_READY, 4), 1);
    }
    assert_eq!(state.queues[0].ready, 1);

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_READY, 4, 0);
        assert_eq!(t.read(QUEUE_READY, 4), 0);
    }
    assert_eq!(state.queues[0].ready, 0);
}

#[test]
fn test_queue_address_registers() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    // Set desc, avail, used addresses
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0); // select queue 0
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(QUEUE_DESC_HIGH, 4, 0);
    }
    assert_eq!(state.queues[0].desc_addr, 0x1000);

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_AVAIL_LOW, 4, 0x2000);
        t.write(QUEUE_AVAIL_HIGH, 4, 0);
    }
    assert_eq!(state.queues[0].avail_addr, 0x2000);

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_USED_LOW, 4, 0x3000);
        t.write(QUEUE_USED_HIGH, 4, 0);
    }
    assert_eq!(state.queues[0].used_addr, 0x3000);

    // Test 64-bit address
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_DESC_LOW, 4, 0xDEAD_BEEF);
        t.write(QUEUE_DESC_HIGH, 4, 0x0000_1234);
    }
    assert_eq!(state.queues[0].desc_addr, 0x0000_1234_DEAD_BEEF);
}

#[test]
fn test_queue_addr_writes_rejected_after_ready() {
    // Per virtio 1.2 §4.2.2.2, QueueDesc/Avail/Used and QueueNum are read-only
    // after QueueReady=1. The device must reject the write and per §2.1.2
    // signal DEVICE_NEEDS_RESET (with a config-change IRQ if DRIVER_OK is set).
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = TestIrqLine::new();

    // Driver setup: program queue 0, mark ready, then complete DRIVER_OK.
    // virtio 1.2 §3.1.1 requires FEATURES_OK to land in its own status write
    // before DRIVER_OK is set, so the driver can re-read STATUS to confirm it
    // stuck. The transport rejects a combined FEATURES_OK|DRIVER_OK write.
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(QUEUE_AVAIL_LOW, 4, 0x2000);
        t.write(QUEUE_USED_LOW, 4, 0x3000);
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK),
        );
    }
    assert!(!irq.is_asserted(), "no IRQ during clean setup");

    // Misbehaving guest writes QUEUE_DESC_LOW while queue is live.
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_DESC_LOW, 4, 0xBAD0_0000);
    }
    assert_eq!(
        state.queues[0].desc_addr, 0x1000,
        "QUEUE_DESC_LOW write must be dropped, no tearing"
    );
    assert_ne!(
        state.transport.status & STATUS_DEVICE_NEEDS_RESET,
        0,
        "DEVICE_NEEDS_RESET must be set on protocol violation"
    );
    assert_ne!(
        state.transport.interrupt_status & INT_CONFIG,
        0,
        "config-change interrupt must be raised when DRIVER_OK is set"
    );
    assert!(irq.is_asserted(), "IRQ must fire to wake the driver");

    // Same gating applies to QUEUE_NUM, QUEUE_AVAIL_*, QUEUE_USED_* — verify
    // one of each address pair to confirm the helper is wired uniformly.
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_NUM, 4, 8);
        t.write(QUEUE_AVAIL_HIGH, 4, 0xDEAD);
        t.write(QUEUE_USED_HIGH, 4, 0xBEEF);
    }
    assert_eq!(state.queues[0].size, 16);
    assert_eq!(state.queues[0].avail_addr, 0x2000);
    assert_eq!(state.queues[0].used_addr, 0x3000);

    // Driver recovers by issuing STATUS=0 reset; reconfiguration then works.
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(STATUS, 4, 0);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_DESC_LOW, 4, 0x4000);
    }
    assert_eq!(state.queues[0].desc_addr, 0x4000);
    assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
}

#[test]
fn test_queue_addr_violation_pre_driver_ok_sets_status_without_irq() {
    // Per virtio 1.2 §2.1.2, the device-change interrupt is only required
    // "if DRIVER_OK is set". Pre-DRIVER_OK, the status bit is still set so
    // a later read sees it, but no IRQ is raised.
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = TestIrqLine::new();

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
        // Status stops before DRIVER_OK, so reset is visible but not IRQed.
        t.write(QUEUE_DESC_LOW, 4, 0xBAD0_0000);
    }

    assert_eq!(state.queues[0].desc_addr, 0x1000, "write must be dropped");
    assert_ne!(
        state.transport.status & STATUS_DEVICE_NEEDS_RESET,
        0,
        "NEEDS_RESET set unconditionally so a later status read sees it"
    );
    assert_eq!(
        state.transport.interrupt_status & INT_CONFIG,
        0,
        "no config-change interrupt before DRIVER_OK"
    );
    assert!(!irq.is_asserted(), "no IRQ before DRIVER_OK");
}

#[test]
fn test_device_needs_reset_is_sticky_until_status_zero() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_READY, 4, 1);
        t.write(STATUS, 4, u64::from(STATUS_DRIVER_OK));
        t.write(QUEUE_NUM, 4, 8);
    }
    assert_ne!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE));
    }
    assert_ne!(
        state.transport.status & STATUS_DEVICE_NEEDS_RESET,
        0,
        "nonzero status writes must not clear NEEDS_RESET"
    );

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(STATUS, 4, 0);
    }
    assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
}

#[test]
fn test_queue_ready_rejects_ring_outside_guest_ram() {
    // Per virtio 1.2 §2.7.1, a ready queue's ring extents must lie within
    // guest RAM. A driver writing addresses past the end of RAM (or near
    // u64::MAX so worst-case length wraps) would otherwise leave us doing
    // unchecked u64 + offset arithmetic in pop/push every notify.
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    // Case A: avail_addr is finite but well beyond the 64 KiB test RAM.
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(QUEUE_AVAIL_LOW, 4, 0xDEAD_0000);
        t.write(QUEUE_USED_LOW, 4, 0x3000);
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
    }
    assert_eq!(
        state.queues[0].ready, 0,
        "ready stays 0 when avail ring falls outside guest RAM"
    );
    assert_ne!(
        state.transport.status & STATUS_DEVICE_NEEDS_RESET,
        0,
        "DEVICE_NEEDS_RESET signaled per §2.1.2"
    );

    // Case B: desc_addr near u64::MAX so the worst-case ring length wraps.
    let mut state = zeroed_state();
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0xFFFF_FFFE);
        t.write(QUEUE_DESC_HIGH, 4, 0xFFFF_FFFF);
        t.write(QUEUE_AVAIL_LOW, 4, 0x2000);
        t.write(QUEUE_USED_LOW, 4, 0x3000);
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
    }
    assert_eq!(state.queues[0].ready, 0);
    assert_ne!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
}

#[test]
fn test_queue_ready_accepts_tight_non_event_idx_layout() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let used_len_without_event_idx = 4 + 8 * 16;
    let used_addr = u32::try_from(RAM_SIZE - used_len_without_event_idx).unwrap();

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(QUEUE_SEL, 4, 0);
        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(QUEUE_AVAIL_LOW, 4, 0x2000);
        t.write(QUEUE_USED_LOW, 4, u64::from(used_addr));
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        t.write(QUEUE_READY, 4, 1);
    }

    assert_eq!(state.queues[0].ready, 1);
    assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
}

#[test]
fn test_queue_ready_rejects_unaligned_ring_addresses() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let irq = NullIrqLine;

    for (desc, avail, used) in [
        (0x1001, 0x2000, 0x3000),
        (0x1000, 0x2001, 0x3000),
        (0x1000, 0x2000, 0x3002),
    ] {
        let mut state = zeroed_state();
        let mut dev = TestDevice;
        {
            let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
            t.write(QUEUE_SEL, 4, 0);
            t.write(QUEUE_NUM, 4, 16);
            t.write(QUEUE_DESC_LOW, 4, desc);
            t.write(QUEUE_AVAIL_LOW, 4, avail);
            t.write(QUEUE_USED_LOW, 4, used);
            t.write(DRIVER_FEATURES_SEL, 4, 1);
            t.write(DRIVER_FEATURES, 4, u64::from(hi32(VIRTIO_F_VERSION_1)));
            t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));
            t.write(
                STATUS,
                4,
                u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
            );
            t.write(QUEUE_READY, 4, 1);
        }
        assert_eq!(state.queues[0].ready, 0);
        assert_ne!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }
}

// =============================================================================
// Interrupt Tests
// =============================================================================

#[test]
fn test_interrupt_status_and_ack() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = TestIrqLine::new();
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(INTERRUPT_STATUS, 4), 0);

    t.notify_config_change();
    assert_eq!(t.read(INTERRUPT_STATUS, 4), u64::from(INT_CONFIG));
    assert!(irq.is_asserted());

    t.write(INTERRUPT_ACK, 4, u64::from(INT_CONFIG));
    assert_eq!(t.read(INTERRUPT_STATUS, 4), 0);
    assert!(!irq.is_asserted());
}

// =============================================================================
// Config Space Tests
// =============================================================================

#[test]
fn test_config_read() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    state.config.cols = 42;
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(CONFIG_SPACE, 4), 42);
}

#[test]
fn test_config_read_rejects_unaligned_access() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    state.config.max_nr_ports = 0x1122_3344;
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(CONFIG_SPACE + 5, 2), 0);
    assert_eq!(t.read(CONFIG_SPACE + 5, 4), 0);
}

#[test]
fn test_config_write() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(CONFIG_SPACE + 4, 4, 99); // offset 4 in config = actual field
    }
    assert_eq!(state.config.max_nr_ports, 99);
}

#[test]
fn test_config_write_rejects_unaligned_access() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(CONFIG_SPACE + 5, 2, 0xffff);
        t.write(CONFIG_SPACE + 5, 4, 0xaabb_ccdd);
    }
    assert_eq!(state.config.max_nr_ports, 0);
}

#[test]
fn test_config_oob_read() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(MMIO_DEVICE_SIZE, 4), 0);
}

// =============================================================================
// QueueNotify register routing
// =============================================================================

#[test]
fn test_queue_notify_write_is_transport_side_effect_free() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = LimitedQueueDevice::new(6);
    let irq = TestIrqLine::new();

    state.transport.status = READY_STATUS;
    state.queues[0].size = 16;
    state.queues[0].ready = 1;
    state.queues[0].desc_addr = 0x0000;
    state.queues[0].avail_addr = 0x1000;
    state.queues[0].used_addr = 0x2000;
    mem.write_obj(0x1004u64, &20u16).unwrap();
    mem.write_obj(0x1002u64, &1u16).unwrap();

    {
        let mut t = MmioTransport::new(
            &mut state.transport,
            &mut state.queues,
            bytemuck::bytes_of_mut(&mut state.config),
            &mut dev,
            &mem,
            &irq,
        );
        t.write(QUEUE_NOTIFY, 4, 0);
    }

    assert_eq!(dev.process_count, 0);
    assert_eq!(state.queues[0].last_avail_idx, 0);
    assert_eq!(state.queues[0].last_used_idx, 0);
    assert_eq!(state.transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    assert_eq!(state.transport.interrupt_status & INT_CONFIG, 0);
    assert!(!irq.is_asserted());
}

// =============================================================================
// Full Device Initialization Sequence
// =============================================================================

#[test]
fn test_full_initialization_sequence() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    // Step 1: Read identification registers and negotiate features
    let feat_low;
    let feat_high;
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

        assert_eq!(t.read(MAGIC_VALUE, 4), u64::from(VIRTIO_MMIO_MAGIC));
        assert_eq!(t.read(VERSION, 4), u64::from(VIRTIO_MMIO_VERSION));
        assert_eq!(t.read(DEVICE_ID, 4), u64::from(DEVICE_ID_CONSOLE));

        // Status: ACKNOWLEDGE | DRIVER
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE));
        t.write(STATUS, 4, u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER));

        // Read features
        t.write(DEVICE_FEATURES_SEL, 4, 0);
        feat_low = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();
        t.write(DEVICE_FEATURES_SEL, 4, 1);
        feat_high = u32::try_from(t.read(DEVICE_FEATURES, 4)).unwrap();

        // Accept all features
        t.write(DRIVER_FEATURES_SEL, 4, 0);
        t.write(DRIVER_FEATURES, 4, u64::from(feat_low));
        t.write(DRIVER_FEATURES_SEL, 4, 1);
        t.write(DRIVER_FEATURES, 4, u64::from(feat_high));

        // FEATURES_OK
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK),
        );
        let status = u32::try_from(t.read(STATUS, 4)).unwrap();
        assert_ne!(status & STATUS_FEATURES_OK, 0);

        // Set up queue 0
        t.write(QUEUE_SEL, 4, 0);
        let max = t.read(QUEUE_NUM_MAX, 4);
        assert!(max > 0);

        t.write(QUEUE_NUM, 4, 16);
        t.write(QUEUE_DESC_LOW, 4, 0x1000);
        t.write(QUEUE_DESC_HIGH, 4, 0);
        t.write(QUEUE_AVAIL_LOW, 4, 0x2000);
        t.write(QUEUE_AVAIL_HIGH, 4, 0);
        t.write(QUEUE_USED_LOW, 4, 0x3000);
        t.write(QUEUE_USED_HIGH, 4, 0);
        t.write(QUEUE_READY, 4, 1);
    }

    // Verify queue state was set correctly
    assert_eq!(state.queues[0].size, 16);
    assert_eq!(state.queues[0].ready, 1);
    assert_eq!(state.queues[0].desc_addr, 0x1000);

    // Step 2: Set DRIVER_OK
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(
            STATUS,
            4,
            u64::from(STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK),
        );
        let final_status = u32::try_from(t.read(STATUS, 4)).unwrap();
        assert_ne!(final_status & STATUS_DRIVER_OK, 0);
    }
}

// =============================================================================
// SHM Region Tests
// =============================================================================

#[test]
fn test_shm_nonexistent() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    t.write(SHM_SEL, 4, 0);
    assert_eq!(t.read(SHM_LEN_LOW, 4), 0xFFFF_FFFF);
    assert_eq!(t.read(SHM_LEN_HIGH, 4), 0xFFFF_FFFF);
    assert_eq!(t.read(SHM_BASE_LOW, 4), 0xFFFF_FFFF);
    assert_eq!(t.read(SHM_BASE_HIGH, 4), 0xFFFF_FFFF);
}

// =============================================================================
// Non-32-bit Access Tests
// =============================================================================

#[test]
fn test_non_32bit_transport_access() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = NullIrqLine;

    // Non-32-bit read returns 0
    {
        let t = make_transport(&mut state, &mut dev, &mem, &irq);
        assert_eq!(t.read(MAGIC_VALUE, 2), 0);
    }

    // Non-32-bit write is ignored
    {
        let mut t = make_transport(&mut state, &mut dev, &mem, &irq);
        t.write(STATUS, 1, 0xFF);
    }
    assert_eq!(state.transport.status, 0);
}

// =============================================================================
// Address Resolution Tests
// =============================================================================

#[test]
fn test_resolve_mmio_addr() {
    let (idx, offset) = resolve_mmio_addr(MMIO_BASE).unwrap();
    assert_eq!(idx, 0);
    assert_eq!(offset, 0);

    let (idx, offset) = resolve_mmio_addr(MMIO_BASE + 0x200 + 0x070).unwrap();
    assert_eq!(idx, 1);
    assert_eq!(offset, 0x070);

    let (idx, offset) = resolve_mmio_addr(MMIO_BASE + 7 * 0x200).unwrap();
    assert_eq!(idx, 7);
    assert_eq!(offset, 0);

    // Slot 63 is the last valid slot
    let (idx, offset) = resolve_mmio_addr(MMIO_BASE + 63 * 0x200).unwrap();
    assert_eq!(idx, 63);
    assert_eq!(offset, 0);

    // Slot 64 is out of range
    assert!(resolve_mmio_addr(MMIO_BASE + 64 * 0x200).is_none());
    assert!(resolve_mmio_addr(MMIO_BASE - 1).is_none());
}

#[test]
fn test_device_mmio_addr_and_gsi() {
    assert_eq!(device_mmio_addr(0), MMIO_BASE);
    assert_eq!(device_mmio_addr(1), MMIO_BASE + 0x200);
    assert_eq!(device_mmio_addr(7), MMIO_BASE + 0xE00);

    #[cfg(not(target_arch = "aarch64"))]
    {
        assert_eq!(device_gsi(0), 5);
        assert_eq!(device_gsi(7), 12);
    }
}

// =============================================================================
// Config Generation
// =============================================================================

#[test]
fn test_config_generation() {
    let buf = make_test_buf();
    let mem = make_state(&buf);
    let mut state = zeroed_state();
    let mut dev = TestDevice;
    let irq = TestIrqLine::new();
    let mut t = make_transport(&mut state, &mut dev, &mem, &irq);

    assert_eq!(t.read(CONFIG_GENERATION, 4), 0);
    t.notify_config_change();
    assert_eq!(t.read(CONFIG_GENERATION, 4), 1);
    t.notify_config_change();
    assert_eq!(t.read(CONFIG_GENERATION, 4), 2);
}
