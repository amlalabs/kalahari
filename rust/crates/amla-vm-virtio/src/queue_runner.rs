// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Shared virtqueue processing policy.
//!
//! [`QueueView`] owns ring parsing, memory ordering, and used-ring writes. This
//! module owns the transport policy around it: queue-work gating, violation to
//! `DEVICE_NEEDS_RESET`, and interrupt publication after `EVENT_IDX`
//! notification suppression is checked.

use amla_core::IrqLine;
use amla_core::vm_state::guest_mem::GuestMemory;
use std::marker::PhantomData;

use crate::queue::{DeferredWritableRegions, QueueClaim};
use crate::{
    CompletableDescriptorChain, INT_CONFIG, INT_VRING, MmioTransportState, QueueState, QueueView,
    QueueViolation, STATUS_ACKNOWLEDGE, STATUS_DEVICE_NEEDS_RESET, STATUS_DRIVER, STATUS_DRIVER_OK,
    STATUS_FAILED, STATUS_FEATURES_OK, SplitDescriptorChain, VirtioDevice, WritableDescriptorChain,
    WrittenBytes,
};

/// Result of a queue-runner operation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[must_use]
pub struct QueueRunOutcome {
    flags: u8,
}

impl QueueRunOutcome {
    const HAD_WORK: u8 = 1 << 0;
    const NOTIFIED: u8 = 1 << 1;
    const NEEDS_RESET: u8 = 1 << 2;
    const DISCARDED_STALE: u8 = 1 << 3;

    /// Return whether at least one used-ring entry was published.
    #[must_use]
    pub const fn had_work(self) -> bool {
        self.flags & Self::HAD_WORK != 0
    }

    /// Return whether the runner asserted an interrupt for used buffers.
    #[must_use]
    pub const fn notified(self) -> bool {
        self.flags & Self::NOTIFIED != 0
    }

    /// Return whether queue processing faulted the device.
    #[must_use]
    pub const fn needs_reset(self) -> bool {
        self.flags & Self::NEEDS_RESET != 0
    }

    /// Return whether delayed completions were discarded as stale.
    #[must_use]
    pub const fn discarded_stale(self) -> bool {
        self.flags & Self::DISCARDED_STALE != 0
    }

    /// Merge another operation outcome into this one.
    pub const fn merge(&mut self, other: Self) {
        self.flags |= other.flags;
    }

    const fn used(notified: bool) -> Self {
        let mut flags = Self::HAD_WORK;
        if notified {
            flags |= Self::NOTIFIED;
        }
        Self { flags }
    }

    const fn reset() -> Self {
        Self {
            flags: Self::NEEDS_RESET,
        }
    }

    const fn stale() -> Self {
        Self {
            flags: Self::DISCARDED_STALE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Descriptor, VIRTQ_DESC_F_WRITE};
    use amla_core::NullIrqLine;
    use amla_core::vm_state::guest_mem::{GuestMemory, GuestRead};
    use amla_core::vm_state::{TEST_RAM_SIZE, VmState, make_test_vmstate, test_mmap};

    const RAM_SIZE: usize = TEST_RAM_SIZE;

    fn ready_transport() -> MmioTransportState {
        MmioTransportState {
            status: STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK,
            pad0: 0,
            driver_features: 0,
            interrupt_status: 0,
            config_generation: 0,
            queue_sel: 0,
            features_sel: 0,
            driver_features_sel: 0,
            shm_sel: 0,
        }
    }

    fn queue_state(queue_idx: usize) -> QueueState {
        let base = u64::try_from(queue_idx).unwrap() * 0x3000;
        QueueState {
            size: 8,
            ready: 1,
            pad0: 0,
            desc_addr: base,
            avail_addr: base + 0x1000,
            used_addr: base + 0x2000,
            last_avail_idx: 0,
            last_used_idx: 0,
            generation: 0,
        }
    }

    fn publish_avail(vm: &VmState<'_>, queue: &QueueState, count: u16) {
        for i in 0..count {
            vm.write_obj(
                queue.desc_addr + u64::from(i) * 16,
                &Descriptor {
                    addr: 0x9000 + queue.desc_addr + u64::from(i) * 0x20,
                    len: 16,
                    flags: VIRTQ_DESC_F_WRITE,
                    next: 0,
                },
            )
            .unwrap();
            vm.write_obj(queue.avail_addr + 4 + u64::from(i) * 2, &i)
                .unwrap();
        }
        vm.write_obj(queue.avail_addr + 2, &count).unwrap();
    }

    fn pop_deferred_completion<'m>(
        runner: &mut QueueRunner<'_, 'm, VmState<'m>>,
        queues: &mut [QueueState],
        queue_idx: usize,
    ) -> DeferredDescriptorCompletion {
        runner
            .pop_view(queue_idx, &mut queues[queue_idx], |view, ctx| {
                let chain = view.pop().unwrap().into_split().unwrap();
                Ok(Some(ctx.defer_split_completion(chain)?))
            })
            .unwrap()
            .unwrap()
    }

    fn read_used_idx(vm: &VmState<'_>, queue: &QueueState) -> u16 {
        vm.read_obj(queue.used_addr + 2).unwrap()
    }

    struct LeakyDevice;

    impl VirtioDevice<VmState<'_>> for LeakyDevice {
        fn device_id(&self) -> u32 {
            crate::DEVICE_ID_RNG
        }

        fn queue_count(&self) -> usize {
            1
        }

        fn device_features(&self) -> u64 {
            0
        }

        fn process_queue(
            &mut self,
            _queue_idx: usize,
            queue: &mut QueueView<'_, '_, '_, VmState<'_>>,
        ) -> Result<(), QueueViolation> {
            let _chain = queue.pop();
            Ok(())
        }
    }

    #[test]
    fn run_device_queue_faults_if_sync_device_forgets_completion() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queue = queue_state(0);
        vm.write_obj(
            queue.desc_addr,
            &Descriptor {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0,
            },
        )
        .unwrap();
        publish_avail(&vm, &queue, 1);

        let mut device = LeakyDevice;
        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.run_device_queue(0, &mut queue, &mut device)
        };

        assert!(outcome.needs_reset());
        assert_ne!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
        assert_eq!(read_used_idx(&vm, &queue), 0);
    }

    #[test]
    fn publish_completion_writes_then_publishes_used_entry() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = [queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[1, 2, 3, 4])
        };

        let mut data = [0u8; 4];
        vm.gpa_read(0x9000, data.len()).unwrap().read_to(&mut data);
        assert_eq!(data, [1, 2, 3, 4]);
        assert!(outcome.had_work());
        assert_eq!(read_used_idx(&vm, &queues[0]), 1);
        assert_eq!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_faults_oversized_response_before_guest_write() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = [queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[0xff; 17])
        };

        assert!(outcome.needs_reset());
        let mut data = [0xffu8; 5];
        vm.gpa_read(0x9000, data.len()).unwrap().read_to(&mut data);
        assert_eq!(data, [0, 0, 0, 0, 0]);
        assert_eq!(read_used_idx(&vm, &queues[0]), 0);
        assert_ne!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_accepts_empty_response() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = [queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[])
        };

        assert!(outcome.had_work());
        assert_eq!(read_used_idx(&vm, &queues[0]), 1);
        assert_eq!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_discards_stale_queue_before_guest_write() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = vec![queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };
        queues[0].generation = queues[0].generation.wrapping_add(1);

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[1, 2, 3, 4])
        };

        let mut data = [0xffu8; 4];
        vm.gpa_read(0x9000, data.len()).unwrap().read_to(&mut data);
        assert_eq!(data, [0, 0, 0, 0]);
        assert!(outcome.discarded_stale());
        assert_eq!(read_used_idx(&vm, &queues[0]), 0);
        assert_eq!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_discards_stale_oversized_reply_before_length_check() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = vec![queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };
        queues[0].generation = queues[0].generation.wrapping_add(1);

        let oversized_response = vec![0xff; 1024];
        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &oversized_response)
        };

        assert!(outcome.discarded_stale());
        assert_eq!(read_used_idx(&vm, &queues[0]), 0);
        assert_eq!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_discards_missing_queue() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = vec![queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };
        queues.clear();

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[1, 2, 3, 4])
        };

        assert!(outcome.discarded_stale());
        assert_eq!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn publish_completion_noops_when_queue_work_disabled() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = vec![queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };
        transport.status = 0;

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[1, 2, 3, 4])
        };

        assert_eq!(outcome, QueueRunOutcome::default());
        assert_eq!(read_used_idx(&vm, &queues[0]), 0);
    }

    #[test]
    fn publish_completion_faults_before_commit_when_used_ring_invalid() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = vec![queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let completion = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            pop_deferred_completion(&mut runner, &mut queues, 0)
        };
        queues[0].used_addr = u64::MAX - 1;

        let outcome = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.publish_completion_bytes(&mut queues, completion, &[1, 2, 3, 4])
        };

        assert!(outcome.needs_reset());
        assert_eq!(read_used_idx(&vm, &queue_state(0)), 0);
        assert_ne!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }

    #[test]
    fn pop_view_faults_when_popped_chain_lacks_completion_capability() {
        let mmap = test_mmap(RAM_SIZE);
        let vm = make_test_vmstate(&mmap, 0);
        let irq = NullIrqLine;
        let mut transport = ready_transport();
        let mut queues = [queue_state(0)];
        publish_avail(&vm, &queues[0], 1);

        let result = {
            let mut runner = QueueRunner::new(&mut transport, &vm, &irq);
            runner.pop_view(0, &mut queues[0], |view, _ctx| {
                let _leaked = view.pop().unwrap().into_split()?;
                Ok::<_, QueueViolation>(())
            })
        };

        assert!(result.is_none());
        assert_eq!(read_used_idx(&vm, &queue_state(0)), 0);
        assert_ne!(transport.status & STATUS_DEVICE_NEEDS_RESET, 0);
    }
}

/// Queue pop context passed to custom async-capable queue scanners.
#[derive(Debug, Eq, PartialEq)]
pub struct QueuePopContext<'brand> {
    claim: QueueClaim,
    issued_completions: usize,
    _brand: PhantomData<fn(&'brand ()) -> &'brand ()>,
}

impl<'brand> QueuePopContext<'brand> {
    fn record_completion(&mut self) -> Result<(), QueueViolation> {
        self.issued_completions = self.issued_completions.checked_add(1).ok_or(
            QueueViolation::UncompletedDescriptorChains {
                popped: self.issued_completions,
                pushed: self.issued_completions,
            },
        )?;
        Ok(())
    }

    /// Convert a split descriptor chain into an async-safe completion token.
    ///
    /// The returned value carries queue identity plus opaque writable regions;
    /// callers can await backend work with it, but cannot write guest response
    /// bytes. [`QueueRunner::publish_completion_bytes`] revalidates the queue,
    /// writes the owned response bytes, and publishes the used-ring entry.
    pub fn defer_split_completion<M>(
        &mut self,
        chain: SplitDescriptorChain<'brand, '_, M>,
    ) -> Result<DeferredDescriptorCompletion, QueueViolation>
    where
        M: GuestMemory,
    {
        let head = CompletableDescriptorChain::head_index(&chain);
        let writable_len = CompletableDescriptorChain::writable_len_for_completion(&chain);
        let writable = chain.into_deferred_writable_regions()?;
        self.record_completion()?;
        Ok(DeferredDescriptorCompletion {
            token: QueueToken {
                claim: self.claim,
                head,
                writable_len,
            },
            writable,
        })
    }

    /// Convert a writable-only descriptor chain into an async-safe completion token.
    pub fn defer_writable_completion<M>(
        &mut self,
        chain: WritableDescriptorChain<'brand, '_, M>,
    ) -> Result<DeferredDescriptorCompletion, QueueViolation>
    where
        M: GuestMemory,
    {
        let head = CompletableDescriptorChain::head_index(&chain);
        let writable_len = CompletableDescriptorChain::writable_len_for_completion(&chain);
        let writable = chain.into_deferred_writable_regions()?;
        self.record_completion()?;
        Ok(DeferredDescriptorCompletion {
            token: QueueToken {
                claim: self.claim,
                head,
                writable_len,
            },
            writable,
        })
    }
}

/// Async-safe descriptor completion captured during queue pop.
#[derive(Debug)]
pub struct DeferredDescriptorCompletion {
    token: QueueToken,
    writable: DeferredWritableRegions,
}

impl DeferredDescriptorCompletion {
    /// Descriptor head captured with this completion.
    #[must_use]
    pub const fn head(&self) -> u16 {
        self.token.head()
    }

    /// Queue index captured with this completion.
    #[must_use]
    pub const fn queue_idx(&self) -> usize {
        self.token.queue_idx()
    }

    /// Writable bytes available to the eventual response writer.
    #[must_use]
    pub const fn writable_capacity(&self) -> usize {
        self.writable.capacity()
    }

    /// Heap bytes reserved for the opaque writable-region plan.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.writable.reserved_bytes()
    }
}

/// Descriptor completion token captured during a pop phase.
///
/// Async devices must carry this token from descriptor pop to used-ring
/// publication. It records the queue slot and reset/reconfiguration generation
/// internally so delayed completions cannot be published into a different
/// queue instance. The runner validates the token before invoking async
/// completion commit callbacks, so stale completions do not write response
/// bytes into guest memory either.
#[derive(Debug, Eq, PartialEq)]
struct QueueToken {
    claim: QueueClaim,
    head: u16,
    writable_len: usize,
}

impl QueueToken {
    #[must_use]
    const fn head(&self) -> u16 {
        self.head
    }

    #[must_use]
    const fn queue_idx(&self) -> usize {
        self.claim.queue_idx()
    }

    fn written_bytes(&self, bytes: usize) -> Result<WrittenBytes, QueueViolation> {
        WrittenBytes::checked(self.head, self.writable_len, bytes)
    }
}

/// Return whether a virtio device may process queue work.
#[must_use]
pub const fn queue_work_enabled(transport: &MmioTransportState) -> bool {
    // virtio 1.2 §3.1.1: DRIVER_OK is valid only after FEATURES_OK has been
    // accepted. Also stop all queue work once the device requires reset.
    let required = STATUS_ACKNOWLEDGE | STATUS_DRIVER | STATUS_FEATURES_OK | STATUS_DRIVER_OK;
    transport.status & required == required
        && transport.status & STATUS_FAILED == 0
        && transport.status & STATUS_DEVICE_NEEDS_RESET == 0
}

/// Fire a virtio configuration-change interrupt.
pub fn notify_config_change(transport: &mut MmioTransportState, irq: &dyn IrqLine) {
    transport.config_generation = transport.config_generation.wrapping_add(1);
    transport.interrupt_status |= INT_CONFIG;
    irq.assert();
}

/// Set `DEVICE_NEEDS_RESET` and notify the driver if it reached `DRIVER_OK`.
pub fn signal_device_needs_reset(transport: &mut MmioTransportState, irq: &dyn IrqLine) {
    transport.status |= STATUS_DEVICE_NEEDS_RESET;
    if transport.status & STATUS_DRIVER_OK != 0 {
        notify_config_change(transport, irq);
    }
}

/// Runs queue work against a transport and IRQ line.
pub struct QueueRunner<'t, 'm, M: GuestMemory> {
    transport: &'t mut MmioTransportState,
    memory: &'m M,
    irq: &'t dyn IrqLine,
}

impl<'t, 'm, M: GuestMemory> QueueRunner<'t, 'm, M> {
    /// Create a queue runner over borrowed transport state.
    pub fn new(transport: &'t mut MmioTransportState, memory: &'m M, irq: &'t dyn IrqLine) -> Self {
        Self {
            transport,
            memory,
            irq,
        }
    }

    /// Return whether this runner may currently process queue work.
    #[must_use]
    pub const fn queue_work_enabled(&self) -> bool {
        queue_work_enabled(self.transport)
    }

    /// Convert a queue violation into `DEVICE_NEEDS_RESET`.
    pub fn signal_device_needs_reset(&mut self) {
        signal_device_needs_reset(self.transport, self.irq);
    }

    /// Run one synchronous device queue.
    pub fn run_device_queue<D: VirtioDevice<M>>(
        &mut self,
        queue_idx: usize,
        queue: &mut QueueState,
        device: &mut D,
    ) -> QueueRunOutcome {
        if !self.queue_work_enabled() || queue.ready == 0 || queue.size == 0 {
            return QueueRunOutcome::default();
        }

        let features = self.transport.driver_features;
        let mut view = match QueueView::try_new(queue_idx, queue, self.memory, features) {
            Ok(view) => view,
            Err(violation) => return self.fault_queue(queue_idx, violation),
        };

        let old_used = view.state().last_used_idx;
        if let Err(violation) = device.process_queue(queue_idx, &mut view) {
            return self.fault_queue(queue_idx, violation);
        }
        let used_changed = view.state().last_used_idx != old_used;
        if let Some(violation) = view.take_violation() {
            return self.fault_queue(queue_idx, violation);
        }
        if let Err(violation) = view.validate_sync_completion_balance() {
            return self.fault_queue(queue_idx, violation);
        }

        if used_changed {
            self.publish_used_interrupt_if_needed(queue_idx, &view)
        } else {
            QueueRunOutcome::default()
        }
    }

    /// Run all active queues for a synchronous virtio device.
    pub fn run_device_queues<D: VirtioDevice<M>>(
        &mut self,
        queues: &mut [QueueState],
        device: &mut D,
    ) -> QueueRunOutcome {
        let active_queue_count = device.queue_count().min(queues.len());
        let mut outcome = QueueRunOutcome::default();
        for (idx, queue) in queues.iter_mut().take(active_queue_count).enumerate() {
            outcome.merge(self.run_device_queue(idx, queue, device));
        }
        outcome
    }

    /// Run custom queue inspection while centralizing violation handling.
    ///
    /// The higher-ranked queue-state lifetime prevents callers from returning
    /// data tied to `QueueView` or `QueueState`; returned values may still
    /// borrow guest memory through `'m`.
    pub fn pop_view<R>(
        &mut self,
        queue_idx: usize,
        queue: &mut QueueState,
        f: impl for<'brand, 'q> FnOnce(
            &mut QueueView<'brand, 'q, 'm, M>,
            &mut QueuePopContext<'brand>,
        ) -> Result<R, QueueViolation>,
    ) -> Option<R>
    where
        R: Default + 'm,
    {
        if !self.queue_work_enabled() || queue.ready == 0 || queue.size == 0 {
            return Some(R::default());
        }

        let features = self.transport.driver_features;
        let mut context = QueuePopContext {
            claim: QueueClaim::current(queue_idx, queue),
            issued_completions: 0,
            _brand: PhantomData,
        };
        let mut view = match QueueView::try_new(queue_idx, queue, self.memory, features) {
            Ok(view) => view,
            Err(violation) => {
                let _outcome = self.fault_queue(queue_idx, violation);
                return None;
            }
        };

        let result = match f(&mut view, &mut context) {
            Ok(result) => result,
            Err(violation) => {
                let _outcome = self.fault_queue(queue_idx, violation);
                return None;
            }
        };
        if let Err(violation) = view.validate_async_completion_balance(context.issued_completions) {
            let _outcome = self.fault_queue(queue_idx, violation);
            return None;
        }
        if let Some(violation) = view.take_violation() {
            let _outcome = self.fault_queue(queue_idx, violation);
            return None;
        }
        Some(result)
    }

    /// Publish one deferred descriptor completion from an owned response buffer.
    ///
    /// The runner consumes the deferred completion and validates queue
    /// liveness, generation, used-ring writability, response length, and
    /// writable descriptor ranges before writing guest response bytes. Callers
    /// provide immutable bytes only, so they cannot write guest memory and then
    /// abort before used-ring publication.
    pub fn publish_completion_bytes(
        &mut self,
        queues: &mut [QueueState],
        completion: DeferredDescriptorCompletion,
        response: &[u8],
    ) -> QueueRunOutcome {
        let DeferredDescriptorCompletion { token, writable } = completion;
        let claim = token.claim;
        let queue_idx = claim.queue_idx();
        let Some(queue) = queues.get_mut(queue_idx) else {
            log::warn!("queue {queue_idx} is no longer present — discarding completion");
            return QueueRunOutcome::stale();
        };

        if !self.queue_work_enabled() {
            return QueueRunOutcome::default();
        }
        if !claim.matches(queue) {
            log::warn!(
                "queue {queue_idx} was reset or reconfigured during async dispatch — discarding completion",
            );
            return QueueRunOutcome::stale();
        }

        let written = match token.written_bytes(response.len()) {
            Ok(written) => written,
            Err(violation) => return self.fault_queue(queue_idx, violation),
        };
        let features = self.transport.driver_features;
        let mut view = match QueueView::try_new(queue_idx, queue, self.memory, features) {
            Ok(view) => view,
            Err(violation) => return self.fault_queue(queue_idx, violation),
        };
        if let Err(violation) =
            view.push_deferred_writable_bytes(claim, token.head, &writable, response, written)
        {
            return self.fault_queue(queue_idx, violation);
        }

        self.publish_used_interrupt_if_needed(queue_idx, &view)
    }

    fn fault_queue(&mut self, queue_idx: usize, violation: QueueViolation) -> QueueRunOutcome {
        log::warn!("queue {queue_idx} faulted: {violation}");
        self.signal_device_needs_reset();
        QueueRunOutcome::reset()
    }

    fn publish_used_interrupt_if_needed(
        &mut self,
        queue_idx: usize,
        view: &QueueView<'_, '_, '_, M>,
    ) -> QueueRunOutcome {
        let needs_notification = match view.needs_notification() {
            Ok(needs_notification) => needs_notification,
            Err(violation) => return self.fault_queue(queue_idx, violation),
        };

        if needs_notification {
            // virtio 1.2 §4.2.4.6: INT_VRING means the interrupt was asserted
            // because of used buffers. If EVENT_IDX suppresses notification,
            // neither the IRQ nor the cause bit should be published.
            self.transport.interrupt_status |= INT_VRING;
            self.irq.assert();
        }

        QueueRunOutcome::used(needs_notification)
    }
}
