// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! Virtio-fs device queue ownership and async completion path.

use parking_lot::Mutex;

use amla_core::vm_state::{DeviceSlot, VmState};
use amla_core::{IrqLine, VmmError};
use amla_fuse::fuse::{
    FsBackend, FuseInHeader, FuseServer, MAX_FUSE_REQUEST_SIZE, OwnedFuseRequest,
};
use amla_virtio::{
    DEFERRED_WRITABLE_REGION_RESERVED_BYTES, DeferredDescriptorCompletion, FsState, QueueRunner,
    QueueState, ReadableDescriptor, queue_work_enabled, signal_device_needs_reset,
};
use amla_virtio_fs::{FIRST_REQUEST_QUEUE, Fs, HIPRIO_QUEUE};

use crate::devices::DeviceKind;

use super::{
    check_resample_virtio, log_mmio_read, log_mmio_write, transport_read_fast_path, with_transport,
};

/// Filesystem device (FUSE). Has async three-phase poll with multi-queue support.
pub struct FsDevice<'irq, F: FsBackend> {
    inner: Mutex<FsInner<'irq>>,
    irq: &'irq dyn IrqLine,
    /// FS backend outside the mutex — `FsBackend: Send + Sync`.
    fs_backend: &'irq F,
}

struct FsInner<'a> {
    slot: DeviceSlot<FsState>,
    vm: &'a VmState<'a>,
    request_queues: amla_virtio_fs::RequestQueueCount,
}

pub struct PoppedFsRequest<'m> {
    completion: Option<DeferredDescriptorCompletion>,
    request: OwnedFuseRequest,
    reply_budget_bytes: usize,
    completion_reserved_bytes: usize,
    head: u16,
    _marker: std::marker::PhantomData<&'m VmState<'m>>,
}

const FS_MAX_DESCRIPTOR_CHAIN_ENTRIES: usize = 256;

pub const FS_MAX_REQUEST_BUDGET_BYTES: usize = (2 * MAX_FUSE_REQUEST_SIZE)
    + (FS_MAX_DESCRIPTOR_CHAIN_ENTRIES * std::mem::size_of::<usize>())
    + (FS_MAX_DESCRIPTOR_CHAIN_ENTRIES * DEFERRED_WRITABLE_REGION_RESERVED_BYTES);

impl PoppedFsRequest<'_> {
    pub(crate) fn budget_bytes(&self) -> usize {
        let budget = self
            .request
            .reserved_bytes()
            .saturating_add(self.completion_reserved_bytes)
            .saturating_add(self.reply_budget_bytes);
        debug_assert!(
            budget <= FS_MAX_REQUEST_BUDGET_BYTES,
            "FS request budget {budget} exceeds conservative admission cap {FS_MAX_REQUEST_BUDGET_BYTES}",
        );
        budget
    }

    const fn take_completion(&mut self) -> Option<DeferredDescriptorCompletion> {
        self.completion.take()
    }

    #[cfg(test)]
    pub(crate) fn queue_idx(&self) -> Option<usize> {
        self.completion
            .as_ref()
            .map(DeferredDescriptorCompletion::queue_idx)
    }

    const fn head_for_log(&self) -> u16 {
        self.head
    }
}

pub struct FsCompletion<'m> {
    pub(crate) device_idx: usize,
    request: PoppedFsRequest<'m>,
    response: Result<Vec<u8>, VmmError>,
}

impl FsCompletion<'_> {
    pub(crate) fn request_budget_bytes(&self) -> usize {
        self.request.budget_bytes()
    }
}

// SAFETY: DeviceSlot + &VmState are Send. VmState is Send+Sync.
unsafe impl Send for FsInner<'_> {}

impl<'irq, F: FsBackend> FsDevice<'irq, F> {
    pub(crate) fn new(
        slot: DeviceSlot<FsState>,
        vm: &'irq VmState<'irq>,
        irq: &'irq dyn IrqLine,
        fs_backend: &'irq F,
        request_queues: amla_virtio_fs::RequestQueueCount,
    ) -> Self {
        Self {
            inner: Mutex::new(FsInner {
                slot,
                vm,
                request_queues,
            }),
            irq,
            fs_backend,
        }
    }

    /// Test-only one-shot poll. Production uses `fs_worker_loop`, which keeps
    /// in-flight requests across wakes and enforces backpressure.
    #[cfg(test)]
    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) async fn poll(&self) -> bool {
        let mut cursor = 0;
        let requests = self.pop_ready_requests(usize::MAX, &mut cursor);
        let mut futs = futures_util::stream::FuturesUnordered::new();
        for request in requests {
            futs.push(self.start_request(0, request));
        }

        let mut had_work = false;
        while let Some(mut completion) = futures_util::StreamExt::next(&mut futs).await {
            had_work |= self.push_fs_completion(&mut completion);
        }
        had_work
    }

    /// Pop up to `max_requests` owned FUSE requests without awaiting the backend.
    ///
    /// The fs worker computes `max_requests` from a worst-case request byte cap
    /// and then accounts the exact reservation for each popped request. This
    /// keeps owned request memory bounded without holding the queue lock across
    /// backend awaits.
    // Reason: inner lock and the device-slot borrow it produces must
    // both live until the pop loop completes; the queue iteration is
    // the entire critical section.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn pop_ready_requests(
        &self,
        max_requests: usize,
        next_request_queue: &mut usize,
    ) -> Vec<PoppedFsRequest<'irq>> {
        if max_requests == 0 {
            return Vec::new();
        }
        let inner = self.inner.lock();
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let vm = inner.vm;
        let state = &mut *state;
        let active_queue_count = inner.request_queues.total_queue_count();
        let transport = &mut state.transport;
        let queues = &mut state.queues;
        if !queue_work_enabled(transport) {
            return Vec::new();
        }
        let mut runner = QueueRunner::new(transport, vm, self.irq);

        let mut requests = Vec::new();
        if HIPRIO_QUEUE < active_queue_count
            && !Self::append_popped_requests(
                &mut runner,
                queues,
                HIPRIO_QUEUE,
                max_requests,
                &mut requests,
            )
        {
            return Vec::new();
        }

        if requests.len() < max_requests && active_queue_count > FIRST_REQUEST_QUEUE {
            let request_queues = active_queue_count - FIRST_REQUEST_QUEUE;
            let start = *next_request_queue % request_queues;
            for offset in 0..request_queues {
                if requests.len() >= max_requests {
                    break;
                }
                let qi = FIRST_REQUEST_QUEUE + ((start + offset) % request_queues);
                if !Self::append_popped_requests(
                    &mut runner,
                    queues,
                    qi,
                    max_requests - requests.len(),
                    &mut requests,
                ) {
                    return Vec::new();
                }
                *next_request_queue = (qi + 1 - FIRST_REQUEST_QUEUE) % request_queues;
            }
        }

        requests
    }

    fn append_popped_requests<'m>(
        runner: &mut QueueRunner<'_, 'm, VmState<'m>>,
        queues: &mut [QueueState],
        qi: usize,
        limit: usize,
        requests: &mut Vec<PoppedFsRequest<'m>>,
    ) -> bool {
        let result = runner.pop_view(qi, &mut queues[qi], |view, ctx| {
            let start_len = requests.len();
            let mut malformed = None;
            while requests.len().saturating_sub(start_len) < limit
                && let Some(chain) = view.pop()
            {
                let chain = chain.into_split()?;
                let head = chain.head_index();
                let request = match Self::own_fs_request(head, chain.readable()) {
                    Ok(request) => request,
                    Err(error) => {
                        malformed = Some(error);
                        break;
                    }
                };
                let completion = ctx.defer_split_completion(chain)?;
                let reply_budget_bytes = completion.writable_capacity().min(MAX_FUSE_REQUEST_SIZE);
                let completion_reserved_bytes = completion.reserved_bytes();
                requests.push(PoppedFsRequest {
                    completion: Some(completion),
                    request,
                    reply_budget_bytes,
                    completion_reserved_bytes,
                    head,
                    _marker: std::marker::PhantomData,
                });
            }
            Ok(malformed)
        });

        match result {
            Some(None) => true,
            Some(Some(error)) => {
                log::error!("FS request queue {qi} produced malformed request: {error}");
                runner.signal_device_needs_reset();
                false
            }
            None => false,
        }
    }

    pub(crate) fn start_request(
        &self,
        device_idx: usize,
        request: PoppedFsRequest<'irq>,
    ) -> impl std::future::Future<Output = FsCompletion<'irq>> + 'irq {
        let fs_backend = self.fs_backend;
        async move {
            let head = request.head_for_log();
            let server = FuseServer::new(fs_backend);
            let response = match server.dispatch_owned_request(&request.request).await {
                Ok(reply) => match reply.encode() {
                    Ok(bytes) => Ok(bytes),
                    Err(e) => {
                        log::error!("FS: FUSE reply encoding failed for descriptor {head}: {e}");
                        Err(e)
                    }
                },
                Err(e) => {
                    log::error!("FS: FUSE dispatch failed for descriptor {head}: {e}");
                    Err(e)
                }
            };
            FsCompletion {
                device_idx,
                request,
                response,
            }
        }
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn push_fs_completion(&self, result: &mut FsCompletion<'_>) -> bool {
        let Some(completion) = result.request.take_completion() else {
            log::error!("FS completion attempted to publish the same descriptor twice");
            return false;
        };
        let queue_idx = completion.queue_idx();
        let response = match &result.response {
            Ok(response) => response.as_slice(),
            Err(e) => {
                log::error!("FS request queue {queue_idx} failed before completion publish: {e}");
                let inner = self.inner.lock();
                let mut guard = inner.vm.device_slot_mut(inner.slot);
                signal_device_needs_reset(&mut guard.transport, self.irq);
                return false;
            }
        };
        let inner = self.inner.lock();
        let mut guard = inner.vm.device_slot_mut(inner.slot);
        let state = &mut *guard;

        if !queue_work_enabled(&state.transport) {
            log::warn!("FS queue reset during async dispatch — discarding results");
            return false;
        }

        let publish_result = {
            let transport = &mut state.transport;
            let mut runner = QueueRunner::new(transport, inner.vm, self.irq);
            runner.publish_completion_bytes(&mut state.queues, completion, response)
        };
        publish_result.had_work()
    }
}

impl<F: FsBackend> FsDevice<'_, F> {
    fn read_fuse_header_from_descriptors<'m>(
        readable: &[ReadableDescriptor<'_, 'm, VmState<'m>>],
    ) -> Result<FuseInHeader, VmmError> {
        let header_size = std::mem::size_of::<FuseInHeader>();
        let mut header_bytes = vec![0u8; header_size];
        let mut copied = 0usize;
        for desc in readable {
            if copied == header_size {
                break;
            }
            let len = (desc.len() as usize).min(header_size - copied);
            if len == 0 {
                continue;
            }
            let n = desc.read_into(0, &mut header_bytes[copied..copied + len])?;
            if n != len {
                return Err(VmmError::DeviceConfig(format!(
                    "short FUSE header read: {n}/{len}"
                )));
            }
            copied += n;
        }
        if copied != header_size {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request header truncated: got {copied}/{header_size}"
            )));
        }
        Ok(amla_core::bytemuck::pod_read_unaligned(&header_bytes))
    }

    fn own_fs_request<'m>(
        head: u16,
        readable: &[ReadableDescriptor<'_, 'm, VmState<'m>>],
    ) -> Result<OwnedFuseRequest, VmmError> {
        let header = Self::read_fuse_header_from_descriptors(readable)?;
        let declared_len = header.len as usize;
        if declared_len < std::mem::size_of::<FuseInHeader>() {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request length {declared_len} smaller than header"
            )));
        }
        if declared_len > MAX_FUSE_REQUEST_SIZE {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request length {declared_len} exceeds cap {MAX_FUSE_REQUEST_SIZE}"
            )));
        }

        let mut request = OwnedFuseRequest::with_capacity(declared_len);
        let mut remaining = declared_len;
        for desc in readable {
            if remaining == 0 {
                break;
            }
            let len = (desc.len() as usize).min(remaining);
            let dst = request.push_zeroed(len);
            let n = desc.read_into(0, dst)?;
            if n != len {
                return Err(VmmError::DeviceConfig(format!(
                    "short FUSE request read for descriptor {head}: {n}/{len}",
                )));
            }
            remaining -= n;
        }
        if remaining != 0 {
            return Err(VmmError::DeviceConfig(format!(
                "FUSE request descriptor chain ended {remaining} bytes before declared length"
            )));
        }

        Ok(request)
    }
}

impl<F: FsBackend> FsDevice<'_, F> {
    #[allow(clippy::unused_self)]
    pub(crate) const fn poll_queue_now(&self, _queue_idx: usize) -> bool {
        false
    }

    #[allow(clippy::unused_self)]
    pub(crate) const fn kind(&self) -> DeviceKind {
        DeviceKind::Fs
    }

    // Reason: lock guard intentionally spans the body so the operation
    // observes a single consistent state snapshot.
    #[allow(clippy::significant_drop_tightening)]
    pub(crate) fn handle_read(&self, offset: u64, size: u8) -> u64 {
        let inner = self.inner.lock();
        let slot_idx = inner.slot.index();
        let mut state = inner.vm.device_slot_mut(inner.slot);
        if let Some(v) =
            transport_read_fast_path(&state.transport, offset, size, amla_virtio::DEVICE_ID_FS)
        {
            log_mmio_read("fast", slot_idx, offset, size, v);
            return v;
        }
        let mut dev = Fs::new(inner.request_queues);
        let v = with_transport(&mut dev, &mut *state, inner.vm, self.irq, |t| {
            t.read(offset, size)
        });
        log_mmio_read("slow", slot_idx, offset, size, v);
        v
    }

    pub(crate) fn handle_write(&self, offset: u64, size: u8, value: u64) {
        let inner = self.inner.lock();
        let slot_idx = inner.slot.index();
        log_mmio_write(slot_idx, offset, size, value);
        let mut state = inner.vm.device_slot_mut(inner.slot);
        let mut dev = Fs::new(inner.request_queues);
        with_transport(&mut dev, &mut *state, inner.vm, self.irq, |t| {
            t.write(offset, size, value);
        });
    }

    pub(crate) fn check_resample(&self) {
        check_resample_virtio(self.irq);
    }
}
