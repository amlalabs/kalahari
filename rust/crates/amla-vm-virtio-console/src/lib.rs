// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

#![forbid(unsafe_code)]

//! Virtio console device with MULTIPORT support.
//!
//! 6 queues:
//! - 0, 1: Port 0 (serial console) RX/TX
//! - 2, 3: Control RX/TX (MULTIPORT handshake + port management)
//! - 4, 5: Port 1 (agent channel) RX/TX
//!
//! Uses `ConsoleBackend` (amla-core) for port 0 and `AgentPortBackend` for port 1.

#[cfg(test)]
mod tests;

use amla_core::backends::ConsoleBackend;
use amla_virtio::{
    ConsoleControlState, DEVICE_ID_CONSOLE, QueueView, QueueViolation, ReadableDescriptor,
    VIRTIO_CONSOLE_F_MULTIPORT, VIRTIO_F_VERSION_1, VirtioDevice,
};

/// Number of virtqueues exposed by the console device.
pub const QUEUE_COUNT: usize = 6;

/// Maximum bytes consumed or produced per descriptor chain.
///
/// Defends against a malicious guest exhausting VMM memory via huge
/// descriptor chains on the console queues.
const MAX_CHAIN_BYTES: usize = 1024 * 1024; // 1 MiB

/// Scratch buffer size for collecting TX descriptors into a bounded record.
const TX_SCRATCH_BYTES: usize = 64 * 1024;

// Queue indices.
const PORT0_RX: usize = 0;
const PORT0_TX: usize = 1;
const CTRL_RX: usize = 2;
const CTRL_TX: usize = 3;
const PORT1_RX: usize = 4;
const PORT1_TX: usize = 5;

// Control message events (struct virtio_console_control).
const VIRTIO_CONSOLE_DEVICE_READY: u16 = 0;
const VIRTIO_CONSOLE_PORT_ADD: u16 = 1;
const VIRTIO_CONSOLE_PORT_READY: u16 = 3;
const VIRTIO_CONSOLE_CONSOLE_PORT: u16 = 4;
const VIRTIO_CONSOLE_PORT_OPEN: u16 = 6;

/// Port 1 kick byte. Written to vport to signal the other side.
pub const AGENT_TAG_KICK: u8 = 0x02;

/// Backend for port 1 (agent channel).
///
/// Port 1 carries kick signals and initial ring GPA between host and guest.
pub trait AgentPortBackend {
    /// Check if there is pending data from the host to send to the guest.
    fn has_pending_rx(&self) -> bool;
    /// Read pending RX data into buf. Returns bytes read.
    fn read_rx(&mut self, buf: &mut [u8]) -> usize;
    /// Guest sent data to host on port 1.
    fn write_tx(&mut self, data: &[u8]);
}

/// Null agent port backend (no port 1 activity).
pub struct NullAgentPort;

impl AgentPortBackend for NullAgentPort {
    fn has_pending_rx(&self) -> bool {
        false
    }
    fn read_rx(&mut self, _buf: &mut [u8]) -> usize {
        0
    }
    fn write_tx(&mut self, _data: &[u8]) {}
}

/// Virtio console device with MULTIPORT (2 ports + control queues).
///
/// Control response progress is stored in [`ConsoleControlState`], which lives
/// in the mmap-backed device slot rather than in VMM local heap state.
pub struct Console<'a> {
    port0: &'a dyn ConsoleBackend,
    port1: &'a mut dyn AgentPortBackend,
    pending_ctrl: &'a mut ConsoleControlState,
}

impl<'a> Console<'a> {
    pub fn new(
        port0: &'a dyn ConsoleBackend,
        port1: &'a mut dyn AgentPortBackend,
        pending_ctrl: &'a mut ConsoleControlState,
    ) -> Self {
        Self {
            port0,
            port1,
            pending_ctrl,
        }
    }
}

impl<M: amla_core::vm_state::guest_mem::GuestMemory> VirtioDevice<M> for Console<'_> {
    fn device_id(&self) -> u32 {
        DEVICE_ID_CONSOLE
    }

    fn queue_count(&self) -> usize {
        QUEUE_COUNT
    }

    fn device_features(&self) -> u64 {
        VIRTIO_F_VERSION_1 | VIRTIO_CONSOLE_F_MULTIPORT
    }

    fn reset(&mut self) {
        self.pending_ctrl.clear();
    }

    fn process_queue(
        &mut self,
        queue_idx: usize,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        match queue_idx {
            PORT0_RX => self.process_port0_rx(queue),
            PORT0_TX => self.process_port0_tx(queue),
            CTRL_RX => self.process_ctrl_rx(queue),
            CTRL_TX => self.process_ctrl_tx(queue),
            PORT1_RX => self.process_port1_rx(queue),
            PORT1_TX => self.process_port1_tx(queue),
            _ => Ok(()),
        }
    }

    fn write_config(&mut self, _config: &mut [u8], offset: usize, data: &[u8]) {
        // Emergency write: guest writes a byte to emerg_wr (offset 8)
        if offset == 8
            && !data.is_empty()
            && let Err(e) = self.port0.emergency_write(data[0])
        {
            log::warn!(
                "virtio-console emergency_write failed for byte 0x{:02x}: {e}",
                data[0]
            );
        }
    }
}

impl Console<'_> {
    // =========================================================================
    // Port 0 (serial console)
    // =========================================================================

    fn process_port0_tx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_readable()?;
            let payload = collect_readable_chain(chain.head_index(), chain.descriptors())?;

            queue.validate_next_completion()?;
            if let Err(e) = self.port0.write(&payload) {
                log::warn!(
                    "virtio-console port0 TX: backend write failed ({} bytes): {e}",
                    payload.len(),
                );
                return Err(QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_CONSOLE,
                    operation: "console_port0_tx_backend_write",
                });
            }
            queue.push(chain.complete_zero())?;
        }
        Ok(())
    }

    fn process_port0_rx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        if !self.port0.has_pending_input() {
            return Ok(());
        }

        while let Some(chain) = queue.pop() {
            let chain = chain.into_writable()?;
            let capacity = chain.writable_len().min(MAX_CHAIN_BYTES);
            let mut response = Vec::new();

            queue.validate_next_completion()?;
            while response.len() < capacity {
                let n = (capacity - response.len()).min(TX_SCRATCH_BYTES);
                let mut buf = vec![0u8; n];
                match self.port0.read(&mut buf) {
                    Ok(0) => break,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => {
                        log::warn!("virtio-console port0 RX: backend read failed: {e}");
                        return Err(QueueViolation::DeviceOperationFailed {
                            device_id: DEVICE_ID_CONSOLE,
                            operation: "console_port0_rx_backend_read",
                        });
                    }
                    Ok(bytes_read) => {
                        check_backend_read_len(bytes_read, buf.len(), "port0 rx read")?;
                        response.extend_from_slice(&buf[..bytes_read]);
                    }
                }
            }

            queue.push_writable_bytes(chain, &response)?;

            // If backend has no more input, stop
            if !self.port0.has_pending_input() {
                break;
            }
        }
        Ok(())
    }

    // =========================================================================
    // Control queues (MULTIPORT handshake)
    // =========================================================================

    /// Write pending control messages to guest (ctrl RX, queue 2).
    fn process_ctrl_rx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &mut self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        if !self.pending_ctrl.is_empty() {
            log::info!("ctrl_rx: {} pending messages", self.pending_ctrl.len());
        }
        while let Some(msg) = self.pending_ctrl.front() {
            let Some(chain) = queue.pop() else { break };
            let chain = chain.into_writable()?;
            chain.require_writable_bytes(8)?;

            let event = u16::from_le_bytes([msg[4], msg[5]]);
            let id = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
            log::info!("ctrl_rx: delivered event={event} id={id}");
            queue.validate_next_completion()?;
            queue.push_writable_bytes(chain, &msg)?;
            let _ = self.pending_ctrl.pop_front();
        }
        Ok(())
    }

    /// Read control messages from guest (ctrl TX, queue 3).
    fn process_ctrl_tx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &mut self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_readable()?;
            chain.require_readable_bytes(8)?;
            let mut msg = [0u8; 8];
            let mut total = 0usize;

            for slice in chain.descriptors() {
                match slice.read_into_checked(0, &mut msg[total..]) {
                    Ok(0) => {}
                    Ok(n) => {
                        total += n;
                        if total >= 8 {
                            break;
                        }
                    }
                    Err(e) => return Err(e),
                }
            }

            if total < 8 {
                return Err(QueueViolation::DescriptorReadableCapacityTooSmall {
                    head_index: chain.head_index(),
                    required: 8,
                    available: total,
                });
            }

            queue.validate_next_completion()?;
            self.handle_ctrl_message(msg);
            queue.push(chain.complete_zero())?;
        }
        Ok(())
    }

    /// Process a control message from the guest.
    fn handle_ctrl_message(&mut self, msg: [u8; 8]) {
        let id = u32::from_le_bytes([msg[0], msg[1], msg[2], msg[3]]);
        let event = u16::from_le_bytes([msg[4], msg[5]]);
        log::info!("virtio-console ctrl: id={id} event={event}");

        match event {
            VIRTIO_CONSOLE_DEVICE_READY => {
                self.queue_ctrl(VIRTIO_CONSOLE_PORT_ADD, 0, 1);
                self.queue_ctrl(VIRTIO_CONSOLE_PORT_ADD, 1, 1);
            }
            VIRTIO_CONSOLE_PORT_READY => match id {
                0 => {
                    self.queue_ctrl(VIRTIO_CONSOLE_CONSOLE_PORT, 0, 1);
                    self.queue_ctrl(VIRTIO_CONSOLE_PORT_OPEN, 0, 1);
                }
                1 => self.queue_ctrl(VIRTIO_CONSOLE_PORT_OPEN, 1, 1),
                _ => log::debug!("virtio-console ctrl: ignoring PORT_READY for port {id}"),
            },
            _ => {}
        }
    }

    /// Queue a control message for delivery to the guest.
    ///
    /// The persisted control state is semantic and idempotent: duplicate
    /// readiness messages set the same pending response bit again rather than
    /// filling a FIFO and crowding out later handshake responses.
    fn queue_ctrl(&mut self, event: u16, id: u32, value: u16) {
        let mut msg = [0u8; 8];
        msg[0..4].copy_from_slice(&id.to_le_bytes());
        msg[4..6].copy_from_slice(&event.to_le_bytes());
        msg[6..8].copy_from_slice(&value.to_le_bytes());
        if !self.pending_ctrl.push_back(msg) {
            log::debug!("virtio-console: ignoring unsupported ctrl msg (event={event}, id={id})");
        }
    }

    // =========================================================================
    // Port 1 (agent channel)
    // =========================================================================

    /// Write pending agent data to guest (port 1 RX, queue 4).
    fn process_port1_rx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &mut self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        if !self.port1.has_pending_rx() {
            return Ok(());
        }

        while let Some(chain) = queue.pop() {
            let chain = chain.into_writable()?;
            let capacity = chain.writable_len().min(MAX_CHAIN_BYTES);
            let mut response = Vec::new();

            queue.validate_next_completion()?;
            while response.len() < capacity {
                let n = (capacity - response.len()).min(TX_SCRATCH_BYTES);
                let mut buf = vec![0u8; n];
                let bytes_read = self.port1.read_rx(&mut buf);
                check_backend_read_len(bytes_read, buf.len(), "port1 rx read")?;
                if bytes_read == 0 {
                    break;
                }
                response.extend_from_slice(&buf[..bytes_read]);
            }

            queue.push_writable_bytes(chain, &response)?;

            if !self.port1.has_pending_rx() {
                break;
            }
        }
        Ok(())
    }

    /// Read agent data from guest (port 1 TX, queue 5).
    fn process_port1_tx<M: amla_core::vm_state::guest_mem::GuestMemory>(
        &mut self,
        queue: &mut QueueView<'_, '_, '_, M>,
    ) -> Result<(), QueueViolation> {
        while let Some(chain) = queue.pop() {
            let chain = chain.into_readable()?;
            let payload = collect_readable_chain(chain.head_index(), chain.descriptors())?;

            queue.validate_next_completion()?;
            self.port1.write_tx(&payload);
            queue.push(chain.complete_zero())?;
        }
        Ok(())
    }
}

/// Collect one readable descriptor chain into an atomic backend record.
fn collect_readable_chain<M>(
    head_index: u16,
    descriptors: &[ReadableDescriptor<'_, '_, M>],
) -> Result<Vec<u8>, QueueViolation>
where
    M: amla_core::vm_state::guest_mem::GuestMemory,
{
    let total = descriptors.iter().try_fold(0usize, |sum, desc| {
        sum.checked_add(desc.len() as usize)
            .ok_or(QueueViolation::DeviceOperationFailed {
                device_id: DEVICE_ID_CONSOLE,
                operation: "console_tx_chain_length_overflow",
            })
    })?;
    if total > MAX_CHAIN_BYTES {
        log::warn!(
            "virtio-console TX: chain head {head_index} is {total} bytes, max {MAX_CHAIN_BYTES}",
        );
        return Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "console_tx_chain_too_large",
        });
    }

    let mut payload = Vec::with_capacity(total);
    let mut scratch = vec![0u8; TX_SCRATCH_BYTES.min(total.max(1))];
    for slice in descriptors {
        let mut offset: u32 = 0;
        loop {
            let remaining = total.saturating_sub(payload.len());
            if remaining == 0 {
                break;
            }
            let window_end = scratch.len().min(remaining);
            let n = match slice.read_into_checked(offset, &mut scratch[..window_end]) {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            payload.extend_from_slice(&scratch[..n]);
            let n = u32::try_from(n).map_err(|_| QueueViolation::DeviceOperationFailed {
                device_id: DEVICE_ID_CONSOLE,
                operation: "console_tx_descriptor_offset",
            })?;
            offset = offset
                .checked_add(n)
                .ok_or(QueueViolation::DeviceOperationFailed {
                    device_id: DEVICE_ID_CONSOLE,
                    operation: "console_tx_descriptor_offset",
                })?;
        }
    }
    if payload.len() != total {
        return Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation: "console_tx_chain_read",
        });
    }
    Ok(payload)
}

const fn check_backend_read_len(
    bytes_read: usize,
    buf_len: usize,
    operation: &'static str,
) -> Result<(), QueueViolation> {
    if bytes_read > buf_len {
        return Err(QueueViolation::DeviceOperationFailed {
            device_id: DEVICE_ID_CONSOLE,
            operation,
        });
    }
    Ok(())
}
