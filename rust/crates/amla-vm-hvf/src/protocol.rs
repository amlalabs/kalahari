// SPDX-License-Identifier: AGPL-3.0-or-later OR BUSL-1.1

//! IPC protocol types for the HVF subprocess backend.
//!
//! Defines the request/response enums exchanged between the VMM parent
//! process and the HVF worker subprocess over the ring buffer.

use amla_core::vcpu::VcpuResponse;
use amla_core::{MemoryMapping, VcpuExit};
use amla_ipc::IpcMessage;
use amla_mem::MemHandle;

use crate::error::VmmError;

// ============================================================================
// WorkerRequest — parent → worker
// ============================================================================

/// Exact device/queue topology sent to an HVF worker.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerTopology {
    /// Device entries in VMM device-slot order.
    pub devices: Vec<WorkerDeviceSlot>,
}

/// One worker-visible device slot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerDeviceSlot {
    /// GSI for the device interrupt line.
    pub gsi: u32,
    /// Queue wake bit to set when this interrupt line receives guest EOI.
    pub resample_wake_idx: Option<u8>,
    /// Exact queue notification slots owned by this device.
    pub queues: Vec<WorkerQueueSlot>,
}

/// One worker-visible queue notification slot.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub(crate) struct WorkerQueueSlot {
    /// MMIO `QueueNotify` address.
    pub mmio_notify_addr: u64,
    /// `QueueNotify` value.
    pub queue_idx: u32,
    /// Global queue wake bit.
    pub wake_idx: u8,
}

/// Typed worker error that can cross the subprocess IPC boundary.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(crate) enum WorkerError {
    /// HVF returned `HV_NO_RESOURCES`.
    HvNoResources {
        /// HVF operation that exhausted host resources.
        operation: String,
    },
    /// Any other worker error.
    Message {
        /// Human-readable description.
        message: String,
    },
}

impl WorkerError {
    /// Preserve typed worker errors when converting from a backend error.
    pub(crate) fn from_vmm_error(error: &VmmError) -> Self {
        match error {
            VmmError::HvNoResources { operation } => Self::HvNoResources {
                operation: operation.clone(),
            },
            _ => Self::Message {
                message: error.to_string(),
            },
        }
    }

    /// Convert the wire error back into the backend error type.
    pub(crate) fn into_vmm_error(self) -> VmmError {
        match self {
            Self::HvNoResources { operation } => VmmError::HvNoResources { operation },
            Self::Message { message } => VmmError::Config(message),
        }
    }

    /// Human-readable error text for logging.
    pub(crate) fn message(&self) -> String {
        match self {
            Self::HvNoResources { operation } => {
                format!("HVF resources exhausted during {operation}")
            }
            Self::Message { message } => message.clone(),
        }
    }
}

/// Request from parent (VMM) to HVF worker.
#[derive(Debug, IpcMessage)]
pub(crate) enum WorkerRequest {
    /// Initialize HVF VM with device topology.
    Init {
        /// Number of vCPUs to create.
        vcpu_count: u32,
        /// Exact worker hardware topology.
        topology: WorkerTopology,
    },
    /// Map guest physical memory.
    MapMemory {
        /// Backing memory regions, transferred out-of-band.
        #[ipc_resource]
        handles: Vec<MemHandle>,
        /// How to project each handle into GPA space.
        mappings: Vec<MemoryMapping>,
    },
    /// Begin save: capture all vCPU + GIC state atomically.
    SaveState {
        /// Number of vCPUs to capture.
        vcpu_count: u32,
    },
    /// Fetch one captured vCPU snapshot (raw bytes).
    GetSavedVcpu {
        /// vCPU index (0-based).
        id: u32,
    },
    /// Fetch captured irqchip (GIC) blob.
    GetSavedIrqchip,
    /// Capture the backend's default irqchip state for a first boot seed.
    CaptureDefaultIrqchip,
    /// Restore one vCPU from snapshot bytes.
    RestoreVcpu {
        /// vCPU index (0-based).
        id: u32,
        /// Raw `HvfVcpuSnapshot` bytes (repr(C) Pod).
        data: Vec<u8>,
    },
    /// Restore irqchip from a non-empty blob.
    RestoreIrqchip {
        /// Irqchip blob bytes.
        blob: Vec<u8>,
    },
    /// Resume a vCPU after the parent handled its exit.
    ResumeVcpu {
        /// vCPU index (0-based).
        id: u32,
        /// Monotonic sequence number for correlating exits with resumes.
        seq: u64,
        /// State update before resuming. None for initial resume.
        response: Option<VcpuResponse>,
    },
    /// Preempt a running vCPU (one-way signal).
    Preempt {
        /// vCPU index.
        id: u32,
    },
    /// Assert or deassert an IRQ line (one-way signal).
    IrqLine {
        /// Global System Interrupt number.
        gsi: u32,
        /// true = assert, false = deassert.
        level: bool,
    },
    /// Shut down the worker.
    Shutdown,
}

// ============================================================================
// WorkerResponse — worker → parent
// ============================================================================

/// Response from HVF worker to parent.
#[derive(Debug, IpcMessage)]
pub(crate) enum WorkerResponse {
    /// Worker initialized. Reply to Init.
    Ready,
    /// A vCPU exited the hypervisor.
    VcpuExit {
        /// vCPU index.
        id: u32,
        /// Sequence number from the corresponding `ResumeVcpu`.
        seq: u64,
        /// Exit reason.
        exit: VcpuExit,
    },
    /// Guest kicked a device queue.
    DeviceKick {
        /// Global queue wake bit index.
        wake_idx: u8,
    },
    /// IRQ line needs resampling (guest EOI).
    IrqResample {
        /// GSI that received EOI.
        gsi: u32,
    },
    /// Bulk state data reply (vCPU snapshot bytes, irqchip blob, etc.).
    StateData {
        /// Raw bytes.
        data: Vec<u8>,
    },
    /// Generic success.
    Ok,
    /// Operation failed.
    Error {
        /// Typed worker error.
        error: WorkerError,
    },
}
